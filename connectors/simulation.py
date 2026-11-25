"""Backend de simulation : rejoue un scénario enregistré (lab/scenarios/S*.json).

Les journaux sont stockés au format des documents Wazuh, les réponses de MISP
et des services de TI au format brut de leurs API : ils passent par les mêmes
fonctions de normalisation que les connecteurs réels. Le backend permet de
développer et d'évaluer l'agent sans laboratoire démarré, de façon
reproductible, et d'injecter des pannes (ENF-04).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from connectors.base import ConnectorError
from connectors.misp import normalize_attribute
from connectors.threat_intel import normalize_abuseipdb, normalize_virustotal
from connectors.wazuh import build_process_tree, matches, normalize_event
from gateway.tool_schemas import MispLookupArgs, ProcessTreeArgs, SearchLogsArgs, TiLookupArgs

VERSION = "1.0"
SCENARIO_DIR = Path(__file__).resolve().parent.parent / "lab" / "scenarios"


def load_scenario(ref: str | Path) -> dict[str, Any]:
    """Charge un scénario par identifiant (« S1 ») ou par chemin."""
    path = Path(ref)
    if not path.exists():
        matches_ = sorted(SCENARIO_DIR.glob(f"{ref}_*.json")) or sorted(SCENARIO_DIR.glob(f"{ref}.json"))
        if not matches_:
            raise FileNotFoundError(f"scénario introuvable : {ref}")
        path = matches_[0]
    return json.loads(path.read_text(encoding="utf-8"))


def list_scenarios() -> list[str]:
    return [p.stem.split("_", 1)[0] for p in sorted(SCENARIO_DIR.glob("S*_*.json"))]


class SimulationBackend:
    VERSION = VERSION

    def __init__(self, scenario: dict[str, Any]):
        self.scenario = scenario
        self.faults: dict[str, str] = dict(scenario.get("faults") or {})
        self.events: list[tuple[dict[str, Any], bool]] = []
        for doc in scenario.get("logs", []):
            src = doc.get("_source", doc)
            self.events.append((normalize_event(doc), bool(src.get("rule"))))
        self.events.sort(key=lambda e: e[0].get("timestamp") or "")
        self.misp = {k.lower(): v for k, v in (scenario.get("misp") or {}).items()}
        self.ti = {k.lower(): v for k, v in (scenario.get("threat_intel") or {}).items()}

    def _fault(self, tool: str) -> bool:
        mode = self.faults.get(tool)
        if mode == "unavailable":
            raise ConnectorError(f"service indisponible ({tool}, panne simulée)", transient=True)
        if mode == "timeout":
            raise ConnectorError(f"délai dépassé ({tool}, panne simulée)", transient=True)
        if mode == "error":
            raise ConnectorError(f"erreur du service ({tool}, panne simulée)")
        return mode == "empty"

    # ------------------------------------------------------------------ outils
    def search_logs(self, args: SearchLogsArgs) -> dict[str, Any]:
        if self._fault("search_logs"):
            return {"items": [], "meta": {"index": args.index, "returned": 0}}
        items = [dict(item) for item, is_alert in self.events if matches(item, args, is_alert=is_alert)]
        total = len(items)
        return {"items": items[: args.limit], "meta": {"index": args.index, "returned": min(total, args.limit),
                                                       "total": total, "backend": "simulation"}}

    def get_process_tree(self, args: ProcessTreeArgs) -> dict[str, Any]:
        if self._fault("get_process_tree"):
            return {"items": [], "meta": {}}
        # Comme le connecteur réel, l'arbre est reconstruit à partir des événements bruts (archives).
        events = [dict(item) for item, is_alert in self.events if not is_alert]
        return {"items": build_process_tree(events, args), "meta": {"backend": "simulation"}}

    def misp_lookup(self, args: MispLookupArgs) -> dict[str, Any]:
        if self._fault("misp_lookup"):
            return {"items": [], "meta": {"queried": args.value, "found": False}}
        attrs = self.misp.get(args.value.lower(), [])
        items = [normalize_attribute(a, args.value) for a in attrs]
        meta = {"queried": args.value, "found": bool(items), "backend": "simulation"}
        if not items:
            meta["note"] = f"{args.value} absent de MISP"
        return {"items": items, "meta": meta}

    def ti_lookup(self, args: TiLookupArgs) -> dict[str, Any]:
        if self._fault("ti_lookup"):
            return {"items": [], "meta": {"queried": args.value}}
        raw = self.ti.get(args.value.lower(), {})
        otype = args.type.value
        items = []
        for provider in args.providers:
            if provider == "virustotal":
                item = normalize_virustotal(args.value, otype, raw.get("virustotal"))
            elif provider == "abuseipdb" and otype == "ip":
                item = normalize_abuseipdb(args.value, raw.get("abuseipdb"))
            else:
                continue
            item["raw_ref"] = f"{provider}:{args.value}"
            items.append(item)
        return {"items": items, "meta": {"queried": args.value, "backend": "simulation"}}
