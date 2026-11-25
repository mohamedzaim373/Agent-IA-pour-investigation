"""Point d'entrée de l'agent : assemble configuration, politique, connecteurs,
passerelle, RAG, LLM et graphe, puis mène une investigation de bout en bout.

    python -m agent.runner --scenario S1
    python -m agent.runner --scenario S4 --level N0 --approve console
    BACKEND=live python -m agent.runner --alert alerte_wazuh.json --analyst jdupont
"""

from __future__ import annotations

import argparse
import json
import queue
import sys
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from agent.entities import normalize_alert
from agent.graph import AgentContext, build_graph
from agent.llm import make_llm
from agent.llm.base import BaseLLM
from config.settings import Settings, load_settings
from evidence.report import export_files, render_markdown
from evidence.store import EvidenceStore
from gateway.approval import Approver, AutoApprover, ConsoleApprover
from gateway.audit import AuditLog
from gateway.gateway import ToolGateway
from gateway.policy import BudgetUsage, IdentityDirectory, Policy
from gateway.privacy import Pseudonymizer
from gateway.run_metadata import collect_run_metadata
from rag.retriever import AttackRAG, get_rag


@dataclass
class InvestigationOutcome:
    investigation_id: str
    status: str
    report: dict[str, Any] = field(default_factory=dict)
    markdown: str = ""
    validation: dict[str, Any] = field(default_factory=dict)
    usage: dict[str, Any] = field(default_factory=dict)
    audit: dict[str, Any] = field(default_factory=dict)
    files: dict[str, str] = field(default_factory=dict)
    plan: dict[str, Any] = field(default_factory=dict)
    replan_log: list[dict[str, Any]] = field(default_factory=list)
    failures: list[dict[str, Any]] = field(default_factory=list)
    injections: list[dict[str, Any]] = field(default_factory=list)
    level: str = ""
    level_notes: list[str] = field(default_factory=list)
    error: str | None = None

    @property
    def verdict(self) -> str | None:
        return self.report.get("verdict")


def new_investigation_id() -> str:
    return f"INV-{datetime.now(timezone.utc):%Y%m%d-%H%M%S}-{uuid.uuid4().hex[:6]}"


class Investigator:
    def __init__(self, settings: Settings | None = None, *, policy: Policy | None = None,
                 identities: IdentityDirectory | None = None, rag: AttackRAG | None = None,
                 llm_factory: Callable[[Pseudonymizer], BaseLLM] | None = None):
        self.settings = settings or load_settings()
        self.settings.ensure_dirs()
        self.policy = policy or Policy.load(self.settings.policy_path)
        self.identities = identities or IdentityDirectory.load(self.settings.analysts_path)
        self.rag = rag or get_rag(self.settings.attack_kb_path, self.settings.embedder, self.settings.vector_store,
                                  self.settings.sbert_model, self.settings.data_dir)
        self.store = EvidenceStore(self.settings.database_url)
        self.audit = AuditLog(self.settings.database_url)
        self.llm_factory = llm_factory

    # ---------------------------------------------------------- connecteurs
    def build_connectors(self, scenario: dict[str, Any] | None) -> tuple[dict[str, Callable], dict[str, Any], str]:
        s = self.settings
        if s.backend == "simulation":
            from connectors.simulation import SimulationBackend

            if scenario is None:
                raise ValueError("le backend de simulation nécessite un scénario (BACKEND=live pour le laboratoire)")
            sim = SimulationBackend(scenario)
            executors = {"search_logs": sim.search_logs, "get_process_tree": sim.get_process_tree,
                         "misp_lookup": sim.misp_lookup, "ti_lookup": sim.ti_lookup}
            connectors = {"simulation": sim}
            backend = "simulation"
        elif s.backend == "live":
            from connectors.misp import MispConnector
            from connectors.threat_intel import AbuseIPDBClient, ThreatIntelService, TICache, VirusTotalClient
            from connectors.wazuh import WazuhIndexerConnector

            wazuh = WazuhIndexerConnector(s.wazuh_indexer_url, s.wazuh_user, s.wazuh_password, s.wazuh_verify_tls)
            misp = MispConnector(s.misp_url, s.misp_key, s.misp_verify_tls)
            ti = ThreatIntelService(
                virustotal=VirusTotalClient(s.virustotal_api_key) if s.virustotal_api_key else None,
                abuseipdb=AbuseIPDBClient(s.abuseipdb_api_key) if s.abuseipdb_api_key else None,
                cache=TICache(s.database_url, s.ti_cache_ttl_s),
            )
            executors = {"search_logs": wazuh.search_logs, "get_process_tree": wazuh.get_process_tree,
                         "misp_lookup": misp.lookup, "ti_lookup": ti.lookup}
            connectors = {"wazuh": wazuh, "misp": misp, "threat_intel": ti}
            backend = "live"
        else:
            raise ValueError(f"backend inconnu : {s.backend} (simulation | live)")
        executors["attack_search"] = self.rag.attack_search
        connectors["attack_rag"] = self.rag
        return executors, connectors, backend

    # ------------------------------------------------------------ enquête
    def investigate(
        self,
        alert: dict[str, Any],
        *,
        analyst_id: str,
        autonomy_level: str | None = None,
        approver: Approver | None = None,
        scenario: dict[str, Any] | None = None,
        on_event: Callable[[dict[str, Any]], None] | None = None,
        directives: "queue.Queue[dict[str, Any]] | None" = None,
        investigation_id: str | None = None,
    ) -> InvestigationOutcome:
        alert_item = normalize_alert(alert)
        analyst = self.identities.get(analyst_id)
        level, notes = self.policy.effective_level(autonomy_level, analyst)
        inv_id = investigation_id or new_investigation_id()
        on_event = on_event or (lambda _e: None)

        pseudonymizer = Pseudonymizer(self.settings.pseudonym_secret or None, self.policy.internal_domains)
        if self.llm_factory is not None:
            llm = self.llm_factory(pseudonymizer)
        else:
            llm = make_llm(self.settings, pseudonymizer,
                           pseudonymize=bool(self.policy.privacy.get("pseudonymize_for_external_llm", True)))
        executors, connectors, backend = self.build_connectors(scenario)
        metadata = collect_run_metadata(llm=llm, policy=self.policy, backend=backend, connectors=connectors, rag=self.rag)
        metadata["autonomy"] = {"requested": autonomy_level, "effective": level, "notes": notes}
        if scenario:
            metadata["scenario"] = scenario.get("id")

        self.store.create_investigation(inv_id, analyst_id=analyst_id, autonomy_level=level, alert=alert_item,
                                        metadata=metadata)
        self.audit.append(investigation_id=inv_id, actor=analyst.actor, event_type="run_start", decision=level,
                          reason=alert_item.get("summary", "")[:300],
                          details={"metadata": metadata, "alert_ref": alert_item.get("raw_ref")})
        for note in notes:
            self.audit.append(investigation_id=inv_id, actor="system", event_type="autonomy_capped", decision=level,
                              reason=note)
        on_event({"type": "run_start", "investigation_id": inv_id, "level": level, "notes": notes,
                  "alert": alert_item.get("summary")})

        usage = BudgetUsage()
        gateway = ToolGateway(policy=self.policy, executors=executors, audit=self.audit, analyst=analyst, level=level,
                              investigation_id=inv_id, approver=approver, identities=self.identities, usage=usage,
                              on_event=lambda e: on_event(dict(e, investigation_id=inv_id)))
        ctx = AgentContext(investigation_id=inv_id, alert=alert_item, gateway=gateway, llm=llm, store=self.store,
                           audit=self.audit, rag=self.rag, policy=self.policy, pseudonymizer=pseudonymizer,
                           on_event=on_event, directives=directives or queue.Queue(), backend=backend)
        graph = build_graph(ctx)
        recursion = int(self.policy.budget("max_steps", 30)) * 4 + 40
        try:
            state = graph.invoke({}, config={"recursion_limit": recursion})
        except Exception as exc:  # ENF-04 : l'échec est consigné, jamais silencieux
            self.audit.append(investigation_id=inv_id, actor="system", event_type="run_error",
                              reason=f"{type(exc).__name__}: {exc}"[:500])
            self.store.finish_investigation(inv_id, status="error", verdict=None, stop_reason=str(exc)[:500])
            on_event({"type": "run_error", "investigation_id": inv_id, "error": str(exc)})
            return InvestigationOutcome(inv_id, "error", usage=usage.snapshot(), level=level, level_notes=notes,
                                        error=f"{type(exc).__name__}: {exc}")

        report = state["report"]
        validation = state.get("validation", {})
        usage.tokens = llm.total_tokens
        snapshot = usage.snapshot()
        self.store.finish_investigation(inv_id, status="completed", verdict=report.get("verdict"),
                                        stop_reason=report.get("stop_reason"))
        self.audit.append(investigation_id=inv_id, actor="agent", event_type="run_end", decision=report.get("verdict"),
                          reason=report.get("stop_reason", "")[:300],
                          details={"usage": snapshot,
                                   "grounding_ratio": validation.get("final", {}).get("grounding_ratio")})
        verify = self.audit.verify()
        audit_info = {"ok": verify.ok, "errors": verify.errors[:5], "head_hash": verify.head_hash,
                      "entries": len(self.audit.entries(inv_id)), "chain_length": verify.checked}
        investigation = self.store.get_investigation(inv_id) or {}
        evidence = self.store.list(inv_id)
        markdown = render_markdown(report, evidence=evidence, investigation=investigation, validation=validation,
                                   audit=audit_info, usage=snapshot, plan=state.get("plan"),
                                   replan_log=state.get("replan_log"))
        self.store.save_report(inv_id, report=report, markdown=markdown, validation=validation)
        files = export_files(self.settings.runs_dir / inv_id, report=report, markdown=markdown)
        on_event({"type": "run_end", "investigation_id": inv_id, "verdict": report.get("verdict"),
                  "grounding_ratio": validation.get("final", {}).get("grounding_ratio")})
        return InvestigationOutcome(
            investigation_id=inv_id, status="completed", report=report, markdown=markdown, validation=validation,
            usage=snapshot, audit=audit_info, files=files, plan=state.get("plan", {}),
            replan_log=state.get("replan_log", []), failures=state.get("failures", []),
            injections=state.get("injections", []), level=level, level_notes=notes,
        )


def _print_event(event: dict[str, Any]) -> None:
    t = event.get("type")
    if t == "plan":
        print(f"  [plan v{event['version']}] {event['rationale']}")
        for ch in event.get("changes", [])[:6]:
            print(f"      + {ch.get('change')} — {ch.get('justification')}")
    elif t == "tool_call":
        print(f"  -> {event['tool']} {json.dumps(event['args'], ensure_ascii=False)[:140]}")
    elif t in {"tool_denied", "tool_rejected", "tool_error"}:
        print(f"  !! {event['tool']} : {event.get('reason') or event.get('error')}")
    elif t == "injection_detected":
        print(f"  !! injection détectée dans le résultat de {event['tool']} ({event['count']} motif(s))")
    elif t == "stop":
        print(f"  [arrêt] {event['reason']}")


def _main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Agent IA d'investigation d'incidents")
    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument("--scenario", help="scénario simulé (S1 à S5)")
    src.add_argument("--alert", type=Path, help="alerte Wazuh (JSON) pour le backend live")
    parser.add_argument("--analyst", default="jdupont")
    parser.add_argument("--level", choices=["N0", "N1", "N2", "N3"], default=None)
    parser.add_argument("--approve", choices=["auto", "deny", "console"], default="console")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args(argv)

    scenario = None
    if args.scenario:
        from connectors.simulation import load_scenario

        scenario = load_scenario(args.scenario)
        alert = scenario["alert"]
        overrides = {"backend": "simulation"}
    else:
        alert = json.loads(args.alert.read_text(encoding="utf-8"))
        overrides = {}
    settings = load_settings(**overrides)
    approver: Approver = {"auto": AutoApprover(True, args.analyst, "approbation en ligne de commande"),
                          "deny": AutoApprover(False, args.analyst, "refus en ligne de commande"),
                          "console": ConsoleApprover(args.analyst)}[args.approve]
    investigator = Investigator(settings)
    outcome = investigator.investigate(alert, analyst_id=args.analyst, autonomy_level=args.level, approver=approver,
                                       scenario=scenario, on_event=None if args.quiet else _print_event)
    if outcome.status != "completed":
        print(f"Échec de l'investigation {outcome.investigation_id} : {outcome.error}")
        return 1
    final = outcome.validation.get("final", {})
    print(f"\nInvestigation {outcome.investigation_id} — niveau {outcome.level}")
    print(f"Verdict : {outcome.verdict} (confiance {outcome.report.get('confidence')})")
    print(f"Techniques : {', '.join(t['technique_id'] for t in outcome.report.get('techniques', [])) or '—'}")
    print(f"Ancrage : {final.get('claims_grounded')}/{final.get('claims_total')} · Audit intègre : {outcome.audit['ok']}")
    print(f"Rapport : {outcome.files.get('markdown')}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(_main())
