"""Téléchargement et lecture du référentiel MITRE ATT&CK Enterprise (STIX 2.1).

Produit une base de connaissances compacte (rag/data/attack_kb.json.gz) :
techniques et sous-techniques actives, tactiques, plateformes, description,
analytiques de détection (stratégies de détection ATT&CK v18+) et exemples de
procédures (relations « uses » des groupes, logiciels et campagnes).

    python -m rag.attack_loader --download            # télécharge puis construit
    python -m rag.attack_loader --stix enterprise-attack.json

© The MITRE Corporation. ATT&CK® est reproduit et distribué avec l'autorisation
de The MITRE Corporation (https://attack.mitre.org/resources/legal-and-branding/terms-of-use/).
"""

from __future__ import annotations

import argparse
import gzip
import json
import re
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests

STIX_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
DEFAULT_KB = Path(__file__).resolve().parent / "data" / "attack_kb.json.gz"

_CITATION_RE = re.compile(r"\(Citation:[^)]*\)")
_LINK_RE = re.compile(r"\[([^\]]+)\]\((?:https?://)?[^)]*\)")
_TAG_RE = re.compile(r"</?code>|<br\s*/?>")
_WS_RE = re.compile(r"[ \t]+")


def clean_text(text: str | None) -> str:
    if not text:
        return ""
    t = _CITATION_RE.sub("", text)
    t = _LINK_RE.sub(r"\1", t)
    t = _TAG_RE.sub("", t)
    t = _WS_RE.sub(" ", t)
    t = re.sub(r"\n{3,}", "\n\n", t)
    return t.strip()


def _external_id(obj: dict[str, Any]) -> tuple[str | None, str | None]:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id"), ref.get("url")
    return None, None


def _active(obj: dict[str, Any]) -> bool:
    return not obj.get("revoked") and not obj.get("x_mitre_deprecated")


def parse_stix(bundle: dict[str, Any], max_procedures: int = 6, max_analytics: int = 3) -> dict[str, Any]:
    objects = bundle.get("objects", [])
    by_id = {o["id"]: o for o in objects}
    tactics = {o["x_mitre_shortname"]: o["name"] for o in objects if o.get("type") == "x-mitre-tactic" and _active(o)}

    procedures: dict[str, list[dict[str, str]]] = defaultdict(list)
    detections: dict[str, list[dict[str, Any]]] = defaultdict(list)
    mitigations: dict[str, list[str]] = defaultdict(list)
    for rel in objects:
        if rel.get("type") != "relationship" or not _active(rel):
            continue
        rtype, src, tgt = rel.get("relationship_type"), by_id.get(rel.get("source_ref")), rel.get("target_ref")
        if src is None or not _active(src):
            continue
        if rtype == "uses" and src.get("type") in {"intrusion-set", "malware", "tool", "campaign"} and rel.get("description"):
            procedures[tgt].append({"actor": src.get("name", "?"), "kind": src["type"],
                                    "text": clean_text(rel["description"])})
        elif rtype == "detects" and src.get("type") == "x-mitre-detection-strategy":
            for aref in src.get("x_mitre_analytic_refs", []):
                analytic = by_id.get(aref)
                if analytic and analytic.get("description"):
                    detections[tgt].append({"platforms": analytic.get("x_mitre_platforms", []),
                                            "text": clean_text(analytic["description"]),
                                            "strategy": src.get("name", "")})
        elif rtype == "mitigates" and src.get("type") == "course-of-action":
            mitigations[tgt].append(src.get("name", ""))

    techniques = []
    latest = ""
    for obj in objects:
        if obj.get("type") != "attack-pattern" or not _active(obj):
            continue
        tid, url = _external_id(obj)
        if not tid:
            continue
        latest = max(latest, obj.get("modified", ""))
        dets = sorted(detections.get(obj["id"], []), key=lambda d: (0 if "Windows" in d["platforms"] else 1))
        procs = sorted(procedures.get(obj["id"], []), key=lambda p: (p["kind"] != "intrusion-set", len(p["text"])))
        techniques.append({
            "id": tid,
            "name": obj["name"],
            "parent": tid.split(".")[0] if "." in tid else None,
            "is_subtechnique": bool(obj.get("x_mitre_is_subtechnique")),
            "tactics": [k["phase_name"] for k in obj.get("kill_chain_phases", [])
                        if k.get("kill_chain_name") == "mitre-attack"],
            "platforms": obj.get("x_mitre_platforms", []),
            "description": clean_text(obj.get("description")),
            "detection": [d["text"] for d in dets[:max_analytics]],
            "procedures": [f"{p['actor']} : {p['text']}" for p in procs[:max_procedures]],
            "mitigations": sorted(set(mitigations.get(obj["id"], [])))[:8],
            "url": url,
        })
    parents = {t["id"]: t["name"] for t in techniques if not t["is_subtechnique"]}
    for t in techniques:
        if t["parent"]:
            t["parent_name"] = parents.get(t["parent"])
    techniques.sort(key=lambda t: t["id"])
    return {
        "source": "MITRE ATT&CK Enterprise (STIX 2.1)",
        "version": f"enterprise-attack@{latest[:10]}",
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "license": "© The MITRE Corporation — ATT&CK terms of use",
        "tactics": tactics,
        "techniques": techniques,
    }


def save_kb(kb: dict[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = json.dumps(kb, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if path.suffix == ".gz":
        with gzip.open(path, "wb", compresslevel=9) as fh:
            fh.write(data)
    else:
        path.write_bytes(data)


def load_kb(path: Path | str = DEFAULT_KB) -> dict[str, Any]:
    path = Path(path)
    raw = gzip.open(path, "rb").read() if path.suffix == ".gz" else path.read_bytes()
    return json.loads(raw.decode("utf-8"))


def download_stix(dest: Path, url: str = STIX_URL, timeout: float = 120) -> Path:
    resp = requests.get(url, timeout=timeout)
    resp.raise_for_status()
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(resp.content)
    return dest


def _main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Construire la base ATT&CK du RAG")
    parser.add_argument("--stix", type=Path, help="fichier enterprise-attack.json local")
    parser.add_argument("--download", action="store_true", help="télécharger le STIX depuis GitHub (mitre/cti)")
    parser.add_argument("--output", type=Path, default=DEFAULT_KB)
    parser.add_argument("--max-procedures", type=int, default=6)
    args = parser.parse_args(argv)
    stix_path = args.stix
    if args.download or stix_path is None:
        stix_path = download_stix(Path("investigation_lab/data/enterprise-attack.json"))
        print(f"STIX téléchargé : {stix_path}")
    kb = parse_stix(json.loads(stix_path.read_text(encoding="utf-8")), max_procedures=args.max_procedures)
    save_kb(kb, args.output)
    print(f"{len(kb['techniques'])} techniques, version {kb['version']} -> {args.output}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(_main())
