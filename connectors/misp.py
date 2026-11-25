"""Connecteur MISP : recherche d'observables dans la base d'IOC (EF-09).

Utilise l'API REST /attributes/restSearch (lecture seule). La clé d'API est
détenue par le connecteur et injectée dans l'en-tête Authorization (GP-06).
"""

from __future__ import annotations

from typing import Any

import requests

from connectors.base import http_json, to_iso_utc
from gateway.tool_schemas import MispLookupArgs

VERSION = "1.0"

THREAT_LEVELS = {"1": "élevé", "2": "moyen", "3": "faible", "4": "non défini"}


def normalize_attribute(attr: dict[str, Any], queried: str) -> dict[str, Any]:
    event = attr.get("Event") or {}
    tags = [t.get("name") for t in (attr.get("Tag") or []) + (event.get("Tag") or []) if t.get("name")]
    threat = THREAT_LEVELS.get(str(event.get("threat_level_id", "4")), "non défini")
    to_ids = bool(attr.get("to_ids"))
    verdict = "malicious" if to_ids and threat in {"élevé", "moyen"} else ("suspicious" if to_ids else "known")
    info = event.get("info") or "?"
    return {
        "source": "misp",
        "raw_ref": f"misp-attr-{attr.get('id', '?')}",
        "timestamp": to_iso_utc(attr.get("timestamp")) if attr.get("timestamp") else None,
        "value": attr.get("value", queried),
        "queried": queried,
        "type": attr.get("type"),
        "category": attr.get("category"),
        "to_ids": to_ids,
        "event_id": str(event.get("id") or attr.get("event_id") or ""),
        "event_info": info,
        "threat_level": threat,
        "tags": sorted(set(tags)),
        "verdict": verdict,
        "summary": f"IOC présent dans MISP : {attr.get('value', queried)} — événement {event.get('id', '?')} "
                   f"« {info} » (menace {threat}, to_ids={to_ids})",
    }


class MispConnector:
    VERSION = VERSION

    def __init__(self, url: str, key: str, verify_tls: bool = False, timeout: float = 15):
        self.url = url.rstrip("/")
        self.timeout = timeout
        self.session = requests.Session()
        self.session.verify = verify_tls
        self.session.headers.update({"Authorization": key, "Accept": "application/json",
                                     "Content-Type": "application/json"})

    def lookup(self, args: MispLookupArgs) -> dict[str, Any]:
        body = {"returnFormat": "json", "value": args.value, "limit": 20, "includeEventTags": True,
                "includeContext": True}
        data = http_json(self.session, "POST", f"{self.url}/attributes/restSearch", json=body, timeout=self.timeout)
        attrs = ((data or {}).get("response") or {}).get("Attribute") or []
        items = [normalize_attribute(a, args.value) for a in attrs]
        meta = {"queried": args.value, "found": bool(items)}
        if not items:
            meta["note"] = f"{args.value} absent de MISP"
        return {"items": items, "meta": meta}
