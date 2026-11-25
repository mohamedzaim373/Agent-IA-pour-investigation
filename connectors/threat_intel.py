"""Enrichissement Threat Intelligence : VirusTotal et AbuseIPDB (EF-08).

Les réponses des deux services sont normalisées vers un même format
(verdict malicious / suspicious / benign / unknown, score, détails) et mises en
cache en base pour économiser les quotas des offres gratuites.
"""

from __future__ import annotations

import base64
import json
import time
from typing import Any, Callable

import requests
from sqlalchemy import select

from connectors.base import ConnectorError, http_json, to_iso_utc
from evidence.db import get_engine, ti_cache
from gateway.tool_schemas import TiLookupArgs

VERSION = "1.0"

VT_PATHS = {"ip": "ip_addresses", "domain": "domains", "url": "urls", "sha256": "files", "sha1": "files", "md5": "files"}


# ----------------------------------------------------------------- normalisation
def normalize_virustotal(value: str, otype: str, data: dict[str, Any] | None) -> dict[str, Any]:
    if not data:
        return {"source": "virustotal", "value": value, "type": otype, "verdict": "unknown", "found": False,
                "summary": f"VirusTotal : {value} inconnu"}
    attrs = (data.get("data") or {}).get("attributes") or {}
    stats = attrs.get("last_analysis_stats") or {}
    mal, sus = int(stats.get("malicious", 0)), int(stats.get("suspicious", 0))
    harmless = int(stats.get("harmless", 0))
    total = sum(int(v) for v in stats.values()) if stats else 0
    if mal >= 3:
        verdict = "malicious"
    elif mal >= 1 or sus >= 2:
        verdict = "suspicious"
    elif harmless > 0 or total > 0:
        verdict = "benign"
    else:
        verdict = "unknown"
    item = {
        "source": "virustotal",
        "value": value,
        "type": otype,
        "found": True,
        "verdict": verdict,
        "score": mal,
        "detections": f"{mal}/{total}" if total else "0/0",
        "reputation": attrs.get("reputation"),
        "tags": attrs.get("tags", [])[:10],
        "last_analysis": to_iso_utc(attrs.get("last_analysis_date")) if attrs.get("last_analysis_date") else None,
    }
    if attrs.get("as_owner"):
        item["as_owner"] = attrs["as_owner"]
    if attrs.get("country"):
        item["country"] = attrs["country"]
    if attrs.get("meaningful_name"):
        item["file_name"] = attrs["meaningful_name"]
    item["summary"] = f"VirusTotal : {value} — {item['detections']} moteurs malveillants (verdict {verdict})"
    return item


def normalize_abuseipdb(value: str, data: dict[str, Any] | None) -> dict[str, Any]:
    d = (data or {}).get("data") or {}
    if not d:
        return {"source": "abuseipdb", "value": value, "type": "ip", "verdict": "unknown", "found": False,
                "summary": f"AbuseIPDB : {value} inconnu"}
    score = int(d.get("abuseConfidenceScore", 0))
    reports = int(d.get("totalReports", 0))
    verdict = "malicious" if score >= 75 else "suspicious" if score >= 25 else ("benign" if reports == 0 or score < 10 else "unknown")
    item = {
        "source": "abuseipdb",
        "value": value,
        "type": "ip",
        "found": True,
        "verdict": verdict,
        "score": score,
        "total_reports": reports,
        "country": d.get("countryCode"),
        "isp": d.get("isp"),
        "usage_type": d.get("usageType"),
        "last_reported": to_iso_utc(d.get("lastReportedAt")) if d.get("lastReportedAt") else None,
    }
    item["summary"] = f"AbuseIPDB : {value} — score de confiance {score}/100, {reports} signalement(s) (verdict {verdict})"
    return item


# ----------------------------------------------------------------------- clients
class VirusTotalClient:
    BASE = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key: str, timeout: float = 20):
        self.api_key = api_key
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({"x-apikey": api_key, "Accept": "application/json"})

    def fetch(self, value: str, otype: str) -> dict[str, Any] | None:
        ident = base64.urlsafe_b64encode(value.encode()).decode().rstrip("=") if otype == "url" else value
        return http_json(self.session, "GET", f"{self.BASE}/{VT_PATHS[otype]}/{ident}", timeout=self.timeout,
                         expected_404=True)


class AbuseIPDBClient:
    BASE = "https://api.abuseipdb.com/api/v2"

    def __init__(self, api_key: str, timeout: float = 20):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({"Key": api_key, "Accept": "application/json"})

    def fetch(self, value: str) -> dict[str, Any] | None:
        return http_json(self.session, "GET", f"{self.BASE}/check", params={"ipAddress": value, "maxAgeInDays": 90},
                         timeout=self.timeout)


# ------------------------------------------------------------------------- cache
class TICache:
    def __init__(self, db_url: str, ttl_s: int = 86400):
        self.engine = get_engine(db_url)
        self.ttl_s = ttl_s

    @staticmethod
    def key(provider: str, value: str) -> str:
        return f"{provider}:{value.strip().lower()}"[:256]

    def get(self, provider: str, value: str) -> dict[str, Any] | None:
        with self.engine.connect() as conn:
            row = conn.execute(select(ti_cache).where(ti_cache.c.key == self.key(provider, value))).mappings().first()
        if not row or time.time() - row["fetched_at"] > self.ttl_s:
            return None
        return json.loads(row["response_json"])

    def put(self, provider: str, value: str, item: dict[str, Any]) -> None:
        k = self.key(provider, value)
        with self.engine.begin() as conn:
            conn.execute(ti_cache.delete().where(ti_cache.c.key == k))
            conn.execute(ti_cache.insert().values(key=k, provider=provider, value=value[:512],
                                                  response_json=json.dumps(item, ensure_ascii=False),
                                                  fetched_at=time.time()))


# ----------------------------------------------------------------------- service
class ThreatIntelService:
    VERSION = VERSION

    def __init__(self, *, virustotal: VirusTotalClient | None, abuseipdb: AbuseIPDBClient | None,
                 cache: TICache | None = None):
        self.providers: dict[str, Callable[[str, str], dict[str, Any]]] = {}
        if virustotal is not None:
            self.providers["virustotal"] = lambda v, t: normalize_virustotal(v, t, virustotal.fetch(v, t))
        if abuseipdb is not None:
            self.providers["abuseipdb"] = lambda v, t: normalize_abuseipdb(v, abuseipdb.fetch(v))
        self.cache = cache

    def lookup(self, args: TiLookupArgs) -> dict[str, Any]:
        otype = args.type.value
        items: list[dict[str, Any]] = []
        errors: dict[str, str] = {}
        for provider in args.providers:
            if provider == "abuseipdb" and otype != "ip":
                continue
            fn = self.providers.get(provider)
            if fn is None:
                errors[provider] = "clé d'API non configurée"
                continue
            cached = self.cache.get(provider, args.value) if self.cache else None
            if cached is not None:
                items.append(dict(cached, cached=True))
                continue
            try:
                item = fn(args.value, otype)
            except ConnectorError as exc:
                errors[provider] = str(exc)
                continue
            item["raw_ref"] = f"{provider}:{args.value}"
            if self.cache:
                self.cache.put(provider, args.value, item)
            items.append(item)
        if not items and errors and len(errors) == len([p for p in args.providers
                                                        if not (p == "abuseipdb" and otype != "ip")]):
            raise ConnectorError("aucune source de TI disponible : " + "; ".join(f"{k}: {v}" for k, v in errors.items()),
                                 transient=any("quota" in v or "indisponible" in v for v in errors.values()))
        return {"items": items, "meta": {"queried": args.value, "errors": errors}}
