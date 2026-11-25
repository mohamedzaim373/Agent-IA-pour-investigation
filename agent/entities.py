"""Ingestion de l'alerte (EF-01) et extraction des observables (EF-02).

Accepte une alerte Wazuh au format JSON ou une saisie manuelle :

    {"manual": true, "title": "...", "host": "WIN10-01", "user": "LAB\\jdoe",
     "timestamp": "2026-10-12T09:14:03Z", "description": "...",
     "observables": [{"type": "ip", "value": "203.0.113.45"}]}
"""

from __future__ import annotations

import base64
import binascii
import re
from typing import Any

from connectors.base import to_iso_utc
from connectors.wazuh import normalize_event
from gateway.observables import (
    DOMAIN_RE,
    IPV4_RE,
    SHA256_RE,
    URL_RE,
    hash_type,
    is_internal_domain,
    is_internal_ip,
    looks_like_domain,
    url_host,
)

REGISTRY_RE = re.compile(r"\b(?:HK(?:LM|CU|CR|U)|HKEY_[A-Z_]+)\\[^\s\"']+", re.IGNORECASE)
WIN_PATH_RE = re.compile(r"[A-Za-z]:\\(?:[^\\/:*?\"<>|\r\n\s]+\\)*[^\\/:*?\"<>|\r\n\s]+\.[A-Za-z0-9]{2,4}")


ENC_RE = re.compile(r"\s-(?:e|en|enc|enco|encod\w*)\s+([A-Za-z0-9+/=]{16,})", re.IGNORECASE)


class AlertFormatError(ValueError):
    pass


def decode_powershell(command_line: str) -> str:
    """Décode une commande PowerShell -EncodedCommand (Base64 UTF-16LE), pour en extraire les observables."""
    m = ENC_RE.search(command_line or "")
    if not m:
        return ""
    try:
        raw = base64.b64decode(m.group(1) + "=" * (-len(m.group(1)) % 4))
        return raw.decode("utf-16-le", errors="ignore")
    except (ValueError, binascii.Error):
        return ""


def normalize_alert(alert: dict[str, Any]) -> dict[str, Any]:
    """Renvoie l'alerte sous forme d'élément normalisé (même format que les journaux)."""
    if not isinstance(alert, dict):
        raise AlertFormatError("l'alerte doit être un objet JSON")
    if alert.get("manual"):
        missing = [k for k in ("host", "timestamp") if not alert.get(k)]
        if missing:
            raise AlertFormatError(f"saisie manuelle incomplète : {', '.join(missing)}")
        return {
            "source": "manual",
            "raw_ref": alert.get("id") or "manual-alert",
            "timestamp": to_iso_utc(alert["timestamp"]),
            "host": str(alert["host"]).split(".")[0],
            "event_type": "manual_alert",
            "fields": {"user": alert.get("user"), "command_line": alert.get("command_line"),
                       "image": alert.get("image"), "description": alert.get("description")},
            "rule": {"id": "manual", "level": int(alert.get("level", 8)), "description": alert.get("title", "Alerte manuelle"),
                     "mitre": []},
            "summary": f"[Alerte manuelle] {alert.get('title', '')} — {alert.get('description', '')}".strip(),
            "manual_observables": alert.get("observables", []),
        }
    src = alert.get("_source", alert)
    if not src.get("rule") or not (src.get("timestamp") or src.get("@timestamp")):
        raise AlertFormatError("alerte Wazuh invalide : champs « rule » et « timestamp » requis")
    item = normalize_event(alert)
    if not item.get("host"):
        raise AlertFormatError("alerte Wazuh invalide : hôte (agent.name) absent")
    return item


def _add(obs: list[dict[str, Any]], seen: set[tuple[str, str]], otype: str, value: Any, origin: str,
         internal: bool | None = None) -> None:
    if value in (None, ""):
        return
    v = str(value).strip().strip("'\"")
    if not v:
        return
    key = (otype, v.lower())
    if key in seen:
        return
    seen.add(key)
    obs.append({"type": otype, "value": v, "internal": bool(internal) if internal is not None else False,
                "origin": origin})


def extract_observables(item: dict[str, Any], internal_domains: list[str] | None = None) -> list[dict[str, Any]]:
    """Observables d'un élément normalisé : champs structurés puis texte libre."""
    domains = internal_domains or ["lab.local"]
    obs: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    f = item.get("fields") or {}

    if item.get("host"):
        _add(obs, seen, "host", item["host"], "host", True)
    for key in ("user", "subject_user", "target_user"):
        if f.get(key) and str(f[key]).upper() not in {"SYSTEM", "NT AUTHORITY\\SYSTEM", "-"}:
            _add(obs, seen, "user", f[key], key, True)
    for key in ("image", "parent_image"):
        if f.get(key):
            _add(obs, seen, "process", f[key], key, True)
    for key in ("destination_ip", "source_ip"):
        if f.get(key):
            _add(obs, seen, "ip", f[key], key, is_internal_ip(str(f[key])))
    for key in ("destination_hostname", "query_name"):
        if f.get(key) and looks_like_domain(str(f[key])):
            _add(obs, seen, "domain", f[key], key, is_internal_domain(str(f[key]), domains))
    hashes = f.get("hashes") if isinstance(f.get("hashes"), dict) else {}
    best = ("sha256", f.get("sha256")) if f.get("sha256") else next(
        ((a, hashes[a]) for a in ("sha1", "md5") if hashes.get(a)), (None, None))
    if best[1]:  # une seule empreinte par fichier, la plus forte
        before = len(obs)
        _add(obs, seen, best[0], best[1], "hashes", False)
        if len(obs) > before:
            obs[-1]["context"] = f.get("image")
    if f.get("target_filename"):
        _add(obs, seen, "filename", f["target_filename"], "target_filename", True)
    if f.get("target_object"):
        _add(obs, seen, "registry", f["target_object"], "target_object", True)

    for m in item.get("manual_observables") or []:
        otype, value = m.get("type"), m.get("value")
        if otype and value:
            internal = is_internal_ip(value) if otype == "ip" else (
                is_internal_domain(value, domains) if otype == "domain" else otype in {"user", "host"})
            _add(obs, seen, otype, value, "manual", internal)

    text = " ".join(str(f.get(k, "")) for k in ("command_line", "parent_command_line", "details", "query_results",
                                                 "script_block", "description", "task_content"))
    decoded = decode_powershell(str(f.get("command_line") or ""))
    if decoded:
        text += " " + decoded
    for url in URL_RE.findall(text):
        url = url.rstrip(").,;'\"")
        host = url_host(url)
        internal = is_internal_ip(host) if IPV4_RE.fullmatch(host or "") else is_internal_domain(host or "x", domains)
        _add(obs, seen, "url", url, "command_line", internal)
        if host and IPV4_RE.fullmatch(host):
            _add(obs, seen, "ip", host, "url", is_internal_ip(host))
        elif host and looks_like_domain(host):
            _add(obs, seen, "domain", host, "url", internal)
    for ip in IPV4_RE.findall(text):
        _add(obs, seen, "ip", ip, "text", is_internal_ip(ip))
    for d in DOMAIN_RE.findall(text):
        if looks_like_domain(d) and not IPV4_RE.fullmatch(d):
            _add(obs, seen, "domain", d.lower(), "text", is_internal_domain(d, domains))
    for h in SHA256_RE.findall(text):
        _add(obs, seen, hash_type(h) or "sha256", h.lower(), "text", False)
    for path in WIN_PATH_RE.findall(text):
        if path.lower().endswith((".exe", ".dll", ".ps1", ".bat", ".vbs", ".hta", ".dmp", ".js")):
            _add(obs, seen, "filename", path, "text", True)
    for reg in REGISTRY_RE.findall(text):
        _add(obs, seen, "registry", reg, "text", True)
    return obs


def entities_summary(observables: list[dict[str, Any]]) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for o in observables:
        out.setdefault(o["type"], [])
        if o["value"] not in out[o["type"]]:
            out[o["type"]].append(o["value"])
    return out


def external_observables(observables: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Observables pouvant être vérifiés dans MISP et la TI externe."""
    return [o for o in observables if o["type"] in {"ip", "domain", "url", "sha256", "sha1", "md5"} and not o["internal"]]
