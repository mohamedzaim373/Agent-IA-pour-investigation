"""Classification des observables (interne / externe) partagée par la politique,
la pseudonymisation et l'extraction d'entités."""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

# Plages considérées comme internes au laboratoire / à l'organisation.
# On n'utilise pas `ip.is_private`, qui classe aussi les plages de
# documentation (TEST-NET) comme privées.
INTERNAL_NETWORKS = [
    ipaddress.ip_network(n)
    for n in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "100.64.0.0/10",
        "0.0.0.0/8",
        "::1/128",
        "fc00::/7",
        "fe80::/10",
    )
]

IPV4_RE = re.compile(r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\d.])")
DOMAIN_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,24})\b", re.IGNORECASE)
URL_RE = re.compile(r"\bhttps?://[^\s\"'<>|]+", re.IGNORECASE)
SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
SHA1_RE = re.compile(r"\b[a-fA-F0-9]{40}\b")
MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,24}\b")

# Extensions de fichiers fréquentes qui ressemblent à des domaines.
FILE_EXTENSIONS = {
    "exe", "dll", "ps1", "bat", "cmd", "vbs", "js", "txt", "log", "dat", "tmp", "sys", "zip",
    "msi", "lnk", "xml", "json", "ini", "cfg", "evtx", "hta", "doc", "docx", "xls", "xlsx",
    "pdf", "png", "jpg", "local", "csv", "py", "sh", "bin", "dmp", "conf", "yaml", "yml",
}


def parse_ip(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(value.strip())
    except ValueError:
        return None


def is_internal_ip(value: str) -> bool:
    ip = parse_ip(value)
    return bool(ip) and any(ip in net for net in INTERNAL_NETWORKS)


def is_internal_domain(value: str, internal_domains: list[str] | tuple[str, ...] = ("lab.local",)) -> bool:
    v = value.strip().lower().rstrip(".")
    if "." not in v:  # nom court NetBIOS : forcément interne
        return True
    return any(v == d or v.endswith("." + d) for d in internal_domains) or v.endswith(".local")


def url_host(value: str) -> str:
    try:
        return (urlsplit(value).hostname or "").lower()
    except ValueError:
        return ""


def is_internal_observable(value: str, otype: str, internal_domains: list[str] | tuple[str, ...] = ("lab.local",)) -> bool:
    """Vrai si l'observable désigne une ressource interne qui ne doit pas sortir (GP-08)."""
    otype = otype.lower()
    if otype == "ip":
        return is_internal_ip(value)
    if otype == "domain":
        return is_internal_domain(value, internal_domains)
    if otype == "url":
        host = url_host(value)
        if not host:
            return True
        return is_internal_ip(host) if parse_ip(host) else is_internal_domain(host, internal_domains)
    if otype in {"user", "host", "email"}:
        return True
    return False  # empreintes de fichiers : pas de donnée personnelle


def looks_like_domain(value: str) -> bool:
    v = value.lower().rstrip(".")
    if not DOMAIN_RE.fullmatch(v):
        return False
    return v.rsplit(".", 1)[-1] not in FILE_EXTENSIONS or v.endswith(".local")


def hash_type(value: str) -> str | None:
    v = value.strip()
    if SHA256_RE.fullmatch(v):
        return "sha256"
    if SHA1_RE.fullmatch(v):
        return "sha1"
    if MD5_RE.fullmatch(v):
        return "md5"
    return None
