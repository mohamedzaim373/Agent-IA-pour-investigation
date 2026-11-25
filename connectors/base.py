"""Éléments communs aux connecteurs.

Contrat : chaque connecteur expose des méthodes qui reçoivent un modèle de
paramètres validé (gateway.tool_schemas) et renvoient
    {"items": [élément normalisé, ...], "meta": {...}}
Chaque élément porte au minimum `source` et `summary`, et si possible
`timestamp` (ISO 8601 UTC), `host`, `event_type` et `raw_ref`.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import requests


class ConnectorError(RuntimeError):
    """Erreur d'un connecteur. `transient=True` autorise une nouvelle tentative."""

    def __init__(self, message: str, *, transient: bool = False):
        super().__init__(message)
        self.transient = transient


def to_iso_utc(value: Any) -> str | None:
    """Normalise un horodatage (ISO, Wazuh « +0000 », epoch) en ISO 8601 UTC."""
    if value in (None, ""):
        return None
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(float(value), tz=timezone.utc).isoformat(timespec="milliseconds")
    if isinstance(value, datetime):
        dt = value
    else:
        text = str(value).strip().replace(" ", "T", 1) if "T" not in str(value) else str(value).strip()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        # Wazuh : 2026-10-12T09:14:03.123+0000 -> +00:00
        if len(text) > 5 and text[-5] in "+-" and text[-4:].isdigit() and text[-3] != ":":
            text = text[:-2] + ":" + text[-2:]
        # fractions de seconde sur 7 chiffres (Windows) -> 6
        if "." in text:
            head, _, tail = text.partition(".")
            digits = "".join(ch for ch in tail if ch.isdigit())
            rest = tail[len(digits):]
            text = f"{head}.{digits[:6]}{rest}"
        try:
            dt = datetime.fromisoformat(text)
        except ValueError:
            return str(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat(timespec="milliseconds")


def parse_iso(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        iso = to_iso_utc(value)
        return datetime.fromisoformat(iso) if iso else None
    except (TypeError, ValueError):
        return None


def http_json(
    session: requests.Session,
    method: str,
    url: str,
    *,
    timeout: float = 15,
    expected_404: bool = False,
    **kwargs: Any,
) -> Any:
    """Requête HTTP renvoyant du JSON, avec des erreurs explicites et classées."""
    try:
        resp = session.request(method, url, timeout=timeout, **kwargs)
    except requests.Timeout as exc:
        raise ConnectorError(f"délai dépassé vers {url.split('?')[0]}", transient=True) from exc
    except requests.ConnectionError as exc:
        raise ConnectorError(f"service indisponible : {url.split('?')[0]}", transient=True) from exc
    if resp.status_code == 404 and expected_404:
        return None
    if resp.status_code == 429:
        raise ConnectorError("quota de l'API atteint (HTTP 429)", transient=True)
    if resp.status_code in (401, 403):
        raise ConnectorError(f"accès refusé (HTTP {resp.status_code}) : vérifier la clé ou les droits")
    if resp.status_code >= 500:
        raise ConnectorError(f"erreur du service (HTTP {resp.status_code})", transient=True)
    if resp.status_code >= 400:
        raise ConnectorError(f"requête rejetée (HTTP {resp.status_code}) : {resp.text[:200]}")
    try:
        return resp.json()
    except ValueError as exc:
        raise ConnectorError("réponse non JSON") from exc


def truncate(text: Any, n: int = 300) -> str:
    s = "" if text is None else str(text)
    return s if len(s) <= n else s[: n - 1] + "…"
