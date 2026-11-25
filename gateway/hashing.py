"""Empreintes canoniques partagées par l'audit et la mémoire de preuves."""

from __future__ import annotations

import hashlib
import json
from datetime import date, datetime
from typing import Any

GENESIS_HASH = "0" * 64


def _default(obj: Any) -> Any:
    if isinstance(obj, (datetime, date)):
        return obj.isoformat()
    if hasattr(obj, "model_dump"):
        return obj.model_dump(mode="json")
    if isinstance(obj, (set, frozenset)):
        return sorted(obj)
    return str(obj)


def canonical_json(obj: Any) -> str:
    """JSON déterministe : clés triées, séparateurs compacts, UTF-8 conservé."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=_default)


def sha256_hex(data: str | bytes) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def hash_obj(obj: Any) -> str:
    return sha256_hex(canonical_json(obj))
