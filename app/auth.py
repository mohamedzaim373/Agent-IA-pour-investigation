"""Authentification de l'interface et de l'API (ENF-05, GP-03).

Chaque analyste dispose d'un jeton d'accès personnel. Seule l'empreinte SHA-256
du jeton est conservée (investigation_lab/data/tokens.json, hors du dépôt).
"""

from __future__ import annotations

import hmac
import json
import secrets
import threading
from pathlib import Path

from gateway.hashing import sha256_hex


class TokenStore:
    def __init__(self, path: Path):
        self.path = Path(path)
        self._lock = threading.Lock()

    def _load(self) -> dict[str, str]:
        if not self.path.exists():
            return {}
        try:
            return json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}

    def issue(self, analyst_id: str) -> str:
        """Crée un jeton pour l'analyste et renvoie sa valeur (affichée une seule fois)."""
        token = secrets.token_urlsafe(32)
        with self._lock:
            data = self._load()
            data[sha256_hex(token)] = analyst_id
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(json.dumps(data, indent=2), encoding="utf-8")
            try:
                self.path.chmod(0o600)
            except OSError:  # pragma: no cover - systèmes sans chmod
                pass
        return token

    def revoke(self, analyst_id: str) -> int:
        with self._lock:
            data = self._load()
            kept = {h: a for h, a in data.items() if a != analyst_id}
            self.path.write_text(json.dumps(kept, indent=2), encoding="utf-8")
        return len(data) - len(kept)

    def verify(self, token: str | None) -> str | None:
        if not token:
            return None
        digest = sha256_hex(token)
        for known, analyst in self._load().items():
            if hmac.compare_digest(known, digest):
                return analyst
        return None
