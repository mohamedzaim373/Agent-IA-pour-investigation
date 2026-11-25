"""Pseudonymisation des données personnelles avant envoi externe (GP-08).

Lorsque le LLM est un service externe (API), les comptes, noms d'hôte,
adresses e-mail et IP internes sont remplacés par des pseudonymes stables
(HMAC-SHA256 avec un secret propre au déploiement). La table de
correspondance reste locale : la réponse du modèle est ré-identifiée avant
d'être utilisée. Les observables externes (IP publiques, domaines malveillants,
empreintes) sont conservés, car ils sont nécessaires au raisonnement.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
import threading
from typing import Any

from gateway.observables import EMAIL_RE, IPV4_RE, is_internal_ip

PREFIXES = {"user": "USER", "host": "HOST", "ip": "IP", "email": "EMAIL"}
DOMAIN_USER_RE = re.compile(r"\b([A-Za-z][A-Za-z0-9-]{0,14})\\([A-Za-z0-9._$-]{1,64})\b")
TOKEN_RE = re.compile(r"\b(?:USER|HOST|IP|EMAIL)_[0-9a-f]{8}\b")


class Pseudonymizer:
    def __init__(self, secret: str | bytes | None = None, internal_domains: list[str] | None = None):
        if not secret:
            secret = secrets.token_bytes(32)
        self._secret = secret.encode() if isinstance(secret, str) else secret
        self.internal_domains = [d.lower() for d in (internal_domains or ["lab.local"])]
        self._forward: dict[str, str] = {}  # valeur (minuscules) -> pseudonyme
        self._reverse: dict[str, str] = {}  # pseudonyme -> valeur d'origine
        self._lock = threading.Lock()
        domains = "|".join(re.escape(d) for d in self.internal_domains + ["local"])
        self._fqdn_re = re.compile(rf"\b(?:[A-Za-z0-9-]+\.)+(?:{domains})\b", re.IGNORECASE)

    # ---------------------------------------------------------------- registre
    def token(self, kind: str, value: str) -> str:
        key = value.strip().lower()
        with self._lock:
            existing = self._forward.get(key)
            if existing:
                return existing
            digest = hmac.new(self._secret, f"{kind}:{key}".encode(), hashlib.sha256).hexdigest()[:8]
            tok = f"{PREFIXES.get(kind, 'ID')}_{digest}"
            self._forward[key] = tok
            self._reverse[tok] = value.strip()
            return tok

    def register(self, kind: str, value: str | None) -> None:
        if value and len(value.strip()) >= 2:
            self.token(kind, value)
            if kind == "user" and "\\" in value:  # LAB\jdoe -> enregistrer aussi jdoe
                self.token(kind, value.split("\\", 1)[1])
            if kind == "host" and "." in value:  # WIN10-01.lab.local -> WIN10-01
                self.token(kind, value.split(".", 1)[0])

    @property
    def mapping(self) -> dict[str, str]:
        return dict(self._reverse)

    # ------------------------------------------------------------ transformation
    def pseudonymize_text(self, text: str) -> str:
        if not text:
            return text
        out = DOMAIN_USER_RE.sub(lambda m: self.token("user", m.group(0)), text)
        out = EMAIL_RE.sub(lambda m: self.token("email", m.group(0)), out)
        out = self._fqdn_re.sub(lambda m: self.token("host", m.group(0)), out)
        out = IPV4_RE.sub(lambda m: self.token("ip", m.group(0)) if is_internal_ip(m.group(0)) else m.group(0), out)
        with self._lock:
            known = sorted(self._forward.items(), key=lambda kv: len(kv[0]), reverse=True)
        for value, tok in known:
            if len(value) < 3:
                continue
            out = re.sub(rf"(?<![\w-]){re.escape(value)}(?![\w-])", tok, out, flags=re.IGNORECASE)
        return out

    def restore_text(self, text: str) -> str:
        if not text:
            return text
        return TOKEN_RE.sub(lambda m: self._reverse.get(m.group(0), m.group(0)), text)

    def pseudonymize_obj(self, obj: Any) -> Any:
        return _map_strings(obj, self.pseudonymize_text)

    def restore_obj(self, obj: Any) -> Any:
        return _map_strings(obj, self.restore_text)


def _map_strings(obj: Any, fn) -> Any:
    if isinstance(obj, str):
        return fn(obj)
    if isinstance(obj, dict):
        return {k: _map_strings(v, fn) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_map_strings(v, fn) for v in obj]
    if isinstance(obj, tuple):
        return tuple(_map_strings(v, fn) for v in obj)
    return obj
