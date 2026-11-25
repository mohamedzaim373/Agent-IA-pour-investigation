"""Interface commune des modèles de langage (ENF-07).

Tous les clients exposent `generate(task, system, user, context)` et renvoient
un dictionnaire JSON. `context` contient les mêmes informations que le prompt
sous forme structurée : seul le modèle hors ligne (règles) l'utilise.
"""

from __future__ import annotations

import json
import re
import threading
from typing import Any

from gateway.privacy import Pseudonymizer


class LLMError(RuntimeError):
    pass


class BaseLLM:
    provider = "base"
    model = "none"

    def __init__(self) -> None:
        self.usage = {"calls": 0, "prompt_tokens": 0, "completion_tokens": 0}
        self._usage_lock = threading.Lock()

    @property
    def total_tokens(self) -> int:
        return self.usage["prompt_tokens"] + self.usage["completion_tokens"]

    def _count(self, prompt_tokens: int, completion_tokens: int) -> None:
        with self._usage_lock:
            self.usage["calls"] += 1
            self.usage["prompt_tokens"] += int(prompt_tokens or 0)
            self.usage["completion_tokens"] += int(completion_tokens or 0)

    def generate(self, task: str, system: str, user: str, context: dict[str, Any] | None = None) -> dict[str, Any]:
        raise NotImplementedError


_FENCE_RE = re.compile(r"^```(?:json)?\s*|\s*```$", re.MULTILINE)


def parse_json_object(text: str) -> dict[str, Any]:
    """Extrait un objet JSON d'une réponse (tolère les blocs ```json)."""
    if not text:
        raise LLMError("réponse vide du modèle")
    cleaned = _FENCE_RE.sub("", text.strip())
    try:
        obj = json.loads(cleaned)
    except json.JSONDecodeError:
        start, end = cleaned.find("{"), cleaned.rfind("}")
        if start < 0 or end <= start:
            raise LLMError("la réponse du modèle ne contient pas de JSON") from None
        try:
            obj = json.loads(cleaned[start:end + 1])
        except json.JSONDecodeError as exc:
            raise LLMError(f"JSON invalide : {exc}") from exc
    if not isinstance(obj, dict):
        raise LLMError("le modèle doit répondre par un objet JSON")
    return obj


class PrivacyFilteredLLM(BaseLLM):
    """Pseudonymise les prompts avant un LLM externe et ré-identifie la réponse (GP-08)."""

    def __init__(self, inner: BaseLLM, pseudonymizer: Pseudonymizer):
        super().__init__()
        self.inner = inner
        self.pseudonymizer = pseudonymizer
        self.provider = inner.provider
        self.model = inner.model
        self.usage = inner.usage

    @property
    def total_tokens(self) -> int:
        return self.inner.total_tokens

    def generate(self, task: str, system: str, user: str, context: dict[str, Any] | None = None) -> dict[str, Any]:
        p = self.pseudonymizer
        answer = self.inner.generate(task, p.pseudonymize_text(system), p.pseudonymize_text(user), None)
        return p.restore_obj(answer)
