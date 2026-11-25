"""Client Ollama : LLM local, aucune donnée ne quitte le laboratoire (GP-08, ENF-07)."""

from __future__ import annotations

from typing import Any

import requests

from agent.llm.base import BaseLLM, LLMError, parse_json_object


class OllamaLLM(BaseLLM):
    provider = "ollama"

    def __init__(self, url: str = "http://localhost:11434", model: str = "qwen2.5:7b-instruct",
                 temperature: float = 0.0, timeout: float = 300, num_ctx: int = 16384):
        super().__init__()
        self.model = model
        self.url = url.rstrip("/") + "/api/chat"
        self.temperature = temperature
        self.timeout = timeout
        self.num_ctx = num_ctx
        self.session = requests.Session()

    def generate(self, task: str, system: str, user: str, context: dict[str, Any] | None = None) -> dict[str, Any]:
        messages = [{"role": "system", "content": system}, {"role": "user", "content": user}]
        for attempt in (1, 2):
            try:
                resp = self.session.post(self.url, timeout=self.timeout, json={
                    "model": self.model,
                    "messages": messages,
                    "stream": False,
                    "format": "json",
                    "options": {"temperature": self.temperature, "num_ctx": self.num_ctx},
                })
            except (requests.Timeout, requests.ConnectionError) as exc:
                raise LLMError(f"Ollama injoignable ({self.url}) : {exc}") from exc
            if resp.status_code != 200:
                raise LLMError(f"Ollama : HTTP {resp.status_code} {resp.text[:300]}")
            data = resp.json()
            self._count(data.get("prompt_eval_count", 0), data.get("eval_count", 0))
            content = (data.get("message") or {}).get("content", "")
            try:
                return parse_json_object(content)
            except LLMError:
                if attempt == 2:
                    raise
                messages = messages + [{"role": "assistant", "content": content},
                                       {"role": "user", "content": "Réponds uniquement par un objet JSON valide."}]
        raise LLMError("réponse JSON invalide")  # pragma: no cover
