"""Client Groq (API compatible OpenAI) : mode JSON, nouvelles tentatives, jetons."""

from __future__ import annotations

import time
from typing import Any

import requests

from agent.llm.base import BaseLLM, LLMError, parse_json_object


class GroqLLM(BaseLLM):
    provider = "groq"

    def __init__(self, api_key: str, model: str = "llama-3.3-70b-versatile",
                 base_url: str = "https://api.groq.com/openai/v1", temperature: float = 0.0,
                 timeout: float = 120, max_retries: int = 4, max_tokens: int = 4096):
        super().__init__()
        if not api_key:
            raise LLMError("GROQ_API_KEY n'est pas configurée")
        self.model = model
        self.url = base_url.rstrip("/") + "/chat/completions"
        self.temperature = temperature
        self.timeout = timeout
        self.max_retries = max_retries
        self.max_tokens = max_tokens
        self.session = requests.Session()
        self.session.headers.update({"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"})

    def _post(self, payload: dict[str, Any]) -> dict[str, Any]:
        delay = 2.0
        last_error = "erreur inconnue"
        for _attempt in range(self.max_retries + 1):
            try:
                resp = self.session.post(self.url, json=payload, timeout=self.timeout)
            except (requests.Timeout, requests.ConnectionError) as exc:
                last_error = f"connexion à Groq impossible : {exc}"
            else:
                if resp.status_code == 200:
                    return resp.json()
                last_error = f"HTTP {resp.status_code} : {resp.text[:300]}"
                if resp.status_code not in (429, 500, 502, 503, 504):
                    raise LLMError(f"Groq a refusé la requête ({last_error})")
                retry_after = resp.headers.get("retry-after")
                if retry_after:
                    try:
                        delay = max(delay, float(retry_after))
                    except ValueError:
                        pass
            time.sleep(min(delay, 30))
            delay *= 2
        raise LLMError(f"Groq indisponible après {self.max_retries + 1} tentatives ({last_error})")

    def generate(self, task: str, system: str, user: str, context: dict[str, Any] | None = None) -> dict[str, Any]:
        messages = [{"role": "system", "content": system}, {"role": "user", "content": user}]
        for attempt in (1, 2):
            data = self._post({
                "model": self.model,
                "messages": messages,
                "temperature": self.temperature,
                "max_tokens": self.max_tokens,
                "response_format": {"type": "json_object"},
            })
            usage = data.get("usage") or {}
            self._count(usage.get("prompt_tokens", 0), usage.get("completion_tokens", 0))
            content = ((data.get("choices") or [{}])[0].get("message") or {}).get("content", "")
            try:
                return parse_json_object(content)
            except LLMError:
                if attempt == 2:
                    raise
                messages = messages + [{"role": "assistant", "content": content},
                                       {"role": "user", "content": "Réponds uniquement par un objet JSON valide."}]
        raise LLMError("réponse JSON invalide")  # pragma: no cover
