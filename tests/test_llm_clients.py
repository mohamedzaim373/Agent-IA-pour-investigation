"""Clients LLM (Groq, Ollama) avec HTTP simulé, et fabrique par configuration (ENF-07)."""

from __future__ import annotations

import json

import pytest
import requests

from agent.llm import OfflineLLM, PrivacyFilteredLLM, make_llm
from agent.llm.base import LLMError, parse_json_object
from agent.llm.groq_client import GroqLLM
from agent.llm.ollama_client import OllamaLLM
from config.settings import load_settings


class FakeResponse:
    def __init__(self, status, payload, headers=None):
        self.status_code, self._payload, self.headers = status, payload, headers or {}
        self.text = json.dumps(payload)

    def json(self):
        return self._payload


def test_parse_json_object():
    assert parse_json_object('```json\n{"a": 1}\n```') == {"a": 1}
    assert parse_json_object('Voici : {"a": 2} fin') == {"a": 2}
    with pytest.raises(LLMError):
        parse_json_object("pas de json")


def test_groq_json_mode_usage_and_retry(monkeypatch):
    responses = [
        FakeResponse(429, {"error": "rate"}, {"retry-after": "0"}),
        FakeResponse(200, {"choices": [{"message": {"content": '{"verdict": "true_positive"}'}}],
                           "usage": {"prompt_tokens": 100, "completion_tokens": 20}}),
    ]
    sent = []

    def fake_post(self, url, json=None, timeout=None):
        sent.append(json)
        return responses.pop(0)

    monkeypatch.setattr(requests.Session, "post", fake_post)
    monkeypatch.setattr("agent.llm.groq_client.time.sleep", lambda s: None)
    llm = GroqLLM("gsk-test", "llama-3.3-70b-versatile")
    assert llm.generate("report", "sys", "user") == {"verdict": "true_positive"}
    assert sent[-1]["response_format"] == {"type": "json_object"}
    assert llm.total_tokens == 120 and llm.usage["calls"] == 1


def test_groq_requires_key():
    with pytest.raises(LLMError):
        GroqLLM("")


def test_groq_non_retryable_error(monkeypatch):
    monkeypatch.setattr(requests.Session, "post", lambda self, url, json=None, timeout=None: FakeResponse(400, {"e": 1}))
    with pytest.raises(LLMError):
        GroqLLM("gsk-test").generate("plan", "s", "u")


def test_ollama(monkeypatch):
    def fake_post(self, url, json=None, timeout=None):
        assert url.endswith("/api/chat") and json["format"] == "json" and json["stream"] is False
        return FakeResponse(200, {"message": {"content": '{"action": "conclude"}'}, "prompt_eval_count": 50,
                                  "eval_count": 5})

    monkeypatch.setattr(requests.Session, "post", fake_post)
    llm = OllamaLLM("http://ollama:11434", "qwen2.5:7b-instruct")
    assert llm.generate("act", "s", "u") == {"action": "conclude"} and llm.total_tokens == 55


def test_factory_by_configuration():
    assert isinstance(make_llm(load_settings(llm_provider="offline")), OfflineLLM)
    assert isinstance(make_llm(load_settings(llm_provider="ollama")), OllamaLLM)
    from gateway.privacy import Pseudonymizer

    groq = make_llm(load_settings(llm_provider="groq", groq_api_key="gsk-test"), Pseudonymizer("s"))
    assert isinstance(groq, PrivacyFilteredLLM)  # LLM externe : pseudonymisation (GP-08)
    with pytest.raises(LLMError):
        make_llm(load_settings(llm_provider="inconnu"))
