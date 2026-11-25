"""Pseudonymisation avant envoi à un LLM externe (GP-08)."""

from __future__ import annotations

from agent.llm.base import BaseLLM, PrivacyFilteredLLM
from gateway.privacy import Pseudonymizer

TEXT = ("Création de processus par LAB\\jdoe sur WIN10-01.lab.local (192.168.56.20) vers 203.0.113.45, "
        "contact admin@lab.local, empreinte 53dadc40bb276161fbb4864750877d9641ebe8a5dee5ce338d2554171eebc6d1")


def test_personal_data_pseudonymized():
    p = Pseudonymizer("secret", ["lab.local"])
    p.register("host", "WIN10-01")
    out = p.pseudonymize_text(TEXT)
    for leaked in ("jdoe", "WIN10-01", "192.168.56.20", "admin@lab.local"):
        assert leaked not in out, leaked
    assert "203.0.113.45" in out  # observable externe conservé
    assert "53dadc40bb276161fbb4864750877d9641ebe8a5dee5ce338d2554171eebc6d1" in out


def test_roundtrip_and_stability():
    p = Pseudonymizer("secret")
    p.register("user", "LAB\\jdoe")
    out = p.pseudonymize_text(TEXT)
    assert p.restore_text(out) == TEXT
    assert Pseudonymizer("secret").token("user", "LAB\\jdoe") == p.token("user", "LAB\\jdoe")
    assert Pseudonymizer("autre").token("user", "LAB\\jdoe") != p.token("user", "LAB\\jdoe")


def test_privacy_filtered_llm_never_sees_personal_data():
    seen = {}

    class Capture(BaseLLM):
        provider, model = "fake-api", "fake"

        def generate(self, task, system, user, context=None):
            seen["user"], seen["context"] = user, context
            return {"summary": user}

    p = Pseudonymizer("secret")
    p.register("user", "LAB\\jdoe")
    p.register("host", "WIN10-01")
    answer = PrivacyFilteredLLM(Capture(), p).generate("report", "système", TEXT, {"brut": TEXT})
    assert "jdoe" not in seen["user"] and "WIN10-01" not in seen["user"]
    assert seen["context"] is None  # le contexte structuré ne quitte jamais le laboratoire
    assert answer["summary"] == TEXT  # réponse ré-identifiée
