"""Fabrique des modèles de langage : le choix se fait par configuration (ENF-07)."""

from __future__ import annotations

from agent.llm.base import BaseLLM, LLMError, PrivacyFilteredLLM
from agent.llm.offline import OfflineLLM


def make_llm(settings, pseudonymizer=None, pseudonymize: bool = True) -> BaseLLM:
    provider = settings.llm_provider
    if provider == "groq":
        from agent.llm.groq_client import GroqLLM

        llm: BaseLLM = GroqLLM(settings.groq_api_key, settings.groq_model, settings.groq_base_url,
                               settings.llm_temperature, settings.llm_timeout_s)
        # LLM externe : pseudonymisation des données personnelles (GP-08).
        if pseudonymize and pseudonymizer is not None:
            llm = PrivacyFilteredLLM(llm, pseudonymizer)
        return llm
    if provider == "ollama":
        from agent.llm.ollama_client import OllamaLLM

        return OllamaLLM(settings.ollama_url, settings.ollama_model, settings.llm_temperature, settings.llm_timeout_s)
    if provider == "offline":
        return OfflineLLM()
    raise LLMError(f"fournisseur de LLM inconnu : {provider} (attendu : offline, groq, ollama)")


__all__ = ["BaseLLM", "LLMError", "OfflineLLM", "PrivacyFilteredLLM", "make_llm"]
