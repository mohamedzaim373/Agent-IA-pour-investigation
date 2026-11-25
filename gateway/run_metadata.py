"""Versions enregistrées pour chaque investigation (GT-05).

Modèle de langage, prompt système, politique et connecteurs sont identifiés par
leur nom et une empreinte SHA-256 de leur contenu : un rapport peut ainsi être
rattaché exactement à la configuration qui l'a produit.
"""

from __future__ import annotations

import inspect
from typing import Any

from gateway.hashing import sha256_hex


def module_hash(module: Any) -> str:
    try:
        return sha256_hex(inspect.getsource(module))
    except (OSError, TypeError):
        return "inconnu"


def collect_run_metadata(*, llm: Any, policy: Any, backend: str, connectors: dict[str, Any], rag: Any = None) -> dict[str, Any]:
    from agent import prompts

    meta: dict[str, Any] = {
        "llm": {"provider": getattr(llm, "provider", "?"), "model": getattr(llm, "model", "?")},
        "prompts": {"version": prompts.PROMPT_VERSION, "sha256": prompts.prompt_hash()},
        "policy": {"version": policy.version, "sha256": policy.sha256, "source": policy.source},
        "backend": backend,
        "connectors": {name: {"version": getattr(c, "VERSION", "1.0"), "sha256": module_hash(inspect.getmodule(c))}
                       for name, c in connectors.items()},
    }
    if rag is not None:
        meta["attack_kb"] = {"version": getattr(rag, "kb_version", "?"), "sha256": getattr(rag, "kb_sha256", "?"),
                             "embedder": getattr(rag, "embedder_name", "?")}
    return meta
