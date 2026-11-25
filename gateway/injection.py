"""Défense contre la prompt injection indirecte (GP-07).

Trois mécanismes complémentaires :

1. **Balisage** : tout contenu issu des journaux ou de la TI est présenté au LLM
   entre balises <untrusted_data>, avec neutralisation des balises imbriquées.
   Le prompt système indique que ce contenu est une donnée, jamais une instruction.
2. **Détection** : les résultats d'outils sont analysés ; un élément suspect est
   marqué `injection_suspected`, l'événement est journalisé et signalé dans le
   rapport.
3. **Contrôle hors LLM** : même si le modèle était manipulé, la passerelle
   applique la politique ; une action interdite reste interdite.
"""

from __future__ import annotations

import copy
import json
import re
from dataclasses import dataclass
from typing import Any

PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (name, re.compile(rx, re.IGNORECASE))
    for name, rx in [
        ("ignore_instructions", r"\b(ignore|disregard|forget|override)\b[^.\n]{0,40}\b(previous|prior|above|all|earlier|system)\b[^.\n]{0,30}\b(instructions?|rules|prompts?|directives?)"),
        ("ignore_instructions_fr", r"\b(ignore[rz]?|oublie[rz]?|outrepasse[rz]?)\b[^.\n]{0,40}\b(instructions?|consignes?|règles|directives?)\b"),
        ("role_override", r"\b(you are now|from now on you|act as|tu es (maintenant|désormais)|agis comme|you must now)\b"),
        ("system_prompt", r"\b(system prompt|prompt syst[eè]me|developer message|jailbreak|admin mode|mode administrateur)\b"),
        ("new_instructions", r"\b(new|updated|nouvelles?) (instructions?|consignes?|task|tâche)\b"),
        ("tool_invocation", r"\b(call|invoke|execute|run|appelle[rz]?|exécute[rz]?|lance[rz]?)\b[^.\n]{0,30}\b(tool|function|outil|isolate_host|search_logs|ti_lookup|misp_lookup|attack_search|get_process_tree)\b"),
        ("verdict_manipulation", r"\b(mark|classify|report|label|close|classe[rz]?|marque[rz]?|clôture[rz]?)\b[^.\n]{0,40}\b(benign|false positive|faux positif|bénin|legitimate|légitime|not malicious)\b"),
        ("suppress_reporting", r"\b(do not|don't|never|ne (pas|jamais))\b[^.\n]{0,25}\b(report|mention|alert|signaler|mentionner|alerter)\b"),
        ("markup_injection", r"</?\s*(untrusted_data|system|assistant|user|tool|instructions?)\b[^>]*>"),
        ("chat_markers", r"(^|\n)\s*(###\s*(instruction|system)|assistant\s*:|system\s*:|\[INST\]|<\|im_start\|>)"),
    ]
]

MAX_SCAN_CHARS = 20_000


@dataclass(frozen=True)
class InjectionFinding:
    pattern: str
    excerpt: str
    path: str = ""

    def to_dict(self) -> dict[str, str]:
        return {"pattern": self.pattern, "excerpt": self.excerpt, "path": self.path}


def scan_text(text: str, path: str = "") -> list[InjectionFinding]:
    if not text:
        return []
    sample = text[:MAX_SCAN_CHARS]
    findings = []
    for name, rx in PATTERNS:
        m = rx.search(sample)
        if m:
            start, end = max(0, m.start() - 30), min(len(sample), m.end() + 30)
            findings.append(InjectionFinding(name, sample[start:end].replace("\n", " "), path))
    return findings


def _iter_strings(obj: Any, path: str = "") -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    if isinstance(obj, str):
        out.append((path, obj))
    elif isinstance(obj, dict):
        for k, v in obj.items():
            if k.startswith("_"):
                continue
            out.extend(_iter_strings(v, f"{path}.{k}" if path else str(k)))
    elif isinstance(obj, (list, tuple)):
        for i, v in enumerate(obj):
            out.extend(_iter_strings(v, f"{path}[{i}]"))
    return out


def scan_payload(payload: dict[str, Any]) -> tuple[dict[str, Any], list[InjectionFinding]]:
    """Analyse un résultat d'outil et marque les éléments suspects.

    Retourne une copie du résultat (les éléments suspects reçoivent
    `_flags: ["injection_suspected"]`) et la liste des détections.
    """
    result = copy.deepcopy(payload)
    all_findings: list[InjectionFinding] = []
    for idx, item in enumerate(result.get("items") or []):
        if not isinstance(item, dict):
            continue
        item_findings: list[InjectionFinding] = []
        for path, value in _iter_strings(item):
            item_findings.extend(scan_text(value, f"items[{idx}].{path}"))
        if item_findings:
            flags = list(item.get("_flags") or [])
            if "injection_suspected" not in flags:
                flags.append("injection_suspected")
            item["_flags"] = flags
            item["_injection_patterns"] = sorted({f.pattern for f in item_findings})
            all_findings.extend(item_findings)
    if all_findings:
        meta = result.setdefault("meta", {})
        meta["injection_findings"] = [f.to_dict() for f in all_findings[:20]]
    return result, all_findings


_TAG_RX = re.compile(r"<\s*(/?)\s*untrusted_data", re.IGNORECASE)


def neutralize(text: str) -> str:
    """Empêche une donnée de fermer ou d'ouvrir une balise <untrusted_data>."""
    return _TAG_RX.sub(lambda m: f"&lt;{m.group(1)}untrusted_data", text)


def wrap_untrusted(content: Any, *, source: str, ref: str = "", max_chars: int = 6000) -> str:
    """Balise un contenu non fiable pour le LLM."""
    if not isinstance(content, str):
        content = json.dumps(content, ensure_ascii=False, default=str)
    if len(content) > max_chars:
        content = content[:max_chars] + " …[tronqué]"
    attrs = f'source="{source}"' + (f' ref="{ref}"' if ref else "")
    return f"<untrusted_data {attrs}>\n{neutralize(content)}\n</untrusted_data>"
