"""Découpage de la base ATT&CK en fragments identifiés « Txxxx[.yyy]#k ».

Chaque fragment commence par l'identifiant et le nom de la technique, ce qui
ancre la recherche et permet au rapport de citer précisément le passage qui
justifie un rattachement (EF-10).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

MAX_CHARS = 900


@dataclass(frozen=True)
class Chunk:
    chunk_id: str
    technique_id: str
    name: str
    kind: str  # overview | description | detection | procedures
    tactics: tuple[str, ...]
    text: str


def _split_paragraphs(text: str, max_chars: int = MAX_CHARS) -> list[str]:
    parts: list[str] = []
    current = ""
    for para in [p.strip() for p in text.split("\n") if p.strip()]:
        while len(para) > max_chars:
            cut = para.rfind(". ", 0, max_chars)
            cut = cut + 1 if cut > max_chars // 3 else max_chars
            head, para = para[:cut].strip(), para[cut:].strip()
            if current:
                parts.append(current)
                current = ""
            parts.append(head)
        if len(current) + len(para) + 1 > max_chars and current:
            parts.append(current)
            current = para
        else:
            current = f"{current}\n{para}".strip()
    if current:
        parts.append(current)
    return parts


def chunk_technique(t: dict[str, Any]) -> list[Chunk]:
    tid, name = t["id"], t["name"]
    full_name = f"{t.get('parent_name')}: {name}" if t.get("parent_name") else name
    header = f"{tid} {full_name}"
    tactics = tuple(t.get("tactics", []))
    chunks: list[Chunk] = []

    def add(kind: str, body: str) -> None:
        chunks.append(Chunk(f"{tid}#{len(chunks)}", tid, name, kind, tactics, f"{header}. {body}".strip()))

    paragraphs = _split_paragraphs(t.get("description", ""))
    meta = f"Tactiques : {', '.join(tactics) or '-'}. Plateformes : {', '.join(t.get('platforms', [])) or '-'}."
    add("overview", f"{meta}\n{paragraphs[0] if paragraphs else ''}")
    for para in paragraphs[1:]:
        add("description", para)
    if t.get("detection"):
        for part in _split_paragraphs("Détection : " + "\n".join(t["detection"])):
            add("detection", part)
    if t.get("procedures"):
        for part in _split_paragraphs("Exemples de procédures :\n" + "\n".join(t["procedures"])):
            add("procedures", part)
    return chunks


def chunk_kb(kb: dict[str, Any]) -> list[Chunk]:
    out: list[Chunk] = []
    for t in kb.get("techniques", []):
        out.extend(chunk_technique(t))
    return out
