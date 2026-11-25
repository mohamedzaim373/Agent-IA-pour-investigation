"""AttackRAG : recherche hybride dans MITRE ATT&CK (EF-10).

Pipeline d'une requête :
  1. identifiants explicites (« T1059.001 ») : correspondance exacte prioritaire ;
  2. enrichissement par un lexique d'artefacts Windows (certutil, lsass, -enc…) ;
  3. recherche lexicale BM25 et recherche dense (embeddings) sur les fragments ;
  4. fusion des classements par Reciprocal Rank Fusion (RRF) ;
  5. reranking : recouvrement avec le nom de la technique, tactique demandée ;
  6. agrégation par technique (meilleur fragment cité : « T1059.001#2 »).

L'outil `attack_search` de la passerelle appelle `AttackRAG.search`.
"""

from __future__ import annotations

import re
import threading
from collections import defaultdict
from pathlib import Path
from typing import Any

import numpy as np

from gateway.hashing import sha256_hex
from gateway.tool_schemas import AttackSearchArgs
from rag.attack_loader import DEFAULT_KB, load_kb
from rag.chunking import Chunk, chunk_kb
from rag.embedder import make_embedder
from rag.vector_store import make_vector_store

VERSION = "1.0"
RRF_K = 60
TECH_ID_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)
TOKEN_RE = re.compile(r"[a-z0-9][a-z0-9_\-]*")
STOP = {
    "the", "a", "an", "of", "to", "and", "or", "in", "on", "for", "by", "with", "is", "are", "be", "as", "at",
    "from", "that", "this", "it", "its", "may", "can", "via", "le", "la", "les", "de", "des", "du", "un", "une",
    "et", "ou", "en", "sur", "par", "pour", "avec", "dans", "est", "adversaries", "adversary", "use", "used",
}

# Lexique d'artefacts : relie des indices techniques fréquents dans les journaux
# au vocabulaire employé par ATT&CK.
SECURITY_EXPANSIONS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(p, re.IGNORECASE), e)
    for p, e in [
        (r"powershell", "powershell"),
        (r"-enc\b|-encodedcommand|frombase64string|base64", "encoded command obfuscation powershell base64"),
        (r"certutil", "certutil urlcache download ingress tool transfer"),
        (r"bitsadmin|invoke-webrequest|\biwr\b|downloadstring|downloadfile|webclient|curl|wget", "download ingress tool transfer"),
        (r"lsass", "lsass memory credential dumping"),
        (r"comsvcs|minidump|procdump|sekurlsa|mimikatz", "lsass memory credential dumping"),
        (r"currentversion\\run|\\run\b|runonce|run key", "registry run keys startup folder persistence"),
        (r"schtasks|scheduled task|tâche planifiée|4698", "scheduled task"),
        (r"whoami", "system owner user discovery"),
        (r"net( |1 )user|net( |1 )localgroup|get-localuser", "local account discovery"),
        (r"ipconfig|route print|arp -a|netsh", "system network configuration discovery"),
        (r"systeminfo|hostname|ver\b", "system information discovery"),
        (r"tasklist|get-process", "process discovery"),
        (r"cmd\.exe|/c ", "windows command shell"),
        (r"rundll32", "rundll32 system binary proxy execution"),
        (r"wmic|win32_process", "windows management instrumentation"),
        (r"sc(\.exe)? create|new-service|7045", "windows service"),
        (r"vssadmin|shadowcopy", "inhibit system recovery"),
        (r"\b(c2|beacon|callback|command and control)\b", "application layer protocol web protocols"),
    ]
]

TACTIC_ALIASES = {
    "defense-evasion": ["stealth", "defense-impairment"],
    "evasion": ["stealth", "defense-impairment"],
}


def tokenize(text: str) -> list[str]:
    return [t for t in TOKEN_RE.findall(text.lower()) if t not in STOP and len(t) > 1]


def expand_query(query: str) -> str:
    extra = [exp for rx, exp in SECURITY_EXPANSIONS if rx.search(query)]
    return query + (" " + " ".join(extra) if extra else "")


class BM25:
    def __init__(self, docs: list[list[str]], k1: float = 1.5, b: float = 0.75):
        self.k1, self.b = k1, b
        self.doc_len = np.array([len(d) for d in docs], dtype=np.float32)
        self.avgdl = float(self.doc_len.mean()) if len(docs) else 1.0
        self.postings: dict[str, list[tuple[int, int]]] = defaultdict(list)
        for i, doc in enumerate(docs):
            counts: dict[str, int] = defaultdict(int)
            for tok in doc:
                counts[tok] += 1
            for tok, c in counts.items():
                self.postings[tok].append((i, c))
        n = len(docs)
        self.idf = {t: float(np.log(1 + (n - len(p) + 0.5) / (len(p) + 0.5))) for t, p in self.postings.items()}
        self.n = n

    def scores(self, query_tokens: list[str]) -> np.ndarray:
        scores = np.zeros(self.n, dtype=np.float32)
        for tok in set(query_tokens):
            idf = self.idf.get(tok)
            if idf is None:
                continue
            for i, tf in self.postings[tok]:
                denom = tf + self.k1 * (1 - self.b + self.b * self.doc_len[i] / self.avgdl)
                scores[i] += idf * tf * (self.k1 + 1) / denom
        return scores


class AttackRAG:
    VERSION = VERSION

    def __init__(self, kb: dict[str, Any], *, embedder: str = "tfidf", vector_store: str = "memory",
                 sbert_model: str | None = None, data_dir: Path | None = None):
        self.kb = kb
        self.kb_version = kb.get("version", "?")
        self.kb_sha256 = sha256_hex(str(len(kb.get("techniques", []))) + self.kb_version)
        self.techniques = {t["id"]: t for t in kb.get("techniques", [])}
        self.tactic_names = kb.get("tactics", {})
        self.chunks: list[Chunk] = chunk_kb(kb)
        self.chunk_index = {c.chunk_id: i for i, c in enumerate(self.chunks)}
        texts = [c.text for c in self.chunks]
        self.bm25 = BM25([tokenize(expand_query(t[:200]) + " " + t) for t in texts])
        self.embedder = make_embedder(embedder, sbert_model).fit(texts)
        self.embedder_name = self.embedder.name
        vectors = self.embedder.encode(texts)
        self.store = make_vector_store(vector_store, data_dir)
        self.store.add([c.chunk_id for c in self.chunks], vectors,
                       [{"technique_id": c.technique_id, "kind": c.kind} for c in self.chunks])
        self.name_tokens = {tid: set(tokenize(t["name"] + " " + (t.get("parent_name") or "")))
                            for tid, t in self.techniques.items()}

    # ---------------------------------------------------------------- accès
    def get_technique(self, technique_id: str) -> dict[str, Any] | None:
        return self.techniques.get(technique_id.upper())

    def fragment(self, fragment_id: str) -> Chunk | None:
        idx = self.chunk_index.get(fragment_id)
        return self.chunks[idx] if idx is not None else None

    def _tactic_ok(self, tid: str, tactic: str | None) -> bool:
        if not tactic:
            return True
        wanted = tactic.lower().replace(" ", "-")
        allowed = set(TACTIC_ALIASES.get(wanted, [wanted]))
        return bool(allowed & set(self.techniques[tid].get("tactics", [])))

    # ------------------------------------------------------------- recherche
    def search(self, query: str, k: int = 5, tactic: str | None = None, pool: int = 60) -> list[dict[str, Any]]:
        expanded = expand_query(query)
        q_tokens = tokenize(expanded)
        fused: dict[int, float] = defaultdict(float)

        sparse = self.bm25.scores(q_tokens)
        for rank, idx in enumerate(np.argsort(-sparse)[:pool]):
            if sparse[idx] > 0:
                fused[int(idx)] += 1.0 / (RRF_K + rank + 1)
        dense = self.store.query(self.embedder.encode([expanded])[0], pool)
        for rank, (cid, score) in enumerate(dense):
            if score > 0:
                fused[self.chunk_index[cid]] += 1.0 / (RRF_K + rank + 1)

        q_set = set(q_tokens)
        per_tech: dict[str, list[tuple[float, int]]] = defaultdict(list)
        for idx, score in fused.items():
            chunk = self.chunks[idx]
            name_tok = self.name_tokens.get(chunk.technique_id, set())
            overlap = len(name_tok & q_set) / len(name_tok) if name_tok else 0.0
            rerank = score + 0.012 * overlap + (0.004 if chunk.kind in {"overview", "detection"} else 0.0)
            per_tech[chunk.technique_id].append((rerank, idx))

        results = []
        for tid, scored in per_tech.items():
            if not self._tactic_ok(tid, tactic):
                continue
            scored.sort(reverse=True)
            total = scored[0][0] + 0.3 * sum(s for s, _ in scored[1:3])
            results.append((total, tid, scored[0][1]))

        explicit = [m.upper() for m in TECH_ID_RE.findall(query)]
        top = max((r[0] for r in results), default=0.0) or 1.0
        for tid in explicit:
            if tid in self.techniques:
                frag = self.chunk_index.get(f"{tid}#0")
                results.append((top * 2, tid, frag))
        results.sort(key=lambda r: r[0], reverse=True)

        out, seen = [], set()
        best = results[0][0] if results else 1.0
        for score, tid, idx in results:
            if tid in seen:
                continue
            seen.add(tid)
            t, chunk = self.techniques[tid], self.chunks[idx]
            out.append({
                "technique_id": tid,
                "name": t["name"],
                "parent_name": t.get("parent_name"),
                "tactics": t.get("tactics", []),
                "score": round(min(1.0, score / best), 4),
                "fragment_id": chunk.chunk_id,
                "fragment_kind": chunk.kind,
                "fragment": chunk.text[:700],
                "url": t.get("url"),
            })
            if len(out) >= k:
                break
        return out

    # -------------------------------------------------------- outil passerelle
    def attack_search(self, args: AttackSearchArgs) -> dict[str, Any]:
        results = self.search(args.query, k=args.k, tactic=args.tactic)
        items = []
        for r in results:
            tactics = ", ".join(r["tactics"])
            items.append(dict(r, source="mitre-attack", raw_ref=r["fragment_id"],
                              summary=f"{r['technique_id']} {r['name']} ({tactics}) — score {r['score']:.2f}, "
                                      f"fragment {r['fragment_id']}"))
        return {"items": items, "meta": {"query": args.query, "kb_version": self.kb_version}}


_cache: dict[tuple, AttackRAG] = {}
_cache_lock = threading.Lock()


def get_rag(kb_path: Path | str = DEFAULT_KB, embedder: str = "tfidf", vector_store: str = "memory",
            sbert_model: str | None = None, data_dir: Path | None = None) -> AttackRAG:
    """Instance partagée (la construction de l'index prend quelques secondes)."""
    key = (str(kb_path), embedder, vector_store, sbert_model)
    with _cache_lock:
        if key not in _cache:
            _cache[key] = AttackRAG(load_kb(kb_path), embedder=embedder, vector_store=vector_store,
                                    sbert_model=sbert_model, data_dir=data_dir)
        return _cache[key]
