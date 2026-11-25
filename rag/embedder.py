"""Modèles d'embeddings pour la recherche dense.

- `tfidf` (défaut) : TF-IDF + LSA (SVD tronquée), sans dépendance lourde ni
  téléchargement, déterministe.
- `sbert` : sentence-transformers (par ex. all-MiniLM-L6-v2), meilleure
  sémantique, nécessite `pip install sentence-transformers`.
"""

from __future__ import annotations

from typing import Protocol

import numpy as np


class Embedder(Protocol):
    name: str

    def fit(self, texts: list[str]) -> "Embedder": ...

    def encode(self, texts: list[str]) -> np.ndarray: ...


def _l2_normalize(x: np.ndarray) -> np.ndarray:
    norms = np.linalg.norm(x, axis=1, keepdims=True)
    norms[norms == 0] = 1.0
    return x / norms


class TfidfLsaEmbedder:
    def __init__(self, n_components: int = 300, random_state: int = 42):
        from sklearn.decomposition import TruncatedSVD
        from sklearn.feature_extraction.text import TfidfVectorizer

        self.name = f"tfidf-lsa-{n_components}"
        self.vectorizer = TfidfVectorizer(
            lowercase=True, ngram_range=(1, 2), sublinear_tf=True, min_df=1, max_df=0.5,
            stop_words="english", token_pattern=r"(?u)\b[a-zA-Z][a-zA-Z0-9_.\-]+\b",
        )
        self.svd = TruncatedSVD(n_components=n_components, random_state=random_state)
        self._fitted = False

    def fit(self, texts: list[str]) -> "TfidfLsaEmbedder":
        matrix = self.vectorizer.fit_transform(texts)
        n = min(self.svd.n_components, max(2, matrix.shape[1] - 1), max(2, matrix.shape[0] - 1))
        if n != self.svd.n_components:
            self.svd.set_params(n_components=n)
        self.svd.fit(matrix)
        self._fitted = True
        return self

    def encode(self, texts: list[str]) -> np.ndarray:
        if not self._fitted:
            raise RuntimeError("embedder non entraîné")
        return _l2_normalize(self.svd.transform(self.vectorizer.transform(texts)).astype(np.float32))


class SentenceTransformerEmbedder:
    def __init__(self, model_name: str = "sentence-transformers/all-MiniLM-L6-v2"):
        from sentence_transformers import SentenceTransformer  # dépendance optionnelle

        self.name = f"sbert:{model_name}"
        self.model = SentenceTransformer(model_name)

    def fit(self, texts: list[str]) -> "SentenceTransformerEmbedder":
        return self

    def encode(self, texts: list[str]) -> np.ndarray:
        return np.asarray(self.model.encode(texts, normalize_embeddings=True, batch_size=64), dtype=np.float32)


def make_embedder(name: str = "tfidf", sbert_model: str | None = None) -> Embedder:
    if name == "sbert":
        return SentenceTransformerEmbedder(sbert_model or "sentence-transformers/all-MiniLM-L6-v2")
    return TfidfLsaEmbedder()
