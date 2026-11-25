"""Stockage des vecteurs : en mémoire (défaut) ou ChromaDB (optionnel).

ChromaDB est prévu par le cahier des charges ; le stockage en mémoire suffit
pour ~3 000 fragments et évite un service supplémentaire. Le choix se fait par
la variable VECTOR_STORE=memory|chroma.
"""

from __future__ import annotations

from pathlib import Path
from typing import Protocol

import numpy as np


class VectorStore(Protocol):
    def add(self, ids: list[str], vectors: np.ndarray, metadatas: list[dict]) -> None: ...

    def query(self, vector: np.ndarray, n: int) -> list[tuple[str, float]]: ...


class InMemoryVectorStore:
    def __init__(self) -> None:
        self.ids: list[str] = []
        self.matrix: np.ndarray | None = None

    def add(self, ids: list[str], vectors: np.ndarray, metadatas: list[dict]) -> None:
        self.ids.extend(ids)
        self.matrix = vectors if self.matrix is None else np.vstack([self.matrix, vectors])

    def query(self, vector: np.ndarray, n: int) -> list[tuple[str, float]]:
        if self.matrix is None:
            return []
        scores = self.matrix @ vector.astype(np.float32)
        top = np.argsort(-scores)[:n]
        return [(self.ids[i], float(scores[i])) for i in top]


class ChromaVectorStore:
    def __init__(self, path: Path, collection: str = "attack"):
        import chromadb  # dépendance optionnelle

        self.client = chromadb.PersistentClient(path=str(path))
        try:
            self.client.delete_collection(collection)
        except Exception:  # la collection n'existe pas encore
            pass
        self.collection = self.client.create_collection(collection, metadata={"hnsw:space": "cosine"})

    def add(self, ids: list[str], vectors: np.ndarray, metadatas: list[dict]) -> None:
        for start in range(0, len(ids), 1000):
            self.collection.add(ids=ids[start:start + 1000], embeddings=vectors[start:start + 1000].tolist(),
                                metadatas=metadatas[start:start + 1000])

    def query(self, vector: np.ndarray, n: int) -> list[tuple[str, float]]:
        res = self.collection.query(query_embeddings=[vector.tolist()], n_results=n)
        return [(i, 1.0 - float(d)) for i, d in zip(res["ids"][0], res["distances"][0])]


def make_vector_store(kind: str, data_dir: Path | None = None) -> VectorStore:
    if kind == "chroma":
        return ChromaVectorStore((data_dir or Path("investigation_lab/data")) / "chroma")
    return InMemoryVectorStore()
