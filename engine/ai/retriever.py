"""ATT&CK technique retrieval for RAG-grounded MITRE mapping.

Retrieval is stage 2 of the documented RAG flow (extract -> retrieve ->
inject -> classify): given indicator text extracted from a correlated
cluster, return the top-k candidate techniques from the local ATT&CK KB.
Only these candidates are injected into the prompt, and the post-generation
validator rejects any technique id outside them.

Two interchangeable backends behind one interface:

- ``VectorRetriever`` — FAISS inner-product index over L2-normalized
  embeddings (default embedder: sentence-transformers all-mpnet-base-v2).
  The documented default; requires the optional ``[rag]`` extra.
- ``LexicalRetriever`` — deterministic Okapi BM25 over the same technique
  documents, pure Python. Used when the vector stack is not installed so
  the tool degrades gracefully instead of failing.

Both are deterministic for a fixed KB (and, for vector, a fixed embedder):
same query in, same candidates out.
"""

from __future__ import annotations

import logging
import math
import re
from dataclasses import dataclass
from typing import Callable, Optional, Protocol, Sequence

from engine.ai.kb import AttackKB, TechniqueRecord
from engine.config import RagConfig

logger = logging.getLogger(__name__)

_TOKEN = re.compile(r"[a-z0-9][a-z0-9._-]*")

#: BM25 constants (standard Okapi defaults).
_BM25_K1 = 1.5
_BM25_B = 0.75

#: Weight of name/tactic tokens relative to body tokens in the lexical index.
_TITLE_WEIGHT = 3


class RetrieverUnavailable(Exception):
    """Raised when a requested retrieval backend cannot be constructed."""


@dataclass(frozen=True)
class Candidate:
    """One retrieved technique with its retrieval score."""

    technique: TechniqueRecord
    score: float

    @property
    def uid(self) -> str:
        return self.technique.uid


class AttackRetriever(Protocol):
    backend: str

    def retrieve(self, query: str, k: int = 8) -> list[Candidate]:
        """Top-k candidate techniques for the query text."""
        ...


def tokenize(text: str) -> list[str]:
    return _TOKEN.findall(text.lower())


class LexicalRetriever:
    """Deterministic Okapi BM25 over the technique documents."""

    backend = "lexical"

    def __init__(self, kb: AttackKB) -> None:
        self._kb = kb
        self._records = kb.techniques()
        self._doc_tfs: list[dict[str, int]] = []
        self._doc_lens: list[int] = []
        df: dict[str, int] = {}
        for record in self._records:
            title_tokens = tokenize(
                " ".join([record.uid, record.name, " ".join(record.tactics)])
            )
            body_tokens = tokenize(
                " ".join([record.description, record.detection,
                          " ".join(record.platforms)])
            )
            tf: dict[str, int] = {}
            for token in title_tokens:
                tf[token] = tf.get(token, 0) + _TITLE_WEIGHT
            for token in body_tokens:
                tf[token] = tf.get(token, 0) + 1
            self._doc_tfs.append(tf)
            self._doc_lens.append(sum(tf.values()))
            for token in tf:
                df[token] = df.get(token, 0) + 1
        self._n_docs = len(self._records)
        self._avg_len = (
            sum(self._doc_lens) / self._n_docs if self._n_docs else 0.0
        )
        self._idf = {
            token: math.log(1 + (self._n_docs - count + 0.5) / (count + 0.5))
            for token, count in df.items()
        }

    def retrieve(self, query: str, k: int = 8) -> list[Candidate]:
        query_tokens = tokenize(query)
        if not query_tokens or not self._n_docs:
            return []
        # Count query terms once; score docs against unique terms.
        query_tf: dict[str, int] = {}
        for token in query_tokens:
            query_tf[token] = query_tf.get(token, 0) + 1
        scores: list[tuple[float, str, int]] = []
        for index, tf in enumerate(self._doc_tfs):
            score = 0.0
            doc_len = self._doc_lens[index] or 1
            for token, qcount in query_tf.items():
                freq = tf.get(token)
                if not freq:
                    continue
                idf = self._idf.get(token, 0.0)
                denom = freq + _BM25_K1 * (
                    1 - _BM25_B + _BM25_B * doc_len / (self._avg_len or 1)
                )
                score += idf * (freq * (_BM25_K1 + 1) / denom) * min(qcount, 3)
            if score > 0:
                scores.append((score, self._records[index].uid, index))
        scores.sort(key=lambda item: (-item[0], item[1]))
        return [
            Candidate(technique=self._records[index], score=round(score, 4))
            for score, _uid, index in scores[:k]
        ]


class VectorRetriever:
    """FAISS inner-product search over L2-normalized document embeddings.

    ``embed_fn`` maps a list of texts to a 2-D float32 array (rows =
    embeddings). By default it lazily loads the configured
    sentence-transformers model; tests inject a deterministic embedder.
    """

    backend = "vector"

    def __init__(
        self,
        kb: AttackKB,
        *,
        embed_fn: Optional[Callable[[Sequence[str]], "object"]] = None,
        embedding_model: str = "sentence-transformers/all-mpnet-base-v2",
    ) -> None:
        try:
            import faiss  # noqa: F401
            import numpy as np
        except ImportError as exc:  # pragma: no cover - environment dependent
            raise RetrieverUnavailable(
                f"vector backend needs faiss + numpy: {exc}"
            ) from exc
        self._np = np
        self._faiss = faiss
        self._records = kb.techniques()
        self._embed = embed_fn or _sentence_transformer_embedder(embedding_model)
        vectors = self._as_normalized(
            self._embed([record.document() for record in self._records])
        )
        self._index = faiss.IndexFlatIP(vectors.shape[1])
        self._index.add(vectors)

    def _as_normalized(self, vectors) -> "object":
        array = self._np.asarray(vectors, dtype="float32")
        if array.ndim != 2:
            raise RetrieverUnavailable(
                f"embedder must return a 2-D array, got shape {array.shape}"
            )
        norms = self._np.linalg.norm(array, axis=1, keepdims=True)
        norms[norms == 0] = 1.0
        return array / norms

    def retrieve(self, query: str, k: int = 8) -> list[Candidate]:
        if not query.strip() or not self._records:
            return []
        query_vec = self._as_normalized(self._embed([query]))
        k = min(k, len(self._records))
        scores, indices = self._index.search(query_vec, k)
        results = []
        for score, index in zip(scores[0].tolist(), indices[0].tolist()):
            if index < 0:
                continue
            results.append(
                Candidate(technique=self._records[index], score=round(score, 4))
            )
        return results


def _sentence_transformer_embedder(model_name: str):
    """Lazy sentence-transformers embedder (optional [rag] extra)."""
    try:
        from sentence_transformers import SentenceTransformer
    except ImportError as exc:
        raise RetrieverUnavailable(
            "sentence-transformers is not installed; install the [rag] extra "
            "or set ai.rag.backend to 'lexical'"
        ) from exc
    model = SentenceTransformer(model_name)

    def embed(texts: Sequence[str]):
        return model.encode(list(texts), normalize_embeddings=False)

    return embed


def build_retriever(
    kb: AttackKB,
    config: RagConfig,
    *,
    embed_fn: Optional[Callable[[Sequence[str]], "object"]] = None,
) -> AttackRetriever:
    """Construct the configured retrieval backend.

    ``backend: auto`` prefers the documented FAISS + embeddings stack and
    falls back to deterministic BM25 when it is not installed.
    """
    backend = config.backend.lower()
    if backend not in ("auto", "vector", "lexical"):
        raise RetrieverUnavailable(
            f"ai.rag.backend must be auto|vector|lexical, got {config.backend!r}"
        )
    if backend in ("auto", "vector"):
        try:
            retriever = VectorRetriever(
                kb, embed_fn=embed_fn, embedding_model=config.embedding_model
            )
            logger.info("ATT&CK retriever: vector (FAISS, %s)",
                        config.embedding_model)
            return retriever
        except RetrieverUnavailable as exc:
            if backend == "vector":
                raise
            logger.info("vector retriever unavailable (%s); using lexical BM25",
                        exc)
    retriever = LexicalRetriever(kb)
    logger.info("ATT&CK retriever: lexical BM25 over %d techniques", len(kb))
    return retriever
