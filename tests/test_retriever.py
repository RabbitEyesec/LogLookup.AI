"""Phase 10 acceptance: deterministic ATT&CK candidate retrieval."""

from __future__ import annotations

import numpy as np
import pytest

from engine.ai.kb import AttackKB
from engine.ai.retriever import (
    Candidate,
    LexicalRetriever,
    RetrieverUnavailable,
    VectorRetriever,
    build_retriever,
)
from engine.config import RagConfig
from tests.test_kb import bundle  # noqa: F401 - fixture reuse


@pytest.fixture()
def kb(bundle) -> AttackKB:  # noqa: F811
    return AttackKB.from_bundle(bundle, source="fixture")


def test_lexical_ranks_relevant_technique_first(kb):
    retriever = LexicalRetriever(kb)
    hits = retriever.retrieve("repeated failed logins brute force password", k=2)
    assert hits and hits[0].uid == "T1110"
    hits = retriever.retrieve("powershell encoded command execution", k=2)
    assert hits and hits[0].uid == "T1059.001"


def test_lexical_is_deterministic(kb):
    retriever = LexicalRetriever(kb)
    first = retriever.retrieve("credential dumping lateral movement", k=4)
    second = retriever.retrieve("credential dumping lateral movement", k=4)
    assert [c.uid for c in first] == [c.uid for c in second]
    assert [c.score for c in first] == [c.score for c in second]


def test_lexical_empty_query(kb):
    assert LexicalRetriever(kb).retrieve("", k=4) == []


def _hash_embedder(dim: int = 32):
    """Deterministic test embedder: token-hash bag-of-words vectors."""

    def embed(texts):
        out = np.zeros((len(texts), dim), dtype="float32")
        for row, text in enumerate(texts):
            for token in text.lower().split():
                out[row][hash(token) % dim] += 1.0
        return out

    return embed


def test_vector_backend_with_injected_embedder(kb):
    retriever = VectorRetriever(kb, embed_fn=_hash_embedder())
    hits = retriever.retrieve(kb.get("T1110").document(), k=1)
    assert isinstance(hits[0], Candidate)
    assert hits[0].uid == "T1110"  # a document retrieves itself
    assert hits[0].score == pytest.approx(1.0, abs=1e-4)


def test_vector_k_clamped_to_kb_size(kb):
    retriever = VectorRetriever(kb, embed_fn=_hash_embedder())
    assert len(retriever.retrieve("brute force", k=99)) == len(kb)


def test_build_retriever_auto_falls_back(kb, monkeypatch):
    # Force the sentence-transformers import path to fail: auto -> lexical.
    import engine.ai.retriever as module

    def unavailable(_name):
        raise RetrieverUnavailable("no embedding stack in tests")

    monkeypatch.setattr(module, "_sentence_transformer_embedder", unavailable)
    retriever = build_retriever(kb, RagConfig(backend="auto"))
    assert retriever.backend == "lexical"
    with pytest.raises(RetrieverUnavailable):
        build_retriever(kb, RagConfig(backend="vector"))


def test_build_retriever_vector_with_embedder(kb):
    retriever = build_retriever(
        kb, RagConfig(backend="vector"), embed_fn=_hash_embedder()
    )
    assert retriever.backend == "vector"


def test_build_retriever_rejects_unknown_backend(kb):
    with pytest.raises(RetrieverUnavailable):
        build_retriever(kb, RagConfig(backend="quantum"))
