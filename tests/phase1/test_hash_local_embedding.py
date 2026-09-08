"""Focused checks for the deterministic hash-local embedding fallback."""

from __future__ import annotations

import json
import math
import os
import subprocess
import sys
from pathlib import Path
from typing import cast

import pytest

from tracebed.adapters.embedding.hash_local import HashLocalEmbeddingClient, _features
from tracebed.adapters.embedding.pinning import ModelPin
from tracebed.domain.clock import FakeClock
from tracebed.domain.config import HASH_LOCAL_MODEL_ID, HASH_LOCAL_MODEL_VERSION
from tracebed.domain.errors import ConfigError, EmbeddingTimeout

pytestmark = pytest.mark.phase1
_PIN = ModelPin(model_id=HASH_LOCAL_MODEL_ID, model_version=HASH_LOCAL_MODEL_VERSION, dim=257)
_REPO_ROOT = Path(__file__).resolve().parents[2]


def _embedder(clock: FakeClock | None = None) -> HashLocalEmbeddingClient:
    return HashLocalEmbeddingClient(pin=_PIN, clock=clock)


def test_nfkc_casefold_and_unigram_bigram_features_are_stable() -> None:
    assert _features("CAFÉ cafe\u0301") == ["café", "café", "café\x1fcafé"]
    assert _embedder().embed(["CAFÉ cafe\u0301"], timeout_ms=100) == _embedder().embed(
        ["café café"], timeout_ms=100
    )


def test_vectors_are_deterministic_l2_normalized_and_input_ordered() -> None:
    texts = ["alpha beta", "beta alpha"]
    first = _embedder().embed(texts, timeout_ms=100)
    second = _embedder().embed(texts, timeout_ms=100)
    assert first == second
    assert len(first) == len(texts)
    assert all(len(vector) == _PIN.dim for vector in first)
    assert all(math.isclose(sum(value * value for value in vector), 1.0) for vector in first)
    assert first[0] != first[1]


def test_golden_vector_and_driver_identity_are_stable() -> None:
    embedder = HashLocalEmbeddingClient(
        pin=ModelPin(
            model_id=HASH_LOCAL_MODEL_ID,
            model_version=HASH_LOCAL_MODEL_VERSION,
            dim=8,
        )
    )
    assert embedder.model_id == "tracebed-hash-local"
    assert embedder.model_version == "sha256-unigram-bigram-v1"
    assert embedder.embed(["alpha beta"], timeout_ms=100) == [
        [0.0, 0.5773502691896258, 0.0, 0.0, 0.0, 0.5773502691896258, 0.5773502691896258, 0.0]
    ]


def test_gemini_or_arbitrary_identity_is_rejected_for_hash_local() -> None:
    with pytest.raises(ConfigError, match="hash-local embedding identity"):
        HashLocalEmbeddingClient(
            pin=ModelPin(model_id="gemini-embedding-2", model_version="test", dim=8)
        )


def test_vectors_do_not_depend_on_python_hash_seed() -> None:
    probe = """
import json
from tracebed.adapters.embedding.hash_local import HashLocalEmbeddingClient
from tracebed.adapters.embedding.pinning import ModelPin
from tracebed.domain.config import HASH_LOCAL_MODEL_ID, HASH_LOCAL_MODEL_VERSION

vector = HashLocalEmbeddingClient(
    pin=ModelPin(HASH_LOCAL_MODEL_ID, HASH_LOCAL_MODEL_VERSION, 8)
).embed(["alpha beta"], timeout_ms=100)[0]
print(json.dumps(vector, separators=(",", ":")))
"""

    def run_with_seed(seed: str) -> list[float]:
        environment = os.environ.copy()
        environment["PYTHONHASHSEED"] = seed
        environment["PYTHONPATH"] = str(_REPO_ROOT / "src")
        result = subprocess.run(  # noqa: S603 -- fixed interpreter and local source-only probe
            [sys.executable, "-c", probe],
            cwd=_REPO_ROOT,
            env=environment,
            check=True,
            capture_output=True,
            text=True,
        )
        return cast(list[float], json.loads(result.stdout))

    assert run_with_seed("0") == run_with_seed("random")


def test_empty_or_punctuation_only_input_has_a_nonzero_unit_vector() -> None:
    vectors = _embedder().embed(["", "---"], timeout_ms=100)
    assert all(any(value != 0.0 for value in vector) for vector in vectors)
    assert all(math.isclose(sum(value * value for value in vector), 1.0) for vector in vectors)
    assert vectors[0] == vectors[1]


class _AdvancingClock(FakeClock):
    def monotonic_ms(self) -> float:
        self.advance(milliseconds=2)
        return super().monotonic_ms()


def test_timeout_is_checked_before_material_work_continues() -> None:
    clock = _AdvancingClock()
    with pytest.raises(EmbeddingTimeout):
        _embedder(clock).embed(["one two three"], timeout_ms=1)


def test_nonpositive_budget_refuses_before_hashing() -> None:
    with pytest.raises(EmbeddingTimeout):
        _embedder().embed(["anything"], timeout_ms=0)
