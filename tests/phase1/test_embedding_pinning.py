"""Tests for the embedding pin registry (`pinning.py`) and the ONNX driver's
load-time refusals (`onnx_local.py`).

The two ONNX tests below exercise real conditions rather than mocks: the
hash-mismatch test hashes an actual temp file, and the missing-runtime test
relies on this environment genuinely lacking `onnxruntime` (it is
deliberately not a `pyproject.toml` dependency — see `onnx_local.py`'s module
docstring) rather than patching an import.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from pathlib import Path

import pytest

from tracebed.adapters.embedding.onnx_local import (
    OnnxLocalEmbeddingClient,
    OnnxModelIntegrityError,
    OnnxRuntimeUnavailable,
)
from tracebed.adapters.embedding.pinning import (
    EmbeddingDimensionMismatch,
    EmbeddingPinMismatch,
    EmbeddingProviderError,
    ModelPin,
    assert_pin_matches,
    validate_batch,
)

# `pytest -m phase1` is what `harness/phase1_gate.py` runs; an unmarked file is
# not merely skipped by that selector, it is never collected, so its coverage is
# invisible to the gate report rather than reported as missing.
pytestmark = pytest.mark.phase1


def test_assert_pin_matches_passes_when_identical() -> None:
    pin = ModelPin(model_id="gemini-embedding-2", model_version="2026-01", dim=768)
    assert_pin_matches("gemini-embedding-2", "2026-01", pin)  # must not raise


@pytest.mark.parametrize(
    ("row_model_id", "row_version"),
    [
        ("gemini-embedding-2", "2025-12"),  # stale version of the same model
        ("onnx-local-mini", "2026-01"),  # a different model entirely
    ],
)
def test_assert_pin_matches_raises_on_any_disagreement(
    row_model_id: str, row_version: str
) -> None:
    pin = ModelPin(model_id="gemini-embedding-2", model_version="2026-01", dim=768)
    with pytest.raises(EmbeddingPinMismatch) as exc_info:
        assert_pin_matches(row_model_id, row_version, pin)
    err = exc_info.value
    assert err.row_model_id == row_model_id
    assert err.row_model_version == row_version
    assert err.configured is pin


def test_embedding_dimension_mismatch_reports_both_dimensions() -> None:
    pin = ModelPin(model_id="m", model_version="v", dim=768)
    err = EmbeddingDimensionMismatch(actual_dim=384, configured=pin)
    assert "384" in str(err)
    assert "768" in str(err)
    assert err.actual_dim == 384
    assert err.configured is pin


_BATCH_PIN = ModelPin(model_id="m", model_version="v", dim=3)


def test_validate_batch_accepts_a_well_formed_batch() -> None:
    validate_batch(
        [[0.0, 1.0, 2.0], [3.0, -4.0, 5.5]], expected=2, configured=_BATCH_PIN
    )  # must not raise


def test_validate_batch_rejects_a_count_disagreement() -> None:
    """One vector short means every later vector is attributed to the wrong
    input text -- silent, and unrecoverable once written."""
    with pytest.raises(EmbeddingProviderError):
        validate_batch([[0.0, 1.0, 2.0]], expected=2, configured=_BATCH_PIN)


@pytest.mark.parametrize(
    "vector",
    [
        pytest.param([0.0, 1.0], id="too-short"),
        pytest.param([0.0, 1.0, 2.0, 3.0], id="too-long"),
        pytest.param([], id="empty"),
    ],
)
def test_validate_batch_rejects_a_dimension_disagreement(vector: list[float]) -> None:
    with pytest.raises(EmbeddingDimensionMismatch) as exc_info:
        validate_batch([vector], expected=1, configured=_BATCH_PIN)
    assert exc_info.value.actual_dim == len(vector)


@pytest.mark.parametrize(
    "poison",
    [
        pytest.param(float("nan"), id="nan"),
        pytest.param(float("inf"), id="inf"),
        pytest.param(float("-inf"), id="-inf"),
    ],
)
def test_validate_batch_rejects_non_finite_components(poison: float) -> None:
    """A non-finite component has the right count and the right dimension, so
    nothing downstream ever raises on it -- it just poisons every ANN distance
    the vector participates in."""
    with pytest.raises(EmbeddingProviderError):
        validate_batch([[0.0, poison, 2.0]], expected=1, configured=_BATCH_PIN)


def test_validate_batch_checks_every_vector_not_just_the_first() -> None:
    """A driver that validated only `vectors[0]` would pass a batch whose
    second vector is the broken one."""
    with pytest.raises(EmbeddingDimensionMismatch):
        validate_batch([[0.0, 1.0, 2.0], [0.0, 1.0]], expected=2, configured=_BATCH_PIN)
    with pytest.raises(EmbeddingProviderError):
        validate_batch(
            [[0.0, 1.0, 2.0], [0.0, float("nan"), 2.0]], expected=2, configured=_BATCH_PIN
        )


class _StubTokenizer:
    """Never actually invoked in these tests: construction fails before `embed()`."""

    def encode_batch(
        self, texts: Sequence[str]
    ) -> tuple[list[list[int]], list[list[int]]]:  # pragma: no cover
        raise AssertionError("tokenizer must not be used when construction itself fails")


def test_onnx_hash_mismatch_refuses_to_load(tmp_path: Path) -> None:
    model_path = tmp_path / "model.onnx"
    model_path.write_bytes(b"not a real onnx model, just needs a stable hash")
    wrong_hash = "0" * 64

    with pytest.raises(OnnxModelIntegrityError) as exc_info:
        OnnxLocalEmbeddingClient(
            model_path=model_path,
            model_hash=wrong_hash,
            pin=ModelPin(model_id="onnx-local-mini", model_version="1", dim=384),
            tokenizer=_StubTokenizer(),
        )
    err = exc_info.value
    assert err.model_path == model_path
    assert err.expected_sha256 == wrong_hash
    assert err.actual_sha256 == hashlib.sha256(model_path.read_bytes()).hexdigest()


def test_onnx_hash_mismatch_refuses_to_load_even_without_onnxruntime_installed(
    tmp_path: Path,
) -> None:
    """The integrity check must fire before onnxruntime is even imported --
    a wrong file at the pinned path is refused independent of what happens
    to be installed on this machine."""
    model_path = tmp_path / "model.onnx"
    model_path.write_bytes(b"another fake file with a deliberately wrong pin")

    with pytest.raises(OnnxModelIntegrityError):
        OnnxLocalEmbeddingClient(
            model_path=model_path,
            model_hash="f" * 64,
            pin=ModelPin(model_id="onnx-local-mini", model_version="1", dim=384),
            tokenizer=_StubTokenizer(),
        )


def test_onnx_missing_runtime_fails_at_construction_not_first_query(tmp_path: Path) -> None:
    """Exercises the genuine absence of `onnxruntime` in this environment:
    construction must fail here, never on the first `embed()` call."""
    try:
        import onnxruntime  # noqa: F401
    except ImportError:
        pass
    else:  # pragma: no cover - only if onnxruntime happens to be installed
        pytest.skip("onnxruntime is installed here; cannot exercise its absence")

    content = b"a correctly-hashed but otherwise fake model file"
    model_path = tmp_path / "model.onnx"
    model_path.write_bytes(content)
    correct_hash = hashlib.sha256(content).hexdigest()

    with pytest.raises(OnnxRuntimeUnavailable):
        OnnxLocalEmbeddingClient(
            model_path=model_path,
            model_hash=correct_hash,
            pin=ModelPin(model_id="onnx-local-mini", model_version="1", dim=384),
            tokenizer=_StubTokenizer(),
        )
