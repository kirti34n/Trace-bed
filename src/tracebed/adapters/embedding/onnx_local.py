"""Local ONNX embedding driver (PLAN.md §6 `embedding.secondary_driver`; D-007).

The fully-supported secondary `EmbeddingPort` driver for air-gapped or
latency-sensitive deployments: a pinned model file (path + sha256 hash)
loaded through `onnxruntime`. Two structural refusals make this driver safe
to point at an arbitrary file path:

  1. **Hash-checked before anything else.** `_sha256_file(model_path)` is
     compared against `model_hash` before `onnxruntime` is even imported.
     A model file that does not match its pin raises
     `OnnxModelIntegrityError` unconditionally — this is what makes "a
     silently-swapped embedding model corrupts every vector in the store"
     (PLAN.md §10) structurally impossible for this driver: there is no path
     from "wrong file at this path" to "session built from it".
  2. **`onnxruntime` import checked at construction, not at first query.**
     `onnxruntime` is deliberately NOT a `pyproject.toml` dependency (adding
     it would need its own `scripts/license_policy.toml` entry, the way
     psycopg's LGPL needed one — D-005) — it is an optional import behind the
     documented `tracebed[onnx]` extra. If it is missing, `__init__` raises
     `OnnxRuntimeUnavailable` immediately, so a misconfigured deployment fails
     at startup wiring, never on the hot path's first retrieval.

CONTRACT_GAP (tokenization): PLAN.md §6 pins `embedding.onnx_model_path` /
`onnx_model_hash` but names no tokenizer, and no tokenizer library is part of
this chunk's dependency set (`pyproject.toml` is owned by a different chunk
and is frozen for this chunk). Rather than hardcoding an assumed
`tokenizers`/`transformers` import this module would then own without a
license-gate entry, tokenization is an injected `OnnxTokenizer` port —
a deployment wiring the ONNX driver supplies the tokenizer that matches its
pinned model. This keeps construction honest instead of silently assuming a
specific tokenizer library is present.

CONTRACT_GAP (extra not yet declared): the `tracebed[onnx]` extra referenced
above (`onnxruntime>=1.20`, which pulls `numpy` — this module's array handling
and `_mean_pool` need it, and it is deliberately not a top-level dependency
either) is documented here but `pyproject.toml` is outside this chunk's file
list — flagged for whoever owns that file next. Every `numpy` import below is
function-local and sits behind the constructor's `onnxruntime` check, so the
default Gemini deployment never touches it.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

from tracebed.adapters.embedding.pinning import (
    EmbeddingProviderError,
    ModelPin,
    validate_batch,
)
from tracebed.domain.clock import Clock, SystemClock
from tracebed.domain.errors import EmbeddingTimeout, TracebedError

if TYPE_CHECKING:
    import numpy as np  # type: ignore[import-not-found]

__all__ = [
    "OnnxLocalEmbeddingClient",
    "OnnxModelIntegrityError",
    "OnnxRuntimeUnavailable",
    "OnnxTokenizer",
]


class OnnxRuntimeUnavailable(TracebedError):
    """`onnxruntime` is not importable in this environment.

    Raised at `OnnxLocalEmbeddingClient.__init__`, never at first `embed()`
    call — a missing optional dependency must fail deployment wiring, not the
    hot path's first query.
    """


class OnnxModelIntegrityError(TracebedError):
    """The file at `model_path` does not hash to its configured `model_hash`.

    Refuses to load unconditionally: there is no "load anyway with a
    warning" path, because a silently-swapped embedding model corrupts every
    vector already in the store against no migration (PLAN.md §10).
    """

    def __init__(self, *, model_path: Path, expected_sha256: str, actual_sha256: str) -> None:
        super().__init__(
            f"model file {model_path} hashes to {actual_sha256!r}, expected "
            f"{expected_sha256!r} -- refusing to load"
        )
        self.model_path = model_path
        self.expected_sha256 = expected_sha256
        self.actual_sha256 = actual_sha256


@runtime_checkable
class OnnxTokenizer(Protocol):
    """What `OnnxLocalEmbeddingClient` needs to turn text into model inputs.

    See the module docstring's CONTRACT_GAP: this is an injected seam rather
    than a hardcoded tokenizer-library import.
    """

    def encode_batch(self, texts: Sequence[str]) -> tuple[list[list[int]], list[list[int]]]:
        """Returns `(input_ids, attention_mask)`, one padded row per text, in
        the same order as `texts`."""
        ...


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


class OnnxLocalEmbeddingClient:
    """Pinned local ONNX driver. Satisfies `EmbeddingPort` structurally."""

    def __init__(
        self,
        *,
        model_path: Path,
        model_hash: str,
        pin: ModelPin,
        tokenizer: OnnxTokenizer,
        clock: Clock | None = None,
        providers: Sequence[str] = ("CPUExecutionProvider",),
        input_ids_name: str = "input_ids",
        attention_mask_name: str = "attention_mask",
        output_name: str = "last_hidden_state",
    ) -> None:
        # Hash-verify BEFORE the onnxruntime import check: integrity of the
        # pinned file is a property of the file itself and must be refused
        # regardless of whether onnxruntime happens to be installed on this
        # particular machine.
        actual_hash = _sha256_file(model_path)
        if actual_hash != model_hash:
            raise OnnxModelIntegrityError(
                model_path=model_path, expected_sha256=model_hash, actual_sha256=actual_hash
            )

        try:
            import onnxruntime as ort  # type: ignore[import-not-found]
        except ImportError as exc:
            raise OnnxRuntimeUnavailable(
                "onnxruntime is not installed; install the `tracebed[onnx]` extra to use "
                "the local ONNX embedding driver (see adapters/embedding/onnx_local.py)"
            ) from exc

        self._session: Any = ort.InferenceSession(str(model_path), providers=list(providers))
        self._pin = pin
        self._tokenizer = tokenizer
        self._clock: Clock = clock if clock is not None else SystemClock()
        self._input_ids_name = input_ids_name
        self._attention_mask_name = attention_mask_name
        self._output_name = output_name

    @property
    def model_id(self) -> str:
        return self._pin.model_id

    @property
    def model_version(self) -> str:
        return self._pin.model_version

    def embed(self, texts: Sequence[str], *, timeout_ms: int) -> list[list[float]]:
        """Raises `EmbeddingTimeout` past `timeout_ms`. Never retries internally.

        The budget is checked at every point where it *can* be checked: before
        any work starts (an already-spent budget never begins an inference),
        and again after tokenization — before the expensive native call, so a
        slow tokenizer that has already eaten the budget does not get to spend
        another multiple of it inside `session.run`. Only the native call
        itself is unavoidably post-hoc: it is one blocking C call that cannot
        be pre-empted mid-flight without a watchdog thread this driver
        deliberately does not spin up. Every reading comes from
        `clock.monotonic_ms()`, never a bare wall-clock call (hard rule 3).
        """
        if not texts:
            return []

        # Budget before work, not after (see docstring): a zero or negative
        # remaining budget must never start an inference.
        if timeout_ms <= 0:
            raise EmbeddingTimeout(
                f"embedding called with a {timeout_ms}ms budget; refusing to start inference"
            )

        import numpy as np

        start_ms = self._clock.monotonic_ms()
        deadline_ms = start_ms + timeout_ms

        try:
            input_ids, attention_mask = self._tokenizer.encode_batch(texts)
            ids_array = np.array(input_ids, dtype=np.int64)
            mask_array = np.array(attention_mask, dtype=np.int64)
        except Exception as exc:
            raise EmbeddingProviderError(
                "ONNX tokenization produced unusable model inputs"
            ) from exc

        if self._clock.monotonic_ms() > deadline_ms:
            raise EmbeddingTimeout(
                f"ONNX tokenization alone exceeded the {timeout_ms}ms budget; "
                "not starting inference"
            )

        try:
            outputs = self._session.run(
                [self._output_name],
                {self._input_ids_name: ids_array, self._attention_mask_name: mask_array},
            )
            vectors = _mean_pool(outputs[0], mask_array)
        except Exception as exc:
            # `EmbeddingProviderError` is the shared "the provider answered,
            # but not with something embed() can return" case; a raw
            # onnxruntime/numpy exception here would be indistinguishable from
            # a Tracebed bug to the caller (`domain.errors.TracebedError` is
            # what api/main.py's single handler keys on).
            raise EmbeddingProviderError("local ONNX inference could not be evaluated") from exc

        elapsed_ms = self._clock.monotonic_ms() - start_ms
        if elapsed_ms > timeout_ms:
            raise EmbeddingTimeout(
                f"local ONNX inference took {elapsed_ms:.0f}ms, over the {timeout_ms}ms budget"
            )

        validate_batch(vectors, expected=len(texts), configured=self._pin)
        return vectors


def _mean_pool(hidden_states: np.ndarray, attention_mask: np.ndarray) -> list[list[float]]:
    """Attention-mask-weighted mean pooling over the token axis.

    The standard sentence-embedding pooling for encoder models exported to
    ONNX with a `(batch, seq_len, hidden)` last-hidden-state output: padded
    positions (`attention_mask == 0`) are excluded from both the sum and the
    denominator so batch padding never dilutes shorter inputs' vectors.
    """
    import numpy as np

    weights = attention_mask.astype(np.float64)[:, :, None]
    summed = (hidden_states.astype(np.float64) * weights).sum(axis=1)
    counts = np.clip(weights.sum(axis=1), 1.0, None)
    pooled = summed / counts
    return [row.tolist() for row in pooled]
