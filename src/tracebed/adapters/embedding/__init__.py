"""`EmbeddingPort` implementations (PLAN.md §3 ports table, §6 `embedding.*`).

`GeminiEmbeddingClient` is the default driver; `OnnxLocalEmbeddingClient` is
the fully-supported secondary for air-gapped / latency-sensitive deployments.
Both satisfy `tracebed.adapters.ports.EmbeddingPort` structurally and are
built from a shared `ModelPin` (`pinning.py`), which is also what a caller
uses to verify a stored row's stamped model identity before trusting its
vector (`assert_pin_matches`).
"""

from __future__ import annotations

from tracebed.adapters.embedding.gemini import GeminiEmbeddingClient
from tracebed.adapters.embedding.onnx_local import (
    OnnxLocalEmbeddingClient,
    OnnxModelIntegrityError,
    OnnxRuntimeUnavailable,
    OnnxTokenizer,
)
from tracebed.adapters.embedding.pinning import (
    EmbeddingDimensionMismatch,
    EmbeddingPinMismatch,
    EmbeddingProviderError,
    ModelPin,
    assert_pin_matches,
    validate_batch,
)

__all__ = [
    "EmbeddingDimensionMismatch",
    "EmbeddingPinMismatch",
    "EmbeddingProviderError",
    "GeminiEmbeddingClient",
    "ModelPin",
    "OnnxLocalEmbeddingClient",
    "OnnxModelIntegrityError",
    "OnnxRuntimeUnavailable",
    "OnnxTokenizer",
    "assert_pin_matches",
    "validate_batch",
]
