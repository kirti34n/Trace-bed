"""The ONE place a deployment's `EmbeddingPort` driver is constructed from config.

Extracted from `api.main._build_embedder` in the integration pass that wired the periodic
learning plane. The reason is not tidiness: `workers.embedder` is the only code in the tree
that WRITES `memory_item.embedding_model_id`/`embedding_model_version`, and
`hotpath.retriever` is the only code that embeds a QUERY against those stored vectors. Those
two live in different processes (`tracebed-api` and `tracebed-worker`). If each process built
its own driver from its own reading of config, a divergence between them would put query
vectors and stored vectors in different vector spaces while every row still carried a
correct-looking pin — the exact silent failure `Embedder._assert_driver_matches_pin` exists to
catch, reached by a different route. One constructor, imported by both, removes the route.

Placement: `adapters/embedding/`, not `api/`. The worker process must not import `api.main`
(that would pull FastAPI, the route table and the app object into a process that serves no
HTTP), and `hotpath/` must not import either — `scripts/purity_check.py`'s reachability walk
over `hotpath/` still sees only `adapters.embedding`, exactly as `_build_embedder`'s own
docstring required, because the driver is INJECTED into the hot path rather than constructed
by it.
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

from tracebed.adapters.embedding.gemini import GeminiEmbeddingClient
from tracebed.adapters.embedding.pinning import ModelPin
from tracebed.domain.errors import ConfigError

if TYPE_CHECKING:  # pragma: no cover - typing only
    from tracebed.adapters.ports import EmbeddingPort
    from tracebed.domain.clock import Clock
    from tracebed.domain.config import TracebedSettings

__all__ = ["build_embedding_driver", "model_pin_from_settings"]


def model_pin_from_settings(settings: TracebedSettings) -> ModelPin:
    """The deployment's configured `(model_id, model_version, dim)` triple.

    Separate from `build_embedding_driver` because `workers.embedder.Embedder` needs the pin
    ITSELF (it stamps those two columns on every row) as well as the driver, and reading the
    same three fields twice at two call sites is how the two drift.
    """
    return ModelPin(
        model_id=settings.embedding.model_id,
        model_version=settings.embedding.model_version,
        dim=settings.embedding.dim,
    )


def build_embedding_driver(settings: TracebedSettings, clock: Clock) -> EmbeddingPort:
    """The configured `EmbeddingPort` driver, pinned (D-007, PLAN.md §6 `embedding.*`).

    A vector endpoint, never a generative client — invariant 1 permits exactly this one
    outbound model call on the read path, under its own `embed_timeout_ms` sub-budget.
    """
    pin = model_pin_from_settings(settings)
    if settings.embedding.driver == "onnx-local":
        if settings.embedding.onnx_model_path is None or settings.embedding.onnx_model_hash is None:
            raise ConfigError(
                "embedding.driver='onnx-local' requires embedding.onnx_model_path and "
                "embedding.onnx_model_hash (the pinned model and its integrity hash)"
            )
        raise ConfigError(
            "the onnx-local embedding driver needs an injected tokenizer, which no "
            "deployment in this repository names yet; configure embedding.driver='gemini'"
        )
    api_key = os.environ.get(settings.llm.api_key_env)
    if not api_key:
        # Loud at startup rather than a per-request `EmbeddingProviderError` that the
        # retriever would fail open on: an embedder that can never succeed makes every single
        # retrieval a silent `degraded_lexical`, which looks like a working deployment on
        # every dashboard. In the WORKER process the same misconfiguration is worse and
        # quieter still: the embedding sweep would burn its timeout on every chunk of every
        # project forever and the ANN arm would stay empty with no error anywhere.
        raise ConfigError(
            f"embedding driver 'gemini' needs an API key in ${settings.llm.api_key_env}"
        )
    return GeminiEmbeddingClient(
        base_url=settings.llm.base_url, api_key=api_key, pin=pin, clock=clock
    )
