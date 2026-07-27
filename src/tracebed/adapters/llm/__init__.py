"""`LLMProviderPort` implementations (PLAN.md §3 ports table, D-008).

`OpenAiCompatibleLLMProvider` is the default driver for the workers that gate Q and promotion --
the contribution judge, the shadow validator, and the distiller. Scoring-epoch pinning itself
(model id + version + sampling params, resolved against a `scoring_epoch` row) is owned by
`workers.epochs`, a sibling Phase 3 chunk -- see `pinning.py`'s module docstring for why that
mechanism is imported directly by consumers (`workers.distiller`) rather than re-exported here.
"""

from __future__ import annotations

from tracebed.adapters.llm.openai_compat import OpenAiCompatibleLLMProvider
from tracebed.adapters.llm.pinning import (
    LLMProviderError,
    LLMProviderTimeout,
    resolve_worker_model,
)

__all__ = [
    "LLMProviderError",
    "LLMProviderTimeout",
    "OpenAiCompatibleLLMProvider",
    "resolve_worker_model",
]
