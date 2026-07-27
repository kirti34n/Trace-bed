"""LLM transport errors and per-worker model resolution (PLAN.md §6 `llm.*`, D-008).

`workers.epochs` (a sibling Phase 3 chunk) already owns the scoring-epoch mechanism PLAN.md
means by "the PIN is model id + version + sampling params, recorded on EVERY artifact together
with scoring_epoch": `JudgePin` is exactly that triple (plus the `prompt_hash` that names which
exact instructions produced a call), `ScoringEpoch` mirrors the `scoring_epoch` table
(migrations/0001_registries.sql) row for row, and `resolve_epoch`/`assert_same_epoch` are the
mint-or-reuse and cross-epoch-refusal functions invariant 7 requires. This module does NOT
redefine any of that -- `workers.distiller` imports `workers.epochs` directly and builds a
`JudgePin` inline (a one-line dataclass call needs no wrapper). Adapters staying free of a
`workers` import also keeps the dependency direction the rest of the codebase uses: workers
depend on adapters, not the reverse.

What IS this chunk's own concern, and lives here: the transport-level failure vocabulary for
`adapters.llm.openai_compat.OpenAiCompatibleLLMProvider` (mirroring
`adapters.embedding.pinning.EmbeddingProviderError`, defined beside its own driver rather than in
`domain/errors.py`, because `LLMProviderPort` is a background-worker-only port and its driver
failures are this adapter's concern, not a cross-chunk vocabulary entry), and the one small piece
of config wiring every Phase 3 generative worker needs: resolving which model string a named
worker actually calls, honouring `LLMProviderConfig.per_worker_overrides` before falling back to
that worker's configured default (`judge_model` / `distiller_model`).
"""

from __future__ import annotations

from tracebed.domain.config import LLMProviderConfig
from tracebed.domain.errors import ConfigError, TracebedError

__all__ = [
    "LLMProviderError",
    "LLMProviderTimeout",
    "resolve_worker_model",
]


class LLMProviderError(TracebedError):
    """An `LLMProviderPort` driver's transport succeeded but its payload was unusable, or the
    transport itself failed for a reason other than the driver's own configured timeout.

    Mirrors `adapters.embedding.pinning.EmbeddingProviderError` -- see the module docstring.
    """


class LLMProviderTimeout(LLMProviderError):
    """The driver's own configured deadline elapsed before a complete response arrived.

    Distinct from `LLMProviderError` for the same reason `adapters.embedding.gemini` splits
    `EmbeddingTimeout` from `EmbeddingProviderError`: a caller needs to tell "ran out of time"
    from "the endpoint or its response was broken" without inspecting exception text.
    """


def resolve_worker_model(cfg: LLMProviderConfig, *, worker: str, default_model: str) -> str:
    """The model string a named worker actually calls: `per_worker_overrides[worker]` if set,
    else `default_model` (the caller passes `cfg.judge_model`/`cfg.distiller_model` -- whichever
    field names that worker's own configured default; `LLMProviderConfig` has no per-worker
    lookup table beyond the override dict, only two named top-level fields, PLAN.md §6).

    Refuses a blank result rather than returning it. `per_worker_overrides` is a plain
    `dict[str, str]` with no value constraint (`domain.config.LLMProviderConfig`), so
    `{"distiller": ""}` is a startable deployment -- and the resolved model string is what
    `workers.epochs.JudgePin` pins an epoch on. Returning `""` mints a permanent `scoring_epoch`
    row naming no model at all, stamps it on whatever artifacts follow, and only THEN fails,
    as an untyped `ValueError` out of the driver's own argument check. Invariant 7 exists so
    that a stamped epoch says which judge produced an artifact; an epoch pinned to the empty
    string satisfies `assert_same_epoch` forever while meaning nothing.
    """
    model = cfg.per_worker_overrides.get(worker, default_model)
    if not model.strip():
        raise ConfigError(
            f"llm model for worker {worker!r} resolves to a blank string; a blank model id "
            "pins a scoring_epoch to no model at all (invariant 7)"
        )
    return model
