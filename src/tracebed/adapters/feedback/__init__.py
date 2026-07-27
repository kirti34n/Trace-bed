"""Host signal -> outcome-event adapters (PLAN.md §3/§7, invariant 8).

Four adapter classes, each with a SERVER-DERIVED trust weight
(`scoring.adapter_weights`, never accepted, inferred, or synthesised from
caller data):

  - `VerdictAdapter`       (w=1.0) -- an explicit human or authoritative
                                       judgement. Built fully.
  - `CorrectionAdapter`    (w=0.8) -- inferred from a real output diff;
                                       derives a graded r.
  - `DownstreamAdapter`    (w=0.3) -- a later system succeeded or failed.
  - `ImplicitAdapter`      (w=0.0) -- logged only, never scored.

`operator_edit` is deliberately NOT in this list and is not exported as an
adapter -- it is a dashboard action that bypasses the scorer entirely and
supersedes a memory directly through `domain.state_machine.apply` (D-032).
It lives in `base` so the distinction is visible in one place; see its
docstring for exactly why it cannot be routed through `dispatch_feedback`.
"""

from __future__ import annotations

from tracebed.adapters.feedback.base import (
    GRADED_R_PAYLOAD_KEY,
    MAX_GUARD_DEPTH,
    NEGATIVE_TOKENS,
    POSITIVE_TOKENS,
    AdapterIdentityMismatch,
    AmbiguousSignal,
    AmbiguousSignalSink,
    CallerSuppliedGradedR,
    CallerSuppliedWeight,
    FeedbackAdapter,
    NoSignal,
    RefusedSignal,
    ScorerPort,
    UnscannablePayload,
    dispatch_feedback,
    guard_no_caller_weight,
    operator_edit,
    resolve_polarity,
    resolve_weight,
)
from tracebed.adapters.feedback.correction import CorrectionAdapter
from tracebed.adapters.feedback.downstream import DownstreamAdapter
from tracebed.adapters.feedback.implicit import ImplicitAdapter
from tracebed.adapters.feedback.verdict import VerdictAdapter

__all__ = [
    "GRADED_R_PAYLOAD_KEY",
    "MAX_GUARD_DEPTH",
    "NEGATIVE_TOKENS",
    "POSITIVE_TOKENS",
    "AdapterIdentityMismatch",
    "AmbiguousSignal",
    "AmbiguousSignalSink",
    "CallerSuppliedGradedR",
    "CallerSuppliedWeight",
    "CorrectionAdapter",
    "DownstreamAdapter",
    "FeedbackAdapter",
    "ImplicitAdapter",
    "NoSignal",
    "RefusedSignal",
    "ScorerPort",
    "UnscannablePayload",
    "VerdictAdapter",
    "dispatch_feedback",
    "guard_no_caller_weight",
    "operator_edit",
    "resolve_polarity",
    "resolve_weight",
]
