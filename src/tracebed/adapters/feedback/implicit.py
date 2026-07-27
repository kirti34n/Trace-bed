"""ImplicitAdapter -- w=0.0, LOGGED ONLY, NEVER SCORED.

PLAN.md §3's adapter table: an implicit behavioural signal (the user
continued without complaint, a session ended normally, a follow-up query
repeated the same request). `scoring.adapter_weights["implicit"] = 0.0` by
default, and `dispatch_feedback`'s w<=0 short-circuit is what actually makes
this class unscoreable -- structurally, from config, not from anything this
adapter does or omits.

That does not license guessing here, though: this adapter still resolves a
real polarity from a closed vocabulary and raises `AmbiguousSignal` when it
cannot, exactly like `VerdictAdapter`/`DownstreamAdapter`. The point is that
what gets logged on the trace is honest, even though invariant 8 guarantees
it can never move a Q value -- "logged only" should mean logged correctly,
not logged as a shrug.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import ClassVar

from tracebed.adapters.feedback.base import (
    extract_payload,
    guard_no_caller_weight,
    optional_datetime,
    require_event_id,
    resolve_polarity,
)
from tracebed.domain.enums import AdapterClass
from tracebed.domain.events import FeedbackEvent

__all__ = ["ImplicitAdapter"]

_POLARITY_KEYS: tuple[str, ...] = ("outcome", "signal", "behavior")


class ImplicitAdapter:
    """w=0.0 (`scoring.adapter_weights["implicit"]`): an inferred behavioural
    signal, never an explicit judgement. Logged only -- `dispatch_feedback`'s
    w<=0 short-circuit refuses every event this adapter can produce, before
    any Q code runs."""

    adapter_class: ClassVar[AdapterClass] = AdapterClass.IMPLICIT

    def to_outcome(self, raw: Mapping[str, object]) -> FeedbackEvent:
        guard_no_caller_weight(raw)
        polarity = resolve_polarity(raw, _POLARITY_KEYS)
        return FeedbackEvent(
            adapter=self.adapter_class,
            outcome=polarity,
            payload=extract_payload(raw, drop=frozenset({"signal", "behavior"})),
            event_id=require_event_id(raw),
            occurred_at=optional_datetime(raw.get("occurred_at")),
        )
