"""DownstreamAdapter -- w=0.3, a later system succeeded or failed.

PLAN.md §3's adapter table asks for "interface + one reference
implementation" here. The interface IS `base.FeedbackAdapter` -- there is no
separate abstract class in this design, matching the codebase's Protocol-only
convention (PHASE0-CONTRACT.md §8) -- and `DownstreamAdapter` is the one
reference implementation: a generic "a later step in the pipeline reported
success or failure" webhook shape.

This is also the adapter the guessed-reward gate names directly: "a
successful downstream event (r=1, w=0.3) must move Q up" (D-011). `r` here is
always outcome polarity, never the adapter's own weight -- `dispatch_feedback`
resolves `w` separately and the two are never allowed to trade places.
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

__all__ = ["DownstreamAdapter"]

# "status"/"result" are the natural shape for a downstream success/failure
# webhook; "outcome" lets a caller submit an already-canonical polarity.
_POLARITY_KEYS: tuple[str, ...] = ("outcome", "status", "result")


class DownstreamAdapter:
    """w=0.3 (`scoring.adapter_weights["downstream"]`): a later system in the
    pipeline succeeded or failed."""

    adapter_class: ClassVar[AdapterClass] = AdapterClass.DOWNSTREAM

    def to_outcome(self, raw: Mapping[str, object]) -> FeedbackEvent:
        guard_no_caller_weight(raw)
        polarity = resolve_polarity(raw, _POLARITY_KEYS)
        return FeedbackEvent(
            adapter=self.adapter_class,
            outcome=polarity,
            payload=extract_payload(raw, drop=frozenset({"status", "result"})),
            event_id=require_event_id(raw),
            occurred_at=optional_datetime(raw.get("occurred_at")),
        )
