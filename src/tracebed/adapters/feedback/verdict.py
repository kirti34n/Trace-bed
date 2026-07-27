"""VerdictAdapter -- w=1.0, an explicit human or authoritative judgement.

PLAN.md §3's adapter table names this the one to "build fully": an explicit
verdict claims to already BE ground truth, so this adapter's polarity
resolution is deliberately strict (a closed, case-insensitive token
vocabulary) -- an adapter that "interprets" an authoritative signal loosely
converts it into a guessed one, which is exactly what invariant 8 forbids.
Feeds both the webhook + per-adapter mapping config and the dashboard
manual-verdict UI PLAN.md's ports table names as the shipped default for
`FeedbackPort`.
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

__all__ = ["VerdictAdapter"]

# Either key resolves: "outcome" lets the dashboard's manual-verdict UI submit
# an already-canonical polarity directly; "verdict" is the host-webhook shape
# (e.g. "approved" / "rejected") that needs mapping through the shared
# vocabulary in `base.resolve_polarity`.
_POLARITY_KEYS: tuple[str, ...] = ("outcome", "verdict")


class VerdictAdapter:
    """w=1.0 (`scoring.adapter_weights["verdict"]`): an explicit human or
    authoritative judgement."""

    adapter_class: ClassVar[AdapterClass] = AdapterClass.VERDICT

    def to_outcome(self, raw: Mapping[str, object]) -> FeedbackEvent:
        guard_no_caller_weight(raw)
        polarity = resolve_polarity(raw, _POLARITY_KEYS)
        return FeedbackEvent(
            adapter=self.adapter_class,
            outcome=polarity,
            payload=extract_payload(raw),
            event_id=require_event_id(raw),
            occurred_at=optional_datetime(raw.get("occurred_at")),
        )
