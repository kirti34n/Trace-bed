"""CorrectionAdapter -- w=0.8, inferred from an output diff.

PLAN.md §3's adapter table asks for "interface + one reference
implementation" that "computes a real diff and derives a graded r". The
interface is `base.FeedbackAdapter`; this is the one reference
implementation, comparing the agent's original output against a
human/system-corrected version with `difflib.SequenceMatcher` -- a real
diff, not a length heuristic or a byte-equality check dressed up as one.

The graded ratio is carried in `payload[base.GRADED_R_PAYLOAD_KEY]`, which
`dispatch_feedback` reads in preference to the wire's binary `outcome`
literal (D-011's `r` stays a float in [0,1] either way; `FeedbackEvent`
itself is frozen and its `outcome` field stays binary for wire/schema
compatibility, PHASE0-CONTRACT.md §3.5). A no-op diff -- the corrected output
is the same as the original, once NFC-normalised -- means nothing was
corrected, so nothing is reported: `NoSignal`, not a zero-magnitude event.
"""

from __future__ import annotations

import difflib
import unicodedata
from collections.abc import Mapping
from typing import ClassVar, Literal

from tracebed.adapters.feedback.base import (
    GRADED_R_PAYLOAD_KEY,
    AmbiguousSignal,
    NoSignal,
    extract_payload,
    guard_no_caller_weight,
    optional_datetime,
    require_event_id,
)
from tracebed.domain.enums import AdapterClass
from tracebed.domain.events import FeedbackEvent

__all__ = ["MAX_DIFF_CHARS", "CorrectionAdapter", "similarity_ratio"]

# Ratio >= floor discretises to "positive" for the wire's binary outcome
# field; below it, "negative". The graded ratio itself is what actually
# reaches scoring (`base._extract_r`) -- this threshold only decides the
# Literal the wire-compatible half of the event carries. Deliberately the
# midpoint of the [0,1] ratio interval and NOT a config field: PLAN.md §6's
# scoring section has no entry for it, and inventing one would make the
# audit label of an event project-overridable while the value that actually
# moves Q (the ratio) stayed fixed -- reported as a contract_gap instead.
_POSITIVE_FLOOR: float = 0.5

_ORIGINAL_KEY = "original_output"
_CORRECTED_KEY = "corrected_output"

# `SequenceMatcher` is O(n*m) in the worst case and BOTH operands here are
# caller-controlled bytes arriving on a webhook that authenticates but does
# not otherwise rate-limit. Two multi-megabyte "outputs" is a CPU-exhaustion
# primitive dressed as feedback (the cost-exhaustion class PLAN.md §9 keeps
# on the backlog), so the diff refuses oversized input rather than computing
# it. The ceiling mirrors `api.models.MAX_QUERY_TEXT_CHARS`, the value this
# codebase already chose for "the largest free-text field a caller may send";
# it is mirrored rather than imported because `adapters` must not depend on
# `api` (the same "mirror, don't import" move C-33 made for the api/ingest
# pair).
MAX_DIFF_CHARS: int = 32_768


def _without_outputs(raw: Mapping[str, object]) -> dict[str, object]:
    """`raw` with the two output fields replaced by their sizes.

    Every `AmbiguousSignal` this adapter raises carries its raw payload to
    `AmbiguousSignalSink.log_ambiguous`, i.e. to a durable write on the
    trace. `MAX_DIFF_CHARS` would be a fiction if the oversized path refused
    to *diff* two 100MB "outputs" and then handed both of them to that write
    anyway -- the CPU exhaustion would simply become storage exhaustion, from
    the same request, with the size ceiling doing nothing but changing which
    resource is consumed. The same elision applies to the malformed-field
    path, where one side may be an oversized string and the other a non-string
    that never reached the ceiling check at all. Lengths are kept because they
    are the only part of these two fields an operator reading the log needs;
    the outputs themselves are already in the trace behind a pointer.
    """
    elided = {k: v for k, v in raw.items() if k not in (_ORIGINAL_KEY, _CORRECTED_KEY)}
    for key in (_ORIGINAL_KEY, _CORRECTED_KEY):
        value = raw.get(key)
        elided[f"{key}_elided_len"] = len(value) if isinstance(value, str) else None
    return elided


def similarity_ratio(original: str, corrected: str) -> float:
    """A real diff: `difflib.SequenceMatcher.ratio()` over NFC-normalised
    text -- 1.0 for identical strings, falling toward 0.0 as the correction
    rewrites more of the original. NFC-normalised for the same reason
    `domain.canonical.content_hash` is: two byte-different but
    canonically-identical strings must not manufacture a phantom diff.
    """
    a = unicodedata.normalize("NFC", original)
    b = unicodedata.normalize("NFC", corrected)
    return difflib.SequenceMatcher(None, a, b).ratio()


class CorrectionAdapter:
    """w=0.8 (`scoring.adapter_weights["correction_adapter"]`): inferred from
    a human or downstream system correcting the agent's *output* -- distinct
    from `base.operator_edit`, which edits a *memory* and never goes through
    an adapter at all (D-032)."""

    adapter_class: ClassVar[AdapterClass] = AdapterClass.CORRECTION_ADAPTER

    def to_outcome(self, raw: Mapping[str, object]) -> FeedbackEvent:
        guard_no_caller_weight(raw)
        # Resolved BEFORE the diff, not after it as the last step of a
        # successful parse: `event_id` is the cheapest possible rejection and
        # the diff is the most expensive work in this package. A signal that
        # can never be deduped must not first buy a quadratic `SequenceMatcher`
        # run over two caller-sized strings.
        event_id = require_event_id(raw)
        original = raw.get(_ORIGINAL_KEY)
        corrected = raw.get(_CORRECTED_KEY)
        if not isinstance(original, str) or not isinstance(corrected, str):
            raise AmbiguousSignal(
                f"correction adapter: '{_ORIGINAL_KEY}' and '{_CORRECTED_KEY}' must both be "
                "present strings",
                _without_outputs(raw),
            )
        if len(original) > MAX_DIFF_CHARS or len(corrected) > MAX_DIFF_CHARS:
            # Refused as ambiguous, not as an error: nothing about the signal
            # is illegal, we simply will not spend an unbounded quadratic diff
            # to manufacture a reward from it. Ambiguous is precisely
            # "logged on the trace, never scored" (invariant 8).
            raise AmbiguousSignal(
                f"correction adapter: output exceeds {MAX_DIFF_CHARS} characters "
                f"({len(original)}/{len(corrected)}); refusing to diff",
                _without_outputs(raw),
            )

        normalized_original = unicodedata.normalize("NFC", original)
        normalized_corrected = unicodedata.normalize("NFC", corrected)
        if normalized_original == normalized_corrected:
            # Nothing was corrected -- there is no signal here at all, not a
            # zero-magnitude one (the task's own framing: "a no-op diff
            # yields no event").
            raise NoSignal(
                f"correction adapter: '{_CORRECTED_KEY}' == '{_ORIGINAL_KEY}' (no-op diff)"
            )

        ratio = similarity_ratio(original, corrected)
        polarity: Literal["positive", "negative"] = (
            "positive" if ratio >= _POSITIVE_FLOOR else "negative"
        )

        payload = extract_payload(raw, drop=frozenset({_ORIGINAL_KEY, _CORRECTED_KEY}))
        payload[GRADED_R_PAYLOAD_KEY] = ratio
        payload["original_len"] = len(original)
        payload["corrected_len"] = len(corrected)

        return FeedbackEvent(
            adapter=self.adapter_class,
            outcome=polarity,
            payload=payload,
            event_id=event_id,
            occurred_at=optional_datetime(raw.get("occurred_at")),
        )
