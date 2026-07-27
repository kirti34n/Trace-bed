"""sequence_pattern: recurring call sequences preceding failure -> a structural
signature note (PLAN.md §7).

For each `error` event in a run, takes the last `n_gram` `tool_call` events
(by trace position) that preceded it in the SAME run, forming an ordered
tool-id signature. Signatures (paired with the error's `error_class`) that
recur across the supplied batch of runs at least `min_repeat_count` times
become one `TierANote` each. Only tool_ids (structured, identifier-shaped)
and an error-class enum ever reach the note -- no call argument, no error
body, and no natural-language content of any kind.

The note's `tool_id` field carries the JOINED signature (tool ids separated
by `.`, which the identifier charset `^[A-Za-z0-9_.:-]{1,128}$` already
permits); `tool_version` carries `seqlen{n}` so a sequence note is
distinguishable, at a glance, from a single-tool note produced by
`tool_failure`/`schema_failure`/`latency_outlier`.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping, Sequence
from datetime import datetime

from tracebed.core.scans import ReviewQueueWriter
from tracebed.core.scans.tier_a_template import ErrorClassEnum
from tracebed.domain.clock import Clock
from tracebed.domain.config import EffectiveConfig
from tracebed.domain.enums import MemType
from tracebed.domain.events import TraceEvent
from tracebed.domain.ids import RunId
from tracebed.domain.scope import ProjectScope
from tracebed.workers.extractors.base import (
    CandidateCapTracker,
    ExtractionOutcome,
    MemoryWriterPort,
    emit_candidate,
    mean_duration_ms,
    read_tool_events,
    resolve_cap_tracker,
    structural_hash,
    try_build_note,
)

__all__ = ["SequencePatternExtractor"]

_MEM_TYPE = MemType.LESSON
_KIND = "failure_precursor_sequence"

_GroupKey = tuple[tuple[str, ...], ErrorClassEnum]


class _Occ:
    """One (run, matched sequence, time-to-failure) occurrence of a group.

    `seq_index` is the failing event's position in its run and exists only to
    give `_Occ` a TOTAL order: two failures in the same run can share a
    timestamp, and ordering on `ts` alone left `primary_run_id` — and so which
    run is charged against `tier_a.candidate_cap_per_run` — dependent on the
    caller's dict iteration order.
    """

    __slots__ = ("duration_ms", "run_id", "seq_index", "ts")

    def __init__(self, run_id: RunId, ts: datetime, duration_ms: int, seq_index: int) -> None:
        self.run_id = run_id
        self.ts = ts
        self.duration_ms = duration_ms
        self.seq_index = seq_index


class SequencePatternExtractor:
    """Recurring-failure-precursor extractor. See module docstring.

    CONTRACT GAP: `n_gram` (how many preceding calls form the signature),
    `min_sequence_length` (the floor below which a "sequence" is too short to
    be meaningful), and `min_repeat_count` (how many recurrences make it a
    pattern) have no `EffectiveConfig` field, matching this package's other
    three extractors' identical gap -- see `tool_failure.py`'s docstring.
    """

    def __init__(
        self,
        *,
        n_gram: int = 3,
        min_sequence_length: int = 2,
        min_repeat_count: int = 2,
    ) -> None:
        if n_gram < 1:
            raise ValueError("n_gram must be >= 1")
        if min_sequence_length < 1 or min_sequence_length > n_gram:
            raise ValueError("min_sequence_length must be in [1, n_gram]")
        if min_repeat_count < 2:
            raise ValueError(
                "min_repeat_count must be >= 2 -- a single occurrence is not 'recurring'"
            )
        self._n_gram = n_gram
        self._min_sequence_length = min_sequence_length
        self._min_repeat_count = min_repeat_count

    def extract(
        self,
        scope: ProjectScope,
        traces: Mapping[RunId, Sequence[TraceEvent]],
        *,
        cfg: EffectiveConfig,
        clock: Clock,
        writer: MemoryWriterPort,
        review_writer: ReviewQueueWriter | None = None,
        cap_tracker: CandidateCapTracker | None = None,
        require_declared_tools: bool = True,
    ) -> list[ExtractionOutcome]:
        groups: dict[_GroupKey, list[_Occ]] = defaultdict(list)
        for run_id, events in traces.items():
            records = read_tool_events(
                run_id, events, require_declared_tools=require_declared_tools
            )
            calls = [r for r in records if r.kind == "call" and r.tool_id is not None]
            errors = [r for r in records if r.kind == "error"]
            for error in errors:
                if error.error_class is None:  # pragma: no cover - guaranteed by read_tool_events
                    continue
                preceding = [c for c in calls if c.seq_index < error.seq_index]
                if len(preceding) < self._min_sequence_length:
                    continue
                window = preceding[-self._n_gram :]
                signature = tuple(c.tool_id for c in window if c.tool_id is not None)
                if len(signature) < self._min_sequence_length:
                    continue
                first_call_ts = window[0].ts
                time_to_failure_ms = max(
                    0, round((error.ts - first_call_ts).total_seconds() * 1000)
                )
                groups[(signature, error.error_class)].append(
                    _Occ(
                        run_id=run_id,
                        ts=error.ts,
                        duration_ms=time_to_failure_ms,
                        seq_index=error.seq_index,
                    )
                )

        tracker = resolve_cap_tracker(cap_tracker, cfg)
        outcomes: list[ExtractionOutcome] = []
        for key in sorted(groups, key=lambda k: (".".join(k[0]), k[1].value)):
            occurrences = groups[key]
            if len(occurrences) < self._min_repeat_count:
                continue
            signature, error_class = key
            ordered = sorted(occurrences, key=lambda o: (o.ts, str(o.run_id), o.seq_index))
            trace_ids = tuple(sorted({o.run_id for o in ordered}, key=str))
            primary_run_id = ordered[-1].run_id
            duration_ms = mean_duration_ms([o.duration_ms for o in ordered])

            note = try_build_note(
                error_class=error_class,
                tool_id=".".join(signature),
                tool_version=f"seqlen{len(signature)}",
                count=len(ordered),
                duration_ms=duration_ms,
                payload_class_hash=structural_hash(list(signature), sort=False),
            )
            if note is None:
                # Reachable, and deliberately a drop rather than a truncation:
                # `".".join(signature)` can exceed the 128-char identifier
                # ceiling for long tool ids, and truncating would fuse two
                # genuinely different sequences into one note's tool_id while
                # `payload_class_hash` still said they were different. A
                # missing note is recoverable from the trace; a note whose
                # rendered sequence disagrees with its own hash is not.
                continue

            outcomes.append(
                emit_candidate(
                    scope=scope,
                    clock=clock,
                    cfg=cfg,
                    writer=writer,
                    note=note,
                    mem_type=_MEM_TYPE,
                    kind=_KIND,
                    trace_ids=trace_ids,
                    primary_run_id=primary_run_id,
                    cap_tracker=tracker,
                    review_writer=review_writer,
                )
            )
        return outcomes
