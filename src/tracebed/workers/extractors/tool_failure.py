"""tool_failure: repeated tool errors -> an error-class Tier A note (PLAN.md §7).

"Which tool, which class, how often" -- groups `error` trace events across the
supplied batch of runs by `(tool_id, tool_version_hash, error_class)` and emits one
`TierANote` per group that has recurred at least `min_repeat_count` times. The
note's `count`/`duration_ms` are aggregates over the group; `payload_class_hash`
is a structural hash of the union of the group's error-event payload key NAMES
-- never of any error body content (D-019; see `base.py`'s module docstring for
the reading convention and its contract gaps).
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping, Sequence

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
    ToolEventRecord,
    emit_candidate,
    mean_duration_ms,
    read_tool_events,
    resolve_cap_tracker,
    structural_hash,
    try_build_note,
)

__all__ = ["ToolFailureExtractor"]

_MEM_TYPE = MemType.EPISODIC
_KIND = "tool_failure_pattern"

_GroupKey = tuple[str, str, ErrorClassEnum]


class ToolFailureExtractor:
    """Repeated-tool-error extractor. See module docstring.

    CONTRACT GAP: `min_repeat_count` (how many occurrences make a tool error a
    "pattern" rather than a one-off) has no `EffectiveConfig` field -- only
    the *emission* cap (`tier_a.candidate_cap_per_run`) exists in PLAN.md §6.
    A constructor parameter, not a bare literal, per hard rule 4.
    """

    def __init__(self, *, min_repeat_count: int = 2) -> None:
        if min_repeat_count < 2:
            raise ValueError(
                "min_repeat_count must be >= 2 -- a single occurrence is not 'repeated'"
            )
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
        groups: dict[_GroupKey, list[ToolEventRecord]] = defaultdict(list)
        for run_id, events in traces.items():
            for record in read_tool_events(
                run_id, events, require_declared_tools=require_declared_tools
            ):
                if record.kind != "error" or record.tool_id is None or record.tool_version_hash is None:
                    continue
                if record.error_class is None:  # pragma: no cover - guaranteed by read_tool_events
                    continue
                groups[(record.tool_id, record.tool_version_hash, record.error_class)].append(record)

        tracker = resolve_cap_tracker(cap_tracker, cfg)
        outcomes: list[ExtractionOutcome] = []
        for key in sorted(groups, key=lambda k: (k[0], k[1], k[2].value)):
            records = groups[key]
            if len(records) < self._min_repeat_count:
                continue
            tool_id, tool_version_hash, error_class = key
            ordered = sorted(records, key=lambda r: r.order_key())
            trace_ids = tuple(sorted({r.run_id for r in ordered}, key=str))
            primary_run_id = ordered[-1].run_id

            duration_ms = mean_duration_ms(
                [r.duration_ms for r in ordered if r.duration_ms is not None]
            )

            keys: list[str] = []
            for r in ordered:
                keys.extend(r.payload_keys)

            note = try_build_note(
                error_class=error_class,
                tool_id=tool_id,
                tool_version=tool_version_hash,
                count=len(ordered),
                duration_ms=duration_ms,
                payload_class_hash=structural_hash(keys),
            )
            if note is None:
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
