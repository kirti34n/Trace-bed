"""latency_outlier: statistical latency outliers per tool -> a duration note
(PLAN.md §7).

Per `(tool_id, tool_version_hash)`, builds a robust baseline (median + MAD, scaled
by the usual 1.4826 constant that makes MAD comparable to a standard
deviation under a roughly-normal distribution) over that tool's successful
(`tool_result`) call durations, then flags any call whose duration exceeds
`median + z * scaled_mad`. This is LLM-free, structural arithmetic over
`duration_ms` values a tool adapter already reported -- no error body, no
free text, is ever read.

Median/MAD rather than mean/stdev: a single genuine outlier should not itself
inflate the baseline it is being measured against, which a mean/stdev
baseline does (an outlier pulls the mean toward itself and the stdev
widens, making the very next outlier of the same size look unremarkable).
"""

from __future__ import annotations

import statistics
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

__all__ = ["LatencyOutlierExtractor"]

_MEM_TYPE = MemType.EPISODIC
_KIND = "latency_outlier"

# median-absolute-deviation -> standard-deviation-equivalent scale factor for
# a normal distribution (the standard constant; not a business threshold).
_MAD_SCALE = 1.4826

_ToolKey = tuple[str, str]


def _median_and_scaled_mad(durations: Sequence[int]) -> tuple[float, float]:
    med = statistics.median(durations)
    mad = statistics.median(abs(d - med) for d in durations)
    return med, mad * _MAD_SCALE


class LatencyOutlierExtractor:
    """Per-tool latency-outlier extractor. See module docstring.

    CONTRACT GAP: none of `min_samples` (baseline sample-size floor),
    `zscore` (the outlier threshold in scaled-MAD units), or
    `min_repeat_count` (how many outliers make a reportable pattern) has an
    `EffectiveConfig` field -- PLAN.md §6 has no `tier_a.*` entries for
    latency-baseline statistics at all. Every one is a constructor parameter
    with a documented default, per hard rule 4, not a literal in the
    arithmetic below.

    CONTRACT GAP: `ErrorClassEnum` (owned by the `scans` chunk, frozen for
    this chunk -- see PHASE0-CONTRACT.md §4) has no member for "unusually
    slow but successful call"; every existing member names a failure mode,
    and a latency outlier is specifically a call that did NOT fail. `UNKNOWN`
    is reused here as the closest neutral fit rather than mis-labelling the
    note `TIMEOUT` (which would claim the call failed when it did not).
    """

    def __init__(
        self,
        *,
        min_samples: int = 5,
        zscore: float = 3.0,
        min_repeat_count: int = 2,
    ) -> None:
        if min_samples < 2:
            raise ValueError("min_samples must be >= 2 -- a baseline needs a spread to measure")
        if zscore <= 0:
            raise ValueError("zscore must be > 0")
        if min_repeat_count < 2:
            raise ValueError(
                "min_repeat_count must be >= 2 -- a single outlier is not yet a pattern"
            )
        self._min_samples = min_samples
        self._zscore = zscore
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
        by_tool: dict[_ToolKey, list[ToolEventRecord]] = defaultdict(list)
        for run_id, events in traces.items():
            for record in read_tool_events(
                run_id, events, require_declared_tools=require_declared_tools
            ):
                if (
                    record.kind != "result"
                    or record.tool_id is None
                    or record.tool_version_hash is None
                    or record.duration_ms is None
                ):
                    continue
                by_tool[(record.tool_id, record.tool_version_hash)].append(record)

        tracker = resolve_cap_tracker(cap_tracker, cfg)
        outcomes: list[ExtractionOutcome] = []
        for key in sorted(by_tool):
            records = by_tool[key]
            durations = [r.duration_ms for r in records if r.duration_ms is not None]
            if len(durations) < self._min_samples:
                continue
            median, scaled_mad = _median_and_scaled_mad(durations)
            if scaled_mad == 0:
                # Every call took the same time: nothing is distinguishable
                # as an outlier without inventing a non-zero spread. Refusing
                # is the safe direction -- it can only suppress a note, never
                # fabricate one from a flat baseline.
                continue
            threshold = median + self._zscore * scaled_mad
            # `duration_ms is not None` for every record in `records` (the
            # read loop above filters on it); spelling that out beats
            # `r.duration_ms or 0`, which silently reads a genuine 0ms call as
            # "no measurement" and would hide the invariant if it ever broke.
            outliers = [
                r for r in records if r.duration_ms is not None and r.duration_ms > threshold
            ]
            if len(outliers) < self._min_repeat_count:
                continue

            tool_id, tool_version_hash = key
            ordered = sorted(outliers, key=lambda r: r.order_key())
            trace_ids = tuple(sorted({r.run_id for r in ordered}, key=str))
            primary_run_id = ordered[-1].run_id

            duration_ms = mean_duration_ms(
                [r.duration_ms for r in ordered if r.duration_ms is not None]
            )

            keys: list[str] = []
            for r in ordered:
                keys.extend(r.payload_keys)

            note = try_build_note(
                error_class=ErrorClassEnum.UNKNOWN,
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
