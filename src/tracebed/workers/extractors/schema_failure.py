"""schema_failure: output-schema violations -> a schema-failure note keyed by
payload class hash (PLAN.md §7).

Restricted to `error` events whose `error_class` is `SCHEMA_VALIDATION`
(`ErrorClassEnum.SCHEMA_VALIDATION`). Grouped not by the tool's generic error
shape but by the *validated schema's* structural fingerprint: the sorted set
of field NAMES the validator named as offending (`payload["schema_fields"]`),
never the rejected values -- this is the vector D-019 found (Pydantic v2's own
`input_value=` embeds attacker-controlled content verbatim), so this extractor
never reads `schema_fields`' VALUES, only whichever field names a validator
already classified structurally.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping, Sequence

from tracebed.core.scans import ReviewQueueWriter
from tracebed.core.scans.tier_a_template import ErrorClassEnum, HexDigest
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

__all__ = ["SchemaFailureExtractor"]

_MEM_TYPE = MemType.EPISODIC
_KIND = "schema_failure_pattern"

_GroupKey = tuple[str, str, HexDigest]


def _schema_hash(record: ToolEventRecord) -> HexDigest:
    """The record's structural fingerprint: `schema_fields` when the upstream
    validator named specific offending fields, else the error event's own
    payload key names as a fallback (still structural, never a value)."""
    fields = record.schema_fields if record.schema_fields else record.payload_keys
    return structural_hash(fields)


class SchemaFailureExtractor:
    """Output-schema-violation extractor, keyed by payload class hash. See
    module docstring.

    CONTRACT GAP: `min_repeat_count` has no `EffectiveConfig` field, matching
    `ToolFailureExtractor`'s own gap -- see that module's docstring.
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
                if record.error_class is not ErrorClassEnum.SCHEMA_VALIDATION:
                    continue
                groups[(record.tool_id, record.tool_version_hash, _schema_hash(record))].append(record)

        tracker = resolve_cap_tracker(cap_tracker, cfg)
        outcomes: list[ExtractionOutcome] = []
        for key in sorted(groups, key=lambda k: (k[0], k[1], str(k[2]))):
            records = groups[key]
            if len(records) < self._min_repeat_count:
                continue
            tool_id, tool_version_hash, schema_hash = key
            ordered = sorted(records, key=lambda r: r.order_key())
            trace_ids = tuple(sorted({r.run_id for r in ordered}, key=str))
            primary_run_id = ordered[-1].run_id

            duration_ms = mean_duration_ms(
                [r.duration_ms for r in ordered if r.duration_ms is not None]
            )

            note = try_build_note(
                error_class=ErrorClassEnum.SCHEMA_VALIDATION,
                tool_id=tool_id,
                tool_version=tool_version_hash,
                count=len(ordered),
                duration_ms=duration_ms,
                payload_class_hash=schema_hash,
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
