"""Tier A parsers -- the LLM-free operational lane (PLAN.md §7 Phase 2).

Four extractors turn structural facts already present in a run's trace events
into Tier A candidate memories: repeated tool errors, output-schema
violations, per-tool latency outliers, and recurring call sequences that
precede a failure. Every one of them emits `TierANote`s only (template +
closed-vocabulary enum, D-019) and runs `core.scans.scan` before anything
reaches `state_machine.apply` -- see `base.py` for the shared emission path.

Two cross-cutting behaviours all four share, both documented in `base.py`:
every tool identity that reaches a note must have been declared in the run's
own `run_start` `tool_manifest` (`require_declared_tools`, default True), and
all four accept a shared `cap_tracker` so one `tier_a.candidate_cap_per_run`
budget can span the whole Tier A lane for a run rather than one per extractor.
"""

from __future__ import annotations

from tracebed.workers.extractors.base import (
    IDENTIFIER_RE,
    MAX_DURATION_MS,
    CandidateCapTracker,
    ExtractionOutcome,
    Extractor,
    MemoryWriterPort,
    ToolEventRecord,
    emit_candidate,
    mean_duration_ms,
    read_tool_events,
    resolve_cap_tracker,
    structural_hash,
    try_build_note,
)
from tracebed.workers.extractors.latency_outlier import LatencyOutlierExtractor
from tracebed.workers.extractors.schema_failure import SchemaFailureExtractor
from tracebed.workers.extractors.sequence_pattern import SequencePatternExtractor
from tracebed.workers.extractors.tool_failure import ToolFailureExtractor

__all__ = [
    "IDENTIFIER_RE",
    "MAX_DURATION_MS",
    "CandidateCapTracker",
    "ExtractionOutcome",
    "Extractor",
    "LatencyOutlierExtractor",
    "MemoryWriterPort",
    "SchemaFailureExtractor",
    "SequencePatternExtractor",
    "ToolEventRecord",
    "ToolFailureExtractor",
    "emit_candidate",
    "mean_duration_ms",
    "read_tool_events",
    "resolve_cap_tracker",
    "structural_hash",
    "try_build_note",
]
