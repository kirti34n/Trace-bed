"""Tier A parsers -- the LLM-free operational lane (PLAN.md §7 Phase 2).

Four extractors turn structural facts already present in a run's trace events
into Tier A candidate memories: repeated tool errors, output-schema
violations, per-tool latency outliers, and recurring call sequences that
precede a failure. Every one of them emits `TierANote`s only (template +
closed-vocabulary enum, D-019). `TierALane` owns scanning, state
construction, and shared cap enforcement after the extractors return their
pure proposals.

Two cross-cutting behaviours all four share, both documented in `base.py`:
every tool identity that reaches a note must have been declared in the run's
own `run_start` `tool_manifest` (`require_declared_tools`, default True), and
the lane applies one `tier_a.candidate_cap_per_run` budget across all four
extractors rather than one budget per extractor.
"""

from __future__ import annotations

from tracebed.workers.extractors.base import (
    IDENTIFIER_RE,
    MAX_DURATION_MS,
    TIER_A_KIND_MEM_TYPES,
    CandidateCapTracker,
    ExtractionOutcome,
    Extractor,
    TierACandidateProposal,
    ToolEventRecord,
    build_candidate_item,
    estimate_tier_a_token_count,
    mean_duration_ms,
    read_tool_events,
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
    "TIER_A_KIND_MEM_TYPES",
    "CandidateCapTracker",
    "ExtractionOutcome",
    "Extractor",
    "LatencyOutlierExtractor",
    "SchemaFailureExtractor",
    "SequencePatternExtractor",
    "TierACandidateProposal",
    "ToolEventRecord",
    "ToolFailureExtractor",
    "build_candidate_item",
    "estimate_tier_a_token_count",
    "mean_duration_ms",
    "read_tool_events",
    "structural_hash",
    "try_build_note",
]
