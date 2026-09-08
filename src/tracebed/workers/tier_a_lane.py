"""Pure Tier-A planning for the trace-learning worker.

Tier A turns already-decrypted trace events into *candidate plans*.  It does
not own a repository, review queue, or job queue: persistence belongs to the
fenced trace-learning finalizer.  Keeping this boundary strict matters for a
leased job: a lost lease must be able to discard every plaintext-derived plan
without leaving a partial memory or review behind.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, replace

from tracebed.core.scans import ScanContext, ScanResult, scan
from tracebed.core.scans.tier_a_template import render_note
from tracebed.domain.clock import Clock
from tracebed.domain.config import MAX_TIER_A_INDIVIDUAL_REJECTIONS_PER_RESULT, EffectiveConfig
from tracebed.domain.enums import Lane, MemType, ProvenanceClass, TrustTier
from tracebed.domain.events import TraceEvent
from tracebed.domain.ids import RunId
from tracebed.domain.memory import NewMemoryItem
from tracebed.domain.scope import ProjectScope
from tracebed.workers.extractors import (
    CandidateCapTracker,
    ExtractionOutcome,
    Extractor,
    LatencyOutlierExtractor,
    SchemaFailureExtractor,
    SequencePatternExtractor,
    TierACandidateProposal,
    ToolFailureExtractor,
    build_candidate_item,
)
from tracebed.workers.trace_learning import TierARejectionOverflow, build_tier_a_rejection_overflow

__all__ = [
    "TierALane",
    "TierAPlan",
    "TierAPlannedCandidate",
    "TierAScanRejection",
    "default_extractors",
]


@dataclass(frozen=True, slots=True)
class TierAPlannedCandidate:
    """A scanned Tier-A candidate awaiting one fenced finalization transaction."""

    item: NewMemoryItem
    scan_result: ScanResult
    primary_run_id: RunId
    contributing_run_ids: tuple[RunId, ...]


@dataclass(frozen=True, slots=True)
class TierAScanRejection:
    """A deterministic scan refusal to persist only if the lease is still held."""

    mem_type: MemType
    content_hash: str
    suite_version: str
    reasons: tuple[str, ...]
    run_id: RunId


@dataclass(frozen=True, slots=True)
class TierAPlan:
    """Immutable, side-effect-free result of one deterministic Tier-A pass."""

    candidates: tuple[TierAPlannedCandidate, ...]
    rejections: tuple[TierAScanRejection, ...]
    outcomes: tuple[ExtractionOutcome, ...]
    rejection_overflow: TierARejectionOverflow | None = None


def default_extractors() -> tuple[Extractor, ...]:
    """The fixed planning order, which also defines cap and dedupe precedence."""

    return (
        ToolFailureExtractor(),
        SchemaFailureExtractor(),
        LatencyOutlierExtractor(),
        SequencePatternExtractor(),
    )


@dataclass(frozen=True, slots=True)
class TierALane:
    """Plan Tier-A candidates without repository, review, or queue I/O."""

    cfg: EffectiveConfig
    clock: Clock
    extractors: tuple[Extractor, ...] = field(default_factory=default_extractors)
    require_declared_tools: bool = True

    def __post_init__(self) -> None:
        if not self.extractors:
            raise ValueError("TierALane needs at least one extractor to plan")

    def plan(
        self,
        scope: ProjectScope,
        traces: Mapping[RunId, Sequence[TraceEvent]],
    ) -> TierAPlan:
        """Return deterministic candidates and rejections with no external writes.

        Extractor order is deliberately load-bearing.  The first proposal for
        an identical rendered note wins before the shared per-run cap is
        reserved; rejected scans release no resource because they never take
        one.  This means replaying the same archive yields the same plan and a
        duplicate cannot starve a distinct candidate for its primary run.
        """

        tracker = CandidateCapTracker(cap=self.cfg.tier_a.candidate_cap_per_run)
        seen_content: set[str] = set()
        candidates: list[TierAPlannedCandidate] = []
        all_rejections: list[TierAScanRejection] = []
        rejection_hash_by_content: dict[str, str] = {}
        outcomes: list[ExtractionOutcome] = []

        for extractor in self.extractors:
            for proposal in extractor.propose(
                traces, require_declared_tools=self.require_declared_tools
            ):
                content = render_note(proposal.note)
                result = scan(
                    content,
                    context=ScanContext(
                        project_id=scope.project_id,
                        mem_type=proposal.mem_type,
                        trust_tier=TrustTier.A,
                        provenance_class=ProvenanceClass.PARSER,
                        lane=Lane.OPERATIONAL,
                    ),
                )

                if result.content_hash in seen_content:
                    outcomes.append(
                        _outcome(proposal, content, skipped_reason="duplicate_candidate")
                    )
                    continue
                seen_content.add(result.content_hash)

                if not result.passed:
                    rejection_hash_by_content[content] = result.content_hash
                    all_rejections.append(
                        TierAScanRejection(
                            mem_type=proposal.mem_type,
                            content_hash=result.content_hash,
                            suite_version=result.suite_version,
                            reasons=result.reasons,
                            run_id=proposal.primary_run_id,
                        )
                    )
                    outcomes.append(
                        _outcome(
                            proposal,
                            content,
                            skipped_reason=f"scan_rejected: {'; '.join(result.reasons)}",
                        )
                    )
                    continue

                if not tracker.try_reserve(proposal.primary_run_id):
                    outcomes.append(
                        _outcome(
                            proposal,
                            content,
                            skipped_reason=(
                                "tier_a.candidate_cap_per_run "
                                f"({tracker.cap}) already reserved for run "
                                f"{proposal.primary_run_id}"
                            ),
                        )
                    )
                    continue

                item = build_candidate_item(
                    scope=scope,
                    clock=self.clock,
                    cfg=self.cfg,
                    proposal=proposal,
                )
                candidates.append(
                    TierAPlannedCandidate(
                        item=item,
                        scan_result=result,
                        primary_run_id=proposal.primary_run_id,
                        contributing_run_ids=proposal.contributing_run_ids,
                    )
                )
                outcomes.append(_outcome(proposal, content, skipped_reason=None))

        ordered_rejections = tuple(sorted(all_rejections, key=_rejection_key))
        retained_rejections = ordered_rejections[:MAX_TIER_A_INDIVIDUAL_REJECTIONS_PER_RESULT]
        rejection_overflow = build_tier_a_rejection_overflow(
            tuple(
                (rejection.content_hash, rejection.mem_type, rejection.suite_version, rejection.reasons)
                for rejection in ordered_rejections
            )
        )
        if rejection_overflow is not None:
            omitted_reasons_by_hash = {
                rejection.content_hash: rejection.reasons
                for rejection in ordered_rejections[
                    MAX_TIER_A_INDIVIDUAL_REJECTIONS_PER_RESULT:
                ]
            }
            outcomes = [
                replace(
                    outcome,
                    skipped_reason=(
                        "scan_rejected_aggregated: "
                        + "; ".join(
                            sorted(
                                omitted_reasons_by_hash[
                                    rejection_hash_by_content[outcome.content]
                                ]
                            )
                        )
                    ),
                )
                if rejection_hash_by_content.get(outcome.content) in omitted_reasons_by_hash
                and outcome.skipped_reason is not None
                else outcome
                for outcome in outcomes
            ]

        return TierAPlan(
            candidates=tuple(candidates),
            rejections=retained_rejections,
            outcomes=tuple(outcomes),
            rejection_overflow=rejection_overflow,
        )


def _outcome(
    proposal: TierACandidateProposal,
    content: str,
    *,
    skipped_reason: str | None,
) -> ExtractionOutcome:
    """Keep legacy extractor-observation telemetry useful without minting IDs."""

    return ExtractionOutcome(
        note=proposal.note,
        primary_run_id=proposal.primary_run_id,
        contributing_run_ids=proposal.contributing_run_ids,
        memory_id=None,
        skipped_reason=skipped_reason,
        content=content,
    )


def _rejection_key(rejection: TierAScanRejection) -> tuple[str, str, str, tuple[str, ...]]:
    return (
        rejection.content_hash,
        rejection.mem_type.value,
        rejection.suite_version,
        tuple(sorted(rejection.reasons)),
    )
