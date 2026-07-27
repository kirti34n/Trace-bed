"""The Tier A lane coordinator -- the one caller that runs all four extractors.

Two cross-chunk defects made this module necessary; neither was fixable inside
any single extractor, because both are properties of the lane rather than of
any parser in it.

1. `tier_a.candidate_cap_per_run` is per RUN, not per extractor. Each
   `Extractor.extract` accepts an optional `CandidateCapTracker` precisely so
   one budget can span the lane, but an optional parameter nobody passes is a
   cap of 1 behaving as a cap of 4. This module builds exactly one tracker per
   batch and threads it through all four, in a fixed order, so "one candidate
   per run" is what the lane does rather than what its config field says.

2. The emission path is not idempotent. `stores.pg.repo.Repo.insert_memory_item`
   is a plain INSERT and `memory_item` carries no uniqueness constraint on
   content (migrations/0002_partitioned.sql declares `PRIMARY KEY (project_id,
   id)` and nothing else), while `queue.lease_seconds` / `queue.max_attempts`
   make redelivery of a work item ordinary rather than exceptional. Re-running
   a batch therefore re-inserts every candidate it already inserted, which
   attacks Phase 2's own gate ("net vault growth rate strictly decreasing
   week-over-week") from inside the very lane the gate measures.

   The dedupe is interposed at the WRITER, not applied to the outcomes
   afterwards, and that placement is the whole design. `emit_candidate`
   reserves a cap slot before it renders and scans, so a filter applied after
   extraction would let an already-stored note spend a run's one candidate
   slot and starve a genuinely new sibling. At the writer, the duplicate never
   becomes an INSERT and the `ExtractionOutcome` still names the memory_id of
   the row that already holds the content -- which is what idempotent means
   here, as opposed to "silently dropped".

   It has two halves and they are not the same guarantee. WITHIN one batch it
   is exact and needs nothing from any store. ACROSS batches it is exactly as
   good as the injected `KnownContentPort`; with none, a redelivered batch
   still duplicates and `TierALaneResult.dedupe_is_durable` says so rather
   than implying a promise this module cannot keep. The structural fix is a
   unique index on `(project_id, content_hash)`, which is a migration against
   Phase 0's frozen DDL -- recorded as a contract gap, not invented here.

PROJECT HOMOGENEITY (invariant 4). `run_batch` takes ONE `ProjectScope` and
attributes every trace in the batch to it; there is deliberately no per-run
project argument, so a batch cannot be assembled from two projects' traces and
write one project's observations into the other's vault.
`workers.runner.group_by_project` is what guarantees a queue batch is
single-project before it reaches here, and the dedupe cache below is likewise
keyed within one scope and rebuilt per batch -- a cache that outlived a batch
would be a cross-project read waiting to happen.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from tracebed.core.scans import ReviewQueueWriter
from tracebed.domain.canonical import content_hash
from tracebed.domain.clock import Clock
from tracebed.domain.config import EffectiveConfig
from tracebed.domain.events import TraceEvent
from tracebed.domain.ids import MemoryId, ProjectId, RunId
from tracebed.domain.memory import NewMemoryItem
from tracebed.domain.scan import ScanVerdict
from tracebed.domain.scope import ProjectScope
from tracebed.workers.extractors import (
    CandidateCapTracker,
    ExtractionOutcome,
    Extractor,
    LatencyOutlierExtractor,
    MemoryWriterPort,
    SchemaFailureExtractor,
    SequencePatternExtractor,
    ToolFailureExtractor,
)

__all__ = [
    "KnownContentPort",
    "TierALane",
    "TierALaneResult",
    "default_extractors",
]


@runtime_checkable
class KnownContentPort(Protocol):
    """"Does this project already hold a memory with exactly this content?"

    Declared here rather than imported from `stores.pg` for the reason every
    port under `workers/` is: there is no Postgres on the build machine, and a
    lane that could only be exercised against a live database is a lane that
    ships unexercised.

    Called at most once per note that has already passed the per-run cap and
    the scan, so the call count is bounded by `tier_a.candidate_cap_per_run`
    times the number of runs in the batch -- not by trace volume.

    CONTRACT GAP: no method on `stores.pg.repo.Repo` satisfies this today. The
    query it needs (a project-scoped `SELECT id FROM memory_item WHERE
    project_id = %(project_id)s AND content_hash = %(content_hash)s`) belongs
    in `stores/pg/`, which no Phase 2 chunk owned. Until it exists the lane
    runs with `known_content=None` and dedupes within a batch only.
    """

    def find_memory_by_content_hash(
        self, project_id: ProjectId, content_hash_hex: str
    ) -> MemoryId | None: ...


@dataclass(frozen=True, slots=True)
class TierALaneResult:
    """What one batch did, in enough detail to audit it without the store.

    `outcomes` is every pattern every extractor considered, in extractor order
    -- including the ones this lane refused -- so "the cap bound here" and
    "this note was already in the vault" are visible rather than inferred from
    an absence.
    """

    outcomes: tuple[ExtractionOutcome, ...]
    inserted: tuple[ExtractionOutcome, ...]
    """Notes that became a new `memory_item` row on this run of the lane."""
    deduplicated: tuple[ExtractionOutcome, ...]
    """Notes whose content the project already held. These still carry a
    `memory_id` -- the pre-existing row's -- because the run really did
    re-observe that condition; what did not happen is a second INSERT."""
    dedupe_is_durable: bool
    """`False` when no `KnownContentPort` was injected, in which case the
    dedupe covers only this batch and a redelivered batch WILL duplicate.
    Reported so a caller cannot mistake the in-batch guarantee for the
    cross-batch one."""


def default_extractors() -> tuple[Extractor, ...]:
    """The four Tier A extractors in a FIXED order.

    Order is load-bearing, not cosmetic: the cap tracker is first-come, so a
    run at its cap keeps whichever note was reserved first. A lane whose order
    varied would charge a different note against the same run's one slot from
    machine to machine, making the vault-growth curve Phase 2's soak measures
    non-reproducible. Every extractor is constructed with its documented
    defaults; the detection thresholds have no `EffectiveConfig` fields (each
    extractor's own docstring records that gap), so a caller needing different
    ones builds the tuple itself and passes it in.
    """
    return (
        ToolFailureExtractor(),
        SchemaFailureExtractor(),
        LatencyOutlierExtractor(),
        SequencePatternExtractor(),
    )


@dataclass(slots=True)
class _DedupingWriter:
    """A `MemoryWriterPort` that returns the existing row instead of inserting.

    Hashes with `domain.canonical.content_hash` -- the same function
    `Repo.insert_memory_item` hashes the content with -- so this filter and the
    column it is standing in for can never disagree about what "the same note"
    means.

    Never raises on a duplicate: `emit_candidate` treats any writer exception
    as fatal to the whole batch, so raising here would let one already-known
    note destroy every genuinely new note behind it.
    """

    inner: MemoryWriterPort
    known_content: KnownContentPort | None
    seen: dict[str, MemoryId] = field(default_factory=dict)
    was_duplicate: list[bool] = field(default_factory=list)
    """One entry per call, in call order: whether that call was answered from
    an existing row instead of inserting. A per-call log rather than a set of
    duplicate hashes, because two extractors can legitimately render the SAME
    note in one batch -- the first of those is a real insert and the second is
    a duplicate, and a set cannot tell them apart."""

    def insert_memory_item(
        self, project_id: ProjectId, item: NewMemoryItem, scan_verdict: ScanVerdict
    ) -> MemoryId:
        digest = content_hash(item.content)

        existing = self.seen.get(digest)
        if existing is None and self.known_content is not None:
            existing = self.known_content.find_memory_by_content_hash(project_id, digest)
        if existing is not None:
            self.seen[digest] = existing
            self.was_duplicate.append(True)
            return existing

        memory_id = self.inner.insert_memory_item(project_id, item, scan_verdict)
        self.seen[digest] = memory_id
        self.was_duplicate.append(False)
        return memory_id


@dataclass(slots=True)
class TierALane:
    """Runs the four extractors over one project's batch of traces."""

    cfg: EffectiveConfig
    clock: Clock
    writer: MemoryWriterPort
    review_writer: ReviewQueueWriter | None = None
    known_content: KnownContentPort | None = None
    extractors: tuple[Extractor, ...] = field(default_factory=default_extractors)
    require_declared_tools: bool = True

    def __post_init__(self) -> None:
        if not self.extractors:
            raise ValueError("TierALane needs at least one extractor to run")

    def run_batch(
        self, scope: ProjectScope, traces: Mapping[RunId, Sequence[TraceEvent]]
    ) -> TierALaneResult:
        """Extract, dedupe, and write every Tier A note this batch supports.

        The cap tracker is built ONCE here and handed to every extractor: that
        is the entire reason this method exists rather than four call sites.
        Both it and the dedupe writer are per-call, so no state from one
        batch -- and therefore from one project -- can reach the next.
        """
        tracker = CandidateCapTracker(cap=self.cfg.tier_a.candidate_cap_per_run)
        dedupe = _DedupingWriter(inner=self.writer, known_content=self.known_content)

        outcomes: list[ExtractionOutcome] = []
        for extractor in self.extractors:
            outcomes.extend(
                extractor.extract(
                    scope,
                    traces,
                    cfg=self.cfg,
                    clock=self.clock,
                    writer=dedupe,
                    review_writer=self.review_writer,
                    cap_tracker=tracker,
                    require_declared_tools=self.require_declared_tools,
                )
            )

        # Every outcome carrying a memory_id is exactly one writer call, in
        # order, so the writer's per-call log lines up positionally. Zipping
        # is what lets the same content rendered twice in one batch be split
        # correctly into one insert and one duplicate.
        written = [o for o in outcomes if o.memory_id is not None]
        if len(written) != len(dedupe.was_duplicate):
            raise AssertionError(
                f"Tier A lane bookkeeping diverged: {len(written)} outcome(s) carry a memory_id "
                f"but the writer recorded {len(dedupe.was_duplicate)} call(s)"
            )
        inserted = tuple(o for o, dup in zip(written, dedupe.was_duplicate, strict=True) if not dup)
        duplicates = tuple(o for o, dup in zip(written, dedupe.was_duplicate, strict=True) if dup)
        return TierALaneResult(
            outcomes=tuple(outcomes),
            inserted=inserted,
            deduplicated=duplicates,
            dedupe_is_durable=self.known_content is not None,
        )
