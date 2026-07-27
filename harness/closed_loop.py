"""THE CLOSED-LOOP DRILL — does a memory actually make it all the way round?

`docs/FIDELITY-AUDIT.md` §1: "the learning half of the system is a library, not a service ...
A deployed Tracebed today ingests traces and outcome events faithfully and learns nothing from
either." Every individual worker had a green test suite when that was written. What no test
asserted was that the workers COMPOSE — that the row one stage writes is the row the next
stage reads, in the shape it expects, and that a status the state machine approves is a status
that reaches a column.

This drill walks nine hops end to end and asserts each one with the PRODUCTION function, never
a reimplementation:

  1. TRACE INGESTED      `ingest.trace_writer.TraceWriter.run_once`
  2. TIER A EXTRACTED    `workers.tier_a_lane.TierALane.run_batch` (real extractors)
  3. EMBEDDED            `workers.embedder.Embedder.run`
  4. CORROBORATED        `workers.corroboration.CorroborationWriter.run_once`
  5. SHADOW-VALIDATED    `workers.shadow_validator.ShadowValidator.run_once`
  6. SCORED              `workers.scorer.run_scorer_batch`
  7. PROMOTED            `workers.promotion.PromotionWorker.evaluate_candidate`
  8. RETRIEVABLE         `stores.pg.search.assert_dynamically_retrievable`
  9. STATUS PERSISTED    `stores.pg.lifecycle.LifecycleWriter.persist_status`

HOW HONEST IS IT? Precisely this honest, stated up front so no reader has to infer it:

  * There is NO Postgres, Valkey or S3 on this machine (PHASE0-CONTRACT.md §12). Every hop
    that needs a store runs against an in-memory `_Vault` that implements the worker's own
    declared `Protocol`, plus — for hops 1 and 9 — the fakes the existing test suites already
    use (`tests.phase0.test_trace_writer`'s `FakeQueue`/`FakeTraceRepo`/`FakeTraceStore`, and a
    statement-recording fake pool of exactly the shape `tests/phase1/test_search_sql.py` uses).
  * Hop 9 therefore proves that `LifecycleWriter` ISSUES the correct `UPDATE memory_item` and
    the correct `INSERT INTO memory_status_log`, inside one transaction, after the RLS GUC —
    it does NOT prove Postgres accepted them. A recording fake does not evaluate SQL.
  * Hop 8 asserts the production retrievability PREDICATE FUNCTION accepts the promoted row and
    refused it at every earlier status. It does not execute a `WHERE` clause, because a fake
    cursor cannot. `tests/phase1/test_learning_repos.py` and `tests/phase1/test_search_sql.py`
    carry the `@pytest.mark.integration` versions of both claims; neither has ever run here.
  * Hops 5, 6 and 7 use in-memory repos for ports that have NO Postgres implementation at all
    (`ShadowValidatorRepoPort`, `ScorerRepoPort`, `PromotionRepoPort` — audit finding M3, still
    open). Those three hops prove the LOGIC composes. They do not prove a deployed process runs
    them, and `workers.composition.UNSCHEDULED_WORKERS` says so by name.

So: a PASS here means "the loop closes when every store method exists", not "the loop closes in
production today". The gap between those two sentences is exactly `UNSCHEDULED_WORKERS`, and
the drill prints it at the end rather than letting a green line imply otherwise.

Run: `python harness/closed_loop.py` (exit 0 on a closed loop, 1 on any broken hop).
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:  # pragma: no cover - script entry
    sys.path.insert(0, str(REPO_ROOT))

from tracebed.core.scans import ScanContext, scan  # noqa: E402
from tracebed.core.scans.tier_a_template import ErrorClassEnum  # noqa: E402
from tracebed.domain.clock import FakeClock  # noqa: E402
from tracebed.domain.config import (  # noqa: E402
    AbstentionConfig,
    BudgetConfig,
    CacheConfig,
    DerivedConfig,
    EffectiveConfig,
    KillswitchConfig,
    LifecycleConfig,
    PromotionConfig,
    ProposalConfig,
    QueueConfig,
    RetirementConfig,
    RetrievalConfig,
    ScoreConfig,
    ScoringConfig,
    SessionConfig,
    SpendConfig,
    TierAConfig,
)
from tracebed.domain.enums import (  # noqa: E402
    AdapterClass,
    Lane,
    MemType,
    ProvenanceClass,
    ScopeType,
    TrustTier,
)
from tracebed.domain.errors import GuardNotSatisfied, TracebedError  # noqa: E402
from tracebed.domain.ids import (  # noqa: E402
    AgentTypeId,
    MemoryId,
    PrincipalId,
    ProjectId,
    RunId,
    mint_memory_id,
)
from tracebed.domain.memory import NewMemoryItem, Provenance  # noqa: E402
from tracebed.domain.scan import ScanVerdict  # noqa: E402
from tracebed.domain.scope import ProjectScope  # noqa: E402
from tracebed.domain.signatures import SIG_HASH_LEN  # noqa: E402
from tracebed.domain.state_machine import Status  # noqa: E402
from tracebed.stores.pg.lifecycle import LifecycleWriter  # noqa: E402
from tracebed.stores.pg.search import assert_dynamically_retrievable  # noqa: E402
from tracebed.workers.composition import UNSCHEDULED_WORKERS  # noqa: E402
from tracebed.workers.corroboration import (  # noqa: E402
    AppendOutcome,
    CorroborationWriter,
    QuarantinedMemoryForCorroboration,
)
from tracebed.workers.edit_ops import MemoryStatusWrite  # noqa: E402
from tracebed.workers.embedder import Embedder, EmbeddingCandidateRow  # noqa: E402
from tracebed.workers.epochs import ScoringEpoch  # noqa: E402
from tracebed.workers.independence import ConfirmingRun  # noqa: E402
from tracebed.workers.promotion import CandidateMemoryRow, PromotionWorker  # noqa: E402
from tracebed.workers.scorer import QUpdate, ScoringEvent, run_scorer_batch  # noqa: E402
from tracebed.workers.shadow_validator import (  # noqa: E402
    QuarantinedMemoryRow,
    ShadowTransitionWrite,
    ShadowValidator,
)
from tracebed.workers.tier_a_lane import TierALane  # noqa: E402

__all__ = ["ClosedLoopReport", "Hop", "main", "render_text", "run_closed_loop"]

_T0 = datetime(2026, 7, 27, tzinfo=UTC)
_MANIFEST = ["tool_a", "tool_b", "tool_c"]
_DIM = 4
"""Vector width for the fake embedding driver. Deliberately tiny and deliberately NOT 768:
this drill asserts that the pin the worker stamps is the pin the driver advertises, which is a
property of the comparison, not of the width. `migrations/0002_partitioned.sql` fixes the real
column at `halfvec(768)`; the integration test in `tests/phase1/test_learning_repos.py` is where
that width is exercised."""


# --------------------------------------------------------------------------- #
# Report types
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class Hop:
    number: int
    name: str
    production_function: str
    checks: Mapping[str, bool]
    """Every named property this hop asserts. `passed` is derived from it and is NOT a field.

    This shape exists because of a mutation that survived the first version of this file. When
    `passed` was a single boolean computed from an `and` chain, DELETING one conjunct (e.g. the
    Sybil control from hop 5, or "the quarantined row got no vector" from hop 3) left both the
    drill and `tests/phase3/test_closed_loop_drill.py` green: the wrapper could only see the
    final boolean and the prose `detail`, and the prose was computed independently of the
    conjunct that had been removed. A drill whose checks can be silently dropped is the exact
    "test that cannot fail" this remediation pass keeps finding.

    Naming each property makes the wrapper able to require it BY NAME, so a deleted check is a
    missing key rather than a shorter `and` chain nobody can see.
    """
    detail: str
    proven_against: str
    """What the assertion actually ran against -- "real in-memory port", "recording fake
    pool", "pure function". Printed beside every hop so a reader never has to guess how much
    of the claim is database-backed. None of it is, on this machine."""

    def __post_init__(self) -> None:
        object.__setattr__(self, "checks", dict(self.checks))
        if not self.checks:
            raise ValueError(f"hop {self.number} ({self.name}) asserts nothing")

    @property
    def passed(self) -> bool:
        return all(self.checks.values())

    @property
    def failed_checks(self) -> tuple[str, ...]:
        return tuple(name for name, ok in self.checks.items() if not ok)


@dataclass(frozen=True, slots=True)
class ClosedLoopReport:
    hops: tuple[Hop, ...]
    unscheduled_in_production: tuple[str, ...]
    generated_at: datetime

    @property
    def closed(self) -> bool:
        return all(hop.passed for hop in self.hops)


# --------------------------------------------------------------------------- #
# The in-memory vault: one object satisfying five worker Protocols
# --------------------------------------------------------------------------- #


@dataclass
class _Row:
    """Everything the five workers between them read off one `memory_item` row."""

    id: MemoryId
    project_id: ProjectId
    status: Status
    trust_tier: TrustTier
    mem_type: MemType
    content: str
    provenance: Provenance
    status_changed_at: datetime | None
    is_failure_lesson: bool = False
    shadow_confirm_runs: tuple[RunId, ...] = ()
    embedding: tuple[float, ...] | None = None
    embedding_model_id: str | None = None
    embedding_model_version: str | None = None
    q_value: float = 0.5
    scored_use_count: int = 0
    applied_event_ids: set[UUID] = field(default_factory=set)
    updates_today: int = 0
    promotion_outcomes: int = 0
    promotion_distinct_principals: int = 0
    outcome_consistent: bool = False
    scan_repass: bool = True
    open_contradiction: bool = False


class _Vault:
    """An in-memory `memory_item` table that structurally satisfies, all at once:

      * `workers.extractors.base.MemoryWriterPort`
      * `workers.embedder.EmbeddingRepoPort`
      * `workers.corroboration.CorroborationRepoPort`
      * `workers.shadow_validator.ShadowValidatorRepoPort`
      * `workers.promotion.PromotionRepoPort`
      * `workers.scorer.ScorerRepoPort`

    ONE object rather than six fakes on purpose: the whole point of this drill is that the row
    one worker writes is the row the next worker reads. Six independent fakes, each seeded by
    the drill with what its worker expects, would prove nothing about composition — it would be
    the same "every module is fine on its own" the audit already found.

    It is a fake, and it is not the real store. What it deliberately DOES mirror is the shape
    of each contract that could hide a composition bug: `append_confirming_run` decides
    eligibility and membership together and returns three values (D-125); every read is scoped
    by `project_id` and returns nothing for another project; and no method here writes `status`
    except `persist`, which takes an already-`apply()`-approved transition.
    """

    def __init__(self, clock: FakeClock) -> None:
        self.rows: dict[MemoryId, _Row] = {}
        self.clock = clock
        self.status_writes: list[tuple[MemoryId, Status, Status]] = []
        self.q_updates: list[QUpdate] = []

    # -- MemoryWriterPort ---------------------------------------------------
    def insert_memory_item(
        self, project_id: ProjectId, item: NewMemoryItem, scan_verdict: ScanVerdict
    ) -> MemoryId:
        del scan_verdict
        memory_id = mint_memory_id()
        self.rows[memory_id] = _Row(
            id=memory_id,
            project_id=project_id,
            status=item.status,
            trust_tier=item.trust_tier,
            mem_type=item.mem_type,
            content=item.content,
            provenance=item.provenance,
            status_changed_at=self.clock.now(),
        )
        return memory_id

    # -- EmbeddingRepoPort --------------------------------------------------
    def select_needing_embedding(
        self, project_id: ProjectId, *, model_id: str, model_version: str, limit: int
    ) -> Sequence[EmbeddingCandidateRow]:
        from tracebed.domain.state_machine import RETRIEVABLE_STATUSES

        out = [
            EmbeddingCandidateRow(
                project_id=row.project_id, id=row.id, status=row.status, content=row.content
            )
            for row in sorted(self.rows.values(), key=lambda r: str(r.id))
            if row.project_id == project_id
            and row.status in RETRIEVABLE_STATUSES
            and (
                row.embedding is None
                or row.embedding_model_id != model_id
                or row.embedding_model_version != model_version
            )
        ]
        return out[:limit]

    def write_embedding(
        self,
        project_id: ProjectId,
        memory_id: MemoryId,
        embedding: Sequence[float],
        *,
        model_id: str,
        model_version: str,
    ) -> None:
        row = self.rows[memory_id]
        if row.project_id != project_id:
            raise TracebedError("cross-project embedding write")
        # All three together, mirroring the DDL CHECK the real statement relies on.
        row.embedding = tuple(embedding)
        row.embedding_model_id = model_id
        row.embedding_model_version = model_version

    # -- CorroborationRepoPort ----------------------------------------------
    def select_quarantined(
        self, project_id: ProjectId
    ) -> Sequence[QuarantinedMemoryForCorroboration]:
        return [
            QuarantinedMemoryForCorroboration(
                id=row.id,
                project_id=row.project_id,
                status=row.status,
                provenance=row.provenance,
                confirming_run_ids=row.shadow_confirm_runs,
            )
            for row in self.rows.values()
            if row.project_id == project_id and row.status is Status.QUARANTINED
        ]

    def append_confirming_run(
        self, project_id: ProjectId, memory_id: MemoryId, run_id: RunId
    ) -> AppendOutcome:
        row = self.rows.get(memory_id)
        if row is None or row.project_id != project_id or row.status is not Status.QUARANTINED:
            return AppendOutcome.ROW_NOT_ELIGIBLE
        if run_id in row.shadow_confirm_runs:
            return AppendOutcome.ALREADY_PRESENT
        row.shadow_confirm_runs = (*row.shadow_confirm_runs, run_id)
        return AppendOutcome.APPENDED

    # -- ShadowValidatorRepoPort --------------------------------------------
    def select_quarantined_for_validation(
        self, project_id: ProjectId
    ) -> Sequence[QuarantinedMemoryRow]:
        return [
            QuarantinedMemoryRow(
                id=row.id,
                project_id=row.project_id,
                status=row.status,
                trust_tier=row.trust_tier,
                mem_type=row.mem_type,
                provenance=row.provenance,
                status_changed_at=row.status_changed_at,
                is_failure_lesson=row.is_failure_lesson,
                confirming_run_ids=row.shadow_confirm_runs,
            )
            for row in self.rows.values()
            if row.project_id == project_id and row.status is Status.QUARANTINED
        ]

    def persist(
        self, project_id: ProjectId, write: ShadowTransitionWrite | Any
    ) -> None:
        """The ONE mutating status path on this fake. Shared by
        `ShadowValidatorRepoPort.persist` and `PromotionRepoPort.persist` — both take a
        transition `apply()` has already returned, and neither decides anything itself."""
        row = self.rows[write.memory_id]
        if row.project_id != project_id:
            raise TracebedError("cross-project status write")
        if row.status is not write.from_status:
            raise TracebedError(
                f"stale transition: row is {row.status.value!r}, write claims "
                f"{write.from_status.value!r}"
            )
        row.status = write.to_status
        row.status_changed_at = write.now
        self.status_writes.append((write.memory_id, write.from_status, write.to_status))

    # -- PromotionRepoPort --------------------------------------------------
    def select_candidates_for_promotion(
        self, project_id: ProjectId
    ) -> Sequence[CandidateMemoryRow]:
        return [self.candidate_row(row) for row in self.rows.values()
                if row.project_id == project_id and row.status is Status.CANDIDATE]

    def select_validated_for_retirement(self, project_id: ProjectId) -> Sequence[Any]:
        del project_id
        return []

    def insert_review_item(
        self, project_id: ProjectId, reason: str, memory_id: MemoryId | None = None
    ) -> None:
        del project_id, reason, memory_id

    def candidate_row(self, row: _Row) -> CandidateMemoryRow:
        return CandidateMemoryRow(
            id=row.id,
            project_id=row.project_id,
            status=row.status,
            trust_tier=row.trust_tier,
            mem_type=row.mem_type,
            provenance=row.provenance,
            status_changed_at=row.status_changed_at,
            promotion_outcomes=row.promotion_outcomes,
            promotion_distinct_principals=row.promotion_distinct_principals,
            outcome_consistent=row.outcome_consistent,
            scan_repass=row.scan_repass,
            open_contradiction=row.open_contradiction,
        )

    # -- ScorerRepoPort -----------------------------------------------------
    def current_q(self, project_id: ProjectId, memory_id: MemoryId) -> float:
        del project_id
        return self.rows[memory_id].q_value

    def applied_event_ids(self, project_id: ProjectId, memory_id: MemoryId) -> set[UUID]:
        del project_id
        return set(self.rows[memory_id].applied_event_ids)

    def scored_updates_today(
        self, project_id: ProjectId, memory_id: MemoryId, day: Any
    ) -> int:
        del project_id, day
        return self.rows[memory_id].updates_today

    def apply_q_update(self, project_id: ProjectId, update: QUpdate) -> None:
        row = self.rows[update.memory_id]
        if row.project_id != project_id:
            raise TracebedError("cross-project Q update")
        row.q_value = update.new_q
        row.scored_use_count += 1
        row.applied_event_ids.add(update.event_id)
        row.updates_today += 1
        self.q_updates.append(update)


class _ShadowRepoView:
    """`ShadowValidatorRepoPort` over the vault.

    A thin view rather than more methods on `_Vault` because `select_quarantined` is declared
    by TWO ports with DIFFERENT return types (`CorroborationRepoPort` wants
    `QuarantinedMemoryForCorroboration`, `ShadowValidatorRepoPort` wants
    `QuarantinedMemoryRow`) — one object cannot satisfy both under one name, and collapsing
    the two projections into one would erase a real distinction: the corroboration writer is
    deliberately NOT given `trust_tier`/`mem_type`/`is_failure_lesson`, because it never judges.
    """

    def __init__(self, vault: _Vault) -> None:
        self._vault = vault

    def select_quarantined(self, project_id: ProjectId) -> Sequence[QuarantinedMemoryRow]:
        return self._vault.select_quarantined_for_validation(project_id)

    def persist(self, project_id: ProjectId, write: ShadowTransitionWrite) -> None:
        self._vault.persist(project_id, write)


class _Lookup:
    """`TracePrincipalLookupPort` — `trace_index.submitter_principal` /
    `input_signature_hash`, the two columns set at authenticated ingest that make independence
    checkable at all (D-020)."""

    def __init__(self) -> None:
        self.rows: dict[RunId, ConfirmingRun] = {}

    def add(self, run_id: RunId, principal: PrincipalId, sig: bytes) -> None:
        self.rows[run_id] = ConfirmingRun(
            run_id=run_id, principal_id=principal, input_signature_hash=sig
        )

    def lookup(self, project_id: ProjectId, run_id: RunId) -> ConfirmingRun | None:
        del project_id
        return self.rows.get(run_id)


class _EmbeddingDriver:
    """`EmbeddingPort` with a fixed pin. Returns a deterministic unit-ish vector per text --
    the content of the vector is irrelevant to this drill; that a vector is WRITTEN, under the
    pin the driver advertises, is the whole claim."""

    def __init__(self, model_id: str, model_version: str) -> None:
        self.model_id = model_id
        self.model_version = model_version
        self.calls = 0

    def embed(self, texts: Sequence[str], *, timeout_ms: int) -> list[list[float]]:
        del timeout_ms
        self.calls += 1
        return [[(len(t) % 7) / 7.0 + i / 100.0 for i in range(_DIM)] for t in texts]


class _SpendSink:
    def __init__(self) -> None:
        self.entries: list[tuple[str, int, float]] = []

    def add(
        self,
        project_id: ProjectId,
        worker: str,
        model_id: str,
        tokens_in: int,
        tokens_out: int,
        cost_usd: float,
    ) -> None:
        del project_id, model_id, tokens_out
        self.entries.append((worker, tokens_in, cost_usd))


class _Judge:
    """`ContributionJudgePort`. The drill's outcome is unambiguous (a `verdict` adapter event),
    so the judged contribution is a multiplier on an update invariant 8 already authorises --
    not the thing that decides whether to score."""

    def judge(self, *, memory_content: str, outcome_summary: str) -> Any:
        from tracebed.workers.contribution_judge import ContributionVerdict

        del memory_content, outcome_summary
        # FULL, the top of the three-value rubric. `ContributionVerdict.__post_init__` refuses
        # anything outside `RUBRIC_FACTORS`, so this fake cannot smuggle a factor the real
        # judge could not have returned -- which is what keeps hop 6's Q movement honest.
        return ContributionVerdict(factor=1.0, epoch_id=_epoch().epoch_id)


# --- recording fake pool, for hop 9 (identical shape to test_search_sql.py's) ---


class _RecCursor:
    def __init__(self, log: list[tuple[str, Any]], rowcount: int) -> None:
        self._log = log
        self.rowcount = rowcount

    def execute(self, sql: str, params: Any = None) -> _RecCursor:
        self._log.append((sql, params))
        return self

    def __enter__(self) -> _RecCursor:
        return self

    def __exit__(self, *exc: object) -> None:
        return None


class _RecConnection:
    def __init__(self, log: list[tuple[str, Any]], rowcount: int) -> None:
        self._log = log
        self._rowcount = rowcount

    def execute(self, sql: str, params: Any = None) -> _RecCursor:
        self._log.append((sql, params))
        return _RecCursor(self._log, self._rowcount)

    def cursor(self, **_: Any) -> _RecCursor:
        return _RecCursor(self._log, self._rowcount)

    @contextmanager
    def transaction(self) -> Any:
        yield self


class _RecPool:
    def __init__(self, rowcount: int = 1) -> None:
        self.log: list[tuple[str, Any]] = []
        self._rowcount = rowcount

    @contextmanager
    def connection(self) -> Any:
        yield _RecConnection(self.log, self._rowcount)


# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #


def _cfg() -> EffectiveConfig:
    return EffectiveConfig(
        retrieval=RetrievalConfig(),
        abstention=AbstentionConfig(),
        score=ScoreConfig(),
        budget=BudgetConfig(),
        scoring=ScoringConfig(),
        promotion=PromotionConfig(),
        retirement=RetirementConfig(),
        lifecycle=LifecycleConfig(),
        derived=DerivedConfig(),
        proposals=ProposalConfig(),
        tier_a=TierAConfig(),
        killswitch=KillswitchConfig(),
        spend=SpendConfig(),
        cache=CacheConfig(),
        session=SessionConfig(),
        queue=QueueConfig(),
        killswitch_overlay={},
    )


def _trace_events(base: datetime) -> list[dict[str, Any]]:
    """One run with a repeated `tool_a` timeout -- the exact pattern
    `workers.extractors.tool_failure.ToolFailureExtractor` is written to recognise."""
    return [
        {
            "type": "run_start",
            "ts": base.isoformat(),
            "payload": {"query_text": "settle the payment", "tool_manifest": list(_MANIFEST)},
        },
        *[
            {
                "type": "error",
                "ts": (base + timedelta(seconds=i)).isoformat(),
                "payload": {
                    "tool_id": "tool_a",
                    "tool_version": "v1",
                    "error_class": ErrorClassEnum.TIMEOUT.value,
                    "duration_ms": 50,
                    "error_body": "",
                },
            }
            for i in (1, 2)
        ],
    ]


def _tier_b_memory(
    vault: _Vault, project_id: ProjectId, origin_run: RunId, clock: FakeClock, content: str
) -> MemoryId:
    """A content-derived (Tier B) SEMANTIC memory, inserted `quarantined` through the REAL
    `NewMemoryItem` construction path -- so `assert_legal_creation_status` and
    `validate_provenance` (invariants 6 and 7's creation half) both run on it.

    SEMANTIC, not a failure LESSON, and the distinction is load-bearing rather than cosmetic.
    `_guard_quarantined_to_candidate` relaxes the corroboration requirement to
    `promotion.failure_lesson_outcomes` (1) for a failure lesson, and to
    `SHADOW_CONFIRM_MIN_INDEPENDENT` (2) for everything else. A drill built on a failure lesson
    would promote on ONE confirmation and could then claim "a second independent run
    corroborates it" while never needing the second run at all. This one needs both.
    """
    item = NewMemoryItem(
        scope_type=ScopeType.PROJECT_SHARED,
        scope_id=None,
        mem_type=MemType.SEMANTIC,
        kind="operational_fact",
        lane=Lane.QUALITY,
        trust_tier=TrustTier.B,
        status=Status.QUARANTINED,
        content=content,
        token_count=len(content.split()),
        provenance=Provenance(cls=ProvenanceClass.DISTILLER, trace_ids=(origin_run,)),
    )
    verdict = scan(
        content,
        context=ScanContext(
            project_id=project_id,
            mem_type=item.mem_type,
            trust_tier=item.trust_tier,
            provenance_class=item.provenance.cls,
            lane=Lane.QUALITY,
        ),
    ).verdict()
    memory_id = vault.insert_memory_item(project_id, item, verdict)
    vault.rows[memory_id].status_changed_at = clock.now()
    return memory_id


# --------------------------------------------------------------------------- #
# The drill
# --------------------------------------------------------------------------- #


def run_closed_loop() -> ClosedLoopReport:
    """Nine hops, in order, each asserted with the production function named in `Hop`.

    Deliberately written as one long linear function rather than nine helpers: the drill's
    subject IS the sequence, and a reader checking whether hop 5 really consumes what hop 4
    wrote must be able to see both without following a call graph.
    """
    from tests.phase0.test_trace_writer import (
        FakeMasterKeyProvider,
        FakeQueue,
        FakeSubjectKeyStore,
        FakeTraceRepo,
        FakeTraceStore,
    )

    from tracebed.crypto.shred import SubjectKeyManager
    from tracebed.domain.config import TracebedSettings
    from tracebed.ingest.trace_writer import TraceWriter
    from tracebed.stores.pg.queue import TOPIC_TRACE_EVENT

    hops: list[Hop] = []
    clock = FakeClock(_T0)
    cfg = _cfg()
    project_id = ProjectId(uuid4())
    agent_type_id = AgentTypeId(uuid4())
    principal_a = PrincipalId(uuid4())
    principal_b = PrincipalId(uuid4())
    scope = ProjectScope(
        project_id=project_id, agent_type_id=agent_type_id, principal_id=principal_a
    )
    vault = _Vault(clock)

    # ---- HOP 1: a trace is ingested --------------------------------------
    run_a = RunId(uuid4())
    settings = TracebedSettings(
        storage={"pg_dsn": "postgresql://drill/none"},  # type: ignore[arg-type]
        embedding={"model_id": "drill-embed", "model_version": "v1", "dim": _DIM},  # type: ignore[arg-type]
    )
    queue = FakeQueue()
    trace_repo = FakeTraceRepo()
    key_store = FakeSubjectKeyStore(clock)
    writer = TraceWriter(
        queue,
        trace_repo,
        FakeTraceStore(),
        SubjectKeyManager(key_store, FakeMasterKeyProvider(), clock),
        clock,
        settings,
    )
    events = _trace_events(_T0)
    for seq, event in enumerate(events):
        queue.enqueue(
            TOPIC_TRACE_EVENT,
            {
                "project_id": str(project_id.value),
                "principal_id": str(principal_a.value),
                "agent_type_id": str(agent_type_id.value),
                "run_id": str(run_a.value),
                "seq": seq,
                "event": event,
            },
        )
    written = writer.run_once()
    indexed = trace_repo.trace_index.get((project_id, run_a))
    hops.append(
        Hop(
            1,
            "trace ingested",
            "ingest.trace_writer.TraceWriter.run_once",
            checks={
                "every enqueued event was durably recorded": written == len(events),
                "a trace_index row exists for the run": indexed is not None,
                "submitter_principal was written server-side from the authenticated envelope":
                    indexed is not None and indexed.submitter_principal == principal_a,
            },
            detail=(
                f"{written}/{len(events)} events durably recorded; trace_index row exists with "
                f"submitter_principal set server-side"
                if indexed is not None
                else "no trace_index row was written"
            ),
            proven_against="real TraceWriter over the fakes tests/phase0/test_trace_writer.py uses",
        )
    )

    # ---- HOP 2: an extractor emits a Tier A candidate ----------------------
    parsed = _parse_events(events)
    lane = TierALane(cfg=cfg, clock=clock, writer=vault)
    lane_result = lane.run_batch(scope, {run_a: parsed})
    tier_a_ids = [o.memory_id for o in lane_result.inserted if o.memory_id is not None]
    tier_a_id = tier_a_ids[0] if tier_a_ids else None
    hops.append(
        Hop(
            2,
            "extractor emits a Tier A candidate",
            "workers.tier_a_lane.TierALane.run_batch (real extractors)",
            checks={
                "an extractor emitted a note from the seeded failure trace": tier_a_id
                is not None,
                "it entered as `candidate`, not `validated`": tier_a_id is not None
                and vault.rows[tier_a_id].status is Status.CANDIDATE,
                "it is Tier A (structurally derived, so it skips quarantine)": tier_a_id
                is not None and vault.rows[tier_a_id].trust_tier is TrustTier.A,
            },
            detail=(
                f"{len(lane_result.inserted)} note(s) inserted; first enters as "
                f"{vault.rows[tier_a_id].status.value}/tier "
                f"{vault.rows[tier_a_id].trust_tier.value}"
                if tier_a_id is not None
                else "no Tier A note was emitted from the seeded failure trace"
            ),
            proven_against="real in-memory memory_item vault",
        )
    )

    # ---- HOP 3: it is embedded and persisted -------------------------------
    driver = _EmbeddingDriver("drill-embed", "v1")
    spend = _SpendSink()
    embedder = Embedder(
        clock=clock,
        embedding_port=driver,  # type: ignore[arg-type]
        repo=vault,  # type: ignore[arg-type]
        spend=spend,
        pin=_pin("drill-embed", "v1"),
        usd_per_1k_tokens=0.0,
        timeout_ms=cfg.retrieval.embed_timeout_ms * 10,
        max_batch=8,
    )
    embed_result = embedder.run(project_id, limit=50)
    embedded = tier_a_id is not None and vault.rows[tier_a_id].embedding is not None
    quarantine_pre_id = _tier_b_memory(
        vault,
        project_id,
        run_a,
        clock,
        "when the settlement tool times out twice, re-check the ledger before retrying",
    )
    # The Sybil control (PLAN.md §2 invariant 7's own test list: "two proposals / two
    # same-principal traces do NOT exit quarantine"). Identical in every respect except the
    # evidence it will be offered, so if it promotes the difference can only be the evidence.
    sybil_id = _tier_b_memory(
        vault,
        project_id,
        run_a,
        clock,
        "when the settlement tool times out twice, escalate to the on-call ledger owner",
    )
    # Re-run AFTER the quarantined row exists: the quarantined row must NOT be embedded.
    embedder.run(project_id, limit=50)
    quarantined_untouched = vault.rows[quarantine_pre_id].embedding is None
    hops.append(
        Hop(
            3,
            "embedded and persisted",
            "workers.embedder.Embedder.run",
            checks={
                "the retrievable row now holds a vector": embedded,
                "the QUARANTINED row holds none": quarantined_untouched,
                "the vector is stamped with the configured pin": tier_a_id is not None
                and vault.rows[tier_a_id].embedding_model_version == "v1",
                "the sweep reported the write it made": embed_result.embedded_count >= 1,
            },
            detail=(
                f"{embed_result.embedded_count} row(s) embedded under pin "
                f"drill-embed/v1 in {embed_result.port_calls} provider call(s); the "
                f"quarantined Tier B row received "
                f"{'no vector' if quarantined_untouched else 'A VECTOR -- quarantine leaked'}"
            ),
            proven_against="real in-memory EmbeddingRepoPort",
        )
    )

    # ---- HOP 4: a second independent run corroborates the quarantined item --
    run_b = RunId(uuid4())
    run_c = RunId(uuid4())
    lookup = _Lookup()
    run_sybil = RunId(uuid4())
    # SIG_HASH_LEN bytes exactly (32 sha256 + 8 simhash). Two properties matter and BOTH were
    # got wrong on the first attempt -- worth recording, because each failed silently:
    #
    #   (a) LENGTH. `ShadowConfirmation.__post_init__` refuses any other length, and it refuses
    #       by REFUSING TO CORROBORATE (a logged warning), not by raising -- so a wrong length
    #       makes hop 5 fail in a way that looks exactly like "the guard worked".
    #   (b) DISTANCE. Only the TRAILING 8 bytes are the simhash, and `signatures.same_cluster`
    #       calls two signatures one cluster when those 8 bytes are within
    #       SAME_CLUSTER_MAX_HAMMING (8 bits). Signatures of 0x02*40 and 0x03*40 differ by
    #       exactly 8 bits and are therefore the SAME cluster -- two "independent" runs that
    #       correctly count as one. The trailing bytes below are 32 and 64 bits apart.
    sig_a = bytes([0x01]) * 32 + bytes([0x00]) * 8
    sig_b = bytes([0x02]) * 32 + bytes([0x0F]) * 8
    sig_c = bytes([0x03]) * 32 + bytes([0xF0]) * 8
    assert len(sig_a) == len(sig_b) == len(sig_c) == SIG_HASH_LEN
    lookup.add(run_a, principal_a, sig_a)
    lookup.add(run_b, principal_b, sig_b)
    lookup.add(run_c, PrincipalId(uuid4()), sig_c)
    # The Sybil control's second run: a DIFFERENT run id, but the SAME principal and the SAME
    # input-signature cluster as run_b. Two calls, one actor -- which invariant 7 counts as one
    # confirmation, not two.
    lookup.add(run_sybil, principal_b, sig_b)

    class _Source:
        """`CorroborationCandidateSource` -- the host-supplied seam (D-121). This drill
        supplies one; no implementation exists in `src/`, which is exactly why the
        corroboration job is constructed and unscheduled in production.

        Offers different evidence per row, which is what a real matcher would do and what
        makes the Sybil control a control rather than a duplicate of the positive case."""

        def candidate_runs(
            self, project_id: ProjectId, row: QuarantinedMemoryForCorroboration
        ) -> Sequence[RunId]:
            del project_id
            if row.id == sybil_id:
                return [run_b, run_sybil]
            # run_a is the memory's OWN origin run: offered deliberately, so the drill
            # exercises the self-corroboration refusal rather than assuming it.
            return [run_a, run_b, run_c]

    corroborator = CorroborationWriter(vault)  # type: ignore[arg-type]
    corr_result = corroborator.run_once(project_id, source=_Source())
    recorded = vault.rows[quarantine_pre_id].shadow_confirm_runs
    refused_origin = any(
        o.run_id == run_a and o.memory_id == quarantine_pre_id and not o.recorded
        for o in corr_result.outcomes
    )
    hops.append(
        Hop(
            4,
            "two independent runs corroborate the quarantined Tier B item",
            "workers.corroboration.CorroborationWriter.run_once",
            checks={
                "both offered non-origin runs were recorded": set(recorded) == {run_b, run_c},
                "the memory's own origin run was refused": refused_origin,
                "correlated evidence is still RECORDED (judging is not this worker's job)":
                    set(vault.rows[sybil_id].shadow_confirm_runs) == {run_b, run_sybil},
            },
            detail=(
                f"{len(recorded)} confirming run(s) recorded on shadow_confirm_runs; the "
                f"memory's own origin run was "
                f"{'refused' if refused_origin else 'RECORDED -- a memory corroborated itself'}"
                f"; the Sybil control row recorded "
                f"{len(vault.rows[sybil_id].shadow_confirm_runs)} run(s) (recording is "
                f"evidence-gathering -- correlated evidence is still recorded, and refused "
                f"only at judgment time)"
            ),
            proven_against="real in-memory CorroborationRepoPort",
        )
    )

    # ---- HOP 5: shadow validation promotes it to candidate ------------------
    validator = ShadowValidator(
        _ShadowRepoView(vault), clock, lookup, _epoch()
    )
    clock.advance(timedelta(minutes=1))
    shadow_result = validator.run_once(project_id, cfg=cfg)
    promoted_to_candidate = vault.rows[quarantine_pre_id].status is Status.CANDIDATE
    sybil_still_quarantined = vault.rows[sybil_id].status is Status.QUARANTINED
    hops.append(
        Hop(
            5,
            "shadow validation promotes quarantined -> candidate (and refuses the Sybil)",
            "workers.shadow_validator.ShadowValidator.run_once",
            # Both halves required. Without the negative control a drill that promoted
            # EVERYTHING would look identical to one that applied the independence rule.
            checks={
                "two independent confirmations promote quarantined -> candidate":
                    promoted_to_candidate,
                "two correlated confirmations do NOT (the Sybil control)":
                    sybil_still_quarantined,
            },
            detail=(
                f"row is now {vault.rows[quarantine_pre_id].status.value}; the Sybil control "
                f"(two runs, one principal, one input-signature cluster) is still "
                f"{vault.rows[sybil_id].status.value}; "
                f"independent confirmations counted: "
                f"{sorted(o.independent_count for o in shadow_result.outcomes)}; "
                f"reasons: {[o.reason for o in shadow_result.outcomes if o.reason]}"
            ),
            proven_against="real in-memory ShadowValidatorRepoPort (NO Postgres impl exists)",
        )
    )

    # ---- HOP 6: outcome events score it --------------------------------------
    q_before = vault.rows[quarantine_pre_id].q_value
    row = vault.rows[quarantine_pre_id]
    score_result = run_scorer_batch(
        project_id=project_id,
        memory_id=row.id,
        memory_content=row.content,
        candidates=[
            ScoringEvent(
                event_id=uuid4(),
                run_id=run_b,
                memory_id=row.id,
                adapter=AdapterClass.VERDICT,
                r=1.0,
                principal_id=principal_b,
                arrived_at=clock.now(),
                outcome_summary="the settlement retry succeeded after the ledger re-check",
            )
        ],
        repo=vault,  # type: ignore[arg-type]
        judge=_Judge(),  # type: ignore[arg-type]
        config=cfg.scoring,
        epoch=_epoch(),
        clock=clock,
    )
    q_after = vault.rows[quarantine_pre_id].q_value
    hops.append(
        Hop(
            6,
            "outcome events move Q (invariant 8)",
            "workers.scorer.run_scorer_batch",
            checks={
                "an unambiguous outcome moved Q upward": q_after > q_before,
                "the scorer reported the update it applied": score_result.applied is not None,
            },
            detail=f"Q {q_before:.4f} -> {q_after:.4f} from one unambiguous verdict outcome",
            proven_against="real in-memory ScorerRepoPort (NO Postgres impl exists)",
        )
    )

    # ---- HOP 7: promotion moves it to validated -------------------------------
    # The four §5 row-6 conditions the store would aggregate from outcome_event/injection_log.
    # `promotion.min_outcomes`, NOT `failure_lesson_outcomes`: the failure-lesson relaxation
    # belongs to the quarantine->candidate guard alone (`_guard_quarantined_to_candidate`), and
    # nothing relaxes candidate->validated. Getting this wrong is how the drill first ran --
    # the guard refused with "promotion_outcomes 1 < required 2", which is the guard being
    # right and the drill being wrong, and is exactly the kind of composition assumption this
    # file exists to catch.
    row.promotion_outcomes = cfg.promotion.min_outcomes
    row.promotion_distinct_principals = cfg.promotion.min_distinct_principals
    row.outcome_consistent = True
    row.scan_repass = True
    clock.advance(timedelta(days=1))
    promoter = PromotionWorker(vault, clock)  # type: ignore[arg-type]
    try:
        promotion_outcome = promoter.evaluate_candidate(
            project_id, vault.candidate_row(row), cfg=cfg
        )
        promotion_reason = promotion_outcome.reason
    except (GuardNotSatisfied, TracebedError) as exc:
        # `TracebedError` as well as `GuardNotSatisfied`: `_require_status` raises the former
        # when the row never reached `candidate` at all, i.e. when hop 5 did not do what this
        # hop assumes. That must be REPORTED as a broken hop, not raised out of the drill --
        # "a failing drill that names the gap is worth more than a passing one that skips it",
        # and a traceback names nothing.
        promotion_reason = f"{type(exc).__name__}: {exc}"
    validated = vault.rows[quarantine_pre_id].status is Status.VALIDATED
    hops.append(
        Hop(
            7,
            "promotion moves candidate -> validated",
            "workers.promotion.PromotionWorker.evaluate_candidate",
            checks={"the promotion guard moved candidate -> validated": validated},
            detail=(
                f"row is now {vault.rows[quarantine_pre_id].status.value}"
                + (f"; guard said: {promotion_reason}" if promotion_reason else "")
            ),
            proven_against="real in-memory PromotionRepoPort (NO Postgres impl exists)",
        )
    )

    # ---- HOP 8: retrieval would return it, and would not have before ----------
    final = vault.rows[quarantine_pre_id]
    retrievable_now = _retrievable(final.id, final.status, final.trust_tier)
    refused_while_quarantined = not _retrievable(final.id, Status.QUARANTINED, TrustTier.B)
    refused_as_tier_b_candidate = not _retrievable(final.id, Status.CANDIDATE, TrustTier.B)
    hops.append(
        Hop(
            8,
            "retrieval returns the promoted row (and refused it before)",
            "stores.pg.search.assert_dynamically_retrievable",
            checks={
                "the promoted row is retrievable": retrievable_now,
                "the SAME row was refused while quarantined": refused_while_quarantined,
                "and refused as a Tier B candidate": refused_as_tier_b_candidate,
            },
            detail=(
                f"validated/Tier B accepted={retrievable_now}; the SAME row refused while "
                f"quarantined={refused_while_quarantined} and refused as a Tier B "
                f"candidate={refused_as_tier_b_candidate}"
            ),
            proven_against="pure production predicate (a fake cursor cannot evaluate WHERE)",
        )
    )

    # ---- HOP 9: a status change is PERSISTED, and lands in memory_status_log --
    pool = _RecPool(rowcount=1)
    lifecycle = LifecycleWriter(pool, clock)  # type: ignore[arg-type]
    lifecycle.persist_status(
        project_id,
        MemoryStatusWrite(
            memory_id=final.id,
            from_status=Status.VALIDATED,
            to_status=Status.STALE,
            now=clock.now(),
        ),
        reason="closed-loop drill",
    )
    sqls = [sql for sql, _ in pool.log]
    guc_first = bool(sqls) and "tracebed.project_id" in sqls[0]
    updated = any("UPDATE memory_item" in s and "SET status" in s for s in sqls)
    logged = any("INSERT INTO memory_status_log" in s for s in sqls)
    hops.append(
        Hop(
            9,
            "the status change is persisted and appears in memory_status_log",
            "stores.pg.lifecycle.LifecycleWriter.persist_status",
            checks={
                "the RLS GUC is the transaction's first statement": guc_first,
                "the status UPDATE was issued": updated,
                "a memory_status_log row was appended in the SAME transaction": logged,
            },
            detail=(
                # Phrased to avoid ruff's S608, which fires on an f-string merely
                # CONTAINING SQL keywords. There is no query here: this is a report line
                # about statements another module issued.
                f"{len(sqls)} statement(s) in one transaction: RLS GUC first={guc_first}, "
                f"status UPDATE on memory_item={updated}, "
                f"history row appended to memory_status_log={logged}"
            ),
            proven_against="statement-recording fake pool -- SQL issued, NOT executed",
        )
    )

    return ClosedLoopReport(
        hops=tuple(hops),
        unscheduled_in_production=tuple(sorted(UNSCHEDULED_WORKERS)),
        generated_at=datetime.now(UTC),
    )


def _epoch() -> ScoringEpoch:
    """One `scoring_epoch` row. Both the shadow validator and the scorer stamp it on what they
    write (PLAN.md §5: "every Q update AND shadow confirmation records epoch_id"), and the drill
    hands them the SAME one so a cross-epoch comparison cannot be what makes the loop appear to
    close."""
    return ScoringEpoch(
        epoch_id=1,
        judge_model_id="drill-judge",
        judge_model_version="v1",
        sampling_params={"temperature": 0.0},
        prompt_hash="0" * 64,
        started_at=_T0,
    )


def _pin(model_id: str, model_version: str) -> Any:
    from tracebed.adapters.embedding.pinning import ModelPin

    return ModelPin(model_id=model_id, model_version=model_version, dim=_DIM)


def _retrievable(memory_id: MemoryId, status: Status, tier: TrustTier) -> bool:
    """`assert_dynamically_retrievable` raises rather than returning a bool -- it is a
    fail-closed assertion, not a predicate. Wrapped here so the drill can report BOTH
    directions; the production behaviour (raise) is unchanged."""
    try:
        assert_dynamically_retrievable(memory_id, status, tier)
    except TracebedError:
        return False
    return True


def _parse_events(raw: Sequence[Mapping[str, Any]]) -> list[Any]:
    """Envelope dicts -> `domain.events.TraceEvent` values through the production discriminated
    union, not through hand-built model instances.

    This matters for the drill's honesty: the SAME dicts were handed to `TraceWriter` in hop 1,
    so hop 2's extractors read exactly what the ingest path accepted, rather than a
    conveniently-shaped object the drill made up. `TypeAdapter` is pydantic's own validator for
    the annotated union `domain.events.TraceEvent` is, so an event the API would reject is
    rejected here too.
    """
    from pydantic import TypeAdapter

    from tracebed.domain.events import TraceEvent

    adapter: TypeAdapter[Any] = TypeAdapter(TraceEvent)
    return [adapter.validate_python(dict(e)) for e in raw]


# --------------------------------------------------------------------------- #
# Rendering / entry point
# --------------------------------------------------------------------------- #


def render_text(report: ClosedLoopReport) -> str:
    lines = [
        "CLOSED-LOOP DRILL — trace in, learned memory out",
        f"generated: {report.generated_at.isoformat()}",
        "",
    ]
    for hop in report.hops:
        mark = "PASS" if hop.passed else "FAIL"
        lines.append(f"  [{mark}] {hop.number}. {hop.name}")
        lines.append(f"          fn:       {hop.production_function}")
        for check, ok in hop.checks.items():
            lines.append(f"            {'ok ' if ok else 'NO '} {check}")
        lines.append(f"          evidence: {hop.detail}")
        lines.append(f"          against:  {hop.proven_against}")
    lines.append("")
    lines.append(
        f"VERDICT: the loop {'CLOSES' if report.closed else 'DOES NOT CLOSE'} "
        f"({sum(h.passed for h in report.hops)}/{len(report.hops)} hops)"
    )
    lines.append("")
    lines.append(
        "SCOPE OF THIS RESULT — read before quoting it. Every hop above ran OFFLINE against "
        "in-memory fakes; there is no Postgres/Valkey/S3 on this machine. A PASS means the "
        "production functions compose: the row each stage writes is the row the next stage "
        "reads. It does NOT mean a deployed process runs them. These workers are complete and "
        "still NOT SCHEDULED in production, each blocked on a named missing store port:"
    )
    for name in report.unscheduled_in_production:
        lines.append(f"  - {name}: {UNSCHEDULED_WORKERS[name].splitlines()[0]}")
    return "\n".join(lines) + "\n"


def _to_json(report: ClosedLoopReport) -> dict[str, Any]:
    return {
        "generated_at": report.generated_at.isoformat(),
        "closed": report.closed,
        "hops": [
            {
                "number": h.number,
                "name": h.name,
                "production_function": h.production_function,
                "passed": h.passed,
                "checks": dict(h.checks),
                "failed_checks": list(h.failed_checks),
                "detail": h.detail,
                "proven_against": h.proven_against,
            }
            for h in report.hops
        ],
        "unscheduled_in_production": list(report.unscheduled_in_production),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="emit JSON instead of text")
    parser.add_argument("--out", type=Path, default=None, help="also write the text report here")
    args = parser.parse_args(argv)

    report = run_closed_loop()
    if args.json:
        print(json.dumps(_to_json(report), indent=2))
    else:
        print(render_text(report), end="")
    if args.out is not None:
        args.out.write_text(render_text(report), encoding="utf-8")
    return 0 if report.closed else 1


if __name__ == "__main__":  # pragma: no cover - script entry
    raise SystemExit(main())
