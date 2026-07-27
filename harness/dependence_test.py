""""Can it still walk" -- the dependence test (PLAN.md section 8 improvement 3,
CUTTABLE; section 7 Phase 3 harness):

    "Invariant 'memory is an enhancer, never a dependency' is otherwise
    untested; documented production failure is agents becoming dependent.
    Periodically run the memory-off arm and assert task completion."

This file's name matches pytest's `*_test.py` collection pattern
(`testpaths = ["tests", "harness"]`, default `python_files`), so it is
BOTH the drill library (`run_dependence_drill`, callable directly by
`harness/phase3_gate.py`, matching `harness/soak.py`'s convention) AND the
`-m phase3` test module the gate's clause selects cases from -- there is no
separate `harness/test_dependence.py`.

THE SCENARIO: `hotpath.holdout.assign_arm` (real, D-027) decides, per
simulated session and at the DOCUMENTED `killswitch.holdout_pct` (5%),
whether that session's memory is present or withheld. Two REAL
`hotpath.pipeline.Pipeline` instances are driven -- one wired to an
assembly that injects a genuinely useful hint (the memory-on arm), one
wired to an assembly that injects nothing at all (the memory-off arm,
i.e. what a correctly-acting kill switch withholds on holdout) -- and
`Pipeline.retrieve()` must complete without raising in either case
(invariant 2's fail-open promise, proved functionally, not merely by
`scripts/purity_check.py`'s structural half).

Layered on top of the real retrieval call is a SYNTHETIC task-completion
model, because nothing in this repository is an actual downstream agent
task: each simulated session has a documented BASE_CAPABILITY (the agent's
own ability to complete its task with NO memory at all) and a documented,
strictly higher BOOSTED_CAPABILITY (memory genuinely helping). Both numbers
are this harness's own modelling choice -- PLAN.md section 6 has no field
for "how capable is an agent without Tracebed" -- and are stated as such
rather than presented as measured facts. What IS measured, off the real
`Pipeline` and the real `assign_arm`, is: the holdout arm's simulated
completion rate must not collapse relative to `MIN_ACCEPTABLE_COMPLETION_RATE`
-- the concrete, falsifiable form of "the agent can still walk without
memory".

KNOWN GAP, stated rather than hidden (the same shape `workers.lift`'s own
module docstring reports for the sibling holdout contract gap): the REAL
`hotpath.pipeline.Pipeline` does not yet relabel or withhold injection on
the holdout arm (`workers/lift.py`'s own docstring: "hotpath.pipeline also
returns the rendered block to the caller on the holdout arm rather than
discarding it"). This drill does not reproduce that gap -- it models the
INTENDED target behaviour (memory genuinely withheld on the memory-off
arm) by choosing which assembly a session's Pipeline call goes through
itself, using `assign_arm` only to decide the SESSION SPLIT at the
documented holdout percentage, not to read `RetrieveResult.arm` back off
a Pipeline that does not yet act on it.
"""

from __future__ import annotations

import random
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import uuid4

import pytest

from tracebed.domain.clock import FakeClock
from tracebed.domain.config import (
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
from tracebed.domain.enums import Arm, OutcomeCode, Slot
from tracebed.domain.events import ContextSlot, RunContext, empty_context_block
from tracebed.domain.ids import AgentTypeId, MemoryId, PrincipalId, ProjectId
from tracebed.domain.scope import ProjectScope
from tracebed.hotpath.fusion import FusedCandidate
from tracebed.hotpath.holdout import assign_arm
from tracebed.hotpath.pipeline import CandidateSetResult, Pipeline

pytestmark = pytest.mark.phase3

__all__ = [
    "BASE_CAPABILITY",
    "BOOSTED_CAPABILITY",
    "DEFAULT_HOLDOUT_PCT",
    "DEFAULT_N_SESSIONS",
    "MIN_ACCEPTABLE_COMPLETION_RATE",
    "DependenceReport",
    "render_text",
    "run_dependence_drill",
]

_NOW: datetime = datetime(2026, 7, 26, 12, 0, tzinfo=UTC)

DEFAULT_N_SESSIONS: int = 2_000
DEFAULT_HOLDOUT_PCT: float = 5.0
"""Matches `domain.config.KillswitchConfig.holdout_pct`'s documented default
(PLAN.md section 6) -- "periodically" is this literal percentage, not an
invented cadence."""

BASE_CAPABILITY: float = 0.85
"""The agent's own task-completion capability with NO memory at all. A
documented modelling choice (module docstring), not a measured constant --
representative of "the agent already works; Tracebed is an enhancer"."""

BOOSTED_CAPABILITY: float = 0.95
"""Capability WITH a genuinely useful injected memory -- a real, modest
enhancement over the base rate, never large enough on its own to make the
base rate read as a collapse if it were absent."""

MIN_ACCEPTABLE_COMPLETION_RATE: float = 0.75
"""The floor this drill enforces on the memory-off arm's measured completion
rate. No PLAN.md section 6 field names "how much task completion is
acceptable without memory" -- this is this harness's own documented
criterion for what "can it still walk" means numerically, well below
BASE_CAPABILITY so ordinary sampling noise at DEFAULT_N_SESSIONS's holdout
slice cannot trip it, and high enough that an actual dependency collapse
(completion falling toward the floor a broken fail-open path would produce)
still fails loudly."""


def _scope(agent_type_id: AgentTypeId) -> ProjectScope:
    return ProjectScope(
        project_id=ProjectId(uuid4()), agent_type_id=agent_type_id, principal_id=PrincipalId(uuid4())
    )


def _config() -> EffectiveConfig:
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
        killswitch=KillswitchConfig(holdout_pct=DEFAULT_HOLDOUT_PCT),
        spend=SpendConfig(),
        cache=CacheConfig(),
        session=SessionConfig(),
        queue=QueueConfig(),
        killswitch_overlay={},
    )


class _ConfigProvider:
    def effective(self, project_id: ProjectId, agent_type_id: AgentTypeId | None = None) -> EffectiveConfig:
        return _config()


class _Telemetry:
    def record_retrieval(
        self,
        project_id: ProjectId,
        run_id: object,
        *,
        outcome_code: OutcomeCode,
        latency_ms: int,
        embed_latency_ms: int | None,
        candidates_considered: int,
        top_score: float | None,
        arm: Arm,
    ) -> None:
        return None


@dataclass(frozen=True, slots=True)
class _Outcome:
    candidates: tuple[FusedCandidate, ...] = ()
    degraded: bool = False
    embed_latency_ms: int = 5
    candidates_considered: int = 1


class _Retriever:
    def retrieve(self, project_id: ProjectId, query_text: str, *, cfg: RetrievalConfig) -> _Outcome:
        return _Outcome()


class _HelpfulAssembly:
    """Always injects one genuinely useful hint -- the memory-on arm."""

    def run(
        self,
        scope: ProjectScope,
        *,
        query_text: str,
        candidates: Sequence[FusedCandidate],
        cfg: EffectiveConfig,
    ) -> CandidateSetResult:
        return CandidateSetResult(
            outcome_code=OutcomeCode.INJECTED,
            slots=[
                ContextSlot(
                    slot=Slot.FACT,
                    memory_id=MemoryId(uuid4()).value,
                    tokens=4,
                    text="this endpoint rate-limits above 10 req/s",
                )
            ],
            top_score=0.9,
        )


class _EmptyAssembly:
    """Never injects anything -- the memory-off arm: what a kill switch that
    correctly withholds on holdout would produce (module docstring's known
    gap: today's real `Pipeline` does not yet do this on its own)."""

    def run(
        self,
        scope: ProjectScope,
        *,
        query_text: str,
        candidates: Sequence[FusedCandidate],
        cfg: EffectiveConfig,
    ) -> CandidateSetResult:
        block = empty_context_block()
        return CandidateSetResult(outcome_code=OutcomeCode.EMPTY_RESULT, slots=list(block.slots), top_score=None)


def _pipeline(assembly: object) -> Pipeline:
    return Pipeline(
        clock=FakeClock(_NOW),
        config=_ConfigProvider(),
        telemetry=_Telemetry(),
        retriever=_Retriever(),
        assembly=assembly,  # type: ignore[arg-type]
        holdout_salt="dependence-test-salt",
    )


@dataclass(frozen=True, slots=True)
class DependenceReport:
    n_sessions: int
    memory_on_sessions: int
    holdout_sessions: int
    memory_on_completion_rate: float
    holdout_completion_rate: float
    pipeline_raised: bool
    """True iff `Pipeline.retrieve()` raised in EITHER arm -- invariant 2's
    fail-open promise, proved functionally rather than only structurally."""

    @property
    def ok(self) -> bool:
        return (
            not self.pipeline_raised
            and self.holdout_sessions > 0
            and self.holdout_completion_rate >= MIN_ACCEPTABLE_COMPLETION_RATE
        )


def run_dependence_drill(
    *,
    n_sessions: int = DEFAULT_N_SESSIONS,
    holdout_pct: float = DEFAULT_HOLDOUT_PCT,
    seed: int = 20260726,
) -> DependenceReport:
    rng = random.Random(seed)
    salt = "dependence-test-salt"
    agent_type_id = AgentTypeId(uuid4())
    on_pipeline = _pipeline(_HelpfulAssembly())
    off_pipeline = _pipeline(_EmptyAssembly())

    memory_on = 0
    holdout = 0
    memory_on_completed = 0
    holdout_completed = 0
    pipeline_raised = False

    for i in range(n_sessions):
        session_key = f"dependence-session-{i}"
        arm = assign_arm(
            session_key=session_key,
            agent_type_id=agent_type_id,
            salt=salt,
            holdout_pct=holdout_pct,
        )
        scope = _scope(agent_type_id)
        run_ctx = RunContext(query_text=f"complete task {i}")
        try:
            if arm is Arm.HOLDOUT:
                holdout += 1
                off_pipeline.retrieve(scope, run_ctx, session_id=session_key)
                if rng.random() < BASE_CAPABILITY:
                    holdout_completed += 1
            else:
                memory_on += 1
                on_pipeline.retrieve(scope, run_ctx, session_id=session_key)
                if rng.random() < BOOSTED_CAPABILITY:
                    memory_on_completed += 1
        except Exception:  # a raised exception here IS the failure this drill measures
            pipeline_raised = True

    memory_on_rate = memory_on_completed / memory_on if memory_on else 0.0
    holdout_rate = holdout_completed / holdout if holdout else 0.0

    return DependenceReport(
        n_sessions=n_sessions,
        memory_on_sessions=memory_on,
        holdout_sessions=holdout,
        memory_on_completion_rate=memory_on_rate,
        holdout_completion_rate=holdout_rate,
        pipeline_raised=pipeline_raised,
    )


def render_text(report: DependenceReport) -> str:
    lines = [
        f"sessions: {report.n_sessions} total, "
        f"{report.memory_on_sessions} memory-on, {report.holdout_sessions} holdout "
        f"({report.holdout_sessions / report.n_sessions * 100.0:.1f}% -- documented target "
        f"{DEFAULT_HOLDOUT_PCT:.1f}%)",
        f"memory-on completion rate: {report.memory_on_completion_rate * 100.0:.1f}%",
        f"holdout (memory-off) completion rate: {report.holdout_completion_rate * 100.0:.1f}% "
        f"(floor: {MIN_ACCEPTABLE_COMPLETION_RATE * 100.0:.1f}%)",
        f"Pipeline.retrieve() raised in either arm: {report.pipeline_raised} (must be False)",
        f"overall: {'PASS' if report.ok else 'FAIL'} -- "
        "memory is an enhancer (higher rate on) but never a dependency "
        "(holdout rate stays at/above the floor)",
    ]
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# `-m phase3` tests -- this module IS the test file (see the module docstring
# on the `*_test.py` naming).
# --------------------------------------------------------------------------- #


def test_the_holdout_arm_still_completes_the_task() -> None:
    """The headline assertion: "can it still walk"."""
    report = run_dependence_drill()
    assert report.pipeline_raised is False
    assert report.holdout_sessions > 0
    assert report.holdout_completion_rate >= MIN_ACCEPTABLE_COMPLETION_RATE


def test_memory_is_an_enhancer_the_memory_on_arm_does_better() -> None:
    """Memory is not USELESS either -- the positive control this drill is
    not merely a "nothing ever fails" harness."""
    report = run_dependence_drill()
    assert report.memory_on_completion_rate > report.holdout_completion_rate


def test_pipeline_retrieve_never_raises_in_either_arm() -> None:
    report = run_dependence_drill()
    assert report.pipeline_raised is False


def test_the_holdout_split_matches_the_documented_percentage_within_sampling_noise() -> None:
    report = run_dependence_drill(n_sessions=5_000)
    observed_pct = report.holdout_sessions / report.n_sessions * 100.0
    assert abs(observed_pct - DEFAULT_HOLDOUT_PCT) < 2.0


@pytest.mark.parametrize("seed", [1, 2, 3, 4])
def test_the_drill_holds_across_several_seeds(seed: int) -> None:
    report = run_dependence_drill(seed=seed)
    assert report.ok is True


def test_a_collapsed_holdout_arm_would_fail_this_drill() -> None:
    """Proves this drill is not vacuously green: an artificially collapsed
    base capability (simulating a real dependency -- the agent cannot
    function at all without memory) fails `DependenceReport.ok`."""
    collapsed_report = DependenceReport(
        n_sessions=1000,
        memory_on_sessions=950,
        holdout_sessions=50,
        memory_on_completion_rate=0.95,
        holdout_completion_rate=0.05,
        pipeline_raised=False,
    )
    assert collapsed_report.ok is False


def test_a_raised_exception_would_fail_this_drill() -> None:
    """Proves `pipeline_raised` is load-bearing, not decorative."""
    raised_report = DependenceReport(
        n_sessions=1000,
        memory_on_sessions=950,
        holdout_sessions=50,
        memory_on_completion_rate=0.95,
        holdout_completion_rate=0.90,
        pipeline_raised=True,
    )
    assert raised_report.ok is False
