"""`workers.spend_enforce` — pausing workers on the daily LLM spend cap without ever touching
retrieval (PLAN.md section 6 `spend.daily_llm_cap_usd` "on cap: workers pause + alert; hot path
unaffected"; section 7 Phase 3: "spend enforcement").

`_FakeMeter` is a plain in-memory stand-in for `SpendCapCheckPort` — the whole point of that
Protocol (see `workers/spend_enforce.py`'s module docstring) is that these tests never touch
`workers.spend.SpendMeter`'s real dependency, a concrete `stores.pg.repo.Repo` over a live
Postgres pool.

`TestHotPathUnaffected` drives a REAL `hotpath.pipeline.Pipeline` while the project is over its
cap. The version this replaced defined a local function returning a constant and asserted it
returned that constant — a test that passes whatever `SpendEnforcer` and `Pipeline` do, i.e. a
test that could not fail.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from uuid import UUID, uuid4

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
from tracebed.domain.errors import CapExceeded
from tracebed.domain.events import ContextSlot, RunContext
from tracebed.domain.ids import AgentTypeId, MemoryId, PrincipalId, ProjectId, RunId
from tracebed.domain.scope import ProjectScope
from tracebed.hotpath.fusion import FusedCandidate
from tracebed.hotpath.pipeline import CandidateSetResult, Pipeline
from tracebed.workers.spend import CapStatus
from tracebed.workers.spend_enforce import SpendEnforcer

pytestmark = pytest.mark.phase3

PROJECT = ProjectId(UUID(int=1))


class _FakeMeter:
    """Structurally satisfies `SpendCapCheckPort` (one method, `check_cap`). Holds a fixed
    `CapStatus` per call rather than accumulating a ledger — these tests are about
    `SpendEnforcer`'s pausing behaviour, not `workers.spend.SpendMeter`'s arithmetic (covered
    by `tests/phase0/test_spend.py`).
    """

    def __init__(self, status: CapStatus) -> None:
        self.status = status
        self.calls: list[ProjectId] = []

    def check_cap(self, project_id: ProjectId) -> CapStatus:
        self.calls.append(project_id)
        return self.status


class _BrokenMeter:
    """A meter whose store is down. `check_cap` is the only thing `SpendEnforcer` can ask, and
    it cannot answer."""

    def __init__(self) -> None:
        self.calls: list[ProjectId] = []

    def check_cap(self, project_id: ProjectId) -> CapStatus:
        self.calls.append(project_id)
        raise RuntimeError("spend_ledger unreachable")


_UNDER_CAP = CapStatus(spent_today_usd=10.0, cap_usd=25.0, exceeded=False)
_AT_CAP = CapStatus(spent_today_usd=25.0, cap_usd=25.0, exceeded=False)
_OVER_CAP = CapStatus(spent_today_usd=30.0, cap_usd=25.0, exceeded=True)


class TestStatusAndGuard:
    def test_status_is_a_pure_read(self) -> None:
        meter = _FakeMeter(_UNDER_CAP)
        enforcer = SpendEnforcer(meter)
        assert enforcer.status(PROJECT) == _UNDER_CAP
        assert meter.calls == [PROJECT]

    def test_guard_passes_under_cap(self) -> None:
        enforcer = SpendEnforcer(_FakeMeter(_UNDER_CAP))
        assert enforcer.guard(PROJECT) == _UNDER_CAP

    def test_spending_exactly_the_cap_is_not_exceeding_it(self) -> None:
        """`workers.spend._cap_status` defines `exceeded` as strictly greater; the enforcer
        must not add a second, stricter boundary of its own."""
        assert SpendEnforcer(_FakeMeter(_AT_CAP)).guard(PROJECT) == _AT_CAP

    def test_guard_raises_cap_exceeded_over_cap(self) -> None:
        enforcer = SpendEnforcer(_FakeMeter(_OVER_CAP))
        with pytest.raises(CapExceeded, match=r"\$30\.00.*\$25\.00"):
            enforcer.guard(PROJECT)

    def test_guard_propagates_a_meter_failure_rather_than_inventing_a_verdict(self) -> None:
        with pytest.raises(RuntimeError, match="spend_ledger unreachable"):
            SpendEnforcer(_BrokenMeter()).guard(PROJECT)


class TestRunGuarded:
    def test_under_cap_runs_fn_and_reports_not_paused(self) -> None:
        enforcer = SpendEnforcer(_FakeMeter(_UNDER_CAP))
        calls: list[str] = []

        def fn() -> str:
            calls.append("ran")
            return "worker-result"

        result, outcome = enforcer.run_guarded(PROJECT, fn)

        assert result == "worker-result"
        assert calls == ["ran"]
        assert outcome.paused is False
        assert outcome.status == _UNDER_CAP
        assert outcome.project_id == PROJECT

    def test_over_cap_skips_fn_and_reports_paused(self) -> None:
        enforcer = SpendEnforcer(_FakeMeter(_OVER_CAP))
        calls: list[str] = []

        def fn() -> str:
            calls.append("ran")  # pragma: no cover - must never execute
            return "should-not-happen"

        result, outcome = enforcer.run_guarded(PROJECT, fn)

        assert result is None
        assert calls == []  # fn was never called -- a skip, not a retry
        assert outcome.paused is True
        assert outcome.status is not None
        assert outcome.status.exceeded is True

    def test_the_cap_is_read_exactly_once_per_call(self) -> None:
        """A second read to fill in the result could disagree with the read the decision was
        made on, and a store error on it would replace `CapExceeded` with an unrelated
        exception escaping into the worker loop."""
        over = _FakeMeter(_OVER_CAP)
        SpendEnforcer(over).run_guarded(PROJECT, lambda: None)
        assert over.calls == [PROJECT]

        under = _FakeMeter(_UNDER_CAP)
        SpendEnforcer(under).run_guarded(PROJECT, lambda: None)
        assert under.calls == [PROJECT]

    def test_an_unreadable_meter_pauses_instead_of_spending_blind(self) -> None:
        """Failing open here means unbounded spend during exactly the outage that makes spend
        unobservable. Nothing about this reaches retrieval (see `TestHotPathUnaffected`), which
        is what makes pausing the safe default on this side of the wall."""
        enforcer = SpendEnforcer(_BrokenMeter())
        calls: list[str] = []

        result, outcome = enforcer.run_guarded(PROJECT, lambda: calls.append("ran"))

        assert result is None
        assert calls == []
        assert outcome.paused is True
        assert outcome.status is None  # genuinely unknown, not a fabricated CapStatus

    def test_run_guarded_never_leaks_cap_exceeded_past_its_own_boundary(self) -> None:
        """The worker-side guard fails closed for THAT worker's unit of work only —
        `CapExceeded` never becomes an exception some unrelated caller has to catch."""
        enforcer = SpendEnforcer(_FakeMeter(_OVER_CAP))
        result, outcome = enforcer.run_guarded(PROJECT, lambda: 1 / 0)
        assert result is None
        assert outcome.paused is True

    def test_an_exception_from_the_guarded_work_itself_is_not_swallowed(self) -> None:
        """Only the CAP decision is handled here. A worker whose own unit of work blew up must
        not be reported as a clean, unpaused success."""
        enforcer = SpendEnforcer(_FakeMeter(_UNDER_CAP))
        with pytest.raises(ZeroDivisionError):
            enforcer.run_guarded(PROJECT, lambda: 1 / 0)


# --------------------------------------------------------------------------- #
# The hot path, for real.
# --------------------------------------------------------------------------- #


def _scope() -> ProjectScope:
    return ProjectScope(
        project_id=PROJECT,
        agent_type_id=AgentTypeId(uuid4()),
        principal_id=PrincipalId(uuid4()),
    )


def _effective_config() -> EffectiveConfig:
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
        # holdout_pct=0, the one tuned field: the holdout arm is memory-off (D-099), so at
        # PLAN.md §6's shipped 5% a run whose random agent_type hashes into holdout returns
        # OutcomeCode.HOLDOUT and an empty block regardless of what this drill injected --
        # a ~1-in-20 false failure with no relation to the property under test.
        killswitch=KillswitchConfig(holdout_pct=0.0),
        # The cap is set to zero dollars: any spend at all is "over". If retrieval had ANY
        # dependency on the cap, this is the configuration that would take it down.
        spend=SpendConfig(daily_llm_cap_usd=0.0),
        cache=CacheConfig(),
        session=SessionConfig(),
        queue=QueueConfig(),
        killswitch_overlay={},
    )


class _ConfigProvider:
    def effective(
        self, project_id: ProjectId, agent_type_id: AgentTypeId | None = None
    ) -> EffectiveConfig:
        return _effective_config()


class _Telemetry:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    def record_retrieval(
        self,
        project_id: ProjectId,
        run_id: RunId,
        *,
        outcome_code: OutcomeCode,
        latency_ms: int,
        embed_latency_ms: int | None,
        candidates_considered: int,
        top_score: float | None,
        arm: Arm,
    ) -> None:
        self.calls.append({"outcome_code": outcome_code, "arm": arm})


@dataclass(frozen=True, slots=True)
class _Outcome:
    """Structurally satisfies `hotpath.pipeline.RetrievalOutcomeLike`."""

    candidates: tuple[FusedCandidate, ...] = ()
    degraded: bool = False
    embed_latency_ms: int = 5
    candidates_considered: int = 1


class _Retriever:
    def retrieve(
        self, project_id: ProjectId, query_text: str, *, cfg: RetrievalConfig
    ) -> _Outcome:
        return _Outcome()


class _Assembly:
    """Always injects one slot, so a successful retrieval is distinguishable from every
    degradation rung."""

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
                    text="tool timeouts on this endpoint average 12s",
                )
            ],
            top_score=0.91,
        )


class TestHotPathUnaffected:
    """PLAN.md section 6: "on cap: workers pause + alert; hot path unaffected". A spend cap
    that takes down retrieval turns a billing event into an outage.

    `scripts/purity_check.py` already proves the STRUCTURAL half (no `workers` module is
    reachable from `hotpath/`'s import graph, invariant 1). These tests prove the functional
    half against the real `Pipeline`, with the project both over its cap and configured with a
    zero-dollar cap, in the same process and at the same time.
    """

    def _pipeline(self, telemetry: _Telemetry) -> Pipeline:
        return Pipeline(
            clock=FakeClock(),
            config=_ConfigProvider(),
            telemetry=telemetry,
            retriever=_Retriever(),
            assembly=_Assembly(),
            holdout_salt="test-salt",
        )

    def test_retrieval_still_injects_while_the_project_is_over_its_cap(self) -> None:
        meter = _FakeMeter(_OVER_CAP)
        enforcer = SpendEnforcer(meter)
        assert enforcer.status(PROJECT).exceeded is True

        # A worker IS paused, right now, for this project.
        worker_result, outcome = enforcer.run_guarded(PROJECT, lambda: "distilled")
        assert worker_result is None
        assert outcome.paused is True

        telemetry = _Telemetry()
        result = self._pipeline(telemetry).retrieve(
            _scope(), RunContext(query_text="how long do these calls take")
        )

        assert result.outcome_code is OutcomeCode.INJECTED
        assert result.context_block.slots
        assert telemetry.calls[0]["outcome_code"] is OutcomeCode.INJECTED

    def test_the_pipeline_never_consults_the_meter(self) -> None:
        """The functional statement of "no shared dependency": running a retrieval must not
        add a single `check_cap` call. A `Pipeline` that grew a spend dependency later — via
        config, telemetry, or any other seam — fails here."""
        meter = _FakeMeter(_OVER_CAP)
        SpendEnforcer(meter)
        before = list(meter.calls)

        self._pipeline(_Telemetry()).retrieve(_scope(), RunContext(query_text="anything"))

        assert meter.calls == before == []

    def test_pipeline_construction_takes_nothing_from_this_module(self) -> None:
        """`Pipeline.__init__`'s keyword surface is the complete list of things that can reach
        retrieval. None of them is a spend meter or an enforcer — asserted against the real
        signature rather than by reading the file."""
        import inspect

        params = set(inspect.signature(Pipeline.__init__).parameters) - {"self"}
        assert params == {
            "clock",
            "config",
            "telemetry",
            "retriever",
            "assembly",
            "static_prefix",
            "injections",
            "holdout_salt",
        }
        assert not any("spend" in name or "cap" in name for name in params)
