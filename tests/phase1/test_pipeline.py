"""`hotpath.pipeline.Pipeline` orchestration (PLAN.md §2 invariant 2, §3): run-id
minting, holdout assignment logged but not acted on, and the arm/outcome_code shape
of `RetrieveResult`. The fail-open fault-injection drill lives in
`test_degradation_ladder.py`; this file covers the rest of the orchestrator's
contract.
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
from tracebed.domain.events import ContextSlot, RunContext
from tracebed.domain.ids import AgentTypeId, PrincipalId, ProjectId, RunId, uuid7_timestamp_ms
from tracebed.domain.scope import ProjectScope
from tracebed.hotpath.fusion import FusedCandidate
from tracebed.hotpath.pipeline import CandidateSetResult, Pipeline

pytestmark = pytest.mark.phase1


def _scope() -> ProjectScope:
    return ProjectScope(
        project_id=ProjectId(uuid4()),
        agent_type_id=AgentTypeId(uuid4()),
        principal_id=PrincipalId(uuid4()),
    )


def _cfg(*, holdout_pct: float = 0.0) -> EffectiveConfig:
    # 0.0, not PLAN.md §6's shipped 5.0 default: the holdout arm is memory-OFF (the pipeline
    # withholds the block and stamps `OutcomeCode.HOLDOUT`), and `assign_arm` hashes a
    # per-test random scope -- so at 5% roughly one run in twenty in every test in this file
    # would have drawn the holdout arm and asserted against an empty block at random. Tests
    # whose subject IS the arm pass an explicit percentage.
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
        killswitch=KillswitchConfig(holdout_pct=holdout_pct),
        spend=SpendConfig(),
        cache=CacheConfig(),
        session=SessionConfig(),
        queue=QueueConfig(),
        killswitch_overlay={},
    )


class _ConfigProvider:
    def __init__(self, cfg: EffectiveConfig) -> None:
        self._cfg = cfg

    def effective(
        self, project_id: ProjectId, agent_type_id: AgentTypeId | None = None
    ) -> EffectiveConfig:
        return self._cfg


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
        self.calls.append(
            {"project_id": project_id, "run_id": run_id, "outcome_code": outcome_code, "arm": arm}
        )


@dataclass(frozen=True, slots=True)
class _Outcome:
    """Structurally satisfies `RetrievalOutcomeLike`."""

    candidates: tuple[FusedCandidate, ...] = ()
    degraded: bool = False
    embed_latency_ms: int = 5
    candidates_considered: int = 1


class _Retriever:
    def __init__(self) -> None:
        self.received: list[dict[str, object]] = []

    def retrieve(
        self, project_id: ProjectId, query_text: str, *, cfg: RetrievalConfig
    ) -> _Outcome:
        self.received.append({"project_id": project_id, "query_text": query_text})
        return _Outcome()


class _Assembly:
    """Records every call it receives — used to prove the arm never changes
    what this stage is asked to do (PLAN.md §7: "Phase 1 assigns and logs but
    does NOT act")."""

    # A FIXED memory_id, not `uuid4()` per call: `renderer.render()` promises
    # byte-stable output for a given slot list, so any test comparing two calls'
    # rendered bytes must not have its own fake inject fresh randomness.
    _MEMORY_ID = UUID("2f9d5a10-0000-7000-8000-000000000001")

    def __init__(self, outcome_code: OutcomeCode = OutcomeCode.INJECTED) -> None:
        self._outcome_code = outcome_code
        self.received: list[dict[str, object]] = []

    def run(
        self,
        scope: ProjectScope,
        *,
        query_text: str,
        candidates: Sequence[FusedCandidate],
        cfg: EffectiveConfig,
    ) -> CandidateSetResult:
        self.received.append(
            {
                "project_id": scope.project_id,
                "agent_type_id": scope.agent_type_id,
                "principal_id": scope.principal_id,
                "query_text": query_text,
                "candidates": tuple(candidates),
            }
        )
        slots = (
            [ContextSlot(slot=Slot.FACT, memory_id=self._MEMORY_ID, tokens=10, text="fact")]
            if self._outcome_code is OutcomeCode.INJECTED
            else []
        )
        return CandidateSetResult(outcome_code=self._outcome_code, slots=slots, top_score=0.9)


def _pipeline(
    clock: FakeClock, cfg: EffectiveConfig, assembly: _Assembly, telemetry: _Telemetry
) -> Pipeline:
    return Pipeline(
        clock=clock,
        config=_ConfigProvider(cfg),
        telemetry=telemetry,
        retriever=_Retriever(),
        assembly=assembly,
        holdout_salt="pipeline-test-salt",
    )


# --------------------------------------------------------------------------- #
# run_id is minted server-side, UUIDv7, distinct per call.
# --------------------------------------------------------------------------- #


class _CountingClock(FakeClock):
    """A `FakeClock` that counts `now_ms()` reads."""

    def __init__(self) -> None:
        super().__init__()
        object.__setattr__(self, "now_ms_calls", 0)

    def now_ms(self) -> int:
        self.now_ms_calls += 1  # type: ignore[has-type]
        return super().now_ms()


def test_run_id_is_minted_server_side_as_uuid7_from_the_injected_clock() -> None:
    clock = _CountingClock()
    pipeline = _pipeline(clock, _cfg(), _Assembly(), _Telemetry())

    result = pipeline.retrieve(_scope(), RunContext(query_text="q"), session_id="session-1")

    assert isinstance(result.run_id, UUID)
    assert result.run_id.version == 7
    assert result.run_id_origin == "server"
    uuid7_timestamp_ms(result.run_id)  # raises unless the v7 layout is real
    # Layout alone would survive a mutation to a bare `mint_run_id()` reading wall
    # time. Phase 2's 30-simulated-day soak needs every minted id on the SIMULATED
    # timeline, so assert the injected clock is what was read. (The embedded ms
    # cannot be compared directly: `ids.uuid7`'s process-global monotonic counter
    # clamps a mint whose ms precedes the last one, which any earlier real-clock
    # mint in the same interpreter would trigger.)
    assert clock.now_ms_calls == 1


def test_two_calls_mint_two_distinct_run_ids() -> None:
    clock = FakeClock()
    pipeline = _pipeline(clock, _cfg(), _Assembly(), _Telemetry())
    scope = _scope()

    first = pipeline.retrieve(scope, RunContext(query_text="q1"), session_id="s")
    second = pipeline.retrieve(scope, RunContext(query_text="q2"), session_id="s")

    assert first.run_id != second.run_id


# --------------------------------------------------------------------------- #
# The arm rides on RetrieveResult, and holdout is logged but never acted on:
# the assembly stage receives an identical call regardless of arm.
# --------------------------------------------------------------------------- #


def test_arm_is_always_memory_on_at_zero_holdout_pct() -> None:
    clock = FakeClock()
    pipeline = _pipeline(clock, _cfg(holdout_pct=0.0), _Assembly(), _Telemetry())

    result = pipeline.retrieve(
        _scope(), RunContext(query_text="q"), session_id="always-on"
    )

    assert result.arm is Arm.MEMORY_ON


def test_arm_is_always_holdout_at_hundred_holdout_pct() -> None:
    clock = FakeClock()
    pipeline = _pipeline(clock, _cfg(holdout_pct=100.0), _Assembly(), _Telemetry())

    result = pipeline.retrieve(
        _scope(), RunContext(query_text="q"), session_id="always-holdout"
    )

    assert result.arm is Arm.HOLDOUT


def test_the_holdout_arm_shadow_retrieves_and_withholds_the_block() -> None:
    """The holdout arm is memory-OFF (MEMORY_PLAN §5: "5% of runs execute memory-off").

    Two halves, and both matter:

    * SHADOW: the ladder still runs and the assembly stage still receives the identical call,
      because PLAN.md §7 stratifies lift on "runs where something was actually injected vs
      shadow-retrieved holdout" and `workers.lift.is_shadow_control` reads the presence of an
      `injection_log` row. A holdout arm that skipped retrieval would empty the control bucket
      and the kill switch could never fire.
    * OFF: the caller gets an empty block and the row is stamped `OutcomeCode.HOLDOUT`. Until
      this landed both arms returned the same rendered text, which made lift a comparison of
      memory-on against memory-on.
    """
    clock = FakeClock()
    scope = _scope()
    run_ctx = RunContext(query_text="identical query")

    assembly_on = _Assembly()
    pipeline_on = _pipeline(clock, _cfg(holdout_pct=0.0), assembly_on, _Telemetry())
    result_on = pipeline_on.retrieve(scope, run_ctx, session_id="same-session")

    assembly_holdout = _Assembly()
    pipeline_holdout = _pipeline(clock, _cfg(holdout_pct=100.0), assembly_holdout, _Telemetry())
    result_holdout = pipeline_holdout.retrieve(scope, run_ctx, session_id="same-session")

    assert result_on.arm is Arm.MEMORY_ON
    assert result_holdout.arm is Arm.HOLDOUT
    # The WHOLE recorded call, not just one field: the shadow retrieval must be identical, so
    # the control bucket is drawn from the same population as the treatment bucket.
    assert assembly_on.received == assembly_holdout.received
    # ... and the agent gets nothing.
    assert result_holdout.outcome_code is OutcomeCode.HOLDOUT
    assert result_holdout.context_block.rendered == ""
    assert result_holdout.context_block.slots == []


def test_holdout_arm_is_session_stable_across_two_pipeline_calls() -> None:
    """Same (session, agent_type) through the same pipeline draws the same arm
    twice — a run cannot flip arms mid-session (D-027)."""
    clock = FakeClock()
    cfg = _cfg(holdout_pct=50.0)
    pipeline = _pipeline(clock, cfg, _Assembly(), _Telemetry())
    scope = _scope()

    first = pipeline.retrieve(scope, RunContext(query_text="q1"), session_id="sticky")
    second = pipeline.retrieve(scope, RunContext(query_text="q2"), session_id="sticky")

    assert first.arm == second.arm


# --------------------------------------------------------------------------- #
# Non-degraded outcome codes pass through from the assembly stage unchanged.
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "outcome_code",
    [OutcomeCode.INJECTED, OutcomeCode.ABSTAINED_THRESHOLD, OutcomeCode.ABSTAINED_RARITY, OutcomeCode.EMPTY_RESULT],
)
def test_non_degraded_outcome_codes_pass_through(outcome_code: OutcomeCode) -> None:
    clock = FakeClock()
    telemetry = _Telemetry()
    pipeline = _pipeline(clock, _cfg(), _Assembly(outcome_code), telemetry)

    result = pipeline.retrieve(_scope(), RunContext(query_text="q"), session_id="s")

    assert result.outcome_code is outcome_code
    assert telemetry.calls[0]["outcome_code"] is outcome_code


def test_context_block_header_is_the_exact_memory_header_when_injected() -> None:
    from tracebed.domain.events import MEMORY_HEADER

    clock = FakeClock()
    pipeline = _pipeline(clock, _cfg(), _Assembly(OutcomeCode.INJECTED), _Telemetry())

    result = pipeline.retrieve(_scope(), RunContext(query_text="q"), session_id="s")

    assert result.context_block.header == MEMORY_HEADER
    assert result.context_block.placement == "append_last"
    assert MEMORY_HEADER in result.context_block.rendered


# --------------------------------------------------------------------------- #
# A session-less run is its own session — never a shared bucket.
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("session_id", [None, "", "   "])
def test_absent_session_id_does_not_collapse_every_run_into_one_arm(
    session_id: str | None,
) -> None:
    """`RunCtxIn.session_id` is `str | None` on the wire. Hashing a shared
    placeholder would put EVERY session-less run of an agent_type into a single
    draw: at holdout_pct=50 that is a coin flip deciding the arm for all of them
    at once. Each run must draw independently instead."""
    clock = FakeClock()
    scope = _scope()
    pipeline = _pipeline(clock, _cfg(holdout_pct=50.0), _Assembly(), _Telemetry())

    arms = {
        pipeline.retrieve(scope, RunContext(query_text="q"), session_id=session_id).arm
        for _ in range(60)
    }

    # P(all 60 independent 50/50 draws agree) = 2**-59. A shared placeholder key
    # gives exactly one arm for all 60, every time.
    assert arms == {Arm.MEMORY_ON, Arm.HOLDOUT}


def test_session_id_is_honoured_when_supplied() -> None:
    """The converse of the test above: a real session must still pin the arm."""
    clock = FakeClock()
    scope = _scope()
    pipeline = _pipeline(clock, _cfg(holdout_pct=50.0), _Assembly(), _Telemetry())

    arms = {
        pipeline.retrieve(scope, RunContext(query_text="q"), session_id="pinned").arm
        for _ in range(60)
    }

    assert len(arms) == 1


# --------------------------------------------------------------------------- #
# The locally-declared Protocols (D-055) must not drift from the real types
# they mirror. They are declared, not imported, to keep `pipeline.py` off the
# `adapters.ports` import edge — but a test file is not in the hot-path import
# graph, so the real types can be checked here for free.
# --------------------------------------------------------------------------- #


def test_local_protocols_still_match_the_real_types_they_mirror() -> None:
    import inspect

    from tracebed.adapters.ports import TelemetryPort
    from tracebed.hotpath.pipeline import (
        HybridRetrieverPort,
        RetrievalOutcomeLike,
        TelemetryRecorderPort,
    )
    from tracebed.hotpath.retriever import RetrievalOutcome, Retriever

    assert inspect.signature(TelemetryRecorderPort.record_retrieval) == inspect.signature(
        TelemetryPort.record_retrieval
    )
    assert inspect.signature(HybridRetrieverPort.retrieve).parameters.keys() == (
        inspect.signature(Retriever.retrieve).parameters.keys()
    )
    # `RetrievalOutcomeLike` mirrors `RetrievalOutcome`'s fields by shape, not by
    # import identity — so the field set is what has to stay in agreement.
    mirrored = {
        name
        for name in vars(RetrievalOutcomeLike)
        if not name.startswith("_") and isinstance(vars(RetrievalOutcomeLike)[name], property)
    }
    assert mirrored == set(RetrievalOutcome.__dataclass_fields__)
