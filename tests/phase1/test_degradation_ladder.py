"""The fail-open drill (PLAN.md §2 invariant 2): `hotpath.pipeline.Pipeline.retrieve()`
must never propagate an exception, and must record the CORRECT `OutcomeCode` for each
rung of the degradation ladder:

    query-embed timeout (200ms)   -> lexical-only retrieval  -> outcome_code = degraded_lexical
    total budget (300ms) exceeded -> static prefix only       -> outcome_code = timeout_prefix_only
    store error                   -> nothing                  -> outcome_code = store_error

Every stall is driven by `FakeClock.advance()` from inside a fake dependency so the
tests are deterministic and fast (no real `time.sleep`); one real-time test at the
bottom proves the wall-clock (`SystemClock`) path also works end to end.

`Pipeline` delegates the actual BM25+ANN+RRF search and its embed sub-budget to an
injected `HybridRetrieverPort` (the real implementation is `hotpath.retriever
.Retriever`, which already owns exactly that logic) — these tests fake that
boundary directly rather than re-simulating an `EmbeddingPort`, matching how
`Pipeline` is actually wired.
"""

from __future__ import annotations

import inspect
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from uuid import uuid4

import pytest

from tracebed.domain.clock import Clock, FakeClock, SystemClock
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
from tracebed.domain.events import MEMORY_HEADER, ContextBlock, ContextSlot, RunContext
from tracebed.domain.ids import AgentTypeId, MemoryId, PrincipalId, ProjectId, RunId
from tracebed.domain.scope import ProjectScope
from tracebed.hotpath.budget import Deadline
from tracebed.hotpath.fusion import FusedCandidate
from tracebed.hotpath.pipeline import CandidateSetResult, InjectionRecorderPort, Pipeline
from tracebed.stores.pg.rows import InjectionRow
from tracebed.stores.pg.telemetry import Telemetry

pytestmark = pytest.mark.phase1


# --------------------------------------------------------------------------- #
# Shared fixtures / fakes.
# --------------------------------------------------------------------------- #


def _scope() -> ProjectScope:
    return ProjectScope(
        project_id=ProjectId(uuid4()),
        agent_type_id=AgentTypeId(uuid4()),
        principal_id=PrincipalId(uuid4()),
    )


def _cfg(
    *, total_budget_ms: int = 300, embed_timeout_ms: int = 200, holdout_pct: float = 0.0
) -> EffectiveConfig:
    return EffectiveConfig(
        retrieval=RetrievalConfig(total_budget_ms=total_budget_ms, embed_timeout_ms=embed_timeout_ms),
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


class _FakeConfigProvider:
    """`stall_ms` advances the injected clock the way a real `ConfigResolver`
    stalling on its `project_config` / `agent_type_config` reads would — the
    latency that happens BEFORE the ladder starts but INSIDE the call the caller
    is waiting on."""

    def __init__(
        self,
        cfg: EffectiveConfig | None = None,
        *,
        raises: bool = False,
        clock: FakeClock | None = None,
        stall_ms: float = 0.0,
    ) -> None:
        self._cfg = cfg if cfg is not None else _cfg()
        self._raises = raises
        self._clock = clock
        self._stall_ms = stall_ms
        self.received_agent_type_ids: list[AgentTypeId | None] = []

    def effective(
        self, project_id: ProjectId, agent_type_id: AgentTypeId | None = None
    ) -> EffectiveConfig:
        self.received_agent_type_ids.append(agent_type_id)
        if self._stall_ms and self._clock is not None:
            self._clock.advance(ms=self._stall_ms)
        if self._raises:
            raise RuntimeError("config store unreachable")
        return self._cfg


class _RecordingTelemetry:
    """Satisfies `TelemetryRecorderPort`. Records every call; can be made to raise."""

    def __init__(self, *, raises: bool = False) -> None:
        self.calls: list[dict[str, object]] = []
        self._raises = raises

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
            {
                "project_id": project_id,
                "run_id": run_id,
                "outcome_code": outcome_code,
                "latency_ms": latency_ms,
                "embed_latency_ms": embed_latency_ms,
                "candidates_considered": candidates_considered,
                "top_score": top_score,
                "arm": arm,
            }
        )
        if self._raises:
            raise RuntimeError("telemetry sink unreachable")


@dataclass(frozen=True, slots=True)
class _Outcome:
    """Structurally satisfies `RetrievalOutcomeLike` — the real return type is
    `hotpath.retriever.RetrievalOutcome`, an equivalent frozen dataclass."""

    candidates: tuple[FusedCandidate, ...] = ()
    degraded: bool = False
    embed_latency_ms: int = 5
    candidates_considered: int = 3


class _FakeRetriever:
    """Satisfies `HybridRetrieverPort`. `stall_ms` advances the injected clock as a
    side effect of the call — simulating real wall-clock cost (embed + both search
    arms) without `time.sleep`. `raises` simulates a genuine store error (the real
    `Retriever` propagates anything but `EmbeddingTimeout` unmodified); `degraded`
    simulates the real `Retriever` having caught an `EmbeddingTimeout` internally
    and falling back to lexical-only."""

    def __init__(
        self,
        clock: FakeClock,
        *,
        stall_ms: float = 0.0,
        degraded: bool = False,
        raises: bool = False,
        candidates_considered: int = 3,
    ) -> None:
        self._clock = clock
        self._stall_ms = stall_ms
        self._degraded = degraded
        self._raises = raises
        self._candidates_considered = candidates_considered
        self.calls = 0
        self.received_cfg: RetrievalConfig | None = None

    def retrieve(
        self, project_id: ProjectId, query_text: str, *, cfg: RetrievalConfig
    ) -> _Outcome:
        self.calls += 1
        self.received_cfg = cfg
        if self._stall_ms:
            self._clock.advance(ms=self._stall_ms)
        if self._raises:
            raise RuntimeError("retrieval store unreachable")
        embed_latency = int(self._stall_ms) if self._stall_ms else 5
        return _Outcome(
            candidates=(),
            degraded=self._degraded,
            embed_latency_ms=embed_latency,
            candidates_considered=self._candidates_considered,
        )


def _slots() -> list[ContextSlot]:
    return [ContextSlot(slot=Slot.FACT, memory_id=uuid4(), tokens=12, text="a recalled fact")]


class _FakeAssembly:
    """Satisfies `CandidateAssemblyPort`. `raises` simulates an assembly-side
    failure (also folded into `store_error` by `Pipeline`); otherwise returns a
    fixed `CandidateSetResult`."""

    def __init__(
        self,
        *,
        outcome_code: OutcomeCode = OutcomeCode.INJECTED,
        slots: list[ContextSlot] | None = None,
        raises: bool = False,
        clock: FakeClock | None = None,
        stall_ms: float = 0.0,
        injections: Sequence[InjectionRow] = (),
    ) -> None:
        self._outcome_code = outcome_code
        self._slots = slots if slots is not None else _slots()
        self._raises = raises
        self._clock = clock
        self._stall_ms = stall_ms
        self._injections = tuple(injections)
        self.calls = 0
        self.received_cfg: EffectiveConfig | None = None

    def run(
        self,
        scope: ProjectScope,
        *,
        query_text: str,
        candidates: Sequence[FusedCandidate],
        cfg: EffectiveConfig,
    ) -> CandidateSetResult:
        self.calls += 1
        self.received_cfg = cfg
        # The real `hotpath.assembly.CandidateAssembly` issues three store round trips of its
        # own (content, document frequency, corpus size); `stall_ms` is that wall time.
        if self._stall_ms and self._clock is not None:
            self._clock.advance(ms=self._stall_ms)
        if self._raises:
            raise RuntimeError("assembly failed")
        return CandidateSetResult(
            outcome_code=self._outcome_code,
            slots=self._slots,
            top_score=0.87,
            injections=self._injections,
        )


class _RecordingInjections:
    """Satisfies `InjectionRecorderPort`; `stores.pg.telemetry.Telemetry` is the real one."""

    def __init__(self, *, raises: bool = False) -> None:
        self.calls: list[tuple[ProjectId, RunId, tuple[InjectionRow, ...]]] = []
        self._raises = raises

    def record_injections(
        self, project_id: ProjectId, run_id: RunId, rows: Sequence[InjectionRow]
    ) -> None:
        self.calls.append((project_id, run_id, tuple(rows)))
        if self._raises:
            raise RuntimeError("injection_log unreachable")


def _pipeline(
    clock: Clock,
    *,
    config: _FakeConfigProvider | None = None,
    telemetry: _RecordingTelemetry | None = None,
    assembly: _FakeAssembly | None = None,
    retriever: _FakeRetriever | None = None,
    injections: _RecordingInjections | None = None,
) -> tuple[Pipeline, _RecordingTelemetry, _FakeAssembly, _FakeRetriever]:
    tel = telemetry if telemetry is not None else _RecordingTelemetry()
    asm = assembly if assembly is not None else _FakeAssembly()
    retr = retriever if retriever is not None else _FakeRetriever(FakeClock())
    pipeline = Pipeline(
        clock=clock,
        config=config if config is not None else _FakeConfigProvider(),
        telemetry=tel,
        retriever=retr,
        assembly=asm,
        injections=injections,
        holdout_salt="test-salt",
    )
    return pipeline, tel, asm, retr


# --------------------------------------------------------------------------- #
# Happy path: no fault injected.
# --------------------------------------------------------------------------- #


def test_happy_path_injected_no_exceptions() -> None:
    clock = FakeClock()
    retriever = _FakeRetriever(clock)
    pipeline, telemetry, assembly, _ = _pipeline(clock, retriever=retriever)

    result = pipeline.retrieve(
        _scope(), RunContext(query_text="what happened"), session_id="s-1"
    )

    assert result.outcome_code is OutcomeCode.INJECTED
    assert result.context_block.slots  # rendered from the fake assembly's slots
    assert len(telemetry.calls) == 1
    assert telemetry.calls[0]["outcome_code"] is OutcomeCode.INJECTED
    assert assembly.calls == 1


# --------------------------------------------------------------------------- #
# Rung 3: store error -> nothing.
# --------------------------------------------------------------------------- #


def test_failing_retriever_returns_store_error_and_nothing() -> None:
    clock = FakeClock()
    retriever = _FakeRetriever(clock, raises=True)
    pipeline, telemetry, assembly, _ = _pipeline(clock, retriever=retriever)

    result = pipeline.retrieve(
        _scope(), RunContext(query_text="q"), session_id="s-2"
    )

    assert result.outcome_code is OutcomeCode.STORE_ERROR
    assert result.context_block.slots == []
    assert result.context_block.rendered == ""
    assert len(telemetry.calls) == 1
    assert telemetry.calls[0]["outcome_code"] is OutcomeCode.STORE_ERROR
    assert assembly.calls == 0  # never reached: the retriever itself failed


def test_failing_assembly_also_returns_store_error() -> None:
    clock = FakeClock()
    assembly = _FakeAssembly(raises=True)
    pipeline, _, _, _ = _pipeline(clock, assembly=assembly)

    result = pipeline.retrieve(
        _scope(), RunContext(query_text="q"), session_id="s-2b"
    )

    assert result.outcome_code is OutcomeCode.STORE_ERROR
    assert result.context_block.slots == []


def test_config_resolution_failure_also_returns_store_error() -> None:
    """Nothing downstream can even be attempted without budgets to read."""
    clock = FakeClock()
    config = _FakeConfigProvider(raises=True)
    pipeline, telemetry, _, retriever = _pipeline(clock, config=config)

    result = pipeline.retrieve(
        _scope(), RunContext(query_text="q"), session_id="s-3"
    )

    assert result.outcome_code is OutcomeCode.STORE_ERROR
    assert result.arm is Arm.MEMORY_ON  # safe default; holdout never even ran
    assert retriever.calls == 0  # the ladder never got far enough to call it
    assert len(telemetry.calls) == 1


# --------------------------------------------------------------------------- #
# Rung 1: query-embed timeout -> lexical-only -> degraded_lexical.
# --------------------------------------------------------------------------- #


def test_degraded_retriever_reports_degraded_lexical() -> None:
    clock = FakeClock()
    # 210ms > embed_timeout_ms (200) but < total_budget_ms (300): only the embed
    # rung fires, the total-budget rung must not.
    retriever = _FakeRetriever(clock, stall_ms=210.0, degraded=True)
    assembly = _FakeAssembly(outcome_code=OutcomeCode.INJECTED)
    pipeline, telemetry, _, _ = _pipeline(clock, retriever=retriever, assembly=assembly)

    result = pipeline.retrieve(
        _scope(), RunContext(query_text="q"), session_id="s-4"
    )

    assert result.outcome_code is OutcomeCode.DEGRADED_LEXICAL
    assert retriever.calls == 1
    assert assembly.calls == 1  # still assembled from whatever the lexical arm found
    assert len(telemetry.calls) == 1
    assert telemetry.calls[0]["outcome_code"] is OutcomeCode.DEGRADED_LEXICAL
    assert telemetry.calls[0]["embed_latency_ms"] == 210


def test_embed_degradation_that_also_blows_total_budget_reports_timeout_not_degraded() -> None:
    """Total-budget exhaustion is the worse degradation and wins if both fire."""
    clock = FakeClock()
    retriever = _FakeRetriever(clock, stall_ms=310.0, degraded=True)
    assembly = _FakeAssembly()
    pipeline, telemetry, _, _ = _pipeline(clock, retriever=retriever, assembly=assembly)

    result = pipeline.retrieve(
        _scope(), RunContext(query_text="q"), session_id="s-5"
    )

    assert result.outcome_code is OutcomeCode.TIMEOUT_PREFIX_ONLY
    assert assembly.calls == 0  # never reached: budget was already blown
    assert telemetry.calls[0]["outcome_code"] is OutcomeCode.TIMEOUT_PREFIX_ONLY


# --------------------------------------------------------------------------- #
# Rung 2: total budget exceeded -> static prefix only -> timeout_prefix_only.
# --------------------------------------------------------------------------- #


def test_total_stall_returns_timeout_prefix_only_before_assembly() -> None:
    clock = FakeClock()
    # The retriever succeeds (no exception, not even degraded) but consumes more
    # than the whole budget — proves the total-budget rung fires independently.
    retriever = _FakeRetriever(clock, stall_ms=350.0, degraded=False)
    assembly = _FakeAssembly()
    pipeline, telemetry, _, _ = _pipeline(clock, retriever=retriever, assembly=assembly)

    result = pipeline.retrieve(
        _scope(), RunContext(query_text="q"), session_id="s-6"
    )

    assert result.outcome_code is OutcomeCode.TIMEOUT_PREFIX_ONLY
    assert result.context_block.slots == []  # no static-prefix port wired in this build
    assert assembly.calls == 0, "assembly must never be started once budget is blown"
    assert len(telemetry.calls) == 1
    assert telemetry.calls[0]["outcome_code"] is OutcomeCode.TIMEOUT_PREFIX_ONLY


def test_total_stall_uses_injected_static_prefix_when_available() -> None:
    clock = FakeClock()
    retriever = _FakeRetriever(clock, stall_ms=350.0)
    prefix_block = ContextBlock(slots=[], rendered="MEMORY (recalled data, verify against current state)")

    class _Prefix:
        def get(self, scope: ProjectScope) -> ContextBlock:
            return prefix_block

    pipeline = Pipeline(
        clock=clock,
        config=_FakeConfigProvider(),
        telemetry=_RecordingTelemetry(),
        retriever=retriever,
        assembly=_FakeAssembly(),
        static_prefix=_Prefix(),
        holdout_salt="test-salt",
    )

    result = pipeline.retrieve(
        _scope(), RunContext(query_text="q"), session_id="s-7"
    )

    assert result.outcome_code is OutcomeCode.TIMEOUT_PREFIX_ONLY
    assert result.context_block is prefix_block


def test_total_stall_with_failing_static_prefix_still_degrades_cleanly() -> None:
    clock = FakeClock()
    retriever = _FakeRetriever(clock, stall_ms=350.0)

    class _RaisingPrefix:
        def get(self, scope: ProjectScope) -> object:
            raise RuntimeError("valkey unreachable")

    pipeline = Pipeline(
        clock=clock,
        config=_FakeConfigProvider(),
        telemetry=_RecordingTelemetry(),
        retriever=retriever,
        assembly=_FakeAssembly(),
        static_prefix=_RaisingPrefix(),  # type: ignore[arg-type]
        holdout_salt="test-salt",
    )

    result = pipeline.retrieve(
        _scope(), RunContext(query_text="q"), session_id="s-8"
    )

    assert result.outcome_code is OutcomeCode.TIMEOUT_PREFIX_ONLY
    assert result.context_block.slots == []


# --------------------------------------------------------------------------- #
# The telemetry write itself must never propagate — "including exceptions
# from the code that records the degradation".
# --------------------------------------------------------------------------- #


def test_failing_telemetry_writer_never_propagates() -> None:
    clock = FakeClock()
    telemetry = _RecordingTelemetry(raises=True)
    retriever = _FakeRetriever(clock)  # succeeds, so this is a genuine non-degraded run
    pipeline, _, _, _ = _pipeline(clock, telemetry=telemetry, retriever=retriever)

    result = pipeline.retrieve(
        _scope(), RunContext(query_text="q"), session_id="s-9"
    )

    # The retrieval itself succeeded; only the recording of it failed.
    assert result.outcome_code is OutcomeCode.INJECTED
    assert len(telemetry.calls) == 1  # the call was attempted despite raising


def test_failing_telemetry_writer_during_a_degraded_outcome_never_propagates() -> None:
    """Exercises "exceptions from the code that records the degradation" literally:
    the run is ALSO degraded (store error), and telemetry ALSO raises."""
    clock = FakeClock()
    telemetry = _RecordingTelemetry(raises=True)
    retriever = _FakeRetriever(clock, raises=True)
    pipeline, _, _, _ = _pipeline(clock, telemetry=telemetry, retriever=retriever)

    result = pipeline.retrieve(
        _scope(), RunContext(query_text="q"), session_id="s-10"
    )

    assert result.outcome_code is OutcomeCode.STORE_ERROR
    assert len(telemetry.calls) == 1


# --------------------------------------------------------------------------- #
# retrieval_event is written for EVERY call, whatever the outcome.
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("build", "expected"),
    [
        (lambda clock: _pipeline(clock), OutcomeCode.INJECTED),
        (
            lambda clock: _pipeline(clock, retriever=_FakeRetriever(clock, raises=True)),
            OutcomeCode.STORE_ERROR,
        ),
        (
            lambda clock: _pipeline(
                clock,
                assembly=_FakeAssembly(outcome_code=OutcomeCode.ABSTAINED_THRESHOLD, slots=[]),
            ),
            OutcomeCode.ABSTAINED_THRESHOLD,
        ),
        (
            lambda clock: _pipeline(clock, retriever=_FakeRetriever(clock, stall_ms=350.0)),
            OutcomeCode.TIMEOUT_PREFIX_ONLY,
        ),
    ],
    ids=["happy", "store_error", "abstained", "timeout_prefix_only"],
)
def test_retrieval_event_recorded_for_every_outcome(build: object, expected: OutcomeCode) -> None:
    clock = FakeClock()
    pipeline, telemetry, _, _ = build(clock)  # type: ignore[operator]

    result = pipeline.retrieve(_scope(), RunContext(query_text="q"), session_id="s-11")

    # Counting rows alone would survive a mutation that stamped one constant code
    # on every row — which is exactly the confusion invariant 2 exists to prevent
    # ("distinguishes abstention from timeout; lift reads this"). Assert the code.
    assert len(telemetry.calls) == 1
    assert telemetry.calls[0]["outcome_code"] is expected
    assert result.outcome_code is expected
    assert telemetry.calls[0]["arm"] is result.arm


def test_telemetry_row_carries_the_measured_latency_and_candidate_counts() -> None:
    """`retrieval_event.latency_ms` / `candidates_considered` / `top_score` feed the
    latency histogram and the lift computation (PLAN.md §5, §6). Nothing else in this
    file reads them, so a pipeline that recorded zeros would go unnoticed."""
    clock = FakeClock()
    retriever = _FakeRetriever(clock, stall_ms=120.0, candidates_considered=17)
    pipeline, telemetry, _, _ = _pipeline(clock, retriever=retriever)

    pipeline.retrieve(_scope(), RunContext(query_text="q"), session_id="s-lat")

    call = telemetry.calls[0]
    assert call["latency_ms"] == 120  # exactly the stall the fake clock advanced
    assert call["candidates_considered"] == 17
    assert call["top_score"] == 0.87  # straight from the assembly seam


# --------------------------------------------------------------------------- #
# The budget is the CALL's budget, not the ladder's: latency spent resolving
# config (a `project_config` / `agent_type_config` read) counts against it.
# --------------------------------------------------------------------------- #


def test_config_resolution_stall_alone_blows_the_total_budget() -> None:
    """A stalled config store must trip the total-budget rung BEFORE the retriever
    is ever called. Anchoring the deadline at the ladder's own entry instead of the
    call's would make this a healthy `injected` row with a >300ms wall time."""
    clock = FakeClock()
    config = _FakeConfigProvider(clock=clock, stall_ms=350.0)
    retriever = _FakeRetriever(clock)
    pipeline, telemetry, assembly, _ = _pipeline(clock, config=config, retriever=retriever)

    result = pipeline.retrieve(_scope(), RunContext(query_text="q"), session_id="s-cfg")

    assert result.outcome_code is OutcomeCode.TIMEOUT_PREFIX_ONLY
    assert retriever.calls == 0, "no search may start with the whole budget already spent"
    assert assembly.calls == 0
    assert telemetry.calls[0]["outcome_code"] is OutcomeCode.TIMEOUT_PREFIX_ONLY
    assert telemetry.calls[0]["latency_ms"] == 350


def test_embed_sub_budget_is_clamped_to_what_remains_of_the_total_budget() -> None:
    """The two budgets are nested, not independent: with 50ms of the 300ms total
    left, the embed call may not be handed its full 200ms."""
    clock = FakeClock()
    config = _FakeConfigProvider(clock=clock, stall_ms=250.0)
    retriever = _FakeRetriever(clock)
    pipeline, _, _, _ = _pipeline(clock, config=config, retriever=retriever)

    pipeline.retrieve(_scope(), RunContext(query_text="q"), session_id="s-embed")

    assert retriever.calls == 1
    assert retriever.received_cfg is not None
    assert retriever.received_cfg.embed_timeout_ms == 50
    # Only the embed budget narrows; every other retrieval knob is passed through.
    assert retriever.received_cfg.rrf_k == 60
    assert retriever.received_cfg.arm_top_n == 50


def test_embed_sub_budget_is_untouched_when_the_whole_budget_remains() -> None:
    clock = FakeClock()
    retriever = _FakeRetriever(clock)
    pipeline, _, _, _ = _pipeline(clock, retriever=retriever)

    pipeline.retrieve(_scope(), RunContext(query_text="q"), session_id="s-embed-2")

    assert retriever.received_cfg is not None
    assert retriever.received_cfg.embed_timeout_ms == 200


# --------------------------------------------------------------------------- #
# The remaining ways `retrieve()` could raise INTO an agent runtime.
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("payload", "why"),
    [
        (None, "a null answer from a cache miss"),
        ("MEMORY (recalled data, verify against current state)", "the raw rendered string"),
        ([{"slot": "fact", "text": "x"}], "a bare slot list"),
        ({"header": "SYSTEM POLICY", "slots": []}, "a mapping that relabels the block"),
        (7, "a corrupted cache entry"),
    ],
    ids=["none", "raw_string", "slot_list", "relabelled_mapping", "garbage"],
)
def test_static_prefix_returning_a_non_context_block_never_propagates(
    payload: object, why: str
) -> None:
    """`StaticPrefixPort` has no implementation until Phase 2 (`prefix_builder`),
    so its return value is unvalidated data read back out of Valkey. A wrong-typed
    one reaches the Pydantic response model from OUTSIDE every ladder guard — the
    one shape of "Tracebed failed the run" the ladder's own try/excepts cannot
    catch. The relabelling case matters twice over: invariant 3 fixes the header,
    and a mapping is the one wrong type Pydantic would otherwise happily coerce.
    """
    clock = FakeClock()

    class _WrongTypePrefix:
        def get(self, scope: ProjectScope) -> object:
            return payload

    pipeline = Pipeline(
        clock=clock,
        config=_FakeConfigProvider(),
        telemetry=_RecordingTelemetry(),
        retriever=_FakeRetriever(clock, stall_ms=350.0),
        assembly=_FakeAssembly(),
        static_prefix=_WrongTypePrefix(),  # type: ignore[arg-type]
        holdout_salt="test-salt",
    )

    result = pipeline.retrieve(_scope(), RunContext(query_text="q"), session_id="s-13")

    assert result.outcome_code is OutcomeCode.TIMEOUT_PREFIX_ONLY, why
    assert result.context_block.slots == []
    assert result.context_block.header == MEMORY_HEADER
    assert result.context_block.rendered == ""


class _BrokenMonotonicClock:
    """A `Clock` whose monotonic source is dead. `Clock` is an injected Protocol,
    so this is third-party code sitting on the synchronous path."""

    def __init__(self) -> None:
        self._inner = FakeClock()

    def now(self) -> datetime:
        return self._inner.now()

    def now_ms(self) -> int:
        return self._inner.now_ms()

    def monotonic_ms(self) -> float:
        raise OSError("monotonic clock unavailable")


class _BrokenWallClock:
    def __init__(self) -> None:
        self._inner = FakeClock()

    def now(self) -> datetime:
        raise OSError("wall clock unavailable")

    def now_ms(self) -> int:
        raise OSError("wall clock unavailable")

    def monotonic_ms(self) -> float:
        return self._inner.monotonic_ms()


def test_broken_monotonic_clock_degrades_instead_of_raising() -> None:
    """Nothing can be budgeted without a monotonic reading, and unbudgeted work on
    the synchronous path is what invariant 2 forbids — so the call degrades to the
    third rung rather than running the ladder blind or raising."""
    clock = _BrokenMonotonicClock()
    telemetry = _RecordingTelemetry()
    retriever = _FakeRetriever(FakeClock())
    pipeline = Pipeline(
        clock=clock,  # type: ignore[arg-type]
        config=_FakeConfigProvider(),
        telemetry=telemetry,
        retriever=retriever,
        assembly=_FakeAssembly(),
        holdout_salt="test-salt",
    )

    result = pipeline.retrieve(_scope(), RunContext(query_text="q"), session_id="s-15")

    assert result.outcome_code is OutcomeCode.STORE_ERROR
    assert retriever.calls == 0
    assert len(telemetry.calls) == 1  # the row is still written; latency is unmeasurable
    assert telemetry.calls[0]["latency_ms"] == 0


def test_broken_wall_clock_still_mints_a_run_id_and_completes() -> None:
    """`now_ms()` only seeds the UUIDv7 timestamp; losing it must cost the caller a
    little determinism, never the run."""
    clock = _BrokenWallClock()
    telemetry = _RecordingTelemetry()
    pipeline = Pipeline(
        clock=clock,  # type: ignore[arg-type]
        config=_FakeConfigProvider(),
        telemetry=telemetry,
        retriever=_FakeRetriever(FakeClock()),
        assembly=_FakeAssembly(),
        holdout_salt="test-salt",
    )

    result = pipeline.retrieve(_scope(), RunContext(query_text="q"), session_id="s-16")

    assert result.run_id.version == 7
    assert result.run_id_origin == "server"
    assert result.outcome_code is OutcomeCode.INJECTED
    assert len(telemetry.calls) == 1


def test_holdout_failure_never_blocks_retrieval() -> None:
    """Arm assignment is bookkeeping about learning, not learning itself: an
    out-of-range `holdout_pct` in project config must not cost the run its memory."""
    clock = FakeClock()
    pipeline, _, assembly, _ = _pipeline(
        clock, config=_FakeConfigProvider(_cfg(holdout_pct=1000.0))
    )

    result = pipeline.retrieve(_scope(), RunContext(query_text="q"), session_id="s-17")

    assert result.arm is Arm.MEMORY_ON  # the safe default, not an exception
    assert result.outcome_code is OutcomeCode.INJECTED
    assert assembly.calls == 1


def test_agent_type_is_taken_from_the_server_derived_scope() -> None:
    """Invariant 4's wall is per-project AND per-agent-type: `/v1/retrieve`'s body
    carries an `agent_type` string, so if the pipeline accepted one it would let a
    caller select another agent's memories and static prefix. There is no parameter
    to pass one, and every downstream stage sees `scope.agent_type_id`."""
    import inspect

    clock = FakeClock()
    config = _FakeConfigProvider()
    assembly = _FakeAssembly()
    pipeline, _, _, _ = _pipeline(clock, config=config, assembly=assembly)
    scope = _scope()

    pipeline.retrieve(scope, RunContext(query_text="q"), session_id="s-18")

    assert "agent_type_id" not in inspect.signature(Pipeline.retrieve).parameters
    assert config.received_agent_type_ids == [scope.agent_type_id]


# --------------------------------------------------------------------------- #
# `budget.Deadline` itself — the mechanism every rung above is built on.
# --------------------------------------------------------------------------- #


def test_deadline_measures_from_the_supplied_anchor_not_from_construction() -> None:
    clock = FakeClock()
    clock.advance(ms=100.0)
    anchor = clock.monotonic_ms()
    clock.advance(ms=250.0)

    deadline = Deadline(
        clock=clock, total_budget_ms=300, embed_timeout_ms=200, started_at_ms=anchor
    )

    assert deadline.elapsed_ms() == 250.0
    assert deadline.remaining_ms() == 50.0
    assert deadline.total_exceeded() is False


def test_deadline_defaults_its_anchor_to_the_clock_reading_at_construction() -> None:
    clock = FakeClock()
    clock.advance(ms=100.0)
    deadline = Deadline(clock=clock, total_budget_ms=300, embed_timeout_ms=200)

    assert deadline.elapsed_ms() == 0.0
    assert deadline.remaining_ms() == 300.0


def test_deadline_is_exceeded_exactly_at_the_budget_not_one_tick_later() -> None:
    clock = FakeClock()
    deadline = Deadline(clock=clock, total_budget_ms=300, embed_timeout_ms=200)

    clock.advance(ms=299.0)
    assert deadline.total_exceeded() is False
    clock.advance(ms=1.0)  # exactly 300ms elapsed
    assert deadline.total_exceeded() is True
    assert deadline.remaining_ms() == 0.0


def test_embed_sub_budget_is_the_tighter_of_the_two_budgets() -> None:
    clock = FakeClock()
    deadline = Deadline(clock=clock, total_budget_ms=300, embed_timeout_ms=200)

    assert deadline.embed_sub_budget_ms() == 200.0  # embed timeout is the binding one
    clock.advance(ms=250.0)
    assert deadline.embed_sub_budget_ms() == 50.0  # remaining total is now binding
    clock.advance(ms=100.0)
    assert deadline.embed_sub_budget_ms() == 0.0  # never negative: "do not attempt"


@pytest.mark.parametrize(
    ("total_budget_ms", "embed_timeout_ms"),
    [(0, 200), (-1, 200), (300, 0), (300, -5)],
)
def test_deadline_rejects_non_positive_budgets(total_budget_ms: int, embed_timeout_ms: int) -> None:
    """A non-positive budget is a misconfiguration, not "no time left": silently
    treating it as an instant timeout would hide a broken `project_config` row."""
    with pytest.raises(ValueError):
        Deadline(
            clock=FakeClock(),
            total_budget_ms=total_budget_ms,
            embed_timeout_ms=embed_timeout_ms,
        )


# --------------------------------------------------------------------------- #
# One real-time test: the wall-clock (SystemClock) path completes normally.
# --------------------------------------------------------------------------- #


def test_real_time_wall_clock_path_completes_fast() -> None:
    clock = SystemClock()
    telemetry = _RecordingTelemetry()
    assembly = _FakeAssembly()
    retriever = _FakeRetriever_RealTime()
    pipeline = Pipeline(
        clock=clock,
        config=_FakeConfigProvider(),
        telemetry=telemetry,
        retriever=retriever,
        assembly=assembly,
        holdout_salt="test-salt",
    )

    start = clock.monotonic_ms()
    result = pipeline.retrieve(
        _scope(), RunContext(query_text="q"), session_id="s-12"
    )
    elapsed = clock.monotonic_ms() - start

    assert result.outcome_code is OutcomeCode.INJECTED
    assert elapsed < 300.0  # well inside the total budget on a real clock
    assert len(telemetry.calls) == 1


class _FakeRetriever_RealTime:
    """Instant success against a real `SystemClock` — no stalling."""

    def retrieve(
        self, project_id: ProjectId, query_text: str, *, cfg: RetrievalConfig
    ) -> _Outcome:
        return _Outcome()


# --------------------------------------------------------------------------- #
# The third budget check: the assembly seam does store work of its own.
# --------------------------------------------------------------------------- #


def test_an_assembly_that_blows_the_budget_reports_timeout_not_injected() -> None:
    """`hotpath.assembly` fetches candidate content, per-term document frequencies and the
    corpus size AFTER the retriever returns. The checks before and after the retriever cannot
    cover that work -- it did not exist yet. Without a third check the call answers `injected`
    at 400ms while writing a `retrieval_event` that says the budget held."""
    clock = FakeClock()
    assembly = _FakeAssembly(clock=clock, stall_ms=400.0)
    pipeline, telemetry, _, _ = _pipeline(clock, assembly=assembly, retriever=_FakeRetriever(clock))

    result = pipeline.retrieve(_scope(), RunContext(query_text="q"), session_id="s")

    assert result.outcome_code is OutcomeCode.TIMEOUT_PREFIX_ONLY
    assert telemetry.calls[0]["outcome_code"] is OutcomeCode.TIMEOUT_PREFIX_ONLY
    assert result.context_block.rendered == ""


def test_an_assembly_inside_the_budget_still_injects() -> None:
    """The control for the test above: the third check must not fire on a healthy call."""
    clock = FakeClock()
    assembly = _FakeAssembly(clock=clock, stall_ms=10.0)
    pipeline, telemetry, _, _ = _pipeline(clock, assembly=assembly, retriever=_FakeRetriever(clock))

    result = pipeline.retrieve(_scope(), RunContext(query_text="q"), session_id="s")

    assert result.outcome_code is OutcomeCode.INJECTED
    assert telemetry.calls[0]["outcome_code"] is OutcomeCode.INJECTED


# --------------------------------------------------------------------------- #
# injection_log: the only record of what actually entered a prompt.
# --------------------------------------------------------------------------- #


def _injection_row() -> InjectionRow:
    return InjectionRow(memory_id=MemoryId(uuid4()), slot=Slot.FACT, score=0.9, tokens=12)


def test_injections_are_written_for_an_injected_call() -> None:
    clock = FakeClock()
    row = _injection_row()
    recorder = _RecordingInjections()
    pipeline, _, _, _ = _pipeline(
        clock,
        assembly=_FakeAssembly(injections=(row,)),
        retriever=_FakeRetriever(clock),
        injections=recorder,
    )
    scope = _scope()

    result = pipeline.retrieve(scope, RunContext(query_text="q"), session_id="s")

    assert len(recorder.calls) == 1
    project_id, run_id, rows = recorder.calls[0]
    assert project_id == scope.project_id
    assert run_id.value == result.run_id
    assert rows == (row,)


def test_no_injection_statement_is_issued_when_nothing_was_placed() -> None:
    """An abstaining call must not pay for a zero-row write."""
    clock = FakeClock()
    recorder = _RecordingInjections()
    pipeline, _, _, _ = _pipeline(
        clock,
        assembly=_FakeAssembly(outcome_code=OutcomeCode.ABSTAINED_RARITY, slots=[], injections=()),
        retriever=_FakeRetriever(clock),
        injections=recorder,
    )
    pipeline.retrieve(_scope(), RunContext(query_text="q"), session_id="s")
    assert recorder.calls == []


def test_nothing_is_injected_on_a_failed_rung() -> None:
    """A ladder rung that returns the prefix or nothing has no placed memories, so there is
    nothing to log -- and the `_LadderResult` default must not leak a previous call's rows."""
    clock = FakeClock()
    recorder = _RecordingInjections()
    pipeline, _, _, _ = _pipeline(
        clock,
        assembly=_FakeAssembly(raises=True),
        retriever=_FakeRetriever(clock),
        injections=recorder,
    )
    result = pipeline.retrieve(_scope(), RunContext(query_text="q"), session_id="s")
    assert result.outcome_code is OutcomeCode.STORE_ERROR
    assert recorder.calls == []


def test_an_injection_log_outage_never_fails_the_run() -> None:
    """Invariant 2 covers the bookkeeping too: recording what was injected must never become
    the reason an agent's run fails."""
    clock = FakeClock()
    pipeline, telemetry, _, _ = _pipeline(
        clock,
        assembly=_FakeAssembly(injections=(_injection_row(),)),
        retriever=_FakeRetriever(clock),
        injections=_RecordingInjections(raises=True),
    )
    result = pipeline.retrieve(_scope(), RunContext(query_text="q"), session_id="s")
    assert result.outcome_code is OutcomeCode.INJECTED
    assert len(telemetry.calls) == 1  # and the retrieval_event was still written


def test_a_pipeline_with_no_injection_recorder_still_serves() -> None:
    """`injections` is optional: a deployment without an `injection_log` writer degrades to no
    forensics, never to a failed retrieve."""
    clock = FakeClock()
    pipeline, _, _, _ = _pipeline(
        clock,
        assembly=_FakeAssembly(injections=(_injection_row(),)),
        retriever=_FakeRetriever(clock),
    )
    assert (
        pipeline.retrieve(_scope(), RunContext(query_text="q"), session_id="s").outcome_code
        is OutcomeCode.INJECTED
    )


def test_the_real_telemetry_satisfies_the_injection_recorder_port() -> None:
    """`stores.pg.telemetry.Telemetry.record_injections` is what production passes here; a
    signature change there would otherwise only surface against a live database."""
    assert inspect.signature(Telemetry.record_injections) == inspect.signature(
        InjectionRecorderPort.record_injections
    )
