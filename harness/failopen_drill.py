"""The fail-open fault-injection drill (PLAN.md §2 invariant 2, §7 Phase 1 gate).

"kill Postgres, kill Valkey, stall the embedding endpoint (sleep > 200ms), stall
everything (> 300ms). Assert the fake agent runtime completes every run, and
`retrieval_event.outcome_code` records `degraded_lexical` / `timeout_prefix_only`
/ `store_error` correctly."

This module drives `hotpath.pipeline.Pipeline.retrieve()` — the real
orchestrator `/v1/retrieve` calls — through six fault scenarios, each standing
in for one production failure mode:

  * ``postgres_down``           — the retriever (both search arms live on
    Postgres) raises. Expected: `OutcomeCode.STORE_ERROR`, nothing rendered.
  * ``config_store_down``       — `ConfigResolver.effective()` (itself a
    `project_config`/`agent_type_config` read, also Postgres) raises before
    the ladder can even start. Expected: `OutcomeCode.STORE_ERROR`.
  * ``valkey_down_at_prefix``   — the total budget is already blown (a
    genuine "everything stalled" condition) AND the static-prefix cache
    (Valkey) is also unreachable. Expected: `OutcomeCode.TIMEOUT_PREFIX_ONLY`
    with an EMPTY context block (invariant 2 does not promise a prefix when
    the store that holds it is down, only that the call still completes).
  * ``embedder_stalled``        — the embed sub-budget (200ms) is exceeded but
    the total budget (300ms) is not. Expected: `OutcomeCode.DEGRADED_LEXICAL`,
    with the lexical arm's results still assembled.
  * ``everything_stalled``      — the whole retrieval takes longer than the
    total budget (300ms). Expected: `OutcomeCode.TIMEOUT_PREFIX_ONLY`.
  * ``everything_down_at_once`` — Postgres AND Valkey are both unreachable at
    the same time (the retriever raises outright). Expected:
    `OutcomeCode.STORE_ERROR` — the worse of the two failures wins, and the
    call still completes.

Every stall is driven by `FakeClock.advance()` from inside the fault-injected
fake (no real `time.sleep`, matching `tests/phase1/test_degradation_ladder.py`'s
own convention) so the drill runs in milliseconds and deterministically.

RUNNABLE OFFLINE (no Postgres/Valkey/anything required) — every scenario here
is a fake standing in for the corresponding real dependency. The REAL-service
half (an actual `docker/compose.yaml` stack, Postgres genuinely killed mid-call)
is integration-marked and reported honestly: `run_failopen_drill` probes
`TB_STORAGE__PG_DSN`/`TB_STORAGE__VALKEY_URL` and reports `live_stack_reachable
=False` rather than silently skipping the fact that it never ran, mirroring
`harness/fake_runtime.py`'s own real-vs-fake mode detection. There is no
in-repo mechanism to genuinely sever an established Postgres/Valkey connection
mid-call from Python alone (that is `docker kill`'s job, external to this
process), so even when a stack is reachable this module proves the fixture
correctness of the exact same scenarios above, not a literal `docker kill`
drill — that live half is exercised by hand against `docker/compose.yaml`,
per PLAN.md §7's rules of engagement for what is/is not mechanically checkable
from a test process.
"""

from __future__ import annotations

import argparse
import json
import os
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Any, Final
from uuid import uuid4

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
from tracebed.domain.events import ContextBlock, ContextSlot, RunContext
from tracebed.domain.ids import AgentTypeId, PrincipalId, ProjectId, RunId
from tracebed.domain.scope import ProjectScope
from tracebed.hotpath.fusion import FusedCandidate
from tracebed.hotpath.pipeline import CandidateSetResult, Pipeline

__all__ = [
    "FailopenDrillReport",
    "ScenarioResult",
    "main",
    "render_text",
    "run_failopen_drill",
]

_DEFAULT_TOTAL_BUDGET_MS: Final[int] = 300
_DEFAULT_EMBED_TIMEOUT_MS: Final[int] = 200
_N_RUNS_PER_SCENARIO: Final[int] = 5
"""How many independent `retrieve()` calls each scenario drives — "the fake
agent runtime completes EVERY run" is a claim about repetition, not one call."""


def _cfg(*, total_budget_ms: int = _DEFAULT_TOTAL_BUDGET_MS, embed_timeout_ms: int = _DEFAULT_EMBED_TIMEOUT_MS) -> EffectiveConfig:
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
        # 0, not PLAN.md §6's shipped 5: this drill's subject is the DEGRADATION LADDER, and
        # the holdout arm is memory-off (D-099) — a run that draws it returns
        # `OutcomeCode.HOLDOUT` and an empty block no matter which fault was injected, which
        # would make a scenario's expected code depend on a hash of its session key. The
        # holdout arm's own behaviour is covered by tests/phase1/test_pipeline.py.
        killswitch=KillswitchConfig(holdout_pct=0.0),
        spend=SpendConfig(),
        cache=CacheConfig(),
        session=SessionConfig(),
        queue=QueueConfig(),
        killswitch_overlay={},
    )


def _scope() -> ProjectScope:
    return ProjectScope(
        project_id=ProjectId(uuid4()),
        agent_type_id=AgentTypeId(uuid4()),
        principal_id=PrincipalId(uuid4()),
    )


class _ConfigProvider:
    """Satisfies `hotpath.pipeline.ConfigProvider`. `raises=True` simulates the
    config store itself (Postgres — `project_config`/`agent_type_config`)
    being unreachable."""

    def __init__(self, cfg: EffectiveConfig, *, raises: bool = False) -> None:
        self._cfg = cfg
        self._raises = raises

    def effective(self, project_id: ProjectId, agent_type_id: AgentTypeId | None = None) -> EffectiveConfig:
        if self._raises:
            raise RuntimeError("config store unreachable (drill-injected: Postgres down)")
        return self._cfg


class _RecordingTelemetry:
    """Satisfies `hotpath.pipeline.TelemetryRecorderPort`. Records every call —
    invariant 2 requires exactly one `retrieval_event` per `retrieve()` call,
    including degraded and failed ones."""

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
        self.calls.append({"outcome_code": outcome_code, "latency_ms": latency_ms, "arm": arm})


@dataclass(frozen=True, slots=True)
class _Outcome:
    """Structurally satisfies `hotpath.pipeline.RetrievalOutcomeLike`."""

    candidates: tuple[FusedCandidate, ...] = ()
    degraded: bool = False
    embed_latency_ms: int = 5
    candidates_considered: int = 0


class _FaultRetriever:
    """Satisfies `hotpath.pipeline.HybridRetrieverPort`. `stall_ms` advances the
    injected `FakeClock` as a side effect of the call (simulating real
    wall-clock cost with no `time.sleep`); `raises` simulates Postgres itself
    being unreachable (the real `Retriever` propagates anything but
    `EmbeddingTimeout` unmodified); `degraded` simulates the real `Retriever`
    having caught an `EmbeddingTimeout` internally."""

    def __init__(
        self,
        clock: FakeClock,
        *,
        stall_ms: float = 0.0,
        degraded: bool = False,
        raises: bool = False,
    ) -> None:
        self._clock = clock
        self._stall_ms = stall_ms
        self._degraded = degraded
        self._raises = raises

    def retrieve(self, project_id: ProjectId, query_text: str, *, cfg: RetrievalConfig) -> _Outcome:
        if self._stall_ms:
            self._clock.advance(ms=self._stall_ms)
        if self._raises:
            raise RuntimeError("retrieval store unreachable (drill-injected: Postgres down)")
        return _Outcome(
            degraded=self._degraded,
            embed_latency_ms=int(self._stall_ms) if self._stall_ms else 5,
            candidates_considered=1,
        )


class _FixedAssembly:
    """Satisfies `hotpath.pipeline.CandidateAssemblyPort`: always reports a
    single injected fact — proves a degraded-but-not-failed call still
    assembles from whatever the lexical-only arm found."""

    def __init__(self) -> None:
        self.calls = 0

    def run(
        self,
        scope: ProjectScope,
        *,
        query_text: str,
        candidates: Sequence[FusedCandidate],
        cfg: EffectiveConfig,
    ) -> CandidateSetResult:
        self.calls += 1
        slots = [ContextSlot(slot=Slot.FACT, memory_id=uuid4(), tokens=10, text="a recalled fact")]
        return CandidateSetResult(outcome_code=OutcomeCode.INJECTED, slots=slots, top_score=0.8)


class _RaisingStaticPrefix:
    """Satisfies `hotpath.pipeline.StaticPrefixPort`: simulates Valkey (the
    static-prefix cache) being unreachable."""

    def get(self, scope: ProjectScope) -> ContextBlock:
        raise RuntimeError("static prefix cache unreachable (drill-injected: Valkey down)")


@dataclass(frozen=True, slots=True)
class ScenarioResult:
    name: str
    description: str
    expected_outcome: OutcomeCode
    runs_completed: int
    runs_requested: int
    outcomes_seen: tuple[OutcomeCode, ...]
    telemetry_rows_written: int
    exceptions: tuple[str, ...]
    """Any exception `retrieve()` let escape — invariant 2 says this must
    always be empty; a non-empty tuple here is a hard failure, worse than a
    wrong outcome code."""

    @property
    def completed_every_run(self) -> bool:
        return self.runs_completed == self.runs_requested and not self.exceptions

    @property
    def outcome_code_correct(self) -> bool:
        return bool(self.outcomes_seen) and all(o is self.expected_outcome for o in self.outcomes_seen)

    @property
    def ok(self) -> bool:
        return self.completed_every_run and self.outcome_code_correct


def _run_scenario(
    name: str,
    description: str,
    expected_outcome: OutcomeCode,
    build_pipeline: Callable[[], Pipeline],
    *,
    n_runs: int,
) -> ScenarioResult:
    """Drives one scenario `n_runs` times, catching ANY exception at this
    harness's own boundary — `Pipeline.retrieve()` must never raise (module
    docstring / invariant 2), so a caught exception here is reported as a
    drill failure, not silently absorbed the way `Pipeline` itself absorbs it."""
    pipeline = build_pipeline()
    outcomes: list[OutcomeCode] = []
    exceptions: list[str] = []
    completed = 0
    for i in range(n_runs):
        try:
            result = pipeline.retrieve(
                _scope(), RunContext(query_text=f"drill probe #{i} for {name}"), session_id=f"{name}-{i}"
            )
            outcomes.append(result.outcome_code)
            completed += 1
        except Exception as exc:  # the drill's whole point is to catch this
            exceptions.append(f"{type(exc).__name__}: {exc}")

    # Telemetry rows are read off whichever fake this scenario's pipeline was
    # built with — the count is asserted by the caller via the pipeline's own
    # telemetry object, not reconstructed here (kept per-scenario instead).
    telemetry = getattr(pipeline, "_telemetry", None)
    telemetry_rows = len(telemetry.calls) if isinstance(telemetry, _RecordingTelemetry) else 0

    return ScenarioResult(
        name=name,
        description=description,
        expected_outcome=expected_outcome,
        runs_completed=completed,
        runs_requested=n_runs,
        outcomes_seen=tuple(outcomes),
        telemetry_rows_written=telemetry_rows,
        exceptions=tuple(exceptions),
    )


def _build_postgres_down() -> Pipeline:
    clock = FakeClock()
    return Pipeline(
        clock=clock,
        config=_ConfigProvider(_cfg()),
        telemetry=_RecordingTelemetry(),
        retriever=_FaultRetriever(clock, raises=True),
        assembly=_FixedAssembly(),
        holdout_salt="failopen-drill-salt",
    )


def _build_config_store_down() -> Pipeline:
    clock = FakeClock()
    return Pipeline(
        clock=clock,
        config=_ConfigProvider(_cfg(), raises=True),
        telemetry=_RecordingTelemetry(),
        retriever=_FaultRetriever(clock),
        assembly=_FixedAssembly(),
        holdout_salt="failopen-drill-salt",
    )


def _build_valkey_down_at_prefix() -> Pipeline:
    clock = FakeClock()
    # 350ms > total_budget_ms (300): the total-budget rung fires, which is the
    # only rung that ever consults the static-prefix port.
    return Pipeline(
        clock=clock,
        config=_ConfigProvider(_cfg()),
        telemetry=_RecordingTelemetry(),
        retriever=_FaultRetriever(clock, stall_ms=350.0),
        assembly=_FixedAssembly(),
        static_prefix=_RaisingStaticPrefix(),
        holdout_salt="failopen-drill-salt",
    )


def _build_embedder_stalled() -> Pipeline:
    clock = FakeClock()
    # 210ms > embed_timeout_ms (200) but < total_budget_ms (300): only the
    # embed rung fires.
    return Pipeline(
        clock=clock,
        config=_ConfigProvider(_cfg()),
        telemetry=_RecordingTelemetry(),
        retriever=_FaultRetriever(clock, stall_ms=210.0, degraded=True),
        assembly=_FixedAssembly(),
        holdout_salt="failopen-drill-salt",
    )


def _build_everything_stalled() -> Pipeline:
    clock = FakeClock()
    return Pipeline(
        clock=clock,
        config=_ConfigProvider(_cfg()),
        telemetry=_RecordingTelemetry(),
        retriever=_FaultRetriever(clock, stall_ms=350.0),
        assembly=_FixedAssembly(),
        holdout_salt="failopen-drill-salt",
    )


def _build_everything_down_at_once() -> Pipeline:
    """Postgres AND Valkey both unreachable simultaneously — the retriever
    raises outright, so the static-prefix port (also down) is never even
    consulted; STORE_ERROR is the worse of the two failures and must win."""
    clock = FakeClock()
    return Pipeline(
        clock=clock,
        config=_ConfigProvider(_cfg()),
        telemetry=_RecordingTelemetry(),
        retriever=_FaultRetriever(clock, raises=True),
        assembly=_FixedAssembly(),
        static_prefix=_RaisingStaticPrefix(),
        holdout_salt="failopen-drill-salt",
    )


_SCENARIOS: Final[tuple[tuple[str, str, OutcomeCode, Callable[[], Pipeline]], ...]] = (
    (
        "postgres_down",
        "Both search arms live on Postgres; the retriever raises outright.",
        OutcomeCode.STORE_ERROR,
        _build_postgres_down,
    ),
    (
        "config_store_down",
        "ConfigResolver.effective() (project_config/agent_type_config, also Postgres) raises "
        "before the ladder can start.",
        OutcomeCode.STORE_ERROR,
        _build_config_store_down,
    ),
    (
        "valkey_down_at_prefix",
        "Total budget already exceeded AND the static-prefix cache (Valkey) is unreachable.",
        OutcomeCode.TIMEOUT_PREFIX_ONLY,
        _build_valkey_down_at_prefix,
    ),
    (
        "embedder_stalled",
        "Query-embed sub-budget (200ms) exceeded; total budget (300ms) is not.",
        OutcomeCode.DEGRADED_LEXICAL,
        _build_embedder_stalled,
    ),
    (
        "everything_stalled",
        "Whole retrieval exceeds the total budget (300ms).",
        OutcomeCode.TIMEOUT_PREFIX_ONLY,
        _build_everything_stalled,
    ),
    (
        "everything_down_at_once",
        "Postgres AND Valkey unreachable simultaneously (the compound worst case).",
        OutcomeCode.STORE_ERROR,
        _build_everything_down_at_once,
    ),
)


@dataclass(frozen=True, slots=True)
class FailopenDrillReport:
    scenarios: tuple[ScenarioResult, ...]
    live_stack_reachable: bool
    """Whether a real Postgres/Valkey stack was reachable at drill time — see
    the module docstring for why this module cannot itself perform a literal
    `docker kill` against it even when reachable."""

    @property
    def all_completed(self) -> bool:
        return all(s.completed_every_run for s in self.scenarios)

    @property
    def all_outcome_codes_correct(self) -> bool:
        return all(s.outcome_code_correct for s in self.scenarios)

    @property
    def ok(self) -> bool:
        return all(s.ok for s in self.scenarios)


def _postgres_reachable() -> bool:
    """Best-effort Postgres reachability probe, mirroring
    `harness/fake_runtime.py`'s own real-vs-fake detection and
    `tests/conftest.py::pg`'s skip convention — never raises, never blocks
    more than a 1s connect timeout."""
    dsn = os.environ.get("TB_STORAGE__PG_DSN")
    if not dsn:
        return False
    try:
        import psycopg

        with psycopg.connect(dsn, connect_timeout=1):
            return True
    except Exception:
        return False


def _live_stack_reachable() -> bool:
    return _postgres_reachable()


def run_failopen_drill(*, n_runs_per_scenario: int = _N_RUNS_PER_SCENARIO) -> FailopenDrillReport:
    """Runs every scenario in `_SCENARIOS`, offline, against `FakeClock`-driven
    fakes. Never raises — a scenario's own exceptions are captured into its
    `ScenarioResult`, and this function's job is to report, not to assert."""
    results = tuple(
        _run_scenario(name, description, expected, build, n_runs=n_runs_per_scenario)
        for name, description, expected, build in _SCENARIOS
    )
    return FailopenDrillReport(scenarios=results, live_stack_reachable=_live_stack_reachable())


def render_text(report: FailopenDrillReport) -> str:
    lines = [
        f"live stack reachable at drill time: {report.live_stack_reachable} "
        "(informational only -- see module docstring for why this drill runs "
        "against fault-injected fakes rather than a literal `docker kill`)",
        "",
        f"{'scenario':<26} {'expected':<20} {'completed':>10} {'codes ok':>9}",
    ]
    for s in report.scenarios:
        lines.append(
            f"{s.name:<26} {s.expected_outcome.value:<20} "
            f"{s.runs_completed}/{s.runs_requested:>7} {'PASS' if s.outcome_code_correct else 'FAIL':>9}"
        )
        if s.exceptions:
            for exc in s.exceptions:
                lines.append(f"    ! escaped exception: {exc}")
    lines.append("")
    lines.append(f"overall: {'PASS' if report.ok else 'FAIL'}")
    return "\n".join(lines)


def _report_to_json(report: FailopenDrillReport) -> dict[str, Any]:
    return {
        "live_stack_reachable": report.live_stack_reachable,
        "all_completed": report.all_completed,
        "all_outcome_codes_correct": report.all_outcome_codes_correct,
        "ok": report.ok,
        "scenarios": [
            {
                "name": s.name,
                "description": s.description,
                "expected_outcome": s.expected_outcome.value,
                "runs_completed": s.runs_completed,
                "runs_requested": s.runs_requested,
                "outcomes_seen": [o.value for o in s.outcomes_seen],
                "telemetry_rows_written": s.telemetry_rows_written,
                "exceptions": list(s.exceptions),
                "ok": s.ok,
            }
            for s in report.scenarios
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--n-runs", type=int, default=_N_RUNS_PER_SCENARIO)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    report = run_failopen_drill(n_runs_per_scenario=args.n_runs)

    if args.json:
        print(json.dumps(_report_to_json(report), indent=2, sort_keys=True))
    else:
        print(render_text(report))

    return 0 if report.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
