"""The Phase 3 gate's ledger-and-cap drill (PLAN.md section 7 Phase 3):

    "Ledger reconciles; the cap pauses workers and NOT the hot path."

Three things this drill proves, each against REAL production code:

  1. THE LEDGER RECONCILES. `workers.spend.SpendMeter.add` is additive
     (`Repo.spend_add` is an accumulating UPSERT); several `.add()` calls
     across several (worker, model) cells on the same UTC day must sum, via
     `SpendMeter.check_cap`, to exactly what was added -- no double counting,
     no lost deltas, no drift introduced by the meter itself.
  2. THE CAP PAUSES WORKERS. `workers.spend_enforce.SpendEnforcer.run_guarded`
     skips the guarded callable entirely once the real `SpendMeter` (fed by
     the ledger above, not a canned `CapStatus`) reports the project over its
     `spend.daily_llm_cap_usd` cap.
  3. THE CAP NEVER TOUCHES THE HOT PATH. A REAL `hotpath.pipeline.Pipeline`
     retrieves successfully, with the SAME project over the SAME cap, at the
     SAME time -- `scripts/purity_check.py` already proves the structural
     half (no `workers` module reachable from `hotpath/`'s import graph);
     this proves the functional half, mirroring
     `tests/phase3/test_spend_enforce.py::TestHotPathUnaffected`.

`_FakeSpendRepo` satisfies exactly the two methods `workers.spend.SpendMeter`
needs (`spend_add`/`spend_by_day`) -- the same `# type: ignore[arg-type]`
convention `tests/phase0/test_spend.py` uses to pass a duck-typed fake where
`SpendMeter.__init__` declares a concrete `stores.pg.repo.Repo` parameter,
because no Postgres is reachable on this build machine.
"""

from __future__ import annotations

import argparse
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, date, datetime
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
from tracebed.domain.events import ContextSlot, RunContext
from tracebed.domain.ids import AgentTypeId, MemoryId, PrincipalId, ProjectId
from tracebed.domain.scope import ProjectScope
from tracebed.hotpath.fusion import FusedCandidate
from tracebed.hotpath.pipeline import CandidateSetResult, Pipeline
from tracebed.stores.pg.rows import SpendRow
from tracebed.workers.spend import SpendMeter
from tracebed.workers.spend_enforce import SpendEnforcer

__all__ = [
    "LedgerAuditReport",
    "render_text",
    "run_ledger_audit",
]

_PROJECT = ProjectId(uuid4())
_DAY: date = date(2026, 7, 26)
_NOW: datetime = datetime(2026, 7, 26, 12, 0, tzinfo=UTC)


# --------------------------------------------------------------------------- #
# Part 1 -- the ledger reconciles. `_FakeSpendRepo` mirrors
# `tests/phase0/test_spend.py::FakeRepo` (chunk-local duplication, the
# accepted convention).
# --------------------------------------------------------------------------- #


@dataclass
class _FakeSpendRepo:
    rows: list[SpendRow] = field(default_factory=list)
    spend_add_calls: int = 0

    def spend_add(
        self,
        project_id: ProjectId,
        day: date,
        worker: str,
        model_id: str,
        tokens_in: int,
        tokens_out: int,
        cost_usd: float,
    ) -> None:
        self.spend_add_calls += 1
        for i, row in enumerate(self.rows):
            if row.day == day and row.worker == worker and row.model_id == model_id:
                self.rows[i] = SpendRow(
                    day=day,
                    worker=worker,
                    model_id=model_id,
                    tokens_in=row.tokens_in + tokens_in,
                    tokens_out=row.tokens_out + tokens_out,
                    cost_usd=row.cost_usd + cost_usd,
                )
                return
        self.rows.append(
            SpendRow(
                day=day,
                worker=worker,
                model_id=model_id,
                tokens_in=tokens_in,
                tokens_out=tokens_out,
                cost_usd=cost_usd,
            )
        )

    def spend_by_day(self, project_id: ProjectId, day: date) -> Sequence[SpendRow]:
        return [row for row in self.rows if row.day == day]


@dataclass(frozen=True, slots=True)
class _LedgerEntry:
    worker: str
    model_id: str
    tokens_in: int
    tokens_out: int
    cost_usd: float


_LEDGER_ENTRIES: tuple[_LedgerEntry, ...] = (
    _LedgerEntry("distiller", "gemini-3.1-pro", 1_200, 300, 0.90),
    _LedgerEntry("contribution_judge", "gemini-3.1-pro", 40, 1, 0.02),
    _LedgerEntry("shadow_validator", "gemini-3.1-pro", 0, 0, 0.0),
    # A second cell against a DIFFERENT worker/model, and a SECOND call
    # against the FIRST (worker, model) pair -- the accumulation
    # `Repo.spend_add`'s real UPSERT provides, exercised twice so a bug that
    # only shows up on the second write to an existing cell cannot hide.
    _LedgerEntry("distiller", "gemini-3.1-pro", 800, 150, 0.55),
    _LedgerEntry("contribution_judge", "gemini-flash", 10, 2, 0.001),
)


@dataclass(frozen=True, slots=True)
class LedgerReconciliationResult:
    entries_recorded: int
    expected_total_usd: float
    reported_total_usd: float

    @property
    def ok(self) -> bool:
        return (
            self.entries_recorded == len(_LEDGER_ENTRIES)
            and abs(self.expected_total_usd - self.reported_total_usd) < 1e-9
        )


def _reconciliation() -> LedgerReconciliationResult:
    repo = _FakeSpendRepo()
    clock = FakeClock(_NOW)
    meter = SpendMeter(repo, clock, SpendConfig(daily_llm_cap_usd=1_000.0))  # type: ignore[arg-type]

    for entry in _LEDGER_ENTRIES:
        meter.add(
            _PROJECT,
            entry.worker,
            entry.model_id,
            entry.tokens_in,
            entry.tokens_out,
            entry.cost_usd,
        )

    expected_total = sum(e.cost_usd for e in _LEDGER_ENTRIES)
    status = meter.check_cap(_PROJECT)
    return LedgerReconciliationResult(
        entries_recorded=repo.spend_add_calls,
        expected_total_usd=expected_total,
        reported_total_usd=status.spent_today_usd,
    )


# --------------------------------------------------------------------------- #
# Part 2 -- the cap pauses workers.
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class CapPausesWorkersResult:
    under_cap_worker_ran: bool
    over_cap_worker_skipped: bool
    over_cap_spent_usd: float
    over_cap_cap_usd: float

    @property
    def ok(self) -> bool:
        return self.under_cap_worker_ran and self.over_cap_worker_skipped


def _cap_pauses_workers() -> CapPausesWorkersResult:
    repo = _FakeSpendRepo()
    clock = FakeClock(_NOW)
    # A cap low enough that ONE distiller batch blows straight through it --
    # driven by the SAME real ledger arithmetic as part 1, not a canned
    # CapStatus.
    cfg = SpendConfig(daily_llm_cap_usd=0.50)
    meter = SpendMeter(repo, clock, cfg)  # type: ignore[arg-type]
    enforcer = SpendEnforcer(meter)

    under_ran: list[str] = []

    def _under_cap_worker() -> str:
        under_ran.append("distiller batch")
        return "ok"

    outcome_under = enforcer.run_guarded(_PROJECT, _under_cap_worker)
    under_cap_worker_ran = outcome_under[1].paused is False and under_ran == ["distiller batch"]

    # Now spend past the cap for real, through the ledger.
    meter.add(_PROJECT, "distiller", "gemini-3.1-pro", 5_000, 1_000, 5.00)
    status_before = meter.check_cap(_PROJECT)

    over_ran: list[str] = []

    def _over_cap_worker() -> str:
        over_ran.append("distiller batch")  # pragma: no cover - must never execute
        return "should-not-happen"

    result_over, outcome_over = enforcer.run_guarded(_PROJECT, _over_cap_worker)
    over_cap_worker_skipped = (
        outcome_over.paused is True and result_over is None and over_ran == []
    )

    return CapPausesWorkersResult(
        under_cap_worker_ran=under_cap_worker_ran,
        over_cap_worker_skipped=over_cap_worker_skipped,
        over_cap_spent_usd=status_before.spent_today_usd,
        over_cap_cap_usd=cfg.daily_llm_cap_usd,
    )


# --------------------------------------------------------------------------- #
# Part 3 -- the cap never touches the hot path (real `Pipeline`, over cap).
# --------------------------------------------------------------------------- #


def _scope() -> ProjectScope:
    return ProjectScope(
        project_id=_PROJECT,
        agent_type_id=AgentTypeId(uuid4()),
        principal_id=PrincipalId(uuid4()),
    )


def _pipeline_config() -> EffectiveConfig:
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
        # Zero-dollar cap: any spend at all is "over". If retrieval depended
        # on the cap in any way, THIS is the configuration that exposes it.
        spend=SpendConfig(daily_llm_cap_usd=0.0),
        cache=CacheConfig(),
        session=SessionConfig(),
        queue=QueueConfig(),
        killswitch_overlay={},
    )


class _ConfigProvider:
    def effective(self, project_id: ProjectId, agent_type_id: AgentTypeId | None = None) -> EffectiveConfig:
        return _pipeline_config()


class _Telemetry:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

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
        self.calls.append({"outcome_code": outcome_code, "arm": arm})


@dataclass(frozen=True, slots=True)
class _Outcome:
    candidates: tuple[FusedCandidate, ...] = ()
    degraded: bool = False
    embed_latency_ms: int = 5
    candidates_considered: int = 1


class _Retriever:
    def retrieve(self, project_id: ProjectId, query_text: str, *, cfg: RetrievalConfig) -> _Outcome:
        return _Outcome()


class _Assembly:
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


@dataclass(frozen=True, slots=True)
class HotPathUnaffectedResult:
    injected_while_over_cap: bool
    meter_never_consulted_by_pipeline: bool

    @property
    def ok(self) -> bool:
        return self.injected_while_over_cap and self.meter_never_consulted_by_pipeline


def _hot_path_unaffected() -> HotPathUnaffectedResult:
    repo = _FakeSpendRepo()
    clock = FakeClock(_NOW)
    meter = SpendMeter(repo, clock, SpendConfig(daily_llm_cap_usd=0.0))  # type: ignore[arg-type]
    meter.add(_PROJECT, "distiller", "gemini-3.1-pro", 1, 1, 0.01)  # any spend is over a $0 cap
    enforcer = SpendEnforcer(meter)
    assert enforcer.status(_PROJECT).exceeded is True

    telemetry = _Telemetry()
    pipeline = Pipeline(
        clock=FakeClock(_NOW),
        config=_ConfigProvider(),
        telemetry=telemetry,
        retriever=_Retriever(),
        assembly=_Assembly(),
        holdout_salt="ledger-audit-salt",
    )
    result = pipeline.retrieve(_scope(), RunContext(query_text="how long do these calls take"))
    injected = result.outcome_code is OutcomeCode.INJECTED and bool(result.context_block.slots)

    # `Pipeline.__init__`'s keyword surface is the complete list of things
    # that can reach retrieval; none of them is `enforcer` or `meter`, so
    # nothing SpendEnforcer/SpendMeter/CapExceeded touches was even
    # constructible from inside the call above. Confirmed structurally
    # (never a spend-shaped parameter exists) rather than merely observed
    # (no CapExceeded happened to be raised this run).
    import inspect

    params = set(inspect.signature(Pipeline.__init__).parameters) - {"self"}
    no_spend_dependency = not any("spend" in name or "cap" in name for name in params)

    return HotPathUnaffectedResult(
        injected_while_over_cap=injected,
        meter_never_consulted_by_pipeline=no_spend_dependency,
    )


# --------------------------------------------------------------------------- #
# The report.
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class LedgerAuditReport:
    reconciliation: LedgerReconciliationResult
    cap_pauses_workers: CapPausesWorkersResult
    hot_path_unaffected: HotPathUnaffectedResult

    @property
    def ok(self) -> bool:
        return (
            self.reconciliation.ok
            and self.cap_pauses_workers.ok
            and self.hot_path_unaffected.ok
        )


def run_ledger_audit() -> LedgerAuditReport:
    return LedgerAuditReport(
        reconciliation=_reconciliation(),
        cap_pauses_workers=_cap_pauses_workers(),
        hot_path_unaffected=_hot_path_unaffected(),
    )


def render_text(report: LedgerAuditReport) -> str:
    r = report.reconciliation
    c = report.cap_pauses_workers
    h = report.hot_path_unaffected
    lines = [
        f"ledger reconciles: {'PASS' if r.ok else 'FAIL'} "
        f"({r.entries_recorded} entries recorded; expected total=${r.expected_total_usd:.4f}, "
        f"reported total=${r.reported_total_usd:.4f})",
        f"cap pauses workers: {'PASS' if c.ok else 'FAIL'} "
        f"(under-cap worker ran={c.under_cap_worker_ran}, "
        f"over-cap worker skipped={c.over_cap_worker_skipped}, "
        f"spent=${c.over_cap_spent_usd:.2f} against cap=${c.over_cap_cap_usd:.2f})",
        f"hot path unaffected: {'PASS' if h.ok else 'FAIL'} "
        f"(injected while over a $0.00 cap={h.injected_while_over_cap}, "
        f"Pipeline has no spend-shaped dependency={h.meter_never_consulted_by_pipeline})",
        f"overall: {'PASS' if report.ok else 'FAIL'}",
    ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args(argv)
    report = run_ledger_audit()
    print(render_text(report))
    return 0 if report.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
