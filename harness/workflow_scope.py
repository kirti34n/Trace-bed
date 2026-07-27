"""Workflow-scope credit-assignment DIRECT DRILL (PLAN.md section 7 Phase 4 gate,
clause 3, verbatim):

    "end-only workflow verdict scores workflow-template scope ONLY, ZERO
    per-agent Q changes. This one needs a strict assertion: capture every
    memory q_value before and after, and assert the per-agent ones are
    BYTE-IDENTICAL. A workflow-level verdict that leaks into per-agent Q
    credits or blames individual agents for a workflow outcome they did not
    control."

WHY THIS FILE EXISTS AS A DRILL, NOT AS A CLAIM ABOUT PRODUCTION CODE. No worker anywhere
in this tree (`workers.scorer`, `workers.contribution_judge`, `workflow.agent_control`, ...)
owns the join between "which memories were injected into one run" (`injection_log`) and
"which of those a workflow-level outcome_event may score". That credit-assignment routing
is a CONTRACT GAP `workers/scorer.py`'s own module docstring does not even mention, because
it sits one level above what `run_scorer_batch` does: that function already takes ONE
`memory_id` at a time and trusts its caller to have chosen the right one -- there is no
scope concept inside it at all (`domain.enums.ScopeType` is not imported by
`workers/scorer.py`). This module is the harness's OWN reference implementation of the
routing PLAN.md section 7 requires -- `route_end_of_workflow_verdict` below -- built so
the property is checkable end-to-end through the REAL `tracebed.workers.scorer
.run_scorer_batch` (the arithmetic that actually moves Q), not merely asserted in the
abstract. Whichever chunk eventually owns real credit-assignment orchestration should
treat this function as the specification to match, not as a drop-in implementation (it
has no repository behind it beyond the in-memory fake this module also defines).

Not a pytest test module either (`workflow_scope.py` matches neither `test_*.py` nor
`*_test.py`) -- `harness/phase4_gate.py` calls `run_workflow_scope_drill()` directly, the
same convention `harness/lift_sim.py` / `harness/guessed_reward.py` follow. No dedicated
`tests/phase4/test_workflow_scope.py` exists (this task's file list is exactly
`harness/contention.py`, `harness/workflow_scope.py`, `harness/phase4_gate.py`,
`harness/full_gate.py` -- a new test file would be a contract_gap, not a file to add), so
`gate_report_phase4.md`'s clause 3 is backed SOLELY by this direct call; that is recorded
explicitly in `phase4_gate.py`'s own assertion detail rather than silently presented as
pytest-covered.

THE ASSERTION IS AGAINST OBSERVATION, NOT AGAINST "WE NEVER CALLED IT". Every memory in
the scenario -- the workflow-template-scoped ones AND every other-scoped one -- has its
`q_value` read directly off the fake store both BEFORE and AFTER the routed update runs,
and the non-workflow ones are compared with Python's `==` (exact float equality, never
`math.isclose`): PLAN.md's phrase "BYTE-IDENTICAL" is enforced literally, not
approximated. `WorkflowScopeReport.broken_variant_caught` proves the check itself is not
vacuous: a deliberately wrong router (`_route_ignoring_scope`, scores every injected
memory regardless of scope -- exactly the leak PLAN.md's clause warns against) is run
through the IDENTICAL before/after comparison over a separate, identically-seeded fake
store, and must fail it.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Final
from uuid import UUID, uuid4

from tracebed.domain.clock import Clock, FakeClock
from tracebed.domain.config import ScoringConfig
from tracebed.domain.enums import AdapterClass, ScopeType
from tracebed.domain.ids import MemoryId, PrincipalId, ProjectId, RunId, mint_run_id
from tracebed.workers.contribution_judge import ContributionVerdict
from tracebed.workers.epochs import ScoringEpoch
from tracebed.workers.scorer import (
    ContributionJudgePort,
    ScoreBatchResult,
    ScorerRepoPort,
    ScoringEvent,
    run_scorer_batch,
)

__all__ = [
    "Injected",
    "WorkflowScopeReport",
    "render_text",
    "route_end_of_workflow_verdict",
    "run_workflow_scope_drill",
]

_EPOCH_STARTED: Final[datetime] = datetime(2026, 1, 1, tzinfo=UTC)
_START_Q: Final[float] = 0.5

#: One injected memory's identity + content, as a real `injection_log` join over one run
#: would hand a credit-assignment orchestrator: which memory, what scope it belongs to,
#: and its content (`run_scorer_batch` needs the content for the contribution judge).
Injected = tuple[MemoryId, ScopeType, str]


@dataclass(slots=True)
class _MemoryRecord:
    scope_type: ScopeType
    content: str
    q: float
    applied_events: set[UUID] = field(default_factory=set)
    scored_today: dict[object, int] = field(default_factory=dict)


class _FakeScorerRepo:
    """Minimal, self-contained `ScorerRepoPort` -- an in-memory dict, no SQL, no
    project-scoping machinery. This drill's property is about SCOPE ROUTING (which
    memory_ids `run_scorer_batch` is ever called for), not about invariant 4 (project
    isolation at query construction), which `harness.contention` already exercises for
    the blackboard's own repository."""

    def __init__(self, memories: dict[MemoryId, _MemoryRecord]) -> None:
        self._memories = memories
        self.apply_calls: list[MemoryId] = []

    def current_q(self, project_id: ProjectId, memory_id: MemoryId) -> float:
        return self._memories[memory_id].q

    def applied_event_ids(self, project_id: ProjectId, memory_id: MemoryId) -> frozenset[UUID]:
        return frozenset(self._memories[memory_id].applied_events)

    def scored_updates_today(self, project_id: ProjectId, memory_id: MemoryId, day: object) -> int:
        return self._memories[memory_id].scored_today.get(day, 0)

    def apply_q_update(self, project_id: ProjectId, update: object) -> None:
        memory_id = update.memory_id  # type: ignore[attr-defined]
        rec = self._memories[memory_id]
        rec.q = update.new_q  # type: ignore[attr-defined]
        rec.applied_events.add(update.event_id)  # type: ignore[attr-defined]
        day = update.scored_at.date()  # type: ignore[attr-defined]
        rec.scored_today[day] = rec.scored_today.get(day, 0) + 1
        self.apply_calls.append(memory_id)


class _FixedJudge:
    """Always answers the same rubric factor -- the drill's property is about WHICH
    memories get judged/scored at all, not about the judge's own rubric arithmetic
    (`workers.contribution_judge`'s own suite covers that)."""

    def __init__(self, factor: float, epoch_id: int) -> None:
        self._factor = factor
        self._epoch_id = epoch_id

    def judge(self, *, memory_content: str, outcome_summary: str) -> ContributionVerdict:
        return ContributionVerdict(factor=self._factor, epoch_id=self._epoch_id)


def _epoch() -> ScoringEpoch:
    return ScoringEpoch(
        epoch_id=1,
        judge_model_id="workflow-scope-drill-judge",
        judge_model_version="1",
        sampling_params={"temperature": 0},
        prompt_hash="workflow-scope-drill",
        started_at=_EPOCH_STARTED,
    )


def route_end_of_workflow_verdict(
    *,
    project_id: ProjectId,
    run_id: RunId,
    injected: Sequence[Injected],
    adapter: AdapterClass,
    r: float,
    principal_id: PrincipalId,
    arrived_at: datetime,
    outcome_summary: str,
    repo: ScorerRepoPort,
    judge: ContributionJudgePort,
    config: ScoringConfig,
    epoch: ScoringEpoch,
    clock: Clock,
) -> dict[MemoryId, ScoreBatchResult]:
    """THE routing rule PLAN.md section 7 Phase 4's clause 3 requires: scores every
    memory in `injected` whose `scope_type` is `ScopeType.WORKFLOW_TEMPLATE`, and calls
    `run_scorer_batch` for NOTHING else -- no `ScoringEvent` is even CONSTRUCTED for a
    non-workflow-scoped memory, let alone scored, so there is no code path here through
    which a per-agent/per-user memory's `q_value` could move.

    One fresh `event_id` per targeted memory: mirrors how a real orchestrator would
    derive one `outcome_event`-shaped candidate per memory an `injection_log` join
    names for this run, since `run_scorer_batch` itself refuses a batch mixing
    memories (each memory has its own current Q, its own daily-cap state and its own
    replay ledger).
    """
    results: dict[MemoryId, ScoreBatchResult] = {}
    for memory_id, scope_type, content in injected:
        if scope_type is not ScopeType.WORKFLOW_TEMPLATE:
            continue
        event = ScoringEvent(
            event_id=uuid4(),
            run_id=run_id,
            memory_id=memory_id,
            adapter=adapter,
            r=r,
            principal_id=principal_id,
            arrived_at=arrived_at,
            outcome_summary=outcome_summary,
        )
        results[memory_id] = run_scorer_batch(
            project_id=project_id,
            memory_id=memory_id,
            memory_content=content,
            candidates=[event],
            repo=repo,
            judge=judge,
            config=config,
            epoch=epoch,
            clock=clock,
        )
    return results


def _route_ignoring_scope(
    *,
    project_id: ProjectId,
    run_id: RunId,
    injected: Sequence[Injected],
    adapter: AdapterClass,
    r: float,
    principal_id: PrincipalId,
    arrived_at: datetime,
    outcome_summary: str,
    repo: ScorerRepoPort,
    judge: ContributionJudgePort,
    config: ScoringConfig,
    epoch: ScoringEpoch,
    clock: Clock,
) -> dict[MemoryId, ScoreBatchResult]:
    """Deliberately WRONG reference router -- scores EVERY injected memory regardless of
    scope, exactly the leak PLAN.md's clause 3 forbids ("a workflow-level verdict that
    leaks into per-agent Q credits"). Exists ONLY so `run_workflow_scope_drill` can prove
    its own before/after check is not vacuous: run through the identical comparison, this
    variant must be CAUGHT, not silently pass. Module-private; not part of this module's
    public surface (`__all__`)."""
    results: dict[MemoryId, ScoreBatchResult] = {}
    for memory_id, _scope_type, content in injected:
        event = ScoringEvent(
            event_id=uuid4(),
            run_id=run_id,
            memory_id=memory_id,
            adapter=adapter,
            r=r,
            principal_id=principal_id,
            arrived_at=arrived_at,
            outcome_summary=outcome_summary,
        )
        results[memory_id] = run_scorer_batch(
            project_id=project_id,
            memory_id=memory_id,
            memory_content=content,
            candidates=[event],
            repo=repo,
            judge=judge,
            config=config,
            epoch=epoch,
            clock=clock,
        )
    return results


def _build_scenario() -> tuple[ProjectId, RunId, PrincipalId, list[Injected]]:
    """One run in which a workflow orchestrator's memories AND several per-agent /
    per-user / project-shared memories were all injected together -- the realistic shape
    a workflow-level outcome_event's `injection_log` join would actually return."""
    project_id = ProjectId(uuid4())
    run_id = mint_run_id()
    principal_id = PrincipalId(uuid4())
    injected: list[Injected] = [
        (MemoryId(uuid4()), ScopeType.WORKFLOW_TEMPLATE, "workflow lesson: retry step 3 with backoff"),
        (MemoryId(uuid4()), ScopeType.WORKFLOW_TEMPLATE, "workflow lesson: validate inputs before step 5"),
        (MemoryId(uuid4()), ScopeType.AGENT_TYPE, "agent-type lesson for the planner agent"),
        (MemoryId(uuid4()), ScopeType.AGENT_TYPE, "agent-type lesson for the executor agent"),
        (MemoryId(uuid4()), ScopeType.USER, "user preference: prefers concise summaries"),
        (MemoryId(uuid4()), ScopeType.PROJECT_SHARED, "project-shared fact about the staging environment"),
    ]
    return project_id, run_id, principal_id, injected


def _fresh_repo(injected: Sequence[Injected], *, start_q: float = _START_Q) -> _FakeScorerRepo:
    memories = {
        memory_id: _MemoryRecord(scope_type=scope_type, content=content, q=start_q)
        for memory_id, scope_type, content in injected
    }
    return _FakeScorerRepo(memories)


@dataclass(frozen=True, slots=True)
class WorkflowScopeReport:
    n_workflow_memories: int
    n_other_memories: int
    workflow_memories_moved: int
    """How many workflow-template-scoped memories actually had their Q change --
    catches a router that is vacuously "correct" by never scoring anything at all."""
    other_memories_untouched: bool
    """True iff EVERY non-workflow-scoped memory's q_value read back byte-identical
    (`==`) before vs. after -- PLAN.md's own phrase, enforced literally."""
    touched_only_workflow_scope: bool
    """True iff `ScorerRepoPort.apply_q_update` was never called for any memory_id
    outside the workflow-template-scoped set -- checked against the repo's own call
    log, not inferred from the Q values alone."""
    broken_variant_caught: bool
    """True iff the deliberately wrong `_route_ignoring_scope` reference, run through
    the IDENTICAL before/after comparison over a separate, identically-seeded store,
    fails `other_memories_untouched` -- i.e. this drill's own check is not vacuous."""

    @property
    def workflow_all_moved(self) -> bool:
        return self.n_workflow_memories > 0 and self.workflow_memories_moved == self.n_workflow_memories

    @property
    def ok(self) -> bool:
        return (
            self.n_workflow_memories > 0
            and self.n_other_memories > 0
            and self.workflow_all_moved
            and self.other_memories_untouched
            and self.touched_only_workflow_scope
            and self.broken_variant_caught
        )


def run_workflow_scope_drill(*, alpha: float = 0.3, r: float = 1.0) -> WorkflowScopeReport:
    project_id, run_id, principal_id, injected = _build_scenario()
    workflow_ids = {mid for mid, scope_type, _ in injected if scope_type is ScopeType.WORKFLOW_TEMPLATE}
    other_ids = {mid for mid, scope_type, _ in injected if scope_type is not ScopeType.WORKFLOW_TEMPLATE}

    config = ScoringConfig(alpha=alpha)
    epoch = _epoch()
    judge = _FixedJudge(factor=1.0, epoch_id=epoch.epoch_id)
    clock = FakeClock(_EPOCH_STARTED)
    common_kwargs = {
        "project_id": project_id,
        "run_id": run_id,
        "injected": injected,
        "adapter": AdapterClass.VERDICT,
        "r": r,
        "principal_id": principal_id,
        "arrived_at": _EPOCH_STARTED,
        "outcome_summary": "workflow completed successfully",
        "judge": judge,
        "config": config,
        "epoch": epoch,
        "clock": clock,
    }

    # -- the correct router --
    repo = _fresh_repo(injected)
    before = {mid: repo.current_q(project_id, mid) for mid, _, _ in injected}
    route_end_of_workflow_verdict(repo=repo, **common_kwargs)  # type: ignore[arg-type]
    after = {mid: repo.current_q(project_id, mid) for mid, _, _ in injected}

    workflow_memories_moved = sum(1 for mid in workflow_ids if after[mid] != before[mid])
    other_memories_untouched = all(after[mid] == before[mid] for mid in other_ids)
    touched_only_workflow_scope = set(repo.apply_calls) <= workflow_ids

    # -- the deliberately wrong router, over a SEPARATE, identically-seeded store, so it
    # cannot be affected by (or affect) the correct router's run above --
    broken_repo = _fresh_repo(injected)
    broken_before = {mid: broken_repo.current_q(project_id, mid) for mid, _, _ in injected}
    _route_ignoring_scope(repo=broken_repo, **common_kwargs)  # type: ignore[arg-type]
    broken_after = {mid: broken_repo.current_q(project_id, mid) for mid, _, _ in injected}
    broken_other_untouched = all(broken_after[mid] == broken_before[mid] for mid in other_ids)
    broken_variant_caught = not broken_other_untouched

    return WorkflowScopeReport(
        n_workflow_memories=len(workflow_ids),
        n_other_memories=len(other_ids),
        workflow_memories_moved=workflow_memories_moved,
        other_memories_untouched=other_memories_untouched,
        touched_only_workflow_scope=touched_only_workflow_scope,
        broken_variant_caught=broken_variant_caught,
    )


def render_text(report: WorkflowScopeReport) -> str:
    lines = [
        f"workflow-template-scoped memories injected: {report.n_workflow_memories}",
        f"other-scoped memories injected (agent_type / user / project_shared): {report.n_other_memories}",
        f"workflow-scoped memories whose Q moved: {report.workflow_memories_moved} "
        f"/ {report.n_workflow_memories} (expect all of them)",
        f"every other-scoped memory's q_value byte-identical before vs. after: "
        f"{report.other_memories_untouched} (expect True)",
        f"apply_q_update touched only the workflow-template scope: "
        f"{report.touched_only_workflow_scope} (expect True)",
        f"negative control: the deliberately wrong (scope-ignoring) router was caught "
        f"leaking into other scopes: {report.broken_variant_caught} (expect True -- "
        "proves this check is not vacuous)",
        f"overall: {'PASS' if report.ok else 'FAIL'}",
    ]
    return "\n".join(lines)
