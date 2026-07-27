"""The Phase 3 gate's guessed-reward drill (PLAN.md section 7 Phase 3):

    "guessed-reward test green (w=0 short-circuits; ambiguous -> zero
    mutations; downstream success moves Q up)."

and section 2 invariant 8's own test description:

    "Guessed-reward test: implicit-behavior and ambiguous fixtures produce
    ZERO Q mutations (assert row-level equality before/after); a successful
    downstream event (r=1, w=0.3) must move Q UP. Include a test that pins
    the formula shape itself, so a future refactor back to the broken
    version is caught."

Driven end to end through the REAL production seams, never a
re-implementation of either: `adapters.feedback.base.dispatch_feedback` (the
edge invariant 8 lives at -- caller-scoring-input guard, w resolution from
the AUTHENTICATED adapter class, `AmbiguousSignal`/`NoSignal` absorption, the
w<=0 short-circuit) feeding a fake `ScorerPort` that records every call it
receives, and `workers.scorer.run_scorer_batch` (the corrected Q arithmetic
itself, `Q <- clamp01(Q + alpha*w*c*(r-Q))`) against a fake `ScorerRepoPort`
that tracks row-level state before and after.

`_broken_spec_formula` is the ORIGINAL spec bug (DECISIONS D-011): it feeds
the adapter weight in as the reward. It exists ONLY as a comparison point --
nothing in this codebase calls it -- so `test_formula_shape_is_pinned`-style
comparison in `run_guessed_reward_drill` fails loudly the moment a future
refactor makes `workers.scorer.compute_new_q` collapse back onto it.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from uuid import UUID, uuid4

from tracebed.adapters.feedback.base import (
    dispatch_feedback,
)
from tracebed.adapters.feedback.downstream import DownstreamAdapter
from tracebed.adapters.feedback.implicit import ImplicitAdapter
from tracebed.domain.enums import AdapterClass
from tracebed.domain.errors import CrossEpochComparison
from tracebed.domain.ids import (
    MemoryId,
    PrincipalId,
    ProjectId,
    RunId,
    mint_memory_id,
    mint_run_id,
)
from tracebed.workers.contribution_judge import ContributionVerdict
from tracebed.workers.epochs import ScoringEpoch, assert_same_epoch
from tracebed.workers.scorer import (
    QUpdate,
    ScoreBatchResult,
    ScoringEvent,
    compute_new_q,
    run_scorer_batch,
)

__all__ = [
    "GuessedRewardReport",
    "render_text",
    "run_guessed_reward_drill",
]

_NOW: datetime = datetime(2026, 7, 26, 12, 0, tzinfo=UTC)
_PROJECT = ProjectId(uuid4())
_EPOCH = ScoringEpoch(
    epoch_id=1,
    judge_model_id="gemini-3.1-pro",
    judge_model_version="2026-07-01",
    sampling_params={"temperature": 0.0, "max_tokens": 8},
    prompt_hash="a" * 64,
    started_at=_NOW,
)
_OTHER_EPOCH = ScoringEpoch(
    epoch_id=2,
    judge_model_id="gemini-4.0-pro",
    judge_model_version="2026-08-01",
    sampling_params={"temperature": 0.0, "max_tokens": 8},
    prompt_hash="b" * 64,
    started_at=_NOW,
)


def _broken_spec_formula(*, current_q: float, w: float, c: float, alpha: float) -> float:
    """The ORIGINAL spec bug, verbatim (DECISIONS D-011): the adapter TRUST
    WEIGHT is fed in as the reward `r`. Exists only so `run_guessed_reward_drill`
    can show it disagrees with the real formula on the exact scenario the gate
    names -- a successful downstream event, w=0.3. From Q=0.5 this computes
    `r - Q = 0.3 - 0.5 = -0.2` and LOWERS the score: the update punishes
    success. Never called from anything but this module.
    """
    r_as_weight = w  # the bug: what should be a separate polarity is the weight
    return max(0.0, min(1.0, current_q + alpha * w * c * (r_as_weight - current_q)))


class _FakeScorerRepo:
    """`ScorerRepoPort`, tracking every mutating call for row-level
    before/after equality assertions (invariant 8's own wording)."""

    def __init__(self, *, project_id: ProjectId, memory_id: MemoryId, initial_q: float) -> None:
        self._project_id = project_id
        self._memory_id = memory_id
        self.q = initial_q
        self._applied_ids: set[UUID] = set()
        self._updates_by_day: dict[date, int] = {}
        self.apply_calls: list[QUpdate] = []

    def current_q(self, project_id: ProjectId, memory_id: MemoryId) -> float:
        return self.q

    def applied_event_ids(self, project_id: ProjectId, memory_id: MemoryId) -> set[UUID]:
        return set(self._applied_ids)

    def scored_updates_today(self, project_id: ProjectId, memory_id: MemoryId, day: date) -> int:
        return self._updates_by_day.get(day, 0)

    def apply_q_update(self, project_id: ProjectId, update: QUpdate) -> None:
        self.apply_calls.append(update)
        self._applied_ids.add(update.event_id)
        self.q = update.new_q
        day = update.scored_at.date()
        self._updates_by_day[day] = self._updates_by_day.get(day, 0) + 1


@dataclass
class _FakeJudge:
    factor: float = 1.0
    epoch_id: int = _EPOCH.epoch_id
    calls: int = 0

    def judge(self, *, memory_content: str, outcome_summary: str) -> ContributionVerdict:
        self.calls += 1
        return ContributionVerdict(factor=self.factor, epoch_id=self.epoch_id)


@dataclass
class _RecordingScorer:
    """`ScorerPort` -- records every `record_outcome` call verbatim so a test
    can assert row-level equality (nothing recorded == nothing mutated) or
    replay the exact `(r, w)` pair into `run_scorer_batch` for the worker-level
    half of the drill."""

    calls: list[dict[str, object]] = field(default_factory=list)

    def record_outcome(
        self,
        project_id: ProjectId,
        run_id: RunId,
        *,
        principal_id: PrincipalId,
        adapter: AdapterClass,
        r: float,
        w: float,
        event_id: UUID,
        occurred_at: datetime,
    ) -> None:
        self.calls.append(
            {
                "project_id": project_id,
                "run_id": run_id,
                "principal_id": principal_id,
                "adapter": adapter,
                "r": r,
                "w": w,
                "event_id": event_id,
                "occurred_at": occurred_at,
            }
        )


@dataclass
class _RecordingSink:
    """`AmbiguousSignalSink` -- records every ambiguous/short-circuited signal
    so "logged, never scored" is an assertion, not an assumption."""

    logged: list[dict[str, object]] = field(default_factory=list)

    def log_ambiguous(
        self,
        project_id: ProjectId,
        run_id: RunId,
        *,
        adapter: AdapterClass,
        reason: str,
        payload: object,
    ) -> None:
        self.logged.append({"project_id": project_id, "run_id": run_id, "adapter": adapter, "reason": reason})


@dataclass(frozen=True, slots=True)
class GuessedRewardReport:
    formula_shape_pinned_ok: bool
    """The corrected formula and the original spec bug diverge on the exact
    scenario D-011 names (a successful downstream event): corrected moves Q
    UP, the bug moves it DOWN. A refactor that collapses the two fails this."""
    correct_q_after: float
    broken_spec_q_after: float

    w_zero_short_circuit_ok: bool
    """implicit (w=0.0) produces NO scorer call at all -- not a call with
    r/w=0 that would still spend the memory's one daily update slot."""

    ambiguous_zero_mutations_ok: bool
    """A downstream signal with no recognisable polarity token raises
    `AmbiguousSignal` inside `to_outcome`; `dispatch_feedback` absorbs it,
    logs it, and the scorer is never called -- row-level equality before and
    after."""

    downstream_success_moves_q_up_ok: bool
    """r=1 (positive outcome), w=0.3 (downstream) drives Q from 0.5 to a
    STRICTLY higher value, both through `dispatch_feedback` (edge) and
    `run_scorer_batch` (worker arithmetic)."""
    q_before: float
    q_after: float

    cross_epoch_rejected_ok: bool
    """A contribution verdict judged under one `scoring_epoch` must never be
    let move Q under a batch resolved for a different one --
    `workers.epochs.assert_same_epoch` (which `run_scorer_batch` calls) raises
    `CrossEpochComparison` rather than silently averaging two rulers."""

    @property
    def ok(self) -> bool:
        return (
            self.formula_shape_pinned_ok
            and self.w_zero_short_circuit_ok
            and self.ambiguous_zero_mutations_ok
            and self.downstream_success_moves_q_up_ok
            and self.cross_epoch_rejected_ok
        )


def _pin_formula_shape() -> tuple[bool, float, float]:
    correct = compute_new_q(current_q=0.5, r=1.0, w=0.3, c=1.0, alpha=0.3)
    broken = _broken_spec_formula(current_q=0.5, w=0.3, c=1.0, alpha=0.3)
    assert correct is not None
    ok = correct > 0.5 and broken < 0.5
    return ok, correct, broken


def _w_zero_short_circuit() -> bool:
    """implicit (w=0.0): `dispatch_feedback` must call the scorer ZERO times.

    Uses the REAL `ImplicitAdapter` (w=0.0 by default,
    `scoring.adapter_weights["implicit"]`) rather than a bespoke fake -- the
    short-circuit is a property of `dispatch_feedback`'s weight resolution,
    not of anything this adapter itself does.
    """
    scorer = _RecordingScorer()
    sink = _RecordingSink()

    dispatch_feedback(
        {"event_id": str(uuid4()), "outcome": "positive"},
        project_id=_PROJECT,
        run_id=mint_run_id(),
        principal_id=PrincipalId(uuid4()),
        adapter=ImplicitAdapter(),
        registered_class=AdapterClass.IMPLICIT,
        weights={"implicit": 0.0, "downstream": 0.3, "verdict": 1.0, "correction_adapter": 0.8},
        scorer=scorer,
        sink=sink,
        clock=_FrozenClock(),
    )
    return len(scorer.calls) == 0 and len(sink.logged) == 1


def _ambiguous_zero_mutations() -> bool:
    """A downstream signal with no recognisable polarity anywhere -- resolves
    to `AmbiguousSignal` inside `DownstreamAdapter.to_outcome`, absorbed by
    `dispatch_feedback`, zero scorer calls."""
    scorer = _RecordingScorer()
    sink = _RecordingSink()
    adapter = DownstreamAdapter()

    dispatch_feedback(
        {"event_id": str(uuid4()), "outcome": "maybe? unclear from the payload"},
        project_id=_PROJECT,
        run_id=mint_run_id(),
        principal_id=PrincipalId(uuid4()),
        adapter=adapter,
        registered_class=AdapterClass.DOWNSTREAM,
        weights={"downstream": 0.3},
        scorer=scorer,
        sink=sink,
        clock=_FrozenClock(),
    )
    return len(scorer.calls) == 0 and len(sink.logged) == 1


class _FrozenClock:
    """Structurally satisfies `domain.clock.Clock`; only `now()` is exercised
    by anything this module calls, but all three protocol members are
    implemented so the fake is a genuine `Clock`, not merely a `now()`-shaped
    stand-in."""

    def now(self) -> datetime:
        return _NOW

    def now_ms(self) -> int:
        return int(_NOW.timestamp() * 1000)

    def monotonic_ms(self) -> float:
        return 0.0


def _downstream_success_moves_q_up() -> tuple[bool, float, float]:
    """Full stack: `dispatch_feedback` (edge) resolves r=1.0, w=0.3 for a
    genuine downstream-success signal; the recorded call is then replayed
    into `run_scorer_batch` (worker), which applies the corrected formula."""
    scorer = _RecordingScorer()
    sink = _RecordingSink()
    adapter = DownstreamAdapter()
    memory_id = mint_memory_id()
    run_id = mint_run_id()
    principal_id = PrincipalId(uuid4())

    dispatch_feedback(
        {"event_id": str(uuid4()), "outcome": "success"},
        project_id=_PROJECT,
        run_id=run_id,
        principal_id=principal_id,
        adapter=adapter,
        registered_class=AdapterClass.DOWNSTREAM,
        weights={"downstream": 0.3},
        scorer=scorer,
        sink=sink,
        clock=_FrozenClock(),
    )
    assert len(scorer.calls) == 1
    call = scorer.calls[0]
    assert call["r"] == 1.0
    assert call["w"] == 0.3

    repo = _FakeScorerRepo(project_id=_PROJECT, memory_id=memory_id, initial_q=0.5)
    judge = _FakeJudge(factor=1.0)
    event = ScoringEvent(
        event_id=call["event_id"],  # type: ignore[arg-type]
        run_id=run_id,
        memory_id=memory_id,
        adapter=AdapterClass.DOWNSTREAM,
        r=call["r"],
        principal_id=principal_id,
        arrived_at=_NOW,
        outcome_summary="the downstream pipeline reported success",
    )
    from tracebed.domain.clock import FakeClock
    from tracebed.domain.config import ScoringConfig

    result: ScoreBatchResult = run_scorer_batch(
        project_id=_PROJECT,
        memory_id=memory_id,
        memory_content="tool X times out after 30s under load",
        candidates=[event],
        repo=repo,
        judge=judge,
        config=ScoringConfig(),
        epoch=_EPOCH,
        clock=FakeClock(_NOW),
    )
    ok = len(result.applied) == 1 and result.applied[0].new_q > 0.5 and repo.q > 0.5
    return ok, 0.5, repo.q


def _cross_epoch_rejected() -> bool:
    """A `ContributionVerdict` stamped with `_OTHER_EPOCH` must never be let
    move Q under a batch resolved for `_EPOCH` -- `assert_same_epoch` (which
    `run_scorer_batch` calls before touching the repo) must raise, and the
    repo must show NOTHING applied."""
    memory_id = mint_memory_id()
    repo = _FakeScorerRepo(project_id=_PROJECT, memory_id=memory_id, initial_q=0.5)
    judge = _FakeJudge(factor=1.0, epoch_id=_OTHER_EPOCH.epoch_id)
    event = ScoringEvent(
        event_id=uuid4(),
        run_id=mint_run_id(),
        memory_id=memory_id,
        adapter=AdapterClass.DOWNSTREAM,
        r=1.0,
        principal_id=PrincipalId(uuid4()),
        arrived_at=_NOW,
        outcome_summary="ok",
    )
    from tracebed.domain.clock import FakeClock
    from tracebed.domain.config import ScoringConfig

    raised = False
    try:
        run_scorer_batch(
            project_id=_PROJECT,
            memory_id=memory_id,
            memory_content="content",
            candidates=[event],
            repo=repo,
            judge=judge,
            config=ScoringConfig(),
            epoch=_EPOCH,
            clock=FakeClock(_NOW),
        )
    except CrossEpochComparison:
        raised = True

    # A second, narrower check directly against the primitive both the
    # scorer and the shadow validator share, so a future caller that stops
    # routing through run_scorer_batch cannot silently lose this.
    try:
        assert_same_epoch(_EPOCH, _OTHER_EPOCH)
        primitive_raised = False
    except CrossEpochComparison:
        primitive_raised = True

    return raised and primitive_raised and repo.apply_calls == []


def run_guessed_reward_drill() -> GuessedRewardReport:
    formula_ok, correct_q, broken_q = _pin_formula_shape()
    w_zero_ok = _w_zero_short_circuit()
    ambiguous_ok = _ambiguous_zero_mutations()
    downstream_ok, q_before, q_after = _downstream_success_moves_q_up()
    cross_epoch_ok = _cross_epoch_rejected()

    return GuessedRewardReport(
        formula_shape_pinned_ok=formula_ok,
        correct_q_after=correct_q,
        broken_spec_q_after=broken_q,
        w_zero_short_circuit_ok=w_zero_ok,
        ambiguous_zero_mutations_ok=ambiguous_ok,
        downstream_success_moves_q_up_ok=downstream_ok,
        q_before=q_before,
        q_after=q_after,
        cross_epoch_rejected_ok=cross_epoch_ok,
    )


def render_text(report: GuessedRewardReport) -> str:
    lines = [
        f"formula shape pinned: {'PASS' if report.formula_shape_pinned_ok else 'FAIL'} "
        f"(corrected formula -> {report.correct_q_after:.4f} [up], "
        f"original spec bug -> {report.broken_spec_q_after:.4f} [down])",
        f"w=0 short-circuit: {'PASS' if report.w_zero_short_circuit_ok else 'FAIL'} "
        "(implicit adapter never reaches the scorer)",
        f"ambiguous -> zero mutations: {'PASS' if report.ambiguous_zero_mutations_ok else 'FAIL'} "
        "(unrecognised polarity never reaches the scorer)",
        f"downstream success moves Q up: {'PASS' if report.downstream_success_moves_q_up_ok else 'FAIL'} "
        f"(Q: {report.q_before:.4f} -> {report.q_after:.4f})",
        f"cross-epoch Q comparison rejected: {'PASS' if report.cross_epoch_rejected_ok else 'FAIL'}",
        f"overall: {'PASS' if report.ok else 'FAIL'}",
    ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args(argv)
    report = run_guessed_reward_drill()
    print(render_text(report))
    return 0 if report.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
