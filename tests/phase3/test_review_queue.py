"""`workers.review_queue` — the five human-actionable reason kinds (PLAN.md §7 Phase 3).

Fully offline: `_FakeRepo` records every `insert_review_item` call so these tests assert
directly on the reason text (must name the memory/key and the numbers involved -- "a
reason a human can act on, not an error code", this chunk's task description) and on
whether an item was opened at all.
"""

from __future__ import annotations

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
from tracebed.domain.enums import MemType, ProvenanceClass, TrustTier
from tracebed.domain.errors import GuardNotSatisfied, IllegalTransition
from tracebed.domain.ids import AgentTypeId, MemoryId, ProjectId, RunId
from tracebed.domain.state_machine import (
    Status,
    TransitionEvidence,
    TransitionLimits,
    apply,
)
from tracebed.workers.derived_state import ClampAlert, DivergenceAlarm
from tracebed.workers.review_queue import (
    _ROUTE_TO_REVIEW_MARKER,
    MAX_REASON_CHARS,
    RetirementCandidate,
    ReviewQueue,
)

pytestmark = pytest.mark.phase3

PROJECT = ProjectId(uuid4())
AGENT_TYPE = AgentTypeId(uuid4())
EPOCH = datetime(2026, 1, 1, tzinfo=UTC)


def _effective_config(**overrides: object) -> EffectiveConfig:
    sections: dict[str, object] = {
        "retrieval": RetrievalConfig(),
        "abstention": AbstentionConfig(),
        "score": ScoreConfig(),
        "budget": BudgetConfig(),
        "scoring": ScoringConfig(),
        "promotion": PromotionConfig(),
        "retirement": RetirementConfig(),
        "lifecycle": LifecycleConfig(),
        "derived": DerivedConfig(),
        "proposals": ProposalConfig(),
        "tier_a": TierAConfig(),
        "killswitch": KillswitchConfig(),
        "spend": SpendConfig(),
        "cache": CacheConfig(),
        "session": SessionConfig(),
        "queue": QueueConfig(),
    }
    sections.update(overrides)
    return EffectiveConfig(**sections)


def _mid() -> MemoryId:
    return MemoryId(uuid4())


class _FakeReviewRepo:
    def __init__(self) -> None:
        self.calls: list[tuple[ProjectId, str, MemoryId | None]] = []

    def insert_review_item(
        self, project_id: ProjectId, reason: str, memory_id: MemoryId | None = None
    ) -> None:
        self.calls.append((project_id, reason, memory_id))


# --------------------------------------------------------------------------- #
# 1. scan rejections
# --------------------------------------------------------------------------- #


def test_flag_scan_rejection_writes_a_human_actionable_reason() -> None:
    repo = _FakeReviewRepo()
    queue = ReviewQueue(repo, FakeClock(EPOCH))
    memory_id = _mid()

    queue.flag_scan_rejection(
        PROJECT,
        reasons=("injection:imperative", "secret:aws-key"),
        memory_id=memory_id,
        mem_type=MemType.LESSON,
    )

    assert len(repo.calls) == 1
    project_id, reason, mid = repo.calls[0]
    assert project_id == PROJECT
    assert mid == memory_id
    assert "injection:imperative" in reason
    assert "secret:aws-key" in reason
    assert "lesson" in reason


def test_flag_scan_rejection_refuses_an_empty_reason_set() -> None:
    repo = _FakeReviewRepo()
    queue = ReviewQueue(repo, FakeClock(EPOCH))
    with pytest.raises(ValueError, match="at least one"):
        queue.flag_scan_rejection(PROJECT, reasons=())
    assert repo.calls == []


def test_flag_scan_rejection_refuses_reasons_that_are_all_blank() -> None:
    """`if not reasons` let `("",)` through and wrote the literal row "scan rejection: "
    -- a review item with no reason on it at all, which is the thing the empty check
    exists to prevent, while the error message already claimed it meant "non-empty"."""
    repo = _FakeReviewRepo()
    queue = ReviewQueue(repo, FakeClock(EPOCH))
    for blank in ((""), ("", "   "), ("\n",)):
        with pytest.raises(ValueError, match="at least one"):
            queue.flag_scan_rejection(PROJECT, reasons=tuple(blank) if blank else ("",))
    assert repo.calls == []


def test_a_blank_reason_does_not_suppress_the_real_ones_beside_it() -> None:
    """Dropped, not rejected: one empty string from a sub-scan must not swallow the real
    findings in the same tuple."""
    repo = _FakeReviewRepo()
    queue = ReviewQueue(repo, FakeClock(EPOCH))

    queue.flag_scan_rejection(PROJECT, reasons=("", "secret:aws-key", "  "))

    assert len(repo.calls) == 1
    _pid, reason, _memory_id = repo.calls[0]
    assert "secret:aws-key" in reason
    assert not reason.endswith(": ")
    assert "; ;" not in reason


# --------------------------------------------------------------------------- #
# 2. open contradictions
# --------------------------------------------------------------------------- #


def test_flag_open_contradiction_names_both_memories() -> None:
    repo = _FakeReviewRepo()
    queue = ReviewQueue(repo, FakeClock(EPOCH))
    a, b = _mid(), _mid()

    queue.flag_open_contradiction(PROJECT, a, contradicting_memory_id=b, note="same subject_tag")

    assert len(repo.calls) == 1
    _, reason, mid = repo.calls[0]
    assert mid == a
    assert str(a) in reason
    assert str(b) in reason
    assert "same subject_tag" in reason


# --------------------------------------------------------------------------- #
# 3. K-1 retirement candidates
# --------------------------------------------------------------------------- #


def _candidate(
    *,
    q_value: float,
    scored_use_count: int,
    distinct_scoring_principals: int,
    status: Status = Status.VALIDATED,
) -> RetirementCandidate:
    return RetirementCandidate(
        memory_id=_mid(),
        status=status,
        provenance_class=ProvenanceClass.DISTILLER,
        trust_tier=TrustTier.B,
        mem_type=MemType.LESSON,
        status_changed_at=EPOCH,
        q_value=q_value,
        scored_use_count=scored_use_count,
        distinct_scoring_principals=distinct_scoring_principals,
    )


def test_retirement_candidate_requires_the_rows_own_validated_status() -> None:
    """A non-validated row is not a retirement candidate at all; `apply()` refuses the
    edge outright rather than this module silently deciding the row is "not due"."""
    repo = _FakeReviewRepo()
    queue = ReviewQueue(repo, FakeClock(EPOCH))
    cfg = _effective_config()
    candidate = _candidate(
        q_value=0.10,
        scored_use_count=5,
        distinct_scoring_principals=2,
        status=Status.QUARANTINED,
    )
    with pytest.raises(IllegalTransition):
        queue.flag_retirement_candidate(PROJECT, candidate, cfg=cfg)
    assert repo.calls == []


def test_retirement_candidate_below_k_principals_opens_a_review_item() -> None:
    repo = _FakeReviewRepo()
    queue = ReviewQueue(repo, FakeClock(EPOCH))
    cfg = _effective_config()  # retirement: q_threshold=0.25, min_scored_uses=4, K=3
    candidate = _candidate(q_value=0.10, scored_use_count=5, distinct_scoring_principals=2)

    flagged = queue.flag_retirement_candidate(PROJECT, candidate, cfg=cfg)

    assert flagged is True
    assert len(repo.calls) == 1
    _, reason, mid = repo.calls[0]
    assert mid == candidate.memory_id
    assert "0.100" in reason
    assert "2 distinct scoring principal" in reason
    assert "K=3" in reason


def test_retirement_candidate_at_k_principals_is_not_flagged() -> None:
    """Meeting every threshold, including K, means `apply()` succeeds outright — this is
    real auto-retirement, not a review-queue case, so nothing is opened."""
    repo = _FakeReviewRepo()
    queue = ReviewQueue(repo, FakeClock(EPOCH))
    cfg = _effective_config()
    candidate = _candidate(q_value=0.10, scored_use_count=5, distinct_scoring_principals=3)

    flagged = queue.flag_retirement_candidate(PROJECT, candidate, cfg=cfg)

    assert flagged is False
    assert repo.calls == []


def test_retirement_candidate_not_due_for_any_other_reason_is_not_flagged() -> None:
    """Q has not dropped far enough yet — refused for a DIFFERENT reason than the
    K-distinct-principals branch, so this must not be treated as a retirement candidate."""
    repo = _FakeReviewRepo()
    queue = ReviewQueue(repo, FakeClock(EPOCH))
    cfg = _effective_config()
    candidate = _candidate(q_value=0.90, scored_use_count=5, distinct_scoring_principals=1)

    flagged = queue.flag_retirement_candidate(PROJECT, candidate, cfg=cfg)

    assert flagged is False
    assert repo.calls == []


def test_retirement_candidate_not_enough_scored_uses_is_not_flagged() -> None:
    repo = _FakeReviewRepo()
    queue = ReviewQueue(repo, FakeClock(EPOCH))
    cfg = _effective_config()
    candidate = _candidate(q_value=0.10, scored_use_count=1, distinct_scoring_principals=1)

    flagged = queue.flag_retirement_candidate(PROJECT, candidate, cfg=cfg)

    assert flagged is False
    assert repo.calls == []


def test_the_route_to_review_marker_is_really_what_the_guard_says() -> None:
    """`flag_retirement_candidate` distinguishes "route to review" from "not due" by
    substring-matching the guard's reason — the only signal the machine offers (see
    `state_machine.GuardOutcome`'s contract-gap note). If `state_machine` rewords that
    branch, K-1 retirement candidates stop being flagged SILENTLY (the method just returns
    False). This test fails loudly at the coupling point instead."""
    limits = TransitionLimits(
        quarantine_ttl_days=30,
        candidate_ttl_days=45,
        promote_min_outcomes=2,
        failure_lesson_outcomes=1,
        promotion_min_distinct_principals=2,
        retire_q_threshold=0.25,
        retire_min_scored_uses=4,
        retire_min_distinct_principals=3,
        archive_floor=0.15,
    )
    evidence = TransitionEvidence(
        now=EPOCH,
        provenance_class=ProvenanceClass.DISTILLER,
        trust_tier=TrustTier.B,
        mem_type=MemType.LESSON,
        status_changed_at=EPOCH,
        q_value=0.10,
        scored_use_count=5,
        distinct_scoring_principals=2,
    )
    with pytest.raises(GuardNotSatisfied) as exc_info:
        apply(Status.VALIDATED, Status.RETIRED, evidence, limits)
    assert _ROUTE_TO_REVIEW_MARKER in exc_info.value.reason


def test_a_caller_supplied_reason_cannot_grow_the_review_row_without_bound() -> None:
    """`review_queue.reason` is unbounded `text` and `reasons`/`note` are caller-supplied;
    `core.scans._dedupe` makes exactly this argument for its own side. A review row a
    human cannot read is a review row that does not get actioned."""
    repo = _FakeReviewRepo()
    queue = ReviewQueue(repo, FakeClock(EPOCH))

    queue.flag_scan_rejection(PROJECT, reasons=("x" * 50_000,))
    queue.flag_open_contradiction(PROJECT, _mid(), contradicting_memory_id=_mid(), note="y" * 50_000)

    for _pid, reason, _memory_id in repo.calls:
        assert len(reason) <= MAX_REASON_CHARS
        assert reason.endswith("[truncated]")


# --------------------------------------------------------------------------- #
# 4/5. derived-state watchdogs
# --------------------------------------------------------------------------- #


def test_flag_clamp_binding_names_the_key_and_streak() -> None:
    repo = _FakeReviewRepo()
    queue = ReviewQueue(repo, FakeClock(EPOCH))
    alert = ClampAlert(
        project_id=PROJECT, agent_type_id=AGENT_TYPE, key="latency_p50", consecutive_clamps=3
    )

    queue.flag_clamp_binding(PROJECT, alert)

    assert len(repo.calls) == 1
    _, reason, mid = repo.calls[0]
    assert mid is None
    assert "latency_p50" in reason
    assert "3 consecutive" in reason


def test_flag_divergence_alarm_names_the_key_and_percentage() -> None:
    repo = _FakeReviewRepo()
    queue = ReviewQueue(repo, FakeClock(EPOCH))
    alarm = DivergenceAlarm(
        project_id=PROJECT,
        agent_type_id=AGENT_TYPE,
        key="error_rate",
        slow_reference=10.0,
        fast_reference=15.0,
        current_value=15.0,
        slow_age=EPOCH - EPOCH,
        divergence_pct=50.0,
    )

    queue.flag_divergence_alarm(PROJECT, alarm)

    assert len(repo.calls) == 1
    _, reason, mid = repo.calls[0]
    assert mid is None
    assert "error_rate" in reason
    assert "50.0%" in reason


# --------------------------------------------------------------------------- #
# Recall & Rollback support (composed by workers.forensics)
# --------------------------------------------------------------------------- #


def test_flag_reopened_outcome_names_run_event_and_memory() -> None:
    repo = _FakeReviewRepo()
    queue = ReviewQueue(repo, FakeClock(EPOCH))
    memory_id = _mid()
    run_id = RunId(uuid4())
    event_id = uuid4()

    queue.flag_reopened_outcome(PROJECT, memory_id=memory_id, run_id=run_id, event_id=event_id)

    assert len(repo.calls) == 1
    _, reason, mid = repo.calls[0]
    assert mid == memory_id
    assert str(run_id) in reason
    assert str(event_id) in reason


def test_flag_descendant_of_quarantined_names_both_memories() -> None:
    repo = _FakeReviewRepo()
    queue = ReviewQueue(repo, FakeClock(EPOCH))
    source, descendant = _mid(), _mid()

    queue.flag_descendant_of_quarantined(
        PROJECT, descendant_memory_id=descendant, source_memory_id=source
    )

    assert len(repo.calls) == 1
    _, reason, mid = repo.calls[0]
    assert mid == descendant
    assert str(source) in reason
    assert str(descendant) in reason
