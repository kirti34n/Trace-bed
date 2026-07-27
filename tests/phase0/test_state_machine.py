"""Table-driven tests for the one memory state machine (PHASE-0 Task 4).

Proves invariant 7: shadow confirmation needs distinct runs AND distinct
principals AND distinct input-signature clusters (not any one of them);
`propose_memory` never satisfies any skip; every legal edge in PLAN.md §5
accepts satisfying evidence and rejects deficient evidence; every pair NOT in
the table is illegal, generated as the exhaustive product over
(Status | None) x Status rather than hand-listed; and no config override can
lower a threshold below what PLAN.md §5 states ("no admin bypass in code").

Every guard is additionally proved to reject an all-defaults `TransitionEvidence`
-- the single test that would go red if any guard were replaced by a
`return GuardOutcome(True, "")` placeholder.
"""

from __future__ import annotations

import dataclasses
import hashlib
import time
from datetime import UTC, datetime, timedelta, timezone
from uuid import uuid4

import pytest

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
from tracebed.domain.errors import ConfigError, GuardNotSatisfied, IllegalTransition
from tracebed.domain.ids import PrincipalId, RunId
from tracebed.domain.signatures import SAME_CLUSTER_MAX_HAMMING, SIG_HASH_LEN, hamming
from tracebed.domain.state_machine import (
    LEGAL_CREATION_STATUSES,
    MAX_CONFIRMATIONS_CONSIDERED,
    RETRIEVABLE_STATUSES,
    TRANSITIONS,
    GuardOutcome,
    ShadowConfirmation,
    Status,
    TransitionEvidence,
    TransitionLimits,
    apply,
    assert_legal_creation_status,
    independent_confirmations,
)

pytestmark = pytest.mark.phase0

# --------------------------------------------------------------------------- #
# Fixtures / helpers
# --------------------------------------------------------------------------- #

BASE_NOW: datetime = datetime(2026, 1, 1, tzinfo=UTC)

LIMITS = TransitionLimits(
    quarantine_ttl_days=30,
    candidate_ttl_days=45,
    promote_min_outcomes=2,
    failure_lesson_outcomes=1,
    promotion_min_distinct_principals=2,
    retire_q_threshold=0.25,
    retire_min_scored_uses=4,
    retire_min_distinct_principals=3,  # K, per D-021
    archive_floor=0.15,
)

# Trailing-8-byte cluster tags (domain/signatures.py's `same_cluster` compares
# only the trailing 8 simhash bytes of a SIG_HASH_LEN signature; the leading
# 32 bytes are irrelevant to clustering, so a fixed zero prefix is sufficient
# and keeps every signature at the correct length regardless of the real
# `input_signature_hash` implementation). Pairwise Hamming distances are 64
# (A-B), 32 (A-C), 32 (B-C) -- all far above SAME_CLUSTER_MAX_HAMMING=8, so
# the three tags are three genuinely different clusters.
_CLUSTER_A = b"\x00" * 8
_CLUSTER_B = b"\xff" * 8
_CLUSTER_C = b"\x0f" * 8


def _sig(cluster_tail: bytes) -> bytes:
    return (b"\x00" * (SIG_HASH_LEN - 8)) + cluster_tail


def _run_id() -> RunId:
    return RunId(uuid4())


def _principal_id() -> PrincipalId:
    return PrincipalId(uuid4())


def _confirmation(
    principal: PrincipalId, cluster_tail: bytes, run: RunId | None = None
) -> ShadowConfirmation:
    return ShadowConfirmation(
        run_id=run if run is not None else _run_id(),
        principal_id=principal,
        input_signature_hash=_sig(cluster_tail),
    )


def _evidence(**overrides: object) -> TransitionEvidence:
    """A `TransitionEvidence` with every optional field at its "obviously
    deficient" default; each test overrides exactly the fields its guard
    inspects. `provenance_class`/`trust_tier`/`mem_type` are required
    positional-ish fields so they get a harmless default here too."""
    base = TransitionEvidence(
        now=BASE_NOW,
        provenance_class=ProvenanceClass.DISTILLER,
        trust_tier=TrustTier.B,
        mem_type=MemType.SEMANTIC,
    )
    return dataclasses.replace(base, **overrides)  # type: ignore[arg-type]


_MINIMAL_EVIDENCE = _evidence()

# Everything a caller could possibly assert, all at once. Used to prove that
# table membership is checked BEFORE any guard runs: no strength of evidence
# may conjure an edge PLAN.md §5 does not contain.
_MAXIMAL_EVIDENCE = TransitionEvidence(
    now=BASE_NOW,
    provenance_class=ProvenanceClass.OPERATOR,
    trust_tier=TrustTier.A,
    mem_type=MemType.PREFERENCE,
    is_failure_lesson=True,
    scan_passed=True,
    scan_repass=True,
    provenance_complete=True,
    status_changed_at=BASE_NOW - timedelta(days=3650),
    confirmations=(
        _confirmation(_principal_id(), _CLUSTER_A),
        _confirmation(_principal_id(), _CLUSTER_B),
        _confirmation(_principal_id(), _CLUSTER_C),
    ),
    has_verified_human_verdict=True,
    promotion_outcomes=999,
    promotion_distinct_principals=999,
    outcome_consistent=True,
    open_contradiction=False,
    contradiction_equal_or_stronger=True,
    contradiction_weaker_provenance=True,
    scan_reflag=True,
    invalidation_event=True,
    ttl_class_expired=True,
    revalidation_failed=True,
    reverified=True,
    strike_count=999,
    q_value=0.0,
    scored_use_count=999,
    distinct_scoring_principals=999,
    decay_floor_reached=True,
    operator_restore=True,
    operator_created=True,
    erasure_or_approved_delete=True,
)

NON_TERMINAL_STATUSES: tuple[Status, ...] = tuple(s for s in Status if s is not Status.TOMBSTONED)


# --------------------------------------------------------------------------- #
# ∅ -> candidate  (PLAN §5 row 1)
# --------------------------------------------------------------------------- #


def test_none_to_candidate_satisfied() -> None:
    evidence = _evidence(
        provenance_class=ProvenanceClass.PARSER,
        trust_tier=TrustTier.A,
        scan_passed=True,
        provenance_complete=True,
    )
    assert apply(None, Status.CANDIDATE, evidence, LIMITS) == Status.CANDIDATE


@pytest.mark.parametrize(
    "overrides",
    [
        {"trust_tier": TrustTier.B},
        {"provenance_class": ProvenanceClass.DISTILLER},
        {"scan_passed": False},
        {"provenance_complete": False},
    ],
)
def test_none_to_candidate_deficient(overrides: dict[str, object]) -> None:
    base = {
        "provenance_class": ProvenanceClass.PARSER,
        "trust_tier": TrustTier.A,
        "scan_passed": True,
        "provenance_complete": True,
    }
    base.update(overrides)
    evidence = _evidence(**base)
    with pytest.raises(GuardNotSatisfied):
        apply(None, Status.CANDIDATE, evidence, LIMITS)


# --------------------------------------------------------------------------- #
# ∅ -> quarantined  (PLAN §5 row 2)
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("provenance_class", [ProvenanceClass.DISTILLER, ProvenanceClass.PROPOSAL])
def test_none_to_quarantined_satisfied(provenance_class: ProvenanceClass) -> None:
    evidence = _evidence(
        trust_tier=TrustTier.B,
        provenance_class=provenance_class,
        scan_passed=True,
        provenance_complete=True,
    )
    assert apply(None, Status.QUARANTINED, evidence, LIMITS) == Status.QUARANTINED


@pytest.mark.parametrize(
    "overrides",
    [
        {"trust_tier": TrustTier.A},
        {"provenance_class": ProvenanceClass.PARSER},
        {"provenance_class": ProvenanceClass.HUMAN_VERDICT},
        {"provenance_class": ProvenanceClass.OPERATOR},
        {"scan_passed": False},
        {"provenance_complete": False},
    ],
)
def test_none_to_quarantined_deficient(overrides: dict[str, object]) -> None:
    base = {
        "trust_tier": TrustTier.B,
        "provenance_class": ProvenanceClass.DISTILLER,
        "scan_passed": True,
        "provenance_complete": True,
    }
    base.update(overrides)
    evidence = _evidence(**base)
    with pytest.raises(GuardNotSatisfied):
        apply(None, Status.QUARANTINED, evidence, LIMITS)


# --------------------------------------------------------------------------- #
# ∅ -> pinned  (PLAN §5 row 3 / D-014)
# --------------------------------------------------------------------------- #


def test_none_to_pinned_satisfied() -> None:
    evidence = _evidence(
        provenance_class=ProvenanceClass.OPERATOR,
        operator_created=True,
        mem_type=MemType.PREFERENCE,
    )
    assert apply(None, Status.PINNED, evidence, LIMITS) == Status.PINNED


@pytest.mark.parametrize(
    "overrides",
    [
        {"operator_created": False},
        {"mem_type": MemType.SEMANTIC},
        {"provenance_class": ProvenanceClass.DISTILLER},
    ],
)
def test_none_to_pinned_deficient(overrides: dict[str, object]) -> None:
    base = {
        "provenance_class": ProvenanceClass.OPERATOR,
        "operator_created": True,
        "mem_type": MemType.PREFERENCE,
    }
    base.update(overrides)
    evidence = _evidence(**base)
    with pytest.raises(GuardNotSatisfied):
        apply(None, Status.PINNED, evidence, LIMITS)


# --------------------------------------------------------------------------- #
# quarantined -> candidate  (PLAN §5 row 4 / D-020 / D-023 — invariant 7's core)
# --------------------------------------------------------------------------- #


def test_quarantined_to_candidate_two_independent_confirmations() -> None:
    p1, p2 = _principal_id(), _principal_id()
    confirmations = (_confirmation(p1, _CLUSTER_A), _confirmation(p2, _CLUSTER_B))
    evidence = _evidence(confirmations=confirmations)
    assert apply(Status.QUARANTINED, Status.CANDIDATE, evidence, LIMITS) == Status.CANDIDATE


def test_quarantined_to_candidate_one_confirmation_rejected() -> None:
    confirmations = (_confirmation(_principal_id(), _CLUSTER_A),)
    evidence = _evidence(confirmations=confirmations)
    with pytest.raises(GuardNotSatisfied):
        apply(Status.QUARANTINED, Status.CANDIDATE, evidence, LIMITS)


def test_quarantined_to_candidate_zero_confirmations_rejected() -> None:
    with pytest.raises(GuardNotSatisfied):
        apply(Status.QUARANTINED, Status.CANDIDATE, _evidence(), LIMITS)


def test_quarantined_to_candidate_same_principal_rejected() -> None:
    """Two runs, one principal: the corroboration is not independent (Sybil bypass)."""
    p1 = _principal_id()
    confirmations = (_confirmation(p1, _CLUSTER_A), _confirmation(p1, _CLUSTER_B))
    evidence = _evidence(confirmations=confirmations)
    with pytest.raises(GuardNotSatisfied):
        apply(Status.QUARANTINED, Status.CANDIDATE, evidence, LIMITS)


def test_quarantined_to_candidate_same_input_signature_cluster_rejected() -> None:
    """Two runs, two principals, but the same input-signature cluster: still not independent."""
    p1, p2 = _principal_id(), _principal_id()
    confirmations = (_confirmation(p1, _CLUSTER_A), _confirmation(p2, _CLUSTER_A))
    evidence = _evidence(confirmations=confirmations)
    with pytest.raises(GuardNotSatisfied):
        apply(Status.QUARANTINED, Status.CANDIDATE, evidence, LIMITS)


def test_quarantined_to_candidate_same_run_rejected() -> None:
    """PLAN §5 row 4 says ">=2 distinct RUNS" as well as distinct principals and
    clusters. One run cannot corroborate itself no matter how the rest of the
    row is filled in, so a confirmation set that names the same run twice must
    count as one -- otherwise a single run replayed into the confirmation set is
    its own second witness."""
    shared_run = _run_id()
    confirmations = (
        _confirmation(_principal_id(), _CLUSTER_A, run=shared_run),
        _confirmation(_principal_id(), _CLUSTER_B, run=shared_run),
    )
    assert independent_confirmations(confirmations) == 1
    evidence = _evidence(confirmations=confirmations)
    with pytest.raises(GuardNotSatisfied):
        apply(Status.QUARANTINED, Status.CANDIDATE, evidence, LIMITS)


def test_quarantined_to_candidate_failure_lesson_needs_only_one() -> None:
    confirmations = (_confirmation(_principal_id(), _CLUSTER_A),)
    evidence = _evidence(
        confirmations=confirmations, is_failure_lesson=True, mem_type=MemType.LESSON
    )
    assert apply(Status.QUARANTINED, Status.CANDIDATE, evidence, LIMITS) == Status.CANDIDATE


@pytest.mark.parametrize(
    "mem_type", [MemType.SEMANTIC, MemType.EPISODIC, MemType.PREFERENCE]
)
def test_failure_lesson_flag_does_not_lower_threshold_for_non_lessons(mem_type: MemType) -> None:
    """PLAN §5 / invariant 7 say "1 run for failure LESSONS". The relaxation is a
    property of the memory type, not of a caller-set boolean: if the flag alone
    sufficed, one `is_failure_lesson=True` would halve the quarantine threshold
    for semantic content -- exactly the class quarantine exists to hold."""
    confirmations = (_confirmation(_principal_id(), _CLUSTER_A),)
    evidence = _evidence(
        confirmations=confirmations, is_failure_lesson=True, mem_type=mem_type
    )
    with pytest.raises(GuardNotSatisfied):
        apply(Status.QUARANTINED, Status.CANDIDATE, evidence, LIMITS)


def test_quarantined_to_candidate_verified_human_verdict_skips_corroboration() -> None:
    evidence = _evidence(
        provenance_class=ProvenanceClass.HUMAN_VERDICT,
        has_verified_human_verdict=True,
    )
    assert apply(Status.QUARANTINED, Status.CANDIDATE, evidence, LIMITS) == Status.CANDIDATE


def test_quarantined_to_candidate_human_verdict_flag_without_matching_class_rejected() -> None:
    evidence = _evidence(
        provenance_class=ProvenanceClass.DISTILLER,
        has_verified_human_verdict=True,
    )
    with pytest.raises(GuardNotSatisfied):
        apply(Status.QUARANTINED, Status.CANDIDATE, evidence, LIMITS)


def test_quarantined_to_candidate_human_verdict_class_without_flag_rejected() -> None:
    """The class alone is not the skip: D-029 makes "verified" mean an
    authenticated verdict actually happened."""
    evidence = _evidence(provenance_class=ProvenanceClass.HUMAN_VERDICT)
    with pytest.raises(GuardNotSatisfied):
        apply(Status.QUARANTINED, Status.CANDIDATE, evidence, LIMITS)


def test_quarantined_to_candidate_proposal_class_never_satisfies_corroboration_skip() -> None:
    """D-023, hard-coded: even maximally-independent confirmations do not help a proposal."""
    p1, p2, p3 = _principal_id(), _principal_id(), _principal_id()
    confirmations = (
        _confirmation(p1, _CLUSTER_A),
        _confirmation(p2, _CLUSTER_B),
        _confirmation(p3, _CLUSTER_C),
    )
    evidence = _evidence(provenance_class=ProvenanceClass.PROPOSAL, confirmations=confirmations)
    with pytest.raises(GuardNotSatisfied):
        apply(Status.QUARANTINED, Status.CANDIDATE, evidence, LIMITS)


def test_quarantined_to_candidate_proposal_class_never_satisfies_human_verdict_skip() -> None:
    """D-023, hard-coded: the human-verdict route is blocked for proposals too, no admin flag."""
    evidence = _evidence(provenance_class=ProvenanceClass.PROPOSAL, has_verified_human_verdict=True)
    with pytest.raises(GuardNotSatisfied):
        apply(Status.QUARANTINED, Status.CANDIDATE, evidence, LIMITS)


def test_quarantined_to_candidate_proposal_class_blocked_even_as_failure_lesson() -> None:
    """The three relaxations do not compose into a fourth: D-023 is checked first."""
    evidence = _evidence(
        provenance_class=ProvenanceClass.PROPOSAL,
        mem_type=MemType.LESSON,
        is_failure_lesson=True,
        has_verified_human_verdict=True,
        confirmations=(_confirmation(_principal_id(), _CLUSTER_A),),
    )
    with pytest.raises(GuardNotSatisfied):
        apply(Status.QUARANTINED, Status.CANDIDATE, evidence, LIMITS)


# --------------------------------------------------------------------------- #
# quarantined -> archived  (PLAN §5 row 5: quarantine TTL)
# --------------------------------------------------------------------------- #


def test_quarantined_to_archived_ttl_reached() -> None:
    evidence = _evidence(status_changed_at=BASE_NOW - timedelta(days=31))
    assert apply(Status.QUARANTINED, Status.ARCHIVED, evidence, LIMITS) == Status.ARCHIVED


def test_quarantined_to_archived_ttl_not_reached() -> None:
    evidence = _evidence(status_changed_at=BASE_NOW - timedelta(days=29))
    with pytest.raises(GuardNotSatisfied):
        apply(Status.QUARANTINED, Status.ARCHIVED, evidence, LIMITS)


def test_quarantined_to_archived_ttl_exact_boundary_is_inclusive() -> None:
    """Pins the comparison direction at the boundary: at exactly the TTL the
    row IS expired (`age >= limit`). One second short is not."""
    evidence = _evidence(status_changed_at=BASE_NOW - timedelta(days=30))
    assert apply(Status.QUARANTINED, Status.ARCHIVED, evidence, LIMITS) == Status.ARCHIVED

    just_short = _evidence(status_changed_at=BASE_NOW - timedelta(days=30) + timedelta(seconds=1))
    with pytest.raises(GuardNotSatisfied):
        apply(Status.QUARANTINED, Status.ARCHIVED, just_short, LIMITS)


def test_quarantined_to_archived_missing_status_changed_at_rejected() -> None:
    evidence = _evidence(status_changed_at=None)
    with pytest.raises(GuardNotSatisfied):
        apply(Status.QUARANTINED, Status.ARCHIVED, evidence, LIMITS)


def test_ttl_guard_rejects_future_status_changed_at() -> None:
    """Clock skew must not archive anything: a negative age is not an expiry."""
    evidence = _evidence(status_changed_at=BASE_NOW + timedelta(days=100))
    with pytest.raises(GuardNotSatisfied):
        apply(Status.QUARANTINED, Status.ARCHIVED, evidence, LIMITS)


def test_ttl_guard_compares_across_timezones_correctly() -> None:
    """`now` and `status_changed_at` may legitimately carry different tzinfo
    (a UTC clock vs a `timestamptz` rendered in the session zone). The
    comparison must be on the instant, not on the wall-clock reading."""
    ist = timezone(timedelta(hours=5, minutes=30))
    # Same instant as BASE_NOW - 30 days, expressed in +05:30.
    changed_at = (BASE_NOW - timedelta(days=30)).astimezone(ist)
    evidence = _evidence(status_changed_at=changed_at)
    assert apply(Status.QUARANTINED, Status.ARCHIVED, evidence, LIMITS) == Status.ARCHIVED


# --------------------------------------------------------------------------- #
# candidate -> validated  (PLAN §5 row 6: promotion predicate)
# --------------------------------------------------------------------------- #


def test_candidate_to_validated_satisfied() -> None:
    evidence = _evidence(
        promotion_outcomes=2,
        promotion_distinct_principals=2,
        outcome_consistent=True,
        scan_repass=True,
        open_contradiction=False,
    )
    assert apply(Status.CANDIDATE, Status.VALIDATED, evidence, LIMITS) == Status.VALIDATED


@pytest.mark.parametrize(
    "overrides",
    [
        {"promotion_outcomes": 1},
        {"promotion_distinct_principals": 1},
        {"outcome_consistent": False},
        {"scan_repass": False},
        {"open_contradiction": True},
    ],
)
def test_candidate_to_validated_deficient(overrides: dict[str, object]) -> None:
    base = {
        "promotion_outcomes": 2,
        "promotion_distinct_principals": 2,
        "outcome_consistent": True,
        "scan_repass": True,
        "open_contradiction": False,
    }
    base.update(overrides)
    evidence = _evidence(**base)
    with pytest.raises(GuardNotSatisfied):
        apply(Status.CANDIDATE, Status.VALIDATED, evidence, LIMITS)


# --------------------------------------------------------------------------- #
# candidate -> quarantined  (PLAN §5 row 7)
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "overrides",
    [
        {"contradiction_weaker_provenance": True},
        {"scan_reflag": True},
    ],
)
def test_candidate_to_quarantined_satisfied(overrides: dict[str, object]) -> None:
    evidence = _evidence(**overrides)
    assert apply(Status.CANDIDATE, Status.QUARANTINED, evidence, LIMITS) == Status.QUARANTINED


def test_candidate_to_quarantined_neither_reason_rejected() -> None:
    evidence = _evidence()
    with pytest.raises(GuardNotSatisfied):
        apply(Status.CANDIDATE, Status.QUARANTINED, evidence, LIMITS)


# --------------------------------------------------------------------------- #
# candidate -> archived  (PLAN §5 row 8: candidate TTL)
# --------------------------------------------------------------------------- #


def test_candidate_to_archived_ttl_reached() -> None:
    evidence = _evidence(status_changed_at=BASE_NOW - timedelta(days=46))
    assert apply(Status.CANDIDATE, Status.ARCHIVED, evidence, LIMITS) == Status.ARCHIVED


def test_candidate_to_archived_ttl_not_reached() -> None:
    evidence = _evidence(status_changed_at=BASE_NOW - timedelta(days=44))
    with pytest.raises(GuardNotSatisfied):
        apply(Status.CANDIDATE, Status.ARCHIVED, evidence, LIMITS)


def test_candidate_to_archived_uses_the_candidate_ttl_not_the_quarantine_ttl() -> None:
    """31 days is past the 30-day quarantine TTL but well short of the 45-day
    candidate TTL -- proves the two guards read different limit fields."""
    evidence = _evidence(status_changed_at=BASE_NOW - timedelta(days=31))
    with pytest.raises(GuardNotSatisfied):
        apply(Status.CANDIDATE, Status.ARCHIVED, evidence, LIMITS)


def test_candidate_to_archived_ttl_exact_boundary_is_inclusive() -> None:
    evidence = _evidence(status_changed_at=BASE_NOW - timedelta(days=45))
    assert apply(Status.CANDIDATE, Status.ARCHIVED, evidence, LIMITS) == Status.ARCHIVED


# --------------------------------------------------------------------------- #
# validated -> superseded  (PLAN §5 row 9)
# --------------------------------------------------------------------------- #


def test_validated_to_superseded_satisfied() -> None:
    evidence = _evidence(contradiction_equal_or_stronger=True)
    assert apply(Status.VALIDATED, Status.SUPERSEDED, evidence, LIMITS) == Status.SUPERSEDED


def test_validated_to_superseded_rejected() -> None:
    evidence = _evidence()
    with pytest.raises(GuardNotSatisfied):
        apply(Status.VALIDATED, Status.SUPERSEDED, evidence, LIMITS)


def test_validated_to_superseded_ignores_the_weaker_provenance_flag() -> None:
    """`contradiction_weaker_provenance` is row 7's field (candidate -> quarantined).
    Row 9 requires EQUAL-or-stronger provenance; a weaker contradiction must not
    supersede a validated memory."""
    evidence = _evidence(contradiction_weaker_provenance=True)
    with pytest.raises(GuardNotSatisfied):
        apply(Status.VALIDATED, Status.SUPERSEDED, evidence, LIMITS)


# --------------------------------------------------------------------------- #
# validated -> stale  (PLAN §5 row 10)
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "overrides",
    [
        {"invalidation_event": True},
        {"ttl_class_expired": True},
        {"revalidation_failed": True},
    ],
)
def test_validated_to_stale_satisfied(overrides: dict[str, object]) -> None:
    evidence = _evidence(**overrides)
    assert apply(Status.VALIDATED, Status.STALE, evidence, LIMITS) == Status.STALE


def test_validated_to_stale_rejected() -> None:
    evidence = _evidence()
    with pytest.raises(GuardNotSatisfied):
        apply(Status.VALIDATED, Status.STALE, evidence, LIMITS)


# --------------------------------------------------------------------------- #
# validated -> archived  (PLAN §5 row 11: decay floor, D-022)
# --------------------------------------------------------------------------- #


def test_validated_to_archived_satisfied() -> None:
    evidence = _evidence(decay_floor_reached=True)
    assert apply(Status.VALIDATED, Status.ARCHIVED, evidence, LIMITS) == Status.ARCHIVED


def test_validated_to_archived_rejected() -> None:
    evidence = _evidence()
    with pytest.raises(GuardNotSatisfied):
        apply(Status.VALIDATED, Status.ARCHIVED, evidence, LIMITS)


def test_validated_to_archived_ignores_status_changed_at() -> None:
    """Row 11 is the decay floor, not a TTL. An ancient validated memory that
    has not decayed must not be archived by age alone."""
    evidence = _evidence(status_changed_at=BASE_NOW - timedelta(days=3650))
    with pytest.raises(GuardNotSatisfied):
        apply(Status.VALIDATED, Status.ARCHIVED, evidence, LIMITS)


# --------------------------------------------------------------------------- #
# validated -> retired  (PLAN §5 row 12 / D-021: K distinct scoring principals)
# --------------------------------------------------------------------------- #


def test_validated_to_retired_satisfied() -> None:
    evidence = _evidence(q_value=0.1, scored_use_count=4, distinct_scoring_principals=3)
    assert apply(Status.VALIDATED, Status.RETIRED, evidence, LIMITS) == Status.RETIRED


def test_validated_to_retired_k_minus_one_principals_fails_not_silently() -> None:
    """D-021: with K-1 distinct scoring principals the guard must FAIL loudly
    (GuardNotSatisfied), never silently pass and never silently no-op -- the
    caller is expected to open a review_queue item from this rejection."""
    evidence = _evidence(q_value=0.1, scored_use_count=4, distinct_scoring_principals=2)
    with pytest.raises(GuardNotSatisfied):
        apply(Status.VALIDATED, Status.RETIRED, evidence, LIMITS)


def test_validated_to_retired_q_at_threshold_is_not_below_it() -> None:
    """PLAN §5 says "Q < 0.25"; at exactly the threshold the memory stays."""
    evidence = _evidence(q_value=0.25, scored_use_count=4, distinct_scoring_principals=3)
    with pytest.raises(GuardNotSatisfied):
        apply(Status.VALIDATED, Status.RETIRED, evidence, LIMITS)


@pytest.mark.parametrize(
    "overrides",
    [
        {"q_value": 0.3},
        {"scored_use_count": 3},
    ],
)
def test_validated_to_retired_other_deficiencies_rejected(overrides: dict[str, object]) -> None:
    base = {"q_value": 0.1, "scored_use_count": 4, "distinct_scoring_principals": 3}
    base.update(overrides)
    evidence = _evidence(**base)
    with pytest.raises(GuardNotSatisfied):
        apply(Status.VALIDATED, Status.RETIRED, evidence, LIMITS)


# --------------------------------------------------------------------------- #
# stale -> validated / stale -> retired  (PLAN §5 rows 13, 14)
# --------------------------------------------------------------------------- #


def test_stale_to_validated_reverified() -> None:
    evidence = _evidence(reverified=True)
    assert apply(Status.STALE, Status.VALIDATED, evidence, LIMITS) == Status.VALIDATED


def test_stale_to_validated_not_reverified_rejected() -> None:
    evidence = _evidence()
    with pytest.raises(GuardNotSatisfied):
        apply(Status.STALE, Status.VALIDATED, evidence, LIMITS)


def test_stale_to_retired_second_strike() -> None:
    evidence = _evidence(strike_count=2)
    assert apply(Status.STALE, Status.RETIRED, evidence, LIMITS) == Status.RETIRED


def test_stale_to_retired_first_strike_rejected() -> None:
    evidence = _evidence(strike_count=1)
    with pytest.raises(GuardNotSatisfied):
        apply(Status.STALE, Status.RETIRED, evidence, LIMITS)


# --------------------------------------------------------------------------- #
# archived -> validated  (PLAN §5 row 15: operator restore)
# --------------------------------------------------------------------------- #


def test_archived_to_validated_operator_restore() -> None:
    evidence = _evidence(operator_restore=True)
    assert apply(Status.ARCHIVED, Status.VALIDATED, evidence, LIMITS) == Status.VALIDATED


def test_archived_to_validated_without_restore_rejected() -> None:
    evidence = _evidence()
    with pytest.raises(GuardNotSatisfied):
        apply(Status.ARCHIVED, Status.VALIDATED, evidence, LIMITS)


# --------------------------------------------------------------------------- #
# any non-terminal -> tombstoned  (PLAN §5 wildcard row / C-08)
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("current", NON_TERMINAL_STATUSES)
def test_any_non_terminal_to_tombstoned_satisfied(current: Status) -> None:
    evidence = _evidence(erasure_or_approved_delete=True)
    assert apply(current, Status.TOMBSTONED, evidence, LIMITS) == Status.TOMBSTONED


@pytest.mark.parametrize("current", NON_TERMINAL_STATUSES)
def test_any_non_terminal_to_tombstoned_without_reason_rejected(current: Status) -> None:
    evidence = _evidence()
    with pytest.raises(GuardNotSatisfied):
        apply(current, Status.TOMBSTONED, evidence, LIMITS)


def test_tombstoned_is_terminal() -> None:
    """Erasure is final: nothing leaves TOMBSTONED, not even to itself."""
    for target in Status:
        assert (Status.TOMBSTONED, target) not in TRANSITIONS


# --------------------------------------------------------------------------- #
# The table itself: exactly PLAN.md §5 plus C-08's *->tombstoned expansion.
# --------------------------------------------------------------------------- #

_EXPECTED_EDGES: frozenset[tuple[Status | None, Status]] = frozenset(
    {
        (None, Status.CANDIDATE),
        (None, Status.QUARANTINED),
        (None, Status.PINNED),
        (Status.QUARANTINED, Status.CANDIDATE),
        (Status.QUARANTINED, Status.ARCHIVED),
        (Status.CANDIDATE, Status.VALIDATED),
        (Status.CANDIDATE, Status.QUARANTINED),
        (Status.CANDIDATE, Status.ARCHIVED),
        (Status.VALIDATED, Status.SUPERSEDED),
        (Status.VALIDATED, Status.STALE),
        (Status.VALIDATED, Status.ARCHIVED),
        (Status.VALIDATED, Status.RETIRED),
        (Status.STALE, Status.VALIDATED),
        (Status.STALE, Status.RETIRED),
        (Status.ARCHIVED, Status.VALIDATED),
        (Status.QUARANTINED, Status.TOMBSTONED),
        (Status.CANDIDATE, Status.TOMBSTONED),
        (Status.VALIDATED, Status.TOMBSTONED),
        (Status.SUPERSEDED, Status.TOMBSTONED),
        (Status.STALE, Status.TOMBSTONED),
        (Status.RETIRED, Status.TOMBSTONED),
        (Status.ARCHIVED, Status.TOMBSTONED),
        (Status.PINNED, Status.TOMBSTONED),
    }
)


def test_transitions_table_matches_plan_exactly() -> None:
    assert set(TRANSITIONS.keys()) == set(_EXPECTED_EDGES)


def test_legal_creation_statuses_are_exactly_the_none_edges() -> None:
    """Invariant 7's creation half. Derived from the table, pinned to PLAN.md §5's three
    entry states here, so widening it is a deliberate two-file change and never a side
    effect of adding an edge."""
    assert {Status.CANDIDATE, Status.QUARANTINED, Status.PINNED} == LEGAL_CREATION_STATUSES
    assert {t for (c, t) in TRANSITIONS if c is None} == LEGAL_CREATION_STATUSES


@pytest.mark.parametrize(
    "status", sorted(set(Status) - {Status.CANDIDATE, Status.QUARANTINED, Status.PINNED},
                     key=lambda s: s.value)
)
def test_assert_legal_creation_status_refuses_every_non_entry_state(status: Status) -> None:
    with pytest.raises(IllegalTransition):
        assert_legal_creation_status(status)


@pytest.mark.parametrize("status", sorted(LEGAL_CREATION_STATUSES, key=lambda s: s.value))
def test_assert_legal_creation_status_admits_every_entry_state(status: Status) -> None:
    assert_legal_creation_status(status)  # does not raise


def test_status_enum_matches_plan_exactly() -> None:
    """The status set is PLAN.md §5's list, in its wire spelling (D-013). Adding
    or renaming a member changes the DB text values and every illegal-pair
    count below, so it is pinned here rather than derived."""
    assert [s.value for s in Status] == [
        "quarantined",
        "candidate",
        "validated",
        "superseded",
        "stale",
        "retired",
        "archived",
        "pinned",
        "tombstoned",
    ]


def test_pinned_participates_in_exactly_two_edges() -> None:
    pinned_edges = {pair for pair in TRANSITIONS if Status.PINNED in pair}
    assert pinned_edges == {(None, Status.PINNED), (Status.PINNED, Status.TOMBSTONED)}


def test_retrievable_statuses_are_exactly_validated_candidate_pinned() -> None:
    assert frozenset({Status.VALIDATED, Status.CANDIDATE, Status.PINNED}) == RETRIEVABLE_STATUSES


def test_quarantined_is_not_retrievable() -> None:
    """Invariant 7's retrieval-side half, stated as its own assertion so it goes
    red on its own if the frozenset is ever widened."""
    for status in (
        Status.QUARANTINED,
        Status.SUPERSEDED,
        Status.STALE,
        Status.RETIRED,
        Status.ARCHIVED,
        Status.TOMBSTONED,
    ):
        assert status not in RETRIEVABLE_STATUSES


def test_transitions_table_is_read_only() -> None:
    """PLAN §10: "no admin bypass exists in code". A mutable module-level table
    IS an admin bypass -- one assignment legalises any edge. The table is a
    read-only mapping, and `apply` reads a private copy so rebinding the public
    name cannot change its behaviour either."""
    with pytest.raises(TypeError):
        TRANSITIONS[(Status.QUARANTINED, Status.VALIDATED)] = (  # type: ignore[index]
            lambda evidence, limits: GuardOutcome(True, "")
        )
    assert (Status.QUARANTINED, Status.VALIDATED) not in TRANSITIONS


@pytest.mark.parametrize(("current", "target"), sorted(_EXPECTED_EDGES, key=repr))
def test_no_legal_edge_passes_on_empty_evidence(current: Status | None, target: Status) -> None:
    """Contract §3.9: "Guards read only their own fields and reject on absence --
    a missing field is never a default-pass."

    This is the test that goes red if ANY guard is a placeholder
    (`return GuardOutcome(True, "")`), forgets to read its field, or defaults
    to pass. Every optional field of `TransitionEvidence` is at its zero value
    here, so no legal edge may be traversable."""
    with pytest.raises(GuardNotSatisfied):
        apply(current, target, _MINIMAL_EVIDENCE, LIMITS)


@pytest.mark.parametrize(("current", "target"), sorted(_EXPECTED_EDGES, key=repr))
def test_every_legal_edge_has_a_distinct_reason_string(
    current: Status | None, target: Status
) -> None:
    """A guard that refuses must say why: `GuardNotSatisfied.reason` is the only
    channel a Phase 3 worker has for deciding between "retry later" and "open a
    review_queue item" (see the GuardOutcome contract-gap note)."""
    with pytest.raises(GuardNotSatisfied) as exc_info:
        apply(current, target, _MINIMAL_EVIDENCE, LIMITS)
    assert exc_info.value.reason.strip()


# --------------------------------------------------------------------------- #
# Exhaustive illegal-pair coverage: generated from the table, never hand-listed.
# --------------------------------------------------------------------------- #

_ALL_CURRENTS: tuple[Status | None, ...] = (None, *Status)
_ALL_PAIRS: list[tuple[Status | None, Status]] = [(c, t) for c in _ALL_CURRENTS for t in Status]
ILLEGAL_PAIRS: list[tuple[Status | None, Status]] = [pair for pair in _ALL_PAIRS if pair not in TRANSITIONS]


def test_illegal_pair_counts_are_the_pinned_numbers() -> None:
    """Hard numbers, not a restatement of how the lists were built.

    9 statuses => 10 possible `current` values (incl. the pre-insert `None`)
    x 9 targets = 90 pairs. PLAN.md §5 has 15 named rows; C-08 expands the
    wildcard into 8 (every status but TOMBSTONED) => 23 legal, 67 illegal.
    Adding a status or legalising an edge changes one of these numbers and
    this assertion goes red -- which is the point."""
    assert len(Status) == 9
    assert len(_ALL_PAIRS) == 90
    assert len(TRANSITIONS) == 23
    assert len(ILLEGAL_PAIRS) == 67


@pytest.mark.parametrize(("current", "target"), ILLEGAL_PAIRS)
def test_illegal_pairs_rejected(current: Status | None, target: Status) -> None:
    with pytest.raises(IllegalTransition):
        apply(current, target, _MINIMAL_EVIDENCE, LIMITS)


@pytest.mark.parametrize(("current", "target"), ILLEGAL_PAIRS)
def test_illegal_pairs_rejected_even_with_maximal_evidence(
    current: Status | None, target: Status
) -> None:
    """Table membership is checked BEFORE any guard runs. With every boolean
    true, every counter saturated and three fully-independent confirmations,
    an absent edge must still raise `IllegalTransition` -- not
    `GuardNotSatisfied`, and certainly not a status. This is what stops a
    future "if the evidence is overwhelming, allow it" shortcut."""
    with pytest.raises(IllegalTransition):
        apply(current, target, _MAXIMAL_EVIDENCE, LIMITS)


def test_quarantined_to_validated_direct_is_illegal() -> None:
    """Explicitly named per PHASE-0 Task 4's own test list, even though it is
    also covered by the exhaustive product above -- this is the edge every
    parallel implementer must not accidentally legalise."""
    assert (Status.QUARANTINED, Status.VALIDATED) not in TRANSITIONS
    with pytest.raises(IllegalTransition):
        apply(Status.QUARANTINED, Status.VALIDATED, _MAXIMAL_EVIDENCE, LIMITS)


def test_illegal_transition_carries_current_and_target() -> None:
    with pytest.raises(IllegalTransition) as exc_info:
        apply(Status.QUARANTINED, Status.VALIDATED, _MINIMAL_EVIDENCE, LIMITS)
    err = exc_info.value
    assert err.current == Status.QUARANTINED
    assert err.target == Status.VALIDATED


def test_guard_not_satisfied_carries_current_target_reason() -> None:
    evidence = _evidence()
    with pytest.raises(GuardNotSatisfied) as exc_info:
        apply(Status.VALIDATED, Status.SUPERSEDED, evidence, LIMITS)
    err = exc_info.value
    assert err.current == Status.VALIDATED
    assert err.target == Status.SUPERSEDED
    assert err.reason  # non-empty: becomes the review-routing signal


def test_guard_not_satisfied_and_illegal_transition_are_distinguishable() -> None:
    """A caller must be able to tell "no such edge" from "not yet": the two are
    siblings under TracebedError, neither a subclass of the other."""
    assert not issubclass(GuardNotSatisfied, IllegalTransition)
    assert not issubclass(IllegalTransition, GuardNotSatisfied)


# --------------------------------------------------------------------------- #
# TransitionEvidence / ShadowConfirmation input validation
# --------------------------------------------------------------------------- #


def test_transition_evidence_rejects_naive_now() -> None:
    """A naive `now` plus an aware `status_changed_at` raises TypeError inside
    the subtraction; both naive silently shifts every TTL by the deployment's
    UTC offset. Neither may reach a guard."""
    with pytest.raises(ValueError, match="timezone-aware"):
        TransitionEvidence(
            now=datetime(2026, 1, 1),
            provenance_class=ProvenanceClass.DISTILLER,
            trust_tier=TrustTier.B,
            mem_type=MemType.SEMANTIC,
        )


def test_transition_evidence_rejects_naive_status_changed_at() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        _evidence(status_changed_at=datetime(2025, 12, 1))


def test_transition_evidence_allows_none_status_changed_at() -> None:
    assert _evidence(status_changed_at=None).status_changed_at is None


@pytest.mark.parametrize("length", [0, 8, SIG_HASH_LEN - 1, SIG_HASH_LEN + 1])
def test_shadow_confirmation_rejects_malformed_signature(length: int) -> None:
    """`signatures.same_cluster` raises ValueError on a wrong-length signature.
    Caught at construction, that is a caller bug; uncaught, it escapes
    `apply()` as a non-TracebedError and crashes the shadow validator instead
    of merely failing to corroborate."""
    with pytest.raises(ValueError, match=str(SIG_HASH_LEN)):
        ShadowConfirmation(
            run_id=_run_id(), principal_id=_principal_id(), input_signature_hash=b"\x00" * length
        )


# --------------------------------------------------------------------------- #
# independent_confirmations: the bounded max-clique helper directly (D-020)
# --------------------------------------------------------------------------- #


def test_independent_confirmations_empty() -> None:
    assert independent_confirmations(()) == 0


def test_independent_confirmations_single_is_one() -> None:
    assert independent_confirmations((_confirmation(_principal_id(), _CLUSTER_A),)) == 1


def test_independent_confirmations_two_independent() -> None:
    p1, p2 = _principal_id(), _principal_id()
    confirmations = (_confirmation(p1, _CLUSTER_A), _confirmation(p2, _CLUSTER_B))
    assert independent_confirmations(confirmations) == 2


def test_independent_confirmations_same_principal_caps_at_one() -> None:
    p1 = _principal_id()
    confirmations = (_confirmation(p1, _CLUSTER_A), _confirmation(p1, _CLUSTER_B))
    assert independent_confirmations(confirmations) == 1


def test_independent_confirmations_same_cluster_caps_at_one() -> None:
    p1, p2 = _principal_id(), _principal_id()
    confirmations = (_confirmation(p1, _CLUSTER_A), _confirmation(p2, _CLUSTER_A))
    assert independent_confirmations(confirmations) == 1


def test_independent_confirmations_same_run_caps_at_one() -> None:
    run = _run_id()
    confirmations = (
        _confirmation(_principal_id(), _CLUSTER_A, run=run),
        _confirmation(_principal_id(), _CLUSTER_B, run=run),
    )
    assert independent_confirmations(confirmations) == 1


def test_independent_confirmations_is_max_clique_not_naive_count() -> None:
    """c1/c3 share a cluster (incompatible); c1/c2 and c2/c3 are each fine. The
    largest mutually-compatible subset has size 2, not 3 -- a naive "count
    distinct principals" or "count distinct clusters" check would overstate
    this (GovMem's 0.597 false-promotion failure mode, D-020)."""
    p1, p2, p3 = _principal_id(), _principal_id(), _principal_id()
    c1 = _confirmation(p1, _CLUSTER_A)
    c2 = _confirmation(p2, _CLUSTER_B)
    c3 = _confirmation(p3, _CLUSTER_A)
    assert independent_confirmations((c1, c2, c3)) == 2


def test_independent_confirmations_finds_the_maximum_not_the_first_greedy_clique() -> None:
    """c4 shares p1's identity with c1 and c3's cluster with c3, so any clique
    containing c4 has size 2. The maximum is {c1, c2, c3} = 3. A greedy scan
    that commits to the first vertex it sees (or any pairwise-only shortcut)
    reports 2 here."""
    p1, p2, p3 = _principal_id(), _principal_id(), _principal_id()
    c1 = _confirmation(p1, _CLUSTER_A)
    c2 = _confirmation(p2, _CLUSTER_B)
    c3 = _confirmation(p3, _CLUSTER_C)
    c4 = _confirmation(p1, _CLUSTER_C)
    assert independent_confirmations((c4, c1, c2, c3)) == 3


def test_independent_confirmations_capped_by_distinct_cluster_count() -> None:
    """Five distinct principals over only two clusters is two independent
    confirmations, not five -- the correlated-trace red-team probe (PLAN §7
    Phase 3 gate, probe 4)."""
    confirmations = tuple(
        _confirmation(_principal_id(), tail)
        for tail in (_CLUSTER_A, _CLUSTER_A, _CLUSTER_A, _CLUSTER_B, _CLUSTER_B)
    )
    assert independent_confirmations(confirmations) == 2


def test_independent_confirmations_is_order_independent() -> None:
    """The answer is a property of the set, not of the tuple order the caller
    happened to build."""
    p1, p2, p3 = _principal_id(), _principal_id(), _principal_id()
    c1 = _confirmation(p1, _CLUSTER_A)
    c2 = _confirmation(p2, _CLUSTER_B)
    c3 = _confirmation(p3, _CLUSTER_C)
    c4 = _confirmation(p1, _CLUSTER_C)
    orderings = [
        (c1, c2, c3, c4),
        (c4, c3, c2, c1),
        (c2, c4, c1, c3),
        (c3, c1, c4, c2),
    ]
    assert {independent_confirmations(o) for o in orderings} == {3}


def test_independent_confirmations_at_least_short_circuits_conservatively() -> None:
    """`at_least` may return early, but only ever at a value that gives the same
    `>=` answer. It must never report clearance the full search would not."""
    p1, p2 = _principal_id(), _principal_id()
    pair = (_confirmation(p1, _CLUSTER_A), _confirmation(p2, _CLUSTER_B))
    assert independent_confirmations(pair, at_least=2) >= 2
    assert independent_confirmations(pair, at_least=5) == 2  # cannot invent independence

    same_principal = (_confirmation(p1, _CLUSTER_A), _confirmation(p1, _CLUSTER_B))
    assert independent_confirmations(same_principal, at_least=2) == 1


def _far_apart_tail(index: int) -> bytes:
    """8-byte cluster tags that are pairwise beyond SAME_CLUSTER_MAX_HAMMING.

    sha256 of the index rather than randomness, so the DoS regression below is
    reproducible run to run; sha256 output is uniform enough that two 64-bit
    tags land within 8 bits of each other with probability ~3e-10, and
    `test_far_apart_tails_really_are_distinct_clusters` checks it outright
    rather than trusting the argument.
    """
    return hashlib.sha256(f"cluster-{index}".encode()).digest()[:8]


def test_far_apart_tails_really_are_distinct_clusters() -> None:
    """Guards the fixture that the DoS regression depends on.

    If these tags were NOT pairwise-distinct clusters, the "true maximum is
    40" assertion below would be measuring a smaller graph and would pass for
    the wrong reason -- a hand-rolled bit-pattern generator used here first
    had a minimum pairwise distance of 4, well inside the threshold."""
    tails = [_far_apart_tail(i) for i in range(40)]
    assert len(set(tails)) == 40
    values = [int.from_bytes(t, "big") for t in tails]
    closest = min(
        hamming(values[i], values[j]) for i in range(len(values)) for j in range(i + 1, len(values))
    )
    assert closest > SAME_CLUSTER_MAX_HAMMING


def test_independent_confirmations_is_bounded_on_a_pathological_input() -> None:
    """DoS regression (write-path availability).

    Maximum clique is NP-hard and the confirmation set is attacker-influenced:
    every principal that can submit a run adds a node. The original
    unpivoted Bron-Kerbosch here was O(2^n) even on entirely *benign* input --
    22 genuine confirmations took 2.1s, 42 took 134s, and a memory that
    accumulated ~50 would never finish. This asserts the bounded search
    returns promptly on a complete-multipartite graph (40 clusters x 3
    principals each = the shape with the most maximal cliques, 3^40).
    """
    confirmations: list[ShadowConfirmation] = []
    for cluster in range(40):
        tail = _far_apart_tail(cluster)
        for _ in range(3):
            confirmations.append(_confirmation(_principal_id(), tail))

    started = time.perf_counter()
    result = independent_confirmations(tuple(confirmations))
    elapsed = time.perf_counter() - started

    assert elapsed < 5.0, f"independent_confirmations took {elapsed:.1f}s on 120 confirmations"
    # Exactness matters as much as speed here. The bounds are conservative by
    # construction -- exhausting the step budget under-reports, which refuses a
    # promotion rather than granting one -- but an implementation that bought
    # its speed by giving up accuracy would silently start refusing legitimate
    # promotions. The true maximum is 40 (one per cluster) and nothing less is
    # acceptable: dropping pivoting from the search, for instance, still returns
    # inside the budget but answers 29.
    assert result == 40


def _overlapping_tail(index: int) -> bytes:
    """Cluster tags that deliberately OVERLAP: minimum pairwise Hamming 4, i.e.
    inside SAME_CLUSTER_MAX_HAMMING, so some nominally different clusters are
    the same cluster. The resulting compatibility graph is irregular rather
    than cleanly multipartite, which is the shape that makes the search
    actually explore instead of finding its answer on the first descent."""
    return bytes(((index * 37 + position * 91) ^ (index * 173)) & 0xFF for position in range(8))


def test_independent_confirmations_stays_exact_when_the_step_budget_binds() -> None:
    """Speed must not be bought with silent accuracy loss.

    The bounds in `independent_confirmations` under-report rather than
    over-report, so a degraded search is fail-SAFE for promotion -- but it
    would quietly start refusing legitimate promotions, which no other test
    here would notice. On this irregular graph the step budget does bind, and
    the answer must still be the true maximum of 32 (confirmed against a
    100x-larger budget, which yields the same 32 after 6.3s). Dropping
    pivoting from the search returns inside the budget too, but answers 29."""
    confirmations = tuple(
        _confirmation(_principal_id(), _overlapping_tail(cluster))
        for cluster in range(40)
        for _ in range(3)
    )
    assert independent_confirmations(confirmations) == 32


def test_independent_confirmations_truncates_unbounded_input() -> None:
    """The O(n^2) graph build is itself an allocation risk on an unbounded
    caller-supplied sequence, so only the first MAX_CONFIRMATIONS_CONSIDERED
    are read. Truncation can only lower the count, which refuses promotions
    rather than granting them."""
    oversized = tuple(
        _confirmation(_principal_id(), _far_apart_tail(i))
        for i in range(MAX_CONFIRMATIONS_CONSIDERED + 50)
    )
    started = time.perf_counter()
    result = independent_confirmations(oversized, at_least=2)
    elapsed = time.perf_counter() - started
    assert elapsed < 5.0
    assert result >= 2


# --------------------------------------------------------------------------- #
# TransitionLimits: config projection AND the invariant floors.
# --------------------------------------------------------------------------- #


def _effective_config(**overrides: object) -> EffectiveConfig:
    """A real `EffectiveConfig` built from the real section models.

    Deliberately NOT a duck-typed stand-in: a fake with the same attribute
    names stays green if `domain/config.py` renames
    `lifecycle.quarantine_ttl_days`, while `from_config` breaks in production.
    This binds the test to the actual contract §3.4 field names.
    """
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
    return EffectiveConfig(**sections)  # type: ignore[arg-type]


def test_transition_limits_from_real_effective_config_defaults() -> None:
    """`from_config` against the real `EffectiveConfig`, asserting it projects
    exactly PLAN.md §6's documented defaults."""
    limits = TransitionLimits.from_config(_effective_config())
    assert limits == LIMITS


def test_transition_limits_from_config_tracks_overridden_values() -> None:
    """Proves each field is read from its own dotted path rather than
    hard-coded: every projected value moves when its source moves."""
    # archive_floor 0.4, not 0.5: `EffectiveConfig` now refuses a floor at or
    # above the default `scoring.q_start` of 0.5, because such a pair archives
    # every memory on its first idle sweep. Any value that differs from the
    # 0.15 default proves what this test is about (the projection reads its
    # own dotted path); 0.5 additionally asserted a config that cannot exist.
    cfg = _effective_config(
        lifecycle=LifecycleConfig(quarantine_ttl_days=7, candidate_ttl_days=9, archive_floor=0.4),
        promotion=PromotionConfig(
            min_outcomes=5, failure_lesson_outcomes=3, min_distinct_principals=4
        ),
        retirement=RetirementConfig(
            q_threshold=0.4, min_scored_uses=6, min_distinct_principals=7
        ),
    )
    limits = TransitionLimits.from_config(cfg)
    assert limits == TransitionLimits(
        quarantine_ttl_days=7,
        candidate_ttl_days=9,
        promote_min_outcomes=5,
        failure_lesson_outcomes=3,
        promotion_min_distinct_principals=4,
        retire_q_threshold=0.4,
        retire_min_scored_uses=6,
        retire_min_distinct_principals=7,
        archive_floor=0.4,
    )


def test_overridden_limits_actually_change_guard_behaviour() -> None:
    """A limits snapshot that nothing reads is a limits snapshot that proves
    nothing. Raising `promotion.min_outcomes` to 5 must make evidence that
    passed at the default fail."""
    strict = TransitionLimits.from_config(
        _effective_config(
            promotion=PromotionConfig(
                min_outcomes=5, failure_lesson_outcomes=1, min_distinct_principals=2
            )
        )
    )
    evidence = _evidence(
        promotion_outcomes=2,
        promotion_distinct_principals=2,
        outcome_consistent=True,
        scan_repass=True,
    )
    assert apply(Status.CANDIDATE, Status.VALIDATED, evidence, LIMITS) == Status.VALIDATED
    with pytest.raises(GuardNotSatisfied):
        apply(Status.CANDIDATE, Status.VALIDATED, evidence, strict)


@pytest.mark.parametrize(
    "field",
    [
        "quarantine_ttl_days",
        "candidate_ttl_days",
        "promote_min_outcomes",
        "failure_lesson_outcomes",
        "promotion_min_distinct_principals",
        "retire_min_scored_uses",
        "retire_min_distinct_principals",
    ],
)
def test_transition_limits_reject_below_floor_thresholds(field: str) -> None:
    """Invariant 7 ends "No admin bypass in code"; PLAN §10 forbids status
    changes outside the machine. `promotion`/`retirement`/`lifecycle` are all
    per-project overridable via `project_config` dotted keys (C-03) and
    `domain/config.py` puts no lower bound on any of them, so
    `promotion.failure_lesson_outcomes = 0` would promote quarantined content
    with ZERO corroboration -- an admin bypass reached through configuration.
    Each floor is refused loudly, never silently clamped."""
    below = {field: 0}
    with pytest.raises(ConfigError, match=field):
        dataclasses.replace(LIMITS, **below)  # type: ignore[arg-type]


def test_transition_limits_reject_negative_ttl() -> None:
    with pytest.raises(ConfigError):
        dataclasses.replace(LIMITS, candidate_ttl_days=-5)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("retire_q_threshold", -0.1),
        ("retire_q_threshold", 1.5),
        ("archive_floor", -1.0),
        ("archive_floor", 2.0),
    ],
)
def test_transition_limits_reject_out_of_range_probabilities(field: str, value: float) -> None:
    with pytest.raises(ConfigError, match=field):
        dataclasses.replace(LIMITS, **{field: value})  # type: ignore[arg-type]


def test_from_config_refuses_a_quarantine_disabling_override() -> None:
    """The end-to-end shape of the bypass: an operator writes
    `promotion.failure_lesson_outcomes = 0` into `project_config`, the
    resolver happily produces it (no `ge=` on the field), and the state
    machine refuses to build limits from it."""
    cfg = _effective_config(
        promotion=PromotionConfig(
            min_outcomes=2, failure_lesson_outcomes=0, min_distinct_principals=2
        )
    )
    assert cfg.promotion.failure_lesson_outcomes == 0  # config layer permits it today
    with pytest.raises(ConfigError, match="failure_lesson_outcomes"):
        TransitionLimits.from_config(cfg)


def test_from_config_refuses_a_single_principal_retirement_override() -> None:
    """D-021: K=1 restores the exact memory-destruction primitive the decision
    exists to close (one attacker-controlled feedback source retires any
    memory in four scored uses)."""
    cfg = _effective_config(
        retirement=RetirementConfig(q_threshold=0.25, min_scored_uses=4, min_distinct_principals=1)
    )
    with pytest.raises(ConfigError, match="retire_min_distinct_principals"):
        TransitionLimits.from_config(cfg)


# --------------------------------------------------------------------------- #
# Smoke tests on the small value types themselves.
# --------------------------------------------------------------------------- #


def test_shadow_confirmation_is_frozen() -> None:
    confirmation = _confirmation(_principal_id(), _CLUSTER_A)
    with pytest.raises(dataclasses.FrozenInstanceError):
        confirmation.principal_id = _principal_id()  # type: ignore[misc]


def test_transition_evidence_is_frozen() -> None:
    with pytest.raises(dataclasses.FrozenInstanceError):
        _MINIMAL_EVIDENCE.scan_passed = True  # type: ignore[misc]


def test_transition_limits_is_frozen() -> None:
    with pytest.raises(dataclasses.FrozenInstanceError):
        LIMITS.promote_min_outcomes = 0  # type: ignore[misc]


def test_guard_outcome_is_frozen() -> None:
    outcome = GuardOutcome(ok=True, reason="")
    with pytest.raises(dataclasses.FrozenInstanceError):
        outcome.ok = False  # type: ignore[misc]


def test_apply_does_not_mutate_its_arguments() -> None:
    """`apply` is a pure function of its four arguments (contract §3.9): a
    replay of the same call must produce the same answer."""
    evidence = _evidence(q_value=0.1, scored_use_count=4, distinct_scoring_principals=3)
    before = dataclasses.astuple(evidence)
    assert apply(Status.VALIDATED, Status.RETIRED, evidence, LIMITS) == Status.RETIRED
    assert apply(Status.VALIDATED, Status.RETIRED, evidence, LIMITS) == Status.RETIRED
    assert dataclasses.astuple(evidence) == before
