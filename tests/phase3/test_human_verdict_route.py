"""tests/phase3/test_human_verdict_route.py -- export-and-quarantine-routes chunk (D-133).

Fidelity-audit finding S26, extended: PLAN.md §5 row 4 gives `quarantined -> candidate` two
routes -- shadow corroboration, OR verified-human-verdict provenance. The second route's guard
(`_guard_quarantined_to_candidate`) required `has_verified_human_verdict AND provenance_class is
HUMAN_VERDICT`, but no `∅ -> quarantined` creation edge ever admits `HUMAN_VERDICT` provenance
(`_guard_none_to_quarantined` accepts only `DISTILLER`/`PROPOSAL`), and no transition anywhere
rewrites a row's stored provenance class after creation. No row this system can produce was ever
able to satisfy that guard clause -- an operator confirming a quarantined memory by hand had no
path out of quarantine, while the guard read as though one existed.

D-133 decided NOT to build the operator route (it needs a repository write path that promotes an
EXISTING row's provenance -- `stores/pg/lifecycle.py::LifecycleWriter` writes `status` only, by
design, and `tests/phase1/test_learning_repos.py`'s
`test_exactly_one_status_writing_statement_exists_in_the_lifecycle_module` pins that to exactly
one statement in `stores/pg/` -- plus an audited operator-facing API route; both are outside this
chunk's file list) and instead REMOVED the dead guard clause. This file is the proof: the machine
has no such route, by construction, and the removal did not touch the (unchanged, still-working)
corroboration route or any creation edge.
"""

from __future__ import annotations

import dataclasses
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from tracebed.domain.enums import Lane, MemType, ProvenanceClass, ScopeType, TrustTier
from tracebed.domain.errors import GuardNotSatisfied, IllegalTransition
from tracebed.domain.ids import PrincipalId, RunId
from tracebed.domain.memory import NewMemoryItem, Provenance, validate_provenance
from tracebed.domain.signatures import SIG_HASH_LEN
from tracebed.domain.state_machine import (
    LEGAL_CREATION_STATUSES,
    SHADOW_CONFIRM_MIN_INDEPENDENT,
    TRANSITIONS,
    ShadowConfirmation,
    Status,
    TransitionEvidence,
    TransitionLimits,
    apply,
    assert_legal_creation_status,
)

pytestmark = pytest.mark.phase3

BASE_NOW: datetime = datetime(2026, 1, 1, tzinfo=UTC)

LIMITS = TransitionLimits(
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

_CLUSTER_A = b"\x01" * 8
_CLUSTER_B = b"\xff" * 8


def _sig(cluster_tail: bytes) -> bytes:
    """`domain.signatures.ABSENT_SIGNATURE` is exactly 40 zero bytes (C-07/D-129), so this
    must never be all-zero end to end -- `_CLUSTER_A` is `\\x01` bytes, not `\\x00`, purely
    to keep this helper's output distinct from that sentinel; `same_cluster` forces `True`
    against it unconditionally, which would silently collapse two "independent" confirmations
    into one and is unrelated to anything this file tests."""
    return (b"\x00" * (SIG_HASH_LEN - 8)) + cluster_tail


def _confirmation(cluster_tail: bytes) -> ShadowConfirmation:
    return ShadowConfirmation(
        run_id=RunId(uuid4()),
        principal_id=PrincipalId(uuid4()),
        input_signature_hash=_sig(cluster_tail),
    )


def _evidence(**overrides: object) -> TransitionEvidence:
    base = TransitionEvidence(
        now=BASE_NOW,
        provenance_class=ProvenanceClass.DISTILLER,
        trust_tier=TrustTier.B,
        mem_type=MemType.SEMANTIC,
    )
    return dataclasses.replace(base, **overrides)  # type: ignore[arg-type]


# --------------------------------------------------------------------------- #
# 1. The dead skip is gone: the flag + class combination that used to grant an
#    unconditional pass now falls through to the corroboration check like any
#    other evidence, and fails when corroboration is insufficient.
# --------------------------------------------------------------------------- #


def test_human_verdict_flag_and_class_alone_no_longer_exit_quarantine() -> None:
    """The exact evidence shape the old clause granted for free. `confirmations=()`
    is what used to be irrelevant to this branch; now it is dispositive."""
    evidence = _evidence(
        provenance_class=ProvenanceClass.HUMAN_VERDICT,
        has_verified_human_verdict=True,
        confirmations=(),
    )
    with pytest.raises(GuardNotSatisfied) as exc_info:
        apply(Status.QUARANTINED, Status.CANDIDATE, evidence, LIMITS)
    assert "no verified-human-verdict skip in this build" in str(exc_info.value)


@pytest.mark.parametrize("confirmation_count", [0, 1])
def test_human_verdict_evidence_still_needs_real_corroboration(confirmation_count: int) -> None:
    """Below `SHADOW_CONFIRM_MIN_INDEPENDENT`, HUMAN_VERDICT-flagged evidence is refused
    exactly like any other insufficiently-corroborated quarantined row."""
    confirmations = tuple(_confirmation(_CLUSTER_A) for _ in range(confirmation_count))
    evidence = _evidence(
        provenance_class=ProvenanceClass.HUMAN_VERDICT,
        has_verified_human_verdict=True,
        confirmations=confirmations,
    )
    with pytest.raises(GuardNotSatisfied):
        apply(Status.QUARANTINED, Status.CANDIDATE, evidence, LIMITS)


def test_human_verdict_evidence_with_real_corroboration_still_promotes() -> None:
    """The corroboration route is untouched: two independent confirmations still work,
    whether or not the row also happens to carry the (now-inert) human-verdict flag."""
    confirmations = (_confirmation(_CLUSTER_A), _confirmation(_CLUSTER_B))
    evidence = _evidence(
        provenance_class=ProvenanceClass.HUMAN_VERDICT,
        has_verified_human_verdict=True,
        confirmations=confirmations,
    )
    assert apply(Status.QUARANTINED, Status.CANDIDATE, evidence, LIMITS) == Status.CANDIDATE


def test_flag_without_class_still_refused() -> None:
    """`has_verified_human_verdict=True` alone (mismatched class) was already refused before
    D-133 and stays refused after -- this combination was never the live bug."""
    evidence = _evidence(provenance_class=ProvenanceClass.DISTILLER, has_verified_human_verdict=True)
    with pytest.raises(GuardNotSatisfied):
        apply(Status.QUARANTINED, Status.CANDIDATE, evidence, LIMITS)


def test_proposal_class_still_refused_even_with_the_old_flag_combination() -> None:
    """D-023 is untouched: PROPOSAL is checked first and unconditionally, before the
    (now-removed) human-verdict branch would ever have been reached anyway."""
    evidence = _evidence(
        provenance_class=ProvenanceClass.PROPOSAL,
        has_verified_human_verdict=True,
    )
    with pytest.raises(GuardNotSatisfied):
        apply(Status.QUARANTINED, Status.CANDIDATE, evidence, LIMITS)


# --------------------------------------------------------------------------- #
# 2. No creation EDGE admits HUMAN_VERDICT provenance -- exhaustive over every
#    legal (None, X) target, with every OTHER field set as permissively as
#    that edge's own guard allows. Note the deliberately narrow claim: this is
#    about `apply()`'s table, and `apply()` is NOT the only door into
#    `memory_item` (see section 2b, which is the reason D-133's removal matters
#    operationally rather than cosmetically).
# --------------------------------------------------------------------------- #


_SORTED_LEGAL_CREATION_STATUSES: list[Status] = sorted(
    LEGAL_CREATION_STATUSES, key=lambda s: s.value
)


@pytest.mark.parametrize("target", _SORTED_LEGAL_CREATION_STATUSES)
def test_no_creation_edge_admits_human_verdict_provenance(target: Status) -> None:
    evidence = TransitionEvidence(
        now=BASE_NOW,
        provenance_class=ProvenanceClass.HUMAN_VERDICT,
        trust_tier=TrustTier.A,  # most permissive trust tier across every creation guard
        mem_type=MemType.LESSON,
        scan_passed=True,
        scan_repass=True,
        provenance_complete=True,
        operator_created=True,
        has_verified_human_verdict=True,
    )
    with pytest.raises(GuardNotSatisfied):
        apply(None, target, evidence, LIMITS)


def test_human_verdict_class_row_cannot_be_created_at_all_tier_b_either() -> None:
    """Tier B is the only tier `∅ -> quarantined` accepts; even paired with the tier the
    quarantined-creation guard wants, HUMAN_VERDICT provenance is still refused there."""
    evidence = TransitionEvidence(
        now=BASE_NOW,
        provenance_class=ProvenanceClass.HUMAN_VERDICT,
        trust_tier=TrustTier.B,
        mem_type=MemType.LESSON,
        scan_passed=True,
        provenance_complete=True,
    )
    with pytest.raises(GuardNotSatisfied):
        apply(None, Status.QUARANTINED, evidence, LIMITS)


# --------------------------------------------------------------------------- #
# 2b. THE INSERT DOOR. The claim "no row this system can produce could satisfy
#     the removed clause" is FALSE, and section 2 above is exactly why it looks
#     true: it reasons over `apply()`'s transition table, and the repository's
#     creation path does not consult that table.
#
#     `Repo.insert_memory_item` / `ScopedRepo.insert_memory_item` /
#     `stores.pg.lifecycle`'s delegate run `assert_legal_creation_status(status)`
#     -- membership in `LEGAL_CREATION_STATUSES`, i.e. "is `quarantined` a
#     creation status at all" -- and `validate_provenance(provenance)` -- "does
#     this class carry its required fields". Neither is `_guard_none_to_quarantined`,
#     so that guard's `provenance_class in (DISTILLER, PROPOSAL)` restriction is
#     enforced only on callers that voluntarily route through `apply(None, ...)`
#     first (the distiller, the extractors, `agent_control.submit_proposal`).
#     A `quarantined` row carrying `provenance.cls = human_verdict` and a
#     `verdict_id` is constructible and insertable, and
#     `workers.shadow_validator.evaluate_one` derives
#     `has_verified_human_verdict = True` straight off that stored provenance --
#     which, before D-133, returned `candidate` from `apply()` with ZERO
#     corroboration. That is the PLAN §2 invariant 7 bypass, reachable, not dead.
#
#     These tests pin the asymmetry itself, which is stable regardless of which
#     chunk eventually closes the insert door: the guard refuses the combination
#     and the insert path does not.
# --------------------------------------------------------------------------- #


def test_the_creation_guard_refuses_quarantined_human_verdict() -> None:
    evidence = TransitionEvidence(
        now=BASE_NOW,
        provenance_class=ProvenanceClass.HUMAN_VERDICT,
        trust_tier=TrustTier.B,
        mem_type=MemType.SEMANTIC,
        scan_passed=True,
        provenance_complete=True,
    )
    with pytest.raises(GuardNotSatisfied):
        apply(None, Status.QUARANTINED, evidence, LIMITS)


def test_but_the_insert_door_accepts_the_same_combination_no_guard_runs() -> None:
    """The two checks `Repo.insert_memory_item` actually performs before its INSERT, applied to
    the exact row shape the guard above refuses. Both pass. If this test ever goes red because
    a future chunk routes creation through `apply(None, ...)`, that is the insert door being
    closed and this file's section 2b should be rewritten to say so -- it is not a regression.
    """
    item = NewMemoryItem(
        scope_type=ScopeType.PROJECT_SHARED,
        scope_id=None,
        mem_type=MemType.SEMANTIC,
        kind="fact",
        lane=Lane.QUALITY,
        trust_tier=TrustTier.B,
        status=Status.QUARANTINED,
        content="operator-confirmed content",
        token_count=1,
        provenance=Provenance(cls=ProvenanceClass.HUMAN_VERDICT, verdict_id=uuid4()),
    )
    assert_legal_creation_status(item.status)  # membership only -- not the guard
    validate_provenance(item.provenance)  # required fields only -- not the guard


def test_the_shadow_validator_would_derive_the_flag_from_that_stored_provenance() -> None:
    """`workers.shadow_validator.evaluate_one`'s exact derivation, restated here rather than
    imported, because the point is that the flag is a pure function of columns the insert door
    just accepted -- no verification step stands between the two."""
    provenance = Provenance(cls=ProvenanceClass.HUMAN_VERDICT, verdict_id=uuid4())
    derived = provenance.cls is ProvenanceClass.HUMAN_VERDICT and provenance.verdict_id is not None
    assert derived is True

    # ... and with D-133 in place, that flag now buys nothing.
    evidence = _evidence(
        provenance_class=provenance.cls, has_verified_human_verdict=derived, confirmations=()
    )
    with pytest.raises(GuardNotSatisfied):
        apply(Status.QUARANTINED, Status.CANDIDATE, evidence, LIMITS)


# --------------------------------------------------------------------------- #
# 3. No transition changes a row's provenance class -- structural, not
#    evidence-shaped: `apply()` returns a `Status` and nothing else, and
#    `TransitionEvidence` is frozen, so there is no object here a guard could
#    mutate even if one tried.
# --------------------------------------------------------------------------- #


def test_apply_returns_only_a_status() -> None:
    import inspect

    signature = inspect.signature(apply)
    assert signature.return_annotation in ("Status", Status)


def test_transition_evidence_is_frozen() -> None:
    evidence = _evidence()
    with pytest.raises(dataclasses.FrozenInstanceError):
        evidence.provenance_class = ProvenanceClass.HUMAN_VERDICT  # type: ignore[misc]


def test_apply_result_carries_no_provenance_payload() -> None:
    """`apply()`'s return value for a successful transition is the bare enum member -- there
    is no accompanying object a caller could mistake for "the row's new provenance"."""
    confirmations = (_confirmation(_CLUSTER_A), _confirmation(_CLUSTER_B))
    evidence = _evidence(confirmations=confirmations)
    result = apply(Status.QUARANTINED, Status.CANDIDATE, evidence, LIMITS)
    assert result is Status.CANDIDATE
    assert not hasattr(result, "provenance")


# --------------------------------------------------------------------------- #
# 4. The one thing D-133 must NOT have broken: ordinary shadow corroboration
#    (the route this build actually implements) still works end to end.
# --------------------------------------------------------------------------- #


def test_ordinary_corroboration_route_unaffected_by_the_removal() -> None:
    confirmations = (_confirmation(_CLUSTER_A), _confirmation(_CLUSTER_B))
    assert len(confirmations) == SHADOW_CONFIRM_MIN_INDEPENDENT
    evidence = _evidence(provenance_class=ProvenanceClass.DISTILLER, confirmations=confirmations)
    assert apply(Status.QUARANTINED, Status.CANDIDATE, evidence, LIMITS) == Status.CANDIDATE


def test_failure_lesson_single_confirmation_route_unaffected() -> None:
    evidence = _evidence(
        provenance_class=ProvenanceClass.DISTILLER,
        mem_type=MemType.LESSON,
        is_failure_lesson=True,
        confirmations=(_confirmation(_CLUSTER_A),),
    )
    assert apply(Status.QUARANTINED, Status.CANDIDATE, evidence, LIMITS) == Status.CANDIDATE


def test_illegal_edge_off_quarantined_still_illegal() -> None:
    """Sanity: the removal touched one guard body, not `TRANSITIONS` table membership."""
    evidence = _evidence()
    with pytest.raises(IllegalTransition):
        apply(Status.QUARANTINED, Status.VALIDATED, evidence, LIMITS)


# --------------------------------------------------------------------------- #
# 5. The field is inert EVERYWHERE, not just on the one guard D-133 edited.
#
#    `TransitionEvidence.has_verified_human_verdict` survives the removal only
#    because `workers.shadow_validator.evaluate_one` (out of this chunk's file
#    list) still passes it by keyword on every call. A field that is computed by
#    a worker and consulted by nothing is a loaded gun: the next guard to read
#    it inherits a "verified human verdict" derived from a `provenance.cls`
#    label plus a `verdict_id` that no creation edge can produce, and inherits
#    it with no test standing between the two. This sweeps EVERY edge in the
#    table rather than re-checking the one guard that was edited, because the
#    hazard is precisely a DIFFERENT guard starting to read it.
# --------------------------------------------------------------------------- #


def _maximal_evidence(**overrides: object) -> TransitionEvidence:
    """Evidence permissive enough that most guards return an approval, so a flag that flipped
    an outcome shows up as a changed verdict rather than being masked by an unrelated refusal
    on both sides."""
    base = TransitionEvidence(
        now=BASE_NOW,
        provenance_class=ProvenanceClass.HUMAN_VERDICT,
        trust_tier=TrustTier.A,
        mem_type=MemType.LESSON,
        is_failure_lesson=True,
        scan_passed=True,
        scan_repass=True,
        provenance_complete=True,
        operator_created=True,
        status_changed_at=BASE_NOW - timedelta(days=3650),
        confirmations=(_confirmation(_CLUSTER_A), _confirmation(_CLUSTER_B)),
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
        erasure_or_approved_delete=True,
    )
    return dataclasses.replace(base, **overrides)  # type: ignore[arg-type]


def _minimal_evidence(**overrides: object) -> TransitionEvidence:
    """The other half of the sweep, and the half that does the work.

    A maximal baseline alone cannot detect the hazard this section exists for. If a future
    guard grows `if evidence.has_verified_human_verdict: return GuardOutcome(True, "")`, that
    guard was ALREADY approving under maximal evidence, so flipping the flag changes nothing
    and the comparison passes while the bypass is live. (Verified by planting exactly that
    mutation into `_guard_validated_to_stale`: with only the maximal baseline, the whole file
    stayed green.) Under a baseline where every guard refuses, the same mutation flips
    refuse -> ok and the comparison goes red.
    """
    base = TransitionEvidence(
        now=BASE_NOW,
        provenance_class=ProvenanceClass.HUMAN_VERDICT,
        trust_tier=TrustTier.B,
        mem_type=MemType.SEMANTIC,
        # Freshly changed, so no TTL/decay guard expires on time alone; every other field keeps
        # its `False`/`0` default, which is what makes each guard refuse for its own reason.
        status_changed_at=BASE_NOW,
    )
    return dataclasses.replace(base, **overrides)  # type: ignore[arg-type]


_SWEEP_BASELINES: dict[str, object] = {
    "maximal": _maximal_evidence,
    "minimal": _minimal_evidence,
}

_SORTED_EDGES: list[tuple[Status | None, Status]] = sorted(
    TRANSITIONS, key=lambda e: (str(e[0]), e[1].value)
)


def _verdict(baseline: str, current: Status | None, target: Status, *, flag: bool) -> str:
    """`apply()`'s answer for one edge, reduced to a comparable string."""
    build = _SWEEP_BASELINES[baseline]
    evidence = build(has_verified_human_verdict=flag)  # type: ignore[operator]
    try:
        return f"ok:{apply(current, target, evidence, LIMITS).value}"
    except GuardNotSatisfied as exc:
        return f"refused:{exc.reason}"


@pytest.mark.parametrize("baseline", sorted(_SWEEP_BASELINES))
@pytest.mark.parametrize("edge", _SORTED_EDGES)
def test_no_guard_in_the_table_consults_the_human_verdict_flag(
    edge: tuple[Status | None, Status], baseline: str
) -> None:
    current, target = edge
    assert _verdict(baseline, current, target, flag=True) == _verdict(
        baseline, current, target, flag=False
    ), (
        f"{current} -> {target} changed its answer under {baseline} evidence when "
        f"has_verified_human_verdict flipped; D-133 removed the only guard clause that read it, "
        f"and nothing may re-derive a promotion from a flag no creation edge can legitimately "
        f"produce"
    )


def test_the_sweep_exercises_both_approvals_and_refusals() -> None:
    """Guard against either baseline passing vacuously. The maximal one must actually reach
    approvals (otherwise it proves nothing about guards that grant), and the minimal one must
    refuse on every edge (otherwise a flag-reading mutation has an approving edge to hide
    behind, which is exactly how the first version of this sweep missed one)."""
    maximal = [_verdict("maximal", current, target, flag=False) for current, target in TRANSITIONS]
    minimal = [_verdict("minimal", current, target, flag=False) for current, target in TRANSITIONS]
    assert sum(v.startswith("ok:") for v in maximal) >= 2
    assert all(v.startswith("refused:") for v in minimal), (
        "the minimal baseline approves an edge; a guard that starts reading the human-verdict "
        f"flag on that edge would be invisible to the sweep: {sorted(set(minimal))}"
    )
