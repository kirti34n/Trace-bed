"""operator_edit — NOT an adapter (D-032; PLAN.md §7).

Proves the distinction the task asks for made structural: `operator_edit`
supersedes a memory directly through `domain.state_machine.apply` — the same
and only mechanism every status change in this codebase uses — and there is
no code path from its signature or its compiled body into
`dispatch_feedback`/`ScorerPort.record_outcome` for a caller to find, because
none of its parameters could construct one.
"""

from __future__ import annotations

import inspect
from datetime import UTC, datetime

import pytest

from tracebed.adapters.feedback.base import operator_edit
from tracebed.domain.enums import MemType, ProvenanceClass, TrustTier
from tracebed.domain.errors import GuardNotSatisfied, IllegalTransition
from tracebed.domain.state_machine import Status, TransitionEvidence, TransitionLimits

pytestmark = pytest.mark.phase3

_NOW = datetime(2026, 1, 1, tzinfo=UTC)

_LIMITS = TransitionLimits(
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


def _operator_evidence(**overrides: object) -> TransitionEvidence:
    base: dict[str, object] = {
        "now": _NOW,
        "provenance_class": ProvenanceClass.OPERATOR,
        "trust_tier": TrustTier.B,
        "mem_type": MemType.SEMANTIC,
        "contradiction_equal_or_stronger": True,
    }
    base.update(overrides)
    return TransitionEvidence(**base)  # type: ignore[arg-type]


# --------------------------------------------------------------------------- #
# Behavioural: it supersedes directly, through the one state machine.
# --------------------------------------------------------------------------- #


def test_operator_edit_supersedes_validated_directly() -> None:
    result = operator_edit(current=Status.VALIDATED, evidence=_operator_evidence(), limits=_LIMITS)
    assert result is Status.SUPERSEDED


def test_operator_edit_requires_operator_provenance_class() -> None:
    """An adapter-sourced evidence object (e.g. built from a verdict/correction
    signal) must never reach this bypass, even if every other field happens
    to line up."""
    evidence = _operator_evidence(provenance_class=ProvenanceClass.HUMAN_VERDICT)
    with pytest.raises(ValueError, match="OPERATOR"):
        operator_edit(current=Status.VALIDATED, evidence=evidence, limits=_LIMITS)


def test_operator_edit_still_refuses_without_a_real_contradiction() -> None:
    """`operator_edit` is a bypass of the *scorer*, never of the state
    machine's own guard — insufficient evidence still raises exactly like a
    direct `state_machine.apply` call would."""
    evidence = _operator_evidence(contradiction_equal_or_stronger=False)
    with pytest.raises(GuardNotSatisfied):
        operator_edit(current=Status.VALIDATED, evidence=evidence, limits=_LIMITS)


def test_operator_edit_refuses_an_edge_the_table_does_not_contain() -> None:
    """Table membership is checked before any guard, exactly like `apply()`
    itself — `operator_edit` adds no edge that PLAN.md §5's table lacks."""
    with pytest.raises(IllegalTransition):
        operator_edit(current=Status.QUARANTINED, evidence=_operator_evidence(), limits=_LIMITS)


def test_operator_edit_matches_a_direct_state_machine_apply_call() -> None:
    """`operator_edit` performs no transition `state_machine.apply` itself
    would not authorise — it is a thin, named wrapper around exactly one
    edge, not a second way to compute a status."""
    from tracebed.domain.state_machine import apply

    evidence = _operator_evidence()
    assert operator_edit(current=Status.VALIDATED, evidence=evidence, limits=_LIMITS) == apply(
        Status.VALIDATED, Status.SUPERSEDED, evidence, _LIMITS
    )


# --------------------------------------------------------------------------- #
# Structural: cannot reach the scorer.
# --------------------------------------------------------------------------- #


def test_operator_edit_signature_carries_no_scoring_parameters() -> None:
    """No `AdapterClass`, no `r`, no `w`, no `ScorerPort`, no `FeedbackEvent`
    — there is nothing in this signature a caller could thread into
    `dispatch_feedback` even by mistake."""
    params = set(inspect.signature(operator_edit).parameters)
    forbidden = {"adapter", "adapter_class", "r", "w", "weight", "scorer", "event", "event_id"}
    assert params.isdisjoint(forbidden)
    assert params == {"current", "evidence", "limits"}


def test_operator_edit_body_never_references_scoring_machinery() -> None:
    """A static property of the compiled function itself, not merely of its
    signature: nothing in `operator_edit`'s body names the scorer, an
    adapter class, or the dispatcher — there is no reference for a future
    edit to accidentally wire up."""
    forbidden_names = {
        "ScorerPort",
        "AdapterClass",
        "dispatch_feedback",
        "resolve_weight",
        "record_outcome",
        "FeedbackEvent",
        "scorer",
    }
    referenced = set(operator_edit.__code__.co_names)
    assert referenced.isdisjoint(forbidden_names)


def test_operator_edit_is_not_exported_as_a_feedback_adapter() -> None:
    """`adapters.feedback.__init__` exports exactly the four adapter classes
    plus `operator_edit` itself — never anything that would let a caller
    construct a `FeedbackAdapter` whose `adapter_class` claims to be an
    operator edit (no such `AdapterClass` member exists to claim, per
    `test_adapter_class_enum_has_exactly_four_members_no_operator`)."""
    import tracebed.adapters.feedback as pkg

    adapter_classes = {pkg.VerdictAdapter, pkg.CorrectionAdapter, pkg.DownstreamAdapter, pkg.ImplicitAdapter}
    assert pkg.operator_edit not in adapter_classes
    assert not hasattr(pkg.operator_edit, "adapter_class")
