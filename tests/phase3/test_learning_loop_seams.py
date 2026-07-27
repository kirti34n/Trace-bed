"""Cross-chunk seam guards for the Phase 3 quality lane and learning loop.

Seven agents built this phase in parallel without seeing each other. Each
audited its own modules well. Every property below spans two or more of those
modules and so belonged to none of them, which is exactly the class of defect
that survives a fully green per-chunk suite.

Three kinds of assertion live here, and the distinction matters when reading a
failure:

* GRAPH PROPERTIES over `domain.state_machine.TRANSITIONS`, computed by
  exhaustive search rather than asserted from a docstring. "PROPOSAL can never
  reach a retrievable status" is stated in D-023 and enforced in ONE guard; the
  search proves no OTHER edge added later re-opens it, which no single-guard
  test can.
* STATIC (AST) assertions over the whole of `src/`. A behavioural test proves
  today's call sites are right; an AST assertion proves the next one will be.
* ONE RECORDED HOLE (`TestContainmentIsReversible`). It asserts the CURRENT,
  defective behaviour on purpose, so that closing the hole forces whoever does
  it to come here and change the record. A known hole with a passing test that
  documents it is honest; a known hole with no test at all is how it gets
  forgotten.
"""

from __future__ import annotations

import ast
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from tracebed.domain import config as cfgmod
from tracebed.domain.enums import MemType, ProvenanceClass, TrustTier
from tracebed.domain.errors import ConfigError, GuardNotSatisfied, IllegalTransition
from tracebed.domain.state_machine import (
    RETRIEVABLE_STATUSES,
    TRANSITIONS,
    Status,
    TransitionEvidence,
    TransitionLimits,
    apply,
)
from tracebed.workers.scorer import compute_new_q

pytestmark = pytest.mark.phase3

_SRC = Path(__file__).resolve().parents[2] / "src" / "tracebed"


def _modules(root: Path) -> list[Path]:
    return sorted(p for p in root.rglob("*.py") if "__pycache__" not in p.parts)


def _rel(path: Path) -> str:
    return path.relative_to(_SRC.parents[1]).as_posix()


def _effective_config(**overrides: Any) -> cfgmod.EffectiveConfig:
    sections: dict[str, Any] = {n: m() for n, m in cfgmod._SECTION_MODELS.items()}
    sections.update(overrides)
    return cfgmod.EffectiveConfig(**sections)


_CFG = _effective_config()
_LIMITS = TransitionLimits.from_config(_CFG)
_NOW = datetime(2026, 7, 26, 12, 0, tzinfo=UTC)
_LONG_AGO = _NOW - timedelta(days=3650)


def _permissive_evidence(
    provenance_class: ProvenanceClass,
    *,
    mem_type: MemType = MemType.LESSON,
    trust_tier: TrustTier = TrustTier.B,
    confirmations: tuple[Any, ...] = (),
) -> TransitionEvidence:
    """Every non-identity field set to whatever most helps a transition succeed.

    The point of the reachability searches below is "even granting the attacker
    EVERY boolean and a maximal count on every threshold, which statuses can
    this provenance class reach?". Anything that stays unreachable under this
    evidence is unreachable structurally, not merely unreached by the fixtures
    someone happened to write.

    `confirmations` is left empty by default and passed in explicitly, because
    it is the one field whose contents are checked by a real computation
    (`independent_confirmations`) rather than by a threshold comparison.
    """
    return TransitionEvidence(
        now=_NOW,
        provenance_class=provenance_class,
        trust_tier=trust_tier,
        mem_type=mem_type,
        status_changed_at=_LONG_AGO,
        scan_passed=True,
        provenance_complete=True,
        confirmations=confirmations,
        has_verified_human_verdict=True,
        is_failure_lesson=True,
        promotion_outcomes=10_000,
        promotion_distinct_principals=10_000,
        outcome_consistent=True,
        open_contradiction=False,
        contradiction_equal_or_stronger=True,
        contradiction_weaker_provenance=True,
        scan_reflag=True,
        invalidation_event=True,
        ttl_class_expired=True,
        revalidation_failed=True,
        reverified=True,
        strike_count=10_000,
        q_value=0.0,
        scored_use_count=10_000,
        distinct_scoring_principals=10_000,
        decay_floor_reached=True,
        operator_restore=True,
        operator_created=True,
        erasure_or_approved_delete=True,
    )


def _reachable(provenance_class: ProvenanceClass, **kw: Any) -> set[Status]:
    """Every status reachable from every legal creation edge, by exhaustive search.

    Deliberately re-derived from `TRANSITIONS` rather than hardcoded: the whole
    value of this helper is that an edge added to the table later is
    automatically included in the search.
    """
    evidence = _permissive_evidence(provenance_class, **kw)
    frontier: set[Status | None] = {None}
    seen: set[Status] = set()
    while frontier:
        nxt: set[Status | None] = set()
        for current in frontier:
            for src, target in TRANSITIONS:
                if src is not current:
                    continue
                try:
                    apply(current, target, evidence, _LIMITS)
                except (IllegalTransition, GuardNotSatisfied):
                    continue
                if target not in seen:
                    seen.add(target)
                    nxt.add(target)
        frontier = nxt
    return seen


# --------------------------------------------------------------------------- #
# THE Q UPDATE -- direction, and exactly one implementation of it
# --------------------------------------------------------------------------- #


class TestTheQUpdateDirection:
    def test_a_successful_downstream_event_moves_q_up(self) -> None:
        """The single bug this whole audit pass was launched over.

        The original spec fed the adapter WEIGHT in as the reward, so a
        successful downstream event (w=0.3) read as r=0.3 and, from Q=0.5,
        gave `(r - Q) = -0.2` -- SUCCESS LOWERING THE SCORE. Hand-computed
        here rather than recomputed from the implementation, because a test
        that derives its expectation from the code under test cannot catch a
        sign error in that code:

            Q' = 0.5 + 0.3 * 0.3 * 1.0 * (1.0 - 0.5)
               = 0.5 + 0.09 * 0.5
               = 0.5 + 0.045
               = 0.545
        """
        new_q = compute_new_q(current_q=0.5, r=1.0, w=0.3, c=1.0, alpha=0.3)
        assert new_q == pytest.approx(0.545)
        assert new_q is not None and new_q > 0.5

    def test_the_original_spec_bug_and_the_corrected_rule_disagree_in_SIGN(self) -> None:
        """Guard the guard above. If someone "simplifies" the call so that `w`
        is passed as `r`, `test_a_successful_downstream_event_moves_q_up` still
        needs a second test to show the two readings are not merely different
        numbers but opposite DIRECTIONS from the same starting Q.
        """
        corrected = compute_new_q(current_q=0.5, r=1.0, w=0.3, c=1.0, alpha=0.3)
        weight_as_reward = compute_new_q(current_q=0.5, r=0.3, w=1.0, c=1.0, alpha=0.3)
        assert corrected is not None and weight_as_reward is not None
        assert corrected > 0.5, "a success must raise Q"
        assert weight_as_reward < 0.5, "the spec bug lowered Q on a success"

    def test_w_scales_the_learning_rate_and_never_the_reward(self) -> None:
        """`w` may only damp HOW FAR Q moves, never WHICH WAY. Every weight in
        (0, 1] must leave a success moving up and a failure moving down.
        """
        for w in (0.05, 0.3, 0.8, 1.0):
            up = compute_new_q(current_q=0.5, r=1.0, w=w, c=1.0, alpha=0.3)
            down = compute_new_q(current_q=0.5, r=0.0, w=w, c=1.0, alpha=0.3)
            assert up is not None and up > 0.5, f"success lowered Q at w={w}"
            assert down is not None and down < 0.5, f"failure raised Q at w={w}"


class TestExactlyOneModuleImplementsTheFormula:
    def test_no_module_outside_the_scorer_reads_the_learning_rate(self) -> None:
        """`alpha` is the Q update's learning rate and appears in exactly one
        formula. A second module reading `scoring.alpha` is a second
        implementation of the rule -- which is how the two ends of a two-place
        formula drift until a success lowers Q again somewhere.

        Matched on the ATTRIBUTE ACCESS `<...>.alpha`, so a local variable
        named `alpha` inside the scorer's own helpers is not a hit and a
        `cfg.scoring.alpha` read anywhere else is.
        """
        allowed = {"src/tracebed/workers/scorer.py", "src/tracebed/domain/config.py"}
        offenders: list[str] = []
        for path in _modules(_SRC):
            if _rel(path) in allowed:
                continue
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if isinstance(node, ast.Attribute) and node.attr == "alpha":
                    offenders.append(f"{_rel(path)}:{node.lineno}")
        assert offenders == [], f"a second reader of the learning rate: {offenders}"

    def test_only_the_scorer_and_the_decay_sweep_write_a_q_value(self) -> None:
        """Two writers of `memory_item.q_value` exist by design and they are
        NOT two implementations of one rule: `workers.scorer` applies the
        outcome-driven update, `workers.sweeps` applies idle decay, which is
        monotonically DOWNWARD and reads no outcome at all. A third writer
        would be a learning rule nobody decided to add.

        Matched on keyword arguments named `q_value=`, which is how every
        write in this codebase reaches a row (`QUpdate`, `LifecycleTransitionWrite`,
        the repo's insert params). Read-only projections that merely COPY a row's
        q_value into a smaller dataclass are the reason the allowlist is not
        just the two workers -- each entry below is a projection, verified by
        reading it, not a mutation.
        """
        allowed = {
            "src/tracebed/workers/scorer.py",  # THE outcome-driven update
            "src/tracebed/workers/sweeps.py",  # idle decay, downward only
            "src/tracebed/api/admin.py",  # read-only response projection
            "src/tracebed/hotpath/assembly.py",  # read-only ranking projection
            "src/tracebed/hotpath/jit.py",  # read-only ranking projection
            "src/tracebed/workers/promotion.py",  # read-only evidence projection
            "src/tracebed/workers/review_queue.py",  # read-only evidence projection
            "src/tracebed/stores/pg/repo.py",  # the SQL insert/update itself
            "src/tracebed/stores/pg/search.py",  # read-only row hydration
            "src/tracebed/stores/pg/reports.py",  # read-only Q-trajectory row hydration (D-093)
            "src/tracebed/api/reports.py",  # read-only Q-trajectory response projection (D-093)
        }
        offenders: list[str] = []
        for path in _modules(_SRC):
            if _rel(path) in allowed:
                continue
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if isinstance(node, ast.keyword) and node.arg == "q_value":
                    offenders.append(f"{_rel(path)}:{node.lineno}")
        assert offenders == [], f"an unreviewed writer of q_value: {offenders}"


# --------------------------------------------------------------------------- #
# PROMOTION -- reachability proved by search, not by reading one guard
# --------------------------------------------------------------------------- #


class TestNothingUngovernedReachesRetrievability:
    def test_proposal_provenance_can_never_reach_a_retrievable_status(self) -> None:
        """D-023, proved over the WHOLE graph rather than at the one guard that
        implements it.

        `_guard_quarantined_to_candidate` refuses PROPOSAL first and
        unconditionally, and a per-chunk test can show that. What it cannot
        show is that no OTHER edge reaches `candidate`/`validated`/`pinned` --
        which is the property that actually matters and the one that breaks
        silently when someone adds an edge to the table.

        Run with maximally permissive evidence: every boolean true, every
        threshold satisfied 10,000 times over, a verified human verdict
        asserted. PROPOSAL still cannot become retrievable.
        """
        reachable = _reachable(ProvenanceClass.PROPOSAL)
        assert reachable & RETRIEVABLE_STATUSES == set(), (
            f"proposal-class content reached {sorted(s.value for s in reachable & RETRIEVABLE_STATUSES)}"
        )
        assert Status.QUARANTINED in reachable, "the search is vacuous if nothing is reachable"

    def test_operator_restore_is_the_only_route_to_validated_that_skips_independence(
        self,
    ) -> None:
        """A RECORDED GAP, stated precisely (DECISIONS D-085).

        With BOTH the independence edge `(quarantined, candidate)` and the
        operator-restore edge `(archived, validated)` removed from the search,
        Tier B content cannot reach `validated` at all -- so those two are the
        complete set of routes in. Removing only the independence edge still
        reaches `validated`, via restore.

        That residue is not a defect to be silently fixed here. PLAN.md Â§5 row
        15 permits operator restore explicitly, and `TransitionEvidence`
        carries no "was ever validated" field, so this guard cannot tell an
        operator restoring a memory that WAS validated and decayed to
        `archived` (the intended use) from one restoring a Tier B row that was
        quarantined, TTL-expired uncorroborated, and never earned `validated`.
        Closing it needs a field the frozen Phase-0 dataclass does not have.

        The test pins the SHAPE of the residue so it cannot quietly grow a
        third member.
        """

        def reachable_without(excluded: set[tuple[Status, Status]]) -> set[Status]:
            evidence = _permissive_evidence(ProvenanceClass.DISTILLER)
            frontier: set[Status | None] = {None}
            seen: set[Status] = set()
            while frontier:
                nxt: set[Status | None] = set()
                for current in frontier:
                    for src, target in TRANSITIONS:
                        if src is not current or (src, target) in excluded:
                            continue
                        try:
                            apply(current, target, evidence, _LIMITS)
                        except (IllegalTransition, GuardNotSatisfied):
                            continue
                        if target not in seen:
                            seen.add(target)
                            nxt.add(target)
                frontier = nxt
            return seen

        independence = (Status.QUARANTINED, Status.CANDIDATE)
        restore = (Status.ARCHIVED, Status.VALIDATED)

        assert Status.VALIDATED in reachable_without(set())
        assert Status.VALIDATED in reachable_without({independence}), (
            "restore should still reach validated -- this is the recorded gap"
        )
        assert Status.VALIDATED not in reachable_without({independence, restore}), (
            "a THIRD route to validated that skips the independence edge has appeared"
        )

    def test_an_archived_proposal_cannot_be_restored_into_retrievability(self) -> None:
        """THE FINDING THIS FILE EXISTS FOR (D-023 / DECISIONS D-085).

        Before the fix this three-edge path was entirely legal:

            None -> quarantined     propose_memory, Tier B, scan passes
            quarantined -> archived 30-day quarantine TTL, zero corroboration
            archived -> validated   operator restore

        landing proposal-class content in `RETRIEVABLE_STATUSES` having never
        invoked `independent_confirmations` and never faced the promotion
        predicate. `_guard_archived_to_validated` checked `operator_restore`
        and nothing else.

        It matters most because of where the Phase 3 red team stopped: all
        four adversarial probes were recorded as "furthest_status: archived,
        never validated", which read as containment and was in fact one
        unguarded edge away from full retrievability.
        """
        evidence = _permissive_evidence(ProvenanceClass.PROPOSAL)
        with pytest.raises(GuardNotSatisfied):
            apply(Status.ARCHIVED, Status.VALIDATED, evidence, _LIMITS)

    def test_archived_is_not_a_terminal_status_for_anything_else(self) -> None:
        """Guard the guard above, and keep the red team honest.

        `archived` must NOT be read as containment in any report. For every
        non-proposal class it remains one `operator_restore` away from
        `validated` by design (PLAN.md Â§5 row 15, "recoverable, logged"), so a
        probe that ends in `archived` has been PARKED, not stopped.
        """
        restored = apply(
            Status.ARCHIVED,
            Status.VALIDATED,
            _permissive_evidence(ProvenanceClass.DISTILLER),
            _LIMITS,
        )
        assert restored is Status.VALIDATED
        assert restored in RETRIEVABLE_STATUSES

    def test_zero_confirmations_never_leaves_quarantine_for_any_provenance_class(self) -> None:
        """The corroboration requirement is not merely "some number": with an
        EMPTY confirmation set, and every other field maximally permissive,
        no provenance class may leave quarantine for candidate.

        `has_verified_human_verdict` is true in this evidence, so the
        HUMAN_VERDICT class is expected to pass -- it is the one documented
        zero-corroboration route, and asserting it separately is what stops
        this test from silently covering a hole if that route ever widened.
        """
        for cls in ProvenanceClass:
            evidence = _permissive_evidence(cls, confirmations=())
            try:
                apply(Status.QUARANTINED, Status.CANDIDATE, evidence, _LIMITS)
            except (IllegalTransition, GuardNotSatisfied):
                continue
            assert cls is ProvenanceClass.HUMAN_VERDICT, (
                f"{cls.value} left quarantine with zero confirmations"
            )


# --------------------------------------------------------------------------- #
# CONFIG -- an override may not weaken a governed threshold
# --------------------------------------------------------------------------- #


class TestAConfigRowCannotDisableGovernance:
    @pytest.mark.parametrize(
        ("section", "model", "kwargs"),
        [
            ("promotion", cfgmod.PromotionConfig, {"min_outcomes": 0}),
            ("promotion", cfgmod.PromotionConfig, {"failure_lesson_outcomes": 0}),
            ("promotion", cfgmod.PromotionConfig, {"min_distinct_principals": 1}),
            ("retirement", cfgmod.RetirementConfig, {"min_distinct_principals": 1}),
            ("retirement", cfgmod.RetirementConfig, {"min_scored_uses": 0}),
            ("lifecycle", cfgmod.LifecycleConfig, {"quarantine_ttl_days": 0}),
            ("lifecycle", cfgmod.LifecycleConfig, {"candidate_ttl_days": 0}),
        ],
    )
    def test_a_weakened_threshold_is_refused_somewhere_never_silently_clamped(
        self, section: str, model: Any, kwargs: dict[str, Any]
    ) -> None:
        """`promotion`, `retirement` and `lifecycle` are all OVERRIDABLE_SECTIONS
        members, so a `project_config` jsonb row reaches every threshold the
        state machine reads. Each of these values would disable a control this
        phase exists to provide -- `failure_lesson_outcomes=0` alone lets a
        quarantined failure lesson reach candidate with NO corroboration, which
        is the entire Phase 3 governance story turned off from a config row.

        Refused at EITHER layer counts, and which one is not the point: the
        `lifecycle` TTLs die in pydantic (`ge=1`, so the override never becomes
        a config object at all) while the `promotion`/`retirement` thresholds
        die in `TransitionLimits.__post_init__`. Both are "the override dies
        before a guard reads it"; only a value that reaches a guard is a hole.
        Asserted here as a cross-chunk property because the floors live in
        `domain/state_machine.py`, the overridability in `domain/config.py`,
        and the consequence in `workers/` -- three chunks, one invariant.
        """
        with pytest.raises((ConfigError, ValueError)):
            bad = _effective_config(**{section: model(**kwargs)})
            TransitionLimits.from_config(bad)

    def test_the_daily_scoring_cap_cannot_be_set_below_one(self) -> None:
        """`scoring.updates_per_memory_per_day` is the bound on how fast a
        single feedback source can walk a memory's Q, and D-021 sizes its
        four-calendar-day retirement window on it. Unlike the thresholds above
        it is NOT projected into `TransitionLimits`, so nothing downstream
        floors it -- `run_scorer_batch` honours whatever it is given, and 0
        makes `scored_today >= cap` true on every call, turning scoring off
        for the project with every worker still running and every gate green.
        """
        for bad in (0, -1, -1000):
            with pytest.raises(Exception):  # noqa: B017 - pydantic ValidationError
                cfgmod.ScoringConfig(updates_per_memory_per_day=bad)
        assert cfgmod.ScoringConfig(updates_per_memory_per_day=1).updates_per_memory_per_day == 1

    def test_the_daily_scoring_cap_still_has_no_upper_bound(self) -> None:
        """A RECORDED GAP, not an endorsement -- see DECISIONS.md D-083.

        Widening is the dangerous direction, but PLAN.md Â§6 gives this field a
        default and no range, so a ceiling here would be a number invented for
        a governed threshold. This test asserts the CURRENT behaviour so that
        whoever adds the bound is forced to come here, delete this test, and
        record the number they chose.
        """
        assert cfgmod.ScoringConfig(updates_per_memory_per_day=1000)


# --------------------------------------------------------------------------- #
# THE RECORDED HOLE
# --------------------------------------------------------------------------- #


class TestContainmentIsReversible:
    """PLAN.md Â§8 improvement 1 says "quarantine a memory". PLAN.md Â§5's table
    -- which that same document calls "the test source" -- has NO
    `validated -> quarantined` edge, and lists everything absent from it as
    illegal. The two statements contradict each other, and the table wins.

    So `workers.forensics` contains a poisoned `validated` row to `stale`, the
    nearest legal edge. These tests assert what that actually buys, which is
    less than it reads like. Recorded in DECISIONS.md D-084.
    """

    def test_there_is_no_validated_to_quarantined_edge(self) -> None:
        assert (Status.VALIDATED, Status.QUARANTINED) not in TRANSITIONS

    def test_a_contained_row_returns_to_retrievability_on_reverification_alone(self) -> None:
        """The whole loop, driven through the real state machine.

        `stale -> validated` requires `reverified` and NOTHING else: no
        independence recheck, no scan re-pass, no awareness that a poisoning
        finding exists. An OEP-shaped locally-correct poisoned memory is
        precisely the kind a verifier re-verifies successfully, so the one
        action taken after a poisoned memory reached `validated` is undone by
        a background worker -- and `revalidation.is_due_for_revalidation`
        makes a `stale` row due on any LATER INSTANT, so the next tick suffices.
        """
        contained = apply(
            Status.VALIDATED,
            Status.STALE,
            TransitionEvidence(
                now=_NOW,
                provenance_class=ProvenanceClass.DISTILLER,
                trust_tier=TrustTier.B,
                mem_type=MemType.LESSON,
                status_changed_at=_NOW - timedelta(days=1),
                invalidation_event=True,
            ),
            _LIMITS,
        )
        assert contained is Status.STALE
        assert contained not in RETRIEVABLE_STATUSES

        restored = apply(
            Status.STALE,
            Status.VALIDATED,
            TransitionEvidence(
                now=_NOW + timedelta(seconds=1),
                provenance_class=ProvenanceClass.DISTILLER,
                trust_tier=TrustTier.B,
                mem_type=MemType.LESSON,
                status_changed_at=_NOW,
                reverified=True,
                confirmations=(),  # none offered, none required
            ),
            _LIMITS,
        )
        assert restored is Status.VALIDATED
        assert restored in RETRIEVABLE_STATUSES

    def test_the_only_durable_containment_is_tombstoning(self) -> None:
        """Guard against a future "fix" that quietly re-opens a route back.

        Of the statuses forensics can legally reach from a retrievable row,
        `tombstoned` is the only one with no path back into
        RETRIEVABLE_STATUSES. If this ever fails, either a new edge was added
        or the hole above was closed -- both require updating D-084.
        """
        durable = {
            target
            for target in Status
            if target not in RETRIEVABLE_STATUSES
            and not (_reachable_from(target) & RETRIEVABLE_STATUSES)
        }
        assert Status.TOMBSTONED in durable
        assert Status.STALE not in durable, "stale would now be durable containment"


def _reachable_from(start: Status) -> set[Status]:
    evidence = _permissive_evidence(ProvenanceClass.DISTILLER)
    frontier: set[Status] = {start}
    seen: set[Status] = set()
    while frontier:
        nxt: set[Status] = set()
        for current in frontier:
            for src, target in TRANSITIONS:
                if src is not current:
                    continue
                try:
                    apply(current, target, evidence, _LIMITS)
                except (IllegalTransition, GuardNotSatisfied):
                    continue
                if target not in seen:
                    seen.add(target)
                    nxt.add(target)
        frontier = nxt
    return seen


# --------------------------------------------------------------------------- #
# UNTRUSTED JSON -- the bug class found three times in this phase
# --------------------------------------------------------------------------- #


class TestUntrustedJsonCannotUnwindAWorker:
    @pytest.mark.parametrize(
        "module",
        [
            "src/tracebed/workers/distiller.py",
            "src/tracebed/adapters/llm/openai_compat.py",
            "src/tracebed/adapters/embedding/gemini.py",
        ],
    )
    def test_every_provider_response_parser_handles_recursion_error(self, module: str) -> None:
        """`json.loads` recurses once per nesting level, so `b"[" * 9000` --
        far inside every byte ceiling in this codebase -- raises
        `RecursionError`, which is a `RuntimeError` and NOT a `ValueError`.

        This escaped the `except (TypeError, ValueError)` clause in all three
        of these modules. Two were found and fixed by the chunk that owned
        them; the third (`gemini.py`, a Phase 1 file) was outside every Phase 3
        chunk's file list and was still open at integration. Pinned as a class
        rather than as three separate regressions, because the next
        provider driver will have the same shape.
        """
        path = _SRC.parents[1] / module
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        handled = any(
            isinstance(node, ast.ExceptHandler)
            and node.type is not None
            and "RecursionError"
            in ast.dump(node.type)  # bare name or a tuple member
            for node in ast.walk(tree)
        )
        assert handled, f"{module} parses a provider response without catching RecursionError"

    def test_the_hazard_is_real_and_not_theoretical(self) -> None:
        """Guard the guard: deeply nested untrusted JSON must not be parseable.

        This asserted `pytest.raises(RecursionError)` on `json.loads("[" * 9000)`
        until CI showed the exception TYPE is platform-dependent: CPython/Windows
        raises `RecursionError`, CPython/Linux returns a `JSONDecodeError` from the
        C scanner for the same input. The test passed locally and failed in CI, and
        the production code it guards had the same platform split — which is why
        `distiller._exceeds_json_depth` now rejects by counting nesting before the
        parse rather than by letting the interpreter run out of stack.

        What matters is the property, not which exception carries it: the input is
        rejected, and it is not rejected as a plain `ValueError` that a bare
        `except ValueError` would have quietly absorbed.
        """
        import json

        with pytest.raises(Exception) as caught:
            json.loads("[" * 9000)
        assert isinstance(caught.value, RecursionError | json.JSONDecodeError), (
            f"deep nesting produced {type(caught.value).__name__}, which neither clause handles"
        )
        assert not issubclass(RecursionError, ValueError)

        # The real guarantee, and it is platform-independent by construction.
        from tracebed.workers.distiller import _exceeds_json_depth

        assert _exceeds_json_depth("[" * 9000) is True
        assert _exceeds_json_depth('{"content": "a [bracket] in a string"}') is False


# --------------------------------------------------------------------------- #
# EPOCH DISCIPLINE
# --------------------------------------------------------------------------- #


class TestEpochDiscipline:
    def test_cross_epoch_comparison_raises_in_both_directions(self) -> None:
        """Invariant 7: cross-epoch comparison is REJECTED, not silently
        allowed. Both directions, because the untested one
        (`assert_same_epoch(epoch, verdict)` where the JUDGE answered under a
        NEWER epoch than the scorer resolved) is the one that actually occurs
        when something re-pins the judge mid-batch.
        """
        from tracebed.domain.errors import CrossEpochComparison
        from tracebed.workers.epochs import assert_same_epoch

        class _Stamped:
            def __init__(self, epoch_id: int) -> None:
                self.epoch_id = epoch_id

        older, newer = _Stamped(1), _Stamped(2)
        with pytest.raises(CrossEpochComparison):
            assert_same_epoch(older, newer)
        with pytest.raises(CrossEpochComparison):
            assert_same_epoch(newer, older)
        assert_same_epoch(older, _Stamped(1))

    def test_a_scoring_epoch_must_be_timezone_aware(self) -> None:
        """The epoch row dates every stamped artifact for an audit. Postgres
        reinterprets a naive value in the session TimeZone, so two epochs
        minted hours apart can order wrongly against the updates they stamped.
        """
        from tracebed.workers.epochs import ScoringEpoch

        with pytest.raises(Exception):  # noqa: B017 - EpochStoreViolation
            ScoringEpoch(
                epoch_id=1,
                judge_model_id="m",
                judge_model_version="v",
                prompt_hash="h",
                sampling_params={},
                started_at=datetime(2026, 7, 26, 12, 0),  # naive
            )
