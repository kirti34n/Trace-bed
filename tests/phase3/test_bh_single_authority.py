"""D-118 / D-093's own words: "the one an operator reads in the dashboard is not the one that arms
the kill switch." Before D-126, `api.reports._bh_adjusted_p_values` and
`workers.killswitch.benjamini_hochberg` were two independently-typed Benjamini-Hochberg
implementations. `workers.statistics` is now the one place the arithmetic happens; this file pins
that, and pins that the arithmetic is RIGHT.

FOUR LAYERS, and the third is the one that can actually go red on a subtle mutation:

  1. `api.reports` no longer AUTHORS a Benjamini-Hochberg implementation -- its old private name is
     bound to the exact object `workers.statistics.bh_adjusted_p_values` is.
  2. Known p-value tables, worked out against the textbook step-up definition, pin the actual
     numbers.
  3. AN INDEPENDENT EXACT REFERENCE. `_classic_reject_exact` implements the OTHER standard
     statement of the procedure -- "largest rank k with `p_(k) <= (k/m)*alpha`, reject every rank
     <= k" -- in `fractions.Fraction`, from the definition, not from `workers.statistics`'s code.
     `test_shared_benjamini_hochberg_equals_the_classic_rule_on_randomised_boundary_inputs` runs
     both over inputs deliberately weighted onto the rank boundaries, which is the ONLY region
     where a wrong implementation of this procedure differs from a right one. A table of seven
     hand-picked p-vectors, which is what this file used to contain, misses that region entirely:
     the two shipped float implementations agreed on all seven and disagreed on ~2% of randomised
     inputs.
  4. The float-vs-exact contract, stated as a theorem and tested as one, plus the exact inputs on
     which `workers.killswitch`'s still-separate float copy disagrees with the exact answer -- so
     the outstanding contract gap ("swap killswitch's import") is a measured behaviour change
     rather than a claimed no-op.
"""

from __future__ import annotations

import pathlib
import random
from collections.abc import Sequence
from fractions import Fraction

import pytest

from tracebed.api import reports as reports_module
from tracebed.workers import killswitch as killswitch_module
from tracebed.workers import statistics as statistics_module
from tracebed.workers.statistics import benjamini_hochberg, bh_adjusted_p_values

pytestmark = pytest.mark.phase3


def _classic_reject_exact(p_values: Sequence[float], alpha: float) -> list[bool]:
    """The classic step-up rule, in exact arithmetic, written from the definition.

    Deliberately NOT the adjusted-p-value formulation `workers.statistics` uses: this is the OTHER
    way the procedure is stated, so agreement between the two is evidence about the procedure and
    not an echo of one implementation. `Fraction(p) * m <= rank * Fraction(alpha)` is the
    cross-multiplied form of `p <= (rank/m)*alpha` with no division and therefore no rounding.
    """
    m = len(p_values)
    if m == 0:
        return []
    a = Fraction(alpha)
    order = sorted(range(m), key=lambda i: p_values[i])
    largest_k = 0
    for rank, idx in enumerate(order, start=1):
        if Fraction(p_values[idx]) * m <= rank * a:
            largest_k = rank
    reject = [False] * m
    for rank, idx in enumerate(order, start=1):
        if rank <= largest_k:
            reject[idx] = True
    return reject


# --------------------------------------------------------------------------- #
# Known p-value tables.
# --------------------------------------------------------------------------- #

# Ten hypotheses, none of which clears alpha=0.05 after correction -- the classic textbook
# illustration of why raw p < 0.05 (true for the first five entries) is not "significant after
# correction".
_TEN_HYPOTHESES = (0.01, 0.02, 0.03, 0.04, 0.05, 0.06, 0.07, 0.08, 0.09, 0.20)
_TEN_HYPOTHESES_ADJUSTED = (0.1, 0.1, 0.1, 0.1, 0.1, 0.1, 0.1, 0.1, 0.1, 0.2)
_TEN_HYPOTHESES_REJECT_AT_05 = (False,) * 10

# Fifteen hypotheses with exactly one rejection at alpha=0.05 -- exercises the "some but not all"
# case the all-False table above cannot.
_FIFTEEN_HYPOTHESES = (
    0.001, 0.008, 0.039, 0.041, 0.042, 0.06, 0.074, 0.205,
    0.212, 0.216, 0.222, 0.251, 0.269, 0.275, 0.34,
)
_FIFTEEN_HYPOTHESES_REJECT_AT_05 = (True,) + (False,) * 14

# Every p equal to alpha. At rank m the step-up comparison is an exact equality, so the correct
# answer is "reject everything" -- and it is the single input on which the float implementation
# this module replaced returned the opposite (see D-126 / workers.statistics's docstring).
_ALL_AT_ALPHA = (0.1, 0.1, 0.1)

_KNOWN_TABLES: tuple[tuple[float, ...], ...] = (
    _TEN_HYPOTHESES,
    _FIFTEEN_HYPOTHESES,
    _ALL_AT_ALPHA,
    (0.5,),
    (0.01,),
    (0.0,),
    (1.0,),
    (),
)
_ALPHAS = (0.01, 0.05, 0.1, 0.2, 0.5)


# --------------------------------------------------------------------------- #
# 1. api.reports authors nothing.
# --------------------------------------------------------------------------- #


def test_reports_private_alias_is_the_shared_object_not_a_copy() -> None:
    """`api.reports._bh_adjusted_p_values` exists only so `tests/phase4/test_report_routes.py`
    (outside this chunk's file list) keeps importing under the old name -- it must be the exact
    object `workers.statistics.bh_adjusted_p_values` is, never a second definition that happens to
    produce the same numbers today."""
    assert reports_module._bh_adjusted_p_values is bh_adjusted_p_values
    assert reports_module.bh_adjusted_p_values is bh_adjusted_p_values


def test_reports_module_defines_no_bh_function_of_its_own() -> None:
    """A `def _bh_adjusted_p_values(...)` reintroduced in `api/reports.py` would leave the identity
    check above red, and this is the assertion that names why."""
    import inspect

    source = inspect.getsource(reports_module)
    assert "def _bh_adjusted_p_values" not in source
    assert "def bh_adjusted_p_values" not in source
    assert "def benjamini_hochberg" not in source


def test_statistics_module_exports_exactly_the_two_bh_shaped_names() -> None:
    assert set(statistics_module.__all__) == {"benjamini_hochberg", "bh_adjusted_p_values"}


def test_workers_lift_does_not_also_export_a_bh_function() -> None:
    """`workers.lift` is where `DEFAULT_BH_ALPHA` and `directional_p_value` live -- it must not
    grow a THIRD Benjamini-Hochberg definition alongside `workers.statistics`'s one."""
    from tracebed.workers import lift as lift_module

    assert "benjamini_hochberg" not in lift_module.__all__
    assert "bh_adjusted_p_values" not in lift_module.__all__
    assert not hasattr(lift_module, "benjamini_hochberg")


# --------------------------------------------------------------------------- #
# 2. Known tables pin the actual numbers.
# --------------------------------------------------------------------------- #


def test_bh_adjusted_p_values_matches_the_documented_ten_hypothesis_table() -> None:
    assert bh_adjusted_p_values(_TEN_HYPOTHESES) == pytest.approx(_TEN_HYPOTHESES_ADJUSTED)


def test_benjamini_hochberg_matches_the_documented_ten_hypothesis_rejections() -> None:
    assert benjamini_hochberg(_TEN_HYPOTHESES, alpha=0.05) == list(_TEN_HYPOTHESES_REJECT_AT_05)


def test_benjamini_hochberg_matches_the_documented_fifteen_hypothesis_rejections() -> None:
    assert benjamini_hochberg(_FIFTEEN_HYPOTHESES, alpha=0.05) == list(
        _FIFTEEN_HYPOTHESES_REJECT_AT_05
    )


def test_every_p_equal_to_alpha_rejects_everything() -> None:
    """The regression that motivated D-126's rewrite. `p_(m) = alpha` satisfies
    `p_(m) <= (m/m)*alpha` as an exact equality, so every hypothesis is rejected. The float step-up
    form this module replaced computed `0.1*3/3 = 0.10000000000000002 > 0.1` and rejected NONE --
    a kill switch that never fires, from one rounding."""
    assert benjamini_hochberg(_ALL_AT_ALPHA, alpha=0.1) == [True, True, True]
    assert benjamini_hochberg((0.05, 0.05), alpha=0.05) == [True, True]


def test_adjusted_values_are_monotone_non_decreasing_in_rank() -> None:
    """The defining property of the step-up adjustment: sorted by raw p, the adjusted values never
    go back down. A `running_min` walked in the wrong direction breaks exactly this."""
    for table in _KNOWN_TABLES:
        adjusted = bh_adjusted_p_values(table)
        by_rank = [adjusted[i] for i in sorted(range(len(table)), key=lambda i: table[i])]
        assert by_rank == sorted(by_rank)


def test_empty_input_is_empty_output_for_both_shapes() -> None:
    assert bh_adjusted_p_values(()) == []
    assert benjamini_hochberg((), alpha=0.05) == []


@pytest.mark.parametrize("bad_alpha", [0.0, 1.0, -0.1, 1.1])
def test_benjamini_hochberg_rejects_alpha_outside_open_unit_interval(bad_alpha: float) -> None:
    with pytest.raises(ValueError, match="alpha must be in"):
        benjamini_hochberg(_TEN_HYPOTHESES, alpha=bad_alpha)
    # Order matters: killswitch's own suite asserts the alpha check fires even on an empty list.
    with pytest.raises(ValueError, match="alpha must be in"):
        benjamini_hochberg((), alpha=bad_alpha)


@pytest.mark.parametrize("bad_p", [-0.01, 1.5, float("nan"), float("inf")])
def test_both_shapes_reject_an_out_of_range_p_value(bad_p: float) -> None:
    """A tightening on the numeric shape, deliberately: the function it replaced validated nothing,
    and a NaN reaching the sort produces an order that depends on which comparisons Timsort made."""
    with pytest.raises(ValueError, match=r"p-value out of \[0, 1\]"):
        benjamini_hochberg((0.01, bad_p), alpha=0.05)
    with pytest.raises(ValueError, match=r"p-value out of \[0, 1\]"):
        bh_adjusted_p_values((0.01, bad_p))


# --------------------------------------------------------------------------- #
# 3. The independent exact reference — the layer that catches subtle mutations.
# --------------------------------------------------------------------------- #


def _boundary_weighted_inputs(seed: int, trials: int) -> list[tuple[list[float], float]]:
    """Random p-vectors deliberately loaded with values sitting exactly on a rank boundary
    (`(k/m)*alpha` as a double), which is the only region where a wrong implementation of this
    procedure differs from a right one. Uniform random p-values almost never land there, which is
    why a purely uniform sweep (or a table of seven hand-picked vectors) proves very little."""
    rng = random.Random(seed)
    cases: list[tuple[list[float], float]] = []
    for _ in range(trials):
        m = rng.randint(1, 8)
        alpha = rng.choice([0.01, 0.05, 0.1, 0.2, 0.5, 0.9])
        p_values: list[float] = []
        for _ in range(m):
            draw = rng.random()
            if draw < 0.45:
                k = rng.randint(1, m)
                p_values.append(min(1.0, (k / m) * alpha))
            elif draw < 0.55:
                p_values.append(rng.choice([0.0, 1.0, alpha]))
            else:
                p_values.append(round(rng.random(), rng.randint(1, 4)))
        cases.append((p_values, alpha))
    return cases


def test_shared_benjamini_hochberg_equals_the_classic_rule_on_randomised_boundary_inputs() -> None:
    """The two standard statements of Benjamini-Hochberg -- "adjusted q <= alpha" and "largest rank
    k with p_(k) <= (k/m)*alpha" -- are the same rejection set. In EXACT arithmetic that is a
    theorem; in float it is false about 2% of the time. `workers.statistics` does the arithmetic
    exactly, so this differential must hold on every input, boundaries included."""
    for p_values, alpha in _boundary_weighted_inputs(seed=20260727, trials=20_000):
        assert benjamini_hochberg(p_values, alpha=alpha) == _classic_reject_exact(
            p_values, alpha
        ), (p_values, alpha)


def test_the_classic_reference_is_not_trivially_agreeable() -> None:
    """A positive control for the reference itself: it must produce both verdicts, and must
    disagree with a deliberately wrong rule. A reference that returned all-False (or simply echoed
    its input's length) would make the differential above vacuous."""
    cases = _boundary_weighted_inputs(seed=1, trials=500)
    verdicts = {v for p_values, alpha in cases for v in _classic_reject_exact(p_values, alpha)}
    assert verdicts == {True, False}
    # An off-by-one in the rank walk must change the answer somewhere.
    disagreed = False
    for p_values, alpha in cases:
        m = len(p_values)
        if m == 0:
            continue
        shifted = _classic_reject_exact(p_values, alpha)
        naive = [Fraction(p) <= Fraction(alpha) / m for p in p_values]  # Bonferroni, not BH
        if shifted != naive:
            disagreed = True
            break
    assert disagreed


def test_known_tables_agree_with_the_exact_reference_at_every_alpha() -> None:
    for table in _KNOWN_TABLES:
        for alpha in _ALPHAS:
            assert benjamini_hochberg(table, alpha=alpha) == _classic_reject_exact(table, alpha), (
                table,
                alpha,
            )


# --------------------------------------------------------------------------- #
# 4. The float/exact contract, and the measured gap against killswitch's copy.
# --------------------------------------------------------------------------- #


def test_the_displayed_q_value_and_the_boolean_can_only_differ_on_an_exact_tie() -> None:
    """`bh_adjusted_p_values` returns `float(exact)`; `benjamini_hochberg` compares `exact` itself.
    Because `float()` rounds to nearest, `float(exact) < alpha` implies `exact <= alpha` and
    `float(exact) > alpha` implies `exact > alpha`. So the displayed number determines the boolean
    everywhere EXCEPT at `float(exact) == alpha`, where the exact value may be a hair above. This
    is the whole of the documented divergence between the two shapes -- asserted, not promised."""
    cases = _boundary_weighted_inputs(seed=555, trials=5_000)
    saw_strictly_below = saw_strictly_above = False
    for p_values, alpha in cases:
        rejected = benjamini_hochberg(p_values, alpha=alpha)
        displayed = bh_adjusted_p_values(p_values)
        for reject, q in zip(rejected, displayed, strict=True):
            if q < alpha:
                saw_strictly_below = True
                assert reject is True, (p_values, alpha, q)
            elif q > alpha:
                saw_strictly_above = True
                assert reject is False, (p_values, alpha, q)
    assert saw_strictly_below and saw_strictly_above


# THE SWAP HAS LANDED (D-128). `workers/killswitch.py` no longer defines the procedure; it
# imports this one, so the name is the SAME function object and there is exactly one author of
# the governing correction. These are the inputs, found by differential search before the swap,
# on which killswitch's own float copy USED to disagree with the exact answer -- kept, and
# re-pointed, because they are the only region where a wrong implementation of this procedure
# differs from a right one, and because the swap's behaviour change should stay legible: each is
# a rank boundary where `p <= (rank/m)*alpha` recomputed the same rounded-up threshold on the
# right-hand side, found equality, and rejected. The correct answer is "no rejection" -- these
# were spurious kill-switch triggers, and they are gone.
_KILLSWITCH_FLOAT_DISAGREEMENTS: tuple[tuple[tuple[float, ...], float], ...] = (
    ((0.03, 0.729, (1 / 5) * 0.05, 0.548, 0.93), 0.05),
    ((0.531, (1 / 5) * 0.05, 0.027, 0.05, (4 / 5) * 0.05), 0.05),
    (((3 / 4) * 0.1, 0.252, 0.05, 0.05), 0.1),
)


def test_killswitch_reexports_the_shared_implementation_rather_than_defining_one() -> None:
    """Identity, not equality of answers: two functions that agree today can drift tomorrow, and
    the whole of D-118's defect was two authors for one number. `is` is the only assertion that
    cannot be satisfied by a second copy that happens to be correct."""
    assert killswitch_module.benjamini_hochberg is benjamini_hochberg
    source = pathlib.Path(killswitch_module.__file__ or "").read_text(encoding="utf-8")
    assert "def benjamini_hochberg(" not in source, (
        "workers/killswitch.py has grown a local definition again -- the re-export is what "
        "makes the kill switch and the dashboard read one number"
    )


@pytest.mark.parametrize(("p_values", "alpha"), _KILLSWITCH_FLOAT_DISAGREEMENTS)
def test_the_kill_switch_no_longer_fires_on_the_boundaries_its_float_copy_fired_on(
    p_values: tuple[float, ...], alpha: float
) -> None:
    """The measured content of the swap, asserted from the kill switch's own import site."""
    exact = _classic_reject_exact(p_values, alpha)
    assert killswitch_module.benjamini_hochberg(p_values, alpha=alpha) == exact
    # The old float rule, restated here so the regression this closes stays named rather than
    # merely absent: it rejected where the exact rule does not.
    m = len(p_values)
    order = sorted(range(m), key=lambda i: p_values[i])
    largest_k = 0
    for rank, idx in enumerate(order, start=1):
        if p_values[idx] <= (rank / m) * alpha:
            largest_k = rank
    old = [False] * m
    for rank, idx in enumerate(order, start=1):
        if rank <= largest_k:
            old[idx] = True
    assert old != exact, "this input no longer discriminates the two roundings"


def test_killswitchs_copy_still_agrees_with_the_shared_one_away_from_the_boundaries() -> None:
    """The two are not arbitrarily different -- away from exact rank boundaries they are the same
    procedure, which is what makes the swap safe to land. A future edit to either that changes the
    answer on ORDINARY inputs (not just boundary ones) is a real divergence and fails here."""
    rng = random.Random(4242)
    compared = 0
    for _ in range(5_000):
        m = rng.randint(1, 8)
        alpha = rng.choice([0.01, 0.05, 0.1, 0.2])
        # Irrational-ish draws: the probability of landing on `(k/m)*alpha` exactly is nil.
        p_values = [rng.random() * 0.3 for _ in range(m)]
        assert killswitch_module.benjamini_hochberg(p_values, alpha=alpha) == benjamini_hochberg(
            p_values, alpha=alpha
        ), (p_values, alpha)
        compared += 1
    assert compared == 5_000


def test_shared_and_killswitch_validation_failures_match() -> None:
    """A caller migrated from one to the other must not discover a validation gap only the old copy
    had."""
    for bad_alpha in (0.0, 1.0, -0.1, 1.1):
        with pytest.raises(ValueError):
            killswitch_module.benjamini_hochberg(_TEN_HYPOTHESES, alpha=bad_alpha)
        with pytest.raises(ValueError):
            benjamini_hochberg(_TEN_HYPOTHESES, alpha=bad_alpha)
    for bad_p in (-0.01, 1.5):
        with pytest.raises(ValueError):
            killswitch_module.benjamini_hochberg((0.01, bad_p), alpha=0.05)
        with pytest.raises(ValueError):
            benjamini_hochberg((0.01, bad_p), alpha=0.05)
