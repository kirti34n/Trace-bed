"""Shared statistical machinery for governance decisions that must not have two authors
(D-118, D-093, D-126).

BEFORE THIS MODULE EXISTED, `api.reports._bh_adjusted_p_values` and
`workers.killswitch.benjamini_hochberg` were two independent implementations of the
Benjamini-Hochberg step-up procedure, typed out twice by two different chunks. D-118 records that
class of defect as live: "the number an operator reads in the dashboard is not the number that
arms the kill switch".

THEY DID NOT AGREE. That was verified, not assumed, before this module was written: a randomised
differential run over the two shipped implementations found roughly 4,500 disagreeing inputs in
200,000 trials, every one of them at a rank boundary. Two worked examples, both reproduced by
`tests/phase3/test_bh_single_authority.py`:

  * `p = (0.1, 0.1, 0.1)` at `alpha = 0.1`. Exact arithmetic rejects all three (at rank 3,
    `p*m <= k*alpha` is an equality). The step-up float form `min(1, p*m/rank) <= alpha` computes
    `0.1*3/3 = 0.10000000000000002 > 0.1` and rejects NONE. A missed trigger.
  * `p = (0.03, 0.729, (1/5)*0.05, 0.548, 0.93)` at `alpha = 0.05`, where the third entry is the
    double `0.010000000000000002`. Exact arithmetic rejects none. The rank-threshold float form
    `p <= (rank/m)*alpha` recomputes the same rounded-up threshold on the right-hand side, finds
    equality, and REJECTS. A spurious trigger -- a kill switch disabling a memory type on a
    rounding artefact.

So the question "which of the two originals was right" has one answer: NEITHER, and neither in a
way the other could be patched to match. `p <= (rank/m)*alpha` rounds the threshold up (false
positives); `p*m/rank <= alpha` rounds the statistic up (false negatives). They are two different
roundings of one exact inequality, and no amount of care about which `<=` faces which way removes
the divergence, because the divergence is in the arithmetic and not in the algorithm.

ONE EXACT COMPUTATION, TWO SHAPES. `_exact_adjusted` computes the step-up adjusted value per
hypothesis in `fractions.Fraction`, which is exact over the inputs (every Python float is a dyadic
rational, and `m`/`rank` are integers -- so no rounding happens anywhere between the caller's
p-values and the answer). The two public functions are two READINGS of that one result:

  * `bh_adjusted_p_values` -> `float` per hypothesis: the "q-value" a dashboard shows, because an
    operator wants the number, not just a verdict.
  * `benjamini_hochberg` -> `bool` per hypothesis: rejected at `alpha`, because a kill switch acts
    on a yes/no.

`adjusted_(k) <= alpha` and the classic "largest rank k with `p_(k) <= (k/m)*alpha`, reject every
rank <= k" rule are THE SAME SET in exact arithmetic (Benjamini & Hochberg 1995's own monotonicity
result). That is not taken on faith either: `tests/phase3/test_bh_single_authority.py` implements
the classic rule independently in `Fraction` and differential-tests the two over 200,000 randomised
inputs weighted onto the rank boundaries where any disagreement would live.

ROUNDING, STATED RATHER THAN HIDDEN. `benjamini_hochberg` compares the EXACT adjusted value to
`alpha`; `bh_adjusted_p_values` returns `float(exact)`, correctly rounded. Because rounding is to
nearest, `float(exact) < alpha` implies `exact <= alpha` and `float(exact) > alpha` implies
`exact > alpha` -- so the displayed q-value and the boolean can differ in exactly one situation:
`float(exact) == alpha` while `exact` is a hair above it, where the boolean says "not rejected"
and the displayed number reads as a tie. That is a display artefact of one double, in the
conservative direction, and it is pinned as a theorem in the test file rather than left as a
surprise. The alternative -- defining the boolean off the rounded float so the two always agree --
is exactly the false-negative bug listed above, and a kill switch that fails to fire is not a
better trade than a dashboard tie that reads ambiguously.

COST. `Fraction` is slower than `float` by roughly two orders of magnitude. Neither caller is on
the 300ms hot path: `api.reports.get_lift_report` corrects one hypothesis per
`(agent_type_id, mem_type)` cell of an admin report, and `workers.killswitch.evaluate_grid`
corrects one per cell of a grid whose size PLAN.md section 6 discusses at ~20. Exactness is
affordable here precisely because the grid is small, and it is worth buying because the decision
is a governance decision.

`workers.killswitch.benjamini_hochberg` still exists as a separate function today --
`workers/killswitch.py` is not this chunk's to edit (hard rule 8), so replacing its local
definition with `from tracebed.workers.statistics import benjamini_hochberg` is a CONTRACT GAP for
whoever owns that file next. That swap is a BEHAVIOUR CHANGE, not a no-op: it removes the spurious
boundary triggers documented above. `tests/phase3/test_bh_single_authority.py` names the exact
inputs on which the two differ and asserts this module matches the exact reference on each, so the
gap is measured rather than merely mentioned.
"""

from __future__ import annotations

from collections.abc import Sequence
from fractions import Fraction

from tracebed.workers.lift import DEFAULT_BH_ALPHA

__all__ = ["benjamini_hochberg", "bh_adjusted_p_values"]

_ONE: Fraction = Fraction(1)


def _validated(p_values: Sequence[float]) -> None:
    """Every p-value must lie in `[0, 1]`.

    Applied by BOTH public shapes, which is a tightening on the numeric shape:
    `api.reports._bh_adjusted_p_values`, the function `bh_adjusted_p_values` replaces, validated
    nothing. It has to now -- `Fraction(float('nan'))` raises a bare `ValueError` from deep inside
    the arithmetic, and a NaN reaching the sort would silently produce an ordering that depends on
    which comparisons Timsort happened to make. Both callers already guarantee the range
    (`workers.lift.LiftEstimate.__post_init__` refuses a `p_value` outside `[0, 1]`, and
    `directional_p_value` maps `[0, 1]` into `[0, 1]`), so this is unreachable in production; it
    exists so that a future caller that does not guarantee it gets an error naming the value
    instead of a plausible-looking number.
    """
    for p in p_values:
        if not 0.0 <= p <= 1.0:
            raise ValueError(f"p-value out of [0, 1]: {p!r}")


def _exact_adjusted(p_values: Sequence[float]) -> list[Fraction]:
    """The step-up adjusted value per hypothesis, in EXACT arithmetic, in input order.

    `adjusted_(k) = min(adjusted_(k+1), min(1, p_(k) * m / k))` walked from the largest rank down,
    so the result is monotone non-decreasing in rank. `Fraction(p) * m / rank` involves no rounding
    at any step -- that is the whole point of this function existing separately from the two public
    readings of it (module docstring). Callers must have validated `p_values` first; `Fraction`
    raises on a non-finite input rather than producing a wrong answer, but the message would name
    the arithmetic instead of the offending p-value.
    """
    m = len(p_values)
    order = sorted(range(m), key=lambda i: p_values[i])
    adjusted = [_ONE] * m
    running_min = _ONE
    for rank in range(m, 0, -1):
        idx = order[rank - 1]
        candidate = min(_ONE, Fraction(p_values[idx]) * m / rank)
        running_min = min(running_min, candidate)
        adjusted[idx] = running_min
    return adjusted


def bh_adjusted_p_values(p_values: Sequence[float]) -> list[float]:
    """Benjamini-Hochberg adjusted ("q-value") p-values, in the SAME order as `p_values`.

    The dashboard reading of `_exact_adjusted`, correctly rounded to `float`. `benjamini_hochberg`
    below is the other reading of the same computation; see the module docstring for the single
    situation in which the two can appear to disagree by one double, and why the boolean is the one
    that stays exact.

    An empty input returns an empty list rather than raising: zero hypotheses have nothing to
    correct for, which is a legitimate call from `api.reports.get_lift_report` on a project with no
    observed cells.
    """
    if len(p_values) == 0:
        return []
    _validated(p_values)
    return [float(a) for a in _exact_adjusted(p_values)]


def benjamini_hochberg(p_values: Sequence[float], *, alpha: float = DEFAULT_BH_ALPHA) -> list[bool]:
    """The Benjamini-Hochberg step-up procedure: whether each entry is rejected (significant after
    correction) at `alpha`, in the SAME order as `p_values`.

    `reject_(k) = (exact adjusted_(k) <= alpha)`, which is provably the same rejection set as the
    classic "largest rank k with `p_(k) <= (k/m)*alpha`, reject every rank <= k" rule -- in exact
    arithmetic, which is why this module does the arithmetic exactly (module docstring: the two
    shipped float forms of that same identity disagreed with each other on ~2% of randomised
    inputs, in opposite directions).

    Validation order matches `workers.killswitch.benjamini_hochberg`'s original exactly, because
    `tests/phase3/test_killswitch.py::...alpha=1.5` on an EMPTY list asserts the alpha check fires
    first: `alpha` outside the open interval `(0, 1)` raises before the empty-input shortcut, and
    the p-value range check runs after it.
    """
    if not 0.0 < alpha < 1.0:
        raise ValueError(f"alpha must be in (0, 1), got {alpha!r}")
    if len(p_values) == 0:
        return []
    _validated(p_values)
    threshold = Fraction(alpha)
    return [a <= threshold for a in _exact_adjusted(p_values)]
