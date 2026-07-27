"""Pytest wrapper around `harness/consolidation_regression.py` (CUTTABLE harness;
PLAN.md §7 Phase 2 gate / §8 improvement 4). The module-level harness function is the
source of truth; this file turns its report into pytest assertions for CI.
"""

from __future__ import annotations

import pytest

from harness.consolidation_regression import (
    ConsolidationRegressionReport,
    _observed_indices,
    run_consolidation_regression,
)

pytestmark = pytest.mark.phase2


def test_retention_is_100_percent_on_every_sweep_at_gate_scale() -> None:
    """The consolidation regression harness is PLAN.md §8's CUTTABLE improvement 4, not a
    §7 Phase 2 gate clause -- an earlier version of this docstring quoted a "verbatim" gate
    sentence ("20 facts across 30 sweeps, retention reported per sweep and asserted at 100%")
    that appears in neither plan. The scale below is this harness's own choice; what §8 asks
    of it is that it "asserts information retention across simulated sweeps", which is what
    100% retention on every one of 30 sweeps means. Deliberately NOT wired into
    `harness/phase2_gate.py`: a gate that imported it would stop it being cuttable (PLAN.md
    §8's promise is that cutting a CUTTABLE improvement "removes a bounded module and its
    tests, nothing else").
    """
    report = run_consolidation_regression(n_facts=20, n_sweeps=30)

    assert len(report.sweeps) == 30
    for sweep_result in report.sweeps:
        assert sweep_result.retention_pct == 100.0, (
            f"sweep {sweep_result.sweep}: retained {sweep_result.retained}/{sweep_result.total} "
            f"({sweep_result.retention_pct:.1f}%) -- retention decay across sweeps is exactly "
            "the brevity-bias signal this gate exists to catch"
        )
    assert report.ok
    assert report.min_retention_pct == 100.0


def test_every_sweep_actually_did_something() -> None:
    """A harness whose sweeps are all no-ops would trivially report 100%
    retention without exercising the AMEND path at all. Each sweep's
    observation text changes (module docstring), so every sweep after the
    first must emit at least one delta."""
    report = run_consolidation_regression(n_facts=20, n_sweeps=30)
    assert all(s.deltas_emitted > 0 for s in report.sweeps)


def test_every_sweep_withholds_some_facts_from_its_observation() -> None:
    """The premise the retention figure rests on. If every sweep re-stated all
    20 facts, 100% retention would be true and empty -- a consolidator that
    retired anything absent from `incoming` would never be given the chance to,
    and the ACE regression this gate exists for would pass clean."""
    report = run_consolidation_regression(n_facts=20, n_sweeps=30)

    assert all(s.observed < s.total for s in report.sweeps)
    assert all(s.observed > 0 for s in report.sweeps)
    assert report.unobserved_carried_forward > 0


def test_every_fact_is_withheld_on_some_sweep_and_observed_on_others() -> None:
    """Rotation, not a fixed split: a fact that is never withheld proves
    nothing about carry-forward, and one that is never observed proves nothing
    about surviving an AMEND."""
    n_facts, n_sweeps = 20, 30
    withheld: dict[int, int] = dict.fromkeys(range(n_facts), 0)
    for sweep in range(1, n_sweeps + 1):
        observed = set(_observed_indices(n_facts, sweep))
        for i in range(n_facts):
            if i not in observed:
                withheld[i] += 1

    assert all(0 < count < n_sweeps for count in withheld.values())


def test_retention_holds_at_a_different_scale_too() -> None:
    report = run_consolidation_regression(n_facts=5, n_sweeps=10)
    assert report.min_retention_pct == 100.0
    assert report.ok


def test_report_min_retention_matches_the_worst_sweep() -> None:
    report = run_consolidation_regression(n_facts=8, n_sweeps=5)
    assert report.min_retention_pct == min(s.retention_pct for s in report.sweeps)


@pytest.mark.parametrize(("n_facts", "n_sweeps"), [(0, 5), (5, 0), (-1, 5)])
def test_degenerate_scales_are_rejected_not_reported_on(n_facts: int, n_sweeps: int) -> None:
    """`n_facts=0` divides by zero computing retention; `n_sweeps=0` produces a
    report whose every assertion passes vacuously. Both must raise rather than
    hand back a PASS that measured nothing."""
    with pytest.raises(ValueError):
        run_consolidation_regression(n_facts=n_facts, n_sweeps=n_sweeps)


def test_a_report_with_no_sweeps_cannot_be_constructed() -> None:
    with pytest.raises(ValueError):
        ConsolidationRegressionReport(n_facts=1, n_sweeps=0, sweeps=())
