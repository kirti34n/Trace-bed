"""The offline fail-open drill must remain a runnable harness gate."""

from __future__ import annotations

from harness.failopen_drill import run_failopen_drill


def test_every_fault_scenario_completes_with_its_declared_outcome() -> None:
    report = run_failopen_drill(n_runs_per_scenario=2)

    assert report.ok
    assert len(report.scenarios) == 6
    assert all(scenario.completed_every_run for scenario in report.scenarios)
    assert all(scenario.outcome_code_correct for scenario in report.scenarios)
