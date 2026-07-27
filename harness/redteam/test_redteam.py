"""PLAN.md section 7 Phase 3 gate: the four-probe red team, the Sybil test,
and the retirement K-1 test. See `probes.py`'s module docstring for how each
scenario is driven end to end through the real governance machinery.
"""

from __future__ import annotations

import pytest

from harness.redteam.probes import (
    probe_correlated_trace_corroboration,
    probe_mpbench_weak_signal,
    probe_oep_locally_correct,
    probe_sleeper_dormancy,
    run_redteam,
    run_retirement_k_minus_one_probe,
    run_sybil_probe,
)
from tracebed.domain.state_machine import Status

pytestmark = pytest.mark.phase3


# --------------------------------------------------------------------------- #
# The headline assertion: all four probes together.
# --------------------------------------------------------------------------- #


def test_all_four_probes_run() -> None:
    report = run_redteam()
    assert len(report.results) == 4


def test_none_of_the_four_probes_ever_reaches_validated() -> None:
    report = run_redteam()
    for result in report.results:
        assert result.reached_validated is False, (
            f"probe {result.probe_id!r} reached validated -- {result.detail}"
        )
    assert report.ok is True


def test_every_probe_reports_a_furthest_status_and_a_stopped_by_reason() -> None:
    report = run_redteam()
    for result in report.results:
        assert result.furthest_status is not None
        assert result.stopped_by.strip() != ""
        assert result.detail.strip() != ""


# --------------------------------------------------------------------------- #
# Probe 1 -- MPBench weak-signal, policy-conformant false precedent.
# --------------------------------------------------------------------------- #


def test_mpbench_probe_is_blocked_by_corroboration_not_by_looking_suspicious() -> None:
    result = probe_mpbench_weak_signal()
    assert result.reached_validated is False
    # It is blocked at exactly 1 independent confirmation (one short of the
    # 2 the guard requires) -- never zero, which would mean the scan (not
    # corroboration) was doing the work.
    assert "1 of >= 2" in result.detail or "1 independent" in result.detail.lower() or "independent_count=1" in result.detail
    assert result.furthest_status in (Status.QUARANTINED, Status.ARCHIVED)


def test_mpbench_probe_eventually_archives_never_promotes() -> None:
    result = probe_mpbench_weak_signal()
    assert result.furthest_status is Status.ARCHIVED


# --------------------------------------------------------------------------- #
# Probe 2 -- OEP locally-correct non-transferable.
# --------------------------------------------------------------------------- #


def test_oep_probe_is_the_trap_it_claims_to_be() -> None:
    """The trap: 4 distinct principals genuinely confirm it. A naive
    "count distinct principals >= 2" rule would promote this. The real
    computable-independence guard must not."""
    result = probe_oep_locally_correct()
    assert result.reached_validated is False
    assert "independent_count=1" in result.detail


def test_oep_probe_eventually_archives_never_promotes() -> None:
    result = probe_oep_locally_correct()
    assert result.furthest_status is Status.ARCHIVED


# --------------------------------------------------------------------------- #
# Probe 3 -- sleeper with dormancy longer than the quarantine TTL.
# --------------------------------------------------------------------------- #


def test_sleeper_probe_is_archived_by_the_ttl_before_activation() -> None:
    result = probe_sleeper_dormancy()
    assert result.reached_validated is False
    assert result.furthest_status is Status.ARCHIVED


def test_sleeper_probe_activation_arrives_too_late_to_matter() -> None:
    """The dormancy window strictly exceeds the quarantine TTL, so the row
    is already archived by the time the attacker submits its confirmations."""
    result = probe_sleeper_dormancy(dormant_days=35)
    assert "day 30" in result.stopped_by or "archived" in result.stopped_by.lower()


@pytest.mark.parametrize("dormant_days", [31, 40, 60])
def test_sleeper_probe_holds_across_dormancy_windows_past_the_ttl(dormant_days: int) -> None:
    result = probe_sleeper_dormancy(dormant_days=dormant_days)
    assert result.reached_validated is False
    assert result.furthest_status is Status.ARCHIVED


# --------------------------------------------------------------------------- #
# Probe 4 -- correlated-trace corroboration.
# --------------------------------------------------------------------------- #


def test_correlated_trace_probe_naive_count_would_have_promoted_it() -> None:
    """20 confirming runs, 20 distinct clusters, ONE principal. A naive
    'count distinct runs' or 'count distinct clusters' rule alone would call
    this massively corroborated; the real guard must still refuse it."""
    result = probe_correlated_trace_corroboration(n_runs=20)
    assert result.reached_validated is False
    assert "independent_count=1" in result.detail
    assert "20" in result.detail


def test_correlated_trace_probe_eventually_archives_never_promotes() -> None:
    result = probe_correlated_trace_corroboration()
    assert result.furthest_status is Status.ARCHIVED


@pytest.mark.parametrize("n_runs", [2, 5, 50])
def test_correlated_trace_probe_holds_regardless_of_run_count(n_runs: int) -> None:
    result = probe_correlated_trace_corroboration(n_runs=n_runs)
    assert result.reached_validated is False


# --------------------------------------------------------------------------- #
# The Sybil test -- item 3: propose_memory twice is NOT corroboration. Ever.
# --------------------------------------------------------------------------- #


def test_propose_memory_twice_never_exits_quarantine() -> None:
    report = run_sybil_probe()
    assert report.two_calls_result.reached_validated is False
    assert report.two_calls_result.furthest_status is not Status.CANDIDATE
    assert report.two_calls_result.furthest_status is not Status.VALIDATED


def test_proposal_class_refuses_even_two_fully_independent_confirmations() -> None:
    """The stress case: this is not "insufficient corroboration" -- it is a
    hard-coded refusal (D-023). Two GENUINELY independent confirmations
    (distinct principal AND distinct cluster each, which is exactly what
    `_guard_quarantined_to_candidate` requires for every OTHER provenance
    class) still never promote a `proposal`-class row."""
    report = run_sybil_probe()
    assert report.two_independent_confirmations_result.reached_validated is False
    assert "D-023" in report.two_independent_confirmations_result.stopped_by


def test_sybil_probe_overall_ok() -> None:
    assert run_sybil_probe().ok is True


# --------------------------------------------------------------------------- #
# Retirement with K-1 distinct principals -- item 4.
# --------------------------------------------------------------------------- #


def test_k_minus_one_principals_routes_to_review_queue_not_retire() -> None:
    report = run_retirement_k_minus_one_probe()
    assert report.k_minus_one.retired is False
    assert report.k_minus_one.routed_to_review is True
    assert report.k_minus_one_row_status is Status.VALIDATED
    assert report.k_minus_one_review_items >= 1


def test_exactly_k_principals_is_the_positive_control_and_does_retire() -> None:
    """Proves this harness is not one that silently never retires anything:
    the identical Q/scored-use preconditions, with exactly K distinct
    principals, DOES retire."""
    report = run_retirement_k_minus_one_probe()
    assert report.k_control.retired is True
    assert report.k_control_row_status is Status.RETIRED


def test_retirement_probe_overall_ok() -> None:
    assert run_retirement_k_minus_one_probe().ok is True
