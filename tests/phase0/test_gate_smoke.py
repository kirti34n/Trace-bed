"""`harness/phase0_gate.py` — tests for the runner whose verdict IS the gate.

PHASE0-CONTRACT.md §13.2 named this file; it was never written, which left the
single most correctness-critical component in Phase 0 verified only by reading
it. A gate that reports FAIL when it should PASS costs an afternoon. A gate that
reports PASS when something did not run is how an unverified isolation property
ships, and it is the exact failure this repository's leak suite exists to
prevent — one level up.

Everything here is offline and drives the runner's pure functions directly:
`_tally`, `_untracked_failures`, `_untracked_skips`, and the overall-verdict
rule. `run_gate` itself spawns pytest and is exercised by actually running the
gate, not from inside the suite it would re-enter.

`harness/` is deliberately outside mypy's configured package scope, so these
imports are untyped from mypy's point of view; the assertions are on values, not
on types.
"""

from __future__ import annotations

from typing import Literal

import pytest
from harness.phase0_gate import (
    Case,
    Tally,
    _tally,
    _untracked_failures,
    _untracked_skips,
)

pytestmark = pytest.mark.phase0


def _case(
    classname: str,
    name: str,
    status: Literal["passed", "failed", "error", "skipped"],
) -> Case:
    return Case(classname=classname, name=name, status=status, message=None)


# --------------------------------------------------------------------------- #
# Tally — the per-assertion verdict.
# --------------------------------------------------------------------------- #


class TestTallyVerdict:
    def test_zero_matched_tests_is_incomplete_data_not_pass(self) -> None:
        """A selector that matches nothing means the report cannot speak to
        that assertion at all. Reporting PASS there would be the gate asserting
        a property from an empty set — vacuously true, and exactly the shape of
        wrongness this whole exercise is guarding against."""
        assert Tally(passed=0, failed=0, skipped=0, total=0).verdict == "INCOMPLETE-DATA"

    def test_any_skip_downgrades_a_pass(self) -> None:
        assert Tally(passed=9, failed=0, skipped=1, total=10).verdict == "SKIPPED-NO-STACK"

    def test_a_failure_beats_a_skip(self) -> None:
        """Precedence matters: a run with both a real failure and an absent
        service must read FAIL, not "we could not tell"."""
        assert Tally(passed=0, failed=1, skipped=8, total=9).verdict == "FAIL"

    def test_all_passed_is_pass(self) -> None:
        assert Tally(passed=10, failed=0, skipped=0, total=10).verdict == "PASS"

    def test_tally_counts_errors_as_failures(self) -> None:
        """A fixture ERROR is not a lesser kind of skip. `tests/phase0/conftest.py`
        spent the whole parallel build one reachable database away from turning
        five modules into setup ERRORs; had that happened, the gate had to call
        it FAIL, not SKIPPED-NO-STACK."""
        cases = [_case("tests.phase0.test_repo_scoping", "t", "error")]
        assert _tally(cases).verdict == "FAIL"


# --------------------------------------------------------------------------- #
# Untracked cases — the false-PASS hole.
# --------------------------------------------------------------------------- #


_UNTRACKED = "tests.phase0.test_repo_scoping"
_TRACKED = "tests.phase0.test_trace_writer"


class TestUntrackedCases:
    def test_an_untracked_failure_is_reported(self) -> None:
        cases = [_case(_UNTRACKED, "t", "failed")]
        assert _untracked_failures(cases) == (cases[0],)

    def test_a_tracked_failure_is_not_double_counted(self) -> None:
        """It is already visible in its own assertion row."""
        assert _untracked_failures([_case(_TRACKED, "t", "failed")]) == ()

    def test_an_untracked_skip_is_reported(self) -> None:
        """THE integration finding. The seven assertions select roughly 600 of
        ~1,500 phase0 tests; every Postgres-backed test in `test_repo_scoping`,
        `test_repo_provenance`, `test_queue`, `test_migrations`,
        `test_partitions`, `test_telemetry` and `test_spend` falls outside all
        seven. Only untracked FAILURES moved the verdict, so a run in which two
        dozen isolation tests never executed could still print PASS."""
        cases = [_case(_UNTRACKED, "t", "skipped")]
        assert _untracked_skips(cases) == (cases[0],)

    def test_a_tracked_skip_is_left_to_its_own_assertion(self) -> None:
        assert _untracked_skips([_case(_TRACKED, "t", "skipped")]) == ()

    def test_passing_cases_are_never_reported(self) -> None:
        cases = [_case(_UNTRACKED, "t", "passed"), _case(_TRACKED, "t", "passed")]
        assert _untracked_failures(cases) == ()
        assert _untracked_skips(cases) == ()


# --------------------------------------------------------------------------- #
# The overall verdict rule, reproduced from `run_gate` and driven directly.
# --------------------------------------------------------------------------- #


def _overall(
    assertion_verdicts: list[str], *, failed: int, untracked_skips: int
) -> str:
    """The exact rule `run_gate` applies, isolated so it can be driven without
    spawning pytest.

    Kept in step with the real one by
    `test_this_rule_matches_run_gates_source` below — a copy that silently
    drifted from the original would be worse than no test, because it would
    report on a rule nobody runs.
    """
    if any(v == "FAIL" for v in assertion_verdicts) or failed > 0:
        return "FAIL"
    if any(v != "PASS" for v in assertion_verdicts) or untracked_skips:
        return "INCOMPLETE"
    return "PASS"


_ALL_PASS = ["PASS"] * 7


class TestOverallVerdict:
    def test_everything_green_and_everything_ran_is_pass(self) -> None:
        """The positive control. Without it, a rule that returned INCOMPLETE
        unconditionally would satisfy every other test in this class."""
        assert _overall(_ALL_PASS, failed=0, untracked_skips=0) == "PASS"

    def test_a_skipped_assertion_can_never_be_pass(self) -> None:
        verdicts = ["PASS", "SKIPPED-NO-STACK", *["PASS"] * 5]
        assert _overall(verdicts, failed=0, untracked_skips=0) == "INCOMPLETE"

    def test_an_empty_selector_can_never_be_pass(self) -> None:
        verdicts = ["PASS", "INCOMPLETE-DATA", *["PASS"] * 5]
        assert _overall(verdicts, failed=0, untracked_skips=0) == "INCOMPLETE"

    def test_untracked_skips_alone_prevent_pass(self) -> None:
        """All seven rows PASS, nothing failed — and the answer is still not
        PASS, because something under `-m phase0` did not run."""
        assert _overall(_ALL_PASS, failed=0, untracked_skips=1) == "INCOMPLETE"

    def test_an_untracked_failure_forces_fail_over_a_green_table(self) -> None:
        assert _overall(_ALL_PASS, failed=1, untracked_skips=0) == "FAIL"

    def test_fail_outranks_incomplete(self) -> None:
        verdicts = ["FAIL", "SKIPPED-NO-STACK", *["PASS"] * 5]
        assert _overall(verdicts, failed=3, untracked_skips=9) == "FAIL"

    def test_this_rule_matches_run_gates_source(self) -> None:
        """Guards the duplication above. `run_gate` spawns a full pytest run,
        so its rule cannot be called from inside this suite; the copy is
        checked against the original's source text instead, which catches the
        realistic drift (a condition added or a clause dropped) even though it
        cannot catch a pure reformatting."""
        import inspect

        from harness import phase0_gate

        source = inspect.getsource(phase0_gate.run_gate)
        for fragment in (
            'if any(a.verdict == "FAIL" for a in assertions) or pytest_tally.failed > 0:',
            'overall = "FAIL"',
            'elif any(a.verdict != "PASS" for a in assertions) or untracked_skips:',
            'overall = "INCOMPLETE"',
            'overall = "PASS"',
        ):
            assert fragment in source, f"run_gate no longer contains: {fragment}"


# --------------------------------------------------------------------------- #
# The report itself.
# --------------------------------------------------------------------------- #


def test_the_committed_gate_report_does_not_claim_pass_without_a_stack() -> None:
    """The artefact a human actually reads. On this machine the leak suite's
    integration half cannot run, so the report must say INCOMPLETE — and must
    say so in words, not only in a table cell."""
    from pathlib import Path

    report = Path(__file__).resolve().parents[2] / "gate_report_phase0.md"
    if not report.is_file():
        pytest.skip("gate_report_phase0.md has not been generated in this tree")

    text = report.read_text(encoding="utf-8")
    verdict_line = next(ln for ln in text.splitlines() if ln.startswith("## Overall verdict:"))

    if "SKIPPED-NO-STACK" in text or "did not run" in text:
        assert "PASS" not in verdict_line, (
            "the report claims PASS while naming tests that did not run:\n" + verdict_line
        )
        assert "INCOMPLETE" in verdict_line
