"""The Phase 2 gate runner (PLAN.md §7 Phase 2 — "Gate:" paragraph, verbatim):

    "seeded failure traces -> expected Tier A notes, and no substring >= 8
    bytes from any tool error body appears in any note (the Pydantic
    `input_value=` fixture is in the corpus). Seeded injection payload in a
    tool error body never reaches candidate (scan wired on the parser path —
    the Phase 3-only scan ordering bug is dead). Staleness injection green
    (flip tool def -> dependents stale -> two strikes retire). 30-simulated
    -day soak (injectable clock): net vault growth rate strictly decreasing
    week-over-week, with a computed projected plateau date (the observed
    -plateau gate was arithmetically unpassable: 0.5 -> 0.15 at 5%/wk ~= 164
    days). Sweep cost measured to scale with vault size, not trace volume.
    Baseline-walk drill: monotone drift attack trips the clamp alert and
    divergence alarm. STOP."

Same discipline as `harness/phase0_gate.py` and `harness/phase1_gate.py`
(both read first, matched here): runs `pytest -m phase2` once (so every
assertion below is drawn from the SAME execution, never two runs that could
disagree), the three static gates (`license_check.py`, `raw_sql_lint.py`,
`purity_check.py` — Phase 2 does not touch `hotpath/`, but the task brief is
explicit that the purity gate is CI-blocking and must be reconfirmed, not
assumed), plus four DIRECT library calls for the concrete numbers a bare
JUnit pass/fail cannot carry on its own: `harness.staleness_injection.
run_staleness_injection`, `harness.soak.run_soak`, `harness.sweep_cost.
run_sweep_cost_drill`, `harness.baseline_walk.run_baseline_walk` — then
renders `gate_report_phase2.md` mapping every result onto the six PLAN.md §7
Phase 2 clauses above, plus the baseline static-gates clause.

THE REPORT MUST NOT LIE (`harness/phase0_gate.py`'s own words, carried
through `harness/phase1_gate.py` unchanged, carried through here unchanged).
Every assertion is one of exactly four verdicts:

  * ``PASS``             — every test/call backing this assertion ran and
                            passed.
  * ``FAIL``              — at least one test/call backing it ran and failed.
  * ``SKIPPED-NO-STACK``  — at least one test backing it could not run
                            (integration-marked, no Postgres/Valkey/S3) and
                            none of the ones that DID run failed.
  * ``INCOMPLETE-DATA``   — this runner found ZERO tests matching the
                            assertion's selector at all — a defect in the
                            gate report's own grouping, never folded silently
                            into SKIPPED-NO-STACK.

The overall verdict is ``PASS`` only when every one of the SEVEN assertions
below (the six PLAN.md §7 clauses plus the static-gates baseline) is
individually ``PASS`` AND no `-m phase2` test anywhere skipped, tracked or
not (mirrors `harness/phase0_gate.py`'s own `test_gate_smoke.py`-pinned
behaviour: a skip is "this was not verified", never folded into a green top
line). Unlike `harness/phase1_gate.py`'s sixth clause (the latency bench,
deliberately excluded from the verdict per D-035 — informational only),
EVERY clause here is CI-blocking: PLAN.md §7 Phase 2 names all six as the
gate, with no "informational" carve-out anywhere in it.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

REPO_ROOT = Path(__file__).resolve().parent.parent
PYTHON = sys.executable

# Mirrors `harness/phase0_gate.py` / `harness/phase1_gate.py`'s own note: a
# direct script run (`python harness/phase2_gate.py`) puts only `harness/` on
# `sys.path[0]`, so `import harness.soak` etc below would fail with
# `ModuleNotFoundError` despite `harness/__init__.py` existing right next to
# this file. Idempotent and harmless under pytest's own collection.
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

Verdict = Literal["PASS", "FAIL", "SKIPPED-NO-STACK", "INCOMPLETE-DATA"]

__all__ = ["main", "run_gate"]


# --------------------------------------------------------------------------- #
# JUnit XML parsing — the one source of truth for every pytest-backed
# assertion. Duplicated from `harness/phase0_gate.py` / `harness/phase1_gate.py`
# deliberately, not imported: those helpers are module-private (leading
# underscore, not in `__all__`), and per-chunk fake/helper duplication is an
# accepted convention in this codebase (PHASE0-CONTRACT.md §13.1's own note).
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class Case:
    classname: str
    name: str
    status: Literal["passed", "failed", "error", "skipped"]
    message: str | None


def _parse_junit(path: Path) -> list[Case]:
    tree = ET.parse(path)  # noqa: S314 - our own pytest-generated file, not untrusted input
    root = tree.getroot()
    suites = [root] if root.tag == "testsuite" else list(root.findall("testsuite"))
    cases: list[Case] = []
    for suite in suites:
        for tc in suite.findall("testcase"):
            status: Literal["passed", "failed", "error", "skipped"] = "passed"
            message: str | None = None
            failure = tc.find("failure")
            error = tc.find("error")
            skipped = tc.find("skipped")
            if failure is not None:
                status, message = "failed", failure.get("message")
            elif error is not None:
                status, message = "error", error.get("message")
            elif skipped is not None:
                status, message = "skipped", skipped.get("message")
            cases.append(
                Case(classname=tc.get("classname", ""), name=tc.get("name", ""), status=status, message=message)
            )
    return cases


def _select(
    cases: list[Case],
    *,
    classname_contains: str | None = None,
    classname_contains_any: tuple[str, ...] | None = None,
    names: tuple[str, ...] | None = None,
) -> list[Case]:
    out = []
    for c in cases:
        if classname_contains is not None and classname_contains not in c.classname:
            continue
        if classname_contains_any is not None and not any(k in c.classname for k in classname_contains_any):
            continue
        if names is not None and c.name not in names:
            continue
        out.append(c)
    return out


@dataclass(frozen=True, slots=True)
class Tally:
    passed: int
    failed: int
    skipped: int
    total: int

    @property
    def verdict(self) -> Verdict:
        if self.total == 0:
            return "INCOMPLETE-DATA"
        if self.failed:
            return "FAIL"
        if self.skipped:
            return "SKIPPED-NO-STACK"
        return "PASS"


def _tally(cases: list[Case]) -> Tally:
    passed = sum(1 for c in cases if c.status == "passed")
    failed = sum(1 for c in cases if c.status in ("failed", "error"))
    skipped = sum(1 for c in cases if c.status == "skipped")
    return Tally(passed=passed, failed=failed, skipped=skipped, total=len(cases))


def _fmt_tally(t: Tally) -> str:
    return f"{t.passed} passed, {t.failed} failed, {t.skipped} skipped ({t.total} total)"


def _worse(a: Verdict, b: Verdict) -> Verdict:
    """Combine two verdicts for one assertion backed by both a pytest
    selection AND a direct library call — FAIL beats everything, then
    INCOMPLETE-DATA, then SKIPPED-NO-STACK, then PASS. Mirrors
    `harness/phase0_gate.py::_worst`'s severity ordering for its
    seven-leak-probe combination, generalised to two inputs."""
    order: dict[Verdict, int] = {"PASS": 0, "SKIPPED-NO-STACK": 1, "INCOMPLETE-DATA": 2, "FAIL": 3}
    return a if order[a] >= order[b] else b


# --------------------------------------------------------------------------- #
# Subprocess steps.
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class ProcResult:
    label: str
    command: tuple[str, ...]
    returncode: int
    stdout: str
    duration_s: float

    @property
    def ok(self) -> bool:
        return self.returncode == 0


def _run(label: str, args: list[str], *, timeout_s: float, cwd: Path = REPO_ROOT) -> ProcResult:
    """Never raises on a non-zero exit or a timeout — both are gate findings,
    not runner crashes. Forces UTF-8 stdout, matching
    `harness/phase0_gate.py`'s own fix for a stock Windows console (cp1252)
    crashing `scripts/license_check.py`'s box-drawing glyph output."""
    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"
    start = datetime.now(UTC)
    try:
        proc = subprocess.run(  # noqa: S603 - fixed argv (our own scripts), no shell, no untrusted input
            [PYTHON, *args],
            cwd=cwd,
            env=env,
            capture_output=True,
            text=True,
            timeout=timeout_s,
            check=False,
        )
        duration = (datetime.now(UTC) - start).total_seconds()
        return ProcResult(
            label=label,
            command=tuple(args),
            returncode=proc.returncode,
            stdout=(proc.stdout or "") + (proc.stderr or ""),
            duration_s=duration,
        )
    except subprocess.TimeoutExpired as exc:
        duration = (datetime.now(UTC) - start).total_seconds()
        return ProcResult(
            label=label,
            command=tuple(args),
            returncode=124,
            stdout=f"TIMEOUT after {timeout_s}s\n"
            + (exc.stdout.decode("utf-8", "replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")),
            duration_s=duration,
        )


def _run_pytest_phase2(junit_path: Path, *, timeout_s: float) -> tuple[ProcResult, list[Case]]:
    result = _run(
        "pytest -m phase2",
        ["-m", "pytest", "-m", "phase2", "-q", f"--junitxml={junit_path}"],
        timeout_s=timeout_s,
    )
    if not junit_path.exists():
        return result, []
    try:
        cases = _parse_junit(junit_path)
    except ET.ParseError:
        cases = []
    return result, cases


# --------------------------------------------------------------------------- #
# The six PLAN.md §7 Phase 2 gate clauses, plus the static-gates baseline.
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class AssertionReport:
    number: int
    title: str
    verdict: Verdict
    detail: str
    measurements: tuple[str, ...] = ()


def _assertion_zero_passthrough(cases: list[Case]) -> AssertionReport:
    """"seeded failure traces -> expected Tier A notes, and no substring >= 8
    bytes from any tool error body appears in any note (the Pydantic
    `input_value=` fixture is in the corpus)." Backed entirely by
    `tests/phase2/test_zero_passthrough.py`, which checks every fixture in
    `tests/fixtures/scan_corpus/tool_error_bodies.jsonl` with a genuine
    rolling 8-byte window (not a naive containment check) plus a 200-sample
    property test over random binary-ish bodies."""
    selected = _select(cases, classname_contains="test_zero_passthrough")
    t = _tally(selected)
    return AssertionReport(
        1,
        "Tier A notes: zero-byte passthrough (no >=8-byte substring of any tool error body)",
        t.verdict,
        _fmt_tally(t),
    )


_SCAN_GATE_TEST_NAMES: tuple[str, ...] = (
    "test_a_note_the_scan_rejects_is_never_written",
    "test_a_scan_rejection_returns_the_run_its_cap_slot",
    "test_the_verdict_handed_to_the_writer_verifies_against_the_written_content",
    "test_undeclared_tool_id_never_reaches_a_note",
    "test_out_of_charset_tool_identity_is_refused_at_read_time",
    "test_a_run_that_declares_no_manifest_yields_no_tier_a_records",
    "test_a_second_run_start_cannot_widen_the_declared_manifest",
    "test_an_oversized_manifest_declares_nothing_rather_than_everything",
)


def _assertion_injection_never_candidate(cases: list[Case]) -> AssertionReport:
    """"Seeded injection payload in a tool error body never reaches
    candidate (scan wired on the parser path — the Phase 3-only scan
    ordering bug is dead)." Backed by the `tests/phase2/test_extractors.py`
    tests that name exactly this: an injection-shaped `tool_id` the scan
    rejects is never written (`writer.inserted == []`), the registry gate
    refuses an undeclared/oversized-manifest tool identity before a note is
    even built, and the written `ScanVerdict` is checked against the actual
    written content — the whole chain D-024 exists to close."""
    selected = _select(cases, classname_contains="test_extractors", names=_SCAN_GATE_TEST_NAMES)
    t = _tally(selected)
    return AssertionReport(
        2,
        "Seeded injection payload in a tool error body never reaches candidate",
        t.verdict,
        _fmt_tally(t),
    )


def _assertion_staleness_injection(cases: list[Case]) -> AssertionReport:
    """"Staleness injection green (flip tool def -> dependents stale -> two
    strikes retire)." Backed by `tests/phase2/test_invalidator.py` /
    `tests/phase2/test_revalidation.py` (JUnit) AND a direct
    `harness.staleness_injection.run_staleness_injection()` call, which
    drives the REAL `Invalidator` + `RevalidationWorker` through the exact
    scenario and reports the concrete dependent/non-dependent counts."""
    from harness.staleness_injection import render_text, run_staleness_injection

    selected = _select(cases, classname_contains_any=("test_invalidator", "test_revalidation"))
    t = _tally(selected)

    report = run_staleness_injection()
    verdict = _worse(t.verdict, "PASS" if report.ok else "FAIL")
    measurements = (render_text(report),)
    return AssertionReport(
        3,
        "Staleness injection: flip tool def -> dependents stale -> two strikes retire",
        verdict,
        _fmt_tally(t) + f"; direct drill: {'PASS' if report.ok else 'FAIL'}",
        measurements,
    )


def _assertion_soak(*, days: int) -> AssertionReport:
    """"30-simulated-day soak (injectable clock): net vault growth rate
    strictly decreasing week-over-week, with a computed projected plateau
    date." No dedicated `-m phase2` test module exists for this (it is the
    centrepiece drill this chunk's own file list adds); backed entirely by a
    direct `harness.soak.run_soak()` call, driving `workers.scheduler.Scheduler`
    + the real `NoveltyGate`/`state_machine.apply`/`run_all_sweeps` for real,
    on a `FakeClock`, with zero database."""
    from harness.soak import render_text, run_soak

    report = run_soak(days=days)
    verdict: Verdict = "PASS" if report.ok else "FAIL"
    return AssertionReport(
        4,
        "30-simulated-day soak: net vault growth strictly decreasing week-over-week "
        "with a computed projected plateau date",
        verdict,
        f"strictly_decreasing={report.strictly_decreasing}, "
        f"projected_plateau={report.plateau.projected_date.date().isoformat() if report.plateau.projected_date else 'None'}",
        (render_text(report),),
    )


def _assertion_sweep_cost(cases: list[Case]) -> AssertionReport:
    """"Sweep cost measured to scale with vault size, not trace volume."
    Backed by `tests/phase2/test_ttl_sweeps.py::
    test_run_all_sweeps_covers_all_three_and_scales_with_memory_rows_not_traces`
    (JUnit) AND a direct `harness.sweep_cost.run_sweep_cost_drill()` call,
    which reports BOTH curves (vault fixed / trace varied, and trace fixed /
    vault varied) rather than a single before/after point."""
    from harness.sweep_cost import render_text, run_sweep_cost_drill

    selected = _select(cases, classname_contains="test_ttl_sweeps")
    t = _tally(selected)

    report = run_sweep_cost_drill()
    verdict = _worse(t.verdict, "PASS" if report.ok else "FAIL")
    simulated_note = (
        "SIMULATED — and one half of it is a construction, not a measurement. "
        "`harness.sweep_cost` calls `trace_row_count` \"an inert label the sweeps never read\", "
        "so \"cost is independent of trace volume\" is true of the drill BY CONSTRUCTION and "
        "proves only that no sweep query mentions traces. The vault-size curve is the half with "
        "content, and it is measured against an in-memory vault split evenly across three "
        "statuses, not against Postgres."
    )
    return AssertionReport(
        5,
        "Sweep cost scales with vault size, not trace volume (SIMULATED)",
        verdict,
        _fmt_tally(t) + f"; direct drill: {'PASS' if report.ok else 'FAIL'}",
        (simulated_note, render_text(report)),
    )


def _assertion_baseline_walk(cases: list[Case]) -> AssertionReport:
    """"Baseline-walk drill: monotone drift attack trips the clamp alert and
    divergence alarm." Backed by `tests/phase2/test_baseline_drift.py` (JUnit
    — including
    `test_monotone_drift_attack_trips_clamp_alert_and_divergence_alarm`
    itself) AND a direct `harness.baseline_walk.run_baseline_walk()` call for
    the concrete day each watchdog fired."""
    from harness.baseline_walk import render_text, run_baseline_walk

    selected = _select(cases, classname_contains="test_baseline_drift")
    t = _tally(selected)

    report = run_baseline_walk()
    verdict = _worse(t.verdict, "PASS" if report.ok else "FAIL")
    return AssertionReport(
        6,
        "Baseline-walk drill: monotone drift attack trips the clamp alert and divergence alarm",
        verdict,
        _fmt_tally(t) + f"; direct drill: {'PASS' if report.ok else 'FAIL'}",
        (render_text(report),),
    )


def _assertion_static_gates(
    license_result: ProcResult, raw_sql_result: ProcResult, purity_result: ProcResult
) -> AssertionReport:
    """Not one of PLAN.md §7 Phase 2's six named clauses, but part of the
    unconditional baseline this task brief states must not regress:
    `license_check.py` / `raw_sql_lint.py` / `purity_check.py` all green.
    Phase 2 touches no `hotpath/` file, but the task brief is explicit that
    the purity gate is CI-blocking and must be reconfirmed here, not merely
    assumed unchanged."""
    ok = license_result.ok and raw_sql_result.ok and purity_result.ok
    verdict: Verdict = "PASS" if ok else "FAIL"
    detail = (
        f"license_check.py: exit={license_result.returncode} ({'PASS' if license_result.ok else 'FAIL'}); "
        f"raw_sql_lint.py: exit={raw_sql_result.returncode} ({'PASS' if raw_sql_result.ok else 'FAIL'}); "
        f"purity_check.py: exit={purity_result.returncode} ({'PASS' if purity_result.ok else 'FAIL'})"
    )
    return AssertionReport(7, "License + raw-SQL lint + purity gate green (baseline, must not regress)", verdict, detail)


# --------------------------------------------------------------------------- #
# Orchestration + rendering.
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class GateRun:
    generated_at: str
    overall_verdict: Literal["PASS", "FAIL", "INCOMPLETE"]
    assertions: tuple[AssertionReport, ...]
    pytest_result: ProcResult
    pytest_tally: Tally
    license_result: ProcResult
    raw_sql_result: ProcResult
    purity_result: ProcResult
    known_gaps: tuple[str, ...] = field(default_factory=tuple)
    untracked_failures: tuple[Case, ...] = field(default_factory=tuple)
    untracked_skips: tuple[Case, ...] = field(default_factory=tuple)


_KNOWN_GAPS: tuple[str, ...] = (
    "The two TTL sweeps (`lifecycle.quarantine_ttl_days`=30, `candidate_ttl_days`=45) "
    "correctly never fire inside `harness/soak.py`'s 30-day window: every row this soak "
    "creates enters `candidate` and no row is 45 days old by day 30. The soak still runs "
    "`workers.sweeps.run_all_sweeps` every simulated day (so the scheduling wiring itself "
    "is exercised, not assumed) -- its zero effect here is expected, not a defect, and is "
    "exactly what `harness/sweep_cost.py`'s separate, purpose-built repo sizes prove "
    "instead (real rows already past their TTL/status thresholds).",
    "`harness/soak.py`'s vault-growth curve is driven by a DECLARED, deterministic weekly "
    "discovery schedule (front-loaded, strictly decreasing by construction) rather than a "
    "sampled/stochastic arrival process -- every number this report shows for that clause "
    "is still MEASURED off the real repository state after the real `NoveltyGate` / "
    "`state_machine.apply` / `Scheduler` ran, never copied from the schedule's own "
    "arithmetic, but the schedule's SHAPE (how fast a real fleet's condition space gets "
    "discovered) is this harness's own modelling choice, not a measurement of a real fleet.",
    "The projected-plateau date (D-012's corrected reading of this gate clause) is computed "
    "against a harness-defined completion criterion (`_PLATEAU_THRESHOLD` = fewer than one "
    "new memory item per week) -- there is no PLAN.md §6 config field for 'what counts as "
    "plateaued', because this is a reporting convention for the projection, not a governed "
    "threshold; a different threshold moves the projected date without moving the "
    "underlying (real, measured) trend.",
    "This machine has no Docker/Postgres/Valkey, so nothing below exercises a real "
    "`stores.pg.repo.Repo`; every drill in this report (staleness injection, sweep cost, "
    "the soak, the baseline walk) runs against the in-memory `MemoryLifecycleRepoPort` / "
    "`DerivedStateStorePort` doubles the Phase 2 worker chunks themselves were built and "
    "tested against -- consistent with those chunks' own reported contract gaps (no "
    "Postgres-backed implementation of either port exists yet anywhere in the tree).",
    "`invalidation_event`/`derived_state` have no queue topic or scheduled drain wiring "
    "the real-time webhook/poller path into `Invalidator.process_event` /"
    "`DerivedStateWriter.update` in the live process (reported by the `invalidator` and "
    "`derived-state` chunks themselves) -- this gate's drills call those workers directly, "
    "proving the LOGIC the gate clauses name, not the still-missing production wiring.",
)

_TRACKED_CLASSNAME_KEYWORDS: tuple[str, ...] = (
    "test_zero_passthrough",
    "test_extractors",
    "test_invalidator",
    "test_revalidation",
    "test_ttl_sweeps",
    "test_baseline_drift",
)


def _untracked_failures(cases: list[Case]) -> tuple[Case, ...]:
    """Every failed/errored `-m phase2` case outside the six tracked clauses
    above -- so a real failure in, say, `test_novelty.py`, `test_gc.py`,
    `test_consolidator.py`, `test_derived_state.py`, `test_prefix_builder.py`,
    `test_jit_trigger.py` or `test_worker_runner.py` can never be invisible
    just because it falls outside this file's six groupings. Mirrors
    `harness/phase0_gate.py` / `harness/phase1_gate.py`'s own
    `_untracked_failures` exactly."""
    return tuple(
        c
        for c in cases
        if c.status in ("failed", "error") and not any(k in c.classname for k in _TRACKED_CLASSNAME_KEYWORDS)
    )


def _untracked_skips(cases: list[Case]) -> tuple[Case, ...]:
    """Every SKIPPED `-m phase2` case outside the six tracked clauses. Load
    -bearing, not belt-and-braces (mirrors `harness/phase0_gate.py`'s own
    docstring on this): PASS requires that everything under `-m phase2`
    actually RAN, not merely that the six selected groups did."""
    return tuple(
        c
        for c in cases
        if c.status == "skipped" and not any(k in c.classname for k in _TRACKED_CLASSNAME_KEYWORDS)
    )


def run_gate(
    *,
    out_path: Path,
    pytest_timeout_s: float = 600.0,
    script_timeout_s: float = 120.0,
    soak_days: int = 30,
) -> GateRun:
    junit_path = REPO_ROOT / ".phase2_gate_junit.xml"

    pytest_result, cases = _run_pytest_phase2(junit_path, timeout_s=pytest_timeout_s)
    pytest_tally = _tally(cases)

    license_self_test = _run(
        "license_check.py --self-test", ["scripts/license_check.py", "--self-test"], timeout_s=script_timeout_s
    )
    license_real = _run("license_check.py", ["scripts/license_check.py"], timeout_s=script_timeout_s)
    license_combined = ProcResult(
        label="license_check.py",
        command=license_real.command,
        returncode=0 if (license_self_test.ok and license_real.ok) else 1,
        stdout=license_self_test.stdout + "\n" + license_real.stdout,
        duration_s=license_self_test.duration_s + license_real.duration_s,
    )

    raw_sql_self_test = _run(
        "raw_sql_lint.py --self-test", ["scripts/raw_sql_lint.py", "--self-test"], timeout_s=script_timeout_s
    )
    raw_sql_real = _run("raw_sql_lint.py", ["scripts/raw_sql_lint.py"], timeout_s=script_timeout_s)
    raw_sql_combined = ProcResult(
        label="raw_sql_lint.py",
        command=raw_sql_real.command,
        returncode=0 if (raw_sql_self_test.ok and raw_sql_real.ok) else 1,
        stdout=raw_sql_self_test.stdout + "\n" + raw_sql_real.stdout,
        duration_s=raw_sql_self_test.duration_s + raw_sql_real.duration_s,
    )

    purity_self_test = _run(
        "purity_check.py --self-test", ["scripts/purity_check.py", "--self-test"], timeout_s=script_timeout_s
    )
    purity_real = _run("purity_check.py", ["scripts/purity_check.py"], timeout_s=script_timeout_s)
    purity_combined = ProcResult(
        label="purity_check.py",
        command=purity_real.command,
        returncode=0 if (purity_self_test.ok and purity_real.ok) else 1,
        stdout=purity_self_test.stdout + "\n" + purity_real.stdout,
        duration_s=purity_self_test.duration_s + purity_real.duration_s,
    )

    assertions = (
        _assertion_zero_passthrough(cases),
        _assertion_injection_never_candidate(cases),
        _assertion_staleness_injection(cases),
        _assertion_soak(days=soak_days),
        _assertion_sweep_cost(cases),
        _assertion_baseline_walk(cases),
        _assertion_static_gates(license_combined, raw_sql_combined, purity_combined),
    )

    untracked_failures = _untracked_failures(cases)
    untracked_skips = _untracked_skips(cases)

    overall: Literal["PASS", "FAIL", "INCOMPLETE"]
    if any(a.verdict == "FAIL" for a in assertions) or pytest_tally.failed > 0:
        overall = "FAIL"
    elif any(a.verdict != "PASS" for a in assertions) or untracked_skips:
        overall = "INCOMPLETE"
    else:
        overall = "PASS"

    run = GateRun(
        generated_at=datetime.now(UTC).isoformat(),
        overall_verdict=overall,
        assertions=assertions,
        pytest_result=pytest_result,
        pytest_tally=pytest_tally,
        license_result=license_combined,
        raw_sql_result=raw_sql_combined,
        purity_result=purity_combined,
        known_gaps=_KNOWN_GAPS,
        untracked_failures=untracked_failures,
        untracked_skips=untracked_skips,
    )
    out_path.write_text(render_markdown(run), encoding="utf-8")
    junit_path.unlink(missing_ok=True)
    return run


def render_markdown(run: GateRun) -> str:
    lines: list[str] = []
    w = lines.append
    w("# Phase 2 gate report")
    w("")
    w(f"Generated: {run.generated_at}")
    w("")
    w(f"## Overall verdict: **{run.overall_verdict}**")
    w("")
    if run.overall_verdict == "PASS":
        # S34 (fidelity audit): the verdict rule keys on skipped tests, so the phases with the
        # LEAST real-stack exposure get the greenest verdicts -- this phase reads PASS partly
        # BECAUSE it contains no integration-marked tests to skip. Disclosed here, beside the
        # verdict, rather than in prose 300 lines below it.
        w(
            "> **What this PASS does and does not mean.** Every clause below executed and "
            "passed against in-memory doubles. This phase contributes no integration-marked "
            "tests. Four of the ten worker ports M3 enumerates now DO have a Postgres "
            "implementation (`EmbeddingRepoPort`, `CorroborationRepoPort`, "
            "`MemoryEditRepoPort`, `ForensicsRepoPort` -- D-128), and not one of those "
            "statements has ever been EXECUTED: no Docker/Postgres on this machine, and their "
            "integration tests skip. The other six ports (PLAN.md §11 M3) still have no "
            "implementation at all. So a green verdict here is evidence about LOGIC, and is "
            "not evidence that any of it has ever run against a database. The verdict rule "
            "keys on skipped tests, and a phase with no integration tests has none to skip."
        )
        w("")
    if run.overall_verdict == "INCOMPLETE":
        w(
            "> INCOMPLETE means at least one assertion below could not be verified (a "
            "selector matched zero tests, or a direct drill could not run) -- it is "
            "**not** a pass. See the per-assertion table and Known Gaps section."
        )
        w("")
    elif run.overall_verdict == "FAIL":
        w("> At least one assertion below FAILED. See the per-assertion table.")
        w("")

    w("## The six PLAN.md §7 Phase 2 gate clauses (plus the static-gates baseline)")
    w("")
    w("| # | Assertion | Verdict | Detail |")
    w("|---|---|---|---|")
    for a in run.assertions:
        detail = a.detail.replace("|", "\\|")
        w(f"| {a.number} | {a.title} | **{a.verdict}** | {detail} |")
    w("")
    for a in run.assertions:
        if a.measurements:
            w(f"**Assertion {a.number} detail:**")
            w("")
            w("```")
            for m in a.measurements:
                w(m)
            w("```")
            w("")

    w("## `pytest -m phase2`")
    w("")
    w(
        f"- exit code: {run.pytest_result.returncode} "
        f"({'OK' if run.pytest_result.ok else 'NONZERO'}, {run.pytest_result.duration_s:.1f}s)"
    )
    w(f"- {_fmt_tally(run.pytest_tally)}")
    w("")
    w("<details><summary>pytest output (tail)</summary>")
    w("")
    w("```")
    tail = run.pytest_result.stdout.strip().splitlines()[-60:]
    w("\n".join(tail))
    w("```")
    w("")
    w("</details>")
    w("")

    w("## Static gates")
    w("")
    w("| Script | Verdict | Exit |")
    w("|---|---|---|")
    for r in (run.license_result, run.raw_sql_result, run.purity_result):
        verdict = "PASS" if r.ok else "FAIL"
        w(f"| {r.label} | {verdict} | {r.returncode} |")
    w("")

    if run.untracked_failures:
        w("## Failures outside the six tracked clauses")
        w("")
        w(
            "These `-m phase2` failures do not belong to any of the six tracked clauses "
            "above, but they are real and are why the overall verdict is **FAIL** even if "
            "every row in the table above reads PASS."
        )
        w("")
        for c in run.untracked_failures:
            w(f"- `{c.classname}::{c.name}` — {c.status}: {c.message or '(no message)'}")
        w("")

    if run.untracked_skips:
        w("## Tests that did not run, outside the six tracked clauses")
        w("")
        w(
            f"{len(run.untracked_skips)} `-m phase2` test(s) were SKIPPED and belong to none "
            "of the six tracked clauses above, so no row in that table reflects them. They "
            "are why the overall verdict cannot be **PASS**: a skip is \"this was not "
            "verified\", and an unverified test must never sit under a green top line."
        )
        w("")
        by_class: dict[str, list[Case]] = {}
        for c in run.untracked_skips:
            by_class.setdefault(c.classname, []).append(c)
        for classname in sorted(by_class):
            group = by_class[classname]
            reason = group[0].message or "(no reason recorded)"
            w(f"- `{classname}` — {len(group)} skipped: {reason}")
        w("")

    w("## Known gaps (reported, not silently papered over)")
    w("")
    for gap in run.known_gaps:
        w(f"- {gap}")
    w("")

    w("---")
    w("")
    w("**STOP.** Present this report to the human. Do not begin Phase 3 without explicit approval (PLAN.md §7).")
    w("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=REPO_ROOT / "gate_report_phase2.md")
    parser.add_argument("--pytest-timeout", type=float, default=600.0)
    parser.add_argument("--script-timeout", type=float, default=120.0)
    parser.add_argument("--soak-days", type=int, default=30)
    args = parser.parse_args(argv)

    run = run_gate(
        out_path=args.out,
        pytest_timeout_s=args.pytest_timeout,
        script_timeout_s=args.script_timeout,
        soak_days=args.soak_days,
    )

    print(f"gate report written to {args.out}")
    print(f"overall verdict: {run.overall_verdict}")
    for a in run.assertions:
        print(f"  [{a.verdict:<16}] {a.number}. {a.title}")

    return 0 if run.overall_verdict == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
