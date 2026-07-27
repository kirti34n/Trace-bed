"""The Phase 0 gate runner (PHASE-0 Task 18).

Runs, in order: `pytest -m phase0` (which collects every offline AND
integration-marked Phase 0 test, including the leak suite — they share one
run so "0 leaks across all seven classes" and "state machine: full table
coverage" come from the SAME execution, never two runs that could disagree),
`scripts/license_check.py`, `scripts/raw_sql_lint.py`, `scripts/purity_check.py`,
and the fake-runtime SDK-overhead measurement — then renders
`gate_report_phase0.md` mapping every result onto the seven gate assertions
PHASE-0.md states at lines 180-187.

THE REPORT MUST NOT LIE. Every assertion below is one of exactly four
verdicts:

  * ``PASS``             — every test backing this assertion ran and passed.
  * ``FAIL``              — at least one test backing it ran and failed.
  * ``SKIPPED-NO-STACK``  — at least one test backing it could not run
                            (integration-marked, no Postgres/Valkey/S3) and
                            none of the ones that DID run failed.
  * ``INCOMPLETE-DATA``   — this runner found ZERO tests matching the
                            assertion's selector at all. Distinct from
                            SKIPPED-NO-STACK on purpose: this usually means a
                            grouping keyword in *this file* drifted from a
                            test file it is supposed to select, which is a
                            defect in the gate report itself, not a
                            legitimate "no stack" skip — it must never be
                            silently folded into the same bucket.

The overall verdict is ``PASS`` only when every one of the seven assertions
is individually ``PASS``. Any ``SKIPPED-NO-STACK``/``INCOMPLETE-DATA``
anywhere makes the overall verdict ``INCOMPLETE`` (never ``PASS``); any
``FAIL`` anywhere makes it ``FAIL``. This file has no code path that can
print ``PASS`` for an assertion whose tests never executed — the verdict is
always computed from parsed JUnit XML / real subprocess exit codes, never
assumed.
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

# CI (`.github/workflows/ci.yml`) and this module's own docstring both invoke
# this as `python harness/phase0_gate.py` -- a direct script run, which puts
# only `harness/` (not the repo root) on `sys.path[0]`, so `import
# harness.fake_runtime` below would fail with `ModuleNotFoundError` despite
# `harness/__init__.py` existing right next to this file. Idempotent and
# harmless when this module is instead imported as `harness.phase0_gate`
# (pytest's own collection, `python -m harness.phase0_gate`), where the repo
# root is already on the path.
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

Verdict = Literal["PASS", "FAIL", "SKIPPED-NO-STACK", "INCOMPLETE-DATA"]

__all__ = ["main", "run_gate"]


# --------------------------------------------------------------------------- #
# JUnit XML — the one source of truth for every pytest-backed assertion.
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
                Case(
                    classname=tc.get("classname", ""),
                    name=tc.get("name", ""),
                    status=status,
                    message=message,
                )
            )
    return cases


def _select(
    cases: list[Case],
    *,
    classname_contains: str | None = None,
    name_prefix: str | None = None,
    names: tuple[str, ...] | None = None,
) -> list[Case]:
    """`names` selects specific test functions (parametrised ids match on their base name),
    for a clause whose evidence is two or three named tests rather than a whole file."""
    out = []
    for c in cases:
        if classname_contains is not None and classname_contains not in c.classname:
            continue
        if name_prefix is not None and not c.name.startswith(name_prefix):
            continue
        if names is not None and c.name.split("[")[0] not in names:
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
    """Runs one subprocess, capturing combined stdout/stderr. NEVER raises on
    a non-zero exit or on a timeout -- both are gate FINDINGS, not runner
    crashes; the caller decides the verdict from `returncode`/`ok`.

    Forces UTF-8 stdout: a stock Windows console (cp1252) crashes
    `scripts/license_check.py`'s own box-drawing glyph output with
    `UnicodeEncodeError`, which every prior chunk audit flagged as a false
    red on this exact runner. Setting it here, once, is the fix.
    """
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


def _run_pytest_phase0(junit_path: Path, *, timeout_s: float) -> tuple[ProcResult, list[Case]]:
    result = _run(
        "pytest -m phase0",
        ["-m", "pytest", "-m", "phase0", "-q", f"--junitxml={junit_path}"],
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
# The seven PHASE-0.md line-180-187 assertions.
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class AssertionReport:
    number: int
    title: str
    verdict: Verdict
    detail: str
    measurements: tuple[str, ...] = ()


def _fmt_tally(t: Tally) -> str:
    return f"{t.passed} passed, {t.failed} failed, {t.skipped} skipped ({t.total} total)"


def _assertion_1(cases: list[Case]) -> AssertionReport:
    """"complete queryable trace per run; T+2-day feedback joins; replay-safe."

    Backed by `tests/phase0/test_trace_writer.py` (trace completeness,
    duplicate-seq idempotency, sig-hash reorder-stability, incomplete
    sweeping) and `tests/phase0/test_outcome_intake.py` (T+2-day attach by
    run_id, event_id replay -> one row).
    """
    selected = _select(cases, classname_contains="test_trace_writer") + _select(
        cases, classname_contains="test_outcome_intake"
    )
    t = _tally(selected)
    return AssertionReport(
        1,
        "Complete queryable trace per run; T+2-day feedback joins; replay-safe",
        t.verdict,
        _fmt_tally(t),
    )


_LEAK_PROBE_TITLES: dict[int, str] = {
    1: "search-path",
    2: "by-id fetch",
    3: "admin endpoints",
    4: "dashboard API",
    5: "export",
    6: "Valkey collisions",
    7: "RLS bypass",
}


# Worse-than ordering for combining several per-probe verdicts into one
# overall verdict for assertion 2 -- FAIL always wins (a real leak found),
# then INCOMPLETE-DATA (this file's own selector matched nothing, a defect
# in the report), then SKIPPED-NO-STACK (a legitimate "no service" skip),
# then PASS.
_VERDICT_SEVERITY: dict[Verdict, int] = {
    "PASS": 0,
    "SKIPPED-NO-STACK": 1,
    "INCOMPLETE-DATA": 2,
    "FAIL": 3,
}


def _worst(verdicts: list[Verdict]) -> Verdict:
    return max(verdicts, key=lambda v: _VERDICT_SEVERITY[v]) if verdicts else "INCOMPLETE-DATA"


def _assertion_2(cases: list[Case]) -> AssertionReport:
    """"leak suite: 0 leaks across all seven classes." Broken out per probe
    (test names are `test_probeN_...`, `harness/leak_suite/test_leaks.py`'s
    own naming convention exists for exactly this)."""
    leak_cases = _select(cases, classname_contains="leak_suite.test_leaks")
    per_probe: list[str] = []
    per_probe_verdicts: list[Verdict] = []
    for n in range(1, 8):
        probe_cases = _select(leak_cases, name_prefix=f"test_probe{n}_")
        t = _tally(probe_cases)
        per_probe.append(f"probe {n} ({_LEAK_PROBE_TITLES[n]}): {t.verdict} — {_fmt_tally(t)}")
        per_probe_verdicts.append(t.verdict)
    overall = _tally(leak_cases)
    return AssertionReport(
        2,
        "Leak suite: 0 leaks across all seven probe classes",
        _worst(per_probe_verdicts),
        _fmt_tally(overall),
        measurements=tuple(per_probe),
    )


def _assertion_3(cases: list[Case]) -> AssertionReport:
    """"scan corpus: 100% strong-signal rejection; insert-without-verdict
    raises; Tier A zero-passthrough proven."

    THE "insert-without-verdict raises" HALF, stated precisely rather than
    substituted. An earlier version of this runner satisfied the clause by
    observing that `scan_verdict` is a required positional parameter, so
    omitting it is a `TypeError` by construction -- true, and it does not
    touch the failure mode the clause guards, which is a verdict that EXISTS
    but does not belong to this content. Three real tests now back it, and
    they are selected by name so this cannot silently become a tally of
    something else:

      * `test_insert_memory_item_executes_no_sql_when_verdict_is_for_other_content`
        (a verdict minted for different content is refused, with zero SQL issued);
      * `test_insert_memory_item_checks_provenance_before_the_scan_verdict`
        (the order is fixed, so a forged verdict cannot slip past a provenance
        failure);
      * `test_scan_verdict_type.py`'s claim that a `ScanVerdict` cannot be
        constructed outside `core.scans` at all.

    The arity half remains true by construction and is no longer cited as
    evidence for anything.
    """
    verdict_tests = (
        "test_insert_memory_item_executes_no_sql_when_verdict_is_for_other_content",
        "test_insert_memory_item_checks_provenance_before_the_scan_verdict",
    )
    named = _select(
        cases, classname_contains="test_repo_isolation_offline", names=verdict_tests
    )
    selected = (
        _select(cases, classname_contains="test_scans")
        + _select(cases, classname_contains="test_tier_a_zero_passthrough")
        + _select(cases, classname_contains="test_scan_verdict_type")
        + _select(cases, classname_contains="test_tier_a_template")
        + named
    )
    t = _tally(selected)
    detail = _fmt_tally(t)
    if len(named) != len(verdict_tests):
        # The clause's own evidence went missing; say so rather than reporting the
        # remaining tally as if it covered the whole clause.
        detail += (
            f" — WARNING: expected {len(verdict_tests)} named verdict-forgery tests, "
            f"selected {len(named)}"
        )
    return AssertionReport(
        3,
        "Scan corpus 100% strong-signal rejection; a verdict issued for other content is "
        "refused before any SQL; Tier A zero-passthrough proven",
        t.verdict if len(named) == len(verdict_tests) else "FAIL",
        detail,
    )


def _assertion_4(cases: list[Case]) -> AssertionReport:
    """"crypto-shred: destroy -> tombstoned, bytes unchanged, provenance intact." """
    selected = _select(cases, classname_contains="test_crypto_shred")
    t = _tally(selected)
    return AssertionReport(
        4, "Crypto-shred: destroy -> tombstoned, bytes unchanged, provenance intact", t.verdict, _fmt_tally(t)
    )


def _assertion_5(cases: list[Case]) -> AssertionReport:
    """"state machine: full table coverage, all illegal transitions rejected." """
    selected = _select(cases, classname_contains="test_state_machine")
    t = _tally(selected)
    return AssertionReport(
        5, "State machine: full table coverage, all illegal transitions rejected", t.verdict, _fmt_tally(t)
    )


def _assertion_6(report: object) -> AssertionReport:
    """"SDK overhead <=1ms p99 with queue stopped; retrieve stub p99 reported."

    `report` is a `harness.fake_runtime.FakeRuntimeReport`; typed `object`
    here to keep this module's import graph independent of import order.
    """
    from harness.fake_runtime import FakeRuntimeReport

    assert isinstance(report, FakeRuntimeReport)
    verdict: Verdict = "PASS" if report.hot_path_ok else "FAIL"
    detail = (
        f"mode={report.mode} ({report.n_runs} runs, {report.tool_events_per_run} tool "
        f"events/run); hot-path (trace+feedback) p99={report.hot_path_p99_ms:.4f}ms "
        f"(budget {report.hot_path_budget_ms:.2f}ms)"
    )
    # In `fakes` mode the backend answers every request with a prompt 503, so the
    # retrieve figures below time the SDK's DEGRADED path, not the server's stub.
    # Saying otherwise would be the exact species of lie this report exists to avoid:
    # a plausible number under a label it does not measure. The stub's real behaviour
    # is covered by tests/phase0/test_api_scope.py (TestClient, asserts empty_result
    # and the retrieval_event row); only a `live` run makes this figure the stub's.
    retrieve_label = (
        "retrieve (SDK fail-open path — backend returns 503)"
        if report.mode == "fakes"
        else "retrieve (live stub)"
    )
    measurements = (
        f"{retrieve_label}: n={report.retrieve.count} p50={report.retrieve.p50_ms:.3f}ms "
        f"p99={report.retrieve.p99_ms:.3f}ms max={report.retrieve.max_ms:.3f}ms",
        f"trace:    n={report.trace.count} p50={report.trace.p50_ms:.3f}ms "
        f"p99={report.trace.p99_ms:.3f}ms max={report.trace.max_ms:.3f}ms",
        f"feedback: n={report.feedback.count} p50={report.feedback.p50_ms:.3f}ms "
        f"p99={report.feedback.p99_ms:.3f}ms max={report.feedback.max_ms:.3f}ms",
        f"run_end:  n={report.run_end.count} p50={report.run_end.p50_ms:.3f}ms "
        f"p99={report.run_end.p99_ms:.3f}ms max={report.run_end.max_ms:.3f}ms",
        f"retrieve outcome_code tally: {report.outcome_codes}",
    )
    title = (
        "SDK overhead <=1ms p99 (queue stopped); retrieve stub p99 reported"
        if report.mode == "live"
        else "SDK overhead <=1ms p99 (queue stopped); retrieve stub p99 NOT measured (no live API)"
    )
    return AssertionReport(6, title, verdict, detail, measurements)


def _assertion_7(license_result: ProcResult, raw_sql_result: ProcResult) -> AssertionReport:
    """"license + raw-SQL lint green." """
    ok = license_result.ok and raw_sql_result.ok
    verdict: Verdict = "PASS" if ok else "FAIL"
    detail = (
        f"license_check.py: exit={license_result.returncode} "
        f"({'PASS' if license_result.ok else 'FAIL'}); "
        f"raw_sql_lint.py: exit={raw_sql_result.returncode} "
        f"({'PASS' if raw_sql_result.ok else 'FAIL'})"
    )
    return AssertionReport(7, "License + raw-SQL lint green", verdict, detail)


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
    fake_runtime_report: object
    known_gaps: tuple[str, ...] = field(default_factory=tuple)
    untracked_failures: tuple[Case, ...] = field(default_factory=tuple)
    untracked_skips: tuple[Case, ...] = field(default_factory=tuple)


_KNOWN_GAPS: tuple[str, ...] = (
    "Probe 1 (search-path): there is still no `/v1/memories` and no content SEARCH route, so "
    "the probe runs at `Repo.list_memories`/`Repo.list_runs`. This text used to say 'no HTTP "
    "list/search route at all', which stopped being true when D-093 added `GET /admin/memory` "
    "(a project-scoped, status-filtered LIST). That route is covered by probe 4's "
    "unauthenticated-caller assertion and by probe 2's by-id isolation, but a row-level "
    "'A's token returns zero B rows' probe over it needs Postgres and does not exist yet.",
    "Probe 4 (dashboard API): the dashboard is a separate React app consuming the same "
    "`/v1/*` and `/admin/*` routes -- there is no `/dashboard/*` route plane. The old probe "
    "grepped registered route paths for the substring 'dashboard' and therefore could never "
    "fire; it now extracts the paths `dashboard/src` actually calls and asserts each exists "
    "and refuses an unauthenticated caller (D-102). What it still does NOT prove is per-route "
    "row-level isolation for the report routes, which needs Postgres -- probe 7 covers the RLS "
    "backstop those routes sit behind.",
    "`GET /admin/projects/{id}` (named by PHASE-0.md Task 17 as a probe-3 target) does "
    "not exist in `api/admin.py` -- only `POST /admin/projects` (create). "
    "`test_probe3_offline_no_get_admin_projects_by_id_route_exists` is a tripwire for it.",
    "`tests/phase0/conftest.py` was rebuilt at integration (C-27/D-045): `pg_pool` now calls "
    "`create_pool(dsn)` (there is no `ScopedPool`), `work_queue` passes `WorkQueue` all three "
    "required arguments, and the missing `two_projects` / `valkey_url` / `s3_config` fixtures "
    "exist. None of it can be executed here -- the skip fires first -- so the fixtures themselves "
    "remain UNVERIFIED against a live database; `tests/phase0/test_integration_seams.py` binds "
    "their constructor calls against the real signatures statically, which is the strongest "
    "check available without Postgres.",
    "The overall verdict cannot read PASS while ANY `-m phase0` test is skipped, tracked by one "
    "of the seven assertions or not (`_untracked_skips`). Before integration only untracked "
    "FAILURES moved the verdict, so a run with two dozen unexecuted isolation tests could have "
    "printed PASS. `tests/phase0/test_gate_smoke.py` pins this.",
    "This machine has no Docker/Postgres/Valkey, so every `@pytest.mark.integration` "
    "assertion below reports SKIPPED-NO-STACK here. Re-run this gate against the compose "
    "stack (docker/compose.yaml) or CI's service containers before trusting a PASS.",
)

# The exact `classname_contains` keywords each of assertions 1-5 select on, kept in one
# place so `_untracked_failures` can compute "every case any assertion looked at" without
# re-deriving it from each `_assertion_N` function's return value (which reports only a
# tally, not the case list) -- MUST stay in sync with `_assertion_1`..`_assertion_5` above.
_TRACKED_CLASSNAME_KEYWORDS: tuple[str, ...] = (
    "test_trace_writer",
    "test_outcome_intake",
    "leak_suite.test_leaks",
    "test_scans",
    "test_tier_a_zero_passthrough",
    "test_scan_verdict_type",
    "test_tier_a_template",
    "test_crypto_shred",
    "test_state_machine",
)


def _untracked_failures(cases: list[Case]) -> tuple[Case, ...]:
    """Every failed/errored `-m phase0` case that none of the seven numbered
    assertions selected -- so a real failure in, say, a domain-config test
    can never be invisible just because it falls outside this file's seven
    groupings. See `run_gate`'s use of this: it alone can force the overall
    verdict to FAIL even when all seven assertions individually read PASS.
    """
    return tuple(
        c
        for c in cases
        if c.status in ("failed", "error")
        and not any(k in c.classname for k in _TRACKED_CLASSNAME_KEYWORDS)
    )


def _untracked_skips(cases: list[Case]) -> tuple[Case, ...]:
    """Every SKIPPED `-m phase0` case that none of the seven assertions selected.

    THE false-PASS hole this closes, found at integration: the seven assertions
    cover roughly 600 of ~1,500 phase0 tests. Every integration test in
    `test_repo_scoping` / `test_repo_provenance` / `test_queue` / `test_migrations`
    / `test_partitions` / `test_telemetry` / `test_spend` falls OUTSIDE all seven
    selectors. `_untracked_failures` forced FAIL for an untracked failure, but an
    untracked SKIP moved nothing -- so a run with no Postgres, in which two dozen
    isolation tests never executed, could still print `overall verdict: PASS` the
    moment assertion 2 happened to be satisfied by its offline half alone.

    A skip is "this was not verified". The overall verdict must never say PASS
    over an unverified test, whichever grouping it does or does not belong to.
    """
    return tuple(
        c
        for c in cases
        if c.status == "skipped"
        and not any(k in c.classname for k in _TRACKED_CLASSNAME_KEYWORDS)
    )


def run_gate(
    *,
    out_path: Path,
    pytest_timeout_s: float = 600.0,
    script_timeout_s: float = 120.0,
    fake_runtime_n_runs: int = 200,
    fake_runtime_tool_events: int = 3,
) -> GateRun:
    junit_path = REPO_ROOT / ".phase0_gate_junit.xml"

    pytest_result, cases = _run_pytest_phase0(junit_path, timeout_s=pytest_timeout_s)
    pytest_tally = _tally(cases)

    license_self_test = _run(
        "license_check.py --self-test",
        ["scripts/license_check.py", "--self-test"],
        timeout_s=script_timeout_s,
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
        "raw_sql_lint.py --self-test",
        ["scripts/raw_sql_lint.py", "--self-test"],
        timeout_s=script_timeout_s,
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
        "purity_check.py --self-test",
        ["scripts/purity_check.py", "--self-test"],
        timeout_s=script_timeout_s,
    )
    purity_real = _run("purity_check.py", ["scripts/purity_check.py"], timeout_s=script_timeout_s)
    purity_combined = ProcResult(
        label="purity_check.py",
        command=purity_real.command,
        returncode=0 if (purity_self_test.ok and purity_real.ok) else 1,
        stdout=purity_self_test.stdout + "\n" + purity_real.stdout,
        duration_s=purity_self_test.duration_s + purity_real.duration_s,
    )

    from harness.fake_runtime import run_fake_runtime

    fake_runtime_report = run_fake_runtime(
        n_runs=fake_runtime_n_runs, tool_events_per_run=fake_runtime_tool_events
    )

    assertions = (
        _assertion_1(cases),
        _assertion_2(cases),
        _assertion_3(cases),
        _assertion_4(cases),
        _assertion_5(cases),
        _assertion_6(fake_runtime_report),
        _assertion_7(license_combined, raw_sql_result=raw_sql_combined),
    )

    # A test can fail without belonging to any of the seven named assertions
    # above (e.g. a domain-config test) -- `pytest_tally.failed` is the
    # ground truth for "did anything under -m phase0 fail", independent of
    # this file's own grouping selectors, so overall PASS can never hide a
    # real failure the seven-assertion table happened not to select.
    untracked_failures = _untracked_failures(cases)
    untracked_skips = _untracked_skips(cases)

    overall: Literal["PASS", "FAIL", "INCOMPLETE"]
    if any(a.verdict == "FAIL" for a in assertions) or pytest_tally.failed > 0:
        overall = "FAIL"
    elif any(a.verdict != "PASS" for a in assertions) or untracked_skips:
        # `untracked_skips` is load-bearing, not belt-and-braces: see its
        # docstring. PASS requires that everything under `-m phase0` actually
        # RAN, not merely that the seven selected groups did.
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
        fake_runtime_report=fake_runtime_report,
        known_gaps=_KNOWN_GAPS,
        untracked_failures=untracked_failures,
        untracked_skips=untracked_skips,
    )
    out_path.write_text(render_markdown(run), encoding="utf-8")
    # Scratch artifact, fully absorbed into `run`/the rendered report above --
    # left on disk it is just noise in the working tree (and not what CI's
    # "phase 0 gate" step uploads; that step uploads `out_path`).
    junit_path.unlink(missing_ok=True)
    return run


def render_markdown(run: GateRun) -> str:
    from harness.fake_runtime import FakeRuntimeReport, render_text

    assert isinstance(run.fake_runtime_report, FakeRuntimeReport)

    lines: list[str] = []
    w = lines.append
    w("# Phase 0 gate report")
    w("")
    w(f"Generated: {run.generated_at}")
    w("")
    w(f"## Overall verdict: **{run.overall_verdict}**")
    w("")
    if run.overall_verdict == "INCOMPLETE":
        w(
            "> INCOMPLETE means at least one gate assertion below could not be verified "
            "(no Postgres/Valkey/S3 reachable, or a selector matched zero tests) -- it is "
            "**not** a pass. See the per-assertion table and Known Gaps section."
        )
        w("")
    elif run.overall_verdict == "FAIL":
        w("> At least one gate assertion below FAILED. See the per-assertion table.")
        w("")

    w("## The seven PHASE-0.md (lines 180-187) gate assertions")
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

    w("## `pytest -m phase0`")
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
    w(
        "`purity_check.py` is not one of the seven numbered gate assertions (there is no "
        "`hotpath/` package in Phase 0 -- it reports `SKIP` by design, per its own docstring: "
        "\"lands in Phase 1\"). Run here anyway per this chunk's brief, for completeness."
    )
    w("")

    w("## Fake-runtime SDK overhead measurement (assertion 6's evidence)")
    w("")
    w("```")
    w(render_text(run.fake_runtime_report))
    w("```")
    w("")

    if run.untracked_failures:
        w("## Failures outside the seven tracked assertions")
        w("")
        w(
            "These `-m phase0` failures do not belong to any of the seven numbered "
            "assertions above, but they are real and are why the overall verdict is "
            "**FAIL** even if every row in the table above reads PASS."
        )
        w("")
        for c in run.untracked_failures:
            w(f"- `{c.classname}::{c.name}` — {c.status}: {c.message or '(no message)'}")
        w("")

    if run.untracked_skips:
        w("## Tests that did not run, outside the seven tracked assertions")
        w("")
        w(
            f"{len(run.untracked_skips)} `-m phase0` test(s) were SKIPPED and belong to none "
            "of the seven numbered assertions above, so no row in that table reflects them. "
            "They are why the overall verdict cannot be **PASS**: a skip is "
            "\"this was not verified\", and an unverified test must never sit under a green "
            "top line. Re-run against the compose stack to clear them."
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
    w(
        "**STOP.** Present this report to the human. Do not begin Phase 1 without "
        "explicit approval (PHASE-0.md)."
    )
    w("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=REPO_ROOT / "gate_report_phase0.md")
    parser.add_argument("--pytest-timeout", type=float, default=600.0)
    parser.add_argument("--script-timeout", type=float, default=120.0)
    parser.add_argument("--fake-runtime-n-runs", type=int, default=200)
    parser.add_argument("--fake-runtime-tool-events", type=int, default=3)
    args = parser.parse_args(argv)

    run = run_gate(
        out_path=args.out,
        pytest_timeout_s=args.pytest_timeout,
        script_timeout_s=args.script_timeout,
        fake_runtime_n_runs=args.fake_runtime_n_runs,
        fake_runtime_tool_events=args.fake_runtime_tool_events,
    )

    print(f"gate report written to {args.out}")
    print(f"overall verdict: {run.overall_verdict}")
    for a in run.assertions:
        print(f"  [{a.verdict:<16}] {a.number}. {a.title}")

    return 0 if run.overall_verdict == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
