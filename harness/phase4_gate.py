"""The Phase 4 gate runner (PLAN.md section 7 Phase 4 -- "Gate:" paragraph, verbatim):

    "parallel-branch contention tests green (fixture-only -- no host
    dependency); key-squatting test: proposed keys cannot shadow another
    agent's committed keys; end-only workflow verdict scores workflow-
    template scope only, ZERO per-agent Q changes; proposals never satisfy
    any skip (re-run from Phase 3); full CI green; DECISIONS.md current.
    STOP. Final review."

Same discipline as `harness/phase0_gate.py` through `harness/phase3_gate.py` (all four
read first, matched here): runs `pytest -m phase4` once (so every clause below is drawn
from the SAME execution, never two runs that could disagree), plus DIRECT library calls
for the concrete numbers a bare JUnit pass/fail cannot carry on its own
(`harness.contention.run_contention_drill`, `harness.workflow_scope
.run_workflow_scope_drill`, `harness.redteam.probes.run_sybil_probe` -- the Phase 3
unit-path re-confirmation clause 4 explicitly asks for alongside the live path) -- then
renders `gate_report_phase4.md` mapping every result onto the six PLAN.md section 7
Phase 4 clauses above.

THE REPORT MUST NOT LIE (`harness/phase0_gate.py`'s own words, carried through every
sibling gate unchanged, carried through here unchanged). Every clause backed by pytest
and/or a direct drill call is one of exactly four verdicts:

  * ``PASS``             -- every test/call backing this clause ran and passed.
  * ``FAIL``              -- at least one test/call backing it ran and failed.
  * ``SKIPPED-NO-STACK``  -- at least one test backing it could not run
                            (integration-marked, no Postgres/Valkey/S3) and none of the
                            ones that DID run failed.
  * ``INCOMPLETE-DATA``   -- this runner found ZERO tests matching the clause's selector
                            at all -- a defect in the gate report's own grouping, or (for
                            clause 3, honestly) the documented absence of any owning
                            pytest file, never folded silently into SKIPPED-NO-STACK.

CLAUSE 3 HAS NO OWNING PYTEST FILE, AND THIS REPORT SAYS SO. This task's file list is
exactly `harness/contention.py`, `harness/workflow_scope.py`, `harness/phase4_gate.py`,
`harness/full_gate.py` -- no `tests/phase4/test_workflow_scope.py` exists anywhere in
this tree, and hard rule 7 ("write ONLY your file list") means one is not added here.
Clause 3's verdict is therefore computed SOLELY from `harness.workflow_scope
.run_workflow_scope_drill()`'s own direct result -- reported plainly as such, never
dressed up as pytest-covered.

CLAUSE 5 ("full CI green") RUNS THE WHOLE PROJECT, NOT ONLY `-m phase4`. Per this task's
own brief, "full CI green" means the baseline that must not regress: the FULL `pytest -q`
(every marker, every phase), `mypy`, `ruff check src tests harness scripts`, and the three
static gates (license/raw-SQL/purity). Expected integration-marked skips in that full run
(no Docker/Postgres/Valkey/S3/LLM in this environment -- documented baseline "3258 passed,
40 skipped") are NOT treated as a failure for clause 5: they are a pre-existing, accepted
condition of this environment, distinct from clause 1-4's OWN `-m phase4` tests, which
PLAN.md section 7 states must be fixture-only with NO host dependency at all -- a skip
there has no legitimate excuse and is what makes the overall verdict INCOMPLETE.

CLAUSE 6 ("DECISIONS.md current") IS A MECHANICAL PARSE, NOT A JUDGEMENT CALL THIS SCRIPT
CANNOT MAKE. This runner verifies DECISIONS.md is well-formed (every `## D-NNN` heading
unique, every entry closed with its own `**Date `) and reports the highest decision number
and its date. Whether every Phase 4 design choice that deserves a NEW entry has one is a
human judgement this script does not fabricate -- see this module's own `_KNOWN_GAPS` for
what a human reviewer should specifically check before treating clause 6 as truly settled.

The overall verdict is ``PASS`` only when every one of the SIX clauses reads ``PASS`` AND
no `-m phase4` test anywhere skipped, tracked or not (mirrors every sibling gate's own
`_untracked_skips` discipline -- explicit in this phase's own task brief: "Overall
INCOMPLETE if any -m phase4 test skipped").
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

REPO_ROOT = Path(__file__).resolve().parent.parent
PYTHON = sys.executable

# Mirrors every sibling gate's own note: a direct script run
# (`python harness/phase4_gate.py`) puts only `harness/` on `sys.path[0]`, so
# `import harness.contention` etc below would fail with `ModuleNotFoundError` despite
# `harness/__init__.py` existing right next to this file.
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

Verdict = Literal["PASS", "FAIL", "SKIPPED-NO-STACK", "INCOMPLETE-DATA"]

__all__ = ["main", "run_gate"]


# --------------------------------------------------------------------------- #
# JUnit XML parsing -- duplicated from every sibling gate deliberately (module-private
# helpers there, and per-chunk fake/helper duplication is an accepted convention in this
# codebase, PHASE0-CONTRACT.md section 13.1's own note).
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
    """FAIL beats everything, then INCOMPLETE-DATA, then SKIPPED-NO-STACK, then PASS.
    Mirrors every sibling gate's own `_worse` exactly."""
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
    """Never raises on a non-zero exit or a timeout -- both are gate findings, not
    runner crashes. Forces UTF-8 stdout, matching every sibling gate's own fix for a
    stock Windows console (cp1252) crashing `scripts/license_check.py`'s box-drawing
    glyph output."""
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


def _run_pytest(
    junit_path: Path, *, markers: str | None, timeout_s: float
) -> tuple[ProcResult, list[Case]]:
    args = ["-m", "pytest"]
    if markers is not None:
        args += ["-m", markers]
    args += ["-q", f"--junitxml={junit_path}"]
    result = _run(f"pytest{' -m ' + markers if markers else ''}", args, timeout_s=timeout_s)
    if not junit_path.exists():
        return result, []
    try:
        cases = _parse_junit(junit_path)
    except ET.ParseError:
        cases = []
    return result, cases


def _combined_static_gate(script: str, *, timeout_s: float) -> ProcResult:
    """`scripts/X.py --self-test` then `scripts/X.py`, combined -- exactly every sibling
    gate's own pattern for the three static gates."""
    self_test = _run(f"{script} --self-test", [f"scripts/{script}", "--self-test"], timeout_s=timeout_s)
    real = _run(script, [f"scripts/{script}"], timeout_s=timeout_s)
    return ProcResult(
        label=script,
        command=real.command,
        returncode=0 if (self_test.ok and real.ok) else 1,
        stdout=self_test.stdout + "\n" + real.stdout,
        duration_s=self_test.duration_s + real.duration_s,
    )


# --------------------------------------------------------------------------- #
# The six PLAN.md section 7 Phase 4 gate clauses.
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class AssertionReport:
    number: int
    title: str
    verdict: Verdict
    detail: str
    measurements: tuple[str, ...] = ()


_KEY_SQUAT_TEST_NAMES: tuple[str, ...] = (
    "test_second_committer_cannot_shadow_an_already_committed_key",
    "test_the_same_key_on_two_branches_are_two_independent_entries",
)


def _assertion_parallel_branch_contention(
    cases: list[Case], contention_report: object
) -> AssertionReport:
    """"parallel-branch contention tests green (fixture-only -- no host dependency)."
    Backed by `tests/phase4/test_blackboard_contention.py` (JUnit -- the `blackboard`
    chunk's own real-OS-thread, repeated-round suite) AND a direct
    `harness.contention.run_contention_drill()` call, which independently drives the
    SAME production entry point (`BlackboardRepo.commit`) with its own fresh real
    threads and its own fresh fake store.
    """
    from harness.contention import ContentionReport, render_text

    assert isinstance(contention_report, ContentionReport)
    selected = _select(cases, classname_contains="test_blackboard_contention")
    t = _tally(selected)
    verdict = _worse(t.verdict, "PASS" if contention_report.parallel_branch_ok else "FAIL")
    return AssertionReport(
        1,
        "Parallel-branch contention tests green (fixture-only, real OS threads, "
        "repeated rounds)",
        verdict,
        _fmt_tally(t)
        + f"; direct drill: {'PASS' if contention_report.parallel_branch_ok else 'FAIL'}",
        (render_text(contention_report),),
    )


def _assertion_key_squatting(cases: list[Case], contention_report: object) -> AssertionReport:
    """"key-squatting test: proposed keys cannot shadow another agent's committed
    keys." Backed by `tests/phase4/test_blackboard.py`'s two key-squatting tests (JUnit,
    single-threaded/sequential) AND `harness.contention.run_contention_drill()`'s
    concurrent-attacker scenario (many real threads racing to shadow one already-
    committed key at once) -- the same drill call assertion 1 uses, read for its
    `key_squat_ok` half instead.
    """
    from harness.contention import ContentionReport

    assert isinstance(contention_report, ContentionReport)
    selected = _select(cases, classname_contains="test_blackboard", names=_KEY_SQUAT_TEST_NAMES)
    t = _tally(selected)
    verdict = _worse(t.verdict, "PASS" if contention_report.key_squat_ok else "FAIL")
    return AssertionReport(
        2,
        "Key-squatting test: proposed keys cannot shadow another agent's committed keys",
        verdict,
        _fmt_tally(t) + f"; direct drill: {'PASS' if contention_report.key_squat_ok else 'FAIL'}",
    )


def _assertion_workflow_scope() -> AssertionReport:
    """"end-only workflow verdict scores workflow-template scope only, ZERO per-agent
    Q changes." Backed SOLELY by a direct `harness.workflow_scope
    .run_workflow_scope_drill()` call -- no `tests/phase4/test_workflow_scope.py` exists
    anywhere in this tree (this task's file list does not include one; adding it would
    be a contract_gap, not this gate's file to write). Reported honestly as
    direct-drill-only rather than dressed up as pytest-covered.
    """
    from harness.workflow_scope import WorkflowScopeReport, render_text, run_workflow_scope_drill

    report = run_workflow_scope_drill()
    assert isinstance(report, WorkflowScopeReport)
    verdict: Verdict = "PASS" if report.ok else "FAIL"
    return AssertionReport(
        3,
        "End-only workflow verdict scores workflow-template scope ONLY -- zero "
        "per-agent Q changes (byte-identical before/after)",
        verdict,
        "no owning pytest file exists for this clause (see this module's docstring); "
        f"direct drill: {'PASS' if report.ok else 'FAIL'}",
        (render_text(report),),
    )


_PROPOSAL_LIVE_PATH_TEST_NAMES: tuple[str, ...] = (
    "test_two_proposals_never_corroborate_each_other_even_as_independent_confirmations",
    "test_a_single_proposal_run_id_can_never_self_corroborate_either",
)


def _assertion_proposals_never_skip(cases: list[Case]) -> AssertionReport:
    """"proposals never satisfy any skip (re-run from Phase 3)." Re-run through the NEW
    live `workflow.agent_control.AgentControl.submit_proposal` path (`tests/phase4
    /test_agent_control.py`'s own two named Sybil-re-assertion tests, JUnit), ALONGSIDE
    the original Phase 3 unit path (`harness.redteam.probes.run_sybil_probe()`, which
    builds the row directly via `RedTeamRepo`/`ShadowValidator` rather than through
    `AgentControl`) -- both must hold, since the task brief is explicit that re-running
    only the Phase 3 unit path is not enough.
    """
    from harness.redteam.probes import run_sybil_probe

    selected = _select(
        cases, classname_contains="test_agent_control", names=_PROPOSAL_LIVE_PATH_TEST_NAMES
    )
    t = _tally(selected)
    report = run_sybil_probe()
    verdict = _worse(t.verdict, "PASS" if report.ok else "FAIL")
    return AssertionReport(
        4,
        "Proposals never satisfy any skip -- re-run through the NEW live "
        "agent_control path, not just the Phase 3 unit path",
        verdict,
        _fmt_tally(t) + f"; Phase 3 unit-path direct drill: {'PASS' if report.ok else 'FAIL'}",
        (
            f"live path (test_agent_control.py): {_fmt_tally(t)}",
            f"Phase 3 unit path (harness.redteam.probes.run_sybil_probe): "
            f"two_calls reached={report.two_calls_result.furthest_status.value}, "
            f"two_independent_confirmations reached="
            f"{report.two_independent_confirmations_result.furthest_status.value}",
        ),
    )


def _assertion_full_ci_green(
    full_pytest: ProcResult,
    full_pytest_tally: Tally,
    mypy_result: ProcResult,
    ruff_result: ProcResult,
    license_result: ProcResult,
    raw_sql_result: ProcResult,
    purity_result: ProcResult,
) -> AssertionReport:
    """"full CI green." Per this task's own brief, the baseline that must not regress:
    the FULL `pytest -q` (every marker, not only `-m phase4`), `mypy`, `ruff check src
    tests harness scripts`, and the three static gates. Expected integration-marked
    skips in THIS run (no Docker/Postgres/Valkey/S3/LLM in this environment) are not a
    failure here -- see this module's docstring for why that is a deliberately
    different rule than clause 1-4's own `-m phase4` no-skip requirement.
    """
    ok = (
        full_pytest.ok
        and full_pytest_tally.failed == 0
        and mypy_result.ok
        and ruff_result.ok
        and license_result.ok
        and raw_sql_result.ok
        and purity_result.ok
    )
    verdict: Verdict = "PASS" if ok else "FAIL"
    detail = (
        f"pytest -q (full suite): exit={full_pytest.returncode}, {_fmt_tally(full_pytest_tally)}; "
        f"mypy: {'PASS' if mypy_result.ok else 'FAIL'}; "
        f"ruff: {'PASS' if ruff_result.ok else 'FAIL'}; "
        f"license_check: {'PASS' if license_result.ok else 'FAIL'}; "
        f"raw_sql_lint: {'PASS' if raw_sql_result.ok else 'FAIL'}; "
        f"purity_check: {'PASS' if purity_result.ok else 'FAIL'}"
    )
    return AssertionReport(5, "Full CI green (full pytest + mypy + ruff + static gates)", verdict, detail)


_DECISION_HEADING = re.compile(r"^## D-(\d{3})\b(.*)$", re.MULTILINE)


@dataclass(frozen=True, slots=True)
class _DecisionsAudit:
    ok: bool
    n_entries: int
    duplicate_ids: tuple[str, ...]
    entries_missing_date: tuple[str, ...]
    entries_missing_fields: tuple[str, ...]
    highest_id: str | None
    latest_line: str | None


# D-110. Entries D-001..D-094 predate the check and are frozen: 32 of them are malformed
# against the file's own mandated format, and the file is append-only.
_LEGACY_FORMAT_MAX_ID: int = 94
_REQUIRED_DECISION_FIELDS: tuple[str, ...] = (
    "**Decision:**",
    "**Context:**",
    "**Alternatives considered:**",
    "**Rationale:**",
    "**Date ",
)


def _audit_decisions_md(text: str) -> _DecisionsAudit:
    headings = list(_DECISION_HEADING.finditer(text))
    ids = [m.group(1) for m in headings]
    seen: set[str] = set()
    duplicates: list[str] = []
    for decision_id in ids:
        if decision_id in seen:
            duplicates.append(decision_id)
        seen.add(decision_id)

    missing_date: list[str] = []
    missing_fields: list[str] = []
    for i, m in enumerate(headings):
        start = m.end()
        end = headings[i + 1].start() if i + 1 < len(headings) else len(text)
        body = text[start:end]
        if "**Date " not in body:
            missing_date.append(f"D-{m.group(1)}")
        # D-110: the file's own header mandates five fields. 32 of D-001..D-094 do not carry
        # them, and the file is append-only -- rewriting history to satisfy a linter is exactly
        # the edit that header forbids. So the rule binds FORWARD, from the first id after the
        # frozen legacy set, where it can still be obeyed.
        if int(m.group(1)) > _LEGACY_FORMAT_MAX_ID:
            absent = [f for f in _REQUIRED_DECISION_FIELDS if f not in body]
            if absent:
                missing_fields.append(f"D-{m.group(1)} (missing: {', '.join(absent)})")

    highest = max(ids, key=int) if ids else None
    latest_line = None
    if highest is not None:
        for m in headings:
            if m.group(1) == highest:
                latest_line = f"D-{m.group(1)}{m.group(2)}".strip()

    return _DecisionsAudit(
        ok=bool(headings) and not duplicates and not missing_date and not missing_fields,
        n_entries=len(headings),
        duplicate_ids=tuple(duplicates),
        entries_missing_date=tuple(missing_date),
        entries_missing_fields=tuple(missing_fields),
        highest_id=highest,
        latest_line=latest_line,
    )


def _assertion_decisions_current(repo_root: Path) -> AssertionReport:
    """"DECISIONS.md current." A MECHANICAL check only: every `## D-NNN` heading is
    unique, every entry is closed with its own `**Date ` field, and every entry newer than
    the frozen legacy set carries all five fields the file's own header mandates (D-110).
    Whether every design decision that deserves a NEW entry has one is a human judgement
    call this script cannot fabricate -- see `_KNOWN_GAPS` for what a human reviewer should
    specifically check before signing off on this clause at the Phase 4 STOP.
    """
    path = repo_root / "DECISIONS.md"
    if not path.exists():
        return AssertionReport(6, "DECISIONS.md current (mechanical parse)", "FAIL", "DECISIONS.md does not exist")
    audit = _audit_decisions_md(path.read_text(encoding="utf-8"))
    verdict: Verdict = "PASS" if audit.ok else "FAIL"
    detail = (
        f"{audit.n_entries} decision entries parsed; duplicate ids: "
        f"{list(audit.duplicate_ids) or 'none'}; entries missing a **Date** field: "
        f"{list(audit.entries_missing_date) or 'none'}; entries after "
        f"D-{_LEGACY_FORMAT_MAX_ID} missing a mandated field: "
        f"{list(audit.entries_missing_fields) or 'none'}; highest id: D-{audit.highest_id} "
        f"({audit.latest_line})"
    )
    return AssertionReport(
        6,
        "DECISIONS.md current (mechanical parse: unique ids, every entry dated, "
        f"every entry after D-{_LEGACY_FORMAT_MAX_ID} carrying all five mandated fields)",
        verdict,
        detail,
    )


# --------------------------------------------------------------------------- #
# Orchestration + rendering.
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class GateRun:
    generated_at: str
    overall_verdict: Literal["PASS", "FAIL", "INCOMPLETE"]
    assertions: tuple[AssertionReport, ...]
    pytest_phase4_result: ProcResult
    pytest_phase4_tally: Tally
    full_pytest_result: ProcResult
    full_pytest_tally: Tally
    mypy_result: ProcResult
    ruff_result: ProcResult
    license_result: ProcResult
    raw_sql_result: ProcResult
    purity_result: ProcResult
    known_gaps: tuple[str, ...] = field(default_factory=tuple)
    untracked_failures: tuple[Case, ...] = field(default_factory=tuple)
    untracked_skips: tuple[Case, ...] = field(default_factory=tuple)


_KNOWN_GAPS: tuple[str, ...] = (
    "Clause 3 (workflow-scope isolation) has NO owning pytest file anywhere in this "
    "tree; this task's file list is exactly harness/contention.py, "
    "harness/workflow_scope.py, harness/phase4_gate.py, harness/full_gate.py, so a new "
    "tests/phase4/test_workflow_scope.py is a contract_gap reported here, not a file "
    "added by this gate. Its verdict is therefore computed SOLELY from "
    "harness.workflow_scope.run_workflow_scope_drill() -- a deterministic, "
    "non-statistical check (no repeated seeds needed: the routing rule is either "
    "applied or it is not) with a built-in negative control proving it is not vacuous.",
    "No real credit-assignment orchestrator exists anywhere in the production codebase "
    "that joins injection_log to an outcome_event and calls workers.scorer.run_scorer_"
    "batch only for the correctly-scoped subset -- harness.workflow_scope.route_end_of_"
    "workflow_verdict is this gate's OWN reference implementation of the routing rule, "
    "not production code. Whichever chunk eventually builds real workflow-verdict "
    "credit assignment should match this function's behaviour, not merely this gate's "
    "green checkmark.",
    "harness.contention's fake blackboard store enforces blackboard_entry's real "
    "primary key under one threading.Lock, which faithfully models what a real unique "
    "index gives a concurrent INSERT ... ON CONFLICT DO NOTHING -- it cannot prove "
    "Postgres' own speculative-insertion behaviour or that RLS FORCE returns zero rows "
    "under concurrency. Identical caveat to the one stores.pg.blackboard's own module "
    "docstring and tests/phase4/test_blackboard_contention.py's own docstring already "
    "state for the sibling pytest suite this clause also relies on.",
    "src/tracebed/workflow/agent_control.py::AgentControl's per-run/per-project proposal "
    "caps are enforced under a PROCESS-LOCAL threading.Lock only (that module's own "
    "documented contract gap): two API/worker processes sharing one Postgres can each "
    "land per_run_cap proposals, bounded by cap x concurrent processes, not cap alone. "
    "tests/phase4/test_agent_control.py::test_concurrent_submissions_never_exceed_the_"
    "per_run_cap has been reported by sibling chunk audits as intermittently failing in "
    "this exact tree ('N proposals landed under a per-run cap of 2') -- that test is "
    "NOT one of clause 4's two tracked Sybil-re-assertion tests, so a failure there "
    "surfaces as an UNTRACKED failure below rather than being silently absorbed by "
    "clause 4's own PASS/FAIL. The untracked-failures section of this report renders "
    "ONLY when there are failures, so its absence above means this run observed none.",
    "DECISIONS.md's own audit trail (clause 6) has no entry for several Phase 4 design "
    "choices this session's own sibling chunk reports describe in code-level CONTRACT "
    "GAP comments -- e.g. the routing_record table PLAN.md section 5 does not "
    "define (the blackboard column types and the three AgentControlRepoPort methods that "
    "used to be listed here were fixed and logged as D-087/D-088; they are no longer gaps "
    "and have been removed from this list). D-035 records that DECISIONS.md logs 'deviations "
    "and dependencies, not micro-choices' -- whether each of these rises to the level "
    "of a NEW numbered decision (as opposed to the in-code CONTRACT GAP comment "
    "convention every chunk already uses) is a human judgement call for the Phase 4 "
    "STOP, not something this mechanical parse can settle. Clause 6 above verifies only "
    "that DECISIONS.md is well-formed (unique ids, every entry dated), not that its "
    "content is complete.",
    "This machine has no Docker/Postgres/Valkey/S3 and no real LLM endpoint. Every "
    "drill in this report (the contention drill, the workflow-scope drill, the Sybil "
    "probe) runs entirely offline against in-memory fakes; the full pytest run behind "
    "clause 5 legitimately skips every @pytest.mark.integration test for the same "
    "reason (documented baseline: '3258 passed, 40 skipped'), which is why clause 5 "
    "does not apply the same zero-skip rule clauses 1-4's own -m phase4 tests are held "
    "to (PLAN.md section 7 states THIS phase's own new tests must be fixture-only with "
    "no host dependency at all -- the pre-existing integration-marked tests from "
    "earlier phases carry no such promise and never have).",
)

# Only classnames covered by a FULL-FILE (no test-name filter) pytest selection belong
# here. `test_blackboard.py` (assertion 2) and `test_agent_control.py` (assertion 4) are
# both selected NARROWLY (specific test names only, see `_KEY_SQUAT_TEST_NAMES` /
# `_PROPOSAL_LIVE_PATH_TEST_NAMES` above) -- adding their bare classnames here would let
# an unrelated failure in either file (e.g. the known, reported
# `test_concurrent_submissions_never_exceed_the_per_run_cap` race) hide inside a
# "tracked" bucket without ever being counted by any of the six clause verdicts above.
# Leaving them out is what makes such a failure surface in `untracked_failures` instead.
_TRACKED_CLASSNAME_KEYWORDS: tuple[str, ...] = ("test_blackboard_contention",)


def _untracked_failures(cases: list[Case]) -> tuple[Case, ...]:
    """Every failed/errored `-m phase4` case outside the six tracked clauses above."""
    return tuple(
        c
        for c in cases
        if c.status in ("failed", "error") and not any(k in c.classname for k in _TRACKED_CLASSNAME_KEYWORDS)
    )


def _untracked_skips(cases: list[Case]) -> tuple[Case, ...]:
    """Every SKIPPED `-m phase4` case outside the six tracked clauses.

    Both kinds force INCOMPLETE -- an unverified test never sits under a green top
    line -- but they are reported apart, because they mean different things and the
    earlier wording conflated them:

    - NO-STACK: the case is `@pytest.mark.integration` and skipped because this
      machine has no Postgres/Valkey/S3. Legitimate, identical in kind to the Phase
      0-3 integration skips, and cleared by running against the compose stack.
    - NO EXCUSE: the case is NOT integration-marked. PLAN.md section 7 Phase 4 says
      the contention tests are FIXTURE-ONLY with no host dependency, so an unmarked
      skip here is a test that was disabled rather than a stack that was absent.

    The distinction is the whole point: a report that tells a reviewer a fixture-only
    test "has no legitimate excuse" when the real cause is a missing database sends
    them hunting for a defect that is not there.
    """
    return tuple(
        c
        for c in cases
        if c.status == "skipped" and not any(k in c.classname for k in _TRACKED_CLASSNAME_KEYWORDS)
    )


def _skip_is_no_stack(case: Case) -> bool:
    """True when a skip is the documented "no Docker on this machine" case.

    Keyed on the skip MESSAGE rather than on the marker, because the JUnit XML this
    module parses carries the reason text but not the marker set. Every such fixture
    in `tests/conftest.py` and `tests/phase0/conftest.py` names the env var it wanted,
    which is what makes the message a reliable signal here.
    """
    reason = (case.message or "").lower()
    return any(
        token in reason
        for token in (
            "no postgres available",
            "no valkey available",
            "no object store available",
            "tb_storage__pg_dsn",
            "tb_storage__valkey_url",
            "tb_s3_endpoint",
            "unreachable",
            "schema current",
        )
    )


def run_gate(
    *,
    out_path: Path,
    pytest_timeout_s: float = 600.0,
    full_pytest_timeout_s: float = 1800.0,
    script_timeout_s: float = 120.0,
    mypy_timeout_s: float = 300.0,
) -> GateRun:
    junit_phase4 = REPO_ROOT / ".phase4_gate_junit.xml"
    junit_full = REPO_ROOT / ".phase4_gate_full_junit.xml"

    pytest_phase4_result, cases = _run_pytest(junit_phase4, markers="phase4", timeout_s=pytest_timeout_s)
    pytest_phase4_tally = _tally(cases)

    from harness.contention import run_contention_drill

    contention_report = run_contention_drill()

    # Clause 5 ("full CI green"): the whole project, not just -m phase4.
    full_pytest_result, full_cases = _run_pytest(junit_full, markers=None, timeout_s=full_pytest_timeout_s)
    full_pytest_tally = _tally(full_cases)
    mypy_result = _run("mypy", ["-m", "mypy"], timeout_s=mypy_timeout_s)
    ruff_result = _run(
        "ruff check", ["-m", "ruff", "check", "src", "tests", "harness", "scripts"], timeout_s=script_timeout_s
    )
    license_result = _combined_static_gate("license_check.py", timeout_s=script_timeout_s)
    raw_sql_result = _combined_static_gate("raw_sql_lint.py", timeout_s=script_timeout_s)
    purity_result = _combined_static_gate("purity_check.py", timeout_s=script_timeout_s)

    assertions: tuple[AssertionReport, ...] = (
        _assertion_parallel_branch_contention(cases, contention_report),
        _assertion_key_squatting(cases, contention_report),
        _assertion_workflow_scope(),
        _assertion_proposals_never_skip(cases),
        _assertion_full_ci_green(
            full_pytest_result,
            full_pytest_tally,
            mypy_result,
            ruff_result,
            license_result,
            raw_sql_result,
            purity_result,
        ),
        _assertion_decisions_current(REPO_ROOT),
    )

    untracked_failures = _untracked_failures(cases)
    untracked_skips = _untracked_skips(cases)

    overall: Literal["PASS", "FAIL", "INCOMPLETE"]
    if any(a.verdict == "FAIL" for a in assertions) or pytest_phase4_tally.failed > 0 or untracked_failures:
        overall = "FAIL"
    elif any(a.verdict != "PASS" for a in assertions) or untracked_skips:
        overall = "INCOMPLETE"
    else:
        overall = "PASS"

    run = GateRun(
        generated_at=datetime.now(UTC).isoformat(),
        overall_verdict=overall,
        assertions=assertions,
        pytest_phase4_result=pytest_phase4_result,
        pytest_phase4_tally=pytest_phase4_tally,
        full_pytest_result=full_pytest_result,
        full_pytest_tally=full_pytest_tally,
        mypy_result=mypy_result,
        ruff_result=ruff_result,
        license_result=license_result,
        raw_sql_result=raw_sql_result,
        purity_result=purity_result,
        known_gaps=_KNOWN_GAPS,
        untracked_failures=untracked_failures,
        untracked_skips=untracked_skips,
    )
    out_path.write_text(render_markdown(run), encoding="utf-8")
    junit_phase4.unlink(missing_ok=True)
    junit_full.unlink(missing_ok=True)
    return run


def render_markdown(run: GateRun) -> str:
    lines: list[str] = []
    w = lines.append
    w("# Phase 4 gate report")
    w("")
    w(f"Generated: {run.generated_at}")
    w("")
    w(f"## Overall verdict: **{run.overall_verdict}**")
    w("")
    if run.overall_verdict == "INCOMPLETE":
        w(
            "> INCOMPLETE means at least one clause below could not be verified (a "
            "selector matched zero tests, or a `-m phase4` test was skipped) -- it is "
            "**not** a pass. See the per-clause table, the untracked-skips section, "
            "and the Known Gaps section."
        )
        w("")
    elif run.overall_verdict == "FAIL":
        w("> At least one clause below FAILED, or an untracked -m phase4 test failed. "
          "See the per-clause table and the untracked-failures section.")
        w("")

    w("## The six PLAN.md section 7 Phase 4 gate clauses")
    w("")
    w("| # | Clause | Verdict | Detail |")
    w("|---|---|---|---|")
    for a in run.assertions:
        detail = a.detail.replace("|", "\\|")
        w(f"| {a.number} | {a.title} | **{a.verdict}** | {detail} |")
    w("")
    for a in run.assertions:
        if a.measurements:
            w(f"**Clause {a.number} detail:**")
            w("")
            w("```")
            for m in a.measurements:
                w(m)
            w("```")
            w("")

    w("## `pytest -m phase4`")
    w("")
    w(
        f"- exit code: {run.pytest_phase4_result.returncode} "
        f"({'OK' if run.pytest_phase4_result.ok else 'NONZERO'}, {run.pytest_phase4_result.duration_s:.1f}s)"
    )
    w(f"- {_fmt_tally(run.pytest_phase4_tally)}")
    w("")
    w("<details><summary>pytest -m phase4 output (tail)</summary>")
    w("")
    w("```")
    tail = run.pytest_phase4_result.stdout.strip().splitlines()[-80:]
    w("\n".join(tail))
    w("```")
    w("")
    w("</details>")
    w("")

    w("## Clause 5 evidence: full CI")
    w("")
    w("| Check | Verdict | Detail |")
    w("|---|---|---|")
    w(
        f"| pytest -q (full suite) | "
        f"{'PASS' if run.full_pytest_result.ok and run.full_pytest_tally.failed == 0 else 'FAIL'} | "
        f"{_fmt_tally(run.full_pytest_tally)} |"
    )
    w(f"| mypy | {'PASS' if run.mypy_result.ok else 'FAIL'} | exit={run.mypy_result.returncode} |")
    w(f"| ruff check | {'PASS' if run.ruff_result.ok else 'FAIL'} | exit={run.ruff_result.returncode} |")
    w(f"| license_check.py | {'PASS' if run.license_result.ok else 'FAIL'} | exit={run.license_result.returncode} |")
    w(f"| raw_sql_lint.py | {'PASS' if run.raw_sql_result.ok else 'FAIL'} | exit={run.raw_sql_result.returncode} |")
    w(f"| purity_check.py | {'PASS' if run.purity_result.ok else 'FAIL'} | exit={run.purity_result.returncode} |")
    w("")
    w("<details><summary>pytest -q (full suite) output (tail)</summary>")
    w("")
    w("```")
    tail_full = run.full_pytest_result.stdout.strip().splitlines()[-120:]
    w("\n".join(tail_full))
    w("```")
    w("")
    w("</details>")
    w("")
    for r in (run.mypy_result, run.ruff_result, run.license_result, run.raw_sql_result, run.purity_result):
        if not r.ok:
            w(f"<details><summary>{r.label} output (tail, FAILED)</summary>")
            w("")
            w("```")
            w("\n".join(r.stdout.strip().splitlines()[-80:]))
            w("```")
            w("")
            w("</details>")
            w("")

    if run.untracked_failures:
        w("## Failures outside the six tracked clauses")
        w("")
        w(
            "These `-m phase4` failures do not belong to any of the six tracked clauses "
            "above, but they are real and are why the overall verdict is **FAIL** even "
            "if every row in the table above reads PASS."
        )
        w("")
        for c in run.untracked_failures:
            w(f"- `{c.classname}::{c.name}` -- {c.status}: {c.message or '(no message)'}")
        w("")

    if run.untracked_skips:
        w("## Tests that did not run, outside the six tracked clauses")
        w("")
        no_stack = [c for c in run.untracked_skips if _skip_is_no_stack(c)]
        no_excuse = [c for c in run.untracked_skips if not _skip_is_no_stack(c)]
        w(
            f"{len(run.untracked_skips)} `-m phase4` test(s) were SKIPPED and belong to "
            "none of the six tracked clauses above. Either kind forces the overall verdict "
            "to **INCOMPLETE** -- an unverified test never sits under a green top line -- "
            "but they mean different things and are listed apart."
        )
        w("")

        def _group(cases: list[Case]) -> None:
            by_class: dict[str, list[Case]] = {}
            for c in cases:
                by_class.setdefault(c.classname, []).append(c)
            for classname in sorted(by_class):
                group = by_class[classname]
                reason = group[0].message or "(no reason recorded)"
                w(f"- `{classname}` -- {len(group)} skipped: {reason}")

        if no_stack:
            w("**SKIPPED-NO-STACK** -- integration-marked, skipped because this machine has no "
              "Postgres/Valkey/S3. Legitimate and identical in kind to the Phase 0-3 integration "
              "skips; cleared by re-running against `docker/compose.yaml`.")
            w("")
            _group(no_stack)
            w("")
        if no_excuse:
            w("**SKIPPED, NO EXCUSE** -- NOT integration-marked. PLAN.md section 7 Phase 4 "
              "requires these to be fixture-only with no host dependency, so this is a test that "
              "was disabled rather than a stack that was absent. Investigate before shipping.")
            w("")
            _group(no_excuse)
            w("")

    w("## Known gaps (reported, not silently papered over)")
    w("")
    for gap in run.known_gaps:
        w(f"- {gap}")
    w("")

    w("---")
    w("")
    w(
        "**STOP. Final review.** Present this report to the human. This is the LAST "
        "gate -- after human approval the project is feature-complete (PLAN.md section 7)."
    )
    w("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=REPO_ROOT / "gate_report_phase4.md")
    parser.add_argument("--pytest-timeout", type=float, default=600.0)
    parser.add_argument("--full-pytest-timeout", type=float, default=1800.0)
    parser.add_argument("--script-timeout", type=float, default=120.0)
    parser.add_argument("--mypy-timeout", type=float, default=300.0)
    args = parser.parse_args(argv)

    run = run_gate(
        out_path=args.out,
        pytest_timeout_s=args.pytest_timeout,
        full_pytest_timeout_s=args.full_pytest_timeout,
        script_timeout_s=args.script_timeout,
        mypy_timeout_s=args.mypy_timeout,
    )

    print(f"gate report written to {args.out}")
    print(f"overall verdict: {run.overall_verdict}")
    for a in run.assertions:
        print(f"  [{a.verdict:<16}] {a.number}. {a.title}")

    return 0 if run.overall_verdict == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())

