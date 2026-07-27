"""The Phase 3 gate runner (PLAN.md section 7 Phase 3 -- "Gate:" paragraph, verbatim):

    "guessed-reward test green (w=0 short-circuits; ambiguous -> zero
    mutations; downstream success moves Q up). Four-probe red team, none
    reach validated: (1) MPBench weak-signal policy-conformant false
    precedent, (2) OEP locally-correct non-transferable, (3) sleeper with
    dormancy > quarantine TTL, (4) correlated-trace corroboration (same
    principal / same input-signature cluster). Sybil test: propose_memory
    twice != corroboration. Retirement with K-1 principals routes to
    review_queue, not retire. Lift sim reports stratified lift with CI;
    "operational lane only" is a documented passing outcome (2026 evidence
    says it is the likely one). Ledger reconciles; cap pauses workers.
    Cross-epoch Q comparison rejected. STOP."

plus section 2 invariant 8's own test description and section 8 improvement
3 (the CUTTABLE "can it still walk" dependence test).

Same discipline as `harness/phase0_gate.py` / `harness/phase1_gate.py` /
`harness/phase2_gate.py` (all three read first, matched here): runs
`pytest -m phase3` once (so every assertion below is drawn from the SAME
execution, never two runs that could disagree), the three static gates
(`license_check.py`, `raw_sql_lint.py`, `purity_check.py`), plus NINE direct
library calls for the concrete numbers a bare JUnit pass/fail cannot carry on
its own: `harness.guessed_reward.run_guessed_reward_drill`,
`harness.redteam.probes.run_redteam`, `harness.redteam.probes.run_sybil_probe`,
`harness.redteam.probes.run_retirement_k_minus_one_probe`,
`harness.lift_sim.run_lift_sim`, `harness.ledger_audit.run_ledger_audit`,
`harness.dependence_test.run_dependence_drill`, and
`harness.closed_loop.run_closed_loop` -- then renders `gate_report_phase3.md`
mapping every result onto the eight PLAN.md section 7 Phase 3 clauses above,
plus the closed-loop clause and the baseline static-gates clause.

CLAUSE 9 IS NOT IN PLAN.md section 7. It was added on 2026-07-27, after
`docs/FIDELITY-AUDIT.md` found that every worker this phase built was correct
and none of them was reachable from a deployed process ("the learning half of
the system is a library, not a service"). It is CI-blocking on the same terms
as the eight named clauses, and for the same reason section 8's dependence
drill is: the failure it guards is silent everywhere else. Its own
measurement block states, beside the verdict, that it runs offline against
fakes -- so a PASS is "the nine production functions compose", never "the
learning plane is live in production".

THE REPORT MUST NOT LIE (`harness/phase0_gate.py`'s own words, carried
through every sibling gate unchanged, carried through here unchanged). Every
assertion is one of exactly four verdicts:

  * ``PASS``             -- every test/call backing this assertion ran and
                            passed.
  * ``FAIL``              -- at least one test/call backing it ran and failed.
  * ``SKIPPED-NO-STACK``  -- at least one test backing it could not run
                            (integration-marked, no Postgres/Valkey/S3) and
                            none of the ones that DID run failed.
  * ``INCOMPLETE-DATA``   -- this runner found ZERO tests matching the
                            assertion's selector at all -- a defect in the
                            gate report's own grouping, never folded silently
                            into SKIPPED-NO-STACK.

The overall verdict is ``PASS`` only when every one of the TEN assertions
below (the eight PLAN.md section 7 Phase 3 clauses, the closed-loop drill, and
the static-gates baseline) is individually ``PASS`` AND no `-m phase3` test anywhere skipped,
tracked or not (mirrors every sibling gate's own `test_gate_smoke.py`-pinned
behaviour: a skip is "this was not verified", never folded into a green top
line). Every clause here is CI-blocking: PLAN.md section 7 Phase 3 names all
eight as the gate, with no "informational" carve-out anywhere in it (unlike
Phase 1's latency bench, D-035) -- including clause 8, the dependence test,
which section 8 marks CUTTABLE (removable as a whole module) but not
optional while it exists.
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

# Mirrors every sibling gate's own note: a direct script run
# (`python harness/phase3_gate.py`) puts only `harness/` on `sys.path[0]`, so
# `import harness.guessed_reward` etc below would fail with
# `ModuleNotFoundError` despite `harness/__init__.py` existing right next to
# this file. Idempotent and harmless under pytest's own collection.
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

Verdict = Literal["PASS", "FAIL", "SKIPPED-NO-STACK", "INCOMPLETE-DATA"]

__all__ = ["main", "run_gate"]


# --------------------------------------------------------------------------- #
# JUnit XML parsing -- the one source of truth for every pytest-backed
# assertion. Duplicated from the sibling gates deliberately, not imported:
# those helpers are module-private (leading underscore, not in `__all__`),
# and per-chunk fake/helper duplication is an accepted convention in this
# codebase (PHASE0-CONTRACT.md section 13.1's own note).
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
    selection AND a direct library call -- FAIL beats everything, then
    INCOMPLETE-DATA, then SKIPPED-NO-STACK, then PASS. Mirrors
    `harness/phase2_gate.py`'s own `_worse` exactly."""
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
    """Never raises on a non-zero exit or a timeout -- both are gate findings,
    not runner crashes. Forces UTF-8 stdout, matching every sibling gate's
    own fix for a stock Windows console (cp1252) crashing
    `scripts/license_check.py`'s box-drawing glyph output."""
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


def _run_pytest_phase3(junit_path: Path, *, timeout_s: float) -> tuple[ProcResult, list[Case]]:
    result = _run(
        "pytest -m phase3",
        ["-m", "pytest", "-m", "phase3", "-q", f"--junitxml={junit_path}"],
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
# The eight PLAN.md section 7 Phase 3 gate clauses, plus the static-gates
# baseline.
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class AssertionReport:
    number: int
    title: str
    verdict: Verdict
    detail: str
    measurements: tuple[str, ...] = ()


def _assertion_guessed_reward(cases: list[Case]) -> AssertionReport:
    """"guessed-reward test green (w=0 short-circuits; ambiguous -> zero
    mutations; downstream success moves Q up)." Backed by
    `tests/phase3/test_scorer_q_update.py` (JUnit -- including
    `test_the_production_formula_is_not_the_original_weight_as_reward_bug`,
    the formula-shape pin PLAN.md section 2 invariant 8 asks for) AND a
    direct `harness.guessed_reward.run_guessed_reward_drill()` call, which
    drives the SAME scenarios end to end through `adapters.feedback.base
    .dispatch_feedback` (the edge) and `workers.scorer.run_scorer_batch`
    (the arithmetic) together.
    """
    from harness.guessed_reward import render_text, run_guessed_reward_drill

    selected = _select(cases, classname_contains="test_scorer_q_update")
    t = _tally(selected)

    report = run_guessed_reward_drill()
    verdict = _worse(t.verdict, "PASS" if report.ok else "FAIL")
    measurements = (render_text(report),)
    return AssertionReport(
        1,
        "Guessed-reward test: w=0 short-circuits; ambiguous -> zero mutations; "
        "downstream success moves Q up; formula shape pinned",
        verdict,
        _fmt_tally(t) + f"; direct drill: {'PASS' if report.ok else 'FAIL'}",
        measurements,
    )


def _assertion_four_probe_redteam(cases: list[Case]) -> AssertionReport:
    """"Four-probe red team, none reach validated: (1) MPBench weak-signal
    policy-conformant false precedent, (2) OEP locally-correct
    non-transferable, (3) sleeper with dormancy > quarantine TTL, (4)
    correlated-trace corroboration." Backed by
    `harness/redteam/test_redteam.py` (JUnit) AND a direct
    `harness.redteam.probes.run_redteam()` call, reporting the furthest
    status and stop reason for each of the four probes.
    """
    from harness.redteam.probes import render_text, run_redteam

    selected = _select(cases, classname_contains="redteam.test_redteam")
    t = _tally(selected)

    report = run_redteam()
    verdict = _worse(t.verdict, "PASS" if report.ok else "FAIL")
    measurements = (render_text(report),)
    return AssertionReport(
        2,
        "Four-probe red team: none reach validated (MPBench weak-signal, OEP "
        "locally-correct, sleeper dormancy, correlated-trace corroboration)",
        verdict,
        _fmt_tally(t) + f"; direct drill: {'PASS' if report.ok else 'FAIL'}",
        measurements,
    )


_SYBIL_TEST_NAMES: tuple[str, ...] = (
    "test_propose_memory_twice_never_exits_quarantine",
    "test_proposal_class_refuses_even_two_fully_independent_confirmations",
    "test_sybil_probe_overall_ok",
)


def _assertion_sybil(cases: list[Case]) -> AssertionReport:
    """"Sybil test: propose_memory twice != corroboration." Backed by
    `harness/redteam/test_redteam.py`'s Sybil tests (JUnit) AND a direct
    `harness.redteam.probes.run_sybil_probe()` call -- driven twice: once
    with the literal two-calls shape, once with two FULLY independent
    confirmations, proving D-023's refusal is unconditional rather than
    merely under-corroborated.
    """
    from harness.redteam.probes import run_sybil_probe

    selected = _select(cases, classname_contains="redteam.test_redteam", names=_SYBIL_TEST_NAMES)
    t = _tally(selected)

    report = run_sybil_probe()
    verdict = _worse(t.verdict, "PASS" if report.ok else "FAIL")
    measurements = (
        f"two propose_memory calls: reached={report.two_calls_result.furthest_status.value}, "
        f"stopped_by={report.two_calls_result.stopped_by}",
        f"two FULLY independent confirmations: reached="
        f"{report.two_independent_confirmations_result.furthest_status.value}, "
        f"stopped_by={report.two_independent_confirmations_result.stopped_by}",
    )
    return AssertionReport(
        3,
        "Sybil test: propose_memory twice is NOT corroboration, ever",
        verdict,
        _fmt_tally(t) + f"; direct drill: {'PASS' if report.ok else 'FAIL'}",
        measurements,
    )


_RETIREMENT_TEST_NAMES: tuple[str, ...] = (
    "test_k_minus_one_principals_routes_to_review_not_retire",
    "test_exactly_k_principals_retires_and_does_not_open_a_review_item",
)
_RETIREMENT_REDTEAM_TEST_NAMES: tuple[str, ...] = (
    "test_k_minus_one_principals_routes_to_review_queue_not_retire",
    "test_exactly_k_principals_is_the_positive_control_and_does_retire",
    "test_retirement_probe_overall_ok",
)


def _assertion_retirement_k_minus_one(cases: list[Case]) -> AssertionReport:
    """"Retirement with K-1 principals routes to review_queue, not retire."
    Backed by `tests/phase3/test_promotion.py` (the owning chunk's own
    coverage, JUnit) AND `harness/redteam/test_redteam.py`'s own retirement
    probe (JUnit) AND a direct
    `harness.redteam.probes.run_retirement_k_minus_one_probe()` call, whose
    positive control (exactly K principals) proves this is not a harness
    that silently never retires anything.
    """
    from harness.redteam.probes import run_retirement_k_minus_one_probe

    selected = _select(cases, classname_contains="tests.phase3.test_promotion", names=_RETIREMENT_TEST_NAMES)
    selected += _select(
        cases, classname_contains="redteam.test_redteam", names=_RETIREMENT_REDTEAM_TEST_NAMES
    )
    t = _tally(selected)

    report = run_retirement_k_minus_one_probe()
    verdict = _worse(t.verdict, "PASS" if report.ok else "FAIL")
    measurements = (
        f"K-1 principals: retired={report.k_minus_one.retired} "
        f"routed_to_review={report.k_minus_one.routed_to_review} "
        f"row_status={report.k_minus_one_row_status.value} "
        f"review_items={report.k_minus_one_review_items}",
        f"K principals (positive control): retired={report.k_control.retired} "
        f"row_status={report.k_control_row_status.value}",
    )
    return AssertionReport(
        4,
        "Retirement with K-1 distinct principals routes to review_queue, does NOT retire",
        verdict,
        _fmt_tally(t) + f"; direct drill: {'PASS' if report.ok else 'FAIL'}",
        measurements,
    )


def _assertion_lift_sim(cases: list[Case]) -> AssertionReport:
    """"Lift sim reports stratified lift with a CI; 'operational lane only'
    is a documented passing outcome." Backed by `tests/phase3/test_lift.py`
    (JUnit, including `TestStratifiedVsAggregate`) AND a direct
    `harness.lift_sim.run_lift_sim()` call. PASS never depends on the
    quality-lane sign -- see `harness.lift_sim.LiftSimReport.ok`'s own
    docstring: the only way this reads anything but PASS is a construction
    defect (insufficient data in a cell), never an unflattering lift number.
    """
    from harness.lift_sim import render_text, run_lift_sim

    selected = _select(cases, classname_contains="tests.phase3.test_lift")
    t = _tally(selected)

    report = run_lift_sim()
    simulated_note = (
        "SIMULATED — every observation below is generated by `harness.lift_sim`, not read from "
        "`retrieval_event`/`injection_log`/`outcome_event`. The arithmetic is the production "
        "`compute_stratified_lift`; the DATA is synthetic, the per-cell N is the simulator's "
        "own parameter, and the lane label attached to each cell is this harness's proxy. Read "
        "the p-value as 'the estimator behaves', never as 'memory paid for its context here'."
    )
    verdict = _worse(t.verdict, "PASS" if report.ok else "FAIL")
    measurements = (simulated_note, render_text(report))
    return AssertionReport(
        5,
        "Lift sim (SIMULATED DATA): stratified lift with a confidence interval; 'operational lane "
        "only' is a documented passing outcome, not a failure",
        verdict,
        _fmt_tally(t) + f"; direct drill: {'PASS' if report.ok else 'FAIL'}",
        measurements,
    )


def _assertion_ledger_and_cap(cases: list[Case]) -> AssertionReport:
    """"Ledger reconciles; the cap pauses workers and NOT the hot path."
    Backed by `tests/phase3/test_spend_enforce.py` (JUnit, including
    `TestHotPathUnaffected` against a REAL `Pipeline`) AND a direct
    `harness.ledger_audit.run_ledger_audit()` call, which additionally
    proves the ledger's own arithmetic reconciles (never asserted by the
    spend_enforce chunk's own tests, which fix `CapStatus` rather than
    accumulate through a real `SpendMeter`).
    """
    from harness.ledger_audit import render_text, run_ledger_audit

    selected = _select(cases, classname_contains="tests.phase3.test_spend_enforce")
    t = _tally(selected)

    report = run_ledger_audit()
    verdict = _worse(t.verdict, "PASS" if report.ok else "FAIL")
    measurements = (render_text(report),)
    return AssertionReport(
        6,
        "Ledger reconciles; the cap pauses workers and NOT the hot path",
        verdict,
        _fmt_tally(t) + f"; direct drill: {'PASS' if report.ok else 'FAIL'}",
        measurements,
    )


_CROSS_EPOCH_TEST_NAMES: tuple[str, ...] = (
    "test_a_judge_verdict_from_a_different_epoch_is_refused",
)


def _assertion_cross_epoch(cases: list[Case]) -> AssertionReport:
    """"Cross-epoch Q comparison rejected." Backed by
    `tests/phase3/test_epochs.py` (JUnit, the primitive's own suite) and
    `tests/phase3/test_scorer_q_update.py::test_a_judge_verdict_from_a_different_epoch_is_refused`
    (JUnit, the worker-level consumer) AND the cross-epoch scenario embedded
    in `harness.guessed_reward.run_guessed_reward_drill()` (both the
    `run_scorer_batch`-level check and the bare `assert_same_epoch`
    primitive).
    """
    from harness.guessed_reward import run_guessed_reward_drill

    selected = _select(cases, classname_contains="tests.phase3.test_epochs")
    selected += _select(
        cases, classname_contains="tests.phase3.test_scorer_q_update", names=_CROSS_EPOCH_TEST_NAMES
    )
    t = _tally(selected)

    report = run_guessed_reward_drill()
    verdict = _worse(t.verdict, "PASS" if report.cross_epoch_rejected_ok else "FAIL")
    return AssertionReport(
        7,
        "Cross-epoch Q comparison is rejected, not silently allowed",
        verdict,
        _fmt_tally(t) + f"; direct check: {'PASS' if report.cross_epoch_rejected_ok else 'FAIL'}",
    )


def _assertion_dependence(cases: list[Case]) -> AssertionReport:
    """"Can it still walk" -- PLAN.md section 8 improvement 3 (CUTTABLE),
    section 7 Phase 3 harness: "Periodically run the memory-off arm and
    assert task completion." Backed by `harness/dependence_test.py` (this
    module IS the `-m phase3` test file, per its own docstring on the
    `*_test.py` collection pattern) AND a direct
    `harness.dependence_test.run_dependence_drill()` call for the concrete
    completion-rate numbers.

    CUTTABLE (PLAN.md section 8) means the module and its tests can be
    removed as a bounded unit if a human vetoes it -- it does not mean this
    clause is informational while the module exists. Unlike Phase 1's
    latency bench (D-035's explicit carve-out), nothing in PLAN.md section 7
    Phase 3 excludes this clause from the gate, so it is CI-blocking here
    like every other clause.
    """
    from harness.dependence_test import render_text, run_dependence_drill

    selected = _select(cases, classname_contains="harness.dependence_test")
    t = _tally(selected)

    report = run_dependence_drill()
    verdict = _worse(t.verdict, "PASS" if report.ok else "FAIL")
    measurements = (
        "SIMULATED — the completion rates below are produced by a simulator whose own inputs "
        "are `dependence_test.BASE_CAPABILITY` (0.85) and `BOOSTED_CAPABILITY` (0.95). What "
        "this drill proves is that the REAL `assign_arm` and the REAL Pipeline wiring carry a "
        "memory-off arm through to completion, not that memory empirically helps by 10 points. "
        "No production run has ever been measured.",
        render_text(report),
    )
    return AssertionReport(
        8,
        '"Can it still walk": the memory-off (holdout) arm still completes its '
        "task -- memory is an enhancer, never a dependency",
        verdict,
        _fmt_tally(t) + f"; direct drill: {'PASS' if report.ok else 'FAIL'}",
        measurements,
    )


def _assertion_closed_loop(cases: list[Case]) -> AssertionReport:
    """The closed-loop drill -- `harness/closed_loop.py`, added in the 2026-07-27 integration
    pass in answer to `docs/FIDELITY-AUDIT.md` §1's headline finding ("the learning half of the
    system is a library, not a service").

    Backed by BOTH the JUnit cases from `tests/phase3/test_closed_loop_drill.py` (so the drill
    is COLLECTED, not merely runnable -- §11.1 records the same correction for the
    guessed-reward drill) AND a direct `run_closed_loop()` call here, so this clause reports the
    hop-by-hop result rather than a pytest tally alone.

    WHAT A PASS HERE MEANS, and the disclosure belongs beside the verdict rather than 300 lines
    below it (S34's correction): the nine production functions COMPOSE -- the row each stage
    writes is the row the next stage reads. It does NOT mean a deployed process runs them. Ten
    of the thirteen periodic workers are still unscheduled, each blocked on a Postgres port that
    does not exist, and `workers.composition.UNSCHEDULED_WORKERS` names every one. The
    measurement block below prints that list, so this clause cannot be quoted as "the learning
    plane is live".
    """
    from harness.closed_loop import render_text, run_closed_loop

    selected = _select(cases, classname_contains="tests.phase3.test_closed_loop_drill")
    t = _tally(selected)

    report = run_closed_loop()
    verdict = _worse(t.verdict, "PASS" if report.closed else "FAIL")
    passed = sum(1 for hop in report.hops if hop.passed)
    return AssertionReport(
        9,
        "Closed-loop drill: trace -> Tier A candidate -> embedded -> corroborated -> shadow"
        "-validated -> scored -> promoted -> retrievable -> status PERSISTED",
        verdict,
        _fmt_tally(t) + f"; direct drill: {passed}/{len(report.hops)} hops",
        (
            "AGAINST FAKES BY CONSTRUCTION -- every hop runs against in-memory implementations "
            "of the worker's own declared Protocol (plus the recording fake pool for the status "
            "write, which proves the statements are ISSUED, not that a database accepted them), "
            "whether or not a live stack is present; this drill does not probe or drive one. A "
            "PASS is 'the loop closes when every store method exists', not 'the loop closes in "
            "production today'.",
            render_text(report),
        ),
    )


def _assertion_static_gates(
    license_result: ProcResult, raw_sql_result: ProcResult, purity_result: ProcResult
) -> AssertionReport:
    """Not one of PLAN.md section 7 Phase 3's eight named clauses, but part of
    the unconditional baseline this task brief states must not regress:
    `license_check.py` / `raw_sql_lint.py` / `purity_check.py` all green --
    the purity gate especially, since invariant 1 ("nothing under hotpath/
    may reach workers/ or a generative client") is exactly what several of
    this phase's new workers (scorer, shadow_validator, killswitch,
    spend_enforce) could otherwise violate.
    """
    ok = license_result.ok and raw_sql_result.ok and purity_result.ok
    verdict: Verdict = "PASS" if ok else "FAIL"
    detail = (
        f"license_check.py: exit={license_result.returncode} ({'PASS' if license_result.ok else 'FAIL'}); "
        f"raw_sql_lint.py: exit={raw_sql_result.returncode} ({'PASS' if raw_sql_result.ok else 'FAIL'}); "
        f"purity_check.py: exit={purity_result.returncode} ({'PASS' if purity_result.ok else 'FAIL'})"
    )
    return AssertionReport(10, "License + raw-SQL lint + purity gate green (baseline, must not regress)", verdict, detail)


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
    "READ CLAUSE 2 WITH THIS: `archived` IS NOT A TERMINAL STATUS, and all four adversarial "
    "probes terminate there. `TRANSITIONS[(ARCHIVED, VALIDATED)]` is a legal edge whose guard "
    "is `operator_restore` -- so for every provenance class except `proposal`, a probe "
    "recorded as 'furthest_status: archived, never validated' has been PARKED one unguarded "
    "edge from full retrievability, not stopped. This harness never exercises that edge, so "
    "clause 2's PASS means 'no probe reached validated along the corroboration path it "
    "attacked', NOT 'no probe can reach validated'. Found by exhaustive reachability search "
    "at Phase 3 integration, not by this red team. The `proposal` case WAS a live hole "
    "(propose_memory -> quarantine TTL -> archived -> operator restore reached `validated` "
    "having never invoked `independent_confirmations`) and is now closed in "
    "`_guard_archived_to_validated`; the broader case is recorded as DECISIONS D-085 and "
    "pinned by `tests/phase3/test_learning_loop_seams.py`.",
    "The narrative DRILLS in this report (guessed-reward, the four-probe red team, the Sybil "
    "probe, the retirement probe, the lift sim, the ledger audit, the dependence drill) run "
    "against in-memory fakes satisfying the Protocol ports the Phase 3 worker chunks were built "
    "and tested against, BY CONSTRUCTION -- those drills never drive a live stack, regardless of "
    "whether one is present. The gate's SEPARATE `pytest -m phase3` run does exercise the real "
    "stores against a database when one is reachable: Postgres-backed implementations of "
    "ScorerRepoPort / ShadowValidatorRepoPort / PromotionRepoPort / KillswitchStorePort now "
    "exist (`stores.pg.{scoring,shadow_validator,promotion,killswitch}`, on `LearningPlane`) and "
    "carry `@pytest.mark.integration` coverage (tests/phase3/test_pg_scoring.py, "
    "test_pg_promotion.py, test_pg_killswitch_writer.py, test_status_persistence.py). Those "
    "workers nonetheless remain unscheduled in production for the reasons "
    "`workers.composition.UNSCHEDULED_WORKERS` names, not for want of a store.",
    "`hotpath.pipeline.Pipeline` does not yet withhold or relabel injection on the holdout "
    "arm (`workers/lift.py`'s own docstring: 'hotpath.pipeline also returns the rendered "
    "block to the caller on the holdout arm rather than discarding it'). "
    "`harness.dependence_test.run_dependence_drill` does not reproduce that gap -- it decides "
    "the memory-on/memory-off split itself (via the real `hotpath.holdout.assign_arm`, at the "
    "documented holdout percentage) and routes each simulated session through whichever "
    "assembly matches the INTENDED target behaviour, rather than reading `RetrieveResult.arm` "
    "back off a Pipeline that does not yet act on it. `harness.lift_sim` has the identical "
    "documented dependency on this gap for its own treatment/shadow-control split.",
    "`harness.lift_sim`'s 'quality lane' vs 'operational lane' framing is this harness's own "
    "interpretive proxy (mem_type=lesson vs mem_type=episodic) over `workers.lift."
    "LiftObservation`, which has no `lane` field of its own -- `lane` lives on `memory_item`, "
    "one level above what the stratification key (`agent_type_id`, `mem_type`) carries. A real "
    "deployment's lift report would need that join to make the same lane-level claim; this "
    "drill's numbers are real (computed by the production `compute_stratified_lift`/"
    "`estimate_lift`), the LANE LABEL attached to each cell is not.",
    "`harness.dependence_test.BASE_CAPABILITY`/`BOOSTED_CAPABILITY` and "
    "`MIN_ACCEPTABLE_COMPLETION_RATE`, and `harness.lift_sim`'s per-cell treatment/control "
    "probabilities, are this harness's own documented modelling choices -- PLAN.md section 6 "
    "defines no config field for 'how capable is an agent without Tracebed' or 'how much true "
    "lift does the operational lane have', because neither is a governed threshold, only a "
    "reporting convention for a simulation.",
    "Cross-chunk (reported by sibling builders, not introduced or fixed here): several "
    "Phase 3 test modules are order-dependent under `pytest-randomly` (observed by the "
    "distiller/killswitch-spend/review-forensics chunks across "
    "`tests/phase3/test_distiller.py`, `test_contribution_judge.py`, `test_forensics.py`, "
    "`test_killswitch.py`, `test_independence.py`, `test_operator_edit.py`, "
    "`test_feedback_adapters.py`, and `test_scorer_q_update.py`'s own tie-break test, which "
    "asserts a total order `select_daily_winner` does not fully provide under every seed). "
    "This gate runs `pytest -m phase3` exactly once, the same way every sibling gate does, so "
    "whichever seed pytest-randomly picks on a given invocation is what this report reflects "
    "-- it is not silently retried or reseeded to produce a flattering run.",
)

_TRACKED_CLASSNAME_KEYWORDS: tuple[str, ...] = (
    "test_scorer_q_update",
    "redteam.test_redteam",
    "tests.phase3.test_promotion",
    "tests.phase3.test_lift",
    "tests.phase3.test_spend_enforce",
    "tests.phase3.test_epochs",
    "harness.dependence_test",
)


def _untracked_failures(cases: list[Case]) -> tuple[Case, ...]:
    """Every failed/errored `-m phase3` case outside the eight tracked
    clauses above -- so a real failure in, say,
    `tests/phase3/test_shadow_validation.py`, `test_killswitch.py`,
    `test_independence.py`, `test_contribution_judge.py`,
    `test_distiller.py`, `test_forensics.py`, `test_review_queue.py`,
    `test_operator_edit.py`, or `test_feedback_adapters.py` can never be
    invisible just because it falls outside this file's eight groupings.
    Mirrors every sibling gate's own `_untracked_failures` exactly."""
    return tuple(
        c
        for c in cases
        if c.status in ("failed", "error") and not any(k in c.classname for k in _TRACKED_CLASSNAME_KEYWORDS)
    )


def _untracked_skips(cases: list[Case]) -> tuple[Case, ...]:
    """Every SKIPPED `-m phase3` case outside the eight tracked clauses.
    Load-bearing, not belt-and-braces (mirrors every sibling gate's own
    docstring on this): PASS requires that everything under `-m phase3`
    actually RAN, not merely that the eight selected groups did."""
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
) -> GateRun:
    junit_path = REPO_ROOT / ".phase3_gate_junit.xml"

    pytest_result, cases = _run_pytest_phase3(junit_path, timeout_s=pytest_timeout_s)
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
        _assertion_guessed_reward(cases),
        _assertion_four_probe_redteam(cases),
        _assertion_sybil(cases),
        _assertion_retirement_k_minus_one(cases),
        _assertion_lift_sim(cases),
        _assertion_ledger_and_cap(cases),
        _assertion_cross_epoch(cases),
        _assertion_dependence(cases),
        _assertion_closed_loop(cases),
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
    w("# Phase 3 gate report")
    w("")
    w(f"Generated: {run.generated_at}")
    w("")
    w(f"## Overall verdict: **{run.overall_verdict}**")
    w("")
    if run.overall_verdict == "PASS":
        # S34 (fidelity audit), updated at live bring-up: the verdict rule forces INCOMPLETE if
        # ANY `-m phase3` case skips, so a PASS is only reachable when every case RAN. This phase
        # now DOES carry @pytest.mark.integration tests against the new Postgres stores, so a
        # PASS here means those integration tests actually executed against a live stack -- it is
        # no longer the "no integration tests, nothing to skip" green the earlier prose claimed.
        w(
            "> **What this PASS does and does not mean.** Every `-m phase3` case executed and "
            "passed, with 0 SKIPPED -- and because the overall verdict rule forces INCOMPLETE "
            "(never PASS) the moment any `-m phase3` case skips, a PASS here is only reachable "
            "when this phase's `@pytest.mark.integration` tests against the new Postgres stores "
            "(tests/phase3/test_pg_scoring.py, test_pg_promotion.py, test_pg_killswitch_writer.py, "
            "test_status_persistence.py) actually RAN against a live database this run, not "
            "merely against in-memory doubles. Several of the worker ports M3 enumerates now have "
            "a Postgres implementation on `LearningPlane` (`stores.pg.{scoring,shadow_validator,"
            "promotion,killswitch,memory_lifecycle,derived_state_store,distillation}`, plus the "
            "D-128 `EmbeddingRepoPort` / `CorroborationRepoPort` / `MemoryEditRepoPort` / "
            "`ForensicsRepoPort`). The narrative DRILLS rendered below additionally exercise the "
            "worker logic against in-memory doubles by construction. So a green verdict is "
            "evidence both that the logic composes and that the integration SQL executed; the "
            "remaining production gap is scheduling, which `workers.composition."
            "UNSCHEDULED_WORKERS` names, not a missing store."
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

    w("## The eight PLAN.md section 7 Phase 3 gate clauses (plus the static-gates baseline)")
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

    w("## `pytest -m phase3`")
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
    tail = run.pytest_result.stdout.strip().splitlines()[-80:]
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
        w("## Failures outside the eight tracked clauses")
        w("")
        w(
            "These `-m phase3` failures do not belong to any of the eight tracked clauses "
            "above, but they are real and are why the overall verdict is **FAIL** even if "
            "every row in the table above reads PASS."
        )
        w("")
        for c in run.untracked_failures:
            w(f"- `{c.classname}::{c.name}` -- {c.status}: {c.message or '(no message)'}")
        w("")

    if run.untracked_skips:
        w("## Tests that did not run, outside the eight tracked clauses")
        w("")
        w(
            f"{len(run.untracked_skips)} `-m phase3` test(s) were SKIPPED and belong to none "
            "of the eight tracked clauses above, so no row in that table reflects them. They "
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
            w(f"- `{classname}` -- {len(group)} skipped: {reason}")
        w("")

    w("## Known gaps (reported, not silently papered over)")
    w("")
    for gap in run.known_gaps:
        w(f"- {gap}")
    w("")

    w("---")
    w("")
    w("**STOP.** Present this report to the human. Do not begin Phase 4 without explicit approval (PLAN.md section 7).")
    w("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=REPO_ROOT / "gate_report_phase3.md")
    parser.add_argument("--pytest-timeout", type=float, default=600.0)
    parser.add_argument("--script-timeout", type=float, default=120.0)
    args = parser.parse_args(argv)

    run = run_gate(
        out_path=args.out,
        pytest_timeout_s=args.pytest_timeout,
        script_timeout_s=args.script_timeout,
    )

    print(f"gate report written to {args.out}")
    print(f"overall verdict: {run.overall_verdict}")
    for a in run.assertions:
        print(f"  [{a.verdict:<16}] {a.number}. {a.title}")

    return 0 if run.overall_verdict == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
