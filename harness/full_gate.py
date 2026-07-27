"""The FULL project gate (PLAN.md section 7): runs all FOUR phase gates
(`harness/phase0_gate.py` through `harness/phase4_gate.py` -- five modules, four
"phases" of build work plus this final Phase 4 review gate) IN ORDER and emits
`gate_report_full.md` -- one document showing the whole project state.

THE OVERALL VERDICT IS THE WEAKEST OF THE FIVE. If any phase gate reads INCOMPLETE, the
project is INCOMPLETE; if any reads FAIL, the project is FAIL. There is no averaging, no
"4 of 5 passed" framing, and no code path here that can report PASS while one of the
five phase gates disagrees.

IT MUST BE IMPOSSIBLE TO READ THIS DOCUMENT AND COME AWAY THINKING THE LEAK SUITE RAN
WHEN IT DID NOT (this task's own brief, verbatim). The mechanism: this module does not
re-derive, re-summarise, or paraphrase any phase gate's own findings -- it calls that
phase's OWN `run_gate()` function (the identical entry point a human running that gate
standalone would call), takes the identical `gate_report_phaseN.md` that call writes to
disk, and embeds that file's ENTIRE rendered content verbatim inside a collapsible
section here. There is no second copy of "what phase 0 found" living in this file that
could drift from what `gate_report_phase0.md` itself says -- if phase 0's own report
says "INCOMPLETE -- leak suite needs Postgres", that exact sentence is what appears
here, not a rephrasing of it that could accidentally drop the caveat.

A PHASE GATE RUNNER CRASHING IS NOT SILENTLY SKIPPED. If calling a phase's `run_gate()`
itself raises (as opposed to that phase's own tests/checks failing, which `run_gate()`
already reports as a normal FAIL/INCOMPLETE verdict), this module records that phase as
FAIL -- the worst possible verdict -- with the exception recorded in the text, rather
than omitting the phase or reporting a stale/absent report as if it were a pass. "The
report crashed before it could tell us anything" must never read as quieter than "the
report told us something bad".
"""

from __future__ import annotations

import sys
import traceback
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

REPO_ROOT = Path(__file__).resolve().parent.parent

# Mirrors every sibling gate's own note: a direct script run (`python
# harness/full_gate.py`) puts only `harness/` on `sys.path[0]`, so `from harness import
# phase0_gate` etc below would fail with `ModuleNotFoundError` despite
# `harness/__init__.py` existing right next to this file.
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from harness import phase0_gate, phase1_gate, phase2_gate, phase3_gate, phase4_gate  # noqa: E402

Verdict = Literal["PASS", "FAIL", "INCOMPLETE"]

__all__ = ["main", "run_full_gate"]

# FAIL is worse than INCOMPLETE is worse than PASS -- the weakest-of-five rule.
_SEVERITY: dict[Verdict, int] = {"PASS": 0, "INCOMPLETE": 1, "FAIL": 2}


def _worst(verdicts: list[Verdict]) -> Verdict:
    return max(verdicts, key=lambda v: _SEVERITY[v]) if verdicts else "FAIL"


@dataclass(frozen=True, slots=True)
class PhaseResult:
    key: str
    label: str
    verdict: Verdict
    report_path: Path
    report_markdown: str
    crashed: str | None
    """`None` if the phase's own `run_gate()` returned normally (whatever verdict it
    computed); otherwise the exception's traceback text -- the phase gate RUNNER itself
    failed to execute, which is distinct from, and worse than, that phase's own tests
    failing."""


def _run_phase0(*, out_path: Path, pytest_timeout_s: float, script_timeout_s: float) -> phase0_gate.GateRun:
    return phase0_gate.run_gate(out_path=out_path, pytest_timeout_s=pytest_timeout_s, script_timeout_s=script_timeout_s)


def _run_phase1(*, out_path: Path, pytest_timeout_s: float, script_timeout_s: float) -> phase1_gate.GateRun:
    return phase1_gate.run_gate(out_path=out_path, pytest_timeout_s=pytest_timeout_s, script_timeout_s=script_timeout_s)


def _run_phase2(*, out_path: Path, pytest_timeout_s: float, script_timeout_s: float) -> phase2_gate.GateRun:
    return phase2_gate.run_gate(out_path=out_path, pytest_timeout_s=pytest_timeout_s, script_timeout_s=script_timeout_s)


def _run_phase3(*, out_path: Path, pytest_timeout_s: float, script_timeout_s: float) -> phase3_gate.GateRun:
    return phase3_gate.run_gate(out_path=out_path, pytest_timeout_s=pytest_timeout_s, script_timeout_s=script_timeout_s)


def _run_phase4(
    *,
    out_path: Path,
    pytest_timeout_s: float,
    full_pytest_timeout_s: float,
    script_timeout_s: float,
    mypy_timeout_s: float,
) -> phase4_gate.GateRun:
    return phase4_gate.run_gate(
        out_path=out_path,
        pytest_timeout_s=pytest_timeout_s,
        full_pytest_timeout_s=full_pytest_timeout_s,
        script_timeout_s=script_timeout_s,
        mypy_timeout_s=mypy_timeout_s,
    )


def _read_report(out_path: Path, *, crash_note: str | None) -> str:
    if out_path.exists():
        return out_path.read_text(encoding="utf-8")
    if crash_note is not None:
        return (
            "**NO REPORT WAS WRITTEN.** The gate runner raised before it could produce "
            f"`{out_path.name}`. This phase is recorded as FAIL, not omitted, because a "
            "runner that crashed verified NOTHING -- that is strictly worse than a "
            "runner that ran and found a problem.\n\n```\n" + crash_note + "\n```\n"
        )
    return f"**NO REPORT FOUND** at `{out_path}` and no crash was recorded either -- this is a defect in `harness/full_gate.py` itself."


def run_full_gate(
    *,
    out_path: Path,
    pytest_timeout_s: float = 600.0,
    full_pytest_timeout_s: float = 1800.0,
    script_timeout_s: float = 120.0,
    mypy_timeout_s: float = 300.0,
) -> FullGateRun:
    phases: list[PhaseResult] = []

    def _attempt(key: str, label: str, out_name: str, call: object) -> None:
        out = REPO_ROOT / out_name
        verdict: Verdict
        crashed: str | None
        try:
            run = call()  # type: ignore[operator]
            verdict = run.overall_verdict
            crashed = None
        except Exception:  # a crashed gate runner IS a top-level finding, not a bug to hide
            verdict = "FAIL"
            crashed = traceback.format_exc()
        markdown = _read_report(out, crash_note=crashed)
        phases.append(
            PhaseResult(
                key=key, label=label, verdict=verdict, report_path=out, report_markdown=markdown, crashed=crashed
            )
        )

    _attempt(
        "phase0",
        "Phase 0 -- Trace substrate, isolation, structural security",
        "gate_report_phase0.md",
        lambda: _run_phase0(
            out_path=REPO_ROOT / "gate_report_phase0.md",
            pytest_timeout_s=pytest_timeout_s,
            script_timeout_s=script_timeout_s,
        ),
    )
    _attempt(
        "phase1",
        "Phase 1 -- Hot path",
        "gate_report_phase1.md",
        lambda: _run_phase1(
            out_path=REPO_ROOT / "gate_report_phase1.md",
            pytest_timeout_s=pytest_timeout_s,
            script_timeout_s=script_timeout_s,
        ),
    )
    _attempt(
        "phase2",
        "Phase 2 -- Operational lane + staleness",
        "gate_report_phase2.md",
        lambda: _run_phase2(
            out_path=REPO_ROOT / "gate_report_phase2.md",
            pytest_timeout_s=pytest_timeout_s,
            script_timeout_s=script_timeout_s,
        ),
    )
    _attempt(
        "phase3",
        "Phase 3 -- Quality lane + learning",
        "gate_report_phase3.md",
        lambda: _run_phase3(
            out_path=REPO_ROOT / "gate_report_phase3.md",
            pytest_timeout_s=pytest_timeout_s,
            script_timeout_s=script_timeout_s,
        ),
    )
    _attempt(
        "phase4",
        "Phase 4 -- Workflow memory + polish (this task's own gate)",
        "gate_report_phase4.md",
        lambda: _run_phase4(
            out_path=REPO_ROOT / "gate_report_phase4.md",
            pytest_timeout_s=pytest_timeout_s,
            full_pytest_timeout_s=full_pytest_timeout_s,
            script_timeout_s=script_timeout_s,
            mypy_timeout_s=mypy_timeout_s,
        ),
    )

    overall = _worst([p.verdict for p in phases])
    run = FullGateRun(generated_at=datetime.now(UTC).isoformat(), overall_verdict=overall, phases=tuple(phases))
    out_path.write_text(render_markdown(run), encoding="utf-8")
    return run


@dataclass(frozen=True, slots=True)
class FullGateRun:
    generated_at: str
    overall_verdict: Verdict
    phases: tuple[PhaseResult, ...]


def render_markdown(run: FullGateRun) -> str:
    lines: list[str] = []
    w = lines.append
    w("# Tracebed -- full project gate report")
    w("")
    w(f"Generated: {run.generated_at}")
    w("")
    w(f"## Overall verdict: **{run.overall_verdict}**")
    w("")
    w(
        "The overall verdict is the WEAKEST of the five phase gates below "
        "(FAIL > INCOMPLETE > PASS) -- never an average, never \"most phases passed\"."
    )
    w("")
    if run.overall_verdict == "FAIL":
        w("> At least one phase gate FAILED (or its runner crashed). The project is NOT feature-complete.")
    elif run.overall_verdict == "INCOMPLETE":
        w(
            "> No phase gate FAILED, but at least one could not be fully verified. This is "
            "**not** a pass -- see each phase's own report below for exactly what was and was "
            "not verified, and (for any integration-coverage caveat) whether it reflects an "
            "actual skip observed in this run rather than an assumed absent stack."
        )
    else:
        w("> All five phase gates read PASS.")
    w("")

    w("## Phase-by-phase summary")
    w("")
    w("| Phase | Verdict | Report |")
    w("|---|---|---|")
    for p in run.phases:
        crash_note = " (**gate runner crashed**)" if p.crashed is not None else ""
        w(f"| {p.label} | **{p.verdict}**{crash_note} | `{p.report_path.name}` |")
    w("")

    w(
        "Each phase's own report is embedded IN FULL below, verbatim, exactly as that "
        "phase's own `run_gate()` wrote it to disk -- nothing here paraphrases or "
        "re-summarises a phase's findings, so there is no second copy of the truth that "
        "could drift from the first."
    )
    w("")

    for p in run.phases:
        w(f"## {p.label} -- **{p.verdict}**")
        w("")
        w(f"<details><summary>Full `{p.report_path.name}` (click to expand)</summary>")
        w("")
        w(p.report_markdown)
        w("")
        w("</details>")
        w("")

    w("---")
    w("")
    w(
        "**This is the full-project gate.** PLAN.md section 7 Phase 4 is the last "
        "phase; a **PASS** overall verdict here, after explicit human approval, is what "
        "makes the project feature-complete."
    )
    w("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=REPO_ROOT / "gate_report_full.md")
    parser.add_argument("--pytest-timeout", type=float, default=600.0)
    parser.add_argument("--full-pytest-timeout", type=float, default=1800.0)
    parser.add_argument("--script-timeout", type=float, default=120.0)
    parser.add_argument("--mypy-timeout", type=float, default=300.0)
    args = parser.parse_args(argv)

    run = run_full_gate(
        out_path=args.out,
        pytest_timeout_s=args.pytest_timeout,
        full_pytest_timeout_s=args.full_pytest_timeout,
        script_timeout_s=args.script_timeout,
        mypy_timeout_s=args.mypy_timeout,
    )

    print(f"gate report written to {args.out}")
    print(f"overall verdict: {run.overall_verdict}")
    for p in run.phases:
        print(f"  [{p.verdict:<11}] {p.label}")

    return 0 if run.overall_verdict == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
