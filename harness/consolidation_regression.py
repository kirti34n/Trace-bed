"""Consolidation regression harness (PLAN.md §7 Phase 2 / §8 improvement 4).

CUTTABLE (PLAN.md §8): this harness — NOT `workers/consolidator.py` itself, which is core
and not cuttable — may be removed without touching anything else; "cutting it removes a
bounded module and its tests, nothing else."

ACE (arXiv:2510.04618, ICLR 2026) names brevity bias and context collapse as the failure
modes of exactly the nightly-merge consolidation loop this harness simulates: a
consolidator that rewrites an item wholesale progressively strips detail until the memory
says something shorter and less true than what it replaced, and nothing detects it because
each individual rewrite looked reasonable in isolation.

This harness seeds N distinct, independently-verifiable facts (each carrying a unique,
grep-able marker token — checking "is this token still present" needs no human or LLM
judge, matching the operational lane's own LLM-free constraint), runs K consolidation
sweeps against the real `workers.consolidator.Consolidator` on a `FakeClock` (hard rule 3:
the soak this stands in for is Phase 2's own 30-simulated-day gate; a wall-clock read here
would make it unrunnable), and after EVERY sweep — not just the last — checks that every
fact's marker is still recoverable. Retention is reported PER SWEEP because that is the
whole point: brevity bias shows up as retention DECAY across sweeps, and a report that only
checks the end could pass while every sweep in between silently lost and regained
information.

Each sweep's "incoming" observation is deliberately not byte-identical to the previous
one (the surrounding text changes; the marker never does) so every sweep genuinely
exercises the AMEND code path rather than a single ADD followed by K-1 no-ops — a harness
that only ever no-ops would not be exercising the consolidator's rewrite logic at all.

Each sweep also observes only a SUBSET of the facts (`PARTIAL_OBSERVATION_STRIDE`), and
that is the part that makes the 100%-retention number mean something. A harness where
every sweep re-states all N facts reports 100% retention no matter what the consolidator
does with facts it did not hear about this run — the number is true and empty, and the
exact regression it is supposed to catch (a consolidator that reads "absent from this
sweep's input" as "retired") passes it clean. Partial observation is also the realistic
input: a nightly consolidation's upstream re-derives its elements per run, and a partial
extractor batch or a reordered fetch routinely surfaces a subset. The rotation is by
stride so that every fact is unobserved on some sweeps and observed on others, and no
fact is permanently in either group.

Usage:
    python harness/consolidation_regression.py
    python harness/consolidation_regression.py --n-facts 20 --n-sweeps 30 --json
"""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from typing import Any, Final

from tracebed.domain.clock import FakeClock
from tracebed.domain.ids import MemoryId, mint_memory_id
from tracebed.workers.consolidator import Consolidator
from tracebed.workers.deltas import Element, ElementSet

__all__ = [
    "ConsolidationRegressionReport",
    "SweepResult",
    "main",
    "render_text",
    "run_consolidation_regression",
]

DEFAULT_N_FACTS: Final = 20
DEFAULT_N_SWEEPS: Final = 30

#: One fact in every `PARTIAL_OBSERVATION_STRIDE` is withheld from each sweep's
#: observation, rotating with the sweep number. A fixture parameter of this
#: harness, not a production tunable — nothing in `workers/` reads it — so it
#: belongs here beside the other two, not in `domain/config.py` (hard rule 4 is
#: about behaviour constants in the service, and PLAN.md §6 defines no
#: consolidation fields at all).
PARTIAL_OBSERVATION_STRIDE: Final = 3


def _fact_name(i: int) -> str:
    return f"fact_{i}"


def _marker(i: int) -> str:
    """A unique, grep-able token per fact. Retention is "is this token still
    present", not "does the text look similar" — checkable without a human
    or an LLM judge."""
    return f"MARKER-{i:04d}"


def _seed_elements(n_facts: int) -> tuple[Element, ...]:
    """The memory's structured content as it stands before this harness's own
    sweeps begin — as if some earlier distillation had already produced it."""
    return tuple(
        Element(name=_fact_name(i), text=f"{_marker(i)}: distinct verifiable fact number {i}")
        for i in range(n_facts)
    )


def _observed_indices(n_facts: int, sweep: int) -> tuple[int, ...]:
    """The subset of facts this sweep re-observes (module docstring). Falls
    back to all of them when the stride would leave the sweep with nothing to
    observe, which happens only at `n_facts < PARTIAL_OBSERVATION_STRIDE`: an
    empty observation emits no deltas, and a sweep that emitted no deltas
    cannot demonstrate retention across a rewrite."""
    observed = tuple(
        i for i in range(n_facts) if (i + sweep) % PARTIAL_OBSERVATION_STRIDE != 0
    )
    return observed or tuple(range(n_facts))


def _observed_elements(n_facts: int, sweep: int) -> tuple[Element, ...]:
    """A fresh re-observation of a subset of the N facts on a given sweep —
    deliberately NOT byte-identical to the seed or to any other sweep's
    observation (a real nightly consolidation re-derives its input every
    run), so every sweep genuinely exercises the AMEND path. The marker is
    carried through unchanged; only the surrounding text changes. Facts this
    sweep does not observe are simply absent from `incoming` — the
    consolidator must carry them forward untouched."""
    return tuple(
        Element(
            name=_fact_name(i),
            text=(
                f"{_marker(i)}: distinct verifiable fact number {i} "
                f"(re-observed at sweep {sweep})"
            ),
        )
        for i in _observed_indices(n_facts, sweep)
    )


def _retained_count(state: ElementSet, n_facts: int) -> int:
    by_name = state.by_name()
    count = 0
    for i in range(n_facts):
        element = by_name.get(_fact_name(i))
        if element is not None and _marker(i) in element.text:
            count += 1
    return count


@dataclass(frozen=True, slots=True)
class SweepResult:
    sweep: int
    deltas_emitted: int
    observed: int
    """How many of `total` this sweep actually re-observed. Reported because
    `retained == total` is only evidence of anything when `observed < total`:
    it is the gap between the two that a fact must survive."""
    retained: int
    total: int

    @property
    def retention_pct(self) -> float:
        return 100.0 * self.retained / self.total


@dataclass(frozen=True, slots=True)
class ConsolidationRegressionReport:
    n_facts: int
    n_sweeps: int
    sweeps: tuple[SweepResult, ...]

    def __post_init__(self) -> None:
        # `ok` and `min_retention_pct` are both vacuously perfect over an empty
        # sweep list, so a report that measured nothing would otherwise PASS.
        if not self.sweeps:
            raise ValueError("a consolidation regression report must contain at least one sweep")

    @property
    def min_retention_pct(self) -> float:
        return min(s.retention_pct for s in self.sweeps)

    @property
    def unobserved_carried_forward(self) -> int:
        """Total fact-sweeps where a fact was NOT re-observed and survived
        anyway. Zero means every sweep re-stated everything, i.e. the run
        proved nothing about carry-forward however good its retention looked."""
        return sum(s.total - s.observed for s in self.sweeps)

    @property
    def ok(self) -> bool:
        """100% retention on EVERY sweep — not just the last one (module
        docstring: retention decay across sweeps is the whole signal a
        brevity-bias regression would show up as) — and at least one fact
        carried forward unobserved, without which the retention figure is
        true but empty."""
        return all(s.retained == s.total for s in self.sweeps) and (
            self.unobserved_carried_forward > 0
        )


def run_consolidation_regression(
    *, n_facts: int = DEFAULT_N_FACTS, n_sweeps: int = DEFAULT_N_SWEEPS
) -> ConsolidationRegressionReport:
    """Seeds `n_facts` distinct facts, runs `n_sweeps` consolidation sweeps
    against the real `Consolidator` on a `FakeClock`, and reports retention
    after every single sweep. Never raises on its own — a real retention
    failure surfaces as `SweepResult.retained < SweepResult.total`, which the
    caller (a pytest wrapper, or `main`'s exit code below) turns into a hard
    failure; this function's job is to measure and report, matching the
    convention of the sibling Phase 1 harness modules (`failopen_drill.py`,
    `negative_probes/probes.py`).

    Rejects degenerate scales rather than reporting on them: `n_facts=0` makes
    `SweepResult.retention_pct` a division by zero, and `n_sweeps=0` produces a
    report with nothing in it that every assertion below passes.
    """
    if n_facts < 1:
        raise ValueError(f"n_facts must be >= 1, got {n_facts}")
    if n_sweeps < 1:
        raise ValueError(f"n_sweeps must be >= 1, got {n_sweeps}")

    clock = FakeClock()
    consolidator = Consolidator(clock)
    memory_id: MemoryId = mint_memory_id()

    state = ElementSet(elements=_seed_elements(n_facts))
    results: list[SweepResult] = []

    for sweep in range(1, n_sweeps + 1):
        clock.advance(days=1)  # simulated-day cadence, matching Phase 2's own soak gate
        incoming = _observed_elements(n_facts, sweep)
        outcome = consolidator.consolidate(memory_id, state, incoming, sweep=sweep)
        state = outcome.after
        results.append(
            SweepResult(
                sweep=sweep,
                deltas_emitted=len(outcome.deltas),
                observed=len(incoming),
                retained=_retained_count(state, n_facts),
                total=n_facts,
            )
        )

    return ConsolidationRegressionReport(n_facts=n_facts, n_sweeps=n_sweeps, sweeps=tuple(results))


def render_text(report: ConsolidationRegressionReport) -> str:
    lines = [
        f"consolidation regression: {report.n_facts} facts x {report.n_sweeps} sweeps",
        "",
        f"{'sweep':>6} {'deltas':>8} {'observed':>10} {'retained':>10} {'retention %':>12}",
    ]
    for s in report.sweeps:
        lines.append(
            f"{s.sweep:>6} {s.deltas_emitted:>8} {s.observed:>4}/{s.total:<5} "
            f"{s.retained:>4}/{s.total:<5} {s.retention_pct:>11.1f}"
        )
    lines.append("")
    lines.append(f"minimum retention across all sweeps: {report.min_retention_pct:.1f}%")
    lines.append(
        f"fact-sweeps carried forward unobserved: {report.unobserved_carried_forward}"
    )
    lines.append(f"overall: {'PASS' if report.ok else 'FAIL'}")
    return "\n".join(lines)


def _report_to_json(report: ConsolidationRegressionReport) -> dict[str, Any]:
    return {
        "n_facts": report.n_facts,
        "n_sweeps": report.n_sweeps,
        "min_retention_pct": report.min_retention_pct,
        "unobserved_carried_forward": report.unobserved_carried_forward,
        "ok": report.ok,
        "sweeps": [
            {
                "sweep": s.sweep,
                "deltas_emitted": s.deltas_emitted,
                "observed": s.observed,
                "retained": s.retained,
                "total": s.total,
                "retention_pct": s.retention_pct,
            }
            for s in report.sweeps
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--n-facts", type=int, default=DEFAULT_N_FACTS)
    parser.add_argument("--n-sweeps", type=int, default=DEFAULT_N_SWEEPS)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    report = run_consolidation_regression(n_facts=args.n_facts, n_sweeps=args.n_sweeps)

    if args.json:
        print(json.dumps(_report_to_json(report), indent=2, sort_keys=True))
    else:
        print(render_text(report))

    return 0 if report.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
