"""`harness/closed_loop.py` run as a pytest, so the drill is COLLECTED rather than merely
runnable.

`docs/FIDELITY-AUDIT.md` §11.1 records the same correction for the guessed-reward drill: "the
prompt makes invariant 8 CI-blocking; a drill pytest never collected is a script." The
closed-loop drill is the evidence for the audit's headline finding, so it gets the same
treatment: every hop is asserted separately here, because a single `assert report.closed` would
name nothing when it broke.

These assertions are ABOUT THE OFFLINE DRILL, and inherit every limit its module docstring
states. Chiefly: no Postgres ran, so "the loop closes" means the production functions compose,
not that a deployed process executes them. `test_the_drill_reports_what_production_still_does_not_run`
below pins the second half so a future reader cannot take the first half for more than it is.
"""

from __future__ import annotations

import pytest
from harness.closed_loop import Hop, render_text, run_closed_loop

pytestmark = pytest.mark.phase3


@pytest.fixture(scope="module")
def report() -> object:
    """One drill run shared by the assertions below. Module-scoped because the drill is a
    single linear narrative -- re-running it per test would assert nine times over nine
    different sets of minted uuids, which is slower and proves nothing extra."""
    return run_closed_loop()


def _hop(report: object, number: int) -> Hop:
    hops = report.hops  # type: ignore[attr-defined]
    matches = [h for h in hops if h.number == number]
    assert len(matches) == 1, f"expected exactly one hop numbered {number}, got {len(matches)}"
    return matches[0]


@pytest.mark.parametrize("number", range(1, 10))
def test_each_hop_of_the_learning_loop_holds(report: object, number: int) -> None:
    """One test per hop, so a break names the stage rather than the drill."""
    hop = _hop(report, number)
    assert hop.passed, (
        f"hop {hop.number} ({hop.name}) failed: {list(hop.failed_checks)} -- {hop.detail}"
    )


# Every property the drill is REQUIRED to assert, by name. This table is the anti-erosion
# guard: with `passed` derived from `Hop.checks`, deleting a conjunct from the drill no longer
# shortens an invisible `and` chain -- it removes a key, and the hop's entry below turns red
# with the name of the property that went missing. Verified by mutation: dropping the Sybil
# control from hop 5, or the quarantined-row check from hop 3, both survived before this table
# existed and both fail now.
_REQUIRED_CHECKS: dict[int, set[str]] = {
    1: {"submitter_principal was written server-side from the authenticated envelope"},
    2: {"it entered as `candidate`, not `validated`"},
    3: {"the QUARANTINED row holds none", "the vector is stamped with the configured pin"},
    4: {"the memory's own origin run was refused"},
    5: {
        "two independent confirmations promote quarantined -> candidate",
        "two correlated confirmations do NOT (the Sybil control)",
    },
    6: {"an unambiguous outcome moved Q upward"},
    7: {"the promotion guard moved candidate -> validated"},
    8: {"the SAME row was refused while quarantined", "and refused as a Tier B candidate"},
    9: {
        "the RLS GUC is the transaction's first statement",
        "a memory_status_log row was appended in the SAME transaction",
    },
}


@pytest.mark.parametrize("number", sorted(_REQUIRED_CHECKS))
def test_each_hop_still_asserts_the_properties_that_make_it_meaningful(
    report: object, number: int
) -> None:
    """A hop that still PASSES while no longer CHECKING the thing it exists to check is the
    failure mode this whole remediation pass keeps finding. Names, not counts: a hop could add
    two trivial checks and drop the load-bearing one without changing a count."""
    hop = _hop(report, number)
    missing = _REQUIRED_CHECKS[number] - set(hop.checks)
    assert not missing, f"hop {hop.number} has stopped asserting: {sorted(missing)}"


def test_the_drill_covers_nine_hops_and_none_is_a_duplicate(report: object) -> None:
    """Guards the drill against the failure mode it exists to catch, one level up: a hop
    silently dropped from the sequence would make the remaining ones pass while the loop no
    longer closes."""
    hops = report.hops  # type: ignore[attr-defined]
    assert [h.number for h in hops] == list(range(1, 10))
    assert len({h.name for h in hops}) == 9


def test_every_hop_names_the_production_function_it_asserted_with(report: object) -> None:
    """The drill's whole claim is "asserted with the real function, not a reimplementation".
    A hop whose `production_function` did not name a real importable symbol would be a hop
    asserting something the drill made up."""
    import importlib

    for hop in report.hops:  # type: ignore[attr-defined]
        # Strip any trailing parenthetical ("(real extractors)").
        target = hop.production_function.split(" ")[0]
        parts = target.split(".")
        # The dotted path mixes modules and attributes (`ingest.trace_writer.TraceWriter
        # .run_once`), so resolve the longest importable module prefix, then walk attributes.
        obj = None
        for split_at in range(len(parts) - 1, 0, -1):
            try:
                obj = importlib.import_module("tracebed." + ".".join(parts[:split_at]))
            except ModuleNotFoundError:
                continue
            for attr in parts[split_at:]:
                assert hasattr(obj, attr), (
                    f"hop {hop.number} names {target}, but {attr} does not exist on {obj}"
                )
                obj = getattr(obj, attr)
            break
        assert obj is not None, f"hop {hop.number} names {target}, which is not importable"


def test_the_drill_reports_what_production_still_does_not_run(report: object) -> None:
    """The honest half. A green drill must not be readable as "the learning plane is live":
    ten periodic workers are still unscheduled in a deployed process, each blocked on a store
    port that does not exist, and the drill prints every one of them beside its verdict.

    Asserted against `workers.composition.UNSCHEDULED_WORKERS` itself rather than a literal
    list, so closing one of those gaps updates this test's expectation automatically instead of
    leaving a stale claim behind -- which is the specific defect FIDELITY-AUDIT.md S33 records
    about hardcoded known-gap sections.
    """
    from tracebed.workers.composition import UNSCHEDULED_WORKERS

    unscheduled = report.unscheduled_in_production  # type: ignore[attr-defined]
    assert set(unscheduled) == set(UNSCHEDULED_WORKERS)
    assert unscheduled, "an empty unscheduled list would mean the learning plane is fully wired"
    text = render_text(report)  # type: ignore[arg-type]
    assert "It does NOT mean a deployed process runs them" in text
    for name in unscheduled:
        assert name in text, f"{name} is unscheduled but absent from the printed report"


def test_no_hop_asserts_nothing(report: object) -> None:
    """`Hop.__post_init__` refuses an empty check map, so this cannot fail while that guard
    holds -- which is exactly why it is here: it pins the guard, so removing it is visible."""
    for hop in report.hops:  # type: ignore[attr-defined]
        assert hop.checks, f"hop {hop.number} asserts nothing"


def test_the_rendered_report_shows_every_individual_check(report: object) -> None:
    """An operator reading the drill's output must be able to see WHAT was checked, not only
    that a hop was green. A summary that hides its own checks is how a hop stops asserting one
    without anybody noticing."""
    text = render_text(report)  # type: ignore[arg-type]
    for hop in report.hops:  # type: ignore[attr-defined]
        for check in hop.checks:
            assert check in text, f"hop {hop.number}'s check {check!r} is not in the report"
