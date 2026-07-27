"""Cross-cutting seam guards for the Phase 2 operational lane.

Seven chunks built this lane in parallel without seeing each other. Every one
of them tested its own module correctly; each of the properties below spans
two or more of those modules and so belonged to none of them. Two of the three
were REAL defects found during integration -- a worker judging a transition
against a hardcoded `current` status instead of the row's own, and a worker
reading the wall clock -- and both are the kind that a passing per-module suite
cannot see.

These are static (AST) assertions on purpose. A behavioural test proves the
call sites that exist today are right; an AST assertion proves the NEXT one
will be too, which is what a seam guard is for. They are deliberately narrow:
each names exactly one property, and none of them lints style.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

pytestmark = pytest.mark.phase2

_SRC = Path(__file__).resolve().parents[2] / "src" / "tracebed"
_WORKERS = _SRC / "workers"


def _modules(root: Path) -> list[Path]:
    return sorted(p for p in root.rglob("*.py") if "__pycache__" not in p.parts)


def _parse(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def _rel(path: Path) -> str:
    return path.relative_to(_SRC.parents[1]).as_posix()


# --------------------------------------------------------------------------- #
# Hard rule 5 / invariant 7 -- the state machine judges the ROW's status
# --------------------------------------------------------------------------- #


def test_every_apply_in_workers_judges_the_rows_own_status() -> None:
    """`state_machine.apply(current, target, ...)` decides whether an edge is
    legal from `current`. Passing a LITERAL there does not merely skip a check
    -- it makes `apply` authorise an edge PLAN.md §5's table does not contain,
    because the guard runs against the evidence while the row underneath is on
    a different edge entirely. That is a status change that did not go through
    the state machine no matter how the call site reads.

    This was a real defect at seven call sites across three workers
    (`check_validated` passing the literal `Status.VALIDATED` at a row that
    might be `quarantined`, and so on). The fix is mechanical, which is exactly
    why it can regress mechanically.

    The permitted shapes are an attribute read (`row.status`, `item.status`), a
    plain name bound from one (`source_status`, `current`), or the literal
    `None` -- which is not a status at all but "this row does not exist yet",
    the only `current` a creation edge can have.
    """
    offenders: list[str] = []
    for path in _modules(_WORKERS):
        tree = _parse(path)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            name = func.id if isinstance(func, ast.Name) else getattr(func, "attr", None)
            if name != "apply" or not node.args:
                continue
            current = node.args[0]
            ok = isinstance(current, ast.Attribute | ast.Name) or (
                isinstance(current, ast.Constant) and current.value is None
            )
            if not ok:
                offenders.append(f"{_rel(path)}:{current.lineno} apply(current={ast.dump(current)})")
    assert offenders == []


def test_no_worker_hardcodes_a_status_as_the_transitions_starting_point() -> None:
    """The narrower, sharper form of the rule above: `apply(Status.X, ...)`.

    Kept separate because it is the exact shape the defect took, and because
    the general check above would go quiet if someone introduced a helper that
    returned a literal.
    """
    offenders: list[str] = []
    for path in _modules(_WORKERS):
        for node in ast.walk(_parse(path)):
            if not isinstance(node, ast.Call) or not node.args:
                continue
            func = node.func
            name = func.id if isinstance(func, ast.Name) else getattr(func, "attr", None)
            if name != "apply":
                continue
            first = node.args[0]
            if (
                isinstance(first, ast.Attribute)
                and isinstance(first.value, ast.Name)
                and first.value.id == "Status"
            ):
                offenders.append(f"{_rel(path)}:{first.lineno} apply(Status.{first.attr}, ...)")
    assert offenders == []


def test_workers_reach_the_state_machine_only_through_apply() -> None:
    """Hard rule 5: there is no admin bypass in code. If a worker ever imports
    `TRANSITIONS` directly it is either re-implementing the guard table or
    reading it to decide something `apply` should have decided; either way the
    single chokepoint has been widened without anyone saying so.
    """
    offenders: list[str] = []
    for path in _modules(_WORKERS):
        for node in ast.walk(_parse(path)):
            if isinstance(node, ast.ImportFrom) and (node.module or "").endswith("state_machine"):
                for alias in node.names:
                    if alias.name == "TRANSITIONS":
                        offenders.append(f"{_rel(path)}:{node.lineno}")
    assert offenders == []


# --------------------------------------------------------------------------- #
# Hard rule 3 -- the 30-simulated-day soak is only runnable if nothing peeks
# --------------------------------------------------------------------------- #

_WALL_CLOCK_ATTRS = {
    ("datetime", "now"),
    ("datetime", "utcnow"),
    ("date", "today"),
    ("time", "time"),
    ("time", "monotonic"),
    ("time", "monotonic_ns"),
    ("time", "perf_counter"),
    ("time", "perf_counter_ns"),
}

# `domain/clock.py` is the definition of "the wall clock" -- SystemClock is
# where these calls are supposed to be, and nowhere else under src/.
_CLOCK_MODULE = _SRC / "domain" / "clock.py"


def test_nothing_under_src_reads_the_wall_clock_outside_system_clock() -> None:
    """Every worker takes an injected `Clock` so the Phase 2 gate can run 30
    simulated days in milliseconds. A SINGLE wall-clock read anywhere in the
    graph does not make the soak slow -- it makes it a lie: that one value
    advances in real time while every other timestamp in the run is frozen, so
    a TTL, an idle window, or a divergence window silently measures a different
    interval than the test believes it set up.

    Scanned as an AST rather than grepped so a docstring mentioning
    `datetime.now()` (there are several, all explaining this rule) does not
    read as a violation, and so `from datetime import datetime as dt` cannot
    hide one.
    """
    offenders: list[str] = []
    for path in _modules(_SRC):
        if path == _CLOCK_MODULE:
            continue
        for node in ast.walk(_parse(path)):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if not isinstance(func, ast.Attribute) or not isinstance(func.value, ast.Name):
                continue
            if (func.value.id, func.attr) in _WALL_CLOCK_ATTRS:
                offenders.append(f"{_rel(path)}:{node.lineno} {func.value.id}.{func.attr}()")
    assert offenders == []


def test_system_clock_is_the_module_that_does_read_it() -> None:
    """Guard the guard. If `domain/clock.py` stopped calling the wall clock,
    the exclusion above would be vacuous and the whole check would pass while
    measuring nothing."""
    source = _CLOCK_MODULE.read_text(encoding="utf-8")
    found = {
        f"{node.func.value.id}.{node.func.attr}"
        for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and (node.func.value.id, node.func.attr) in _WALL_CLOCK_ATTRS
    }
    assert found, "domain/clock.py reads no wall clock -- the exclusion above proves nothing"


# --------------------------------------------------------------------------- #
# The write path -- nothing reaches a memory_item insert without a verdict
# --------------------------------------------------------------------------- #


def test_the_only_insert_path_verifies_a_scan_verdict_against_the_content() -> None:
    """PLAN.md §2 invariant 6 and Phase 0's gate ("`memory_item` insert without
    a `ScanVerdict` raises"). `Repo.insert_memory_item` and
    `ScopedRepo.insert_memory_item` are the two public doors; both must call
    `validate_provenance`, then `content_hash`, then `verify_verdict`, in that
    order, before reaching the shared `_impl_insert_memory_item`.

    The order is the property. `verify_verdict` binds the verdict to THIS
    content's hash, so a verdict minted for different bytes is rejected --
    but only if the hash it is checked against was computed from the content
    actually being written, which is what "content_hash before verify_verdict"
    means.
    """
    repo = _SRC / "stores" / "pg" / "repo.py"
    tree = _parse(repo)

    doors = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == "insert_memory_item"
    ]
    assert len(doors) == 2, "expected exactly Repo and ScopedRepo to expose insert_memory_item"

    for door in doors:
        calls = [
            n.func.id
            for n in ast.walk(door)
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
        ]
        assert "validate_provenance" in calls
        assert "content_hash" in calls
        assert "verify_verdict" in calls
        assert calls.index("content_hash") < calls.index("verify_verdict")


def test_no_module_outside_the_repo_calls_the_unchecked_insert() -> None:
    """`_impl_insert_memory_item` is the half that performs the INSERT with no
    provenance or verdict check of its own -- both doors above do that work
    first. A third caller anywhere would be a memory_item write that skipped
    both, which is precisely what invariant 6 forbids."""
    offenders: list[str] = []
    for path in _modules(_SRC):
        if path == _SRC / "stores" / "pg" / "repo.py":
            continue
        if "_impl_insert_memory_item" in path.read_text(encoding="utf-8"):
            offenders.append(_rel(path))
    assert offenders == []
