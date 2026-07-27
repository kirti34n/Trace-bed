"""Killswitch holdout-arm assignment (PLAN.md §2 invariant 2 / §6 `killswitch.*`; D-027).

`hotpath.holdout` is pure and offline: no Postgres/Valkey/S3 fixture is touched,
and nothing here imports a clock — arm assignment is a stateless function of its
inputs, which is the entire property these tests exist to prove.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap
from pathlib import Path
from uuid import uuid4

import pytest

from tracebed.domain.enums import Arm
from tracebed.domain.ids import AgentTypeId
from tracebed.hotpath.holdout import assign_arm, read_salt

pytestmark = pytest.mark.phase1


# --------------------------------------------------------------------------- #
# Determinism: same (session, agent_type, salt) -> same arm, recomputed fresh.
# --------------------------------------------------------------------------- #


def test_same_inputs_yield_same_arm_when_recomputed() -> None:
    agent_type_id = AgentTypeId(uuid4())

    # "Across fresh processes" is asserted by recomputing from scratch, not by
    # reading back a cached value — there is no cache anywhere in this module.
    first = assign_arm(session_key="session-abc", agent_type_id=agent_type_id, salt="s3cr3t", holdout_pct=5.0)
    second = assign_arm(session_key="session-abc", agent_type_id=agent_type_id, salt="s3cr3t", holdout_pct=5.0)

    assert first == second


def test_recomputation_is_stable_across_many_distinct_sessions() -> None:
    agent_type_id = AgentTypeId(uuid4())
    for i in range(200):
        session_key = f"session-{i}"
        first = assign_arm(
            session_key=session_key, agent_type_id=agent_type_id, salt="pepper", holdout_pct=5.0
        )
        second = assign_arm(
            session_key=session_key, agent_type_id=agent_type_id, salt="pepper", holdout_pct=5.0
        )
        assert first == second


def test_different_agent_types_can_draw_different_arms_for_the_same_session() -> None:
    """The triple, not just the session, determines the arm — same session_key and
    salt but a different agent_type_id is a legitimately different draw.

    `assert arms <= {MEMORY_ON, HOLDOUT}` would be a tautology (every set of Arms
    satisfies it) and would pass an implementation that ignored `agent_type_id`
    entirely. At holdout_pct=50 an ignored agent_type_id yields ONE arm for all 120
    draws; P(120 honest draws all agreeing) = 2**-119.
    """
    session_key = "shared-session"
    salt = "pepper"
    arms = {
        assign_arm(
            session_key=session_key, agent_type_id=AgentTypeId(uuid4()), salt=salt, holdout_pct=50.0
        )
        for _ in range(120)
    }
    assert arms == {Arm.MEMORY_ON, Arm.HOLDOUT}


# --------------------------------------------------------------------------- #
# Distribution over many synthetic sessions is within tolerance of holdout_pct.
# --------------------------------------------------------------------------- #


def test_distribution_over_100k_sessions_matches_holdout_pct() -> None:
    agent_type_id = AgentTypeId(uuid4())
    n = 100_000
    holdout_pct = 5.0
    holdout_count = sum(
        1
        for i in range(n)
        if assign_arm(
            session_key=f"synthetic-session-{i}",
            agent_type_id=agent_type_id,
            salt="distribution-salt",
            holdout_pct=holdout_pct,
        )
        is Arm.HOLDOUT
    )
    fraction = holdout_count / n
    # std dev of a Bernoulli(0.05) mean at n=100_000 is ~0.00069; 0.01 (1 point)
    # is a >14-sigma band, generous enough to be robust yet still meaningful.
    assert abs(fraction - (holdout_pct / 100.0)) < 0.01, fraction


def test_distribution_at_a_different_holdout_pct() -> None:
    agent_type_id = AgentTypeId(uuid4())
    n = 100_000
    holdout_pct = 20.0
    holdout_count = sum(
        1
        for i in range(n)
        if assign_arm(
            session_key=f"other-session-{i}",
            agent_type_id=agent_type_id,
            salt="distribution-salt-2",
            holdout_pct=holdout_pct,
        )
        is Arm.HOLDOUT
    )
    fraction = holdout_count / n
    assert abs(fraction - (holdout_pct / 100.0)) < 0.01, fraction


# --------------------------------------------------------------------------- #
# Changing the salt reshuffles the assignment.
# --------------------------------------------------------------------------- #


def test_changing_the_salt_reshuffles_assignment() -> None:
    agent_type_id = AgentTypeId(uuid4())
    n = 2_000
    holdout_pct = 50.0  # maximises information from a match/mismatch comparison

    arms_a = [
        assign_arm(
            session_key=f"reshuffle-{i}", agent_type_id=agent_type_id, salt="salt-a", holdout_pct=holdout_pct
        )
        for i in range(n)
    ]
    arms_b = [
        assign_arm(
            session_key=f"reshuffle-{i}", agent_type_id=agent_type_id, salt="salt-b", holdout_pct=holdout_pct
        )
        for i in range(n)
    ]

    matches = sum(1 for a, b in zip(arms_a, arms_b, strict=True) if a == b)
    match_fraction = matches / n

    # Two independent unbiased-ish 50/50 draws agree ~half the time; a
    # generous [0.3, 0.7] band tolerates hash noise while still failing if the
    # salt were silently ignored (which would give a 1.0 match fraction).
    assert 0.3 < match_fraction < 0.7, match_fraction
    assert match_fraction < 0.99  # the salt provably changed the mapping


# --------------------------------------------------------------------------- #
# Validation.
# --------------------------------------------------------------------------- #


def test_holdout_pct_out_of_range_is_rejected() -> None:
    agent_type_id = AgentTypeId(uuid4())
    with pytest.raises(ValueError):
        assign_arm(session_key="s", agent_type_id=agent_type_id, salt="salt", holdout_pct=-1.0)
    with pytest.raises(ValueError):
        assign_arm(session_key="s", agent_type_id=agent_type_id, salt="salt", holdout_pct=100.1)


def test_empty_salt_is_rejected() -> None:
    agent_type_id = AgentTypeId(uuid4())
    with pytest.raises(ValueError):
        assign_arm(session_key="s", agent_type_id=agent_type_id, salt="", holdout_pct=5.0)


def test_empty_session_key_is_rejected() -> None:
    """An empty session key is the ABSENCE of a session, and `RunCtxIn.session_id`
    is optional on the wire. Accepting "" would hash every session-less run of an
    agent_type into ONE draw — at holdout_pct=5, a 5% chance that all of that
    traffic sits in the holdout arm. Callers substitute a per-run key instead
    (`pipeline.Pipeline` uses the minted run_id); this refuses the degenerate
    input loudly rather than returning a plausible arm."""
    agent_type_id = AgentTypeId(uuid4())
    with pytest.raises(ValueError):
        assign_arm(session_key="", agent_type_id=agent_type_id, salt="salt", holdout_pct=5.0)


def test_read_salt_reads_the_configured_env_var(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TB_HOLDOUT_SALT_TEST", "the-real-salt")
    assert read_salt("TB_HOLDOUT_SALT_TEST") == "the-real-salt"


def test_read_salt_raises_when_env_var_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("TB_HOLDOUT_SALT_MISSING", raising=False)
    with pytest.raises(LookupError):
        read_salt("TB_HOLDOUT_SALT_MISSING")


def test_read_salt_raises_when_env_var_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TB_HOLDOUT_SALT_EMPTY", "")
    with pytest.raises(LookupError):
        read_salt("TB_HOLDOUT_SALT_EMPTY")


# --------------------------------------------------------------------------- #
# Working memory and the tool cache are untouched by holdout assignment — by
# construction, not by convention: this module has no Valkey import at all.
# --------------------------------------------------------------------------- #


def test_holdout_module_never_imports_valkey() -> None:
    """Structural, not textual: the module's prose docstring is allowed to talk
    about Valkey (that is the whole point being documented); its import graph
    must not — checked over the parsed AST, not a substring match, so a real
    import cannot hide from this check the way it could from a grep."""
    import ast

    import tracebed.hotpath.holdout as holdout_module

    module_file = holdout_module.__file__
    assert module_file is not None
    tree = ast.parse(Path(module_file).read_text(encoding="utf-8"))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module)

    assert not any("valkey" in name.lower() for name in imported), imported


# --------------------------------------------------------------------------- #
# Genuinely across processes, not just twice in one: PLAN.md §7's gate is
# "same (session, agent_type, salt) -> same arm ACROSS RESTARTS".
# --------------------------------------------------------------------------- #


def test_arm_is_identical_in_a_freshly_started_interpreter() -> None:
    """Recomputing twice in one process cannot distinguish a stateless hash from a
    process-salted one: Python's builtin `hash()` of a str is randomised per
    process (PYTHONHASHSEED), so an implementation built on it would look perfectly
    stable in-process and silently reshuffle every arm on every restart — exactly
    the contamination D-027 exists to prevent. This runs the assignment in a child
    interpreter with a DIFFERENT hash seed and compares.
    """
    agent_type_id = AgentTypeId(uuid4())
    session_key = "cross-process-session"
    salt = "cross-process-salt"
    holdout_pct = 50.0  # maximal information per draw

    in_process = [
        assign_arm(
            session_key=f"{session_key}-{i}",
            agent_type_id=agent_type_id,
            salt=salt,
            holdout_pct=holdout_pct,
        ).value
        for i in range(32)
    ]

    program = textwrap.dedent(
        """
        import json, sys
        from tracebed.domain.ids import AgentTypeId
        from tracebed.hotpath.holdout import assign_arm

        agent_type_id = AgentTypeId(sys.argv[1])
        print(json.dumps([
            assign_arm(
                session_key=f"{sys.argv[2]}-{i}",
                agent_type_id=agent_type_id,
                salt=sys.argv[3],
                holdout_pct=float(sys.argv[4]),
            ).value
            for i in range(32)
        ]))
        """
    )
    env = dict(os.environ)
    env["PYTHONHASHSEED"] = "12345"  # deliberately not this process's seed
    completed = subprocess.run(  # noqa: S603 - fixed argv, no shell, test-local
        [sys.executable, "-c", program, str(agent_type_id), session_key, salt, str(holdout_pct)],
        capture_output=True,
        text=True,
        env=env,
        check=True,
    )
    child = json.loads(completed.stdout)

    assert child == in_process
    # ...and the comparison is only meaningful if the draws are not all one arm.
    assert len(set(in_process)) == 2
