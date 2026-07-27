"""Killswitch holdout-arm assignment (PLAN.md §2 invariant 2 / §6 `killswitch.*`; D-027).

A salted deterministic hash: the same `(session_key, agent_type_id, salt)` triple
always yields the same `Arm`, in this process or a freshly started one, because the
assignment is a pure function of its inputs — never a coin flip, never cached. That is
what stops a run from flipping arms mid-session and contaminating the lift measurement
D-027 describes: arm assignment must be session-stable across process restarts for the
comparison between "memory_on" and "holdout" runs to mean anything.

Phase 1 assigned and logged the arm without acting on it; Phase 3's "kill switch acting"
deliverable (PLAN.md §7) closed that. `pipeline.py` now SHADOW-retrieves on the holdout arm --
every retrieval stage runs identically, so the control bucket is drawn from the same population
as the treatment bucket and `injection_log` still records what would have been placed -- and
then withholds the rendered block from the caller and stamps `OutcomeCode.HOLDOUT`. The arm is
therefore memory-off for the agent and fully observable for the kill switch. `trace_index.arm`
is no longer stamped by the SDK either: it is derived server-side from `retrieval_event.arm`
(PLAN.md §10 forbids accepting an arm assignment from a caller).

CRITICAL (task instruction, restated as an import-graph fact rather than a promise):
holdout assignment must never disable working memory or the tool cache — those are
run-state (Valkey), not learning. This module has no import of `tracebed.stores.valkey`
anywhere in it, so "never touches working memory or the tool cache" is true because
the code that could touch them is simply absent, not because of a convention a future
edit could quietly break.
"""

from __future__ import annotations

import hashlib
import os
from typing import Final

from tracebed.domain.enums import Arm
from tracebed.domain.ids import AgentTypeId

__all__ = ["assign_arm", "read_salt"]

# Width of the uniform draw derived from the hash: the leading 8 digest bytes,
# interpreted as an unsigned big-endian integer, range over exactly this space.
_HASH_SPACE: Final[int] = 1 << 64

# Joins the (salt, agent_type_id, session_key) triple before hashing. A plain
# string join is ambiguous ("a" + "bc" == "ab" + "c"); the unit separator (0x1F)
# is the same de-ambiguation choice `stores.valkey.keys` makes for its own hash
# inputs (C-17) — no legitimate salt, agent-type id, or session key contains it.
_RS: Final[str] = "\x1f"


def read_salt(salt_env: str) -> str:
    """Read the killswitch salt from the configured env var (`killswitch.salt_env`).

    A pure lookup, not a default: a missing or empty salt is refused here rather than
    silently substituted with an empty string, because an empty salt is a salt anyone
    can reproduce, which defeats D-027's session-stability guarantee only in the sense
    that it becomes *predictable* rather than *stable* — every session would still get
    a consistent arm, just one an outside party could pre-compute and target. Wiring
    this at process startup (reading `os.environ` once, not per-request) is the
    caller's job; this function has no opinion about when it is called.
    """
    value = os.environ.get(salt_env)
    if not value:
        raise LookupError(f"killswitch salt env var {salt_env!r} is not set (or empty)")
    return value


def assign_arm(
    *, session_key: str, agent_type_id: AgentTypeId, salt: str, holdout_pct: float
) -> Arm:
    """Deterministic `(session_key, agent_type_id, salt)` -> `Arm`.

    `holdout_pct` is a percentage in `[0, 100]` (PLAN.md §6 `killswitch.holdout_pct`,
    default 5). The draw is `sha256(salt RS agent_type_id RS session_key)`'s leading 8
    bytes, read as an unsigned integer and normalised to `[0, 1)`; `draw < holdout_pct
    / 100` assigns `Arm.HOLDOUT`, otherwise `Arm.MEMORY_ON`. Because SHA-256 is a fixed,
    stateless function, calling this twice with the same arguments — in this process,
    in a different one, before or after a restart — always produces the same `Arm`;
    there is no cache to warm and no global state to lose.
    """
    if not 0.0 <= holdout_pct <= 100.0:
        raise ValueError(f"holdout_pct must be within [0, 100], got {holdout_pct!r}")
    if not salt:
        raise ValueError("salt must not be empty — an empty salt makes the arm predictable")
    if not session_key:
        # An empty session key is not a session, it is the ABSENCE of one, and
        # `session_id` is optional on the wire (`api.models.RunCtxIn.session_id:
        # str | None`). Hashing "" would put every session-less run for an
        # agent_type into ONE bucket: with holdout_pct=5 that is a 5% chance that
        # 100% of that traffic sits in the holdout arm (memory withheld wholesale
        # once Phase 3 acts on it) and a 95% chance none of it does (lift measured
        # on an empty cell). Callers must substitute a per-run key instead —
        # `pipeline.Pipeline` uses the minted run_id — so refuse it loudly here
        # rather than return a plausible, quietly-degenerate arm.
        raise ValueError("session_key must not be empty — see the module docstring")
    joined = _RS.join((salt, str(agent_type_id), session_key))
    digest = hashlib.sha256(joined.encode("utf-8")).digest()
    draw = int.from_bytes(digest[:8], "big") / _HASH_SPACE
    return Arm.HOLDOUT if draw < (holdout_pct / 100.0) else Arm.MEMORY_ON
