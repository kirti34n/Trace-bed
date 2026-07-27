"""`ScorerRepo` — `workers.scorer.ScorerRepoPort` over Postgres (docs/FIDELITY-AUDIT.md M3;
PLAN.md §11 M3; `workers/scorer.py`'s module docstring, contract gaps one and two).

The scorer (invariant 8) applies `Q <- clamp01(Q + alpha*w*c*(r - Q))` and needs a store it
declared beside itself (dependency inversion, `adapters/ports.py` C-18) because migrations
0001-0005 could not answer three of its questions. `memory_item` holds a memory's CURRENT
values only (one `q_value`, one `scored_use_count`); nothing recorded the individual Q updates
that produced them (reports.py:15-27). `migrations/0006_q_update_ledger.sql` adds the
`memory_q_update` ledger this store reads and appends to, and this class is the writer for
`memory_item.epoch_id`/`last_scored_at` that `0004_lifecycle.sql` deferred to "whichever chunk
owns ScorerRepoPort's Postgres implementation".

FAKE FIDELITY (the contract, `tests/phase3/test_scorer_q_update.py::FakeScorerRepo`,
`harness/closed_loop.py::_Vault`): the four observable results — the current `q_value`, the set
of applied `event_id`s, the per-UTC-day update count, and the (idempotent) mutation
`apply_q_update` performs — match the in-memory fake method-for-method. The fake's `_Vault`
raises `TracebedError('cross-project Q update')` when a scoped write targets another project's
row; the real store gets that for free from `scoped()` + the RLS GUC + the explicit
`project_id` predicate + the `FOR UPDATE` lock matching zero rows.

The extra columns the ledger persists (`previous_q`, `principal_id`, `contribution`,
`epoch_id`) are additive durability the fakes could not express (they only live on the
appended `QUpdate` object): `principal_id` is what makes retirement's DISTINCT-PRINCIPALS-OVER-
SCORED-UPDATES floor countable (D-021), and `epoch_id` satisfies invariant 7.

ATOMICITY (`ScorerRepoPort.apply_q_update`'s own docstring; the module's second contract gap).
`apply_q_update` runs the whole read-modify-write inside ONE `scoped()` transaction:

  1. `SELECT ... FOR UPDATE` the `memory_item` row — locking it serialises concurrent scorer
     ticks on the same memory, and a lock that matches zero rows (the memory does not exist, or
     it belongs to another project and RLS/predicate filtered it) is the cross-project raise the
     fake's `_Vault` performs explicitly.
  2. `INSERT ... ON CONFLICT (project_id, memory_id, event_id) DO NOTHING` into the ledger —
     the ATOMIC REPLAY GUARD. If the row already exists (`rowcount == 0`), this event has already
     moved Q; the method returns without touching `memory_item`, so a replayed event never moves
     Q twice even under concurrency (two ticks racing the SAME event → exactly one write, the
     loser's INSERT conflicts and its q-write is skipped). This mirrors `lifecycle.py`'s
     conditional-write-then-check-rowcount shape.
  3. Only when the ledger INSERT actually inserted does the `memory_item` UPDATE run
     (`q_value`, `scored_use_count + 1`, `last_scored_at`, `epoch_id`).

CONTRACT GAP (reported, not silently worked around): the daily cap is `scoring
.updates_per_memory_per_day` (default 1, configurable `>= 1`), held by `run_scorer_batch`'s
`config`, and `apply_q_update`'s Protocol signature is `(project_id, update)` — it is passed no
cap value. So the store CAN and DOES close the concurrency window for a REPLAYED event (step 2's
`ON CONFLICT`, cap-value-independent), but it cannot, from inside this signature, be the atomic
backstop for two concurrent ticks applying DIFFERENT fresh events on the same UTC day for a cap
`> 0`: enforcing "one per day" here would hard-code cap = 1 and break any `updates_per_memory_
per_day > 1` config even single-threaded. Closing that residual window needs the cap value
threaded onto the port (an `apply_q_update(project_id, update, *, daily_cap)` widening, or a
`day` re-count compared against a passed cap) — a Protocol change owned by whoever revises
`workers/scorer.py`, out of this store-only chunk's file list.
"""

from __future__ import annotations

from collections.abc import Set as AbstractSet
from datetime import UTC, date, datetime, time, timedelta
from typing import Any, Final
from uuid import UUID

from psycopg_pool import ConnectionPool

from tracebed.domain.errors import TracebedError
from tracebed.domain.ids import MemoryId, ProjectId
from tracebed.stores.pg.pool import scoped
from tracebed.workers.scorer import QUpdate

__all__ = ["ScorerRepo"]


# `current_q` reads the memory's q_value FRESH every call (never cached) — a concurrent update
# elsewhere must be seen (ScorerRepoPort.current_q's docstring).
_CURRENT_Q_SQL: Final[str] = """
SELECT q_value
FROM memory_item
WHERE project_id = %(project_id)s AND id = %(memory_id)s
""".strip()

# The replay-idempotency ledger: every event_id that has EVER moved this memory's Q. NOT
# day-scoped (ScorerRepoPort.applied_event_ids's docstring). The (project_id, memory_id) prefix
# of the PK prunes to this project's partition and this memory.
_APPLIED_EVENT_IDS_SQL: Final[str] = """
SELECT event_id
FROM memory_q_update
WHERE project_id = %(project_id)s AND memory_id = %(memory_id)s
""".strip()

# Per-UTC-day update count. Bounds are a half-open UTC range computed in Python, never
# `DATE(scored_at) = %(day)s`: `scored_at` is timestamptz and `DATE(timestamptz)` renders it in
# the SESSION's TimeZone, so the same row would fall on different "days" for two connections and
# the per-UTC-day cap would silently become a per-server-local-day cap. The half-open range is
# also sargable against the (project_id, memory_id, scored_at) index. Identical discipline to
# `Repo.count_proposals_in_project_day` (repo.py).
_SCORED_UPDATES_TODAY_SQL: Final[str] = """
SELECT count(*)
FROM memory_q_update
WHERE project_id = %(project_id)s AND memory_id = %(memory_id)s
  AND scored_at >= %(day_start)s AND scored_at < %(day_end)s
""".strip()

# Locks the memory_item row for the apply transaction. Selects project_id too so the store can
# re-assert scope (a loud raise, never a silent cross-project write) mirroring
# `lifecycle._require_scoped`. A zero-row result is the cross-project / missing raise.
_LOCK_MEMORY_SQL: Final[str] = """
SELECT project_id, q_value
FROM memory_item
WHERE project_id = %(project_id)s AND id = %(memory_id)s
FOR UPDATE
""".strip()

# The atomic replay guard: DO NOTHING when this (memory, event) already moved Q.
_INSERT_LEDGER_SQL: Final[str] = """
INSERT INTO memory_q_update (
    project_id, memory_id, event_id, principal_id,
    previous_q, new_q, contribution, epoch_id, scored_at
) VALUES (
    %(project_id)s, %(memory_id)s, %(event_id)s, %(principal_id)s,
    %(previous_q)s, %(new_q)s, %(contribution)s, %(epoch_id)s, %(scored_at)s
)
ON CONFLICT (project_id, memory_id, event_id) DO NOTHING
""".strip()

# The current-value write. `scored_use_count + 1` and `last_scored_at`/`epoch_id` are the
# current-value columns memory_item carries (reports.py:19 confirms last_scored_at holds the
# current value only); the durable trajectory lives in the ledger row inserted above.
_UPDATE_MEMORY_Q_SQL: Final[str] = """
UPDATE memory_item
   SET q_value = %(new_q)s,
       scored_use_count = scored_use_count + 1,
       last_scored_at = %(scored_at)s,
       epoch_id = %(epoch_id)s
 WHERE project_id = %(project_id)s AND id = %(memory_id)s
""".strip()


class ScorerRepo:
    """`ScorerRepo(pool)`. `workers.scorer.ScorerRepoPort` over Postgres.

    A `memory_item` writer in the same family as `stores.pg.lifecycle.LifecycleWriter` — it
    takes only the pool, and every project-scoped statement goes through `scoped()` (which sets
    the RLS GUC as the transaction's first statement) with an explicit `project_id` predicate
    besides.
    """

    def __init__(self, pool: ConnectionPool) -> None:
        self._pool = pool

    def current_q(self, project_id: ProjectId, memory_id: MemoryId) -> float:
        with scoped(self._pool, project_id) as conn:
            row = conn.execute(
                _CURRENT_Q_SQL, {"project_id": project_id, "memory_id": memory_id}
            ).fetchone()
        if row is None:
            # The fake indexes `self.rows[memory_id]` and raises KeyError; here a missing row is
            # either a genuinely absent memory or one RLS/predicate filtered as out-of-project.
            # Fail loud rather than fabricating a 0.5 that would read as "brand-new memory".
            raise TracebedError(
                f"current_q: memory {memory_id} not found in project {project_id}"
            )
        return float(row[0])

    def applied_event_ids(
        self, project_id: ProjectId, memory_id: MemoryId
    ) -> AbstractSet[UUID]:
        with scoped(self._pool, project_id) as conn:
            rows = conn.execute(
                _APPLIED_EVENT_IDS_SQL, {"project_id": project_id, "memory_id": memory_id}
            ).fetchall()
        # A fresh copy, empty for a never-scored memory — matches the fake's `set(...)`.
        return {row[0] for row in rows}

    def scored_updates_today(
        self, project_id: ProjectId, memory_id: MemoryId, day: date
    ) -> int:
        day_start = datetime.combine(day, time.min, tzinfo=UTC)
        with scoped(self._pool, project_id) as conn:
            row = conn.execute(
                _SCORED_UPDATES_TODAY_SQL,
                {
                    "project_id": project_id,
                    "memory_id": memory_id,
                    "day_start": day_start,
                    "day_end": day_start + timedelta(days=1),
                },
            ).fetchone()
        if row is None:  # pragma: no cover - count(*) always returns exactly one row
            raise TracebedError("scored_updates_today: count(*) returned no row")
        return int(row[0])

    def apply_q_update(self, project_id: ProjectId, update: QUpdate) -> None:
        params = {
            "project_id": project_id,
            "memory_id": update.memory_id,
            "event_id": update.event_id,
            "principal_id": update.principal_id,
            "previous_q": update.previous_q,
            "new_q": update.new_q,
            "contribution": update.contribution,
            "epoch_id": update.epoch_id,
            "scored_at": update.scored_at,
        }
        with scoped(self._pool, project_id) as conn:
            locked = conn.execute(
                _LOCK_MEMORY_SQL,
                {"project_id": project_id, "memory_id": update.memory_id},
            ).fetchone()
            if locked is None:
                # Zero rows locked: the memory does not exist, or belongs to another project and
                # RLS + the predicate filtered it. Either way this is the fake `_Vault`'s
                # `TracebedError('cross-project Q update')` — a scoped write must never touch a
                # row this project cannot see.
                raise TracebedError(
                    f"apply_q_update: memory {update.memory_id} not writable in project "
                    f"{project_id} (absent or cross-project)"
                )
            self._require_scoped(locked[0], project_id)
            inserted = conn.execute(_INSERT_LEDGER_SQL, params)
            if inserted.rowcount == 0:
                # Replay: this (memory, event) already moved Q. Never move it twice — leave
                # memory_item untouched (the atomic replay guard).
                return
            conn.execute(
                _UPDATE_MEMORY_Q_SQL,
                {
                    "new_q": update.new_q,
                    "scored_at": update.scored_at,
                    "epoch_id": update.epoch_id,
                    "project_id": project_id,
                    "memory_id": update.memory_id,
                },
            )

    @staticmethod
    def _require_scoped(row_project_id: Any, project_id: ProjectId) -> None:
        """The SQL predicate is the control; this is the assertion the control held.

        Same discipline as `lifecycle._require_scoped`. A row whose `project_id` is not this
        project's is a hypothetical RLS-plus-predicate failure turned into a loud raise rather
        than a silent Q write onto another tenant's memory.
        """
        if ProjectId(row_project_id) != project_id:  # pragma: no cover - RLS + predicate hold
            raise TracebedError(
                f"apply_q_update for project {project_id} locked a memory_item belonging to "
                f"project {row_project_id} -- invariant 4"
            )
