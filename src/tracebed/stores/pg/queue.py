"""SKIP LOCKED work queue (PHASE-0 Task 12; PLAN.md invariant 5 — async writes).

Delivery is **AT-LEAST-ONCE**. A leased row is redelivered if its lease expires
before `ack()`, or if a consumer crashes after doing side effects but before
calling `ack()`. This is not an edge case to be papered over: **every consumer
of this queue must be idempotent on its own natural key** — `trace_writer`
dedups on `(run_id, seq)`, `outcome_intake` on `event_id` (PHASE0-CONTRACT.md
§5.3/§14). A consumer that assumes exactly-once delivery will double-write.

`work_queue`/`dead_letter` are unpartitioned (PLAN.md §5 DDL): no RLS GUC is
set for these tables, because `project_id` rides in the row and every consumer
re-scopes its own downstream writes from it, per §5.3.
"""

from __future__ import annotations

import math
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Final

from prometheus_client import Gauge
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb
from psycopg_pool import ConnectionPool

from tracebed.domain.clock import Clock
from tracebed.domain.ids import ProjectId

if TYPE_CHECKING:
    # domain-config chunk's module (PHASE0-CONTRACT.md §3.4). Guarded so this file — and
    # every offline test importing it — does not hard-fail while that chunk is still
    # landing in a parallel build; `from __future__ import annotations` makes the
    # constructor's `cfg: QueueConfig` annotation a lazy string either way.
    from tracebed.domain.config import QueueConfig

__all__ = [
    "QUEUE_DEAD_LETTER_COUNT",
    "QUEUE_DEPTH",
    "QUEUE_OLDEST_AGE_SECONDS",
    "QUEUE_XMIN_HORIZON_AGE_SECONDS",
    "QUEUE_XMIN_HORIZON_ALARM",
    "TOPIC_MEMORY_PROPOSAL",
    "TOPIC_OUTCOME_EVENT",
    "TOPIC_TRACE_EVENT",
    "XMIN_HORIZON_ALARM_THRESHOLD_S",
    "QueueItem",
    "WorkQueue",
    "compute_backoff",
    "is_poisoned",
    "xmin_horizon_alarm_from_age",
]

# --------------------------------------------------------------------------- #
# Topic names. Owned exclusively here (PHASE0-CONTRACT.md §5.3 module map row
# for stores/pg/queue.py: "WorkQueue (SKIP LOCKED) + TOPIC_* constants").
# Producers/consumers import these — no chunk constructs a topic string inline.
#
# CONTRACT_GAP: this chunk's task brief asked for a *separate* `topics.py` file
# holding a wider, frozen-enum topic vocabulary (distill, consolidate,
# invalidate, prefix_build, score, ...). PHASE0-CONTRACT.md §1's module map has
# no `topics.py` row ("If a file is not in this table, it is not part of
# Phase 0 — do not create it"), §5.3 defines exactly these three as plain
# `Final` string constants living in queue.py, and §14's queue DO-NOT list is
# explicit: "do NOT add topics beyond the three constants." The contract wins
# per the authority order in PHASE0-CONTRACT.md's preamble; topics.py was not
# created and no extra topic constants were added. See the return-value
# contract_gaps for the mirror of this note.
# --------------------------------------------------------------------------- #
TOPIC_TRACE_EVENT: Final = "trace_event"
TOPIC_OUTCOME_EVENT: Final = "outcome_event"
TOPIC_MEMORY_PROPOSAL: Final = "memory_proposal"  # enqueued Phase 0, consumed Phase 4


@dataclass(frozen=True, slots=True)
class QueueItem:
    """One claimed row (PHASE0-CONTRACT.md §5.3).

    `payload` is a read-only view over the already-decoded jsonb (psycopg loads jsonb
    columns to plain Python objects). It is a `MappingProxyType`, not a `dict`, because a
    frozen dataclass whose only interesting field is a mutable dict is not frozen in any
    sense a consumer can rely on: at-least-once delivery means the same logical payload can
    be handed to two consumers, and neither may observe the other's edits.
    """

    id: int
    topic: str
    project_id: ProjectId
    payload: Mapping[str, object]
    priority: int
    attempts: int


# --------------------------------------------------------------------------- #
# SQL — module-level constants so the "FOR UPDATE SKIP LOCKED" regression
# guard (Task 12's proving test) can assert on the text without a database.
# --------------------------------------------------------------------------- #

# C-11: attempts-exhausted rows for this topic move to dead_letter FIRST, inside the same
# connection/transaction as the claim that follows.
#
# The inner `FOR UPDATE SKIP LOCKED ... LIMIT` is load-bearing twice over, and its absence
# was a real defect:
#   * Without SKIP LOCKED, two consumers calling claim() concurrently serialise — the second
#     one's sweep blocks on the first one's uncommitted DELETE of the same poison rows, so a
#     handful of poison rows convoys every consumer on the hot ingest path.
#   * Without LIMIT, the sweep is O(rows-for-this-topic) on EVERY claim call, because the
#     predicate `attempts > max_attempts` is not indexable off the claim index. On a backed-up
#     topic that turns each claim into a full scan of the backlog — the exact
#     dead-tuple/xmin-horizon pressure PLAN.md §3 flags as a hot-path latency risk.
# Because the sweep is now bounded, `_CLAIM_SQL` carries its own `attempts <= max_attempts`
# guard so a poison row past the sweep's per-call budget still cannot be handed out again.
_DEAD_LETTER_SQL: Final = """
WITH poisoned AS (
    DELETE FROM work_queue
    WHERE id IN (
        SELECT id FROM work_queue
        WHERE topic = %(topic)s AND attempts > max_attempts
        ORDER BY id
        FOR UPDATE SKIP LOCKED
        LIMIT %(n)s
    )
    RETURNING id, project_id, topic, payload, priority, attempts, max_attempts,
              available_at, created_at
)
INSERT INTO dead_letter
    (id, project_id, topic, payload, priority, attempts, max_attempts,
     available_at, created_at, failed_at, last_error)
SELECT id, project_id, topic, payload, priority, attempts, max_attempts,
       available_at, created_at, now(), 'max_attempts exceeded'
FROM poisoned
""".strip()

# PHASE-0.md Task 12's statement, verbatim in shape (named params in place of $1/$n so
# psycopg can bind them; RETURNING lists columns instead of `*` so QueueItem construction
# doesn't depend on column order). Deliberately uses Postgres's own `now()`, not the
# injected Clock: two consumers racing this UPDATE must agree on a single time source, and
# that has to be the database's, not either process's local clock.
#
# `attempts <= max_attempts` is not in Task 12's sketch. It belongs here anyway: C-11 puts
# the dead-letter sweep in front of this select, and this predicate makes the guarantee hold
# even for a poison row the (bounded) sweep has not reached yet. Without it, the correctness
# of "a row is never delivered more than max_attempts + 1 times" would rest entirely on the
# sweep never falling behind.
_CLAIM_SQL: Final = """
UPDATE work_queue
SET lease_expires_at = now() + %(lease)s, attempts = attempts + 1
WHERE id IN (
    SELECT id FROM work_queue
    WHERE topic = %(topic)s
      AND available_at <= now()
      AND (lease_expires_at IS NULL OR lease_expires_at < now())
      AND attempts <= max_attempts
    ORDER BY priority, id
    FOR UPDATE SKIP LOCKED
    LIMIT %(n)s
)
RETURNING id, project_id, topic, payload, priority, attempts
""".strip()

_ENQUEUE_SQL: Final = """
INSERT INTO work_queue
    (project_id, topic, payload, priority, attempts, max_attempts, available_at, created_at)
VALUES (%(project_id)s, %(topic)s, %(payload)s, %(priority)s, 0, %(max_attempts)s,
        %(available_at)s, %(created_at)s)
RETURNING id
""".strip()

_ACK_SQL: Final = "DELETE FROM work_queue WHERE id = %(id)s"

_NACK_SQL: Final = (
    "UPDATE work_queue SET available_at = now() + %(backoff)s, "
    "lease_expires_at = NULL WHERE id = %(id)s"
)

_DEPTH_SQL: Final = "SELECT COUNT(*) FROM work_queue WHERE topic = %(topic)s"
_OLDEST_AVAILABLE_AT_SQL: Final = (
    "SELECT MIN(available_at) FROM work_queue WHERE topic = %(topic)s"
)
_DEAD_LETTER_COUNT_SQL: Final = "SELECT COUNT(*) FROM dead_letter WHERE topic = %(topic)s"

# The oldest in-progress transaction's age is the practical proxy for how long dead tuples on
# work_queue/dead_letter have sat unreclaimed by autovacuum. PLAN.md §3 flags this table as
# sharing Postgres's buffer cache with the vector index, so bloat here is a hot-path latency
# risk, not merely an ingest-side one — hence monitoring it from the queue module.
#
# Both arms are filtered to the current database because the vacuum horizon for an ordinary
# (non-shared, non-catalog) relation is database-local. `pg_prepared_xacts` is the second arm
# because an orphaned two-phase-commit transaction pins the horizon indefinitely and never
# appears in pg_stat_activity — it is the classic silent bloat cause, and omitting it made
# the alarm blind to exactly the failure mode that does not resolve on its own.
#
# KNOWN BLIND SPOTS (documented rather than overclaimed): a role without `pg_read_all_stats`
# sees NULL `xact_start` for other roles' backends, so this under-reports unless the app role
# is granted that role; and a replication slot holding `xmin` back is not visible here at all.
# Both are deployment concerns, not something this query can fix.
_XMIN_HORIZON_SQL: Final = """
SELECT max(age_s) FROM (
    SELECT EXTRACT(EPOCH FROM (now() - xact_start))::float8 AS age_s
    FROM pg_stat_activity
    WHERE datname = current_database()
      AND xact_start IS NOT NULL
      AND pid <> pg_backend_pid()
    UNION ALL
    SELECT EXTRACT(EPOCH FROM (now() - prepared))::float8 AS age_s
    FROM pg_prepared_xacts
    WHERE database = current_database()
) AS horizon_holders
""".strip()

# --------------------------------------------------------------------------- #
# Prometheus metrics (depth / age / dead-letter, per Task 12; module-level so
# every WorkQueue instance in a process shares one registry entry per name).
# --------------------------------------------------------------------------- #
QUEUE_DEPTH: Final = Gauge(
    "tracebed_queue_depth", "Rows currently on work_queue for a topic.", ["topic"]
)
QUEUE_OLDEST_AGE_SECONDS: Final = Gauge(
    "tracebed_queue_oldest_age_seconds",
    "Age in seconds of the oldest available_at on work_queue for a topic (0 when empty).",
    ["topic"],
)
QUEUE_DEAD_LETTER_COUNT: Final = Gauge(
    "tracebed_queue_dead_letter_count", "Rows currently on dead_letter for a topic.", ["topic"]
)
QUEUE_XMIN_HORIZON_AGE_SECONDS: Final = Gauge(
    "tracebed_queue_xmin_horizon_age_seconds",
    "Age in seconds of the oldest open transaction holding back the vacuum horizon "
    "(PLAN.md §3: work_queue shares Postgres's buffer cache with the vector index); "
    "0 when no other backend holds one.",
)
QUEUE_XMIN_HORIZON_ALARM: Final = Gauge(
    "tracebed_queue_xmin_horizon_alarm",
    "1 when the xmin-horizon age exceeds XMIN_HORIZON_ALARM_THRESHOLD_S, else 0.",
)

# Chosen conservatively for a table that shares buffer cache with the HNSW index: a
# transaction held open for five minutes is already long enough for dead-tuple buildup on
# a busy queue to start displacing hot vector-index pages from cache.
XMIN_HORIZON_ALARM_THRESHOLD_S: Final = 300.0


def xmin_horizon_alarm_from_age(
    age_s: float | None, threshold_s: float = XMIN_HORIZON_ALARM_THRESHOLD_S
) -> bool:
    """Pure predicate behind `WorkQueue.xmin_horizon_alarm()` — offline-testable without a
    database. `age_s is None` (no other backend holding a transaction open) never alarms.
    """
    return age_s is not None and age_s > threshold_s


def is_poisoned(attempts: int, max_attempts: int) -> bool:
    """The dead-letter predicate (C-11) — mirrors `_DEAD_LETTER_SQL`'s WHERE clause exactly,
    so the SQL and this pure function can be tested against the same table-driven cases."""
    return attempts > max_attempts


_DEFAULT_BACKOFF_BASE: Final = timedelta(seconds=1)
_DEFAULT_BACKOFF_FACTOR: Final = 2.0
_DEFAULT_BACKOFF_CEILING: Final = timedelta(minutes=5)


def compute_backoff(
    attempts: int,
    *,
    base: timedelta = _DEFAULT_BACKOFF_BASE,
    factor: float = _DEFAULT_BACKOFF_FACTOR,
    ceiling: timedelta = _DEFAULT_BACKOFF_CEILING,
) -> timedelta:
    """Exponential backoff for `nack(id, backoff)` callers. Pure — no clock, no I/O; a
    consumer passes the `attempts` count off the `QueueItem` it just failed to process.
    Because delivery is at-least-once, a hot-looping poison row is otherwise only bounded by
    `max_attempts`; growing the delay between attempts is what keeps that loop cheap until
    the row crosses into dead_letter."""
    if attempts < 0:
        raise ValueError("attempts must be >= 0")
    if ceiling < timedelta(0):
        raise ValueError("ceiling must be >= 0")
    # Work in float seconds and defer constructing the timedelta until after the ceiling
    # clamp: `timedelta * huge_float` overflows its internal microsecond representation
    # immediately (a poison row with attempts in the hundreds hits this), whereas the
    # min() below always brings a float back down to a representable, human-scale ceiling.
    #
    # `float ** int` does NOT saturate to inf — CPython raises OverflowError above ~2.0**1023.
    # `attempts` is caller-supplied (it rides on QueueItem), so a retry helper must not be the
    # thing that raises: past the ceiling the answer is the ceiling, at every magnitude.
    exponent = max(attempts - 1, 0)
    try:
        delay_s = base.total_seconds() * (factor**exponent)
    except OverflowError:
        delay_s = math.inf
    return timedelta(seconds=min(delay_s, ceiling.total_seconds()))


def _row_to_item(row: Mapping[str, Any]) -> QueueItem:
    payload = row["payload"]
    if not isinstance(payload, Mapping):
        # Every enqueue path writes a JSON object. A jsonb array/scalar/null here means the
        # row was written by something other than enqueue(); failing loudly with the row id
        # beats a bare `dict(None)` TypeError three frames away in a consumer.
        raise ValueError(
            f"work_queue row {row['id']!r}: payload is {type(payload).__name__}, "
            "expected a JSON object"
        )
    return QueueItem(
        id=int(row["id"]),
        topic=str(row["topic"]),
        project_id=ProjectId(row["project_id"]),
        payload=MappingProxyType(dict(payload)),
        priority=int(row["priority"]),
        attempts=int(row["attempts"]),
    )


class WorkQueue:
    """The one producer/consumer surface over `work_queue`/`dead_letter` (PHASE0-CONTRACT.md
    §5.3). See the module docstring: delivery is at-least-once, every consumer must be
    idempotent.
    """

    def __init__(self, pool: ConnectionPool, clock: Clock, cfg: QueueConfig) -> None:
        self._pool = pool
        self._clock = clock
        self._cfg = cfg
        self._lease = timedelta(seconds=cfg.lease_seconds)

    def enqueue(
        self,
        topic: str,
        project_id: ProjectId,
        payload: Mapping[str, object],
        priority: int = 100,
        available_at: datetime | None = None,
    ) -> int:
        """Producer side. `available_at` defaults to the injected Clock's `now()` — never
        `datetime.now()` — so offline-adjacent tests can enqueue into a deterministic
        future by advancing a `FakeClock` before calling this. `max_attempts` on the row
        comes from `QueueConfig.max_attempts` at enqueue time (Task 12 gives `enqueue` no
        per-call override, so there is exactly one place this is decided).

        A naive `available_at` is rejected rather than bound: the column is `timestamptz`,
        so psycopg would silently interpret a naive instant in the session's TimeZone and
        the row would become claimable at an hour nobody chose. Every `Clock` in this
        codebase returns aware UTC, so a naive value can only arrive from a caller that
        reached for `datetime.now()` — which PHASE-0's conventions forbid outright.
        """
        if not topic:
            raise ValueError("topic must be a non-empty string")
        if available_at is not None and available_at.tzinfo is None:
            raise ValueError("available_at must be timezone-aware (the column is timestamptz)")
        now = self._clock.now()
        when = available_at if available_at is not None else now
        with self._pool.connection() as conn, conn.cursor() as cur:
            cur.execute(
                _ENQUEUE_SQL,
                {
                    "project_id": project_id.value,
                    "topic": topic,
                    "payload": Jsonb(dict(payload)),
                    "priority": priority,
                    "max_attempts": self._cfg.max_attempts,
                    "available_at": when,
                    "created_at": now,
                },
            )
            row = cur.fetchone()
        if row is None:  # pragma: no cover - INSERT ... RETURNING always yields a row
            raise RuntimeError("enqueue: INSERT ... RETURNING id produced no row")
        return int(row[0])

    def claim(self, topic: str, n: int) -> list[QueueItem]:
        """Task 12's `UPDATE ... WHERE id IN (SELECT ... FOR UPDATE SKIP LOCKED)` claim,
        preceded — in the same transaction — by the dead-letter sweep for `topic` (C-11), so
        a row that just crossed `max_attempts` cannot be claimed one extra time between the
        check and the move. See the class/module docstrings for the at-least-once contract.

        `n` is clamped to `QueueConfig.batch_size`. That field existed and was ignored, which
        left `LIMIT n` — and therefore the `fetchall()` that materialises every claimed
        payload in memory — bounded only by whatever the caller passed. A consumer loop
        drains identically with a clamped batch, so nothing is lost by making the bound real.
        """
        if n <= 0:
            raise ValueError("n must be positive")
        batch = min(n, self._cfg.batch_size)
        with self._pool.connection() as conn, conn.cursor(row_factory=dict_row) as cur:
            cur.execute(_DEAD_LETTER_SQL, {"topic": topic, "n": batch})
            cur.execute(_CLAIM_SQL, {"topic": topic, "lease": self._lease, "n": batch})
            rows = cur.fetchall()
        return [_row_to_item(row) for row in rows]

    def ack(self, item_id: int) -> None:
        """DELETE — the only success path. Acking an id that is already gone (redelivered
        and acked by a second consumer, or already dead-lettered) is a no-op, never an
        error: at-least-once delivery means a race here is expected, not exceptional."""
        with self._pool.connection() as conn, conn.cursor() as cur:
            cur.execute(_ACK_SQL, {"id": item_id})

    def nack(self, item_id: int, backoff: timedelta) -> None:
        """Explicit failure: makes the row available again after `backoff` and clears the
        lease immediately (rather than waiting for it to expire), so a *different* live
        consumer can pick it up right away. Does not touch `attempts` — `claim()` already
        incremented it once for this lease; nack must not double-count."""
        if backoff < timedelta(0):
            raise ValueError("backoff must be >= 0")
        with self._pool.connection() as conn, conn.cursor() as cur:
            cur.execute(_NACK_SQL, {"backoff": backoff, "id": item_id})

    def depth(self, topic: str) -> int:
        """Rows currently queued (any state) for `topic`. Updates `QUEUE_DEPTH`."""
        with self._pool.connection() as conn, conn.cursor() as cur:
            cur.execute(_DEPTH_SQL, {"topic": topic})
            row = cur.fetchone()
        count = int(row[0]) if row is not None else 0
        QUEUE_DEPTH.labels(topic=topic).set(count)
        return count

    def oldest_age_s(self, topic: str) -> float | None:
        """Age, in seconds, of the oldest `available_at` on `topic` — `None` when the topic
        is empty. Computed against the injected Clock's `now()`, not the database's, so this
        is deterministic under a `FakeClock` in tests.

        Always writes `QUEUE_OLDEST_AGE_SECONDS`, including the empty case (as 0). A gauge
        that is only written when there is something to report keeps its last value forever:
        an age alert would latch at whatever the backlog peaked at and never clear once the
        topic drained, which inverts the signal this metric exists to give.
        """
        with self._pool.connection() as conn, conn.cursor() as cur:
            cur.execute(_OLDEST_AVAILABLE_AT_SQL, {"topic": topic})
            row = cur.fetchone()
        oldest: datetime | None = row[0] if row is not None else None
        if oldest is None:
            QUEUE_OLDEST_AGE_SECONDS.labels(topic=topic).set(0.0)
            return None
        age_s = max((self._clock.now() - oldest).total_seconds(), 0.0)
        QUEUE_OLDEST_AGE_SECONDS.labels(topic=topic).set(age_s)
        return age_s

    def dead_letter_count(self, topic: str) -> int:
        """Rows currently on `dead_letter` for `topic`. Updates `QUEUE_DEAD_LETTER_COUNT`."""
        with self._pool.connection() as conn, conn.cursor() as cur:
            cur.execute(_DEAD_LETTER_COUNT_SQL, {"topic": topic})
            row = cur.fetchone()
        count = int(row[0]) if row is not None else 0
        QUEUE_DEAD_LETTER_COUNT.labels(topic=topic).set(count)
        return count

    def xmin_horizon_age_s(self) -> float | None:
        """The real query behind the xmin-horizon age alarm (PHASE-0 Task 12), not a
        comment: the age in seconds of the oldest transaction — live or two-phase-prepared —
        against this database other than our own, which is what bounds how long
        work_queue/dead_letter dead tuples can go unreclaimed. `None` when nothing else holds
        one open. See `_XMIN_HORIZON_SQL` for the two documented blind spots.

        Always writes `QUEUE_XMIN_HORIZON_AGE_SECONDS`, including the `None` case (as 0), for
        the same reason `oldest_age_s` does: a latched gauge is worse than no gauge.
        """
        with self._pool.connection() as conn, conn.cursor() as cur:
            cur.execute(_XMIN_HORIZON_SQL)
            row = cur.fetchone()
        if row is None or row[0] is None:
            QUEUE_XMIN_HORIZON_AGE_SECONDS.set(0.0)
            return None
        age_s = float(row[0])
        QUEUE_XMIN_HORIZON_AGE_SECONDS.set(age_s)
        return age_s

    def xmin_horizon_alarm(
        self, threshold_s: float = XMIN_HORIZON_ALARM_THRESHOLD_S
    ) -> bool:
        """Real threshold check (Task 12: "implement the age query and the alarm threshold
        as a real check, not a comment"). Updates `QUEUE_XMIN_HORIZON_ALARM` alongside the
        age gauge and returns whether the alarm is firing.

        `threshold_s` is a parameter rather than a hard-wired read of the module constant
        because PLAN.md §6's rule is "no magic numbers in code"; `QueueConfig` is frozen by
        PHASE0-CONTRACT.md §3.4 at three fields, so an operator override has to enter here.
        """
        age_s = self.xmin_horizon_age_s()
        fired = xmin_horizon_alarm_from_age(age_s, threshold_s)
        QUEUE_XMIN_HORIZON_ALARM.set(1.0 if fired else 0.0)
        return fired
