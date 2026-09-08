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

import json
import math
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Final, cast
from uuid import UUID

import psycopg
from prometheus_client import Gauge
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb
from psycopg_pool import ConnectionPool

from tracebed.adapters.ports import AuthorizedQueueWrite
from tracebed.domain.authority import AccessContext, GrantBinding
from tracebed.domain.clock import Clock
from tracebed.domain.enums import FeedbackSource, ProjectRole
from tracebed.domain.errors import (
    AuthorizationDenied,
    ErasureFenced,
    QueueFull,
    RunAuthorityDenied,
    TracebedError,
)
from tracebed.domain.ids import AgentTypeId, PrincipalId, ProjectId, RunId
from tracebed.stores.pg.activity import ActivityGate
from tracebed.stores.pg.pool import scoped

if TYPE_CHECKING:
    # domain-config chunk's module (PHASE0-CONTRACT.md §3.4). Guarded so this file — and
    # every offline test importing it — does not hard-fail while that chunk is still
    # landing in a parallel build; `from __future__ import annotations` makes the
    # constructor's `cfg: QueueConfig` annotation a lazy string either way.
    from tracebed.domain.config import QueueConfig

__all__ = [
    "MAX_AUTHORIZED_QUEUE_BATCH",
    "QUEUE_DEAD_LETTER_COUNT",
    "QUEUE_DEPTH",
    "QUEUE_OLDEST_AGE_SECONDS",
    "QUEUE_XMIN_HORIZON_AGE_SECONDS",
    "QUEUE_XMIN_HORIZON_ALARM",
    "TOPIC_MEMORY_PROPOSAL",
    "TOPIC_OUTCOME_EVENT",
    "TOPIC_TRACE_EVENT",
    "XMIN_HORIZON_ALARM_THRESHOLD_S",
    "AuthorizedQueuePlan",
    "AuthorizedWorkQueue",
    "QueueItem",
    "WorkQueue",
    "WorkerQueue",
    "compute_backoff",
    "is_poisoned",
    "plan_authorized_enqueue",
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

# A public hard cap for the pure planner, deliberately equal to the largest
# configurable admission batch.  It bounds allocation before a pool/activity
# resource is touched.
MAX_AUTHORIZED_QUEUE_BATCH: Final = 500


@dataclass(frozen=True, slots=True)
class AuthorizedQueuePlan:
    """Pure authorization shape for one homogeneous durable enqueue batch."""

    topic: str
    required_role: ProjectRole
    grant: GrantBinding
    run_ids: tuple[RunId, ...]

    def __post_init__(self) -> None:
        if type(self.topic) is not str or self.topic not in {
            TOPIC_TRACE_EVENT,
            TOPIC_OUTCOME_EVENT,
            TOPIC_MEMORY_PROPOSAL,
        }:
            raise ValueError("authorized queue plan has an unsupported topic")
        if type(self.required_role) is not ProjectRole:
            raise TypeError("authorized queue plan role must be a ProjectRole")
        if type(self.grant) is not GrantBinding:
            raise TypeError("authorized queue plan grant must be a GrantBinding")
        if type(self.run_ids) is not tuple or not self.run_ids:
            raise ValueError("authorized queue plan requires an exact non-empty run id tuple")
        if any(type(run_id) is not RunId for run_id in self.run_ids):
            raise TypeError("authorized queue plan run ids must be RunId values")
        if tuple(sorted(set(self.run_ids), key=lambda run_id: run_id.value.bytes)) != self.run_ids:
            raise ValueError("authorized queue plan run ids must be sorted and distinct")


def plan_authorized_enqueue(
    access: AccessContext,
    writes: tuple[AuthorizedQueueWrite, ...],
) -> AuthorizedQueuePlan:
    """Validate exact, homogeneous write shapes before activity or database I/O."""

    if type(access) is not AccessContext:
        raise TypeError("access must be an AccessContext")
    if type(writes) is not tuple:
        raise TypeError("writes must be an exact tuple")
    if not writes or len(writes) > MAX_AUTHORIZED_QUEUE_BATCH:
        raise ValueError("authorized queue write count is outside the supported range")
    for write in writes:
        if type(write) is not AuthorizedQueueWrite:
            raise TypeError("writes must contain AuthorizedQueueWrite values")

    topic = writes[0].topic
    if any(write.topic != topic for write in writes):
        raise ValueError("authorized queue writes must have one topic")
    if topic == TOPIC_TRACE_EVENT:
        required_role = ProjectRole.DATA
    elif topic == TOPIC_MEMORY_PROPOSAL:
        if len(writes) != 1:
            raise ValueError("memory proposal admission accepts exactly one write")
        required_role = ProjectRole.DATA
    elif topic == TOPIC_OUTCOME_EVENT:
        if len(writes) != 1:
            raise ValueError("outcome admission accepts exactly one write")
        required_role = ProjectRole.FEEDBACK
    else:  # AuthorizedQueueWrite prevents this; retain the pure fail-closed seam.
        raise ValueError("unsupported authorized queue topic")

    grant = access.grant_for(required_role)
    if grant is None:
        raise AuthorizationDenied()
    run_ids = tuple(
        sorted({write.run_id for write in writes}, key=lambda run_id: run_id.value.bytes)
    )
    return AuthorizedQueuePlan(
        topic=topic,
        required_role=required_role,
        grant=grant,
        run_ids=run_ids,
    )


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
    # The fields below are optional only so isolated *legacy* fixtures can
    # continue to construct the old six-field carrier.  WorkerQueue never
    # returns one of those values: `_row_to_item` accepts exactly the v1
    # authority envelope before a consumer can see it.
    authority_version: int = 0
    run_id: RunId | None = None
    source_principal_id: PrincipalId | None = None
    source_agent_type_id: AgentTypeId | None = None
    source_grant_id: UUID | None = None
    required_role: ProjectRole | None = None
    feedback_source: FeedbackSource | None = None
    run_owner_principal_id: PrincipalId | None = None
    run_owner_agent_type_id: AgentTypeId | None = None
    subject_digests: tuple[bytes, ...] = ()
    max_attempts: int = 0
    available_at: datetime | None = None
    created_at: datetime | None = None
    lease_expires_at: datetime | None = None


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
_LEGACY_DEAD_LETTER_SQL: Final = """
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
_LEGACY_CLAIM_SQL: Final = """
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

_LEGACY_ACK_SQL: Final = "DELETE FROM work_queue WHERE id = %(id)s"

_LEGACY_NACK_SQL: Final = (
    "UPDATE work_queue SET available_at = now() + %(backoff)s, "
    "lease_expires_at = NULL WHERE id = %(id)s"
)

_DEPTH_SQL: Final = "SELECT COUNT(*) FROM work_queue WHERE topic = %(topic)s"
_OLDEST_AVAILABLE_AT_SQL: Final = "SELECT MIN(available_at) FROM work_queue WHERE topic = %(topic)s"
_DEAD_LETTER_COUNT_SQL: Final = "SELECT COUNT(*) FROM dead_letter WHERE topic = %(topic)s"

# v1 worker SQL deliberately has no insert/enqueue primitive.  A claimed
# generation is the triple `(id, attempts, lease_expires_at)`: an expired
# lease can be renewed by another worker while the first worker is still doing
# side effects, so an id-only ack/nack/reject is an authority bug rather than
# a harmless at-least-once race.
_DEAD_LETTER_SQL: Final = """
WITH poisoned AS (
    DELETE FROM work_queue
    WHERE id IN (
        SELECT id FROM work_queue
        WHERE topic = %(topic)s
          AND attempts > max_attempts
          AND (lease_expires_at IS NULL OR lease_expires_at < now())
        ORDER BY id
        FOR UPDATE SKIP LOCKED
        LIMIT %(n)s
    )
    RETURNING id, project_id, topic, payload, priority, attempts, max_attempts,
              available_at, created_at, lease_expires_at, authority_version, run_id,
              source_principal_id, source_agent_type_id, source_grant_id, required_role,
              feedback_source, run_owner_principal_id, run_owner_agent_type_id, subject_digests
)
INSERT INTO dead_letter
    (id, project_id, topic, payload, priority, attempts, max_attempts,
     available_at, created_at, lease_expires_at, authority_version, run_id,
     source_principal_id, source_agent_type_id, source_grant_id, required_role,
     feedback_source, run_owner_principal_id, run_owner_agent_type_id,
     subject_digests, failed_at, last_error)
SELECT id, project_id, topic, payload, priority, attempts, max_attempts,
       available_at, created_at, lease_expires_at, authority_version, run_id,
       source_principal_id, source_agent_type_id, source_grant_id, required_role,
       feedback_source, run_owner_principal_id, run_owner_agent_type_id,
       subject_digests, now(), 'max_attempts_exceeded'
FROM poisoned
""".strip()

_CLAIM_SQL: Final = """
UPDATE work_queue
SET lease_expires_at = now() + %(lease)s, attempts = attempts + 1
WHERE id IN (
    SELECT id FROM work_queue
    WHERE topic = %(topic)s
      AND available_at <= now()
      AND (lease_expires_at IS NULL OR lease_expires_at < now())
      AND attempts <= max_attempts
      AND authority_version = 1
    ORDER BY priority, id
    FOR UPDATE SKIP LOCKED
    LIMIT %(n)s
)
RETURNING id, project_id, topic, payload, priority, attempts, max_attempts,
          available_at, created_at, lease_expires_at, authority_version, run_id,
          source_principal_id, source_agent_type_id, source_grant_id, required_role,
          feedback_source, run_owner_principal_id, run_owner_agent_type_id, subject_digests
""".strip()

_ACK_SQL: Final = """
DELETE FROM work_queue
WHERE id = %(id)s
  AND attempts = %(attempts)s
  AND lease_expires_at IS NOT DISTINCT FROM %(lease_expires_at)s
""".strip()

_NACK_SQL: Final = """
UPDATE work_queue
SET available_at = now() + %(backoff)s, lease_expires_at = NULL
WHERE id = %(id)s
  AND attempts = %(attempts)s
  AND lease_expires_at IS NOT DISTINCT FROM %(lease_expires_at)s
""".strip()

_REJECT_SQL: Final = """
WITH rejected AS (
    DELETE FROM work_queue
    WHERE id = %(id)s
      AND attempts = %(attempts)s
      AND lease_expires_at IS NOT DISTINCT FROM %(lease_expires_at)s
    RETURNING id, project_id, topic, payload, priority, attempts, max_attempts,
              available_at, created_at, lease_expires_at, authority_version, run_id,
              source_principal_id, source_agent_type_id, source_grant_id, required_role,
              feedback_source, run_owner_principal_id, run_owner_agent_type_id, subject_digests
)
INSERT INTO dead_letter
    (id, project_id, topic, payload, priority, attempts, max_attempts,
     available_at, created_at, lease_expires_at, authority_version, run_id,
     source_principal_id, source_agent_type_id, source_grant_id, required_role,
     feedback_source, run_owner_principal_id, run_owner_agent_type_id,
     subject_digests, failed_at, last_error)
SELECT id, project_id, topic, payload, priority, attempts, max_attempts,
       available_at, created_at, lease_expires_at, authority_version, run_id,
       source_principal_id, source_agent_type_id, source_grant_id, required_role,
       feedback_source, run_owner_principal_id, run_owner_agent_type_id,
       subject_digests, now(), %(reason)s
FROM rejected
RETURNING id
""".strip()

# c12 intentionally removes raw global queue access from the worker role.
# These narrow profiled routines are the only scheduler/disposition surface:
# a claim may cross projects internally, but returns only the rows actually
# leased to this worker and never exposes an arbitrary project scan.
_WORKER_CLAIM_FUNCTION_SQL: Final = """
SELECT id, project_id, topic, payload, priority, attempts, max_attempts,
       available_at, created_at, lease_expires_at, authority_version, run_id,
       source_principal_id, source_agent_type_id, source_grant_id, required_role,
       feedback_source, run_owner_principal_id, run_owner_agent_type_id,
       subject_digests
FROM public.tracebed_worker_queue_claim(
    %(topic)s::text, %(lease)s::interval, %(n)s::integer
)
""".strip()

_WORKER_DISPOSITION_FUNCTION_SQL: Final = """
SELECT public.tracebed_worker_queue_disposition(
    %(id)s::bigint, %(attempts)s::integer, %(lease_expires_at)s::timestamptz,
    %(action)s::text, %(backoff)s::interval, %(reason)s::text
) AS applied
""".strip()

_WORKER_METRICS_FUNCTION_SQL: Final = """
SELECT depth, oldest_available_at, dead_count
FROM public.tracebed_worker_queue_metrics(%(topic)s::text)
""".strip()

_REJECTION_REASONS: Final[frozenset[str]] = frozenset(
    {
        "malformed_authority",
        "malformed_business_payload",
        "authority_payload_shadow",
        "owner_conflict",
        "outcome_replay_conflict",
        "proposal_authority_conflict",
        "max_attempts_exceeded",
    }
)

# The authorized producer has no raw table statement in this module.  c12
# revokes that privilege; the profiled API-only function below derives every
# authority/owner/subject field and performs the bounded capacity check.
_AUTHORIZED_ENQUEUE_FUNCTION_SQL: Final = """
SELECT queue_id, writable
FROM public.tracebed_enqueue_authorized(
    %(project_id)s::uuid, %(principal_id)s::uuid, %(agent_type_id)s::uuid,
    %(grant_id)s::uuid, %(feedback_source)s::text, %(topic)s::text,
    %(run_id)s::uuid, %(payload)s::jsonb, %(priority)s::integer,
    %(max_attempts)s::integer, %(available_at)s::timestamptz,
    %(max_global_depth)s::integer, %(max_topic_depth)s::integer,
    %(max_project_depth)s::integer, %(enqueue)s::boolean
)
""".strip()

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


def _legacy_row_to_item(row: Mapping[str, Any]) -> QueueItem:
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


def _exact_int(value: object, *, field: str, minimum: int | None = None) -> int:
    if type(value) is not int:
        raise ValueError(f"work_queue row has an invalid {field}")
    if minimum is not None and value < minimum:
        raise ValueError(f"work_queue row has an invalid {field}")
    return value


def _exact_uuid(value: object, *, field: str) -> UUID:
    if type(value) is not UUID:
        raise ValueError(f"work_queue row has an invalid {field}")
    return value


def _exact_datetime(value: object, *, field: str, nullable: bool = False) -> datetime | None:
    if value is None and nullable:
        return None
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"work_queue row has an invalid {field}")
    return value


def _subject_digest_tuple(value: object) -> tuple[bytes, ...]:
    if type(value) not in {list, tuple}:
        raise ValueError("work_queue row has invalid subject_digests")
    digests: tuple[object, ...] = tuple(cast(list[object] | tuple[object, ...], value))
    if len(digests) > 64 or any(
        type(digest) is not bytes or len(digest) != 32 for digest in digests
    ):
        raise ValueError("work_queue row has invalid subject_digests")
    byte_digests = cast(tuple[bytes, ...], digests)
    if tuple(sorted(byte_digests)) != byte_digests or len(set(byte_digests)) != len(byte_digests):
        raise ValueError("work_queue row has invalid subject_digests")
    return byte_digests


def _row_to_item(row: Mapping[str, Any]) -> QueueItem:
    """Decode exactly one claimed authority-v1 queue row.

    This boundary precedes business parsing.  In particular, JSON must never
    be allowed to fill in a missing principal, owner, role, grant, or adapter.
    """

    required = {
        "id",
        "project_id",
        "topic",
        "payload",
        "priority",
        "attempts",
        "max_attempts",
        "available_at",
        "created_at",
        "lease_expires_at",
        "authority_version",
        "run_id",
        "source_principal_id",
        "source_agent_type_id",
        "source_grant_id",
        "required_role",
        "feedback_source",
        "run_owner_principal_id",
        "run_owner_agent_type_id",
        "subject_digests",
    }
    if set(row) != required:
        raise ValueError("work_queue row has an unexpected authority shape")
    payload = row["payload"]
    if not isinstance(payload, Mapping):
        raise ValueError("work_queue row payload is not an object")
    topic = row["topic"]
    if type(topic) is not str or topic not in {
        TOPIC_TRACE_EVENT,
        TOPIC_OUTCOME_EVENT,
        TOPIC_MEMORY_PROPOSAL,
    }:
        raise ValueError("work_queue row has an unsupported topic")
    if _exact_int(row["authority_version"], field="authority_version") != 1:
        raise ValueError("work_queue row is not authority version 1")
    role_raw = row["required_role"]
    if type(role_raw) is not str:
        raise ValueError("work_queue row has an invalid required_role")
    try:
        required_role = ProjectRole(role_raw)
    except (TypeError, ValueError) as exc:
        raise ValueError("work_queue row has an invalid required_role") from exc
    feedback_raw = row["feedback_source"]
    if feedback_raw is not None and type(feedback_raw) is not str:
        raise ValueError("work_queue row has an invalid feedback_source")
    try:
        feedback_source = None if feedback_raw is None else FeedbackSource(feedback_raw)
    except (TypeError, ValueError) as exc:
        raise ValueError("work_queue row has an invalid feedback_source") from exc
    if topic in {TOPIC_TRACE_EVENT, TOPIC_MEMORY_PROPOSAL}:
        if (
            required_role is not ProjectRole.DATA
            or feedback_source is not None
            or row["source_principal_id"] != row["run_owner_principal_id"]
            or row["source_agent_type_id"] != row["run_owner_agent_type_id"]
        ):
            raise ValueError("work_queue row has an invalid data authority shape")
    elif required_role is not ProjectRole.FEEDBACK or feedback_source is None:
        raise ValueError("work_queue row has an invalid feedback authority shape")
    return QueueItem(
        id=_exact_int(row["id"], field="id", minimum=1),
        topic=topic,
        project_id=ProjectId(_exact_uuid(row["project_id"], field="project_id")),
        payload=MappingProxyType(dict(payload)),
        priority=_exact_int(row["priority"], field="priority"),
        attempts=_exact_int(row["attempts"], field="attempts", minimum=1),
        authority_version=1,
        run_id=RunId(_exact_uuid(row["run_id"], field="run_id")),
        source_principal_id=PrincipalId(
            _exact_uuid(row["source_principal_id"], field="source_principal_id")
        ),
        source_agent_type_id=AgentTypeId(
            _exact_uuid(row["source_agent_type_id"], field="source_agent_type_id")
        ),
        source_grant_id=_exact_uuid(row["source_grant_id"], field="source_grant_id"),
        required_role=required_role,
        feedback_source=feedback_source,
        run_owner_principal_id=PrincipalId(
            _exact_uuid(row["run_owner_principal_id"], field="run_owner_principal_id")
        ),
        run_owner_agent_type_id=AgentTypeId(
            _exact_uuid(row["run_owner_agent_type_id"], field="run_owner_agent_type_id")
        ),
        subject_digests=_subject_digest_tuple(row["subject_digests"]),
        max_attempts=_exact_int(row["max_attempts"], field="max_attempts", minimum=0),
        available_at=_exact_datetime(row["available_at"], field="available_at"),
        created_at=_exact_datetime(row["created_at"], field="created_at"),
        lease_expires_at=_exact_datetime(row["lease_expires_at"], field="lease_expires_at"),
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
            cur.execute(_LEGACY_DEAD_LETTER_SQL, {"topic": topic, "n": batch})
            cur.execute(_LEGACY_CLAIM_SQL, {"topic": topic, "lease": self._lease, "n": batch})
            rows = cur.fetchall()
        # `_CLAIM_SQL`'s inner `SELECT ... ORDER BY priority, id ... LIMIT n` decides WHICH rows
        # are claimed, but `UPDATE ... RETURNING` does NOT return rows in a subquery's order —
        # Postgres yields them in an unspecified, physically-driven order (id order, in practice).
        # Sort the materialised batch here so `claim()` hands the caller highest-priority-first,
        # as its contract (and `test_claim_orders_by_priority_then_id`) requires. Kept here rather
        # than wrapping the UPDATE in an ordered CTE so `_CLAIM_SQL` stays the single UPDATE the
        # offline guards pin (FOR UPDATE SKIP LOCKED on the inner select; RETURNING last).
        items = [_legacy_row_to_item(row) for row in rows]
        items.sort(key=lambda item: (item.priority, item.id))
        return items

    def ack(self, item_id: int) -> None:
        """DELETE — the only success path. Acking an id that is already gone (redelivered
        and acked by a second consumer, or already dead-lettered) is a no-op, never an
        error: at-least-once delivery means a race here is expected, not exceptional."""
        with self._pool.connection() as conn, conn.cursor() as cur:
            cur.execute(_LEGACY_ACK_SQL, {"id": item_id})

    def nack(self, item_id: int, backoff: timedelta) -> None:
        """Explicit failure: makes the row available again after `backoff` and clears the
        lease immediately (rather than waiting for it to expire), so a *different* live
        consumer can pick it up right away. Does not touch `attempts` — `claim()` already
        incremented it once for this lease; nack must not double-count."""
        if backoff < timedelta(0):
            raise ValueError("backoff must be >= 0")
        with self._pool.connection() as conn, conn.cursor() as cur:
            cur.execute(_LEGACY_NACK_SQL, {"backoff": backoff, "id": item_id})

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

    def xmin_horizon_alarm(self, threshold_s: float = XMIN_HORIZON_ALARM_THRESHOLD_S) -> bool:
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


class WorkerQueue:
    """Authority-v1 worker-side queue surface.

    This object intentionally does not inherit :class:`WorkQueue`: inheritance
    would make its legacy ``enqueue`` method available to a worker process.
    Its only mutating operations are generation-fenced claim outcomes.
    """

    def __init__(self, pool: ConnectionPool, clock: Clock, cfg: QueueConfig) -> None:
        self._pool = pool
        self._clock = clock
        self._cfg = cfg
        self._lease = timedelta(seconds=cfg.lease_seconds)

    @staticmethod
    def _fence(item: QueueItem) -> dict[str, object]:
        if type(item) is not QueueItem or item.authority_version != 1:
            raise ValueError("worker queue mutations require a claimed authority-v1 QueueItem")
        if item.lease_expires_at is None:
            raise ValueError("worker queue mutations require a leased QueueItem")
        return {
            "id": item.id,
            "attempts": item.attempts,
            "lease_expires_at": item.lease_expires_at,
        }

    @staticmethod
    def _fence_from_row(row: Mapping[str, Any]) -> dict[str, object]:
        lease = _exact_datetime(row.get("lease_expires_at"), field="lease_expires_at")
        if lease is None:  # `_exact_datetime` only allows this with nullable=True
            raise ValueError("work_queue row has an invalid lease_expires_at")
        return {
            "id": _exact_int(row.get("id"), field="id", minimum=1),
            "attempts": _exact_int(row.get("attempts"), field="attempts", minimum=1),
            "lease_expires_at": lease,
        }

    def claim(self, topic: str, n: int) -> list[QueueItem]:
        if type(topic) is not str or topic not in {
            TOPIC_TRACE_EVENT,
            TOPIC_OUTCOME_EVENT,
            TOPIC_MEMORY_PROPOSAL,
        }:
            raise ValueError("worker queue claim has an unsupported topic")
        if type(n) is not int or n <= 0:
            raise ValueError("n must be positive")
        batch = min(n, self._cfg.batch_size)
        items: list[QueueItem] = []
        with self._pool.connection() as conn, conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                _WORKER_CLAIM_FUNCTION_SQL,
                {"topic": topic, "lease": self._lease, "n": batch},
            )
            for row in cur.fetchall():
                try:
                    items.append(_row_to_item(row))
                except (TypeError, ValueError):
                    # The database row is already claimed.  Its business data
                    # must never be handed to a consumer after its authority
                    # envelope failed validation; move exactly that generation.
                    params = self._fence_from_row(row)
                    params.update(
                        {
                            "action": "reject",
                            "backoff": None,
                            "reason": "malformed_authority",
                        }
                    )
                    cur.execute(_WORKER_DISPOSITION_FUNCTION_SQL, params)
        items.sort(key=lambda item: (item.priority, item.id))
        return items

    def ack(self, item: QueueItem) -> bool:
        with self._pool.connection() as conn, conn.cursor() as cur:
            params = self._fence(item)
            params.update({"action": "ack", "backoff": None, "reason": None})
            cur.execute(_WORKER_DISPOSITION_FUNCTION_SQL, params)
            row = cur.fetchone()
            return row is not None and row[0] is True

    def nack(self, item: QueueItem, backoff: timedelta) -> bool:
        if type(backoff) is not timedelta or backoff < timedelta(0):
            raise ValueError("backoff must be a non-negative timedelta")
        params = self._fence(item)
        params.update({"action": "nack", "backoff": backoff, "reason": None})
        with self._pool.connection() as conn, conn.cursor() as cur:
            cur.execute(_WORKER_DISPOSITION_FUNCTION_SQL, params)
            row = cur.fetchone()
            return row is not None and row[0] is True

    def reject(self, item: QueueItem, reason: str) -> bool:
        if type(reason) is not str or reason not in _REJECTION_REASONS:
            raise ValueError("worker queue rejection reason is not a bounded reason code")
        params = self._fence(item)
        params.update({"action": "reject", "backoff": None, "reason": reason})
        with self._pool.connection() as conn, conn.cursor() as cur:
            cur.execute(_WORKER_DISPOSITION_FUNCTION_SQL, params)
            row = cur.fetchone()
            return row is not None and row[0] is True

    def poison(self, item: QueueItem, reason: str) -> bool:
        """Explicit alias for a terminal worker rejection; no free-text errors."""

        return self.reject(item, reason)

    def depth(self, topic: str) -> int:
        with self._pool.connection() as conn, conn.cursor() as cur:
            cur.execute(_WORKER_METRICS_FUNCTION_SQL, {"topic": topic})
            row = cur.fetchone()
        count = int(row[0]) if row is not None else 0
        QUEUE_DEPTH.labels(topic=topic).set(count)
        return count

    def oldest_age_s(self, topic: str) -> float | None:
        with self._pool.connection() as conn, conn.cursor() as cur:
            cur.execute(_WORKER_METRICS_FUNCTION_SQL, {"topic": topic})
            row = cur.fetchone()
        oldest: datetime | None = row[1] if row is not None else None
        if oldest is None:
            QUEUE_OLDEST_AGE_SECONDS.labels(topic=topic).set(0.0)
            return None
        age_s = max((self._clock.now() - oldest).total_seconds(), 0.0)
        QUEUE_OLDEST_AGE_SECONDS.labels(topic=topic).set(age_s)
        return age_s

    def dead_letter_count(self, topic: str) -> int:
        with self._pool.connection() as conn, conn.cursor() as cur:
            cur.execute(_WORKER_METRICS_FUNCTION_SQL, {"topic": topic})
            row = cur.fetchone()
        count = int(row[2]) if row is not None else 0
        QUEUE_DEAD_LETTER_COUNT.labels(topic=topic).set(count)
        return count

    def xmin_horizon_age_s(self) -> float | None:
        with self._pool.connection() as conn, conn.cursor() as cur:
            cur.execute(_XMIN_HORIZON_SQL)
            row = cur.fetchone()
        if row is None or row[0] is None:
            QUEUE_XMIN_HORIZON_AGE_SECONDS.set(0.0)
            return None
        age_s = float(row[0])
        QUEUE_XMIN_HORIZON_AGE_SECONDS.set(age_s)
        return age_s

    def xmin_horizon_alarm(self, threshold_s: float = XMIN_HORIZON_ALARM_THRESHOLD_S) -> bool:
        age_s = self.xmin_horizon_age_s()
        fired = xmin_horizon_alarm_from_age(age_s, threshold_s)
        QUEUE_XMIN_HORIZON_ALARM.set(1.0 if fired else 0.0)
        return fired


@dataclass(frozen=True, slots=True)
class _MeasuredAuthorizedWrite:
    write: AuthorizedQueueWrite
    payload: dict[str, object]


class _DiscardWritablePreflight(Exception):
    """Rollback a preflight savepoint that found no late containment.

    A writable preflight may create a live run/fence or extend attribution,
    but those ordinary effects belong exclusively to the final all-or-nothing
    enqueue transaction.  A false preflight, in contrast, is durable erasure
    containment and must survive a later bad item in the same batch.
    """


def _compact_json_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


class AuthorizedWorkQueue:
    """Authority-fenced producer for the future 0010 queue schema.

    It intentionally has no claim/ack/nack methods and never implements the
    legacy producer protocol.  Consumers remain unchanged until their own
    migration and route cutover land.
    """

    def __init__(
        self,
        pool: ConnectionPool,
        clock: Clock,
        cfg: QueueConfig,
        *,
        activity: ActivityGate,
    ) -> None:
        self._pool = pool
        self._clock = clock
        self._cfg = cfg
        self._activity = activity

    def enqueue_many_authorized(
        self,
        access: AccessContext,
        writes: tuple[AuthorizedQueueWrite, ...],
    ) -> tuple[int, ...]:
        """Admit a batch or commit durable late-erasure containment first.

        Every item first executes the exact server-side open/bind path without
        a queue INSERT.  If a subject request discovers this run, that path
        returns ``writable=false`` *after* atomically attaching/fencing its
        closure.  The scoped transaction then exits successfully, preserving
        containment, and the caller receives ``ErasureFenced`` outside it.
        When all preflights are writable, the same idempotent boundary is run
        a second time with the business INSERT enabled, so queue-capacity and
        ordinary admission failures still roll back all binding and inserts.
        """

        plan = plan_authorized_enqueue(access, writes)
        measured = self._measure_writes(writes)
        # The SECDEF takes the per-run serialization lock.  Process distinct
        # runs in canonical UUID-byte order (while retaining caller order for
        # multiple items of one run) so independently batched producers never
        # reverse the global run-lock order.
        ordered_measured = tuple(
            entry
            for _index, entry in sorted(
                enumerate(measured),
                key=lambda indexed: (indexed[1].write.run_id.value.bytes, indexed[0]),
            )
        )
        now = self._clock.now()
        if type(now) is not datetime or now.tzinfo is None or now.utcoffset() is None:
            raise ValueError("authorized queue clock must return a timezone-aware datetime")
        with self._activity.shared(access.project_id):
            fenced = False
            preflight_error: TracebedError | None = None
            # Each preflight is a savepoint under one project-scoped
            # transaction.  A writable result deliberately rolls its
            # savepoint back, while a false result releases it and remains
            # committed when this outer transaction exits.  Crucially, keep
            # scanning after an auth/business refusal: a later (or, under
            # canonical sorting, earlier) late target must not be forgotten
            # merely because another batch item is invalid or foreign-owned.
            with scoped(self._pool, access.project_id) as conn:
                grant = access.grant_for(plan.required_role)
                if grant is None:
                    raise AuthorizationDenied()
                for entry in ordered_measured:
                    write = entry.write
                    available_at = write.available_at if write.available_at is not None else now
                    try:
                        with conn.transaction(), conn.cursor() as cur:
                            _queue_id, writable = self._call_authorized_enqueue(
                                cur,
                                access,
                                grant,
                                entry,
                                available_at,
                                enqueue=False,
                            )
                            if writable:
                                # Roll back any normal admission effects; the
                                # final pass below remains the sole atomic
                                # bind+enqueue transaction for a writable
                                # batch.
                                raise _DiscardWritablePreflight()
                            fenced = True
                    except _DiscardWritablePreflight:
                        continue
                    except TracebedError as error:
                        # The canonical run order fixes precedence independent
                        # of caller order.  The error is raised only after the
                        # outer transaction has committed every false result.
                        if preflight_error is None:
                            preflight_error = error

            # Do not raise while ``scoped`` is active: its successful exit is
            # the commit point for every late-run closure.  A typed bad-item
            # refusal takes precedence over a fence, matching ordinary
            # authority precedence without rolling containment back.
            if preflight_error is not None:
                raise preflight_error
            if fenced:
                raise ErasureFenced()

            ids: list[int] = []
            fenced_during_enqueue = False
            final_containment_error: TracebedError | None = None
            with scoped(self._pool, access.project_id) as conn:
                grant = access.grant_for(plan.required_role)
                if grant is None:
                    raise AuthorizationDenied()
                for entry in ordered_measured:
                    write = entry.write
                    available_at = write.available_at if write.available_at is not None else now
                    if fenced_during_enqueue:
                        # A request won between the isolated preflight and
                        # final transaction.  Do not enqueue any more work,
                        # but do visit every remaining run under its own
                        # savepoint so a later target association cannot be
                        # skipped because an unrelated lower UUID observed
                        # the request first.
                        try:
                            with conn.transaction(), conn.cursor() as cur:
                                _queue_id, writable = self._call_authorized_enqueue(
                                    cur,
                                    access,
                                    grant,
                                    entry,
                                    available_at,
                                    enqueue=False,
                                )
                                if writable:
                                    raise _DiscardWritablePreflight()
                        except _DiscardWritablePreflight:
                            continue
                        except TracebedError as error:
                            if final_containment_error is None:
                                final_containment_error = error
                        continue

                    with conn.cursor() as cur:
                        queue_id, writable = self._call_authorized_enqueue(
                            cur,
                            access,
                            grant,
                            entry,
                            available_at,
                            enqueue=True,
                        )
                        # A shared ActivityGate plus the in-transaction
                        # durable locks make a false result after an inserted
                        # row impossible for normal callers.  A direct,
                        # authorized request may still win in the small gap
                        # between the isolated preflight and this final
                        # transaction.  If it wins before the first INSERT,
                        # let its binder containment commit and refuse only
                        # after the scoped transaction exits.  Once business
                        # work exists, fail/rollback rather than permit a
                        # partial batch.
                        if not writable:
                            if not ids:
                                fenced_during_enqueue = True
                                continue
                            raise TracebedError()
                        if queue_id is None:
                            raise TracebedError()
                        ids.append(queue_id)
            if final_containment_error is not None:
                raise final_containment_error
            if fenced_during_enqueue:
                raise ErasureFenced()
        return tuple(ids)

    def _call_authorized_enqueue(
        self,
        cur: Any,
        access: AccessContext,
        grant: GrantBinding,
        entry: _MeasuredAuthorizedWrite,
        available_at: datetime,
        *,
        enqueue: bool,
    ) -> tuple[int | None, bool]:
        write = entry.write
        try:
            cur.execute(
                _AUTHORIZED_ENQUEUE_FUNCTION_SQL,
                {
                    "project_id": access.project_id.value,
                    "principal_id": access.principal_id.value,
                    "agent_type_id": access.agent_type_id.value,
                    "grant_id": grant.grant_id,
                    "feedback_source": (
                        grant.feedback_source.value if grant.feedback_source is not None else None
                    ),
                    "topic": write.topic,
                    "payload": Jsonb(entry.payload),
                    "priority": write.priority,
                    "max_attempts": self._cfg.max_attempts,
                    "available_at": available_at,
                    "run_id": write.run_id.value,
                    "max_global_depth": self._cfg.admission.max_global_depth,
                    "max_topic_depth": self._cfg.admission.max_topic_depth,
                    "max_project_depth": self._cfg.admission.max_project_depth,
                    "enqueue": enqueue,
                },
            )
        except psycopg.Error as error:
            if error.sqlstate == "42501":
                raise AuthorizationDenied() from None
            if error.sqlstate == "P0002":
                raise RunAuthorityDenied() from None
            if error.sqlstate == "P0004":
                raise ErasureFenced() from None
            if error.sqlstate == "P0005":
                # Recursive closure overflow is an operator-blocking opaque
                # refusal.  Keep it indistinguishable from another durable
                # fence at the API boundary; never expose the SQLSTATE.
                raise ErasureFenced() from None
            if error.sqlstate == "P0006":
                raise QueueFull() from None
            raise TracebedError() from None
        row = cur.fetchone()
        if row is None or len(row) != 2:  # pragma: no cover - profiled row shape is exact
            raise TracebedError()
        raw_id, writable = row
        if type(writable) is not bool:
            raise TracebedError()
        if raw_id is not None and type(raw_id) is not int:
            raise TracebedError()
        return raw_id, writable

    def _measure_writes(
        self, writes: tuple[AuthorizedQueueWrite, ...]
    ) -> tuple[_MeasuredAuthorizedWrite, ...]:
        limit = self._cfg.admission
        measured: list[_MeasuredAuthorizedWrite] = []
        envelopes: list[dict[str, object]] = []
        for write in writes:
            payload = write.to_json_payload()
            envelope = {
                "topic": write.topic,
                "run_id": str(write.run_id.value),
                "payload": payload,
                "priority": write.priority,
                "available_at": write.available_at.isoformat()
                if write.available_at is not None
                else None,
            }
            if len(_compact_json_bytes(envelope)) > limit.max_item_bytes:
                raise ValueError("authorized queue item exceeds the configured byte limit")
            measured.append(_MeasuredAuthorizedWrite(write=write, payload=payload))
            envelopes.append(envelope)
        if len(measured) > limit.max_batch_items:
            raise ValueError("authorized queue batch exceeds the configured item limit")
        if len(_compact_json_bytes(envelopes)) > limit.max_batch_bytes:
            raise ValueError("authorized queue batch exceeds the configured byte limit")
        return tuple(measured)
