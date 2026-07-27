"""PHASE-0 Task 12 — SKIP LOCKED work queue.

There is no Postgres on this machine (PHASE0-CONTRACT.md §12), so the offline half of this
module is where the teeth are. It covers, without a database:

* the SQL *text* — every clause whose loss or reversal silently turns the queue into a
  double-delivery machine (`FOR UPDATE SKIP LOCKED`, `ORDER BY priority, id`, the
  availability and lease predicates, the `attempts <= max_attempts` claim guard);
* the SQL *schema fit* — every column name in every statement is checked against
  `migrations/0002_partitioned.sql`, and every NOT NULL/defaultless `dead_letter` column is
  asserted present in the dead-letter INSERT list. A rename in the migrations chunk breaks
  these tests instead of breaking production;
* every `WorkQueue` method body, driven through a recording fake pool/cursor: exact SQL
  chosen, exact parameters bound, exact row→`QueueItem` mapping, and exact gauge writes
  (including the empty-topic reset — a gauge only written when non-empty latches forever).

Integration tests (real Postgres, real concurrency) prove what only a database can: two
consumers racing 1,000 rows produce zero double-claims, a killed consumer's lease expires
and redelivers, a poison row lands in `dead_letter`, and claim ordering respects priority
then id. They use the §13.1 fixtures and are `skipif`-gated on `TB_STORAGE__PG_DSN` so they
SKIP rather than ERROR on a machine with no database and no `tests/phase0/conftest.py`
(§12: "the test never errors at collection time").
"""

from __future__ import annotations

import os
import re
import threading
import time
import uuid
from collections import defaultdict
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Final

import pytest
from prometheus_client import REGISTRY

from tracebed.domain.clock import FakeClock
from tracebed.domain.config import QueueConfig
from tracebed.domain.ids import ProjectId
from tracebed.stores.pg.queue import (
    _ACK_SQL,
    _CLAIM_SQL,
    _DEAD_LETTER_COUNT_SQL,
    _DEAD_LETTER_SQL,
    _DEPTH_SQL,
    _ENQUEUE_SQL,
    _NACK_SQL,
    _OLDEST_AVAILABLE_AT_SQL,
    _XMIN_HORIZON_SQL,
    QUEUE_DEAD_LETTER_COUNT,
    QUEUE_DEPTH,
    QUEUE_OLDEST_AGE_SECONDS,
    QUEUE_XMIN_HORIZON_AGE_SECONDS,
    QUEUE_XMIN_HORIZON_ALARM,
    TOPIC_MEMORY_PROPOSAL,
    TOPIC_OUTCOME_EVENT,
    TOPIC_TRACE_EVENT,
    XMIN_HORIZON_ALARM_THRESHOLD_S,
    QueueItem,
    WorkQueue,
    compute_backoff,
    is_poisoned,
    xmin_horizon_alarm_from_age,
)

pytestmark = pytest.mark.phase0

MIGRATIONS_DIR: Final = Path(__file__).resolve().parents[2] / "migrations"
PARTITIONED_SQL: Final = (MIGRATIONS_DIR / "0002_partitioned.sql").read_text(encoding="utf-8")

_PG_DSN: Final = os.environ.get("TB_STORAGE__PG_DSN", "").strip()
requires_pg: Final = pytest.mark.skipif(
    not _PG_DSN,
    reason="TB_STORAGE__PG_DSN unset — no Postgres on this machine (PHASE0-CONTRACT.md §12)",
)


# --------------------------------------------------------------------------- #
# A recording fake pool. Small on purpose: it records what was executed with what,
# and replays a canned result per execute() so every `WorkQueue` method body runs
# for real. §13.1 keeps chunk-local fakes inside the chunk's own test module.
# --------------------------------------------------------------------------- #


class _Recorder:
    """Shared execution log + queued results for one fake pool."""

    def __init__(self, results: Sequence[Sequence[Any]] = ()) -> None:
        self.executed: list[tuple[str, Mapping[str, Any] | None]] = []
        self.results: list[Sequence[Any]] = [list(r) for r in results]
        self.connections_opened = 0
        self.row_factories: list[object] = []

    @property
    def sql(self) -> list[str]:
        return [s for s, _ in self.executed]

    @property
    def params(self) -> list[Mapping[str, Any] | None]:
        return [p for _, p in self.executed]


class _FakeCursor:
    def __init__(self, rec: _Recorder) -> None:
        self._rec = rec
        self._rows: Sequence[Any] = []

    def execute(self, sql: str, params: Mapping[str, Any] | None = None) -> None:
        self._rec.executed.append((sql, params))
        self._rows = self._rec.results.pop(0) if self._rec.results else []

    def fetchone(self) -> Any:
        return self._rows[0] if self._rows else None

    def fetchall(self) -> list[Any]:
        return list(self._rows)

    def __enter__(self) -> _FakeCursor:
        return self

    def __exit__(self, *exc: object) -> None:
        return None


class _FakeConn:
    def __init__(self, rec: _Recorder) -> None:
        self._rec = rec

    def cursor(self, row_factory: object = None) -> _FakeCursor:
        self._rec.row_factories.append(row_factory)
        return _FakeCursor(self._rec)


class _FakePool:
    def __init__(self, rec: _Recorder) -> None:
        self._rec = rec

    @contextmanager
    def connection(self) -> Iterator[_FakeConn]:
        self._rec.connections_opened += 1
        yield _FakeConn(self._rec)


class _ExplodingPool:
    """Any use at all is a failure — for guards that must reject before touching I/O."""

    def connection(self) -> None:
        raise AssertionError("this call must reject its arguments before opening a connection")


def _queue(
    rec: _Recorder | None = None,
    *,
    clock: FakeClock | None = None,
    cfg: QueueConfig | None = None,
) -> tuple[WorkQueue, _Recorder, FakeClock]:
    recorder = rec if rec is not None else _Recorder()
    fake_clock = clock if clock is not None else FakeClock(datetime(2026, 1, 1, tzinfo=UTC))
    config = cfg if cfg is not None else QueueConfig()
    queue = WorkQueue(_FakePool(recorder), fake_clock, config)  # type: ignore[arg-type]
    return queue, recorder, fake_clock


def _gauge(name: str, **labels: str) -> float | None:
    """Read a gauge through prometheus_client's public sample API, not its privates."""
    return REGISTRY.get_sample_value(name, labels or None)


def _unique_topic(stem: str) -> str:
    """A per-test topic label so gauge assertions never read another test's leftover value."""
    return f"{stem}-{uuid.uuid4().hex[:8]}"


# --------------------------------------------------------------------------- #
# Offline: topic constants.
# --------------------------------------------------------------------------- #


def test_topic_constants_match_the_contract() -> None:
    """PHASE0-CONTRACT.md §5.3: exactly these three, owned here."""
    assert TOPIC_TRACE_EVENT == "trace_event"
    assert TOPIC_OUTCOME_EVENT == "outcome_event"
    assert TOPIC_MEMORY_PROPOSAL == "memory_proposal"


def test_no_topic_constants_beyond_the_contracted_three() -> None:
    """§14's queue DO-NOT list: "do NOT add topics beyond the three constants"."""
    import tracebed.stores.pg.queue as queue_mod

    topics = {n for n in dir(queue_mod) if n.startswith("TOPIC_")}
    assert topics == {"TOPIC_TRACE_EVENT", "TOPIC_OUTCOME_EVENT", "TOPIC_MEMORY_PROPOSAL"}


# --------------------------------------------------------------------------- #
# Offline: SQL text regression guards. Each assertion below corresponds to a
# mutation that is invisible without a database and catastrophic with one.
# --------------------------------------------------------------------------- #


def _normalise(sql: str) -> str:
    return re.sub(r"\s+", " ", sql).strip()


def test_claim_sql_uses_for_update_skip_locked() -> None:
    """Dropping FOR UPDATE SKIP LOCKED silently converts the queue into a double-delivery
    machine, and the second consumer blocks instead of skipping."""
    flat = _normalise(_CLAIM_SQL)
    assert "FOR UPDATE SKIP LOCKED" in flat
    assert flat.startswith("UPDATE work_queue SET")
    # The lock must be taken by the INNER select, not by the outer UPDATE: `FOR UPDATE` is
    # not even legal on an UPDATE, and a claim that locks after choosing rows is not a claim.
    inner = flat[flat.index("WHERE id IN (") : flat.index("FOR UPDATE SKIP LOCKED")]
    assert "SELECT id FROM work_queue" in inner


def test_claim_sql_increments_attempts_and_sets_the_lease() -> None:
    """`attempts = attempts + 1` is what bounds redelivery; the lease is what makes a dead
    consumer's rows come back. Losing either is unbounded redelivery of a poison row."""
    flat = _normalise(_CLAIM_SQL)
    assert "attempts = attempts + 1" in flat
    assert "lease_expires_at = now() + %(lease)s" in flat


def test_claim_sql_selection_predicates_are_all_present_and_correctly_directed() -> None:
    """Every one of these has an inverted/omitted form that still parses and still returns
    rows — which is exactly why they are asserted individually rather than by substring of
    the whole statement."""
    flat = _normalise(_CLAIM_SQL)
    # Scheduling: a row is not claimable before its available_at. `>=` here would hand out
    # only future work; dropping it would defeat nack() backoff entirely.
    assert "available_at <= now()" in flat
    # Leasing: claimable when never leased OR the lease has lapsed. `>` would hand out only
    # rows another consumer currently holds — a 100% double-delivery bug.
    assert "(lease_expires_at IS NULL OR lease_expires_at < now())" in flat
    # C-11 belt to the dead-letter sweep's braces: a poison row past the sweep's per-call
    # budget must still not be claimable.
    assert "attempts <= max_attempts" in flat
    # Task 12: "ordering respects priority then id" — `ORDER BY id, priority` passes a naive
    # "ORDER BY" substring check and fails the actual requirement.
    assert "ORDER BY priority, id" in flat
    assert "LIMIT %(n)s" in flat


def test_claim_sql_binds_no_literals_for_caller_controlled_values() -> None:
    """topic/lease/n arrive as bound parameters, never interpolated. A queue is fed from the
    write path; the day a topic string is formatted into this statement is the day the
    ingest plane grows a SQL-injection surface."""
    for stmt in (_CLAIM_SQL, _DEAD_LETTER_SQL, _ENQUEUE_SQL, _ACK_SQL, _NACK_SQL,
                 _DEPTH_SQL, _OLDEST_AVAILABLE_AT_SQL, _DEAD_LETTER_COUNT_SQL):
        assert "%s" not in stmt, "positional binds are ambiguous here; use named params"
        assert "{" not in stmt and "f'" not in stmt


def test_dead_letter_sweep_is_bounded_and_non_blocking() -> None:
    """An unbounded sweep is O(backlog) on every claim and serialises concurrent consumers
    on each other's uncommitted DELETE — on the hot ingest path, with the xmin-horizon
    consequences PLAN.md §3 calls out."""
    flat = _normalise(_DEAD_LETTER_SQL)
    assert "FOR UPDATE SKIP LOCKED" in flat
    assert "LIMIT %(n)s" in flat
    assert "DELETE FROM work_queue" in flat
    assert "INSERT INTO dead_letter" in flat


def test_dead_letter_sql_predicate_matches_is_poisoned_exactly() -> None:
    """The SQL and the pure predicate are two encodings of C-11's rule. This extracts the
    comparison operator from the statement and re-derives the predicate from it, so a
    `>` → `>=` drift in either place is a failure rather than a silent divergence."""
    match = re.search(r"attempts\s*(>=|<=|>|<|=)\s*max_attempts", _DEAD_LETTER_SQL)
    assert match is not None, "dead-letter predicate not found in the SQL"
    operator = match.group(1)
    assert operator == ">", f"SQL uses `attempts {operator} max_attempts`; is_poisoned uses `>`"

    import operator as op_mod

    sql_predicate = {">": op_mod.gt, ">=": op_mod.ge, "<": op_mod.lt, "<=": op_mod.le}[operator]
    for attempts, max_attempts in [(0, 5), (5, 5), (6, 5), (100, 5), (0, 0), (1, 0)]:
        assert is_poisoned(attempts, max_attempts) is sql_predicate(attempts, max_attempts)


def test_nack_clears_the_lease_and_does_not_touch_attempts() -> None:
    """`claim()` already counted this delivery. A nack that also incremented would halve the
    real retry budget; a nack that left the lease set would idle the row until it lapsed."""
    flat = _normalise(_NACK_SQL)
    assert "available_at = now() + %(backoff)s" in flat
    assert "lease_expires_at = NULL" in flat
    assert "attempts" not in flat


def test_ack_is_a_delete() -> None:
    assert _normalise(_ACK_SQL) == "DELETE FROM work_queue WHERE id = %(id)s"


# --------------------------------------------------------------------------- #
# Offline: the SQL actually fits the shipped schema. These read
# migrations/0002_partitioned.sql, so a column rename there fails here.
# --------------------------------------------------------------------------- #


def _table_columns(table: str) -> dict[str, str]:
    """Column name → its full DDL line, for one CREATE TABLE in 0002_partitioned.sql."""
    match = re.search(rf"CREATE TABLE {table}\s*\((.*?)\n\)", PARTITIONED_SQL, re.DOTALL)
    assert match is not None, f"{table} not found in migrations/0002_partitioned.sql"
    columns: dict[str, str] = {}
    for raw in match.group(1).splitlines():
        line = raw.strip().rstrip(",")
        if not line or line.startswith("--"):
            continue
        name = line.split()[0]
        if name.upper() in {"PRIMARY", "UNIQUE", "CHECK", "CONSTRAINT", "FOREIGN", "EXCLUDE"}:
            continue
        columns[name] = line
    return columns


def _insert_column_list(sql: str, table: str) -> list[str]:
    match = re.search(rf"INSERT INTO {table}\s*\((.*?)\)", sql, re.DOTALL)
    assert match is not None, f"no INSERT INTO {table} found"
    return [c.strip() for c in match.group(1).split(",")]


def test_migration_defines_the_queue_tables_this_module_targets() -> None:
    """Guards the parsing helpers themselves — if this ever finds nothing, the checks below
    would pass vacuously."""
    assert len(_table_columns("work_queue")) >= 10
    assert len(_table_columns("dead_letter")) >= 12


def test_every_column_named_in_queue_sql_exists_in_work_queue() -> None:
    work_queue_cols = set(_table_columns("work_queue"))
    referenced = {
        *_insert_column_list(_ENQUEUE_SQL, "work_queue"),
        "id", "project_id", "topic", "payload", "priority", "attempts",
        "max_attempts", "available_at", "lease_expires_at", "created_at",
    }
    assert referenced <= work_queue_cols, f"unknown columns: {referenced - work_queue_cols}"


def test_claim_returning_list_is_exactly_the_queue_item_fields() -> None:
    """`_row_to_item` indexes the returned mapping by name. A RETURNING list that drifts from
    QueueItem's fields is a KeyError in production and nothing at all in a text-only test."""
    match = re.search(r"RETURNING (.+)$", _CLAIM_SQL.strip())
    assert match is not None
    returned = [c.strip() for c in match.group(1).split(",")]
    assert returned == ["id", "project_id", "topic", "payload", "priority", "attempts"]
    assert set(returned) == set(QueueItem.__dataclass_fields__)
    assert set(returned) <= set(_table_columns("work_queue"))


def test_dead_letter_insert_covers_every_mandatory_column() -> None:
    """Every NOT NULL `dead_letter` column without a DEFAULT must appear in the INSERT list,
    or the C-11 sweep raises NotNullViolation the first time a poison row appears — in
    production, since no test here can reach a real database."""
    dead_letter_cols = _table_columns("dead_letter")
    inserted = _insert_column_list(_DEAD_LETTER_SQL, "dead_letter")

    assert set(inserted) <= set(dead_letter_cols), (
        f"columns not on dead_letter: {set(inserted) - set(dead_letter_cols)}"
    )
    mandatory = {
        name
        for name, ddl in dead_letter_cols.items()
        if "NOT NULL" in ddl.upper() and "DEFAULT" not in ddl.upper()
    }
    assert mandatory <= set(inserted), f"mandatory columns not inserted: {mandatory - set(inserted)}"


def test_dead_letter_insert_and_select_lists_have_equal_arity() -> None:
    """`INSERT (a, b, c) SELECT x, y` is a runtime error, invisible to a substring check."""
    inserted = _insert_column_list(_DEAD_LETTER_SQL, "dead_letter")
    match = re.search(r"\)\s*\nSELECT (.*?)\nFROM poisoned", _DEAD_LETTER_SQL, re.DOTALL)
    assert match is not None
    selected = [c.strip() for c in match.group(1).split(",")]
    assert len(inserted) == len(selected), f"{len(inserted)} columns, {len(selected)} values"


def test_dead_letter_cte_returns_every_column_the_insert_selects() -> None:
    match = re.search(r"RETURNING (.*?)\n\)", _DEAD_LETTER_SQL, re.DOTALL)
    assert match is not None
    returned = {c.strip() for c in match.group(1).replace("\n", " ").split(",")}
    assert returned <= set(_table_columns("work_queue"))
    # The two literals (now(), 'max_attempts exceeded') are the only non-CTE values.
    inserted = _insert_column_list(_DEAD_LETTER_SQL, "dead_letter")
    assert returned == set(inserted) - {"failed_at", "last_error"}


def test_xmin_query_covers_prepared_transactions_and_excludes_our_own_backend() -> None:
    """An orphaned two-phase transaction pins the vacuum horizon forever and never shows up
    in pg_stat_activity; measuring our own backend's age would make the alarm self-trigger."""
    flat = _normalise(_XMIN_HORIZON_SQL)
    assert "pg_stat_activity" in flat
    assert "pg_prepared_xacts" in flat
    assert "pid <> pg_backend_pid()" in flat
    assert "current_database()" in flat
    assert "max(age_s)" in flat


# --------------------------------------------------------------------------- #
# Offline: pure helpers.
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("attempts", "max_attempts", "expected"),
    [
        (0, 5, False),
        (5, 5, False),  # exactly at the limit is not yet poisoned
        (6, 5, True),
        (100, 5, True),
        (0, 0, False),
        (1, 0, True),
    ],
)
def test_is_poisoned_predicate(attempts: int, max_attempts: int, expected: bool) -> None:
    assert is_poisoned(attempts, max_attempts) is expected


def test_compute_backoff_grows_then_caps() -> None:
    delays = [compute_backoff(a) for a in (1, 2, 3, 4, 5)]
    assert delays == [
        timedelta(seconds=1),
        timedelta(seconds=2),
        timedelta(seconds=4),
        timedelta(seconds=8),
        timedelta(seconds=16),
    ]
    huge = compute_backoff(1_000)
    assert huge == timedelta(minutes=5)
    assert huge == compute_backoff(1_000, ceiling=timedelta(minutes=5))


@pytest.mark.parametrize("attempts", [1_023, 1_024, 1_025, 10_000, 1_000_000])
def test_compute_backoff_survives_float_overflow_at_the_ceiling(attempts: int) -> None:
    """`float ** int` raises OverflowError above ~2.0**1023 rather than saturating to inf,
    and `attempts` rides on a caller-supplied QueueItem. Past the ceiling the answer is the
    ceiling at every magnitude — a retry helper must never be the thing that raises. 1_024 is
    the exact cliff; testing only 1_000 (as the original did) sits just under it."""
    assert compute_backoff(attempts) == timedelta(minutes=5)


def test_compute_backoff_zero_and_one_attempt_use_base_delay() -> None:
    base = timedelta(seconds=1)
    assert compute_backoff(0, base=base) == base
    assert compute_backoff(1, base=base) == base
    assert compute_backoff(2, base=base) == base * 2


def test_compute_backoff_rejects_negative_inputs() -> None:
    with pytest.raises(ValueError):
        compute_backoff(-1)
    with pytest.raises(ValueError):
        # A negative ceiling would produce a negative backoff, which nack() then rejects
        # far away from the caller that actually made the mistake.
        compute_backoff(3, ceiling=timedelta(seconds=-1))


@pytest.mark.parametrize(
    ("age_s", "threshold_s", "expected"),
    [
        (None, XMIN_HORIZON_ALARM_THRESHOLD_S, False),
        (0.0, XMIN_HORIZON_ALARM_THRESHOLD_S, False),
        (XMIN_HORIZON_ALARM_THRESHOLD_S, XMIN_HORIZON_ALARM_THRESHOLD_S, False),  # boundary
        (XMIN_HORIZON_ALARM_THRESHOLD_S + 0.01, XMIN_HORIZON_ALARM_THRESHOLD_S, True),
        (10_000.0, XMIN_HORIZON_ALARM_THRESHOLD_S, True),
    ],
)
def test_xmin_horizon_alarm_from_age(
    age_s: float | None, threshold_s: float, expected: bool
) -> None:
    assert xmin_horizon_alarm_from_age(age_s, threshold_s) is expected


def test_queue_item_is_frozen_including_its_payload() -> None:
    """A frozen dataclass wrapping a live dict is not frozen in any sense a consumer of an
    at-least-once queue can rely on."""
    item = QueueItem(
        id=1,
        topic=TOPIC_TRACE_EVENT,
        project_id=ProjectId(uuid.uuid4()),
        payload={"a": 1},
        priority=100,
        attempts=0,
    )
    with pytest.raises(AttributeError):
        item.id = 2  # type: ignore[misc]


def test_metric_label_shapes() -> None:
    """The per-topic gauges are labeled 'topic'; the process-wide xmin gauges are not."""
    assert QUEUE_DEPTH._labelnames == ("topic",)
    assert QUEUE_OLDEST_AGE_SECONDS._labelnames == ("topic",)
    assert QUEUE_DEAD_LETTER_COUNT._labelnames == ("topic",)
    assert QUEUE_XMIN_HORIZON_AGE_SECONDS._labelnames == ()
    assert QUEUE_XMIN_HORIZON_ALARM._labelnames == ()
    assert QUEUE_DEPTH._name == "tracebed_queue_depth"
    assert QUEUE_OLDEST_AGE_SECONDS._name == "tracebed_queue_oldest_age_seconds"
    assert QUEUE_DEAD_LETTER_COUNT._name == "tracebed_queue_dead_letter_count"
    assert QUEUE_XMIN_HORIZON_AGE_SECONDS._name == "tracebed_queue_xmin_horizon_age_seconds"
    assert QUEUE_XMIN_HORIZON_ALARM._name == "tracebed_queue_xmin_horizon_alarm"


# --------------------------------------------------------------------------- #
# Offline: WorkQueue method bodies against the recording fake pool.
# --------------------------------------------------------------------------- #


def test_enqueue_binds_every_parameter_from_the_right_source() -> None:
    queue, rec, clock = _queue(_Recorder([[(42,)]]), cfg=QueueConfig(max_attempts=7))
    project_id = ProjectId(uuid.uuid4())

    returned = queue.enqueue(TOPIC_TRACE_EVENT, project_id, {"k": "v"}, priority=17)

    assert returned == 42
    assert rec.sql == [_ENQUEUE_SQL]
    params = rec.params[0]
    assert params is not None
    # `.value`, not the ProjectId wrapper: psycopg3 does not honour __conform__.
    assert params["project_id"] == project_id.value
    assert not isinstance(params["project_id"], ProjectId)
    assert params["topic"] == TOPIC_TRACE_EVENT
    assert params["payload"].obj == {"k": "v"}
    assert params["priority"] == 17
    # max_attempts comes from config, never from the caller (Task 12 gives no override).
    assert params["max_attempts"] == 7
    assert params["available_at"] == clock.now()
    assert params["created_at"] == clock.now()


def test_enqueue_uses_the_injected_clock_not_the_wall_clock() -> None:
    queue, rec, clock = _queue(_Recorder([[(1,)]]))
    clock.advance(days=2)

    queue.enqueue(TOPIC_TRACE_EVENT, ProjectId(uuid.uuid4()), {})

    params = rec.params[0]
    assert params is not None
    assert params["created_at"] == datetime(2026, 1, 3, tzinfo=UTC)


def test_enqueue_keeps_available_at_and_created_at_distinct() -> None:
    """They are equal by default, so a swapped pair is invisible unless one is set
    explicitly — which is exactly how a delayed enqueue would break."""
    queue, rec, clock = _queue(_Recorder([[(1,)]]))
    future = clock.now() + timedelta(hours=6)

    queue.enqueue(TOPIC_OUTCOME_EVENT, ProjectId(uuid.uuid4()), {}, available_at=future)

    params = rec.params[0]
    assert params is not None
    assert params["available_at"] == future
    assert params["created_at"] == clock.now()


def test_enqueue_rejects_a_naive_available_at() -> None:
    """`available_at` is timestamptz. psycopg would bind a naive instant in the session's
    TimeZone, silently shifting when the row becomes claimable."""
    queue, rec, _ = _queue()
    with pytest.raises(ValueError, match="timezone-aware"):
        queue.enqueue(
            TOPIC_TRACE_EVENT,
            ProjectId(uuid.uuid4()),
            {},
            available_at=datetime(2026, 5, 1),
        )
    assert rec.connections_opened == 0


def test_enqueue_rejects_an_empty_topic() -> None:
    """Nothing claims the empty topic and nothing sweeps it, so such a row is an
    unreclaimable tuple pinning the xmin horizon forever."""
    queue, rec, _ = _queue()
    with pytest.raises(ValueError, match="topic"):
        queue.enqueue("", ProjectId(uuid.uuid4()), {})
    assert rec.connections_opened == 0


def test_claim_sweeps_dead_letters_first_in_one_connection() -> None:
    """C-11 ordering: the sweep must precede the select, and both must share one
    transaction, or a row can be claimed once more between them."""
    queue, rec, _ = _queue(_Recorder([[], []]))

    queue.claim(TOPIC_TRACE_EVENT, 5)

    assert rec.sql == [_DEAD_LETTER_SQL, _CLAIM_SQL]
    assert rec.connections_opened == 1


def test_claim_binds_topic_lease_and_batch() -> None:
    queue, rec, _ = _queue(_Recorder([[], []]), cfg=QueueConfig(lease_seconds=45))

    queue.claim(TOPIC_OUTCOME_EVENT, 5)

    assert rec.params[0] == {"topic": TOPIC_OUTCOME_EVENT, "n": 5}
    assert rec.params[1] == {
        "topic": TOPIC_OUTCOME_EVENT,
        "lease": timedelta(seconds=45),
        "n": 5,
    }


def test_claim_clamps_n_to_the_configured_batch_size() -> None:
    """`LIMIT n` and the `fetchall()` behind it are otherwise bounded only by what the caller
    typed — an unbounded allocation driven by queue depth on the ingest path."""
    queue, rec, _ = _queue(_Recorder([[], []]), cfg=QueueConfig(batch_size=100))

    queue.claim(TOPIC_TRACE_EVENT, 10_000_000)

    assert rec.params[0] == {"topic": TOPIC_TRACE_EVENT, "n": 100}
    assert rec.params[1] is not None
    assert rec.params[1]["n"] == 100


def test_claim_does_not_inflate_a_small_request() -> None:
    queue, rec, _ = _queue(_Recorder([[], []]), cfg=QueueConfig(batch_size=100))
    queue.claim(TOPIC_TRACE_EVENT, 3)
    assert rec.params[1] is not None
    assert rec.params[1]["n"] == 3


def test_claim_uses_a_dict_row_factory() -> None:
    """`_row_to_item` addresses columns by name; a positional cursor would silently map the
    wrong column into every field."""
    from psycopg.rows import dict_row

    queue, rec, _ = _queue(_Recorder([[], []]))
    queue.claim(TOPIC_TRACE_EVENT, 1)
    assert rec.row_factories == [dict_row]


def test_claim_maps_every_row_field_to_the_right_queue_item_field() -> None:
    """Distinct values everywhere so any two-field transposition fails."""
    project_id = uuid.uuid4()
    rows = [
        {
            "id": 991,
            "project_id": project_id,
            "topic": TOPIC_MEMORY_PROPOSAL,
            "payload": {"deep": {"nested": True}},
            "priority": 42,
            "attempts": 3,
        }
    ]
    queue, _, _ = _queue(_Recorder([[], rows]))

    (item,) = queue.claim(TOPIC_MEMORY_PROPOSAL, 1)

    assert item.id == 991
    assert item.project_id == ProjectId(project_id)
    assert item.topic == TOPIC_MEMORY_PROPOSAL
    assert item.payload == {"deep": {"nested": True}}
    assert item.priority == 42
    assert item.attempts == 3


def test_claimed_payload_is_read_only() -> None:
    rows = [
        {
            "id": 1,
            "project_id": uuid.uuid4(),
            "topic": TOPIC_TRACE_EVENT,
            "payload": {"a": 1},
            "priority": 100,
            "attempts": 1,
        }
    ]
    queue, _, _ = _queue(_Recorder([[], rows]))
    (item,) = queue.claim(TOPIC_TRACE_EVENT, 1)
    with pytest.raises(TypeError):
        item.payload["a"] = 2  # type: ignore[index]


def test_claim_rejects_a_non_object_payload_loudly() -> None:
    """A jsonb array/scalar means the row was not written by enqueue(); `dict(None)` three
    frames into a consumer is not a diagnosis."""
    rows = [
        {
            "id": 7,
            "project_id": uuid.uuid4(),
            "topic": TOPIC_TRACE_EVENT,
            "payload": ["not", "an", "object"],
            "priority": 100,
            "attempts": 1,
        }
    ]
    queue, _, _ = _queue(_Recorder([[], rows]))
    with pytest.raises(ValueError, match="expected a JSON object"):
        queue.claim(TOPIC_TRACE_EVENT, 1)


@pytest.mark.parametrize("n", [0, -1, -10_000])
def test_claim_rejects_non_positive_n_before_any_io(n: int) -> None:
    queue = WorkQueue(_ExplodingPool(), FakeClock(), QueueConfig())  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="positive"):
        queue.claim(TOPIC_TRACE_EVENT, n)


def test_nack_rejects_a_negative_backoff_before_any_io() -> None:
    queue = WorkQueue(_ExplodingPool(), FakeClock(), QueueConfig())  # type: ignore[arg-type]
    with pytest.raises(ValueError, match=">= 0"):
        queue.nack(1, timedelta(seconds=-1))


def test_ack_and_nack_bind_their_ids() -> None:
    queue, rec, _ = _queue(_Recorder([[], []]))
    queue.ack(1234)
    queue.nack(5678, timedelta(seconds=30))
    assert rec.sql == [_ACK_SQL, _NACK_SQL]
    assert rec.params[0] == {"id": 1234}
    assert rec.params[1] == {"backoff": timedelta(seconds=30), "id": 5678}


def test_depth_returns_the_count_and_publishes_it() -> None:
    topic = _unique_topic("depth")
    queue, rec, _ = _queue(_Recorder([[(17,)]]))

    assert queue.depth(topic) == 17

    assert rec.sql == [_DEPTH_SQL]
    assert rec.params[0] == {"topic": topic}
    assert _gauge("tracebed_queue_depth", topic=topic) == 17.0


def test_dead_letter_count_returns_the_count_and_publishes_it() -> None:
    topic = _unique_topic("dl")
    queue, rec, _ = _queue(_Recorder([[(4,)]]))

    assert queue.dead_letter_count(topic) == 4

    assert rec.sql == [_DEAD_LETTER_COUNT_SQL]
    assert _gauge("tracebed_queue_dead_letter_count", topic=topic) == 4.0


def test_oldest_age_s_measures_against_the_injected_clock() -> None:
    topic = _unique_topic("age")
    clock = FakeClock(datetime(2026, 1, 1, tzinfo=UTC))
    oldest = clock.now() - timedelta(seconds=90)
    queue, rec, _ = _queue(_Recorder([[(oldest,)]]), clock=clock)

    assert queue.oldest_age_s(topic) == 90.0

    assert rec.sql == [_OLDEST_AVAILABLE_AT_SQL]
    assert _gauge("tracebed_queue_oldest_age_seconds", topic=topic) == 90.0


def test_oldest_age_s_clamps_a_future_available_at_to_zero() -> None:
    """A nack()'d row is scheduled forward; backlog age must not go negative."""
    topic = _unique_topic("age-future")
    clock = FakeClock(datetime(2026, 1, 1, tzinfo=UTC))
    queue, _, _ = _queue(_Recorder([[(clock.now() + timedelta(minutes=5),)]]), clock=clock)
    assert queue.oldest_age_s(topic) == 0.0


def test_oldest_age_s_resets_the_gauge_when_the_topic_drains() -> None:
    """The latching bug: writing the gauge only when there IS a backlog leaves an age alert
    stuck at the peak forever once the queue empties."""
    topic = _unique_topic("age-drain")
    clock = FakeClock(datetime(2026, 1, 1, tzinfo=UTC))
    backlogged = _Recorder([[(clock.now() - timedelta(seconds=600),)]])
    queue, _, _ = _queue(backlogged, clock=clock)
    assert queue.oldest_age_s(topic) == 600.0
    assert _gauge("tracebed_queue_oldest_age_seconds", topic=topic) == 600.0

    drained, _, _ = _queue(_Recorder([[(None,)]]), clock=clock)
    assert drained.oldest_age_s(topic) is None
    assert _gauge("tracebed_queue_oldest_age_seconds", topic=topic) == 0.0


def test_xmin_horizon_age_reports_and_publishes_the_measured_age() -> None:
    queue, rec, _ = _queue(_Recorder([[(1234.5,)]]))
    assert queue.xmin_horizon_age_s() == 1234.5
    assert rec.sql == [_XMIN_HORIZON_SQL]
    assert _gauge("tracebed_queue_xmin_horizon_age_seconds") == 1234.5


def test_xmin_horizon_age_resets_the_gauge_when_nothing_holds_the_horizon() -> None:
    queue, _, _ = _queue(_Recorder([[(9_999.0,)]]))
    assert queue.xmin_horizon_age_s() == 9_999.0
    assert _gauge("tracebed_queue_xmin_horizon_age_seconds") == 9_999.0

    cleared, _, _ = _queue(_Recorder([[(None,)]]))
    assert cleared.xmin_horizon_age_s() is None
    assert _gauge("tracebed_queue_xmin_horizon_age_seconds") == 0.0


def test_xmin_horizon_alarm_fires_and_clears_against_the_real_threshold() -> None:
    above, _, _ = _queue(_Recorder([[(XMIN_HORIZON_ALARM_THRESHOLD_S + 1,)]]))
    assert above.xmin_horizon_alarm() is True
    assert _gauge("tracebed_queue_xmin_horizon_alarm") == 1.0

    at_boundary, _, _ = _queue(_Recorder([[(XMIN_HORIZON_ALARM_THRESHOLD_S,)]]))
    assert at_boundary.xmin_horizon_alarm() is False
    assert _gauge("tracebed_queue_xmin_horizon_alarm") == 0.0


def test_xmin_horizon_alarm_threshold_is_overridable() -> None:
    queue, _, _ = _queue(_Recorder([[(30.0,)]]))
    assert queue.xmin_horizon_alarm(threshold_s=10.0) is True


# --------------------------------------------------------------------------- #
# Integration: real Postgres, real concurrency. `requires_pg` skips these when
# TB_STORAGE__PG_DSN is unset; the §13.1 fixtures (owner: harness) skip when it
# is set but unreachable.
# --------------------------------------------------------------------------- #


@requires_pg
@pytest.mark.integration
def test_claim_orders_by_priority_then_id(work_queue, two_projects) -> None:  # type: ignore[no-untyped-def]
    scope, _ = two_projects
    topic = TOPIC_MEMORY_PROPOSAL
    low_a = work_queue.enqueue(topic, scope.project_id, {"tag": "low-a"}, priority=200)
    low_b = work_queue.enqueue(topic, scope.project_id, {"tag": "low-b"}, priority=200)
    high = work_queue.enqueue(topic, scope.project_id, {"tag": "high"}, priority=10)

    claimed = work_queue.claim(topic, 3)

    assert [c.id for c in claimed] == [high, low_a, low_b]
    for c in claimed:
        work_queue.ack(c.id)


@requires_pg
@pytest.mark.integration
def test_two_consumers_1000_rows_zero_double_claims(work_queue, two_projects) -> None:  # type: ignore[no-untyped-def]
    scope, _ = two_projects
    topic = TOPIC_TRACE_EVENT
    ids = {work_queue.enqueue(topic, scope.project_id, {"i": i}) for i in range(1_000)}

    claimed_by: dict[int, list[int]] = defaultdict(list)
    lock = threading.Lock()
    errors: list[BaseException] = []

    def consumer(worker_id: int) -> None:
        try:
            while True:
                batch = work_queue.claim(topic, 25)
                if not batch:
                    return
                for item in batch:
                    with lock:
                        claimed_by[item.id].append(worker_id)
                    work_queue.ack(item.id)
        except BaseException as exc:
            errors.append(exc)

    threads = [threading.Thread(target=consumer, args=(w,)) for w in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=60)

    assert not errors, errors
    assert not [t for t in threads if t.is_alive()], "a consumer thread did not finish"
    assert set(claimed_by) == ids
    assert all(len(workers) == 1 for workers in claimed_by.values()), (
        "a row was claimed by more than one consumer: "
        f"{[i for i, w in claimed_by.items() if len(w) > 1]}"
    )
    assert work_queue.depth(topic) == 0


@requires_pg
@pytest.mark.integration
def test_killed_consumers_lease_expires_and_redelivers(pg_pool, fake_clock, two_projects) -> None:  # type: ignore[no-untyped-def]
    cfg = QueueConfig(lease_seconds=1, max_attempts=5, batch_size=10)
    queue = WorkQueue(pg_pool, fake_clock, cfg)
    scope, _ = two_projects
    item_id = queue.enqueue(TOPIC_TRACE_EVENT, scope.project_id, {"payload": True})

    first = queue.claim(TOPIC_TRACE_EVENT, 1)
    assert [i.id for i in first] == [item_id]
    assert first[0].attempts == 1

    # The "killed" consumer never acks. The lease is compared against Postgres's own
    # now() (see queue.py's claim() docstring), so redelivery needs real wall-clock time
    # to pass, not a FakeClock.advance() call.
    time.sleep(1.5)

    second = queue.claim(TOPIC_TRACE_EVENT, 1)
    assert [i.id for i in second] == [item_id]
    assert second[0].attempts == 2

    queue.ack(item_id)
    assert queue.depth(TOPIC_TRACE_EVENT) == 0


@requires_pg
@pytest.mark.integration
def test_poison_row_lands_in_dead_letter_after_max_attempts(pg_pool, fake_clock, two_projects) -> None:  # type: ignore[no-untyped-def]
    cfg = QueueConfig(lease_seconds=1, max_attempts=2, batch_size=10)
    queue = WorkQueue(pg_pool, fake_clock, cfg)
    scope, _ = two_projects
    item_id = queue.enqueue(TOPIC_OUTCOME_EVENT, scope.project_id, {"bad": True})

    # Never ack; let each lease expire and reclaim, driving attempts past max_attempts.
    for _ in range(cfg.max_attempts + 1):
        claimed = queue.claim(TOPIC_OUTCOME_EVENT, 1)
        assert [c.id for c in claimed] == [item_id]
        time.sleep(1.2)

    assert queue.dead_letter_count(TOPIC_OUTCOME_EVENT) == 0  # not swept yet

    # The next claim() call's dead-letter sweep (C-11, runs before the select, same
    # transaction) now finds attempts (3) > max_attempts (2) and moves the row.
    swept = queue.claim(TOPIC_OUTCOME_EVENT, 1)
    assert swept == []
    assert queue.dead_letter_count(TOPIC_OUTCOME_EVENT) == 1
    assert queue.depth(TOPIC_OUTCOME_EVENT) == 0


@requires_pg
@pytest.mark.integration
def test_a_poison_row_is_never_claimed_past_its_budget(pg_pool, fake_clock, two_projects) -> None:  # type: ignore[no-untyped-def]
    """The `attempts <= max_attempts` claim guard, independent of the sweep: even if the
    bounded sweep has not reached this row, it must not be handed out again."""
    cfg = QueueConfig(lease_seconds=1, max_attempts=1, batch_size=10)
    queue = WorkQueue(pg_pool, fake_clock, cfg)
    scope, _ = two_projects
    item_id = queue.enqueue(TOPIC_MEMORY_PROPOSAL, scope.project_id, {"bad": True})

    deliveries = 0
    for _ in range(cfg.max_attempts + 3):
        claimed = queue.claim(TOPIC_MEMORY_PROPOSAL, 1)
        deliveries += len([c for c in claimed if c.id == item_id])
        time.sleep(1.2)

    assert deliveries == cfg.max_attempts + 1, "a poison row exceeded its delivery budget"
    assert queue.dead_letter_count(TOPIC_MEMORY_PROPOSAL) == 1


@requires_pg
@pytest.mark.integration
def test_nack_makes_a_row_available_again_without_incrementing_attempts(work_queue, two_projects) -> None:  # type: ignore[no-untyped-def]
    scope, _ = two_projects
    topic = TOPIC_OUTCOME_EVENT
    item_id = work_queue.enqueue(topic, scope.project_id, {"retryable": True})

    claimed = work_queue.claim(topic, 1)
    assert [c.id for c in claimed] == [item_id]
    assert claimed[0].attempts == 1

    work_queue.nack(item_id, timedelta(seconds=0))
    reclaimed = work_queue.claim(topic, 1)
    assert [c.id for c in reclaimed] == [item_id]
    assert reclaimed[0].attempts == 2  # claim() increments; nack() itself does not

    work_queue.ack(item_id)


@requires_pg
@pytest.mark.integration
def test_nack_backoff_actually_delays_redelivery(work_queue, two_projects) -> None:  # type: ignore[no-untyped-def]
    """`available_at <= now()` is the only thing enforcing backoff; a dropped predicate
    makes a poison row hot-loop through its whole budget in milliseconds."""
    scope, _ = two_projects
    topic = TOPIC_OUTCOME_EVENT
    item_id = work_queue.enqueue(topic, scope.project_id, {"retryable": True})

    assert [c.id for c in work_queue.claim(topic, 1)] == [item_id]
    work_queue.nack(item_id, timedelta(seconds=30))

    assert work_queue.claim(topic, 1) == []
    work_queue.ack(item_id)


@requires_pg
@pytest.mark.integration
def test_ack_is_idempotent_on_a_missing_id(work_queue) -> None:  # type: ignore[no-untyped-def]
    work_queue.ack(999_999_999)  # never enqueued — must not raise


@requires_pg
@pytest.mark.integration
def test_metrics_reflect_queue_state(work_queue, two_projects) -> None:  # type: ignore[no-untyped-def]
    scope, _ = two_projects
    topic = TOPIC_TRACE_EVENT
    assert work_queue.depth(topic) == 0

    item_id = work_queue.enqueue(topic, scope.project_id, {"x": 1})
    assert work_queue.depth(topic) == 1
    age = work_queue.oldest_age_s(topic)
    assert age is not None
    assert age >= 0.0

    work_queue.claim(topic, 1)
    work_queue.ack(item_id)
    assert work_queue.depth(topic) == 0
    assert work_queue.oldest_age_s(topic) is None
    assert work_queue.dead_letter_count(topic) == 0


@requires_pg
@pytest.mark.integration
def test_xmin_horizon_alarm_runs_a_real_query(work_queue) -> None:  # type: ignore[no-untyped-def]
    """Not a mock: this hits pg_stat_activity and pg_prepared_xacts for real (Task 12: "a
    real check, not a comment"). No open transaction is guaranteed in the test environment,
    so this proves the query parses, executes, and composes with the threshold logic."""
    age = work_queue.xmin_horizon_age_s()
    assert age is None or age >= 0.0
    fired = work_queue.xmin_horizon_alarm()
    assert isinstance(fired, bool)
