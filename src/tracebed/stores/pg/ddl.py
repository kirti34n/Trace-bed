"""Per-partition DDL templates (PHASE-0 Task 6; contract §5.5, §1).

The single source of truth for what must exist on every per-project
partition of every LIST-partitioned table: the partition itself, its
row-level-security setup, its grants, and its indexes (HNSW halfvec_cosine_ops
ANN on `memory_item.embedding`, pg_textsearch BM25 on `memory_item.content`,
btree on hot lookup keys). `stores.pg.partitions.create_project_partitions`
and `ensure_schema_current` both call these functions instead of embedding
their own SQL, so a partition created after a migration landed cannot drift
from one created before it — the failure mode this module exists to close.

Every table name here must appear, PARTITION BY LIST (project_id), in
migrations/0002_partitioned.sql; `tests/phase0/test_partitions.py`'s
`test_ddl_partitioned_tables_match_migration` proves the two never diverge.

Identifier construction: every name this module emits is derived from
`PARTITIONED_TABLES` (a closed, internal vocabulary) plus a `ProjectId`,
which is a validated `uuid.UUID` — no caller-supplied text ever reaches the
SQL text. `_checked_ident` additionally refuses to emit an identifier longer
than PostgreSQL's 63-byte `NAMEDATALEN - 1`: over that limit the server
silently truncates, and a silently-truncated name is a name the catalog
cannot be queried by (`to_regclass(partition_name(...))` would return NULL
for an object that exists).
"""

from __future__ import annotations

import re
from uuid import UUID

from tracebed.domain.ids import ProjectId

__all__ = [
    "PARTITIONED_TABLES",
    "create_partition_sql",
    "partition_grant_statements",
    "partition_index_statements",
    "partition_name",
    "partition_policy_name",
    "partition_rls_statements",
]

# The 13 LIST-partitioned learning-plane tables (PLAN.md §5), one place.
# Order matters only for readability — none of these tables has a foreign
# key to another partitioned table, so partition creation order is free.
PARTITIONED_TABLES: tuple[str, ...] = (
    "memory_item",
    "memory_link",
    "derived_state",
    "trace_index",
    "trace_subject",
    "subject_key",
    "outcome_event",
    "injection_log",
    "retrieval_event",
    "blackboard_entry",
    "invalidation_event",
    "spend_ledger",
    "review_queue",
)

# Grantee for every per-partition GRANT below. Must match the role created in
# migrations/0003_rls.sql exactly — duplicated here (not imported from that
# .sql file, there is nothing to import from) rather than left as a bare
# string at each call site, so a rename is a one-line change.
_APP_ROLE = "tracebed_app"

# PostgreSQL's NAMEDATALEN - 1. Over this the server truncates with a NOTICE.
_IDENT_MAX = 63

# The RLS predicate, character-for-character identical to the one
# migrations/0003_rls.sql puts on the parent tables. `NULLIF(..., '')` is
# load-bearing, not defensive noise: see that migration's header comment.
_ISOLATION_PREDICATE = (
    "project_id = NULLIF(current_setting('tracebed.project_id', true), '')::uuid"
)

_UUID_TEXT = re.compile(r"\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")


def _require_partitioned(table: str) -> None:
    if table not in PARTITIONED_TABLES:
        raise ValueError(f"{table!r} is not a LIST-partitioned table")


def _checked_ident(name: str) -> str:
    """Refuse to emit an identifier PostgreSQL would silently truncate."""
    if len(name.encode("utf-8")) > _IDENT_MAX:
        raise ValueError(
            f"generated identifier {name!r} exceeds PostgreSQL's {_IDENT_MAX}-byte limit "
            "and would be silently truncated"
        )
    return name


def _bound_literal(project_id: ProjectId) -> str:
    """The partition bound as a quoted SQL literal.

    PostgreSQL's grammar for `FOR VALUES IN (...)` accepts only literal
    constants (`partbound_datum` is `Sconst | NumericOnly | TRUE | FALSE |
    NULL`) — not a bind parameter, and not even a cast. A DDL statement
    carrying `%(project_id)s` therefore reaches the server as `$1` under
    psycopg's server-side binding and fails with a syntax error, which is why
    the value is rendered here instead of bound at execute time.

    That is safe only because the value is a `uuid.UUID`, never text: it is
    re-validated against the canonical UUID spelling below so a future change
    to `ProjectId` cannot turn this into an injection point.
    """
    value = project_id.value
    if not isinstance(value, UUID):  # pragma: no cover - ProjectId enforces this
        raise TypeError(f"ProjectId must wrap a UUID, got {type(value).__name__}")
    text = str(value)
    if not _UUID_TEXT.match(text):  # pragma: no cover - UUID.__str__ is canonical
        raise ValueError(f"non-canonical UUID text: {text!r}")
    return f"'{text}'"


def partition_name(table: str, project_id: ProjectId) -> str:
    """Deterministic per-project partition name.

    `f"{table}_p_{project_id.value.hex}"` — fixed so tests (and admin
    tooling) can compute a partition's name without querying the catalog
    (contract §5.5). Rejects tables outside `PARTITIONED_TABLES`: this name
    is interpolated into `DROP TABLE` by `partitions.drop_project`, so the
    closed vocabulary is what keeps that interpolation safe.
    """
    _require_partitioned(table)
    return _checked_ident(f"{table}_p_{project_id.value.hex}")


def partition_policy_name(table: str, project_id: ProjectId) -> str:
    """Name of the isolation policy on one partition (invariant 4)."""
    return _checked_ident(f"{partition_name(table, project_id)}_isolation")


def create_partition_sql(table: str, project_id: ProjectId) -> str:
    """`CREATE TABLE ... PARTITION OF ... FOR VALUES IN (...)` for `table`.

    Idempotent (`IF NOT EXISTS`) — safe to re-issue from
    `ensure_schema_current`. Takes no query parameters by design; see
    `_bound_literal` for why the partition bound cannot be bound.
    """
    name = partition_name(table, project_id)
    return (
        f"CREATE TABLE IF NOT EXISTS {name} "
        f"PARTITION OF {table} FOR VALUES IN ({_bound_literal(project_id)})"
    )


def partition_rls_statements(table: str, project_id: ProjectId) -> list[str]:
    """ENABLE + FORCE RLS and the isolation policy on one partition.

    migrations/0003_rls.sql sets this up on the *parent* partitioned table.
    Whether that setting is inherited by a partition created later (via this
    module, at admin-provisioning time, long after the migration ran) is a
    detail of Postgres's declarative-partitioning implementation this module
    does not trust blindly — invariant 4 is too load-bearing to depend on
    inheritance semantics working a particular way across versions. Setting
    it explicitly, identically, on every partition makes correctness
    independent of that question. Idempotent: `DROP POLICY IF EXISTS` then
    recreate, so a second call (from `ensure_schema_current`) is a no-op.
    """
    name = partition_name(table, project_id)
    policy = partition_policy_name(table, project_id)
    return [
        f"ALTER TABLE {name} ENABLE ROW LEVEL SECURITY",
        f"ALTER TABLE {name} FORCE ROW LEVEL SECURITY",
        f"DROP POLICY IF EXISTS {policy} ON {name}",
        f"CREATE POLICY {policy} ON {name} USING ({_ISOLATION_PREDICATE})",
    ]


def partition_grant_statements(table: str, project_id: ProjectId) -> list[str]:
    """DML grants for the app role on one partition.

    `migrations/0003_rls.sql`'s `ALTER DEFAULT PRIVILEGES` only covers
    objects created by the same role that ran the migration; partitions are
    created later by admin tooling that may run under a different role
    (contract §5.5 — these take a raw `conn` "run under migration/admin
    privileges"). Granting explicitly here removes that assumption. No
    TRUNCATE and no DDL: TRUNCATE has no row-level filter for RLS to apply.
    """
    name = partition_name(table, project_id)
    return [f"GRANT SELECT, INSERT, UPDATE, DELETE ON {name} TO {_APP_ROLE}"]


# (index-name suffix, index definition after `ON <partition>`) per table.
# Suffixes are kept short deliberately: `partition_name` already spends
# 32 characters on the project uuid, and `_checked_ident` refuses anything
# PostgreSQL would truncate.
_INDEX_SPECS: dict[str, tuple[tuple[str, str], ...]] = {
    "memory_item": (
        ("hnsw", "USING hnsw (embedding halfvec_cosine_ops)"),
        # pg_textsearch indexes the source text column directly (it maintains
        # its own on-disk representation internally); `lexemes` stays a plain
        # tsvector column for the zero-extension ts_rank fallback
        # (DECISIONS D-003), not what this index is built over.
        ("bm25", "USING bm25 (content) WITH (text_config='english')"),
        ("status", "(status)"),
        ("subject", "(subject_tag)"),
        ("verdict", "(scan_verdict_id)"),
    ),
    "trace_index": (
        ("submitter", "(submitter_principal)"),
        ("outstatus", "(outcome_status)"),
    ),
    "outcome_event": (("run", "(run_id)"),),
    "injection_log": (("mem", "(memory_id)"),),
    "review_queue": (("mem", "(memory_id)"),),
    "trace_subject": (("subject", "(subject_tag)"),),
}


def partition_index_statements(table: str, project_id: ProjectId) -> list[str]:
    """Per-partition indexes for `table`'s partition of `project_id`.

    `memory_item` gets the HNSW `halfvec_cosine_ops` ANN index (pgvector) and
    the pg_textsearch BM25 index (both PLAN.md §5's "retrieval quality" half
    of invariant 4) plus btree on its hot filter columns; every other
    partitioned table gets a btree on the column its Repo builders filter or
    join on most (contract §5.1's builder list). Idempotent throughout
    (`IF NOT EXISTS`) so `ensure_schema_current` can re-issue these against
    every existing partition without erroring on ones that already have
    them.
    """
    name = partition_name(table, project_id)
    return [
        f"CREATE INDEX IF NOT EXISTS {_checked_ident(f'{name}_{suffix}')} ON {name} {definition}"
        for suffix, definition in _INDEX_SPECS.get(table, ())
    ]
