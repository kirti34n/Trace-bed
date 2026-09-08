"""Per-partition DDL templates (PHASE-0 Task 6; contract §5.5, §1).

The single source of truth for what must exist on every per-project
partition of every LIST-partitioned table: the partition itself, its
row-level-security setup, its grants, and its indexes (HNSW halfvec_cosine_ops
ANN on `memory_item.embedding`, vchord_bm25 BM25 on `memory_item.content_bm25`,
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
from typing import Final
from uuid import UUID

from tracebed.domain.ids import ProjectId

__all__ = [
    "LEXICAL_TOKENIZER",
    "MEMORY_ITEM_BM25_INDEX_SUFFIX",
    "PARTITIONED_TABLES",
    "create_partition_sql",
    "partition_grant_statements",
    "partition_index_expectations",
    "partition_index_name",
    "partition_index_statements",
    "partition_name",
    "partition_policy_name",
    "partition_rls_statements",
]

# The 22 project-keyed LIST parents, one place.  ``run_owner`` is an
# authority registry rather than learning-plane content, but it shares the
# same project lifecycle: every new active project needs its child and project
# erasure must detach/drop that child with the rest of its state.
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
    # 14th, added with migrations/0004_lifecycle.sql. `stores.pg.lifecycle
    # .LifecycleWriter` writes one row here per persisted `apply()` result, in the
    # same transaction as the `memory_item` status UPDATE; without a per-project
    # partition every one of those INSERTs fails with "no partition of relation
    # found for row" and takes the status write down with it.
    "memory_status_log",
    # 15th, added with migrations/0006_q_update_ledger.sql. `stores.pg.scoring
    # .ScorerRepo` appends one row here per fresh Q update (the replay-idempotency
    # + per-day-cap + distinct-principals ledger invariant 8 needs); without a
    # per-project partition every ledger INSERT fails with "no partition of relation
    # found for row" and takes the scorer's status write down with it.
    "memory_q_update",
    # 16th, added with migrations/0008_trace_learning_job.sql. This durable
    # project-scoped lease substrate must be dropped with the project's other
    # learning-plane state during partition lifecycle operations.
    "trace_learning_job",
    # 17th, added with 0010_authority_foundation.sql.  Its child grants are
    # deliberately narrower and include the new NOLOGIN group roles; no other
    # historical partition gets group privileges until the 0011 cutover.
    "run_owner",
    # E2 fencing foundations share project lifecycle, but runtime roles
    # receive no direct DML on their ledgers/fences.
    "subject_fence",
    "run_fence",
    "erase_run_set",
    "erase_mem_set",
    # Normalized, monotone run-to-memory provenance.  It has no direct
    # runtime DML grant: E2's profiled bind routine is the only writer.
    "run_memory_binding",
)

# Grantee for every per-partition GRANT below. Must match the role created in
# migrations/0003_rls.sql exactly — duplicated here (not imported from that
# .sql file, there is nothing to import from) rather than left as a bare
# string at each call site, so a rename is a one-line change.
_APP_ROLE = "tracebed_app"
_API_GROUP = "tracebed_api_group"
_WORKER_GROUP = "tracebed_worker_group"
_ERASURE_GROUP = "tracebed_erasure_group"
_API_ROLE = "tracebed_api"
_WORKER_ROLE = "tracebed_worker"

_CUTOVER_CHILD_GRANTS: dict[str, tuple[str | None, str | None]] = {
    "memory_item": ("SELECT", "SELECT, INSERT, UPDATE"),
    "memory_link": ("SELECT", "SELECT"),
    "derived_state": ("SELECT", "SELECT, INSERT, DELETE"),
    "trace_index": ("SELECT", "SELECT, INSERT, UPDATE"),
    "trace_subject": (None, "SELECT, INSERT"),
    "subject_key": (None, "SELECT, INSERT"),
    "outcome_event": ("SELECT", "SELECT, INSERT"),
    "injection_log": ("SELECT, INSERT", "SELECT"),
    "retrieval_event": ("SELECT, INSERT", "SELECT"),
    "blackboard_entry": (None, None),
    "invalidation_event": ("SELECT, INSERT", "SELECT"),
    "spend_ledger": ("SELECT", "SELECT, INSERT, UPDATE"),
    "review_queue": ("SELECT", "SELECT, INSERT"),
    "memory_status_log": (None, "SELECT, INSERT"),
    "memory_q_update": (None, "SELECT, INSERT"),
    "trace_learning_job": (None, "SELECT, INSERT, UPDATE"),
    "run_owner": ("SELECT, INSERT", "SELECT"),
    "subject_fence": (None, None),
    "run_fence": (None, None),
    "erase_run_set": (None, None),
    "erase_mem_set": (None, None),
    "run_memory_binding": (None, None),
}

# PostgreSQL's NAMEDATALEN - 1. Over this the server truncates with a NOTICE.
_IDENT_MAX = 63

# The longest name this module builds is the isolation POLICY name:
# `<table>_p_<32 hex>_isolation` = len(table) + 3 + 32 + 10. So a table name
# longer than 18 characters cannot be added to `PARTITIONED_TABLES` without
# `partition_policy_name` raising for every project. That is not a theoretical
# bound: `memory_status_log` was first written as `memory_status_history` (21),
# which made `create_project_partitions` raise on its very first call — the
# status writer would have been dead on arrival in any real deployment while
# passing every offline test that did not build the policy name. Checked by
# `tests/phase0/test_partitions.py::test_generated_identifiers_fit_postgres_limit`,
# which is parametrised over `PARTITIONED_TABLES` and is what caught it.
_TABLE_NAME_MAX = _IDENT_MAX - len("_p_") - 32 - len("_isolation")

# The RLS predicate, character-for-character identical to the one
# migrations/0003_rls.sql puts on the parent tables. `NULLIF(..., '')` is
# load-bearing, not defensive noise: see that migration's header comment.
_ISOLATION_PREDICATE = (
    "project_id = NULLIF(current_setting('tracebed.project_id', true), '')::uuid"
)

# E2 keeps the established one-policy-per-leaf catalog shape.  At c12 the
# existing isolation policy gains a read-side project fence, while its explicit
# WITH CHECK remains the plain project predicate so the BEFORE write guard can
# return the typed durable refusal for a raw INSERT.  The five owner-only E2
# ledger/fence families have no runtime SELECT grant and deliberately retain
# their narrower original policy shape.
_E2_RUNTIME_READ_GUARDED_TABLES = frozenset(PARTITIONED_TABLES[:17])
_ERASURE_READ_FENCE_PREDICATE = (
    f"({_ISOLATION_PREDICATE}) "
    "AND public.tracebed_runtime_erasure_read_allowed(project_id)"
)

_UUID_TEXT = re.compile(r"\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")


def _require_partitioned(table: str) -> None:
    if table not in PARTITIONED_TABLES:
        raise ValueError(f"{table!r} is not a LIST-partitioned table")


_OVERLONG_TABLES = tuple(t for t in PARTITIONED_TABLES if len(t) > _TABLE_NAME_MAX)
if _OVERLONG_TABLES:  # pragma: no cover - import-time refusal, see _TABLE_NAME_MAX
    raise ValueError(
        f"PARTITIONED_TABLES entries {list(_OVERLONG_TABLES)} exceed {_TABLE_NAME_MAX} "
        "characters, so partition_policy_name would exceed PostgreSQL's identifier limit "
        "for every project and create_project_partitions would raise on first use"
    )


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


def partition_index_name(table: str, project_id: ProjectId, suffix: str) -> str:
    """The exact index name `partition_index_statements` builds for `(table, suffix)` — exposed
    so `stores.pg.search` resolves a partition's vchord_bm25 index regclass for `to_bm25query`
    without re-deriving the spelling (single source of truth with the CREATE INDEX above)."""
    return _checked_ident(f"{partition_name(table, project_id)}_{suffix}")


def create_partition_sql(table: str, project_id: ProjectId) -> str:
    """`CREATE TABLE ... PARTITION OF ... FOR VALUES IN (...)` for `table`.

    Idempotent (`IF NOT EXISTS`) — safe to re-issue from
    `ensure_schema_current`. Takes no query parameters by design; see
    `_bound_literal` for why the partition bound cannot be bound.
    """
    name = partition_name(table, project_id)
    return (
        f"CREATE TABLE IF NOT EXISTS public.{name} "
        f"PARTITION OF public.{table} FOR VALUES IN ({_bound_literal(project_id)})"
    )


def partition_rls_statements(
    table: str, project_id: ProjectId, *, erasure_foundation: bool = False
) -> list[str]:
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
    # E2's owner-only erasure/binding families use an explicit WITH CHECK on the
    # parent policy. Match that exact c12 catalog shape on late-created
    # leaves; historical c11 parents intentionally retain their original
    # USING-only policies, so applying this indiscriminately would fabricate
    # profile drift for an otherwise valid c11 project.
    runtime_read_guarded = erasure_foundation and table in _E2_RUNTIME_READ_GUARDED_TABLES
    predicate = _ERASURE_READ_FENCE_PREDICATE if runtime_read_guarded else _ISOLATION_PREDICATE
    # c12 makes the ordinary data-table WITH CHECK explicit so raw INSERTs
    # reach ``tracebed_runtime_erasure_write_guard`` and fail with P0002,
    # rather than being hidden by the read-side RLS predicate first.
    with_check = (
        f" WITH CHECK ({_ISOLATION_PREDICATE})"
        if runtime_read_guarded
        or table
        in {"subject_fence", "run_fence", "erase_run_set", "erase_mem_set", "run_memory_binding"}
        else ""
    )
    return [
        f"ALTER TABLE public.{name} ENABLE ROW LEVEL SECURITY",
        f"ALTER TABLE public.{name} FORCE ROW LEVEL SECURITY",
        f"DROP POLICY IF EXISTS {policy} ON public.{name}",
        f"CREATE POLICY {policy} ON public.{name} USING ({predicate}){with_check}",
    ]


def partition_grant_statements(
    table: str,
    project_id: ProjectId,
    *,
    authority_cutover: bool = False,
    erasure_foundation: bool = False,
) -> list[str]:
    """DML grants for the app role on one partition.

    `migrations/0003_rls.sql`'s `ALTER DEFAULT PRIVILEGES` only covers
    objects created by the same role that ran the migration; partitions are
    created later by admin tooling that may run under a different role
    (contract §5.5 — these take a raw `conn` "run under migration/admin
    privileges"). Granting explicitly here removes that assumption. No
    TRUNCATE and no DDL: TRUNCATE has no row-level filter for RLS to apply.
    """
    name = partition_name(table, project_id)
    if not authority_cutover:
        if table == "run_owner":
            return [
                f"REVOKE ALL PRIVILEGES ON public.{name} FROM PUBLIC",
                "REVOKE ALL PRIVILEGES ON "
                f"public.{name} FROM {_APP_ROLE}, {_API_GROUP}, {_WORKER_GROUP}, {_ERASURE_GROUP}",
                f"GRANT SELECT, INSERT ON public.{name} TO {_APP_ROLE}, {_API_GROUP}",
                f"GRANT SELECT ON public.{name} TO {_WORKER_GROUP}",
            ]
        if table in {"trace_index", "trace_learning_job"}:
            return [
                f"REVOKE DELETE ON public.{name} FROM {_APP_ROLE}",
                f"GRANT SELECT, INSERT, UPDATE ON public.{name} TO {_APP_ROLE}",
            ]
        return [f"GRANT SELECT, INSERT, UPDATE, DELETE ON public.{name} TO {_APP_ROLE}"]

    api_privileges, worker_privileges = _CUTOVER_CHILD_GRANTS[table]
    # c12 has profiled admission/binding/key routines.  Late-created leaves
    # must not quietly restore the raw DML that 0012 revoked on existing
    # partitions; otherwise a newly provisioned project becomes a bypass.
    if erasure_foundation and table == "run_owner":
        api_privileges, worker_privileges = "SELECT", "SELECT"
    elif erasure_foundation and table in {"trace_subject", "subject_key"}:
        api_privileges, worker_privileges = None, "SELECT"
    elif erasure_foundation and table == "invalidation_event":
        # E2 admits invalidation writes only through its profiled API SECDEF
        # routine; c11 retains its historical direct API producer surface.
        api_privileges, worker_privileges = "SELECT", "SELECT"
    statements = [
        f"REVOKE ALL PRIVILEGES ON public.{name} FROM PUBLIC",
        "REVOKE ALL PRIVILEGES ON "
        f"public.{name} FROM {_APP_ROLE}, {_API_ROLE}, {_WORKER_ROLE}, {_API_GROUP}, "
        f"{_WORKER_GROUP}, {_ERASURE_GROUP}",
    ]
    if api_privileges is not None:
        statements.append(f"GRANT {api_privileges} ON public.{name} TO {_API_GROUP}")
    if worker_privileges is not None:
        statements.append(f"GRANT {worker_privileges} ON public.{name} TO {_WORKER_GROUP}")
    return statements


# The pg_tokenizer tokenizer migrations/0005_bm25.sql creates; the single source of truth for
# its name, referenced by the write path (stores.pg.repo) and the read path (stores.pg.search).
LEXICAL_TOKENIZER: Final[str] = "tracebed_lexical"

# Suffix of the per-partition vchord_bm25 ranking index; shared by the CREATE INDEX below and
# stores.pg.search's to_bm25query index-regclass resolution so the two cannot drift.
MEMORY_ITEM_BM25_INDEX_SUFFIX: Final[str] = "bm25"

# (index-name suffix, index definition after `ON <partition>`) per table.
# Suffixes are kept short deliberately: `partition_name` already spends
# 32 characters on the project uuid, and `_checked_ident` refuses anything
# PostgreSQL would truncate.
_INDEX_SPECS: dict[str, tuple[tuple[str, str], ...]] = {
    "memory_item": (
        ("hnsw", "USING hnsw (embedding halfvec_cosine_ops)"),
        # Rarity-gate document-frequency source: GIN over the `lexemes` tsvector supports the
        # `lexemes @@ plainto_tsquery(...)` counting in search.document_frequency — an EXACT
        # document frequency, which is the quantity the abstention rarity gate reads (D-003
        # rejected ts_rank's *ranking*, not tsvector *matching*).
        ("lex", "USING gin (lexemes)"),
        # The true BM25 *ranking* index (STAGE 2, D-140): vchord_bm25's `bm25` access method over
        # the `content_bm25 bm25vector` column migrations/0005_bm25.sql adds. Per-partition only,
        # exactly like HNSW — to_bm25query reads THIS index's own per-project IDF statistics, and
        # the storage-less partitioned PARENT index errors at query time (UndefinedFile). The
        # opclass is schema-qualified so the CREATE INDEX resolves under the default search_path.
        (MEMORY_ITEM_BM25_INDEX_SUFFIX, "USING bm25 (content_bm25 bm25_catalog.bm25_ops)"),
        ("status", "(status)"),
        ("subject", "(subject_tag)"),
        ("subjects", "USING gin (subject_digests)"),
        ("verdict", "(scan_verdict_id)"),
    ),
    "trace_index": (
        ("submitter", "(submitter_principal)"),
        ("outstatus", "(outcome_status)"),
        ("subjects", "USING gin (subject_digests)"),
    ),
    "outcome_event": (("run", "(run_id)"), ("subjects", "USING gin (subject_digests)")),
    "injection_log": (("mem", "(memory_id)"), ("subjects", "USING gin (subject_digests)")),
    "retrieval_event": (("subjects", "USING gin (subject_digests)"),),
    "blackboard_entry": (("subjects", "USING gin (subject_digests)"),),
    "memory_link": (("subjects", "USING gin (subject_digests)"),),
    "derived_state": (("subjects", "USING gin (subject_digests)"),),
    "spend_ledger": (("subjects", "USING gin (subject_digests)"),),
    "review_queue": (("mem", "(memory_id)"), ("subjects", "USING gin (subject_digests)")),
    "trace_subject": (("subject", "(subject_digest, run_id)"),),
    # The dashboard's MemoryDetail transition-log panel and every "why is this
    # memory in this state" query read one memory's history newest-first; without
    # this the read is a partition scan whose cost grows with every transition the
    # project has ever made, not with the one memory being inspected.
    "memory_status_log": (
        ("mem", "(memory_id, changed_at DESC)"),
        ("subjects", "USING gin (subject_digests)"),
    ),
    # The per-day cap counter `ScorerRepo.scored_updates_today` buckets a memory's
    # Q updates by (project_id, memory_id) over a half-open UTC-day range on
    # scored_at; without this the count is a partition scan whose cost grows with
    # every Q update the project has ever made, not with the one memory and day
    # being capped.
    "memory_q_update": (
        ("scored", "(project_id, memory_id, scored_at)"),
        ("subjects", "USING gin (subject_digests)"),
    ),
    "trace_learning_job": (
        (
            "ready",
            "(pipeline, pipeline_version, available_at, scheduled_at, run_id) "
            "WHERE state IN ('pending', 'retry')",
        ),
        (
            "lease",
            "(pipeline, pipeline_version, lease_expires_at, scheduled_at, run_id) "
            "WHERE state = 'running'",
        ),
        ("subjects", "USING gin (subject_digests)"),
    ),
    "run_owner": (
        ("owner", "(principal_id, agent_type_id, run_id)"),
        ("subjects", "USING gin (subject_digests)"),
    ),
    "invalidation_event": (("subjects", "USING gin (subject_digests)"),),
    "subject_fence": (("state", "(state, subject_digest)"),),
    "run_fence": (("state", "(state, run_id)"),),
    "run_memory_binding": (("run", "(run_id, memory_id)"),),
}


def _index_specs_for_schema(
    table: str, *, erasure_foundation: bool
) -> tuple[tuple[str, str], ...]:
    """Return the exact index vocabulary supported by the live catalog.

    The unreleased 0012 migration adds digest attribution and five parents atomically.
    Before that receipt exists, project provisioning must retain the exact c11
    index shape; after it exists, a missing E1 parent is caller-visible drift.
    This is a catalog probe, not a deploy-time feature flag.
    """

    specs = _INDEX_SPECS.get(table, ())
    if erasure_foundation:
        return specs
    if table in {
        "memory_item",
        "outcome_event",
        "invalidation_event",
        "trace_learning_job",
        "trace_index",
        "injection_log",
        "retrieval_event",
        "blackboard_entry",
        "memory_link",
        "derived_state",
        "spend_ledger",
        "review_queue",
        "memory_status_log",
        "memory_q_update",
        "run_owner",
    }:
        return tuple(spec for spec in specs if spec[0] != "subjects")
    if table == "trace_subject":
        return (("subject", "(subject_tag)"),)
    return specs


def partition_index_statements(
    table: str, project_id: ProjectId, *, erasure_foundation: bool = True
) -> list[str]:
    """Per-partition indexes for `table`'s partition of `project_id`.

    `memory_item` gets the HNSW `halfvec_cosine_ops` ANN index (pgvector) and
    the vchord_bm25 BM25 index (both PLAN.md §5's "retrieval quality" half
    of invariant 4) plus btree on its hot filter columns; every other
    partitioned table gets a btree on the column its Repo builders filter or
    join on most (contract §5.1's builder list). Idempotent throughout
    (`IF NOT EXISTS`) so `ensure_schema_current` can re-issue these against
    every existing partition without erroring on ones that already have
    them.
    """
    name = partition_name(table, project_id)
    return [
        # PostgreSQL does not permit a schema-qualified index name in CREATE
        # INDEX.  The caller pins ``search_path`` to pg_catalog,public before
        # executing this, while the target relation stays explicitly public.
        f"CREATE INDEX IF NOT EXISTS {_checked_ident(f'{name}_{suffix}')} ON public.{name} {definition}"
        for suffix, definition in _index_specs_for_schema(
            table, erasure_foundation=erasure_foundation
        )
    ]


def partition_index_expectations(
    table: str, project_id: ProjectId, *, erasure_foundation: bool = True
) -> list[tuple[str, str, str, str | None]]:
    """Canonical catalog shape for each index created for one partition.

    ``CREATE INDEX IF NOT EXISTS`` only promises not to raise when an object
    with the requested name already exists.  The partition manager uses this
    companion shape to reject an index planted on the wrong relation, with a
    different access method/opclass, key list, or predicate.
    """

    expectations: list[tuple[str, str, str, str | None]] = []
    for suffix, definition in _index_specs_for_schema(
        table, erasure_foundation=erasure_foundation
    ):
        before_predicate, separator, predicate = definition.partition(" WHERE ")
        if before_predicate.startswith("USING "):
            access_method, _, key_group = before_predicate.removeprefix("USING ").partition(" ")
        else:
            access_method, key_group = "btree", before_predicate
        if not (key_group.startswith("(") and key_group.endswith(")")):
            raise AssertionError("partition index specification has invalid key syntax")
        expectations.append(
            (
                partition_index_name(table, project_id, suffix),
                access_method,
                key_group[1:-1],
                predicate if separator else None,
            )
        )
    return expectations
