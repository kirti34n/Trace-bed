"""The typed repository (PHASE-0 Task 7; PLAN.md §2 invariants 4 and 6; contract §5.1).

`Repo` is the *only* place SQL is allowed to run outside migrations (`scripts/raw_sql_lint.py`
enforces this at the AST level for the whole `src/` tree). Two structural guarantees live here,
not by convention:

1. **Invariant 4 (project isolation).** Every public builder's first parameter is `project_id:
   ProjectId`, with exactly the six-method registry allowlist in `REGISTRY_METHODS_WITHOUT_PROJECT_ID`
   below as the exception (unpartitioned tables where project identity either doesn't exist yet
   or is what the call derives). `tests/phase0/test_repo_scoping.py` introspects every public
   method's signature with `inspect` to enforce this exhaustively, not by grep -- checking the
   parameter's TYPE, not just its name. Every partitioned-table method obtains its connection
   exclusively through `tracebed.stores.pg.pool.scoped()`, which cannot be entered without a
   `ProjectId` and sets the RLS GUC as the transaction's first statement (contract §5.0, C-09);
   `tests/phase0/test_repo_isolation_offline.py` drives every public method against a fake
   connection and asserts that, with `REGISTRY_METHODS_WITHOUT_GUC` as the only exception --
   without it "uses scoped()" would be a claim in this docstring rather than a tested property,
   and there is no Postgres on the build machine to catch it any other way. RLS FORCE
   (migrations Task 6) is the backstop; this is the primary control.
2. **Invariant 6 (provenance-complete-or-rejected).** `insert_memory_item` runs
   `validate_provenance` (pure, offline-testable) and `core.scans.verify_verdict` (HMAC + content
   -hash check against the *actual* content being inserted, not just the verdict's own fields)
   before any row is written, in that order, and neither exception is ever caught here --
   they propagate to the caller unmodified (contract §14).

`Repo.tx(project_id)` is the one composition tool for multi-statement atomic units (contract
§5.0): every other public method opens its own connection and is atomic on its own.

Parameter binding: every builder binds `domain.ids` newtypes directly. That only works because
`stores.pg.pool` registers a psycopg dumper for `TypedId` at import (psycopg 3 has no
`__conform__` hook) -- see the block at the top of `pool.py`. Importing `pool` is therefore a
hard requirement of this module, not an incidental dependency.

NOTE: this file was drafted against PLAN.md §5's DDL sketch before `migrations/*.sql` (owner:
migrations) existed on disk, then reconciled against the real `0001_registries.sql` /
`0002_partitioned.sql` / `0003_rls.sql` once they landed. `domain/memory.py` and `domain/scope.py`
-- both assigned to chunk domain-events-scan by contract §1 -- did not exist at audit time, which
blocks importing this module at all; that is a cross-chunk blocker, not a defect here.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, date, datetime, time, timedelta
from decimal import Decimal
from enum import StrEnum
from typing import Any, Final, Literal
from uuid import UUID, uuid4

import psycopg
from psycopg import errors as pg_errors
from psycopg.rows import DictRow, dict_row
from psycopg.types.json import Json
from psycopg_pool import ConnectionPool

from tracebed.core.scans import verify_verdict
from tracebed.domain.canonical import content_hash
from tracebed.domain.clock import Clock
from tracebed.domain.enums import (
    Arm,
    InstrumentationSource,
    Lane,
    MemType,
    ProvenanceClass,
    ScopeType,
    TraceOutcomeStatus,
    TrustTier,
)
from tracebed.domain.errors import (
    DuplicateRegistration,
    NotFound,
    ScopeResolutionFailed,
)
from tracebed.domain.ids import AgentTypeId, MemoryId, PrincipalId, ProjectId, RunId, mint_memory_id
from tracebed.domain.memory import NewMemoryItem, Provenance, validate_provenance
from tracebed.domain.scan import ScanVerdict
from tracebed.domain.scope import ProjectScope
from tracebed.domain.signatures import ABSENT_SIGNATURE, is_absent_signature
from tracebed.domain.state_machine import Status, assert_legal_creation_status
from tracebed.stores.pg.pool import _unscoped, scoped
from tracebed.stores.pg.rows import (
    InjectionRow,
    InvalidationEventRow,
    KillswitchStateRow,
    MemoryItemRow,
    OutcomeEventInsert,
    PrincipalRow,
    RetrievalEventInsert,
    ReviewQueueRow,
    SpendRow,
    SubjectKeyRow,
    TraceIndexRow,
    TraceIndexUpsert,
)

__all__ = [
    "MAX_ROW_LIMIT",
    "MAX_SWEEP_BATCH",
    "PROPOSAL_CAP_LOCK_CLASS",
    "REGISTRY_METHODS_WITHOUT_GUC",
    "REGISTRY_METHODS_WITHOUT_PROJECT_ID",
    "ProposalCapOutcome",
    "ProposalInsertResult",
    "Repo",
    "ScopedRepo",
]

logger = logging.getLogger(__name__)

# Capability token: holding it is what proves a `ScopedRepo` came from `Repo.tx`. Module-private
# and never exported, so no other module can pass the check (see `ScopedRepo.__init__`).
_SCOPED_REPO_TOKEN: Final[object] = object()

# The exhaustive exception list to "every builder's first parameter is project_id" (contract
# §5.1). A single source of truth so the repo and its introspection test cannot drift apart.
REGISTRY_METHODS_WITHOUT_PROJECT_ID: frozenset[str] = frozenset(
    {
        "resolve_project",
        "create_project",
        "create_principal",
        "get_principal_by_external_ref",
        "list_project_ids",
        "record_embedding_model",
    }
)

# The *other* allowlist, and a different question: which methods legitimately do NOT set the RLS
# GUC (contract §5.0 -- "registry-only methods (project/principal/agent_type/agent_registration/
# embedding_model/scoring_epoch -- unpartitioned tables) skip the GUC; every partitioned-table
# path sets it"). `create_agent_type`/`register_agent` take a `project_id` (it is an FK value)
# but touch unpartitioned registry tables, so they are here and not above -- the two lists are
# deliberately different sets, and conflating them is how a partitioned-table method silently
# ends up without a GUC. `tests/phase0/test_repo_isolation_offline.py` drives every public method
# against a fake connection and asserts that everything outside this set issues the GUC as the
# first statement of its transaction. Without that test, "uses scoped()" is a docstring claim.
REGISTRY_METHODS_WITHOUT_GUC: frozenset[str] = REGISTRY_METHODS_WITHOUT_PROJECT_ID | frozenset(
    {"create_agent_type", "register_agent", "create_agent_registration"}
)

# Hard ceiling on any caller-supplied `limit`. Repo builders are reachable from `api/admin.py`
# and the dashboard API; an unbounded (or negative) limit is either an unbounded server-side
# allocation or a SQL error, neither of which should depend on a route remembering to clamp.
MAX_ROW_LIMIT: Final[int] = 1_000

# Ceiling on one `find_runs_missing_sentinel` sweep. The sweeper runs on a schedule, so a
# truncated batch is picked up next tick; an untruncated one on a busy project is a multi-million
# -element list built inside a worker.
MAX_SWEEP_BATCH: Final[int] = 10_000

# ScoringConfig.q_start / initial confidence for a freshly inserted memory (PLAN.md §6). Repo
# does not depend on domain.config (no ConfigResolver is wired into it in Phase 0), so these are
# the same literal defaults, kept in one place and documented rather than hardcoded inline.
_INITIAL_Q_VALUE = 0.5
_INITIAL_CONFIDENCE = 0.0

# Leak-suite probe 2 (PLAN.md §2 invariant 4): the by-id 404 body must be byte-identical whether
# the id genuinely does not exist or belongs to another project. One literal, used everywhere.
_NOT_FOUND_MESSAGE = "not found"

# Tables considered "this project's data" for /export/project (contract §5.1 iter_export_rows).
# Not specified exhaustively by the contract; see this chunk's contract_gaps.
_EXPORT_TABLES: tuple[str, ...] = (
    "memory_item",
    "trace_index",
    "outcome_event",
    "injection_log",
    "retrieval_event",
)

# One export projection per table, assembled into `_EXPORT_COLUMNS` below alongside
# `_EXPORT_EXCLUDED_COLUMNS`. `tests/phase0/test_export_column_list.py` parses the real DDL
# (`CREATE TABLE` plus every column-shaped `ALTER TABLE`) and asserts that every real column of
# every exported table is accounted for by EXACTLY one of the two maps, AND that the SQL
# `_impl_iter_export_rows` actually issues projects exactly this list. Both halves are needed:
# asserting only on these constants cannot fail if a future edit puts `SELECT *` back into the
# statement, which is the original defect verbatim.
_MEMORY_ITEM_EXPORT_COLUMNS: Final[str] = (
    "id, project_id, scope_type, scope_id, mem_type, kind, lane, trust_tier, status, "
    "content, content_hash, token_count, embedding_model_id, embedding_model_version, "
    "subject_tag, q_value, confidence, scored_use_count, last_scored_at, strike_count, "
    "shadow_confirm_runs, cluster_id, ttl_class, pinned, last_retrieved_at, "
    "last_revalidated_at, status_changed_at, valid_from, valid_to, created_at, expired_at, "
    "provenance, scan_verdict_id, schema_version, epoch_id"
)

# `outcome_event` / `injection_log` / `retrieval_event` carry no vector/tsvector columns, so
# their export lists are every column the table has -- still explicit, and still one entry per
# table, because the point of this fix is that a FUTURE column added to any of these five tables
# has to be a conscious edit here, not a `SELECT *` that picks it up for free.
_OUTCOME_EVENT_EXPORT_COLUMNS: Final[str] = (
    "event_id, run_id, project_id, principal_id, adapter, r, payload, occurred_at, arrived_at"
)
_INJECTION_LOG_EXPORT_COLUMNS: Final[str] = (
    "run_id, project_id, memory_id, slot, score, tokens, injected_at"
)
_RETRIEVAL_EVENT_EXPORT_COLUMNS: Final[str] = (
    "run_id, project_id, outcome_code, latency_ms, embed_latency_ms, candidates_considered, "
    "top_score, arm, created_at"
)

# `arm` is DERIVED, never bound. PLAN.md §10 forbids accepting an experiment-arm assignment
# from any caller in those words, and this upsert used to bind `%(arm)s` straight out of the
# caller-supplied `run_start` payload (`ingest.trace_writer`), which made the kill switch's
# audit column -- and therefore the governing stratified-lift number -- caller-controlled. The
# server's own record of the arm this run started under is `retrieval_event.arm`, written by
# `hotpath.pipeline` from `hotpath.holdout.assign_arm`; the scalar subquery below reads it, and
# there is no bound parameter a caller could reach. `ORDER BY created_at ASC` because a run may
# write several retrieval_event rows (the ordinary call plus any JIT checkpoint) and the arm the
# run STARTED under is the one the experiment is stratified on. The COALESCE fallback is the
# non-holdout default for a trace whose retrieval was never recorded (a run that never called
# /v1/retrieve at all): failing safe to `memory_on` can only ever shrink the measured holdout
# cell, never invent one.
#
# The merge rules for `outcome_status` have to compare against literal enum VALUES inside a
# CASE, so the tokens below are substituted from `domain.enums` at import rather than
# hand-typed. A renamed enum member would otherwise leave the CASE comparing against a value that
# no longer exists -- the branch would simply never fire, silently restoring the exact bug the
# CASE was added to fix. Written as a plain template plus `str.replace` (not an f-string) so the
# template stays literally the SQL that runs, and so no interpolation machinery sits next to a
# query string at all. Substitution completeness is asserted immediately below.
_SERVER_DERIVED_ARM_SUBQUERY = """(
        SELECT re.arm FROM retrieval_event re
        WHERE re.project_id = %(project_id)s AND re.run_id = %(run_id)s
        ORDER BY re.created_at ASC
        LIMIT 1
    )"""
_TRACE_INDEX_UPSERT_TEMPLATE = """
INSERT INTO trace_index (
    project_id, run_id, agent_type_id, workflow_template_id, submitter_principal,
    input_signature_hash, instrumentation_source, arm, path, started_at, ended_at,
    payload_ref, outcome_status
) VALUES (
    %(project_id)s, %(run_id)s, %(agent_type_id)s, %(workflow_template_id)s,
    %(submitter_principal)s, %(input_signature_hash)s, %(instrumentation_source)s,
    COALESCE(@ARM_SUBQUERY@, '@MEMORY_ON@'),
    %(path)s, %(started_at)s, %(ended_at)s, %(payload_ref)s, %(outcome_status)s
)
ON CONFLICT (project_id, run_id) DO UPDATE SET
    -- `agent_type_id` is the third identity-bearing column: it is an INPUT to
    -- `domain.signatures.input_signature_hash`, so letting a later batch move it would move
    -- the signature cluster the next `run_start` computes. `ingest.trace_writer._resolve_owner`
    -- already pins it application-side (an existing row's `agent_type_id` IS the owner, and
    -- envelopes disagreeing with the owner are refused), so this makes the database agree with
    -- the only caller instead of trusting it to keep agreeing. NOT NULL, so the EXCLUDED arm
    -- fires only on the INSERT half.
    agent_type_id = COALESCE(trace_index.agent_type_id, EXCLUDED.agent_type_id),
    workflow_template_id = COALESCE(EXCLUDED.workflow_template_id, trace_index.workflow_template_id),
    -- `submitter_principal` and `input_signature_hash` are the identity columns
    -- `workers.independence.build_confirmations` resolves a `ShadowConfirmation`'s principal
    -- and signature cluster from (PLAN.md invariant 7 / D-020). Plain `EXCLUDED.<col>` used to
    -- let a retry, a duplicate delivery, or a late batch for the SAME run silently overwrite
    -- the identity the independence check relies on.
    --
    -- `submitter_principal` follows the same first-write-wins COALESCE idiom as `started_at`
    -- below: the EXISTING row's value wins. It is `NOT NULL` from the first insert and has no
    -- sentinel value, so the FIRST authenticated submitter is pinned permanently.
    submitter_principal = COALESCE(trace_index.submitter_principal, EXCLUDED.submitter_principal),
    -- `input_signature_hash` CANNOT use that idiom, and this is the one asymmetry in the
    -- statement worth reading twice. It is `NOT NULL` too, but unlike `submitter_principal` it
    -- has a SENTINEL: `domain.signatures.ABSENT_SIGNATURE` (40 zero bytes, C-07), which
    -- `trace_writer._identity_columns` writes for a batch that does not carry this run's
    -- `run_start`. Delivery is at-least-once and out of order, so the FIRST batch for a run is
    -- routinely a non-`run_start` one; a plain `COALESCE(trace_index.x, EXCLUDED.x)` would see
    -- a non-NULL sentinel, keep it, and pin the run at ABSENT_SIGNATURE forever -- after which
    -- `workers.independence.build_confirmations` drops that run from the evidence tuple
    -- outright (D-131: missing evidence must not read as independent evidence), so it could
    -- never corroborate anything again. The mechanism is that exclusion, NOT `same_cluster`:
    -- `domain.signatures.same_cluster` is deliberately left a pure Hamming predicate (D-131),
    -- which answers True for ABSENT vs ABSENT and False -- "distinct cluster" -- for ABSENT vs
    -- a real signature, which is precisely the BMAD B5 defect the exclusion exists to close.
    -- Delivery order would silently decide whether a legitimate run counts as evidence. The
    -- rule is therefore a ONE-WAY
    -- upgrade rather than first-write-wins: the sentinel may be replaced by a real signature
    -- exactly once, and a real signature is never replaced by anything -- not by a different
    -- real signature (the spoofing case) and not by the sentinel (the late-partial-batch case).
    -- The sentinel literal is substituted from `domain.signatures.ABSENT_SIGNATURE` rather than
    -- hand-typed, so the SQL cannot drift from the Python definition of "absent". `decode(...,
    -- 'hex')` rather than a `'\xdead'::bytea` literal: the literal form's meaning depends on the
    -- session's `standard_conforming_strings`, and a sentinel comparison that silently stops
    -- matching under a non-default GUC would disable the upgrade branch with no error anywhere.
    input_signature_hash = CASE
        WHEN trace_index.input_signature_hash = decode('@ABSENT_SIGNATURE@', 'hex')
            THEN EXCLUDED.input_signature_hash
        ELSE trace_index.input_signature_hash
    END,
    -- `instrumentation_source` is descriptive, not identity: nothing reads it to decide trust,
    -- independence, or arm, and a re-instrumented run legitimately reports the newest source.
    -- Last-write-wins is the deliberate rule here, not an oversight.
    instrumentation_source = EXCLUDED.instrumentation_source,
    path = COALESCE(EXCLUDED.path, trace_index.path),
    started_at = COALESCE(trace_index.started_at, EXCLUDED.started_at),
    ended_at = COALESCE(EXCLUDED.ended_at, trace_index.ended_at),
    payload_ref = COALESCE(trace_index.payload_ref, EXCLUDED.payload_ref),
    -- Delivery is at-least-once and batches can arrive (or be replayed) out of order, so a
    -- partial upsert -- one whose batch carried no `run_end` and therefore reports the
    -- TraceIndexUpsert default 'pending' -- must never un-finish an already-finished run.
    -- Plain `EXCLUDED.outcome_status` regressed ok/error/cancelled/incomplete back to
    -- 'pending', after which `find_runs_missing_sentinel` sweeps a genuinely complete run and
    -- `mark_run_incomplete` makes the distiller refuse it (PLAN.md §3: "missing sentinel ...
    -- => outcome_status='incomplete' and the distiller refuses").
    outcome_status = CASE
        WHEN EXCLUDED.outcome_status = '@PENDING@' THEN trace_index.outcome_status
        ELSE EXCLUDED.outcome_status
    END,
    -- `arm` is re-derived from the same server-side source on every merge, never from
    -- EXCLUDED: `EXCLUDED.arm` would be whatever the INSERT half computed for THIS batch, and
    -- an earlier batch that ran before the retrieval_event row was visible must not pin the
    -- column to the fallback forever. `COALESCE(..., trace_index.arm)` keeps an already-derived
    -- value when the subquery finds nothing, so the merge is monotone: it can correct
    -- 'memory_on' upward to the real arm, never downward to a default.
    arm = COALESCE(@ARM_SUBQUERY@, trace_index.arm)
"""

# `_impl_upsert_trace_index` reads these two columns back after the upsert above to compare
# the row's KEPT (post-merge) identity against what THIS call claimed -- see the long
# comment on `submitter_principal`/`input_signature_hash` in the template above. A separate
# statement rather than a `RETURNING EXCLUDED....` clause on the upsert itself: RETURNING
# would sit after the `arm` assignment as the literal last thing in that SQL string, and
# `tests/phase0/test_repo_isolation_offline.py::test_trace_index_upsert_never_regresses_a_finished_run_to_pending`
# already asserts, byte for byte, that the upsert's SQL ends at `trace_index.arm)` -- a
# structural check this fix must not have to fight. The extra round trip is one indexed
# primary-key lookup per ingest write, not a scan.
_TRACE_INDEX_IDENTITY_SELECT_SQL: Final[str] = (
    "SELECT submitter_principal, input_signature_hash FROM trace_index "
    "WHERE project_id = %(project_id)s AND run_id = %(run_id)s"
)

_TRACE_INDEX_UPSERT_SQL: Final[str] = (
    _TRACE_INDEX_UPSERT_TEMPLATE.replace("@PENDING@", TraceOutcomeStatus.PENDING.value)
    .replace("@MEMORY_ON@", Arm.MEMORY_ON.value)
    .replace("@ABSENT_SIGNATURE@", ABSENT_SIGNATURE.hex())
    .replace("@ARM_SUBQUERY@", _SERVER_DERIVED_ARM_SUBQUERY)
)

if "@" in _TRACE_INDEX_UPSERT_SQL:  # pragma: no cover - import-time structural guard
    raise RuntimeError(
        "trace_index upsert template has an unsubstituted placeholder; the merge rules would "
        "compare against a literal token instead of an enum value"
    )

_TRACE_INDEX_COLUMNS: Final[str] = (
    "project_id, run_id, agent_type_id, workflow_template_id, submitter_principal, "
    "input_signature_hash, instrumentation_source, arm, path, started_at, ended_at, "
    "payload_ref, outcome_status"
)

# Explicit column list instead of `SELECT *` on `memory_item`. Three reasons, all real:
# (1) `memory_item` carries `embedding halfvec(768)` and `lexemes tsvector` (migrations
#     0002) -- neither has a registered psycopg loader, both are decoded as multi-kilobyte
#     text on EVERY by-id fetch, and neither appears in `MemoryItemRow`;
# (2) `SELECT *` binds this module to column ORDER and to every future column a migration
#     adds, so a schema change turns into a silent behaviour change here;
# (3) it makes the projection auditable -- what leaves the repository is a fixed list.
_MEMORY_ITEM_COLUMNS: Final[str] = (
    "id, project_id, scope_type, scope_id, mem_type, kind, lane, trust_tier, status, "
    "content, content_hash, token_count, subject_tag, q_value, confidence, "
    "scored_use_count, strike_count, provenance, scan_verdict_id, schema_version, "
    "created_at, status_changed_at"
)

# `trace_index`'s export list is the same projection the upsert already writes
# (`_TRACE_INDEX_COLUMNS` above -- deliberately reused, not duplicated, since it is already every
# column the table has and a second hand-typed copy is exactly the drift this fix removes).
_EXPORT_COLUMNS: Final[Mapping[str, str]] = {
    "memory_item": _MEMORY_ITEM_EXPORT_COLUMNS,
    "trace_index": _TRACE_INDEX_COLUMNS,
    "outcome_event": _OUTCOME_EVENT_EXPORT_COLUMNS,
    "injection_log": _INJECTION_LOG_EXPORT_COLUMNS,
    "retrieval_event": _RETRIEVAL_EVENT_EXPORT_COLUMNS,
}

# Columns an exported table carries that the export deliberately WITHHOLDS. Keyed by table, with
# an explicit empty entry for the four tables that withhold nothing, because the completeness
# check in `tests/phase0/test_export_column_list.py` is "every real column of every exported table
# is in exactly one of these two maps" -- a per-table entry is what lets a future migration adding
# a `halfvec`/`tsvector`/blob column to `retrieval_event` be excluded the same way `memory_item`'s
# two are. A single `memory_item`-only set left that test with exactly one possible green answer
# for the other four tables ("add it to the export list"), which is the wrong steer for precisely
# the column class this fix exists to keep out of an NDJSON body.
#
# `memory_item`'s two are withheld for the same reasons `_MEMORY_ITEM_COLUMNS` above withholds
# them from every by-id fetch: `embedding halfvec(768)` and `lexemes tsvector` have no registered
# psycopg loader and are multi-kilobyte per row, and neither belongs in an export a caller reads
# as text. This is its OWN set (not folded into `_MEMORY_ITEM_COLUMNS`) because the export's
# projection is a different one -- it carries fields `MemoryItemRow` does not
# (`shadow_confirm_runs`, `pinned`, `ttl_class`, ...) precisely because "this project's data" for
# an export means more than "what a retrieval-path row needs".
_EXPORT_EXCLUDED_COLUMNS: Final[Mapping[str, frozenset[str]]] = {
    "memory_item": frozenset({"embedding", "lexemes"}),
    "trace_index": frozenset(),
    "outcome_event": frozenset(),
    "injection_log": frozenset(),
    "retrieval_event": frozenset(),
}

if frozenset(_EXPORT_COLUMNS) != frozenset(_EXPORT_TABLES) or frozenset(
    _EXPORT_EXCLUDED_COLUMNS
) != frozenset(_EXPORT_TABLES):  # pragma: no cover - import-time guard
    raise RuntimeError(
        "_EXPORT_COLUMNS/_EXPORT_EXCLUDED_COLUMNS and _EXPORT_TABLES have drifted -- every "
        "exported table needs exactly one explicit column list and one explicit excluded set"
    )


# Advisory-lock class id for the proposal-cap critical section. `pg_advisory_xact_lock`'s
# two-int form namespaces the lock: every other subsystem that ever needs an advisory lock
# picks its own class here, so two unrelated features cannot collide on one hashed project
# id and serialise each other for no reason. Arbitrary but FIXED -- changing it silently
# splits running processes into two non-excluding groups, which is exactly the failure the
# lock exists to prevent.
PROPOSAL_CAP_LOCK_CLASS: Final[int] = 0x7B_00_01

# `provenance->>'class'` is the discriminator (`domain.memory.Provenance.to_json`), and
# `provenance->>'run_id'` is `str(RunId)`. Both are jsonb text extractions rather than a
# join: `memory_item` has no `run_id` column -- a proposal's run lives only in provenance.
_PROPOSAL_PREDICATE: Final[str] = (
    "project_id = %(project_id)s AND provenance->>'class' = %(provenance_class)s"
)
_COUNT_PROPOSALS_IN_RUN_SQL: Final[str] = (
    f"SELECT count(*) FROM memory_item WHERE {_PROPOSAL_PREDICATE} "  # noqa: S608
    "AND provenance->>'run_id' = %(run_id)s"
)
_COUNT_PROPOSALS_IN_DAY_SQL: Final[str] = (
    f"SELECT count(*) FROM memory_item WHERE {_PROPOSAL_PREDICATE} "  # noqa: S608
    "AND created_at >= %(day_start)s AND created_at < %(day_end)s"
)
_FIND_PROPOSAL_SQL: Final[str] = (
    f"SELECT id FROM memory_item WHERE {_PROPOSAL_PREDICATE} "  # noqa: S608
    "AND provenance->>'run_id' = %(run_id)s AND content_hash = %(content_hash)s LIMIT 1"
)


class ProposalCapOutcome(StrEnum):
    """Why `insert_proposal_within_caps` did or did not write a row. A closed vocabulary
    rather than a bool plus a message, so `workflow.agent_control` maps outcomes by
    identity instead of by parsing prose."""

    INSERTED = "inserted"
    DUPLICATE = "duplicate"
    PER_RUN_CAP = "per_run_cap"
    PER_PROJECT_DAILY_CAP = "per_project_daily_cap"


@dataclass(frozen=True, slots=True)
class ProposalInsertResult:
    outcome: ProposalCapOutcome
    memory_id: MemoryId | None
    """Set for INSERTED (the new row) and DUPLICATE (the row that already existed);
    `None` for both cap refusals, where no row exists to name."""
    observed_count: int
    """The count actually compared against the cap, so a refusal can report the number
    the database held rather than restating the cap back to the caller."""


def _proposal_run_params(project_id: ProjectId, run_id: RunId) -> dict[str, Any]:
    return {
        "project_id": project_id,
        "provenance_class": ProvenanceClass.PROPOSAL.value,
        "run_id": str(run_id),
    }


def _proposal_day_params(project_id: ProjectId, day: date) -> dict[str, Any]:
    start = datetime.combine(day, time.min, tzinfo=UTC)
    return {
        "project_id": project_id,
        "provenance_class": ProvenanceClass.PROPOSAL.value,
        "day_start": start,
        "day_end": start + timedelta(days=1),
    }


def _scalar_count(row: Any) -> int:
    """`count(*)` always returns exactly one row with one integer. A `None` here means the
    statement did not run as written (a fake that returned nothing, a rewritten query), and
    silently reporting 0 would read as "no proposals yet" -- i.e. it would open the cap."""
    if row is None:
        raise NotFound("count(*) returned no row -- the proposal-count query did not execute")
    return int(row[0])


def _bounded_limit(limit: int) -> int:
    """Clamp a caller-supplied row limit into [1, MAX_ROW_LIMIT] (see `MAX_ROW_LIMIT`)."""
    if limit < 1:
        return 1
    return min(limit, MAX_ROW_LIMIT)


def _json_safe(value: object) -> object:
    """Coerce one Postgres value into something `json.dumps` accepts.

    `iter_export_rows` feeds `GET /export/project`'s NDJSON body (contract §9.3). Straight
    `dict(row)` yields `memoryview` for every `bytea` (`trace_index.input_signature_hash` is
    `bytea NOT NULL`), `Decimal` for `numeric` (`spend_ledger.cost_usd`), and `datetime`/`UUID`
    objects -- all of which raise `TypeError` inside `json.dumps`, i.e. the export route would
    500 on its first non-empty project. Bytes become lowercase hex; that is the same encoding
    `Provenance`'s jsonb shape uses for `input_sig_hashes` (contract §3.6), so an exported
    signature and a stored one are the same string.
    """
    if isinstance(value, memoryview | bytes | bytearray):
        return bytes(value).hex()
    if isinstance(value, Decimal):
        return float(value)
    if isinstance(value, datetime | date):
        return value.isoformat()
    if isinstance(value, UUID):
        return str(value)
    if isinstance(value, dict):
        return {str(k): _json_safe(v) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return [_json_safe(v) for v in value]
    return value


def _row_to_memory_item(row: DictRow) -> MemoryItemRow:
    """The one place a `memory_item` DB row becomes a `MemoryItemRow` (contract §5.2)."""
    return MemoryItemRow(
        id=MemoryId(row["id"]),
        project_id=ProjectId(row["project_id"]),
        scope_type=ScopeType(row["scope_type"]),
        scope_id=row["scope_id"],
        mem_type=MemType(row["mem_type"]),
        kind=row["kind"],
        lane=Lane(row["lane"]),
        trust_tier=TrustTier(row["trust_tier"]),
        status=Status(row["status"]),
        content=row["content"],
        content_hash=row["content_hash"],
        token_count=row["token_count"],
        subject_tag=row["subject_tag"],
        q_value=row["q_value"],
        confidence=row["confidence"],
        scored_use_count=row["scored_use_count"],
        strike_count=row["strike_count"],
        provenance=Provenance.from_json(row["provenance"]),
        scan_verdict_id=row["scan_verdict_id"],
        schema_version=row["schema_version"],
        created_at=row["created_at"],
        status_changed_at=row["status_changed_at"],
    )


def _row_to_trace_index(row: DictRow) -> TraceIndexRow:
    """The one place a `trace_index` DB row becomes a `TraceIndexRow` (contract §5.2)."""
    return TraceIndexRow(
        project_id=ProjectId(row["project_id"]),
        run_id=RunId(row["run_id"]),
        agent_type_id=AgentTypeId(row["agent_type_id"]),
        workflow_template_id=row["workflow_template_id"],
        submitter_principal=PrincipalId(row["submitter_principal"]),
        input_signature_hash=bytes(row["input_signature_hash"]),
        instrumentation_source=InstrumentationSource(row["instrumentation_source"]),
        arm=Arm(row["arm"]),
        path=row["path"],
        started_at=row["started_at"],
        ended_at=row["ended_at"],
        payload_ref=row["payload_ref"],
        outcome_status=TraceOutcomeStatus(row["outcome_status"]),
    )


def _trace_index_params(project_id: ProjectId, row: TraceIndexUpsert) -> dict[str, Any]:
    return {
        "project_id": project_id,
        "run_id": row.run_id,
        "agent_type_id": row.agent_type_id,
        "workflow_template_id": row.workflow_template_id,
        "submitter_principal": row.submitter_principal,
        "input_signature_hash": row.input_signature_hash,
        "instrumentation_source": row.instrumentation_source.value,
        "path": Json(dict(row.path)) if row.path is not None else None,
        "started_at": row.started_at,
        "ended_at": row.ended_at,
        "payload_ref": row.payload_ref,
        "outcome_status": row.outcome_status.value,
    }


class Repo:
    """`Repo(pool, clock)` (contract §5.1). See module docstring for the two structural
    guarantees this class exists to make load-bearing rather than conventional.
    """

    def __init__(self, pool: ConnectionPool, clock: Clock) -> None:
        self._pool = pool
        self._clock = clock

    # ------------------------------------------------------------------ transactions -------

    @contextmanager
    def tx(self, project_id: ProjectId) -> Iterator[ScopedRepo]:
        """One transaction, GUC set once at entry (contract §5.0); yields a handle exposing the
        same builders WITHOUT `project_id` (bound to this transaction). Used by
        `ingest.trace_writer` (trace_index + trace_subject atomically) and
        `stores.pg.partitions.drop_project`.
        """
        with scoped(self._pool, project_id) as conn:
            yield ScopedRepo(self, conn, project_id, _token=_SCOPED_REPO_TOKEN)

    # ------------------------------------------------------------------ registry [registry]-

    def resolve_project(self, principal_id: PrincipalId) -> ProjectScope:
        """Server-side scope derivation (PLAN.md §2 invariant 4): the *only* place a
        `ProjectScope` is constructed from a live principal. Raises `ScopeResolutionFailed` if no
        `agent_registration` row exists -- an authenticated caller with no registration gets
        nothing, never a default project.
        """
        with _unscoped(self._pool) as conn, conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                "SELECT project_id, agent_type_id FROM agent_registration "
                "WHERE principal_id = %(principal_id)s",
                {"principal_id": principal_id},
            )
            row = cur.fetchone()
        if row is None:
            raise ScopeResolutionFailed("no agent_registration for principal")
        return ProjectScope(
            project_id=ProjectId(row["project_id"]),
            agent_type_id=AgentTypeId(row["agent_type_id"]),
            principal_id=principal_id,
        )

    def create_project(
        self, name: str, retention_policy: Mapping[str, object] | None = None
    ) -> ProjectId:
        """Registry row only -- partitions and the project KEK are provisioned by the
        `/admin/projects` route composing this with `partitions.create_project_partitions` and
        `SubjectKeyManager.ensure_project_kek` (contract §9.3), not by `Repo` itself.
        """
        project_id = ProjectId(uuid4())
        with _unscoped(self._pool) as conn:
            conn.execute(
                "INSERT INTO project (project_id, name, status, retention_policy, created_at) "
                "VALUES (%(project_id)s, %(name)s, %(status)s, %(retention_policy)s, %(created_at)s)",
                {
                    "project_id": project_id,
                    "name": name,
                    "status": "active",
                    "retention_policy": Json(dict(retention_policy))
                    if retention_policy is not None
                    else None,
                    "created_at": self._clock.now(),
                },
            )
        return project_id

    def create_principal(
        self, kind: Literal["oidc_sub", "api_key"], external_ref: str, key_hash: str | None
    ) -> PrincipalId:
        principal_id = PrincipalId(uuid4())
        with _unscoped(self._pool) as conn:
            conn.execute(
                "INSERT INTO principal (principal_id, kind, external_ref, key_hash, created_at) "
                "VALUES (%(principal_id)s, %(kind)s, %(external_ref)s, %(key_hash)s, %(created_at)s)",
                {
                    "principal_id": principal_id,
                    "kind": kind,
                    "external_ref": external_ref,
                    "key_hash": key_hash,
                    "created_at": self._clock.now(),
                },
            )
        return principal_id

    def get_principal_by_external_ref(
        self, external_ref: str, *, kind: Literal["oidc_sub", "api_key"] | None = None
    ) -> PrincipalRow | None:
        """Authentication's identity lookup (contract §9.1: `ApiKeyVerifier`/`OidcJwksVerifier`
        both reach a principal through this one method).

        `principal`'s uniqueness constraint is `UNIQUE (kind, external_ref)` (migrations/0001),
        not `UNIQUE (external_ref)`. `external_ref` for an `api_key` principal is a server-minted
        key-id hex (C-19), while for an `oidc_sub` principal it is the IdP's `sub` claim, which
        the IdP -- not Tracebed -- controls. A `sub` that collides with an existing key-id would
        otherwise make this lookup return an arbitrary one of the two rows, and whichever row is
        returned decides `principal_id`, which decides `agent_registration`, which decides
        `project_id`: authenticating as one principal and being scoped into another principal's
        project. That is exactly invariant 4's failure mode.

        `kind` (C-29, keyword-only, added at integration) makes the query match the real
        constraint, so a collision cannot arise at all. It DEFAULTS to None purely so the
        one-argument form the contract's §5.1 sketch fixes still works; that form retains the
        original defence -- fetch two, and refuse to guess if both exist. Failing both identities
        closed is the correct direction, but it is still a denial of service an IdP can trigger,
        which is why every caller in this repository passes `kind`.
        """
        sql = "SELECT principal_id, kind, external_ref, key_hash, revoked_at FROM principal WHERE "
        params: dict[str, object] = {"external_ref": external_ref}
        if kind is None:
            sql += "external_ref = %(external_ref)s ORDER BY principal_id LIMIT 2"
        else:
            # Hits the UNIQUE(kind, external_ref) index exactly; at most one row can match, so
            # the ambiguity branch below is unreachable rather than merely unlikely.
            sql += "kind = %(kind)s AND external_ref = %(external_ref)s LIMIT 2"
            params["kind"] = kind
        with _unscoped(self._pool) as conn, conn.cursor(row_factory=dict_row) as cur:
            cur.execute(sql, params)
            rows = cur.fetchall()
        if len(rows) != 1:
            return None
        row = rows[0]
        return PrincipalRow(
            principal_id=PrincipalId(row["principal_id"]),
            kind=row["kind"],
            external_ref=row["external_ref"],
            key_hash=row["key_hash"],
            revoked_at=row["revoked_at"],
        )

    def list_project_ids(self) -> list[ProjectId]:
        """Sweeper iteration (ingest's `sweep_incomplete`, contract §11)."""
        with _unscoped(self._pool) as conn, conn.cursor() as cur:
            cur.execute("SELECT project_id FROM project WHERE deleted_at IS NULL")
            rows = cur.fetchall()
        return [ProjectId(r[0]) for r in rows]

    def record_embedding_model(
        self, model_id: str, model_version: str, dim: int, provider: str
    ) -> None:
        with _unscoped(self._pool) as conn:
            conn.execute(
                "INSERT INTO embedding_model (model_id, model_version, dim, provider) "
                "VALUES (%(model_id)s, %(model_version)s, %(dim)s, %(provider)s) "
                "ON CONFLICT (model_id, model_version) DO NOTHING",
                {
                    "model_id": model_id,
                    "model_version": model_version,
                    "dim": dim,
                    "provider": provider,
                },
            )

    def create_agent_type(self, project_id: ProjectId, name: str) -> AgentTypeId:
        """`agent_type` is an unpartitioned registry table (contract §5.0) -- takes `project_id`
        as the FK value, but skips the RLS GUC (`_unscoped`), matching every other registry
        write.
        """
        agent_type_id = AgentTypeId(uuid4())
        with _unscoped(self._pool) as conn:
            conn.execute(
                "INSERT INTO agent_type (agent_type_id, project_id, name, created_at) "
                "VALUES (%(agent_type_id)s, %(project_id)s, %(name)s, %(created_at)s)",
                {
                    "agent_type_id": agent_type_id,
                    "project_id": project_id,
                    "name": name,
                    "created_at": self._clock.now(),
                },
            )
        return agent_type_id

    def register_agent(
        self, project_id: ProjectId, principal_id: PrincipalId, agent_type_id: AgentTypeId
    ) -> None:
        """Binds principal -> project -> agent_type (`UNIQUE(principal_id)`); this row is what
        makes `resolve_project` possible at all (PLAN.md §5). A second registration for the same
        principal raises `DuplicateRegistration`, never silently rebinding scope.
        """
        with _unscoped(self._pool) as conn:
            try:
                conn.execute(
                    "INSERT INTO agent_registration "
                    "(principal_id, project_id, agent_type_id, registered_at) "
                    "VALUES (%(principal_id)s, %(project_id)s, %(agent_type_id)s, %(registered_at)s)",
                    {
                        "principal_id": principal_id,
                        "project_id": project_id,
                        "agent_type_id": agent_type_id,
                        "registered_at": self._clock.now(),
                    },
                )
            except pg_errors.UniqueViolation as exc:
                raise DuplicateRegistration("principal already registered") from exc

    def create_agent_registration(
        self,
        project_id: ProjectId,
        agent_type_name: str,
        principal_kind: Literal["oidc_sub", "api_key"],
        external_ref: str,
        key_hash: str | None,
    ) -> tuple[PrincipalId, AgentTypeId]:
        """The three registry writes of `POST /admin/agents/register` (contract §9.3) in ONE
        transaction (C-30).

        Composed here rather than in the route because `_unscoped` is module-private and a
        transaction cannot span three separate `Repo` calls, each of which opens and commits
        its own. As three calls, a `DuplicateRegistration` on the last one committed an
        `agent_type` row and -- worse -- an `api_key` `principal` row whose `key_hash` is live
        but whose plaintext was returned to nobody: an undead credential, deposited by every
        failed retry of an idempotent-looking admin call. The write order is forced by the FK
        chain (agent_type <- agent_registration -> principal), so no reordering fixes it.

        `agent_type` is get-or-create by `(project_id, name)`, which is exactly the constraint
        the table declares -- this is what makes §9.3's "creates agent_type if new" true rather
        than aspirational, and it is why re-registering a second agent under an existing type
        no longer forks a duplicate type row.
        """
        principal_id = PrincipalId(uuid4())
        now = self._clock.now()
        with _unscoped(self._pool) as conn, conn.cursor() as cur:
            cur.execute(
                "INSERT INTO agent_type (agent_type_id, project_id, name, created_at) "
                "VALUES (%(agent_type_id)s, %(project_id)s, %(name)s, %(created_at)s) "
                "ON CONFLICT (project_id, name) DO UPDATE SET name = EXCLUDED.name "
                "RETURNING agent_type_id",
                {
                    "agent_type_id": AgentTypeId(uuid4()),
                    "project_id": project_id,
                    "name": agent_type_name,
                    "created_at": now,
                },
            )
            # DO UPDATE, not DO NOTHING: DO NOTHING suppresses the RETURNING row on conflict,
            # which would make the existing type's id unreachable without a second round trip.
            type_row = cur.fetchone()
            if type_row is None:  # pragma: no cover - RETURNING always yields on upsert
                raise RuntimeError("agent_type upsert returned no row")
            agent_type_id = AgentTypeId(type_row[0])

            try:
                cur.execute(
                    "INSERT INTO principal "
                    "(principal_id, kind, external_ref, key_hash, created_at) "
                    "VALUES (%(principal_id)s, %(kind)s, %(external_ref)s, %(key_hash)s,"
                    " %(created_at)s)",
                    {
                        "principal_id": principal_id,
                        "kind": principal_kind,
                        "external_ref": external_ref,
                        "key_hash": key_hash,
                        "created_at": now,
                    },
                )
            except pg_errors.UniqueViolation as exc:
                # `UNIQUE(kind, external_ref)`: re-registering an OIDC `sub` that already has a
                # principal. Same `DuplicateRegistration` (and so the same 409 body) as the
                # agent_registration collision below -- deliberately indistinguishable, because
                # telling an admin-key holder *which* uniqueness constraint fired is a registry
                # enumeration oracle for exactly the identities that decide project scope.
                raise DuplicateRegistration("principal already registered") from exc
            try:
                cur.execute(
                    "INSERT INTO agent_registration "
                    "(principal_id, project_id, agent_type_id, registered_at) "
                    "VALUES (%(principal_id)s, %(project_id)s, %(agent_type_id)s, %(registered_at)s)",
                    {
                        "principal_id": principal_id,
                        "project_id": project_id,
                        "agent_type_id": agent_type_id,
                        "registered_at": now,
                    },
                )
            except pg_errors.UniqueViolation as exc:
                # Rolls back the principal and any newly-created agent_type with it, because
                # all three statements share the one `_unscoped` transaction.
                raise DuplicateRegistration("principal already registered") from exc
        return principal_id, agent_type_id

    # ------------------------------------------------------------------ memory -------------

    def insert_memory_item(
        self, project_id: ProjectId, item: NewMemoryItem, scan_verdict: ScanVerdict
    ) -> MemoryId:
        """PLAN.md §2 invariant 6. Fixed order, never reordered, neither exception ever caught
        here: `validate_provenance` (pure, no I/O) -> `verify_verdict` against this content's
        *actual* hash (rejects a forged verdict or one issued for different content) -> INSERT.
        """
        assert_legal_creation_status(item.status)
        validate_provenance(item.provenance)
        ch = content_hash(item.content)
        verify_verdict(scan_verdict, ch)
        with scoped(self._pool, project_id) as conn:
            return self._impl_insert_memory_item(conn, project_id, item, scan_verdict, ch)

    def _impl_insert_memory_item(
        self,
        conn: psycopg.Connection[Any],
        project_id: ProjectId,
        item: NewMemoryItem,
        scan_verdict: ScanVerdict,
        content_hash_hex: str,
    ) -> MemoryId:
        memory_id = item.id if item.id is not None else mint_memory_id()
        now = self._clock.now()
        conn.execute(
            """
            INSERT INTO memory_item (
                id, project_id, scope_type, scope_id, mem_type, kind, lane, trust_tier, status,
                content, content_hash, token_count, subject_tag, q_value, confidence,
                scored_use_count, strike_count, cluster_id, ttl_class, pinned, valid_from,
                valid_to, created_at, status_changed_at, provenance, scan_verdict_id,
                schema_version
            ) VALUES (
                %(id)s, %(project_id)s, %(scope_type)s, %(scope_id)s, %(mem_type)s, %(kind)s,
                %(lane)s, %(trust_tier)s, %(status)s, %(content)s, %(content_hash)s,
                %(token_count)s, %(subject_tag)s, %(q_value)s, %(confidence)s,
                %(scored_use_count)s, %(strike_count)s, %(cluster_id)s, %(ttl_class)s,
                %(pinned)s, %(valid_from)s, %(valid_to)s, %(created_at)s, %(status_changed_at)s,
                %(provenance)s, %(scan_verdict_id)s, %(schema_version)s
            )
            """,
            {
                "id": memory_id,
                "project_id": project_id,
                "scope_type": item.scope_type.value,
                "scope_id": item.scope_id,
                "mem_type": item.mem_type.value,
                "kind": item.kind,
                "lane": item.lane.value,
                "trust_tier": item.trust_tier.value,
                "status": item.status.value,
                "content": item.content,
                "content_hash": content_hash_hex,
                "token_count": item.token_count,
                "subject_tag": item.subject_tag,
                "q_value": _INITIAL_Q_VALUE,
                "confidence": _INITIAL_CONFIDENCE,
                "scored_use_count": 0,
                "strike_count": 0,
                "cluster_id": item.cluster_id,
                "ttl_class": item.ttl_class,
                # migrations/0002_partitioned.sql kept a separate `pinned boolean` column
                # alongside `status` (PLAN.md's DDL sketch listed both; D-014 makes `status`
                # the single source of truth). Derived from status here, never caller-set, so
                # the two columns cannot disagree.
                "pinned": item.status is Status.PINNED,
                "valid_from": item.valid_from,
                "valid_to": item.valid_to,
                "created_at": now,
                "status_changed_at": now,
                "provenance": Json(item.provenance.to_json()),
                "scan_verdict_id": scan_verdict.verdict_id,
                "schema_version": item.schema_version,
            },
        )
        return memory_id

    # ---------------------------------------------------------------- proposals ------------
    # `workflow.agent_control.AgentControlRepoPort`'s three proposal queries plus the one
    # method that makes the caps hold across processes. See `PROPOSAL_CAP_LOCK_CLASS`.

    def count_proposals_in_run(self, project_id: ProjectId, run_id: RunId) -> int:
        with scoped(self._pool, project_id) as conn:
            return self._impl_count_proposals_in_run(conn, project_id, run_id)

    def _impl_count_proposals_in_run(
        self, conn: psycopg.Connection[Any], project_id: ProjectId, run_id: RunId
    ) -> int:
        row = conn.execute(_COUNT_PROPOSALS_IN_RUN_SQL, _proposal_run_params(project_id, run_id)).fetchone()
        return _scalar_count(row)

    def count_proposals_in_project_day(self, project_id: ProjectId, day: date) -> int:
        """Proposals created on `day` **as a UTC calendar day**.

        The bounds are computed here, in Python, as an explicit half-open UTC range --
        never `DATE(created_at) = %(day)s`. `created_at` is `timestamptz`, and
        `DATE(timestamptz)` renders it in the SESSION's `TimeZone` setting: the same row
        would fall on different "days" for two connections, so a per-UTC-day cap would
        silently become a per-server-local-day cap. A half-open range is also sargable
        against a plain `(project_id, created_at)` index, which `DATE(...)` is not.
        """
        with scoped(self._pool, project_id) as conn:
            return self._impl_count_proposals_in_project_day(conn, project_id, day)

    def _impl_count_proposals_in_project_day(
        self, conn: psycopg.Connection[Any], project_id: ProjectId, day: date
    ) -> int:
        row = conn.execute(
            _COUNT_PROPOSALS_IN_DAY_SQL, _proposal_day_params(project_id, day)
        ).fetchone()
        return _scalar_count(row)

    def find_proposal_in_run(
        self, project_id: ProjectId, run_id: RunId, content_hash_hex: str
    ) -> MemoryId | None:
        with scoped(self._pool, project_id) as conn:
            return self._impl_find_proposal_in_run(conn, project_id, run_id, content_hash_hex)

    def _impl_find_proposal_in_run(
        self,
        conn: psycopg.Connection[Any],
        project_id: ProjectId,
        run_id: RunId,
        content_hash_hex: str,
    ) -> MemoryId | None:
        params = _proposal_run_params(project_id, run_id) | {"content_hash": content_hash_hex}
        row = conn.execute(_FIND_PROPOSAL_SQL, params).fetchone()
        return None if row is None else MemoryId(row[0])

    def insert_proposal_within_caps(
        self,
        project_id: ProjectId,
        run_id: RunId,
        item: NewMemoryItem,
        scan_verdict: ScanVerdict,
        *,
        per_run_cap: int,
        per_project_daily_cap: int,
        day: date,
    ) -> ProposalInsertResult:
        """Dedup-check, both caps, and the INSERT as ONE transaction, serialised across
        every process that shares this database.

        The caps are a read-modify-write over durable state. `AgentControl._cap_lock`
        makes them exact for one process; two API/worker processes counting concurrently
        both observe `count == cap - 1` and both land, so the durable control has to be
        here. It is a transaction-scoped advisory lock keyed on the project
        (`pg_advisory_xact_lock`), taken as the first statement, released by COMMIT or
        ROLLBACK with no unlock path to forget. An advisory lock rather than `SELECT ...
        FOR UPDATE` because there is no existing row to lock: the thing being serialised
        is a COUNT, and a count has nothing to take a row lock on. Contention is bounded
        by the very control it protects (`proposals.per_project_daily_cap`, 50/day).

        The order is deliberate and matches `AgentControl.submit_proposal`'s: dedup
        first (a redelivery must not consume a cap slot), then per-run, then per-day.
        """
        assert_legal_creation_status(item.status)
        validate_provenance(item.provenance)
        ch = content_hash(item.content)
        verify_verdict(scan_verdict, ch)
        with scoped(self._pool, project_id) as conn:
            conn.execute(
                "SELECT pg_advisory_xact_lock(%(cls)s, hashtext(%(project_id)s::text))",
                {"cls": PROPOSAL_CAP_LOCK_CLASS, "project_id": project_id},
            )
            existing = self._impl_find_proposal_in_run(conn, project_id, run_id, ch)
            if existing is not None:
                return ProposalInsertResult(
                    outcome=ProposalCapOutcome.DUPLICATE, memory_id=existing, observed_count=0
                )
            run_count = self._impl_count_proposals_in_run(conn, project_id, run_id)
            if run_count >= per_run_cap:
                return ProposalInsertResult(
                    outcome=ProposalCapOutcome.PER_RUN_CAP, memory_id=None, observed_count=run_count
                )
            day_count = self._impl_count_proposals_in_project_day(conn, project_id, day)
            if day_count >= per_project_daily_cap:
                return ProposalInsertResult(
                    outcome=ProposalCapOutcome.PER_PROJECT_DAILY_CAP,
                    memory_id=None,
                    observed_count=day_count,
                )
            memory_id = self._impl_insert_memory_item(conn, project_id, item, scan_verdict, ch)
        return ProposalInsertResult(
            outcome=ProposalCapOutcome.INSERTED, memory_id=memory_id, observed_count=run_count
        )

    def get_memory_by_id(self, project_id: ProjectId, memory_id: MemoryId) -> MemoryItemRow:
        with scoped(self._pool, project_id) as conn:
            return self._impl_get_memory_by_id(conn, project_id, memory_id)

    def _impl_get_memory_by_id(
        self, conn: psycopg.Connection[Any], project_id: ProjectId, memory_id: MemoryId
    ) -> MemoryItemRow:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                # _MEMORY_ITEM_COLUMNS is a fixed module constant, never caller data.
                f"SELECT {_MEMORY_ITEM_COLUMNS} FROM memory_item "  # noqa: S608
                "WHERE project_id = %(project_id)s AND id = %(id)s",
                {"project_id": project_id, "id": memory_id},
            )
            row = cur.fetchone()
        if row is None:
            # Deliberately identical for "does not exist" and "not your project" (leak-suite
            # probe 2). RLS plus the explicit WHERE project_id already collapsed both cases to
            # "zero rows" before this branch runs -- there is nothing left here that could leak.
            raise NotFound(_NOT_FOUND_MESSAGE)
        return _row_to_memory_item(row)

    def list_memories(
        self,
        project_id: ProjectId,
        *,
        statuses: Sequence[Status] | None = None,
        limit: int = 100,
    ) -> list[MemoryItemRow]:
        """`statuses=None` means "every status"; `statuses=[]` means "none of them" and returns
        an empty list without a query. The previous truthiness test (`if statuses:`) collapsed
        those two into "every status", so a caller that filtered its status list down to nothing
        -- e.g. a retrieval predicate intersecting `RETRIEVABLE_STATUSES` with a killswitch
        overlay that disabled everything -- received the WHOLE vault, quarantined and tombstoned
        rows included. That is a fail-open filter (PLAN.md §2 invariant 7).
        """
        if statuses is not None and not statuses:
            return []
        bounded = _bounded_limit(limit)
        with scoped(self._pool, project_id) as conn, conn.cursor(row_factory=dict_row) as cur:
            if statuses is not None:
                cur.execute(
                    f"SELECT {_MEMORY_ITEM_COLUMNS} FROM memory_item "  # noqa: S608
                    "WHERE project_id = %(project_id)s "
                    "AND status = ANY(%(statuses)s) ORDER BY created_at DESC LIMIT %(limit)s",
                    {
                        "project_id": project_id,
                        "statuses": [s.value for s in statuses],
                        "limit": bounded,
                    },
                )
            else:
                cur.execute(
                    f"SELECT {_MEMORY_ITEM_COLUMNS} FROM memory_item "  # noqa: S608
                    "WHERE project_id = %(project_id)s "
                    "ORDER BY created_at DESC LIMIT %(limit)s",
                    {"project_id": project_id, "limit": bounded},
                )
            rows = cur.fetchall()
        return [_row_to_memory_item(r) for r in rows]

    # ------------------------------------------------------------------ trace index --------

    def upsert_trace_index(self, project_id: ProjectId, row: TraceIndexUpsert) -> None:
        with scoped(self._pool, project_id) as conn:
            self._impl_upsert_trace_index(conn, project_id, row)

    def _impl_upsert_trace_index(
        self, conn: psycopg.Connection[Any], project_id: ProjectId, row: TraceIndexUpsert
    ) -> None:
        conn.execute(_TRACE_INDEX_UPSERT_SQL, _trace_index_params(project_id, row))
        kept = conn.execute(
            _TRACE_INDEX_IDENTITY_SELECT_SQL, {"project_id": project_id, "run_id": row.run_id}
        ).fetchone()
        if kept is None:
            # `(project_id, run_id)` is `trace_index`'s primary key, so a genuine Postgres
            # connection always has a row here -- the upsert above just committed one. `None`
            # only happens against a fake/stub connection (the offline `Repo` test suite's
            # connections assert on STATEMENTS issued, not results, and their default
            # cursor's `fetchone()` always returns `None`). There is no evidence to compare
            # in that case, so there is nothing to log.
            return
        kept_principal_uuid, kept_signature = kept
        kept_principal = PrincipalId(kept_principal_uuid)
        claimed_signature = bytes(row.input_signature_hash)
        # A claimed `ABSENT_SIGNATURE` is not a claim at all -- it is `trace_writer.
        # _identity_columns`'s "this batch carried no run_start" sentinel (C-07). Comparing it
        # like a rival signature would warn on the ordinary out-of-order batch, i.e. it would
        # cry Sybil on the single most common shape of at-least-once delivery, and a signal that
        # fires on the normal path is a signal nobody reads.
        signature_conflict = (
            not is_absent_signature(claimed_signature) and bytes(kept_signature) != claimed_signature
        )
        if kept_principal != row.submitter_principal or signature_conflict:
            # The COALESCE fix above means THIS call's claimed identity lost to
            # first-write-wins -- correct for D-020's independence evidence, but a second
            # principal or signature cluster claiming the same run_id is itself a signal:
            # either a retry that picked up the wrong credential (a bug) or an attempted
            # Sybil/spoofing collision against `workers.independence` corroboration. Discarding
            # it without a trace would mean nobody could ever notice either possibility
            # occurred. `logger.warning`, not raise: the write already did the safe thing, and
            # raising here would turn an at-least-once retry into an ingest outage over a
            # signal, not a failure.
            logger.warning(
                "trace_index identity conflict on run_id=%s project_id=%s: kept "
                "submitter_principal=%s input_signature_hash=%s (first write); this upsert "
                "claimed submitter_principal=%s input_signature_hash=%s instead. "
                "First-write-wins kept the original evidence; investigate this as a "
                "possible retry bug or Sybil/spoofing attempt (D-020).",
                row.run_id,
                project_id,
                kept_principal,
                bytes(kept_signature).hex(),
                row.submitter_principal,
                claimed_signature.hex(),
            )

    def get_trace_index(self, project_id: ProjectId, run_id: RunId) -> TraceIndexRow:
        with scoped(self._pool, project_id) as conn:
            return self._impl_get_trace_index(conn, project_id, run_id)

    def _impl_get_trace_index(
        self,
        conn: psycopg.Connection[Any],
        project_id: ProjectId,
        run_id: RunId,
        *,
        for_update: bool = False,
    ) -> TraceIndexRow:
        if for_update:
            # C-32. `_TRACE_INDEX_UPSERT_SQL` replaces `path` wholesale (a jsonb column cannot be
            # per-key merged by ON CONFLICT), so two ingest workers holding different batches of
            # the SAME run both read the pre-batch `path` and the last commit wins: the loser's
            # `seq_ranges` vanish (a complete run can stay pinned at `incomplete`) and, worse,
            # its `payload_refs` entry vanishes -- orphaning the only pointer to that batch's
            # stored ciphertext.
            #
            # `SELECT ... FOR UPDATE` alone is not enough: it locks nothing when the row does not
            # exist yet, which is exactly the first-batch case where two workers race to create
            # it. The transaction-scoped advisory lock covers both, is taken on the (project,
            # run) pair rather than the table, and is released by COMMIT/ROLLBACK with no
            # unlock path to forget.
            conn.execute(
                "SELECT pg_advisory_xact_lock("
                "  hashtextextended(%(project_id)s::text || ':' || %(run_id)s::text, 0))",
                {"project_id": project_id, "run_id": run_id},
            )
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                # _TRACE_INDEX_COLUMNS is a fixed module constant (the exact column list,
                # contract §5.2), never caller data -- nothing here is interpolated.
                f"SELECT {_TRACE_INDEX_COLUMNS} FROM trace_index "  # noqa: S608
                "WHERE project_id = %(project_id)s AND run_id = %(run_id)s"
                + (" FOR UPDATE" if for_update else ""),
                {"project_id": project_id, "run_id": run_id},
            )
            row = cur.fetchone()
        if row is None:
            raise NotFound(_NOT_FOUND_MESSAGE)
        return _row_to_trace_index(row)

    def list_runs(self, project_id: ProjectId, *, limit: int = 100) -> list[TraceIndexRow]:
        with scoped(self._pool, project_id) as conn, conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                f"SELECT {_TRACE_INDEX_COLUMNS} FROM trace_index "  # noqa: S608
                "WHERE project_id = %(project_id)s "
                "ORDER BY started_at DESC NULLS LAST LIMIT %(limit)s",
                {"project_id": project_id, "limit": _bounded_limit(limit)},
            )
            rows = cur.fetchall()
        return [_row_to_trace_index(r) for r in rows]

    def find_runs_missing_sentinel(
        self, project_id: ProjectId, older_than: datetime, *, limit: int = MAX_SWEEP_BATCH
    ) -> list[RunId]:
        """Feeds `ingest.trace_writer.sweep_incomplete` (contract §11).

        `older_than` MUST be timezone-aware: `started_at` is `timestamptz` and a naive bound
        would be interpreted in the server's session timezone, making the sweep window depend on
        where the process runs rather than on the injected `Clock`. Rejected rather than silently
        coerced -- a sweeper whose cut-off is hours off either resurrects finished runs or never
        fires, and both are invisible.

        CAVEAT (contract_gap): `trace_index` has no ingestion-time column independent of
        `started_at` (business event time from `run_start`), so a run that never had a
        `run_start` at all falls back to the epoch here and is swept eagerly -- migrations should
        consider adding a `first_seen_at` server timestamp if that proves too eager in practice.
        """
        if older_than.tzinfo is None or older_than.utcoffset() is None:
            raise ValueError("find_runs_missing_sentinel requires a timezone-aware `older_than`")
        with scoped(self._pool, project_id) as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT run_id FROM trace_index WHERE project_id = %(project_id)s "
                "AND outcome_status = %(pending)s "
                # TIMESTAMPTZ, not TIMESTAMP: `COALESCE(timestamptz, timestamp)` would cast the
                # literal through the session timezone, so "epoch" would mean a different
                # instant on a server that is not UTC.
                "AND COALESCE(started_at, TIMESTAMPTZ 'epoch') < %(older_than)s "
                "ORDER BY started_at NULLS FIRST LIMIT %(limit)s",
                {
                    "project_id": project_id,
                    "pending": TraceOutcomeStatus.PENDING.value,
                    "older_than": older_than,
                    "limit": max(1, min(limit, MAX_SWEEP_BATCH)),
                },
            )
            rows = cur.fetchall()
        return [RunId(r[0]) for r in rows]

    def mark_run_incomplete(self, project_id: ProjectId, run_id: RunId) -> None:
        """Only ever moves a run OUT of 'pending'. The sweeper reads with
        `find_runs_missing_sentinel` and writes here in a separate transaction, so a `run_end`
        can land in between; without the status predicate that race overwrote a legitimately
        complete run with 'incomplete' and the distiller then permanently refused it (PLAN.md
        §3). The predicate makes the write a no-op instead.
        """
        with scoped(self._pool, project_id) as conn:
            conn.execute(
                "UPDATE trace_index SET outcome_status = %(status)s "
                "WHERE project_id = %(project_id)s AND run_id = %(run_id)s "
                "AND outcome_status = %(pending)s",
                {
                    "status": TraceOutcomeStatus.INCOMPLETE.value,
                    "pending": TraceOutcomeStatus.PENDING.value,
                    "project_id": project_id,
                    "run_id": run_id,
                },
            )

    def append_trace_subject(
        self, project_id: ProjectId, run_id: RunId, subject_tags: Sequence[str]
    ) -> None:
        with scoped(self._pool, project_id) as conn:
            self._impl_append_trace_subject(conn, project_id, run_id, subject_tags)

    def _impl_append_trace_subject(
        self, conn: psycopg.Connection[Any], project_id: ProjectId, run_id: RunId, subject_tags: Sequence[str]
    ) -> None:
        # `subject_tags` originates in a caller-supplied trace payload (`SUBJECT_TAGS_KEY` on
        # state_note/artifact_ref, contract C-05), so the same tag repeated N times is one
        # cheap way for a client to turn one event into N round-trips. De-duplicated here,
        # order-preserving, so the statement count is bounded by the number of DISTINCT tags.
        # A cap on tag COUNT and LENGTH belongs to the ingest validator, not to storage --
        # reported as a cross-chunk issue.
        deduped = list(dict.fromkeys(subject_tags))
        if not deduped:
            return
        with conn.cursor() as cur:
            cur.executemany(
                "INSERT INTO trace_subject (run_id, project_id, subject_tag) "
                "VALUES (%(run_id)s, %(project_id)s, %(subject_tag)s) "
                "ON CONFLICT (project_id, run_id, subject_tag) DO NOTHING",
                [
                    {"run_id": run_id, "project_id": project_id, "subject_tag": tag}
                    for tag in deduped
                ],
            )

    # ------------------------------------------------------------------ outcomes -----------

    def insert_outcome_event(self, project_id: ProjectId, row: OutcomeEventInsert) -> bool:
        """`ON CONFLICT (project_id, event_id) DO NOTHING`; returns `False` on a replayed
        `event_id` (contract §5.1) -- `ingest.outcome_intake` relies on this for replay safety.
        """
        with scoped(self._pool, project_id) as conn:
            return self._impl_insert_outcome_event(conn, project_id, row)

    def _impl_insert_outcome_event(
        self, conn: psycopg.Connection[Any], project_id: ProjectId, row: OutcomeEventInsert
    ) -> bool:
        # C-10: w=0 is never a schema column (w is server-derived, never caller data) -- it is
        # folded into payload["_w_zero"] here, the one place that reserved key is written.
        payload = dict(row.payload)
        payload["_w_zero"] = row.w_zero
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO outcome_event (
                    event_id, run_id, project_id, principal_id, adapter, r, payload,
                    occurred_at, arrived_at
                ) VALUES (
                    %(event_id)s, %(run_id)s, %(project_id)s, %(principal_id)s, %(adapter)s,
                    %(r)s, %(payload)s, %(occurred_at)s, %(arrived_at)s
                )
                ON CONFLICT (project_id, event_id) DO NOTHING
                RETURNING event_id
                """,
                {
                    "event_id": row.event_id,
                    "run_id": row.run_id,
                    "project_id": project_id,
                    "principal_id": row.principal_id,
                    "adapter": row.adapter.value,
                    "r": row.r,
                    "payload": Json(payload),
                    "occurred_at": row.occurred_at,
                    "arrived_at": row.arrived_at,
                },
            )
            inserted = cur.fetchone() is not None
        return inserted

    # ------------------------------------------------------------------ telemetry ----------

    def insert_retrieval_event(self, project_id: ProjectId, row: RetrievalEventInsert) -> None:
        with scoped(self._pool, project_id) as conn:
            self._impl_insert_retrieval_event(conn, project_id, row)

    def _impl_insert_retrieval_event(
        self, conn: psycopg.Connection[Any], project_id: ProjectId, row: RetrievalEventInsert
    ) -> None:
        conn.execute(
            """
            INSERT INTO retrieval_event (
                run_id, project_id, outcome_code, latency_ms, embed_latency_ms,
                candidates_considered, top_score, arm, created_at
            ) VALUES (
                %(run_id)s, %(project_id)s, %(outcome_code)s, %(latency_ms)s,
                %(embed_latency_ms)s, %(candidates_considered)s, %(top_score)s, %(arm)s,
                %(created_at)s
            )
            """,
            {
                "run_id": row.run_id,
                "project_id": project_id,
                "outcome_code": row.outcome_code.value,
                "latency_ms": row.latency_ms,
                "embed_latency_ms": row.embed_latency_ms,
                "candidates_considered": row.candidates_considered,
                "top_score": row.top_score,
                "arm": row.arm.value,
                "created_at": self._clock.now(),
            },
        )

    def insert_injection_rows(
        self, project_id: ProjectId, run_id: RunId, rows: Sequence[InjectionRow]
    ) -> None:
        with scoped(self._pool, project_id) as conn:
            self._impl_insert_injection_rows(conn, project_id, run_id, rows)

    def _impl_insert_injection_rows(
        self, conn: psycopg.Connection[Any], project_id: ProjectId, run_id: RunId, rows: Sequence[InjectionRow]
    ) -> None:
        if not rows:
            return
        now = self._clock.now()
        with conn.cursor() as cur:
            cur.executemany(
                """
                INSERT INTO injection_log (run_id, project_id, memory_id, slot, score, tokens,
                                            injected_at)
                VALUES (%(run_id)s, %(project_id)s, %(memory_id)s, %(slot)s, %(score)s,
                        %(tokens)s, %(injected_at)s)
                ON CONFLICT (project_id, run_id, memory_id) DO NOTHING
                """,
                [
                    {
                        "run_id": run_id,
                        "project_id": project_id,
                        "memory_id": r.memory_id,
                        "slot": r.slot.value,
                        "score": r.score,
                        "tokens": r.tokens,
                        "injected_at": now,
                    }
                    for r in rows
                ],
            )

    def spend_add(
        self,
        project_id: ProjectId,
        day: date,
        worker: str,
        model_id: str,
        tokens_in: int,
        tokens_out: int,
        cost_usd: float,
    ) -> None:
        """Accumulates into `spend_ledger` (contract §5.1) -- each call adds to the running
        (day, worker, model_id) cell rather than overwriting it.
        """
        with scoped(self._pool, project_id) as conn:
            conn.execute(
                """
                INSERT INTO spend_ledger (project_id, day, worker, model_id, tokens_in,
                                           tokens_out, cost_usd)
                VALUES (%(project_id)s, %(day)s, %(worker)s, %(model_id)s, %(tokens_in)s,
                        %(tokens_out)s, %(cost_usd)s)
                ON CONFLICT (project_id, day, worker, model_id) DO UPDATE SET
                    tokens_in = spend_ledger.tokens_in + EXCLUDED.tokens_in,
                    tokens_out = spend_ledger.tokens_out + EXCLUDED.tokens_out,
                    cost_usd = spend_ledger.cost_usd + EXCLUDED.cost_usd
                """,
                {
                    "project_id": project_id,
                    "day": day,
                    "worker": worker,
                    "model_id": model_id,
                    "tokens_in": tokens_in,
                    "tokens_out": tokens_out,
                    "cost_usd": cost_usd,
                },
            )

    def spend_by_day(self, project_id: ProjectId, day: date) -> list[SpendRow]:
        with scoped(self._pool, project_id) as conn, conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                "SELECT day, worker, model_id, tokens_in, tokens_out, cost_usd FROM spend_ledger "
                "WHERE project_id = %(project_id)s AND day = %(day)s",
                {"project_id": project_id, "day": day},
            )
            rows = cur.fetchall()
        # `spend_ledger.cost_usd` is `numeric(14,6)` (migrations/0002), which psycopg loads as
        # `decimal.Decimal`. `SpendRow.cost_usd` is declared `float` and `SpendMeter.check_cap`
        # compares it against `SpendConfig.daily_llm_cap_usd` (a float): `Decimal + float` and
        # `sum(..., 0.0)` both raise TypeError, so the spend cap would blow up on the first
        # non-empty ledger instead of pausing workers. Converted once, here, at the boundary.
        return [
            SpendRow(
                day=r["day"],
                worker=r["worker"],
                model_id=r["model_id"],
                tokens_in=int(r["tokens_in"]),
                tokens_out=int(r["tokens_out"]),
                cost_usd=float(r["cost_usd"]),
            )
            for r in rows
        ]

    def spend_since(self, project_id: ProjectId, since: date) -> list[SpendRow]:
        """Every ledger cell on or after `since`, oldest day first (D-093).

        `spend_by_day` answers the spend METER's question ("has today's cap been
        reached"). A dashboard asking "what has this project been spending" needs a
        window, and looping `spend_by_day` over N dates is N round trips whose result
        set is indistinguishable from this one. Bounded by `MAX_ROW_LIMIT` for the same
        reason every other read here is: a caller-chosen `since` of 1970 is otherwise an
        unbounded server-side allocation.
        """
        with scoped(self._pool, project_id) as conn, conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                "SELECT day, worker, model_id, tokens_in, tokens_out, cost_usd FROM spend_ledger "
                "WHERE project_id = %(project_id)s AND day >= %(since)s "
                "ORDER BY day ASC, worker ASC, model_id ASC LIMIT %(limit)s",
                {"project_id": project_id, "since": since, "limit": MAX_ROW_LIMIT},
            )
            rows = cur.fetchall()
        return [
            SpendRow(
                day=r["day"],
                worker=r["worker"],
                model_id=r["model_id"],
                tokens_in=int(r["tokens_in"]),
                tokens_out=int(r["tokens_out"]),
                cost_usd=float(r["cost_usd"]),
            )
            for r in rows
        ]

    # ------------------------------------------------------------------ subject keys -------

    def get_subject_key(self, project_id: ProjectId, subject_tag: str) -> SubjectKeyRow | None:
        with scoped(self._pool, project_id) as conn, conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                "SELECT subject_tag, key_id, wrapped_kek, created_at, destroyed_at "
                "FROM subject_key WHERE project_id = %(project_id)s "
                "AND subject_tag = %(subject_tag)s",
                {"project_id": project_id, "subject_tag": subject_tag},
            )
            row = cur.fetchone()
        if row is None:
            return None
        return SubjectKeyRow(
            subject_tag=row["subject_tag"],
            key_id=row["key_id"],
            wrapped_kek=bytes(row["wrapped_kek"]),
            created_at=row["created_at"],
            destroyed_at=row["destroyed_at"],
        )

    def insert_subject_key(
        self, project_id: ProjectId, subject_tag: str, key_id: UUID, wrapped_kek: bytes
    ) -> None:
        with scoped(self._pool, project_id) as conn:
            conn.execute(
                "INSERT INTO subject_key (project_id, subject_tag, key_id, wrapped_kek, "
                "created_at) VALUES (%(project_id)s, %(subject_tag)s, %(key_id)s, "
                "%(wrapped_kek)s, %(created_at)s)",
                {
                    "project_id": project_id,
                    "subject_tag": subject_tag,
                    "key_id": key_id,
                    "wrapped_kek": wrapped_kek,
                    "created_at": self._clock.now(),
                },
            )

    def destroy_subject_key(self, project_id: ProjectId, subject_tag: str) -> bool:
        """Crypto-shredding (PHASE-0 Task 10): zeroes `wrapped_kek` and stamps `destroyed_at`.
        `False` iff no row exists for this `(project_id, subject_tag)`; re-destroying an already
        -destroyed key is idempotent and still returns `True`.

        `destroyed_at` is set with `COALESCE` so a repeat call cannot move it. The first value is
        the record of WHEN the erasure happened -- the evidence an erasure request was honoured
        within its statutory window. A retry, a replayed queue item, or an operator clicking twice
        would otherwise silently rewrite that timestamp forward, and the original is unrecoverable
        (the row is the only place it exists).
        """
        with scoped(self._pool, project_id) as conn, conn.cursor() as cur:
            cur.execute(
                "UPDATE subject_key "
                "SET destroyed_at = COALESCE(destroyed_at, %(destroyed_at)s), "
                "    wrapped_kek = %(empty)s "
                "WHERE project_id = %(project_id)s AND subject_tag = %(subject_tag)s "
                "RETURNING subject_tag",
                {
                    "destroyed_at": self._clock.now(),
                    "empty": b"",
                    "project_id": project_id,
                    "subject_tag": subject_tag,
                },
            )
            return cur.fetchone() is not None

    # ------------------------------------------------------------------ review + config ----

    def insert_review_item(
        self, project_id: ProjectId, reason: str, memory_id: MemoryId | None = None
    ) -> None:
        with scoped(self._pool, project_id) as conn:
            conn.execute(
                "INSERT INTO review_queue (project_id, item_id, reason, memory_id, opened_at) "
                "VALUES (%(project_id)s, %(item_id)s, %(reason)s, %(memory_id)s, %(opened_at)s)",
                {
                    "project_id": project_id,
                    "item_id": uuid4(),
                    "reason": reason,
                    "memory_id": memory_id,
                    "opened_at": self._clock.now(),
                },
            )

    def list_review_items(
        self, project_id: ProjectId, *, include_resolved: bool = False, limit: int = 100
    ) -> list[ReviewQueueRow]:
        """`review_queue` rows, newest first (D-093).

        Open items only by default. The queue is the human backstop for decisions the
        machine refused to make on its own (retirement below K distinct principals,
        PLAN.md §6 `retirement.min_distinct_principals`); a reader that mixed resolved
        history into the default view would bury the items that still need a decision
        under the ones that already got one.
        """
        bounded = _bounded_limit(limit)
        clause = "" if include_resolved else "AND resolved_at IS NULL "
        with scoped(self._pool, project_id) as conn, conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                # `clause` is one of two module-local literals chosen by a bool -- never
                # caller text. Same pattern as `_MEMORY_ITEM_COLUMNS` above.
                "SELECT item_id, reason, memory_id, opened_at, resolved_at, resolution "  # noqa: S608
                "FROM review_queue WHERE project_id = %(project_id)s "
                f"{clause}"
                "ORDER BY opened_at DESC LIMIT %(limit)s",
                {"project_id": project_id, "limit": bounded},
            )
            rows = cur.fetchall()
        return [
            ReviewQueueRow(
                item_id=r["item_id"],
                reason=r["reason"],
                memory_id=MemoryId(r["memory_id"]) if r["memory_id"] is not None else None,
                opened_at=r["opened_at"],
                resolved_at=r["resolved_at"],
                resolution=r["resolution"],
            )
            for r in rows
        ]

    def list_killswitch_state(self, project_id: ProjectId) -> list[KillswitchStateRow]:
        """Every `killswitch_state` cell for this project (D-093).

        `get_killswitch_overlay` answers the CONFIG resolver's question -- "is this
        mem_type disabled for this one agent_type" -- and deliberately returns a bare
        `mem_type -> disabled` mapping with no evidence and no timestamp, because the
        hot path must not be able to branch on either. A governance reader needs the
        opposite: the evidence and the change time are the whole point, since a
        disablement with no recorded reason is not something an operator can review.

        Every scope is returned, project-wide (`agent_type_id IS NULL`) rows included -- this
        query filters on `project_id` alone, so it never had `get_killswitch_overlay`'s D-129
        NULL-row blindness. What it does NOT return is the EFFECTIVE state: a row is one
        recorded decision, and under D-129's precedence an agent-type row reading
        `disabled=False` is still effectively disabled while a project-wide row for the same
        `mem_type` reads `disabled=True`. Reading a single row as the answer therefore
        overstates what is enabled, which is the safe direction to be wrong in but still worth
        knowing at the surface an operator checks. Resolving the pair is
        `get_killswitch_overlay`'s job and is deliberately not duplicated here: two functions
        computing "is this disabled" is how they come to disagree.
        """
        with scoped(self._pool, project_id) as conn, conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                "SELECT agent_type_id, mem_type, disabled, evidence, changed_at "
                "FROM killswitch_state WHERE project_id = %(project_id)s "
                "ORDER BY changed_at DESC LIMIT %(limit)s",
                {"project_id": project_id, "limit": MAX_ROW_LIMIT},
            )
            rows = cur.fetchall()
        return [
            KillswitchStateRow(
                agent_type_id=AgentTypeId(r["agent_type_id"])
                if r["agent_type_id"] is not None
                else None,
                mem_type=MemType(r["mem_type"]),
                disabled=bool(r["disabled"]),
                evidence=r["evidence"],
                changed_at=r["changed_at"],
            )
            for r in rows
        ]

    def insert_invalidation_event(
        self, project_id: ProjectId, event_type: str, selector: Mapping[str, object] | None = None
    ) -> UUID:
        """One `invalidation_event` row (PLAN.md §5; C-31).

        Added at integration so `POST /v1/invalidation` stops returning "accepted" for data it
        drops. `event_id` is server-generated here, matching the column's own DDL comment
        ("the caller's webhook payload never determines the row's identity") -- a caller-chosen
        event_id is a way to overwrite or collide with an existing row.

        A synchronous, scoped insert rather than a queue write: §14's queue DO-NOT list forbids
        a fourth topic, and this is a small bounded row on a low-rate route, not a trace payload.
        """
        event_id = uuid4()
        with scoped(self._pool, project_id) as conn:
            conn.execute(
                "INSERT INTO invalidation_event "
                "(project_id, event_id, event_type, selector, fired_at) "
                "VALUES (%(project_id)s, %(event_id)s, %(event_type)s, %(selector)s, %(fired_at)s)",
                {
                    "project_id": project_id,
                    "event_id": event_id,
                    "event_type": event_type,
                    "selector": Json(dict(selector)) if selector is not None else None,
                    "fired_at": self._clock.now(),
                },
            )
        return event_id

    def list_invalidation_events(
        self, project_id: ProjectId, *, limit: int = 100
    ) -> list[InvalidationEventRow]:
        """`invalidation_event` rows, newest first (D-093).

        PLAN.md's own "known open items" note records that nothing drains this table:
        `POST /v1/invalidation` writes rows and `workers.invalidator` is never fed them.
        A reader does not close that gap, and is not presented as doing so -- but an
        operator who can see the events piling up unconsumed can at least know it, which
        is strictly better than the table being invisible from every surface.
        """
        bounded = _bounded_limit(limit)
        with scoped(self._pool, project_id) as conn, conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                "SELECT event_id, event_type, selector, fired_at FROM invalidation_event "
                "WHERE project_id = %(project_id)s ORDER BY fired_at DESC LIMIT %(limit)s",
                {"project_id": project_id, "limit": bounded},
            )
            rows = cur.fetchall()
        return [
            InvalidationEventRow(
                event_id=r["event_id"],
                event_type=r["event_type"],
                selector=r["selector"],
                fired_at=r["fired_at"],
            )
            for r in rows
        ]

    def get_project_config(self, project_id: ProjectId) -> Mapping[str, object]:
        """Satisfies `domain.config.ConfigStorePort` structurally (contract §3.4)."""
        with scoped(self._pool, project_id) as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT key, value FROM project_config WHERE project_id = %(project_id)s",
                {"project_id": project_id},
            )
            rows = cur.fetchall()
        return dict(rows)

    def get_agent_type_config(
        self, project_id: ProjectId, agent_type_id: AgentTypeId
    ) -> Mapping[str, object]:
        with scoped(self._pool, project_id) as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT key, value FROM agent_type_config "
                "WHERE project_id = %(project_id)s AND agent_type_id = %(agent_type_id)s",
                {"project_id": project_id, "agent_type_id": agent_type_id},
            )
            rows = cur.fetchall()
        return dict(rows)

    def get_killswitch_overlay(
        self, project_id: ProjectId, agent_type_id: AgentTypeId | None
    ) -> Mapping[str, bool]:
        """Exact `ConfigStorePort` signature (contract §3.4): `agent_type_id` has no default, so
        a caller cannot accidentally read the project-wide overlay when it meant an agent-type
        one. A NULL `agent_type_id` row is the project-wide overlay (migrations/0001:127-141).

        D-129: the predicate matches BOTH the agent-type-specific row (`agent_type_id = %(...)s`)
        AND the project-wide row (`agent_type_id IS NULL`) in one query, not the project-wide row
        alone or the agent-type row alone -- the old `IS NOT DISTINCT FROM %(agent_type_id)s`
        predicate only ever matched one of the two, so a resolved (non-NULL) `agent_type_id`
        could never see the NULL project-wide row and the control failed OPEN while
        `list_killswitch_state` kept reporting it as active. Per-`mem_type` precedence, when both
        rows exist, is the logical OR of their `disabled` flags: whichever row says disabled
        wins. That is deliberately not "the more specific row wins" -- a project-wide DISABLE
        overrides an agent-type ENABLE (the project-wide row is the bigger hammer; an operator
        reaching for it is stating an intent about the whole project), and symmetrically an
        agent-type-specific DISABLE is never silently re-enabled by the project defaulting back
        to enabled elsewhere. Disabling is always the safer direction for a memory-injection
        control, so either row asserting it is authoritative.

        The consequence an operator will meet: while a project-wide DISABLE row stands,
        `workers.killswitch.KillswitchGridEvaluator.record_override(disabled=False)` for ONE
        agent type writes its row and is reported by `list_killswitch_state`, but changes
        nothing here. That is the intended reading of "a narrower ENABLE cannot lift a wider
        DISABLE"; the remedy is to clear the project-wide row, which is the scope the operator
        actually disagrees with. `list_killswitch_state`'s docstring carries the same warning,
        because that is the surface where the two rows are read side by side.
        """
        with scoped(self._pool, project_id) as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT mem_type, disabled FROM killswitch_state "
                "WHERE project_id = %(project_id)s "
                "AND (agent_type_id IS NULL OR agent_type_id = %(agent_type_id)s)",
                {"project_id": project_id, "agent_type_id": agent_type_id},
            )
            rows = cur.fetchall()
        overlay: dict[str, bool] = {}
        for mem_type, disabled in rows:
            overlay[mem_type] = overlay.get(mem_type, False) or bool(disabled)
        return overlay

    def set_project_config(self, project_id: ProjectId, key: str, value: object) -> None:
        """`updated_at` is written explicitly from the injected `Clock`, not left to the column
        default: `DEFAULT now()` only fires on INSERT (so an override edited a hundred times kept
        its original timestamp) and, more importantly, `now()` is the database's wall clock --
        the simulated-clock soak (PLAN.md §7 Phase 2) needs every timestamp Tracebed writes to
        move with `Clock`, never with the server (hard rule 5).
        """
        with scoped(self._pool, project_id) as conn:
            conn.execute(
                "INSERT INTO project_config (project_id, key, value, updated_at) "
                "VALUES (%(project_id)s, %(key)s, %(value)s, %(updated_at)s) "
                "ON CONFLICT (project_id, key) DO UPDATE SET "
                "value = EXCLUDED.value, updated_at = EXCLUDED.updated_at",
                {
                    "project_id": project_id,
                    "key": key,
                    "value": Json(value),
                    "updated_at": self._clock.now(),
                },
            )

    # ------------------------------------------------------------------ export -------------

    def iter_export_rows(self, project_id: ProjectId) -> Iterator[dict[str, object]]:
        """Streams `{"table": ..., "row": {...}}` for every row this project owns across
        `_EXPORT_TABLES`, scoped by the same `scoped()` GUC as everything else -- `api.export`
        turns this into the NDJSON body of `GET /export/project` (contract §9.3). The connection
        stays checked out for the lifetime of the returned iterator (standard generator +
        context-manager composition): callers must exhaust or `.close()` it.
        """
        with scoped(self._pool, project_id) as conn:
            yield from self._impl_iter_export_rows(conn, project_id)

    def _impl_iter_export_rows(
        self, conn: psycopg.Connection[Any], project_id: ProjectId
    ) -> Iterator[dict[str, object]]:
        for table in _EXPORT_TABLES:
            # SERVER-side cursor. A plain client-side cursor fetches the ENTIRE result set into
            # the process before the first `yield`, so "streaming" a project export of
            # memory_item was a full materialisation of every row (content included) in RAM --
            # the generator shape made it look streamed. `name=` makes psycopg DECLARE a cursor
            # and FETCH `itersize` rows at a time; it is legal here because `scoped()` has
            # already opened the transaction the cursor must live inside.
            #
            # The name embeds a uuid4 so two exports in one transaction cannot collide; the
            # table name comes from the fixed `_EXPORT_TABLES` constant, never caller data.
            cursor_name = f"tb_export_{table}_{uuid4().hex}"
            # Explicit per-table column list (`_EXPORT_COLUMNS`), never `SELECT *`: the latter
            # streamed `memory_item.embedding`/`lexemes` (multi-KB, no JSON encoding) for every
            # row, and silently absorbed any future column a migration added with no one having
            # decided it should leave the repository. Both the table name and the column list
            # come from fixed module constants, never caller data.
            columns = _EXPORT_COLUMNS[table]
            with conn.cursor(name=cursor_name, row_factory=dict_row) as cur:
                cur.itersize = 500
                cur.execute(
                    f"SELECT {columns} FROM {table} WHERE project_id = %(project_id)s",  # noqa: S608
                    {"project_id": project_id},
                )
                for row in cur:
                    yield {
                        "table": table,
                        "row": {str(k): _json_safe(v) for k, v in dict(row).items()},
                    }


class ScopedRepo:
    """The handle `Repo.tx()` yields: every builder mirrored from `Repo` with `project_id` and
    the connection already bound to one transaction (contract §5.0).

    Construction is gated on `_SCOPED_REPO_TOKEN`, which only `Repo.tx` holds. The class itself
    stays exported because it is the declared return type of `Repo.tx` (`Iterator[ScopedRepo]`)
    and consumers annotate against it -- but an exported name with an ordinary `__init__` is a
    public constructor, and this one would have accepted any connection at all, including one
    whose transaction never issued the RLS GUC and one opened for a DIFFERENT project than the
    `project_id` passed alongside it. Every `ScopedRepo` method then writes that `project_id`
    into its SQL, so a hand-built handle is a scope-mismatched writer that RLS can only partly
    catch (it blocks reads and cross-project writes, but a mismatched pair is exactly the case
    the docstring used to assert was impossible). The token makes the assertion true.
    """

    def __init__(
        self, repo: Repo, conn: psycopg.Connection[Any], project_id: ProjectId, *, _token: object = None
    ) -> None:
        if _token is not _SCOPED_REPO_TOKEN:
            raise TypeError(
                "ScopedRepo is not directly constructible; obtain one from Repo.tx(project_id), "
                "which is the only path that guarantees the connection's transaction has set "
                "the tracebed.project_id GUC for this exact project"
            )
        self._repo = repo
        self._conn = conn
        self._project_id = project_id

    def insert_memory_item(self, item: NewMemoryItem, scan_verdict: ScanVerdict) -> MemoryId:
        assert_legal_creation_status(item.status)
        validate_provenance(item.provenance)
        ch = content_hash(item.content)
        verify_verdict(scan_verdict, ch)
        return self._repo._impl_insert_memory_item(
            self._conn, self._project_id, item, scan_verdict, ch
        )

    def get_memory_by_id(self, memory_id: MemoryId) -> MemoryItemRow:
        return self._repo._impl_get_memory_by_id(self._conn, self._project_id, memory_id)

    def upsert_trace_index(self, row: TraceIndexUpsert) -> None:
        self._repo._impl_upsert_trace_index(self._conn, self._project_id, row)

    def get_trace_index(self, run_id: RunId, *, for_update: bool = False) -> TraceIndexRow:
        """`for_update=True` serialises concurrent writers on this run for the rest of the
        transaction (C-32) — the read-modify-write `ingest.trace_writer` performs on
        `trace_index.path` is not safe without it. Defaults to False so plain reads
        (`GET /admin/...`, the sweeper) do not take locks they have no use for."""
        return self._repo._impl_get_trace_index(
            self._conn, self._project_id, run_id, for_update=for_update
        )

    def append_trace_subject(self, run_id: RunId, subject_tags: Sequence[str]) -> None:
        self._repo._impl_append_trace_subject(
            self._conn, self._project_id, run_id, subject_tags
        )

    def insert_outcome_event(self, row: OutcomeEventInsert) -> bool:
        return self._repo._impl_insert_outcome_event(self._conn, self._project_id, row)

    def insert_retrieval_event(self, row: RetrievalEventInsert) -> None:
        self._repo._impl_insert_retrieval_event(self._conn, self._project_id, row)

    def insert_injection_rows(self, run_id: RunId, rows: Sequence[InjectionRow]) -> None:
        self._repo._impl_insert_injection_rows(self._conn, self._project_id, run_id, rows)

    def iter_export_rows(self) -> Iterator[dict[str, object]]:
        yield from self._repo._impl_iter_export_rows(self._conn, self._project_id)
