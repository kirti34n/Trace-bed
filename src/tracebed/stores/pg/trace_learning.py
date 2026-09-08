"""RLS-scoped, DB-time leases for Phase 2A trace-learning jobs.

There is intentionally no success/skip completion method here.  This store
owns only safe lease mutation and bounded recovery; P2B will add a separate
idempotent result-write path after trace reading and memory creation have a
complete contract.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from datetime import datetime, timedelta
from typing import Any, Final, cast
from uuid import UUID

from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool

from tracebed.core.scans import SUITE_VERSION, rejection_reason_codes, verify_verdict
from tracebed.core.scans.tier_a_template import parse_note
from tracebed.crypto.subject_digest import subject_digest
from tracebed.domain.canonical import canonical_json, content_hash
from tracebed.domain.config import (
    MAX_TIER_A_CANDIDATES_PER_RESULT,
    MAX_TIER_A_INDIVIDUAL_REJECTIONS_PER_RESULT,
)
from tracebed.domain.enums import Lane, MemType, ProvenanceClass, ScopeType, TrustTier
from tracebed.domain.ids import MemoryId, ProjectId, RunId
from tracebed.domain.memory import NewMemoryItem, Provenance, validate_provenance
from tracebed.domain.scan import ScanVerdict
from tracebed.domain.state_machine import Status
from tracebed.ingest.trace_archive import ArchivedTrace, SubjectKeyBinding
from tracebed.stores.pg.pool import scoped
from tracebed.stores.pg.repo import Repo
from tracebed.workers.extractors import TIER_A_KIND_MEM_TYPES, estimate_tier_a_token_count
from tracebed.workers.trace_learning import (
    DIGEST_BYTES,
    MAX_CLAIM_LIMIT,
    SAFE_ERROR_CODES,
    SAFE_SKIP_CODES,
    TIER_A_PIPELINE,
    TIER_A_PIPELINE_VERSION,
    PreparedTierACandidate,
    PreparedTierARejection,
    PreparedTierAResult,
    TierARejectionOverflow,
    TraceLearningLease,
    TraceLearningLeaseLost,
    TraceLearningState,
    is_safe_owner,
    result_receipt_digest,
    skip_receipt_digest,
    success_receipt_digest,
    validate_digest,
    validate_pipeline,
)

__all__ = ["TraceLearningFinalizer", "TraceLearningJobStore"]

_MAX_BACKOFF: Final = timedelta(days=7)
_MAX_REASONS_PER_REJECTION: Final = 32
_CONTENT_HASH_RE: Final = re.compile(r"\A[0-9a-f]{64}\Z")
_TIER_A_REJECTION_MEM_TYPES: Final = frozenset(TIER_A_KIND_MEM_TYPES.values())
_OVERFLOW_REVIEW_CODE: Final = "tier_a_scan_rejection_overflow/v1"
_OVERFLOW_REVIEW_SCHEMA: Final = "tracebed.tier-a-rejection-overflow/v1"


def _tier_a_tool_ref(content: str) -> str:
    """Extract the sole structural tool reference from a canonical TAN1 note.

    Finalization must not accept a caller-supplied provenance tool reference:
    the note already carries the bounded structural identity that planning
    derived.  Parsing this compact, closed template is deliberately stricter
    than searching for a substring, so a forged content/provenance pair fails
    before any database mutation.
    """
    return str(parse_note(content).tool_id)


def _overflow_review_reason(overflow: TierARejectionOverflow) -> str:
    """Render the one bounded aggregate review row without trace-derived text."""

    return canonical_json(
        {
            "code": _OVERFLOW_REVIEW_CODE,
            "schema": _OVERFLOW_REVIEW_SCHEMA,
            "total_count": overflow.total_count,
            "retained_count": MAX_TIER_A_INDIVIDUAL_REJECTIONS_PER_RESULT,
            "omitted_count": overflow.omitted_count,
            "omitted_digest": overflow.omitted_digest.hex(),
            "suite_version": overflow.suite_version,
            "mem_type_counts": [
                [mem_type.value, count] for mem_type, count in overflow.mem_type_counts
            ],
            "reason_counts": [[reason, count] for reason, count in overflow.reason_counts],
        }
    ).decode("utf-8")

_EXPIRED_RUNNING_SQL: Final = """
SELECT run_id, attempts, max_attempts, trace_digest
FROM trace_learning_job
WHERE project_id = %(project_id)s
  AND pipeline = %(pipeline)s
  AND pipeline_version = %(pipeline_version)s
  AND state = 'running'
  AND lease_expires_at <= statement_timestamp()
ORDER BY lease_expires_at, scheduled_at, run_id
FOR UPDATE SKIP LOCKED
LIMIT %(limit)s
"""

_EXPIRE_TO_RETRY_SQL: Final = """
UPDATE trace_learning_job
SET state = 'retry',
    available_at = clock_timestamp(),
    lease_token = NULL,
    lease_owner = NULL,
    lease_expires_at = NULL,
    last_error_code = 'lease_expired',
    updated_at = clock_timestamp()
WHERE project_id = %(project_id)s
  AND run_id = %(run_id)s
  AND pipeline = %(pipeline)s
  AND pipeline_version = %(pipeline_version)s
  AND state = 'running'
  AND lease_expires_at <= clock_timestamp()
"""

_EXPIRE_TO_DEAD_SQL: Final = """
UPDATE trace_learning_job
SET state = 'dead',
    lease_token = NULL,
    lease_owner = NULL,
    lease_expires_at = NULL,
    memory_ids = '{}'::uuid[],
    skip_code = NULL,
    last_error_code = 'max_attempts_exhausted',
    result_digest = %(result_digest)s,
    finished_at = clock_timestamp(),
    updated_at = clock_timestamp()
WHERE project_id = %(project_id)s
  AND run_id = %(run_id)s
  AND pipeline = %(pipeline)s
  AND pipeline_version = %(pipeline_version)s
  AND state = 'running'
  AND lease_expires_at <= clock_timestamp()
"""

_CLAIM_SQL: Final = """
WITH ready AS (
    SELECT job.project_id, job.run_id, job.pipeline, job.pipeline_version
    FROM trace_learning_job AS job
    WHERE job.project_id = %(project_id)s
      AND job.pipeline = %(pipeline)s
      AND job.pipeline_version = %(pipeline_version)s
      AND job.state IN ('pending', 'retry')
      AND job.attempts < job.max_attempts
      AND job.available_at <= statement_timestamp()
      -- E2 durable refusal mirrors the foreground gate. A claimed worker
      -- job must never become an archive/model side effect after a request
      -- has fenced its project, run, or authoritative subject union.
      AND public.tracebed_runtime_run_visible(job.project_id, job.run_id)
    ORDER BY available_at, scheduled_at, run_id
    FOR UPDATE SKIP LOCKED
    LIMIT %(limit)s
)
UPDATE trace_learning_job AS job
SET state = 'running',
    attempts = job.attempts + 1,
    lease_token = gen_random_uuid(),
    lease_owner = %(owner)s,
    lease_expires_at = clock_timestamp() + make_interval(secs => %(lease_seconds)s),
    first_started_at = COALESCE(job.first_started_at, clock_timestamp()),
    last_error_code = NULL,
    updated_at = clock_timestamp()
FROM ready
WHERE job.project_id = ready.project_id
  AND job.run_id = ready.run_id
  AND job.pipeline = ready.pipeline
  AND job.pipeline_version = ready.pipeline_version
RETURNING job.project_id, job.run_id, job.pipeline, job.pipeline_version,
          job.lease_token, job.lease_owner, job.attempts, job.max_attempts,
          job.lease_expires_at, job.trace_ended_at, job.trace_digest,
          job.subject_digests
"""

_RENEW_SELECT_SQL: Final = """
SELECT lease_expires_at
FROM trace_learning_job
WHERE project_id = %(project_id)s
  AND run_id = %(run_id)s
  AND pipeline = %(pipeline)s
  AND pipeline_version = %(pipeline_version)s
  AND state = 'running'
  AND lease_token = %(lease_token)s
  AND lease_owner = %(lease_owner)s
FOR UPDATE
"""

_CLOCK_SQL: Final = "SELECT clock_timestamp()"

_RENEW_UPDATE_SQL: Final = """
UPDATE trace_learning_job
SET lease_expires_at = clock_timestamp() + make_interval(secs => %(lease_seconds)s),
    updated_at = clock_timestamp()
WHERE project_id = %(project_id)s
  AND run_id = %(run_id)s
  AND pipeline = %(pipeline)s
  AND pipeline_version = %(pipeline_version)s
  AND state = 'running'
  AND lease_token = %(lease_token)s
  AND lease_owner = %(lease_owner)s
  AND lease_expires_at > clock_timestamp()
RETURNING project_id, run_id, pipeline, pipeline_version, lease_token,
          lease_owner, attempts, max_attempts, lease_expires_at, trace_ended_at, trace_digest,
          subject_digests
"""

_RETRY_SELECT_SQL: Final = """
SELECT trace_digest, attempts, max_attempts, lease_expires_at
FROM trace_learning_job
WHERE project_id = %(project_id)s
  AND run_id = %(run_id)s
  AND pipeline = %(pipeline)s
  AND pipeline_version = %(pipeline_version)s
  AND state = 'running'
  AND lease_token = %(lease_token)s
  AND lease_owner = %(lease_owner)s
FOR UPDATE
"""

_RETRY_SQL: Final = """
UPDATE trace_learning_job
SET trace_digest = COALESCE(trace_digest, %(trace_digest)s),
    state = CASE WHEN attempts >= max_attempts THEN 'dead' ELSE 'retry' END,
    available_at = CASE
        WHEN attempts >= max_attempts THEN available_at
        ELSE clock_timestamp() + make_interval(secs => %(backoff_seconds)s)
    END,
    lease_token = NULL,
    lease_owner = NULL,
    lease_expires_at = NULL,
    memory_ids = '{}'::uuid[],
    skip_code = NULL,
    last_error_code = CASE
        WHEN attempts >= max_attempts THEN 'max_attempts_exhausted'
        ELSE %(error_code)s
    END,
    result_digest = CASE
        WHEN attempts >= max_attempts THEN %(result_digest)s::bytea
        ELSE NULL::bytea
    END,
    finished_at = CASE WHEN attempts >= max_attempts THEN clock_timestamp() ELSE NULL END,
    updated_at = clock_timestamp()
WHERE project_id = %(project_id)s
  AND run_id = %(run_id)s
  AND pipeline = %(pipeline)s
  AND pipeline_version = %(pipeline_version)s
  AND state = 'running'
  AND lease_token = %(lease_token)s
  AND lease_owner = %(lease_owner)s
  AND lease_expires_at > clock_timestamp()
RETURNING state
"""

# P2B finalization deliberately uses the repository transaction rather than a
# second scoped checkout: the job fence, key-row checks, new/reused memories,
# reviews, and terminal result must commit or roll back together.
_FINALIZE_LOCK_SQL: Final = """
SELECT trace_digest, trace_ended_at, lease_expires_at
FROM trace_learning_job
WHERE project_id = %(project_id)s
  AND run_id = %(run_id)s
  AND pipeline = %(pipeline)s
  AND pipeline_version = %(pipeline_version)s
  AND state = 'running'
  AND lease_token = %(lease_token)s
  AND lease_owner = %(lease_owner)s
FOR UPDATE
"""

_LOCK_SUBJECT_KEYS_SQL: Final = """
SELECT subject_digest, key_id, destroyed_at
FROM public.tracebed_lock_subject_bindings(
    %(project_id)s::uuid,
    %(subject_digests)s::bytea[]
)
"""

_SEMANTIC_LOCK_SQL: Final = "SELECT pg_advisory_xact_lock(hashtext(%(content_hash)s)::bigint)"

_REUSE_TIER_A_SQL: Final = """
SELECT id
FROM memory_item
WHERE project_id = %(project_id)s
  AND content_hash = %(content_hash)s
  AND content = %(content)s
  AND scope_type = %(scope_type)s
  AND scope_id IS NOT DISTINCT FROM %(scope_id)s
  AND mem_type = %(mem_type)s
  AND kind = %(kind)s
  AND lane = 'operational'
  AND trust_tier = 'A'
  AND status IN ('candidate', 'validated', 'pinned')
  AND token_count = %(token_count)s
  AND schema_version = %(schema_version)s
  AND subject_tag IS NOT DISTINCT FROM %(subject_tag)s
  AND provenance->>'class' = 'parser'
  AND cluster_id IS NULL
  AND ttl_class IS NULL
  AND valid_from IS NULL
  AND valid_to IS NULL
ORDER BY created_at, id
LIMIT 1
FOR UPDATE
"""

_FINALIZE_SUCCESS_SQL: Final = """
UPDATE trace_learning_job
SET state = 'succeeded',
    trace_digest = COALESCE(trace_digest, %(trace_digest)s),
    result_digest = %(result_digest)s,
    memory_ids = %(memory_ids)s::uuid[],
    lease_token = NULL,
    lease_owner = NULL,
    lease_expires_at = NULL,
    skip_code = NULL,
    last_error_code = NULL,
    finished_at = clock_timestamp(),
    updated_at = clock_timestamp()
WHERE project_id = %(project_id)s
  AND run_id = %(run_id)s
  AND pipeline = %(pipeline)s
  AND pipeline_version = %(pipeline_version)s
  AND state = 'running'
  AND lease_token = %(lease_token)s
  AND lease_owner = %(lease_owner)s
  AND lease_expires_at > clock_timestamp()
RETURNING state
"""

_FINALIZE_SKIP_SQL: Final = """
UPDATE trace_learning_job
SET state = 'skipped',
    trace_digest = COALESCE(trace_digest, %(trace_digest)s),
    result_digest = %(result_digest)s,
    memory_ids = '{}'::uuid[],
    lease_token = NULL,
    lease_owner = NULL,
    lease_expires_at = NULL,
    skip_code = %(skip_code)s,
    last_error_code = NULL,
    finished_at = clock_timestamp(),
    updated_at = clock_timestamp()
WHERE project_id = %(project_id)s
  AND run_id = %(run_id)s
  AND pipeline = %(pipeline)s
  AND pipeline_version = %(pipeline_version)s
  AND state = 'running'
  AND lease_token = %(lease_token)s
  AND lease_owner = %(lease_owner)s
  AND lease_expires_at > clock_timestamp()
RETURNING state
"""

_FINALIZE_DEAD_SQL: Final = """
UPDATE trace_learning_job
SET state = 'dead',
    trace_digest = COALESCE(trace_digest, %(trace_digest)s),
    result_digest = %(result_digest)s,
    memory_ids = '{}'::uuid[],
    lease_token = NULL,
    lease_owner = NULL,
    lease_expires_at = NULL,
    skip_code = NULL,
    last_error_code = %(error_code)s,
    finished_at = clock_timestamp(),
    updated_at = clock_timestamp()
WHERE project_id = %(project_id)s
  AND run_id = %(run_id)s
  AND pipeline = %(pipeline)s
  AND pipeline_version = %(pipeline_version)s
  AND state = 'running'
  AND lease_token = %(lease_token)s
  AND lease_owner = %(lease_owner)s
  AND lease_expires_at > clock_timestamp()
RETURNING state
"""


class TraceLearningFinalizer:
    """Durably finish one Tier-A/v1 job under its running-row fence.

    This is intentionally separate from the claim/retry store.  Claiming can
    be a small lease transaction; finalization must make the archive digest,
    subject-erasure check, candidate/review rows, and terminal job state one
    atomic unit on the *same* repository transaction.
    """

    def __init__(self, repo: Repo) -> None:
        self._repo = repo

    def finalize_success(
        self,
        lease: TraceLearningLease,
        archived: ArchivedTrace,
        prepared: PreparedTierAResult,
    ) -> TraceLearningState | None:
        self._validate_tier_a_lease(lease)
        validate_digest(archived.trace_digest, field="archived.trace_digest")
        self._validate_archive_identity(lease, archived)
        self._validate_prepared(lease, archived, prepared)
        expected_receipt = success_receipt_digest(
            lease=lease,
            trace_digest=archived.trace_digest,
            candidates=prepared.candidates,
            rejections=prepared.rejections,
            rejection_overflow=prepared.rejection_overflow,
        )
        if prepared.result_digest != expected_receipt:
            raise ValueError("prepared Tier-A result receipt does not match semantic output")

        try:
            with self._repo.tx(lease.project_id) as scoped_repo:
                conn = scoped_repo._conn
                with conn.cursor(row_factory=dict_row) as cur:
                    # Canonical E2 order: project/run/subject snapshot before
                    # the job row, subject keys, or any memory row. A changed
                    # union is a retry outcome and a fenced run refuses before
                    # this finalizer can recreate a memory.
                    scoped_repo.lock_erasure_snapshot(lease.run_id, lease.subject_digests)
                    self._lock_live_fence(cur, lease, archived.trace_digest)
                    if self._lock_subject_bindings(cur, lease, archived.subject_key_bindings):
                        return self._finish_skip_locked(cur, lease, archived.trace_digest, "privacy_tombstoned")

                    memory_ids = self._persist_prepared_locked(cur, scoped_repo, lease, prepared)
                    state = self._finish_success_locked(
                        cur,
                        lease,
                        archived.trace_digest,
                        prepared.result_digest,
                        memory_ids,
                    )
                    if state is None:
                        raise TraceLearningLeaseLost()
                    return state
        except TraceLearningLeaseLost:
            return None

    def finalize_skip(
        self,
        lease: TraceLearningLease,
        trace_digest: bytes,
        code: str,
    ) -> TraceLearningState | None:
        self._validate_tier_a_lease(lease)
        validate_digest(trace_digest, field="trace_digest")
        if trace_digest is None or code not in SAFE_SKIP_CODES:
            raise ValueError("invalid Tier-A skip result")
        try:
            with self._repo.tx(lease.project_id) as scoped_repo, scoped_repo._conn.cursor(
                row_factory=dict_row
            ) as cur:
                scoped_repo.lock_erasure_snapshot(lease.run_id, lease.subject_digests)
                self._lock_live_fence(cur, lease, trace_digest)
                state = self._finish_skip_locked(cur, lease, trace_digest, code)
                if state is None:
                    raise TraceLearningLeaseLost()
                return state
        except TraceLearningLeaseLost:
            return None

    def finalize_dead(
        self,
        lease: TraceLearningLease,
        code: str,
        observed_digest: bytes | None = None,
    ) -> TraceLearningState | None:
        self._validate_tier_a_lease(lease)
        if code not in SAFE_ERROR_CODES:
            raise ValueError("invalid Tier-A dead-result code")
        validate_digest(observed_digest, field="observed_digest")
        try:
            with self._repo.tx(lease.project_id) as scoped_repo, scoped_repo._conn.cursor(
                row_factory=dict_row
            ) as cur:
                scoped_repo.lock_erasure_snapshot(lease.run_id, lease.subject_digests)
                stored_trace_digest = self._lock_live_fence(
                    cur,
                    lease,
                    observed_digest,
                    allow_digest_mismatch=code == "archive_digest_mismatch",
                )
                # A mismatch is a comparison between two distinct, concrete
                # ciphertext commitments.  Never turn a missing/equal
                # observation into a terminal corruption receipt.
                if code == "archive_digest_mismatch" and (
                    stored_trace_digest is None
                    or observed_digest is None
                    or stored_trace_digest == observed_digest
                ):
                    raise ValueError("archive digest mismatch requires distinct stored and observed digests")
                baseline_trace_digest = (
                    stored_trace_digest if stored_trace_digest is not None else observed_digest
                )
                receipt = result_receipt_digest(
                    project_id=lease.project_id,
                    run_id=lease.run_id,
                    pipeline=lease.pipeline,
                    pipeline_version=lease.pipeline_version,
                    code=code,
                    # A digest-mismatch result must commit the expected,
                    # write-once baseline already on the job; never replace it
                    # with the observed ciphertext digest that failed to bind.
                    trace_digest=baseline_trace_digest,
                )
                cur.execute(
                    _FINALIZE_DEAD_SQL,
                    self._lease_params(lease)
                    | {
                        "trace_digest": baseline_trace_digest,
                        "result_digest": receipt,
                        "error_code": code,
                    },
                )
                row = cur.fetchone()
                if row is None:
                    raise TraceLearningLeaseLost()
                return TraceLearningState(row["state"])
        except TraceLearningLeaseLost:
            return None

    @staticmethod
    def _validate_tier_a_lease(lease: TraceLearningLease) -> None:
        if type(lease.project_id) is not ProjectId or type(lease.run_id) is not RunId:
            raise ValueError("lease project_id and run_id must have exact typed identities")
        if type(lease.lease_token) is not UUID:
            raise ValueError("lease token must be an exact UUID")
        if type(lease.pipeline_version) is not int:
            raise ValueError("lease pipeline_version must be an integer")
        if type(lease.attempts) is not int or type(lease.max_attempts) is not int:
            raise ValueError("lease attempts and max_attempts must be integers")
        validate_pipeline(lease.pipeline, lease.pipeline_version)
        if (lease.pipeline, lease.pipeline_version) != (TIER_A_PIPELINE, TIER_A_PIPELINE_VERSION):
            raise ValueError("finalizer handles only tier_a pipeline version 1")
        if not is_safe_owner(lease.lease_owner):
            raise ValueError("lease owner is not safe")
        if lease.attempts < 1 or lease.attempts > lease.max_attempts:
            raise ValueError("lease attempts are invalid")
        validate_digest(lease.trace_digest, field="lease.trace_digest")

    @staticmethod
    def _validate_archive_identity(lease: TraceLearningLease, archived: ArchivedTrace) -> None:
        if (
            archived.index.project_id != lease.project_id
            or archived.index.run_id != lease.run_id
            or archived.index.ended_at != lease.trace_ended_at
        ):
            raise ValueError("archived trace does not bind the leased job identity")

    def _lock_live_fence(
        self,
        cur: Any,
        lease: TraceLearningLease,
        trace_digest: bytes | None,
        *,
        allow_digest_mismatch: bool = False,
    ) -> bytes | None:
        cur.execute(_FINALIZE_LOCK_SQL, self._lease_params(lease))
        row = cur.fetchone()
        if row is None:
            raise TraceLearningLeaseLost()
        cur.execute(_CLOCK_SQL)
        clock_row = cur.fetchone()
        assert clock_row is not None
        if row["lease_expires_at"] <= clock_row["clock_timestamp"]:
            raise TraceLearningLeaseLost()
        stored = row["trace_digest"]
        if (
            stored is not None
            and trace_digest is not None
            and bytes(stored) != trace_digest
            and not allow_digest_mismatch
        ):
            raise ValueError("trace digest is write-once and does not bind this archive")
        if row["trace_ended_at"] != lease.trace_ended_at:
            raise ValueError("leased trace end timestamp changed")
        return bytes(stored) if stored is not None else None

    def _lock_subject_bindings(
        self,
        cur: Any,
        lease: TraceLearningLease,
        bindings: Sequence[SubjectKeyBinding],
    ) -> bool:
        if not bindings:
            raise ValueError("archive has no subject-key bindings")
        resolved_list: list[bytes] = []
        for binding in bindings:
            if binding.subject_digest is not None:
                resolved_list.append(binding.subject_digest)
            elif binding.subject_tag is not None:
                resolved_list.append(subject_digest(lease.project_id, binding.subject_tag))
            else:
                raise ValueError("archive subject key binding is invalid")
        resolved = tuple(resolved_list)
        if any(not isinstance(digest, bytes) or len(digest) != 32 for digest in resolved):
            raise ValueError("archive subject key binding is invalid")
        ordered = tuple(sorted(zip(resolved, bindings, strict=True), key=lambda item: item[0]))
        if len({digest for digest, _binding in ordered}) != len(ordered):
            raise ValueError("archive repeats a subject binding")
        cur.execute(
            _LOCK_SUBJECT_KEYS_SQL,
            {
                "project_id": lease.project_id.value,
                "subject_digests": [digest for digest, _binding in ordered],
            },
        )
        rows = cur.fetchall()
        if len(rows) != len(ordered):
            raise ValueError("archive subject key binding is missing")
        by_digest = {bytes(row["subject_digest"]): row for row in rows}
        if tuple(sorted(by_digest)) != tuple(digest for digest, _binding in ordered):
            raise ValueError("archive subject key binding set changed")
        for digest, binding in ordered:
            if by_digest[digest]["key_id"] != binding.key_id:
                raise ValueError("archive subject key binding changed")
        return any(by_digest[digest]["destroyed_at"] is not None for digest, _binding in ordered)

    def _persist_prepared_locked(
        self,
        cur: Any,
        scoped_repo: Any,
        lease: TraceLearningLease,
        prepared: PreparedTierAResult,
    ) -> tuple[UUID, ...]:
        memory_ids: list[UUID] = []
        for candidate in sorted(prepared.candidates, key=lambda item: item.content_hash):
            cur.execute(_SEMANTIC_LOCK_SQL, {"content_hash": candidate.content_hash})
            cur.execute(
                _REUSE_TIER_A_SQL,
                {
                    "project_id": scoped_repo._project_id.value,
                    "content_hash": candidate.content_hash,
                    "content": candidate.item.content,
                    "scope_type": candidate.item.scope_type.value,
                    "scope_id": candidate.item.scope_id,
                    "mem_type": candidate.item.mem_type.value,
                    "kind": candidate.item.kind,
                    "token_count": candidate.item.token_count,
                    "schema_version": candidate.item.schema_version,
                    "subject_tag": candidate.item.subject_tag,
                },
            )
            existing = cur.fetchone()
            if existing is None:
                memory_id = scoped_repo.insert_memory_item(
                    candidate.item,
                    candidate.scan_verdict,
                    subject_digests=lease.subject_digests,
                )
                scoped_repo.bind_run_memory(lease.run_id, memory_id, lease.subject_digests)
                memory_ids.append(memory_id.value)
            else:
                memory_id = MemoryId(cast(UUID, existing["id"]))
                scoped_repo.bind_run_memory(lease.run_id, memory_id, lease.subject_digests)
                memory_ids.append(memory_id.value)
        for rejection in prepared.rejections:
            scoped_repo.insert_review_item("; ".join(rejection.reasons))
        if prepared.rejection_overflow is not None:
            scoped_repo.insert_review_item(_overflow_review_reason(prepared.rejection_overflow))
        return tuple(sorted(set(memory_ids), key=str))

    @staticmethod
    def _validate_candidate(
        lease: TraceLearningLease,
        archived: ArchivedTrace,
        candidate: PreparedTierACandidate,
    ) -> None:
        if type(candidate) is not PreparedTierACandidate:
            raise ValueError("prepared Tier-A candidate must have the exact immutable type")
        item = candidate.item
        if (
            type(item) is not NewMemoryItem
            or type(item.provenance) is not Provenance
            or type(candidate.scan_verdict) is not ScanVerdict
        ):
            raise ValueError("prepared Tier-A candidate contains a mutable or forged object")
        if type(item.id) is not MemoryId:
            raise ValueError("prepared Tier-A item must have an exact pre-minted MemoryId")
        if candidate.content_hash != content_hash(item.content):
            raise ValueError("prepared Tier-A item content hash does not bind its content")
        if (
            item.lane is not Lane.OPERATIONAL
            or item.trust_tier is not TrustTier.A
            or item.status is not Status.CANDIDATE
            or item.scope_type is not ScopeType.AGENT_TYPE
            or item.scope_id != archived.index.agent_type_id.value
            or item.subject_tag is not None
            or item.cluster_id is not None
            or item.ttl_class is not None
            or item.valid_from is not None
            or item.valid_to is not None
            or bool(item.extra)
            or item.schema_version != 1
            or TIER_A_KIND_MEM_TYPES.get(item.kind) is not item.mem_type
            or item.token_count != estimate_tier_a_token_count(item.content)
            or item.provenance.cls is not ProvenanceClass.PARSER
            or item.provenance.trace_ids != (lease.run_id,)
            or item.provenance.verdict_id is not None
            or item.provenance.input_sig_hashes
            or item.provenance.run_id is not None
            or item.provenance.principal is not None
            or candidate.primary_run_id != lease.run_id
            or candidate.contributing_run_ids != (lease.run_id,)
            or candidate.content_hash != candidate.scan_verdict.content_hash
            or candidate.scan_suite_version != SUITE_VERSION
            or candidate.scan_verdict.suite_version != candidate.scan_suite_version
        ):
            raise ValueError("prepared result contains a non-candidate Tier-A item")
        if item.provenance.tool_refs != (_tier_a_tool_ref(item.content),):
            raise ValueError("prepared Tier-A candidate tool provenance does not bind its note")
        validate_provenance(item.provenance)
        verify_verdict(candidate.scan_verdict, candidate.content_hash)

    @staticmethod
    def _validate_rejection(rejection: PreparedTierARejection) -> None:
        if (
            type(rejection) is not PreparedTierARejection
            or _CONTENT_HASH_RE.fullmatch(rejection.content_hash) is None
            or type(rejection.mem_type) is not MemType
            or rejection.mem_type not in _TIER_A_REJECTION_MEM_TYPES
            or rejection.suite_version != SUITE_VERSION
            or type(rejection.reasons) is not tuple
            or not rejection.reasons
            or len(rejection.reasons) > _MAX_REASONS_PER_REJECTION
            or any(
                type(reason) is not str or reason not in rejection_reason_codes()
                for reason in rejection.reasons
            )
            or len(set(rejection.reasons)) != len(rejection.reasons)
        ):
            raise ValueError("prepared Tier-A rejection is not a canonical scanner result")

    @staticmethod
    def _validate_rejection_overflow(
        overflow: TierARejectionOverflow | None,
        rejections: tuple[PreparedTierARejection, ...],
    ) -> None:
        if overflow is None:
            # The visible list is the complete set when no aggregate exists.
            if len(rejections) > MAX_TIER_A_INDIVIDUAL_REJECTIONS_PER_RESULT:
                raise ValueError("prepared Tier-A result has too many rejections")
            return
        if type(overflow) is not TierARejectionOverflow:
            raise ValueError("prepared Tier-A rejection overflow has an invalid shape")
        if len(rejections) != MAX_TIER_A_INDIVIDUAL_REJECTIONS_PER_RESULT:
            raise ValueError("rejection overflow requires exactly the retained rejection bound")
        if (
            type(overflow.total_count) is not int
            or type(overflow.omitted_count) is not int
            or overflow.omitted_count < 1
            or overflow.total_count
            != MAX_TIER_A_INDIVIDUAL_REJECTIONS_PER_RESULT + overflow.omitted_count
            or type(overflow.suite_version) is not str
            or overflow.suite_version != SUITE_VERSION
        ):
            raise ValueError("prepared Tier-A rejection overflow has invalid totals")
        if type(overflow.omitted_digest) is not bytes or len(overflow.omitted_digest) != DIGEST_BYTES:
            raise ValueError("rejection_overflow.omitted_digest must be exactly 32 bytes")
        if (
            type(overflow.mem_type_counts) is not tuple
            or type(overflow.reason_counts) is not tuple
        ):
            raise ValueError("prepared Tier-A rejection overflow counters must be tuples")

        mem_type_counts: list[tuple[MemType, int]] = []
        for pair in overflow.mem_type_counts:
            if type(pair) is not tuple or len(pair) != 2:
                raise ValueError("prepared Tier-A rejection overflow mem-type counter is invalid")
            mem_type, count = pair
            if (
                type(mem_type) is not MemType
                or mem_type not in _TIER_A_REJECTION_MEM_TYPES
                or type(count) is not int
                or not 1 <= count <= overflow.omitted_count
            ):
                raise ValueError("prepared Tier-A rejection overflow mem-type counter is invalid")
            mem_type_counts.append((mem_type, count))
        if (
            not mem_type_counts
            or len({mem_type for mem_type, _count in mem_type_counts}) != len(mem_type_counts)
            or tuple(sorted(mem_type_counts, key=lambda item: item[0].value))
            != overflow.mem_type_counts
            or sum(count for _mem_type, count in mem_type_counts) != overflow.omitted_count
        ):
            raise ValueError("prepared Tier-A rejection overflow mem-type counters are noncanonical")

        reason_counts: list[tuple[str, int]] = []
        for reason_pair in overflow.reason_counts:
            if type(reason_pair) is not tuple or len(reason_pair) != 2:
                raise ValueError("prepared Tier-A rejection overflow reason counter is invalid")
            reason, count = reason_pair
            if (
                type(reason) is not str
                or reason not in rejection_reason_codes()
                or type(count) is not int
                or not 1 <= count <= overflow.omitted_count
            ):
                raise ValueError("prepared Tier-A rejection overflow reason counter is invalid")
            reason_counts.append((reason, count))
        if (
            not reason_counts
            or len({reason for reason, _count in reason_counts}) != len(reason_counts)
            or tuple(sorted(reason_counts)) != overflow.reason_counts
            or not overflow.omitted_count
            <= sum(count for _reason, count in reason_counts)
            <= overflow.omitted_count * _MAX_REASONS_PER_REJECTION
        ):
            raise ValueError("prepared Tier-A rejection overflow reason counters are noncanonical")

    def _validate_prepared(
        self,
        lease: TraceLearningLease,
        archived: ArchivedTrace,
        prepared: PreparedTierAResult,
    ) -> None:
        if type(prepared) is not PreparedTierAResult:
            raise ValueError("prepared Tier-A result must have the exact immutable type")
        if type(prepared.candidates) is not tuple or type(prepared.rejections) is not tuple:
            raise ValueError("prepared Tier-A result containers must be exact tuples")
        if type(prepared.result_digest) is not bytes or len(prepared.result_digest) != DIGEST_BYTES:
            raise ValueError("prepared.result_digest must be exactly 32 bytes")
        if len(prepared.candidates) > MAX_TIER_A_CANDIDATES_PER_RESULT:
            raise ValueError("prepared Tier-A result has too many candidates")
        self._validate_rejection_overflow(prepared.rejection_overflow, prepared.rejections)

        candidate_ids: set[object] = set()
        candidate_semantics: set[tuple[object, ...]] = set()
        candidate_hashes: set[str] = set()
        for candidate in prepared.candidates:
            self._validate_candidate(lease, archived, candidate)
            assert candidate.item.id is not None
            if candidate.item.id in candidate_ids:
                raise ValueError("prepared Tier-A result repeats a memory id")
            candidate_ids.add(candidate.item.id)
            candidate_semantic = (
                candidate.content_hash,
                candidate.item.scope_type,
                candidate.item.scope_id,
                candidate.item.mem_type,
                candidate.item.kind,
                candidate.item.lane,
                candidate.item.trust_tier,
                candidate.item.status,
                candidate.item.token_count,
                candidate.item.schema_version,
                candidate.scan_suite_version,
            )
            if candidate.content_hash in candidate_hashes:
                raise ValueError("prepared Tier-A result repeats a candidate content hash")
            candidate_hashes.add(candidate.content_hash)
            if candidate_semantic in candidate_semantics:
                raise ValueError("prepared Tier-A result repeats a semantic candidate")
            candidate_semantics.add(candidate_semantic)

        rejection_semantics: set[tuple[object, ...]] = set()
        for rejection in prepared.rejections:
            self._validate_rejection(rejection)
            rejection_semantic = (
                rejection.content_hash,
                rejection.mem_type,
                rejection.suite_version,
                tuple(sorted(rejection.reasons)),
            )
            if rejection_semantic in rejection_semantics:
                raise ValueError("prepared Tier-A result repeats a scan rejection")
            rejection_semantics.add(rejection_semantic)
            if rejection.content_hash in candidate_hashes:
                raise ValueError("prepared Tier-A result overlaps accepted and rejected scan output")

    def _finish_success_locked(
        self,
        cur: Any,
        lease: TraceLearningLease,
        trace_digest: bytes,
        result_digest: bytes,
        memory_ids: Sequence[UUID],
    ) -> TraceLearningState | None:
        cur.execute(
            _FINALIZE_SUCCESS_SQL,
            self._lease_params(lease)
            | {
                "trace_digest": trace_digest,
                "result_digest": result_digest,
                "memory_ids": list(memory_ids),
            },
        )
        row = cur.fetchone()
        return TraceLearningState(row["state"]) if row is not None else None

    def _finish_skip_locked(
        self,
        cur: Any,
        lease: TraceLearningLease,
        trace_digest: bytes,
        code: str,
    ) -> TraceLearningState | None:
        cur.execute(
            _FINALIZE_SKIP_SQL,
            self._lease_params(lease)
            | {
                "trace_digest": trace_digest,
                "result_digest": skip_receipt_digest(
                    lease=lease,
                    trace_digest=trace_digest,
                    code=code,
                ),
                "skip_code": code,
            },
        )
        row = cur.fetchone()
        return TraceLearningState(row["state"]) if row is not None else None

    @staticmethod
    def _lease_params(lease: TraceLearningLease) -> dict[str, object]:
        return TraceLearningJobStore._lease_params(lease)


class TraceLearningJobStore:
    """One transaction per lease operation, all scoped to one project."""

    def __init__(
        self,
        pool: ConnectionPool,
        *,
        lease_duration: timedelta = timedelta(minutes=5),
        max_claim_limit: int = MAX_CLAIM_LIMIT,
    ) -> None:
        if lease_duration < timedelta(seconds=1):
            raise ValueError("lease_duration must be at least one second")
        if max_claim_limit < 1 or max_claim_limit > MAX_CLAIM_LIMIT:
            raise ValueError(f"max_claim_limit must be in 1..{MAX_CLAIM_LIMIT}")
        self._pool = pool
        self._lease_seconds = int(lease_duration.total_seconds())
        self._max_claim_limit = max_claim_limit

    def claim(
        self,
        project_id: ProjectId,
        pipeline: str,
        pipeline_version: int,
        owner: str,
        limit: int,
    ) -> Sequence[TraceLearningLease]:
        validate_pipeline(pipeline, pipeline_version)
        self._validate_owner(owner)
        batch = self._validate_limit(limit)
        params = {
            "project_id": project_id.value,
            "pipeline": pipeline,
            "pipeline_version": pipeline_version,
            "limit": batch,
        }
        with scoped(self._pool, project_id) as conn, conn.cursor(row_factory=dict_row) as cur:
            cur.execute(_EXPIRED_RUNNING_SQL, params)
            expired = cur.fetchall()
            for row in expired:
                run_id = RunId(row["run_id"])
                attempts = int(row["attempts"])
                max_attempts = int(row["max_attempts"])
                trace_digest = row["trace_digest"]
                update_params = params | {"run_id": run_id.value}
                if attempts >= max_attempts:
                    cur.execute(
                        _EXPIRE_TO_DEAD_SQL,
                        update_params
                        | {
                            "result_digest": result_receipt_digest(
                                project_id=project_id,
                                run_id=run_id,
                                pipeline=pipeline,
                                pipeline_version=pipeline_version,
                                code="max_attempts_exhausted",
                                trace_digest=(bytes(trace_digest) if trace_digest is not None else None),
                            )
                        },
                    )
                else:
                    cur.execute(_EXPIRE_TO_RETRY_SQL, update_params)

            cur.execute(
                _CLAIM_SQL,
                params | {"owner": owner, "lease_seconds": self._lease_seconds},
            )
            return tuple(self._lease_from_row(row) for row in cur.fetchall())

    def renew(self, lease: TraceLearningLease) -> TraceLearningLease | None:
        self._validate_lease(lease)
        with scoped(self._pool, lease.project_id) as conn, conn.cursor(row_factory=dict_row) as cur:
            params = self._lease_params(lease)
            cur.execute(_RENEW_SELECT_SQL, params)
            row = cur.fetchone()
            if row is None:
                return None
            cur.execute(_CLOCK_SQL)
            clock_row = cur.fetchone()
            assert clock_row is not None
            if row["lease_expires_at"] <= clock_row["clock_timestamp"]:
                return None
            cur.execute(
                _RENEW_UPDATE_SQL,
                params | {"lease_seconds": self._lease_seconds},
            )
            row = cur.fetchone()
        return self._lease_from_row(row) if row is not None else None

    def retry(
        self,
        lease: TraceLearningLease,
        backoff: timedelta,
        error_code: str,
        trace_digest: bytes | None = None,
    ) -> TraceLearningState | None:
        self._validate_lease(lease)
        if backoff < timedelta(0) or backoff > _MAX_BACKOFF:
            raise ValueError(f"backoff must be in 0..{_MAX_BACKOFF}")
        if error_code not in SAFE_ERROR_CODES:
            raise ValueError("error_code is not an approved trace-learning code")
        validate_digest(trace_digest, field="trace_digest")

        params = self._lease_params(lease)
        with scoped(self._pool, lease.project_id) as conn, conn.cursor(row_factory=dict_row) as cur:
            cur.execute(_RETRY_SELECT_SQL, params)
            row = cur.fetchone()
            if row is None:
                return None
            cur.execute(_CLOCK_SQL)
            clock_row = cur.fetchone()
            assert clock_row is not None
            if row["lease_expires_at"] <= clock_row["clock_timestamp"]:
                return None
            stored_trace = row["trace_digest"]
            if stored_trace is not None and trace_digest is not None and bytes(stored_trace) != trace_digest:
                raise ValueError("trace_digest is write-once and does not match the stored value")

            attempts = int(row["attempts"])
            max_attempts = int(row["max_attempts"])
            receipt = (
                result_receipt_digest(
                    project_id=lease.project_id,
                    run_id=lease.run_id,
                    pipeline=lease.pipeline,
                    pipeline_version=lease.pipeline_version,
                    code="max_attempts_exhausted",
                    trace_digest=(bytes(stored_trace) if stored_trace is not None else trace_digest),
                )
                if attempts >= max_attempts
                else None
            )
            cur.execute(
                _RETRY_SQL,
                params
                | {
                    "backoff_seconds": int(backoff.total_seconds()),
                    "error_code": error_code,
                    "trace_digest": trace_digest,
                    "result_digest": receipt,
                },
            )
            result = cur.fetchone()
        return TraceLearningState(result["state"]) if result is not None else None

    def _validate_limit(self, limit: int) -> int:
        if limit < 1:
            raise ValueError("limit must be positive")
        return min(limit, self._max_claim_limit)

    @staticmethod
    def _validate_owner(owner: str) -> None:
        if not is_safe_owner(owner):
            raise ValueError("owner must contain only safe bounded identifier characters")

    def _validate_lease(self, lease: TraceLearningLease) -> None:
        validate_pipeline(lease.pipeline, lease.pipeline_version)
        self._validate_owner(lease.lease_owner)
        validate_digest(lease.trace_digest, field="lease.trace_digest")
        if (
            len(lease.subject_digests) > 64
            or any(type(value) is not bytes or len(value) != DIGEST_BYTES for value in lease.subject_digests)
            or tuple(sorted(lease.subject_digests)) != lease.subject_digests
            or len(set(lease.subject_digests)) != len(lease.subject_digests)
        ):
            raise ValueError("lease subject_digests must be canonical")
        if lease.attempts < 1 or lease.attempts > lease.max_attempts:
            raise ValueError("lease attempts must be in 1..max_attempts")

    @staticmethod
    def _lease_params(lease: TraceLearningLease) -> dict[str, object]:
        return {
            "project_id": lease.project_id.value,
            "run_id": lease.run_id.value,
            "pipeline": lease.pipeline,
            "pipeline_version": lease.pipeline_version,
            "lease_token": lease.lease_token,
            "lease_owner": lease.lease_owner,
        }

    @staticmethod
    def _lease_from_row(row: Mapping[str, Any]) -> TraceLearningLease:
        token = cast(UUID, row["lease_token"])
        expiry = cast(datetime, row["lease_expires_at"])
        trace_ended_at = cast(datetime, row["trace_ended_at"])
        trace = row["trace_digest"]
        raw_subject_digests = row.get("subject_digests", ())
        if raw_subject_digests is None or type(raw_subject_digests) not in {list, tuple}:
            raise ValueError("trace-learning lease subject_digests are malformed")
        subject_digests = tuple(bytes(value) for value in raw_subject_digests)
        if (
            len(subject_digests) > 64
            or any(len(value) != DIGEST_BYTES for value in subject_digests)
            or tuple(sorted(subject_digests)) != subject_digests
            or len(set(subject_digests)) != len(subject_digests)
        ):
            raise ValueError("trace-learning lease subject_digests are not canonical")
        return TraceLearningLease(
            project_id=ProjectId(row["project_id"]),
            run_id=RunId(row["run_id"]),
            pipeline=cast(str, row["pipeline"]),
            pipeline_version=int(row["pipeline_version"]),
            lease_token=token,
            lease_owner=cast(str, row["lease_owner"]),
            attempts=int(row["attempts"]),
            max_attempts=int(row["max_attempts"]),
            lease_expires_at=expiry,
            trace_ended_at=trace_ended_at,
            trace_digest=bytes(trace) if trace is not None else None,
            subject_digests=subject_digests,
        )
