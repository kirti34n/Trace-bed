"""Typed lease contract for durable trace-learning jobs (Phase 2A1).

This module deliberately has no runner, trace-reader, or success-completion
surface.  It is the stable job/lease substrate P2B will consume; keeping it
small prevents a scheduler from becoming reachable before the learning result
path has an idempotency contract of its own.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum
from typing import TYPE_CHECKING, Final, Protocol, runtime_checkable
from uuid import UUID

from tracebed.domain.canonical import canonical_json
from tracebed.domain.config import MAX_TIER_A_INDIVIDUAL_REJECTIONS_PER_RESULT
from tracebed.domain.enums import MemType
from tracebed.domain.ids import ProjectId, RunId
from tracebed.domain.memory import NewMemoryItem
from tracebed.domain.scan import ScanVerdict

if TYPE_CHECKING:
    from tracebed.ingest.trace_archive import ArchivedTrace

__all__ = [
    "CLAIMABLE_STATES",
    "DIGEST_BYTES",
    "MAX_CLAIM_LIMIT",
    "MAX_OWNER_LENGTH",
    "SAFE_ERROR_CODES",
    "SAFE_SKIP_CODES",
    "TERMINAL_STATES",
    "TIER_A_PIPELINE",
    "TIER_A_PIPELINE_VERSION",
    "PreparedTierACandidate",
    "PreparedTierARejection",
    "PreparedTierAResult",
    "TierARejectionOverflow",
    "TraceLearningFinalizerPort",
    "TraceLearningJobPort",
    "TraceLearningLease",
    "TraceLearningLeaseLost",
    "TraceLearningState",
    "build_tier_a_rejection_overflow",
    "claimable_states",
    "is_safe_owner",
    "prepare_tier_a_result",
    "result_receipt_digest",
    "skip_receipt_digest",
    "success_receipt_digest",
    "terminal_states",
    "validate_digest",
    "validate_pipeline",
]

TIER_A_PIPELINE = "tier_a"
TIER_A_PIPELINE_VERSION = 1
DIGEST_BYTES = 32
MAX_CLAIM_LIMIT = 100
MAX_OWNER_LENGTH = 96

_REJECTION_OVERFLOW_SCHEMA: Final = "tracebed.tier-a-rejection-overflow/v1"
_REJECTION_OVERFLOW_LEAF_DOMAIN: Final = b"tracebed.tier-a-rejection-overflow-leaf/v1\0"
_REJECTION_OVERFLOW_ROOT_DOMAIN: Final = b"tracebed.tier-a-rejection-overflow-root/v1\0"

_PIPELINE_RE = re.compile(r"\A[a-z][a-z0-9_]{0,31}\Z")
_OWNER_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._:-]{0,95}\Z")


class TraceLearningState(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    RETRY = "retry"
    SUCCEEDED = "succeeded"
    SKIPPED = "skipped"
    DEAD = "dead"


TERMINAL_STATES = frozenset(
    {TraceLearningState.SUCCEEDED, TraceLearningState.SKIPPED, TraceLearningState.DEAD}
)
CLAIMABLE_STATES = frozenset({TraceLearningState.PENDING, TraceLearningState.RETRY})
# Lower-case aliases are retained for the initial P2A reader packet, while
# uppercase names make their constant nature clear to ordinary callers.
terminal_states = TERMINAL_STATES
claimable_states = CLAIMABLE_STATES

# These are non-sensitive receipts and diagnostics, not exception messages or
# trace text.  The store rejects arbitrary values so a caller cannot create a
# second data-exfiltration field through `last_error_code`.
SAFE_ERROR_CODES = frozenset(
    {
        "lease_expired",
        "max_attempts_exhausted",
        "trace_unavailable",
        "transient_failure",
        "config_invalid",
        "extractor_failure",
        "archive_invalid",
        "archive_auth_failed",
        "archive_digest_mismatch",
    }
)
SAFE_SKIP_CODES = frozenset({"privacy_tombstoned"})


@dataclass(frozen=True, slots=True)
class TraceLearningLease:
    """One ownership token returned by an atomic claim.

    The four-part identity is intentionally carried on every lease.  A token
    alone cannot identify a project or pipeline version safely, and all store
    updates must match the full identity plus token, owner, and unexpired
    state.
    """

    project_id: ProjectId
    run_id: RunId
    pipeline: str
    pipeline_version: int
    lease_token: UUID
    lease_owner: str
    attempts: int
    max_attempts: int
    lease_expires_at: datetime
    trace_ended_at: datetime
    trace_digest: bytes | None
    # E2 snapshots the complete, canonical run union with the lease.  This is
    # derived by the database, never supplied by a worker payload; keeping it
    # on the immutable lease lets the coordinator fence before archive/model
    # I/O and lets the finalizer repeat that fence in its write transaction.
    # The default preserves the pre-E2 test/fake constructor while real SQL
    # leases always carry an explicit (possibly empty) tuple.
    subject_digests: tuple[bytes, ...] = ()


class TraceLearningLeaseLost(RuntimeError):
    """A fenced finalization observed a stale lease and persisted nothing."""


@dataclass(frozen=True, slots=True)
class PreparedTierACandidate:
    """A pre-minted, scanned Tier-A item ready for one atomic finalizer call."""

    item: NewMemoryItem
    scan_verdict: ScanVerdict
    content_hash: str
    scan_suite_version: str
    primary_run_id: RunId
    contributing_run_ids: tuple[RunId, ...]


@dataclass(frozen=True, slots=True)
class PreparedTierARejection:
    """A scan refusal that becomes a review row only under a retained fence."""

    content_hash: str
    mem_type: MemType
    suite_version: str
    reasons: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class TierARejectionOverflow:
    """Bounded commitment to scanner rejections retained only in aggregate.

    The individual overflow records never reach a review row or result
    receipt.  Their domain-separated leaf/root commitment, plus closed
    counters, makes loss visible without retaining tool identifiers or note
    contents outside the trace archive.
    """

    total_count: int
    omitted_count: int
    omitted_digest: bytes
    suite_version: str
    mem_type_counts: tuple[tuple[MemType, int], ...]
    reason_counts: tuple[tuple[str, int], ...]


@dataclass(frozen=True, slots=True)
class PreparedTierAResult:
    """Finalizer input whose digest commits only semantic, non-sensitive facts."""

    candidates: tuple[PreparedTierACandidate, ...]
    rejections: tuple[PreparedTierARejection, ...]
    result_digest: bytes
    rejection_overflow: TierARejectionOverflow | None = None


@runtime_checkable
class TraceLearningJobPort(Protocol):
    """Lease-only Phase 2A1 store seam; success completion belongs to P2B."""

    def claim(
        self,
        project_id: ProjectId,
        pipeline: str,
        pipeline_version: int,
        owner: str,
        limit: int,
    ) -> Sequence[TraceLearningLease]: ...

    def renew(self, lease: TraceLearningLease) -> TraceLearningLease | None: ...

    def retry(
        self,
        lease: TraceLearningLease,
        backoff: timedelta,
        error_code: str,
        trace_digest: bytes | None = None,
    ) -> TraceLearningState | None: ...


@runtime_checkable
class TraceLearningFinalizerPort(Protocol):
    """Fenced terminal result writes for the exact Tier-A/v1 handler."""

    def finalize_success(
        self,
        lease: TraceLearningLease,
        archived: ArchivedTrace,
        prepared: PreparedTierAResult,
    ) -> TraceLearningState | None: ...

    def finalize_skip(
        self,
        lease: TraceLearningLease,
        trace_digest: bytes,
        code: str,
    ) -> TraceLearningState | None: ...

    def finalize_dead(
        self,
        lease: TraceLearningLease,
        code: str,
        observed_digest: bytes | None = None,
    ) -> TraceLearningState | None: ...


def validate_pipeline(pipeline: str, pipeline_version: int) -> None:
    if _PIPELINE_RE.fullmatch(pipeline) is None:
        raise ValueError("pipeline must match ^[a-z][a-z0-9_]{0,31}$")
    if pipeline_version < 1:
        raise ValueError("pipeline_version must be >= 1")


def is_safe_owner(owner: str) -> bool:
    return _OWNER_RE.fullmatch(owner) is not None


def validate_digest(digest: bytes | None, *, field: str = "digest") -> None:
    if digest is not None and (not isinstance(digest, bytes) or len(digest) != DIGEST_BYTES):
        raise ValueError(f"{field} must be exactly {DIGEST_BYTES} bytes")


def prepare_tier_a_result(
    *,
    lease: TraceLearningLease,
    trace_digest: bytes,
    candidates: Sequence[PreparedTierACandidate],
    rejections: Sequence[PreparedTierARejection],
    rejection_overflow: TierARejectionOverflow | None = None,
) -> PreparedTierAResult:
    """Freeze Tier-A's semantic receipt before the database transaction starts."""

    validate_digest(trace_digest, field="trace_digest")
    if trace_digest is None:  # placate the optional public validator for type checkers
        raise ValueError("trace_digest is required for a successful Tier-A result")
    ordered_candidates = tuple(sorted(candidates, key=_candidate_receipt_key))
    ordered_rejections = tuple(sorted(rejections, key=_rejection_receipt_key))
    return PreparedTierAResult(
        candidates=ordered_candidates,
        rejections=ordered_rejections,
        rejection_overflow=rejection_overflow,
        result_digest=success_receipt_digest(
            lease=lease,
            trace_digest=trace_digest,
            candidates=ordered_candidates,
            rejections=ordered_rejections,
            rejection_overflow=rejection_overflow,
        ),
    )


def _candidate_receipt_key(candidate: PreparedTierACandidate) -> tuple[str, str, str, str, str, str, str, str, int, int, str]:
    item = candidate.item
    return (
        candidate.content_hash,
        item.scope_type.value,
        str(item.scope_id) if item.scope_id is not None else "",
        item.mem_type.value,
        item.kind,
        item.lane.value,
        item.trust_tier.value,
        item.status.value,
        item.token_count,
        item.schema_version,
        candidate.scan_suite_version,
    )


def _rejection_receipt_key(rejection: PreparedTierARejection) -> tuple[str, str, str, tuple[str, ...]]:
    return (
        rejection.content_hash,
        rejection.mem_type.value,
        rejection.suite_version,
        tuple(sorted(rejection.reasons)),
    )


def _overflow_record(
    content_hash: str,
    mem_type: MemType,
    suite_version: str,
    reasons: tuple[str, ...],
) -> dict[str, object]:
    return {
        "content_hash": content_hash,
        "mem_type": mem_type.value,
        "suite_version": suite_version,
        "reasons": sorted(reasons),
    }


def build_tier_a_rejection_overflow(
    records: Sequence[tuple[str, MemType, str, tuple[str, ...]]],
) -> TierARejectionOverflow | None:
    """Commit canonical rejections after the first retained hundred.

    Sorting semantic records and then sorting their fixed-size leaf hashes
    makes this commitment independent of extractor or mapping iteration
    order.  The returned object carries only closed scanner vocabulary and
    hashes, never rendered note content or tool identifiers.
    """

    ordered = tuple(
        sorted(
            records,
            key=lambda record: (record[0], record[1].value, record[2], tuple(sorted(record[3]))),
        )
    )
    if len(ordered) <= MAX_TIER_A_INDIVIDUAL_REJECTIONS_PER_RESULT:
        return None
    suite_versions = {record[2] for record in ordered}
    if len(suite_versions) != 1:
        raise ValueError("Tier-A rejection overflow requires one scanner suite version")
    omitted = ordered[MAX_TIER_A_INDIVIDUAL_REJECTIONS_PER_RESULT :]
    leaves = sorted(
        hashlib.sha256(
            _REJECTION_OVERFLOW_LEAF_DOMAIN
            + canonical_json(_overflow_record(content_hash, mem_type, suite_version, reasons))
        ).digest()
        for content_hash, mem_type, suite_version, reasons in omitted
    )
    mem_type_counts: dict[MemType, int] = {}
    reason_counts: dict[str, int] = {}
    for _content_hash, mem_type, _suite_version, reasons in omitted:
        mem_type_counts[mem_type] = mem_type_counts.get(mem_type, 0) + 1
        for reason in reasons:
            reason_counts[reason] = reason_counts.get(reason, 0) + 1
    return TierARejectionOverflow(
        total_count=len(ordered),
        omitted_count=len(omitted),
        omitted_digest=hashlib.sha256(_REJECTION_OVERFLOW_ROOT_DOMAIN + b"".join(leaves)).digest(),
        suite_version=next(iter(suite_versions)),
        mem_type_counts=tuple(sorted(mem_type_counts.items(), key=lambda item: item[0].value)),
        reason_counts=tuple(sorted(reason_counts.items())),
    )


def _overflow_receipt_value(overflow: TierARejectionOverflow | None) -> dict[str, object] | None:
    if overflow is None:
        return None
    return {
        "schema": _REJECTION_OVERFLOW_SCHEMA,
        "total_count": overflow.total_count,
        "retained_count": MAX_TIER_A_INDIVIDUAL_REJECTIONS_PER_RESULT,
        "omitted_count": overflow.omitted_count,
        "omitted_digest": overflow.omitted_digest.hex(),
        "suite_version": overflow.suite_version,
        "mem_type_counts": [[mem_type.value, count] for mem_type, count in overflow.mem_type_counts],
        "reason_counts": [[reason, count] for reason, count in overflow.reason_counts],
    }


def _receipt_digest(receipt: dict[str, object]) -> bytes:
    return hashlib.sha256(canonical_json(receipt)).digest()


def success_receipt_digest(
    *,
    lease: TraceLearningLease,
    trace_digest: bytes,
    candidates: Sequence[PreparedTierACandidate],
    rejections: Sequence[PreparedTierARejection],
    rejection_overflow: TierARejectionOverflow | None = None,
) -> bytes:
    """Hash only semantic outputs; never IDs, plaintext, leases, or timestamps."""

    validate_digest(trace_digest, field="trace_digest")
    if trace_digest is None:
        raise ValueError("trace_digest is required")
    outputs = [
        {
            "content_hash": candidate.content_hash,
            "scope_type": candidate.item.scope_type.value,
            "scope_id": str(candidate.item.scope_id) if candidate.item.scope_id is not None else None,
            "mem_type": candidate.item.mem_type.value,
            "kind": candidate.item.kind,
            "lane": candidate.item.lane.value,
            "trust_tier": candidate.item.trust_tier.value,
            "status": candidate.item.status.value,
            "token_count": candidate.item.token_count,
            "schema_version": candidate.item.schema_version,
            "scan_suite_version": candidate.scan_suite_version,
        }
        for candidate in sorted(candidates, key=_candidate_receipt_key)
    ]
    rejected = [
        {
            "content_hash": rejection.content_hash,
            "mem_type": rejection.mem_type.value,
            "suite_version": rejection.suite_version,
            "reasons": sorted(rejection.reasons),
        }
        for rejection in sorted(rejections, key=_rejection_receipt_key)
    ]
    return _receipt_digest(
        {
            "schema": "tracebed.learning-result/v1",
            "project_id": str(lease.project_id),
            "run_id": str(lease.run_id),
            "pipeline": lease.pipeline,
            "pipeline_version": lease.pipeline_version,
            "state": "succeeded",
            "trace_digest": trace_digest.hex(),
            "outputs": outputs,
            "rejections": rejected,
            "rejection_overflow": _overflow_receipt_value(rejection_overflow),
        }
    )


def skip_receipt_digest(
    *,
    lease: TraceLearningLease,
    trace_digest: bytes,
    code: str,
) -> bytes:
    if code not in SAFE_SKIP_CODES:
        raise ValueError("skip code is not an approved trace-learning code")
    validate_digest(trace_digest, field="trace_digest")
    if trace_digest is None:
        raise ValueError("trace_digest is required")
    return _receipt_digest(
        {
            "schema": "tracebed.learning-result/v1",
            "project_id": str(lease.project_id),
            "run_id": str(lease.run_id),
            "pipeline": lease.pipeline,
            "pipeline_version": lease.pipeline_version,
            "state": "skipped",
            "code": code,
            "trace_digest": trace_digest.hex(),
            "outputs": [],
        }
    )


def result_receipt_digest(
    *,
    project_id: ProjectId,
    run_id: RunId,
    pipeline: str,
    pipeline_version: int,
    code: str,
    trace_digest: bytes | None,
) -> bytes:
    """Digest a non-sensitive terminal receipt without trace plaintext.

    The receipt deliberately identifies only the stable job identity, pinned
    ciphertext digest (if available) and fixed diagnostic code. Retry count
    is operational job metadata; a result receipt must remain stable across
    transient retries. It never includes trace payload, exception text,
    owner, or lease token.
    """
    return hashlib.sha256(
        canonical_json(
            {
                "code": code,
                "outputs": [],
                "pipeline": pipeline,
                "pipeline_version": pipeline_version,
                "project_id": str(project_id),
                "schema": "tracebed.learning-result/v1",
                "run_id": str(run_id),
                "state": "dead",
                "trace_digest": trace_digest.hex() if trace_digest is not None else None,
            }
        )
    ).digest()
