"""Offline contract tests for the P2A durable trace-learning lease substrate."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import cast
from uuid import UUID

import pytest
from psycopg_pool import ConnectionPool

from tracebed.core.scans import ScanContext, scan
from tracebed.domain.clock import FakeClock
from tracebed.domain.enums import Lane, MemType, ProvenanceClass, ScopeType, TrustTier
from tracebed.domain.ids import ProjectId, RunId
from tracebed.domain.memory import NewMemoryItem, Provenance
from tracebed.domain.state_machine import Status
from tracebed.stores.pg.trace_learning import TraceLearningJobStore
from tracebed.workers.trace_learning import (
    CLAIMABLE_STATES,
    DIGEST_BYTES,
    SAFE_ERROR_CODES,
    TERMINAL_STATES,
    TIER_A_PIPELINE,
    TIER_A_PIPELINE_VERSION,
    PreparedTierACandidate,
    PreparedTierARejection,
    TraceLearningJobPort,
    TraceLearningLease,
    TraceLearningState,
    prepare_tier_a_result,
    result_receipt_digest,
    skip_receipt_digest,
    validate_digest,
    validate_pipeline,
)

pytestmark = pytest.mark.phase2

_PROJECT_ID = ProjectId("12345678-1234-5678-1234-567812345678")
_RUN_ID = RunId("87654321-4321-8765-4321-876543214321")
_NOW = datetime(2026, 1, 1, tzinfo=UTC)


def _lease() -> TraceLearningLease:
    return TraceLearningLease(
        project_id=_PROJECT_ID,
        run_id=_RUN_ID,
        pipeline=TIER_A_PIPELINE,
        pipeline_version=TIER_A_PIPELINE_VERSION,
        lease_token=UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
        lease_owner="worker-1",
        attempts=1,
        max_attempts=3,
        lease_expires_at=_NOW + timedelta(minutes=1),
        trace_ended_at=_NOW,
        trace_digest=None,
    )


def test_fixed_tier_a_identity_and_state_partition_are_exact() -> None:
    assert (TIER_A_PIPELINE, TIER_A_PIPELINE_VERSION) == ("tier_a", 1)
    assert set(TraceLearningState) == {
        TraceLearningState.PENDING,
        TraceLearningState.RUNNING,
        TraceLearningState.RETRY,
        TraceLearningState.SUCCEEDED,
        TraceLearningState.SKIPPED,
        TraceLearningState.DEAD,
    }
    assert {TraceLearningState.PENDING, TraceLearningState.RETRY} == CLAIMABLE_STATES
    assert {
        TraceLearningState.SUCCEEDED,
        TraceLearningState.SKIPPED,
        TraceLearningState.DEAD,
    } == TERMINAL_STATES
    assert not hasattr(TraceLearningJobPort, "complete")


@pytest.mark.parametrize(
    ("pipeline", "version"),
    [("Tier_A", 1), ("a" * 33, 1), ("tier-a", 1), ("tier_a", 0)],
)
def test_pipeline_identity_validation_rejects_noncanonical_values(pipeline: str, version: int) -> None:
    with pytest.raises(ValueError):
        validate_pipeline(pipeline, version)


@pytest.mark.parametrize("digest", [b"x" * 31, b"x" * 33, cast(bytes, "x" * 32)])
def test_digest_validation_rejects_wrong_length_or_type(digest: bytes) -> None:
    with pytest.raises(ValueError, match="exactly 32 bytes"):
        validate_digest(digest)


def test_terminal_receipt_digest_has_a_stable_non_sensitive_golden_vector() -> None:
    assert result_receipt_digest(
        project_id=_PROJECT_ID,
        run_id=_RUN_ID,
        pipeline=TIER_A_PIPELINE,
        pipeline_version=TIER_A_PIPELINE_VERSION,
        code="max_attempts_exhausted",
        trace_digest=b"d" * DIGEST_BYTES,
    ).hex() == "1cc359d872b8a8b990e5a155dfdd1241378e242abeb1b31d48e9e8d73b452621"
    assert result_receipt_digest(
        project_id=_PROJECT_ID,
        run_id=_RUN_ID,
        pipeline=TIER_A_PIPELINE,
        pipeline_version=TIER_A_PIPELINE_VERSION,
        code="max_attempts_exhausted",
        trace_digest=b"d" * DIGEST_BYTES,
    ) != result_receipt_digest(
        project_id=_PROJECT_ID,
        run_id=_RUN_ID,
        pipeline=TIER_A_PIPELINE,
        pipeline_version=TIER_A_PIPELINE_VERSION,
        code="max_attempts_exhausted",
        trace_digest=b"e" * DIGEST_BYTES,
    )


def test_success_receipt_is_canonical_and_excludes_row_ids_or_plaintext() -> None:
    content = "tier-a structural note"
    result = scan(
        content,
        context=ScanContext(
            project_id=_PROJECT_ID,
            mem_type=MemType.EPISODIC,
            trust_tier=TrustTier.A,
            provenance_class=ProvenanceClass.PARSER,
            lane=Lane.OPERATIONAL,
        ),
    )
    candidate = PreparedTierACandidate(
        item=NewMemoryItem(
            scope_type=ScopeType.AGENT_TYPE,
            scope_id=UUID("11111111-1111-1111-1111-111111111111"),
            mem_type=MemType.EPISODIC,
            kind="tool_failure_pattern",
            lane=Lane.OPERATIONAL,
            trust_tier=TrustTier.A,
            status=Status.CANDIDATE,
            content=content,
            token_count=5,
            provenance=Provenance(cls=ProvenanceClass.PARSER, trace_ids=(_RUN_ID,)),
        ),
        scan_verdict=result.verdict(clock=FakeClock(_NOW)),
        content_hash=result.content_hash,
        scan_suite_version=result.suite_version,
        primary_run_id=_RUN_ID,
        contributing_run_ids=(_RUN_ID,),
    )
    rejection = PreparedTierARejection(
        content_hash="a" * 64,
        mem_type=MemType.LESSON,
        suite_version="scans/test",
        reasons=("z_reason", "a_reason"),
    )

    prepared = prepare_tier_a_result(
        lease=_lease(), trace_digest=b"d" * DIGEST_BYTES, candidates=(candidate,), rejections=(rejection,)
    )

    assert prepared.result_digest.hex() == "842ef5c5c6739bd66219cd550a502fb2d73651b202de64ddcebc9b21f46ee36d"
    assert prepared.result_digest == prepare_tier_a_result(
        lease=_lease(), trace_digest=b"d" * DIGEST_BYTES, candidates=(candidate,), rejections=(rejection,)
    ).result_digest
    assert prepared.result_digest != prepare_tier_a_result(
        lease=_lease(), trace_digest=b"e" * DIGEST_BYTES, candidates=(candidate,), rejections=(rejection,)
    ).result_digest
    retry_lease = replace(_lease(), attempts=2)
    assert prepared.result_digest == prepare_tier_a_result(
        lease=retry_lease,
        trace_digest=b"d" * DIGEST_BYTES,
        candidates=(candidate,),
        rejections=(rejection,),
    ).result_digest
    assert skip_receipt_digest(
        lease=_lease(), trace_digest=b"d" * DIGEST_BYTES, code="privacy_tombstoned"
    ) == skip_receipt_digest(
        lease=retry_lease, trace_digest=b"d" * DIGEST_BYTES, code="privacy_tombstoned"
    )
    assert prepared.result_digest != skip_receipt_digest(
        lease=_lease(), trace_digest=b"d" * DIGEST_BYTES, code="privacy_tombstoned"
    )
    changed_output = replace(candidate, item=replace(candidate.item, kind="different_kind"))
    assert prepared.result_digest != prepare_tier_a_result(
        lease=_lease(),
        trace_digest=b"d" * DIGEST_BYTES,
        candidates=(changed_output,),
        rejections=(rejection,),
    ).result_digest


def test_lease_row_round_trip_preserves_trace_end_time_and_full_identity() -> None:
    lease = _lease()
    row = {
        "project_id": lease.project_id.value,
        "run_id": lease.run_id.value,
        "pipeline": lease.pipeline,
        "pipeline_version": lease.pipeline_version,
        "lease_token": lease.lease_token,
        "lease_owner": lease.lease_owner,
        "attempts": lease.attempts,
        "max_attempts": lease.max_attempts,
        "lease_expires_at": lease.lease_expires_at,
        "trace_ended_at": lease.trace_ended_at,
        "trace_digest": b"d" * DIGEST_BYTES,
    }

    restored = TraceLearningJobStore._lease_from_row(row)

    assert restored.project_id == lease.project_id
    assert restored.run_id == lease.run_id
    assert restored.pipeline == lease.pipeline
    assert restored.pipeline_version == lease.pipeline_version
    assert restored.trace_ended_at == lease.trace_ended_at
    assert restored.trace_digest == b"d" * DIGEST_BYTES


def test_store_rejects_unbounded_claims_and_unsafe_retry_input_before_io() -> None:
    store = TraceLearningJobStore(cast(ConnectionPool, object()))
    with pytest.raises(ValueError, match="limit"):
        store.claim(_PROJECT_ID, TIER_A_PIPELINE, 1, "worker-1", 0)
    with pytest.raises(ValueError, match="approved"):
        store.retry(_lease(), timedelta(), "untrusted_error")
    assert "max_attempts_exhausted" in SAFE_ERROR_CODES


def test_retry_sql_types_nullable_terminal_receipts_as_bytea() -> None:
    from tracebed.stores.pg import trace_learning as store_module

    assert "%(result_digest)s::bytea" in store_module._RETRY_SQL
    assert "ELSE NULL::bytea" in store_module._RETRY_SQL


def test_lease_sql_uses_db_wall_time_and_renew_has_a_fencing_recheck() -> None:
    from tracebed.stores.pg import trace_learning as store_module

    candidate_statements = (
        store_module._EXPIRED_RUNNING_SQL,
        store_module._CLAIM_SQL,
    )
    mutation_statements = (
        store_module._EXPIRE_TO_RETRY_SQL,
        store_module._EXPIRE_TO_DEAD_SQL,
        store_module._CLAIM_SQL,
        store_module._RENEW_UPDATE_SQL,
        store_module._RETRY_SQL,
    )
    # Candidate scans do not wait, so the stable statement timestamp remains
    # indexable.  Every state-changing or post-lock fencing predicate uses
    # wall time instead of transaction-start ``now()``.
    assert all("statement_timestamp()" in statement for statement in candidate_statements)
    assert all("clock_timestamp()" in statement for statement in mutation_statements)
    assert all(
        "now()" not in statement
        for statement in candidate_statements
        + mutation_statements
        + (store_module._RENEW_SELECT_SQL, store_module._RETRY_SELECT_SQL)
    )
    assert "FOR UPDATE" in store_module._RENEW_SELECT_SQL
    assert "FOR UPDATE" in store_module._RETRY_SELECT_SQL
    assert store_module._CLOCK_SQL == "SELECT clock_timestamp()"
    assert "lease_expires_at > clock_timestamp()" in store_module._RENEW_UPDATE_SQL
    assert "lease_expires_at > clock_timestamp()" in store_module._RETRY_SQL
