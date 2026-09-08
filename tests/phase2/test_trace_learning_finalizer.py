"""Offline fences for the P2B Tier-A finalizer's untrusted prepared input."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any, cast, overload
from uuid import UUID, uuid4

import pytest

from tracebed.core.scans import ScanContext, scan
from tracebed.core.scans.tier_a_template import (
    ErrorClassEnum,
    HexDigest,
    TierANote,
    ToolIdentifier,
    parse_note,
    render_note,
)
from tracebed.domain.clock import FakeClock
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
from tracebed.domain.ids import AgentTypeId, MemoryId, PrincipalId, ProjectId, RunId, mint_memory_id
from tracebed.domain.memory import NewMemoryItem, Provenance
from tracebed.domain.state_machine import Status
from tracebed.ingest.trace_archive import ArchivedTrace
from tracebed.stores.pg.repo import Repo
from tracebed.stores.pg.rows import TraceIndexRow
from tracebed.stores.pg.trace_learning import TraceLearningFinalizer
from tracebed.workers.extractors import estimate_tier_a_token_count, try_build_note
from tracebed.workers.trace_learning import (
    DIGEST_BYTES,
    TIER_A_PIPELINE,
    TIER_A_PIPELINE_VERSION,
    PreparedTierACandidate,
    PreparedTierARejection,
    PreparedTierAResult,
    TierARejectionOverflow,
    TraceLearningLease,
    prepare_tier_a_result,
)

pytestmark = pytest.mark.phase2

_NOW = datetime(2026, 8, 1, tzinfo=UTC)


def _lease() -> TraceLearningLease:
    return TraceLearningLease(
        project_id=ProjectId("12345678-1234-5678-1234-567812345678"),
        run_id=RunId("87654321-4321-8765-4321-876543214321"),
        pipeline=TIER_A_PIPELINE,
        pipeline_version=TIER_A_PIPELINE_VERSION,
        lease_token=UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
        lease_owner="finalizer-test",
        attempts=1,
        max_attempts=3,
        lease_expires_at=_NOW + timedelta(minutes=1),
        trace_ended_at=_NOW,
        trace_digest=b"p" * DIGEST_BYTES,
    )


def _archive(lease: TraceLearningLease) -> ArchivedTrace:
    return ArchivedTrace(
        index=TraceIndexRow(
            project_id=lease.project_id,
            run_id=lease.run_id,
            agent_type_id=AgentTypeId("11111111-1111-1111-1111-111111111111"),
            workflow_template_id=None,
            submitter_principal=PrincipalId(uuid4()),
            input_signature_hash=b"s" * 32,
            instrumentation_source=InstrumentationSource.SDK,
            arm=Arm.MEMORY_ON,
            path={"end_seq": 0, "end_status": "ok", "seq_ranges": [[0, 0]], "payload_refs": ["fs://x"]},
            started_at=_NOW,
            ended_at=_NOW,
            payload_ref="fs://x",
            outcome_status=TraceOutcomeStatus.OK,
        ),
        events=(),
        trace_digest=b"p" * DIGEST_BYTES,
        subject_key_bindings=(),
    )


def _candidate(lease: TraceLearningLease, archive: ArchivedTrace) -> PreparedTierACandidate:
    note = try_build_note(
        error_class=ErrorClassEnum.TIMEOUT,
        tool_id="tool_a",
        tool_version="v1",
        count=2,
        duration_ms=1,
        payload_class_hash="a" * 64,
    )
    assert note is not None
    content = render_note(note)
    scan_result = scan(
        content,
        context=ScanContext(
            project_id=lease.project_id,
            mem_type=MemType.EPISODIC,
            trust_tier=TrustTier.A,
            provenance_class=ProvenanceClass.PARSER,
            lane=Lane.OPERATIONAL,
        ),
    )
    return PreparedTierACandidate(
        item=NewMemoryItem(
            id=mint_memory_id(),
            scope_type=ScopeType.AGENT_TYPE,
            scope_id=archive.index.agent_type_id.value,
            mem_type=MemType.EPISODIC,
            kind="tool_failure_pattern",
            lane=Lane.OPERATIONAL,
            trust_tier=TrustTier.A,
            status=Status.CANDIDATE,
            content=content,
            token_count=estimate_tier_a_token_count(content),
            provenance=Provenance(
                cls=ProvenanceClass.PARSER,
                trace_ids=(lease.run_id,),
                tool_refs=("tool_a",),
            ),
        ),
        scan_verdict=scan_result.verdict(clock=FakeClock(_NOW)),
        content_hash=scan_result.content_hash,
        scan_suite_version=scan_result.suite_version,
        primary_run_id=lease.run_id,
        contributing_run_ids=(lease.run_id,),
    )


def _finalizer() -> TraceLearningFinalizer:
    return TraceLearningFinalizer(cast(Repo, object()))


def test_finalizer_requires_exact_archive_bound_candidate_and_closed_rejection() -> None:
    lease = _lease()
    archive = _archive(lease)
    candidate = _candidate(lease, archive)
    prepared = prepare_tier_a_result(
        lease=lease, trace_digest=archive.trace_digest, candidates=(candidate,), rejections=()
    )

    _finalizer()._validate_prepared(lease, archive, prepared)

    no_id = replace(candidate, item=replace(candidate.item, id=None))
    with pytest.raises(ValueError, match="exact pre-minted MemoryId"):
        _finalizer()._validate_prepared(
            lease, archive, replace(prepared, candidates=(no_id,))
        )

    forged_content = replace(candidate, item=replace(candidate.item, content=candidate.item.content + "x"))
    with pytest.raises(ValueError, match="content hash"):
        _finalizer()._validate_prepared(
            lease, archive, replace(prepared, candidates=(forged_content,))
        )
    wrong_scope = replace(candidate, item=replace(candidate.item, scope_id=uuid4()))
    with pytest.raises(ValueError, match="non-candidate"):
        _finalizer()._validate_prepared(
            lease, archive, replace(prepared, candidates=(wrong_scope,))
        )

    arbitrary = PreparedTierARejection(
        content_hash="b" * 64,
        mem_type=MemType.EPISODIC,
        suite_version=candidate.scan_suite_version,
        reasons=("attacker-controlled review body",),
    )
    with pytest.raises(ValueError, match="canonical scanner"):
        _finalizer()._validate_prepared(
            lease, archive, replace(prepared, rejections=(arbitrary,))
        )
    overlap = PreparedTierARejection(
        content_hash=candidate.content_hash,
        mem_type=MemType.EPISODIC,
        suite_version=candidate.scan_suite_version,
        reasons=("schema:empty_content",),
    )
    with pytest.raises(ValueError, match="overlaps"):
        _finalizer()._validate_prepared(
            lease, archive, replace(prepared, rejections=(overlap,))
        )


@pytest.mark.parametrize("wrong_id", (RunId(uuid4()), ProjectId(uuid4()), uuid4(), "not-a-memory-id"))
def test_finalizer_rejects_non_memory_typed_ids_before_io(wrong_id: object) -> None:
    lease = _lease()
    archive = _archive(lease)
    candidate = _candidate(lease, archive)
    invalid = replace(candidate, item=replace(candidate.item, id=wrong_id))  # type: ignore[arg-type]
    prepared = PreparedTierAResult(candidates=(invalid,), rejections=(), result_digest=b"r" * DIGEST_BYTES)
    with pytest.raises(ValueError, match="exact pre-minted MemoryId"):
        _finalizer()._validate_prepared(lease, archive, prepared)
    assert type(candidate.item.id) is MemoryId


@pytest.mark.parametrize(
    "field, wrong_value",
    (
        ("project_id", RunId(uuid4())),
        ("run_id", ProjectId(uuid4())),
        ("project_id", uuid4()),
        ("run_id", "not-a-run-id"),
        ("lease_token", "not-a-token"),
        ("pipeline_version", True),
        ("attempts", True),
        ("max_attempts", False),
    ),
)
def test_finalizer_lease_identity_and_numeric_shapes_fail_before_io(
    field: str, wrong_value: object
) -> None:
    lease = replace(_lease(), **{field: wrong_value})  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        _finalizer()._validate_tier_a_lease(lease)


def test_finalizer_rejects_duplicate_semantic_output_and_preserves_scan_reason_order() -> None:
    lease = _lease()
    archive = _archive(lease)
    candidate = _candidate(lease, archive)
    duplicate = replace(candidate, item=replace(candidate.item, id=mint_memory_id()))
    result = PreparedTierAResult(
        candidates=(candidate, duplicate), rejections=(), result_digest=b"r" * DIGEST_BYTES
    )
    with pytest.raises(ValueError, match="candidate content hash"):
        _finalizer()._validate_prepared(lease, archive, result)

    rejection = PreparedTierARejection(
        content_hash="c" * 64,
        mem_type=MemType.EPISODIC,
        suite_version=candidate.scan_suite_version,
        reasons=("schema:control_characters", "schema:empty_content"),
    )
    _finalizer()._validate_prepared(
        lease,
        archive,
        PreparedTierAResult(candidates=(), rejections=(rejection,), result_digest=b"r" * DIGEST_BYTES),
    )


class _FenceCursor:
    def __init__(self, lease: TraceLearningLease, *, stored: bytes | None = b"s" * DIGEST_BYTES) -> None:
        self._rows: list[dict[str, Any]] = [
            {
                "trace_digest": stored,
                "trace_ended_at": lease.trace_ended_at,
                "lease_expires_at": _NOW + timedelta(minutes=1),
            },
            {"clock_timestamp": _NOW},
        ]

    def execute(self, _sql: str, _params: object = None) -> None:
        pass

    def fetchone(self) -> dict[str, Any] | None:
        return self._rows.pop(0) if self._rows else None


def test_digest_mismatch_dead_path_retains_the_stored_write_once_baseline() -> None:
    lease = _lease()
    baseline = _finalizer()._lock_live_fence(
        _FenceCursor(lease), lease, b"o" * DIGEST_BYTES, allow_digest_mismatch=True
    )
    assert baseline == b"s" * DIGEST_BYTES
    with pytest.raises(ValueError, match="write-once"):
        _finalizer()._lock_live_fence(_FenceCursor(lease), lease, b"o" * DIGEST_BYTES)


def test_reuse_query_locks_exact_canonical_tier_a_rows_only() -> None:
    from tracebed.stores.pg import trace_learning as module

    sql = module._REUSE_TIER_A_SQL
    for clause in (
        "content = %(content)s",
        "token_count = %(token_count)s",
        "schema_version = %(schema_version)s",
        "provenance->>'class' = 'parser'",
        "cluster_id IS NULL",
        "ttl_class IS NULL",
        "valid_from IS NULL",
        "valid_to IS NULL",
        "ORDER BY created_at, id",
    ):
        assert clause in sql


def test_terminal_finalizer_sql_clears_all_running_lease_fields_once() -> None:
    from tracebed.stores.pg import trace_learning as module

    for sql in (
        module._FINALIZE_SUCCESS_SQL,
        module._FINALIZE_SKIP_SQL,
        module._FINALIZE_DEAD_SQL,
    ):
        assert "lease_token = NULL" in sql
        assert "lease_owner = NULL" in sql
        assert "lease_expires_at = NULL" in sql
        assert sql.count("AND state = 'running'") == 1


@pytest.mark.parametrize(
    "field, replacement",
    (
        ("ec", "FREE_TEXT"),
        ("ti", "tool with spaces"),
        ("ti", "tool\n"),
        ("ti", "tool\r\n"),
        ("tv", "version with spaces"),
        ("n", "01"),
        ("dur", "-1"),
        ("pch", "A" * 64),
        ("pch", "a" * 64 + "\n"),
    ),
)
def test_finalizer_tier_a_note_parser_rejects_every_forged_field(
    field: str, replacement: str
) -> None:
    lease = _lease()
    content = _candidate(lease, _archive(lease)).item.content
    forged = "|".join(
        f"{key}={replacement if key == field else value}"
        for key, value in (
            part.split("=", 1) for part in content.split("|")[1:]
        )
    )
    with pytest.raises(ValueError):
        parse_note(f"TAN1|{forged}")


@pytest.mark.parametrize("suffix", ("\n", "\r\n"))
def test_tier_a_note_constructor_refuses_trailing_line_breaks(suffix: str) -> None:
    with pytest.raises(ValueError):
        TierANote(
            error_class=ErrorClassEnum.TIMEOUT,
            tool_id=ToolIdentifier(f"tool{suffix}"),
            tool_version=ToolIdentifier("v1"),
            count=1,
            duration_ms=1,
            payload_class_hash=HexDigest("a" * 64),
        )
    with pytest.raises(ValueError):
        TierANote(
            error_class=ErrorClassEnum.TIMEOUT,
            tool_id=ToolIdentifier("tool"),
            tool_version=ToolIdentifier("v1"),
            count=1,
            duration_ms=1,
            payload_class_hash=HexDigest("a" * 64 + suffix),
        )


def test_finalizer_binds_kind_and_token_count_to_the_canonical_tier_a_shape() -> None:
    lease = _lease()
    archive = _archive(lease)
    candidate = _candidate(lease, archive)
    prepared = prepare_tier_a_result(
        lease=lease, trace_digest=archive.trace_digest, candidates=(candidate,), rejections=()
    )
    with pytest.raises(ValueError, match="non-candidate"):
        _finalizer()._validate_prepared(
            lease,
            archive,
            replace(prepared, candidates=(replace(candidate, item=replace(candidate.item, kind="free_text")),)),
        )
    with pytest.raises(ValueError, match="non-candidate"):
        _finalizer()._validate_prepared(
            lease,
            archive,
            replace(
                prepared,
                candidates=(replace(candidate, item=replace(candidate.item, token_count=0)),),
            ),
        )


def test_finalizer_rejects_repeated_candidate_hash_even_if_other_fields_differ() -> None:
    lease = _lease()
    archive = _archive(lease)
    candidate = _candidate(lease, archive)
    second = replace(candidate, item=replace(candidate.item, id=mint_memory_id()))
    prepared = PreparedTierAResult(
        candidates=(candidate, second), rejections=(), result_digest=b"r" * DIGEST_BYTES
    )
    with pytest.raises(ValueError, match="content hash"):
        _finalizer()._validate_prepared(lease, archive, prepared)


def test_finalizer_rejects_same_rejection_codes_in_a_different_review_order() -> None:
    lease = _lease()
    archive = _archive(lease)
    suite_version = _candidate(lease, archive).scan_suite_version
    first = PreparedTierARejection(
        content_hash="d" * 64,
        mem_type=MemType.EPISODIC,
        suite_version=suite_version,
        reasons=("schema:control_characters", "schema:empty_content"),
    )
    second = replace(first, reasons=tuple(reversed(first.reasons)))
    prepared = PreparedTierAResult(
        candidates=(), rejections=(first, second), result_digest=b"r" * DIGEST_BYTES
    )
    with pytest.raises(ValueError, match="scan rejection"):
        _finalizer()._validate_prepared(lease, archive, prepared)


@pytest.mark.parametrize("mem_type", tuple(MemType))
def test_finalizer_rejection_mem_type_is_limited_to_tier_a_outputs(mem_type: MemType) -> None:
    lease = _lease()
    archive = _archive(lease)
    rejection = PreparedTierARejection(
        content_hash="e" * 64,
        mem_type=mem_type,
        suite_version=_candidate(lease, archive).scan_suite_version,
        reasons=("schema:empty_content",),
    )
    prepared = PreparedTierAResult(candidates=(), rejections=(rejection,), result_digest=b"r" * DIGEST_BYTES)
    if mem_type in {MemType.EPISODIC, MemType.LESSON}:
        _finalizer()._validate_prepared(lease, archive, prepared)
    else:
        with pytest.raises(ValueError, match="canonical scanner"):
            _finalizer()._validate_prepared(lease, archive, prepared)


def test_finalizer_rejection_requires_a_real_mem_type_not_an_enum_equal_string() -> None:
    lease = _lease()
    archive = _archive(lease)
    rejection = PreparedTierARejection(
        content_hash="e" * 64,
        mem_type=cast(MemType, "episodic"),
        suite_version=_candidate(lease, archive).scan_suite_version,
        reasons=("schema:empty_content",),
    )
    with pytest.raises(ValueError, match="canonical scanner"):
        _finalizer()._validate_prepared(
            lease,
            archive,
            PreparedTierAResult(candidates=(), rejections=(rejection,), result_digest=b"r" * DIGEST_BYTES),
        )


def _retained_rejections(count: int, *, suite_version: str) -> tuple[PreparedTierARejection, ...]:
    return tuple(
        PreparedTierARejection(
            content_hash=f"{index:064x}",
            mem_type=MemType.EPISODIC,
            suite_version=suite_version,
            reasons=("schema:empty_content",),
        )
        for index in range(count)
    )


def _valid_overflow(*, suite_version: str) -> TierARejectionOverflow:
    return TierARejectionOverflow(
        total_count=101,
        omitted_count=1,
        omitted_digest=b"o" * DIGEST_BYTES,
        suite_version=suite_version,
        mem_type_counts=((MemType.EPISODIC, 1),),
        reason_counts=(("schema:empty_content", 1),),
    )


def test_finalizer_validates_the_bounded_rejection_overflow_shape_before_io() -> None:
    lease = _lease()
    archive = _archive(lease)
    suite_version = _candidate(lease, archive).scan_suite_version
    retained = _retained_rejections(100, suite_version=suite_version)
    overflow = _valid_overflow(suite_version=suite_version)
    valid = PreparedTierAResult(
        candidates=(),
        rejections=retained,
        result_digest=b"r" * DIGEST_BYTES,
        rejection_overflow=overflow,
    )
    _finalizer()._validate_prepared(lease, archive, valid)

    malformed = (
        replace(overflow, omitted_digest=cast(bytes, None)),
        replace(overflow, omitted_digest=b"short"),
        replace(overflow, suite_version="obsolete-suite"),
        replace(overflow, total_count=100),
        replace(
            overflow,
            total_count=102,
            omitted_count=2,
            mem_type_counts=((MemType.EPISODIC, 2),),
            reason_counts=(("schema:empty_content", 1),),
        ),
        replace(overflow, mem_type_counts=cast(tuple[tuple[MemType, int], ...], [(MemType.EPISODIC, 1)])),
        replace(overflow, reason_counts=cast(tuple[tuple[str, int], ...], [("schema:empty_content", 1)])),
        replace(overflow, reason_counts=(("not-a-safe-code", 1),)),
    )
    for invalid in malformed:
        with pytest.raises(ValueError):
            _finalizer()._validate_prepared(
                lease, archive, replace(valid, rejection_overflow=invalid)
            )
    with pytest.raises(ValueError, match="too many rejections"):
        _finalizer()._validate_prepared(
            lease,
            archive,
            replace(valid, rejections=(*retained, retained[-1]), rejection_overflow=None),
        )


class _MutablePreparedSequence(Sequence[object]):
    def __init__(self, values: list[object]) -> None:
        self.values = values

    def __len__(self) -> int:
        return len(self.values)

    @overload
    def __getitem__(self, index: int) -> object: ...

    @overload
    def __getitem__(self, index: slice) -> Sequence[object]: ...

    def __getitem__(self, index: int | slice) -> object | Sequence[object]:
        return self.values[index]


@pytest.mark.parametrize(
    "candidates,rejections",
    (
        (cast(tuple[PreparedTierACandidate, ...], []), cast(tuple[PreparedTierARejection, ...], [])),
        (
            cast(tuple[PreparedTierACandidate, ...], _MutablePreparedSequence([])),
            cast(tuple[PreparedTierARejection, ...], ()),
        ),
    ),
)
def test_finalizer_requires_exact_prepared_tuple_containers_before_io(
    candidates: tuple[PreparedTierACandidate, ...],
    rejections: tuple[PreparedTierARejection, ...],
) -> None:
    with pytest.raises(ValueError, match="exact tuples"):
        _finalizer()._validate_prepared(
            _lease(),
            _archive(_lease()),
            PreparedTierAResult(candidates=candidates, rejections=rejections, result_digest=b"r" * DIGEST_BYTES),
        )


def test_finalizer_rejects_mutable_duck_candidate_before_any_field_is_read() -> None:
    class _MutableCandidate:
        def __init__(self) -> None:
            self.item = object()

    with pytest.raises(ValueError, match="exact immutable type"):
        _finalizer()._validate_prepared(
            _lease(),
            _archive(_lease()),
            PreparedTierAResult(
                candidates=(cast(PreparedTierACandidate, _MutableCandidate()),),
                rejections=(),
                result_digest=b"r" * DIGEST_BYTES,
            ),
        )

    class _MutableRejection:
        pass

    with pytest.raises(ValueError, match="canonical scanner"):
        _finalizer()._validate_prepared(
            _lease(),
            _archive(_lease()),
            PreparedTierAResult(
                candidates=(),
                rejections=(cast(PreparedTierARejection, _MutableRejection()),),
                result_digest=b"r" * DIGEST_BYTES,
            ),
        )

    with pytest.raises(ValueError, match="exact immutable type"):
        _finalizer()._validate_prepared(
            _lease(), _archive(_lease()), cast(PreparedTierAResult, object())
        )


def test_finalizer_requires_exact_tuple_of_exact_string_reasons_before_io() -> None:
    lease = _lease()
    archive = _archive(lease)
    rejection = PreparedTierARejection(
        content_hash="e" * 64,
        mem_type=MemType.EPISODIC,
        suite_version=_candidate(lease, archive).scan_suite_version,
        reasons=cast(tuple[str, ...], ["schema:empty_content"]),
    )
    with pytest.raises(ValueError, match="canonical scanner"):
        _finalizer()._validate_prepared(
            lease,
            archive,
            PreparedTierAResult(candidates=(), rejections=(rejection,), result_digest=b"r" * DIGEST_BYTES),
        )

    class _StringSubclass(str):
        pass

    subclass_reason = replace(rejection, reasons=(_StringSubclass("schema:empty_content"),))
    with pytest.raises(ValueError, match="canonical scanner"):
        _finalizer()._validate_prepared(
            lease,
            archive,
            PreparedTierAResult(
                candidates=(), rejections=(subclass_reason,), result_digest=b"r" * DIGEST_BYTES
            ),
        )
