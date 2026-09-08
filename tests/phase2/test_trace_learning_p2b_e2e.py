"""Live P2B finalizer atomicity, reuse, and erasure-race evidence."""

from __future__ import annotations

import os
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import psycopg
import pytest
from psycopg.conninfo import make_conninfo

from tests.phase2.trace_e2e_support import _enqueue, _event, _Master
from tracebed.core.scans import ScanContext, scan
from tracebed.core.scans.tier_a_template import ErrorClassEnum, render_note
from tracebed.crypto.shred import SubjectKeyManager
from tracebed.domain.clock import FakeClock
from tracebed.domain.config import ConfigResolver, TracebedSettings
from tracebed.domain.enums import Lane, MemType, ProvenanceClass, ScopeType, TrustTier
from tracebed.domain.ids import AgentTypeId, MemoryId, PrincipalId, ProjectId, RunId, mint_memory_id
from tracebed.domain.memory import NewMemoryItem, Provenance
from tracebed.domain.scope import ProjectScope
from tracebed.domain.state_machine import Status
from tracebed.ingest.trace_archive import ArchivedTrace, TraceArchiveReader
from tracebed.ingest.trace_writer import TraceWriter
from tracebed.stores.pg.partitions import create_project_partitions
from tracebed.stores.pg.pool import create_pool, scoped
from tracebed.stores.pg.queue import WorkQueue
from tracebed.stores.pg.repo import Repo, ScopedRepo
from tracebed.stores.pg.trace_learning import TraceLearningFinalizer, TraceLearningJobStore
from tracebed.stores.tracestore.fs import FsTraceStore
from tracebed.workers.extractors import (
    ToolFailureExtractor,
    estimate_tier_a_token_count,
    try_build_note,
)
from tracebed.workers.tier_a_lane import TierALane
from tracebed.workers.trace_learning import (
    TIER_A_PIPELINE,
    TIER_A_PIPELINE_VERSION,
    PreparedTierACandidate,
    PreparedTierARejection,
    PreparedTierAResult,
    TraceLearningLease,
    TraceLearningState,
    prepare_tier_a_result,
    result_receipt_digest,
)

pytestmark = [pytest.mark.phase2, pytest.mark.integration]


def _prepared_tier_a_result(
    *,
    lease: TraceLearningLease,
    archive: ArchivedTrace,
    clock: FakeClock,
    tool_id: str,
    include_rejection: bool,
) -> PreparedTierAResult:
    """Build one genuine scanner-bound parser item for the live finalizer.

    This is deliberately not a fake finalizer payload: the token count, note,
    scanner verdict, provenance, and receipt all travel through the same
    public constructors used by the coordinator.
    """
    note = try_build_note(
        error_class=ErrorClassEnum.TIMEOUT,
        tool_id=tool_id,
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
    assert scan_result.passed
    candidate = PreparedTierACandidate(
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
                tool_refs=(tool_id,),
            ),
        ),
        scan_verdict=scan_result.verdict(clock=clock),
        content_hash=scan_result.content_hash,
        scan_suite_version=scan_result.suite_version,
        primary_run_id=lease.run_id,
        contributing_run_ids=(lease.run_id,),
    )
    rejections = (
        (
            PreparedTierARejection(
                content_hash="b" * 64,
                mem_type=MemType.EPISODIC,
                suite_version=scan_result.suite_version,
                reasons=("schema:empty_content",),
            ),
        )
        if include_rejection
        else ()
    )
    return prepare_tier_a_result(
        lease=lease,
        trace_digest=archive.trace_digest,
        candidates=(candidate,),
        rejections=rejections,
    )


def _real_lane_overflow_prepared_result(
    *,
    settings: TracebedSettings,
    repo: Repo,
    project_id: ProjectId,
    agent_type_id: AgentTypeId,
    principal_id: PrincipalId,
    lease: TraceLearningLease,
    archive: ArchivedTrace,
    clock: FakeClock,
) -> PreparedTierAResult:
    """Plan the decrypted archive's 101 injection-shaped tool notes.

    The caller has created the archive with the production queue, writer, and
    reader.  Planning only these returned events proves an overflow receipt is
    bound to the trace job that finalization fences.
    """
    lane = TierALane(
        cfg=ConfigResolver(settings, repo).effective(project_id, agent_type_id),
        clock=clock,
        extractors=(ToolFailureExtractor(),),
    )
    plan = lane.plan(
        ProjectScope(project_id, agent_type_id, principal_id), {lease.run_id: archive.events}
    )
    assert len(plan.rejections) == 100
    assert plan.rejection_overflow is not None
    assert (plan.rejection_overflow.total_count, plan.rejection_overflow.omitted_count) == (101, 1)
    assert plan.candidates == ()
    return prepare_tier_a_result(
        lease=lease,
        trace_digest=archive.trace_digest,
        candidates=(),
        rejections=tuple(
            PreparedTierARejection(
                content_hash=rejection.content_hash,
                mem_type=rejection.mem_type,
                suite_version=rejection.suite_version,
                reasons=rejection.reasons,
            )
            for rejection in plan.rejections
        ),
        rejection_overflow=plan.rejection_overflow,
    )


def test_real_finalizer_atomic_reuse_and_subject_erasure_races(
    settings: TracebedSettings,
    tmp_path: Path,
    scratch_dsn: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Exercise P2B's whole finalizer boundary against a fresh RLS database.

    The cases intentionally use no transactional fakes: memory/review insert,
    terminal job update, job reuse, subject-key locking, lifecycle lookup, and
    tombstoning all execute through their production Postgres adapters.
    """
    owner_pool = create_pool(scratch_dsn)
    owner_pool.wait(timeout=5)
    app_dsn = make_conninfo(
        scratch_dsn,
        user="tracebed_app",
        password=os.environ.get("TB_APP_PASSWORD", "tracebed_app_dev_only"),
    )
    app_pool = None
    try:
        with psycopg.connect(app_dsn, connect_timeout=2):
            pass
        app_pool = create_pool(app_dsn)
        app_pool.wait(timeout=5)
    except Exception as exc:  # pragma: no cover - deployment-owned app credential
        if app_pool is not None:
            app_pool.close()
        owner_pool.close()
        pytest.skip(f"tracebed_app connection unavailable for P2B E2E: {exc.__class__.__name__}")

    try:
        clock = FakeClock(datetime(2026, 1, 2, tzinfo=UTC))
        owner_repo = Repo(owner_pool, clock)
        project_id = owner_repo.create_project("p2b-finalizer-e2e")
        principal_id = owner_repo.create_principal("api_key", "p2b-finalizer-e2e", "hash")
        agent_type_id = owner_repo.create_agent_type(project_id, "p2b-finalizer-agent")
        owner_repo.register_agent(project_id, principal_id, agent_type_id)
        with owner_pool.connection() as conn:
            create_project_partitions(conn, project_id)

        repo = Repo(app_pool, clock)
        queue = WorkQueue(app_pool, clock, settings.queue)
        store = FsTraceStore(tmp_path / "p2b-finalizer-traces")
        keys = SubjectKeyManager(repo, _Master(), clock)
        writer = TraceWriter(queue, repo, store, keys, clock, settings)
        reader = TraceArchiveReader(repo, store, keys)
        jobs = TraceLearningJobStore(app_pool)

        def terminal_archive(
            subject_tags: tuple[str, ...], *, offset: int
        ) -> tuple[TraceLearningLease, ArchivedTrace]:
            run_id = RunId(uuid.uuid4())
            ended_at = clock.now() + timedelta(seconds=offset)
            _enqueue(
                queue,
                project_id,
                principal_id,
                agent_type_id,
                run_id,
                [
                    (0, _event("run_start", clock.now(), {"query_text": f"p2b-{offset}"})),
                    (1, _event("state_note", clock.now(), {"subject_tags": list(subject_tags)})),
                    (2, _event("run_end", ended_at, {"status": "ok"})),
                ],
            )
            assert writer.run_once() == 3
            leases = jobs.claim(
                project_id, TIER_A_PIPELINE, TIER_A_PIPELINE_VERSION, f"p2b-{offset}", 1
            )
            assert len(leases) == 1
            archive = reader.read_complete(
                project_id,
                run_id,
                expected_ended_at=ended_at,
            )
            return leases[0], archive

        def overflow_terminal_archive(
            subject_tag: str, *, offset: int
        ) -> tuple[TraceLearningLease, ArchivedTrace, tuple[str, ...]]:
            """Build the full 101-rejection trace through queue/writer/reader."""

            run_id = RunId(uuid.uuid4())
            tool_ids = tuple(
                f"ignore_all_previous_instructions_{index:03d}" for index in range(101)
            )
            base = clock.now() + timedelta(seconds=offset)
            events: list[tuple[int, dict[str, object]]] = [
                (
                    0,
                    _event(
                        "run_start",
                        base,
                        {"query_text": "overflow planner proof", "tool_manifest": list(tool_ids)},
                    ),
                ),
                (1, _event("state_note", base, {"subject_tags": [subject_tag]})),
            ]
            seq = 2
            for index, tool_id in enumerate(tool_ids, start=1):
                for repeat in range(2):
                    events.append(
                        (
                            seq,
                            _event(
                                "error",
                                base + timedelta(seconds=index * 2 + repeat),
                                {
                                    "tool_id": tool_id,
                                    "tool_version": "v1",
                                    "error_class": "timeout",
                                },
                            ),
                        )
                    )
                    seq += 1
            ended_at = base + timedelta(seconds=seq + 1)
            events.append((seq, _event("run_end", ended_at, {"status": "ok"})))
            _enqueue(queue, project_id, principal_id, agent_type_id, run_id, events)

            processed = 0
            while batch_count := writer.run_once():
                processed += batch_count
            assert processed == len(events)
            (lease,) = jobs.claim(
                project_id, TIER_A_PIPELINE, TIER_A_PIPELINE_VERSION, f"p2b-overflow-{offset}", 1
            )
            assert lease.run_id == run_id
            archive = reader.read_complete(project_id, run_id, expected_ended_at=ended_at)
            assert len(archive.events) == len(events)
            return lease, archive, tool_ids

        def counts() -> tuple[int, int]:
            with scoped(app_pool, project_id) as conn:
                row = conn.execute(
                    "SELECT "
                    "(SELECT count(*) FROM memory_item WHERE project_id = %(project_id)s), "
                    "(SELECT count(*) FROM review_queue WHERE project_id = %(project_id)s)",
                    {"project_id": project_id},
                ).fetchone()
            assert row is not None
            return int(row[0]), int(row[1])

        # Candidate + scanner rejection + fenced terminal state commit in one
        # transaction.  A later query sees all three durable facts together.
        lease, archive = terminal_archive(("user:success",), offset=2)
        prepared = _prepared_tier_a_result(
            lease=lease,
            archive=archive,
            clock=clock,
            tool_id="tool-shared",
            include_rejection=True,
        )
        finalizer = TraceLearningFinalizer(repo)
        assert finalizer.finalize_success(lease, archive, prepared) is TraceLearningState.SUCCEEDED
        assert counts() == (1, 1)
        with scoped(app_pool, project_id) as conn:
            first_job = conn.execute(
                "SELECT state, memory_ids FROM trace_learning_job "
                "WHERE project_id = %s AND run_id = %s AND pipeline = %s AND pipeline_version = %s",
                (project_id.value, lease.run_id.value, TIER_A_PIPELINE, TIER_A_PIPELINE_VERSION),
            ).fetchone()
        assert first_job is not None and first_job[0] == "succeeded" and len(first_job[1]) == 1
        first_memory_id = first_job[1][0]

        # The 101st scanner refusal is represented by exactly one committed
        # summary row.  The job succeeds with no memory output, while the
        # finalizer transaction carries its 100 normal rows plus the summary.
        overflow_lease, overflow_archive, overflow_tool_ids = overflow_terminal_archive(
            "user:overflow", offset=20
        )
        overflow_prepared = _real_lane_overflow_prepared_result(
            settings=settings,
            repo=repo,
            project_id=project_id,
            agent_type_id=agent_type_id,
            principal_id=principal_id,
            lease=overflow_lease,
            archive=overflow_archive,
            clock=clock,
        )
        assert (
            overflow_prepared.result_digest
            == _real_lane_overflow_prepared_result(
                settings=settings,
                repo=repo,
                project_id=project_id,
                agent_type_id=agent_type_id,
                principal_id=principal_id,
                lease=overflow_lease,
                archive=overflow_archive,
                clock=clock,
            ).result_digest
        )
        before_overflow = counts()
        assert (
            TraceLearningFinalizer(repo).finalize_success(
                overflow_lease, overflow_archive, overflow_prepared
            )
            is TraceLearningState.SUCCEEDED
        )
        assert counts() == (before_overflow[0], before_overflow[1] + 101)
        review_count_after_overflow = before_overflow[1] + 101
        with scoped(app_pool, project_id) as conn:
            overflow_job = conn.execute(
                "SELECT state, memory_ids FROM trace_learning_job "
                "WHERE project_id = %s AND run_id = %s AND pipeline = %s AND pipeline_version = %s",
                (
                    project_id.value,
                    overflow_lease.run_id.value,
                    TIER_A_PIPELINE,
                    TIER_A_PIPELINE_VERSION,
                ),
            ).fetchone()
        assert overflow_job == ("succeeded", [])
        with scoped(app_pool, project_id) as conn:
            summaries = conn.execute(
                "SELECT reason FROM review_queue WHERE project_id = %s AND reason LIKE %s",
                (project_id.value, "%tier_a_scan_rejection_overflow/v1%"),
            ).fetchall()
        assert len(summaries) == 1
        summary_reason = str(summaries[0][0])
        assert all(tool_id not in summary_reason for tool_id in overflow_tool_ids)
        assert "TAN1|" not in summary_reason

        # A summary-row failure is inside the same repository transaction as
        # all retained reviews and the terminal state: no partial review rows
        # or terminal success can survive it.
        summary_fail_lease, summary_fail_archive, _summary_fail_tool_ids = (
            overflow_terminal_archive("user:overflow-fail", offset=21)
        )
        summary_fail_overflow = _real_lane_overflow_prepared_result(
            settings=settings,
            repo=repo,
            project_id=project_id,
            agent_type_id=agent_type_id,
            principal_id=principal_id,
            lease=summary_fail_lease,
            archive=summary_fail_archive,
            clock=clock,
        )
        summary_fail_candidate = _prepared_tier_a_result(
            lease=summary_fail_lease,
            archive=summary_fail_archive,
            clock=clock,
            tool_id="tool-overflow-fail",
            include_rejection=False,
        )
        summary_fail_prepared = prepare_tier_a_result(
            lease=summary_fail_lease,
            trace_digest=summary_fail_archive.trace_digest,
            candidates=summary_fail_candidate.candidates,
            rejections=summary_fail_overflow.rejections,
            rejection_overflow=summary_fail_overflow.rejection_overflow,
        )
        summary_counts = counts()
        original_insert_review_item = ScopedRepo.insert_review_item

        def reject_overflow_summary(
            scoped_repo: ScopedRepo, reason: str, memory_id: MemoryId | None = None
        ) -> None:
            if "tier_a_scan_rejection_overflow/v1" in reason:
                raise RuntimeError("summary review insertion failure")
            original_insert_review_item(scoped_repo, reason, memory_id)

        monkeypatch.setattr(ScopedRepo, "insert_review_item", reject_overflow_summary)
        with pytest.raises(RuntimeError, match="summary review insertion failure"):
            TraceLearningFinalizer(repo).finalize_success(
                summary_fail_lease, summary_fail_archive, summary_fail_prepared
            )
        assert counts() == summary_counts
        with scoped(app_pool, project_id) as conn:
            assert conn.execute(
                "SELECT state FROM trace_learning_job "
                "WHERE project_id = %s AND run_id = %s AND pipeline = %s AND pipeline_version = %s",
                (
                    project_id.value,
                    summary_fail_lease.run_id.value,
                    TIER_A_PIPELINE,
                    TIER_A_PIPELINE_VERSION,
                ),
            ).fetchone() == ("running",)
        monkeypatch.setattr(ScopedRepo, "insert_review_item", original_insert_review_item)

        # A second terminal trace with byte-identical Tier-A semantics binds
        # the existing canonical row, never creates another one.
        reuse_lease, reuse_archive = terminal_archive(("user:reuse",), offset=3)
        reuse_prepared = _prepared_tier_a_result(
            lease=reuse_lease,
            archive=reuse_archive,
            clock=clock,
            tool_id="tool-shared",
            include_rejection=False,
        )
        assert (
            TraceLearningFinalizer(repo).finalize_success(
                reuse_lease, reuse_archive, reuse_prepared
            )
            is TraceLearningState.SUCCEEDED
        )
        assert counts() == (1, review_count_after_overflow)
        with scoped(app_pool, project_id) as conn:
            reuse_job = conn.execute(
                "SELECT memory_ids FROM trace_learning_job "
                "WHERE project_id = %s AND run_id = %s AND pipeline = %s AND pipeline_version = %s",
                (
                    project_id.value,
                    reuse_lease.run_id.value,
                    TIER_A_PIPELINE,
                    TIER_A_PIPELINE_VERSION,
                ),
            ).fetchone()
        assert reuse_job == ([first_memory_id],)

        # Force the *last* fenced terminal UPDATE to lose after its real
        # memory/review writes.  The enclosing Repo.tx rolls every earlier
        # insert back, leaving the job running and counts unchanged.
        lost_lease, lost_archive = terminal_archive(("user:lost",), offset=4)
        lost_prepared = _prepared_tier_a_result(
            lease=lost_lease,
            archive=lost_archive,
            clock=clock,
            tool_id="tool-lost",
            include_rejection=True,
        )
        lost_finalizer = TraceLearningFinalizer(repo)
        original_finish = lost_finalizer._finish_success_locked

        def expire_before_last_fence(*args: object) -> TraceLearningState | None:
            cur = args[0]
            assert hasattr(cur, "execute")
            cur.execute(
                "UPDATE trace_learning_job SET lease_expires_at = clock_timestamp() - interval '1 second' "
                "WHERE project_id = %s AND run_id = %s AND pipeline = %s AND pipeline_version = %s",
                (
                    project_id.value,
                    lost_lease.run_id.value,
                    TIER_A_PIPELINE,
                    TIER_A_PIPELINE_VERSION,
                ),
            )
            return original_finish(*args)  # type: ignore[arg-type]

        monkeypatch.setattr(lost_finalizer, "_finish_success_locked", expire_before_last_fence)
        assert lost_finalizer.finalize_success(lost_lease, lost_archive, lost_prepared) is None
        assert counts() == (1, review_count_after_overflow)
        with scoped(app_pool, project_id) as conn:
            lost_state = conn.execute(
                "SELECT state FROM trace_learning_job "
                "WHERE project_id = %s AND run_id = %s AND pipeline = %s AND pipeline_version = %s",
                (
                    project_id.value,
                    lost_lease.run_id.value,
                    TIER_A_PIPELINE,
                    TIER_A_PIPELINE_VERSION,
                ),
            ).fetchone()
        assert lost_state == ("running",)

        # Public mismatch finalization has a three-way fence: a job must have
        # a previously pinned digest and the observation must be concrete and
        # different. Missing/equal observations leave the running row and all
        # durable artifacts untouched; a distinct observation terminalizes
        # over the stored baseline, never the observed bytes.
        mismatch_lease, mismatch_archive = terminal_archive(("user:mismatch",), offset=5)
        assert (
            jobs.retry(
                mismatch_lease,
                timedelta(),
                "archive_digest_mismatch",
                trace_digest=mismatch_archive.trace_digest,
            )
            is TraceLearningState.RETRY
        )
        (mismatch_reclaim,) = jobs.claim(
            project_id, TIER_A_PIPELINE, TIER_A_PIPELINE_VERSION, "p2b-mismatch-reclaim", 1
        )
        mismatch_finalizer = TraceLearningFinalizer(repo)
        for observed in (None, mismatch_archive.trace_digest):
            with pytest.raises(ValueError, match="distinct stored and observed"):
                mismatch_finalizer.finalize_dead(
                    mismatch_reclaim, "archive_digest_mismatch", observed
                )
        with scoped(app_pool, project_id) as conn:
            still_running = conn.execute(
                "SELECT state, trace_digest, result_digest, memory_ids, lease_token, lease_owner, lease_expires_at "
                "FROM trace_learning_job WHERE project_id = %s AND run_id = %s AND pipeline = %s AND pipeline_version = %s",
                (
                    project_id.value,
                    mismatch_reclaim.run_id.value,
                    TIER_A_PIPELINE,
                    TIER_A_PIPELINE_VERSION,
                ),
            ).fetchone()
        assert still_running is not None
        assert still_running[:4] == ("running", mismatch_archive.trace_digest, None, [])
        assert all(value is not None for value in still_running[4:])
        assert counts() == (1, review_count_after_overflow)
        observed = b"z" * 32
        assert (
            mismatch_finalizer.finalize_dead(mismatch_reclaim, "archive_digest_mismatch", observed)
            is TraceLearningState.DEAD
        )
        with scoped(app_pool, project_id) as conn:
            dead = conn.execute(
                "SELECT state, trace_digest, result_digest, memory_ids, lease_token, lease_owner, lease_expires_at "
                "FROM trace_learning_job WHERE project_id = %s AND run_id = %s AND pipeline = %s AND pipeline_version = %s",
                (
                    project_id.value,
                    mismatch_reclaim.run_id.value,
                    TIER_A_PIPELINE,
                    TIER_A_PIPELINE_VERSION,
                ),
            ).fetchone()
        assert dead is not None
        assert dead[:2] == ("dead", mismatch_archive.trace_digest)
        assert bytes(dead[2]) == result_receipt_digest(
            project_id=project_id,
            run_id=mismatch_reclaim.run_id,
            pipeline=TIER_A_PIPELINE,
            pipeline_version=TIER_A_PIPELINE_VERSION,
            code="archive_digest_mismatch",
            trace_digest=mismatch_archive.trace_digest,
        )
        assert dead[3:] == ([], None, None, None)
        assert counts() == (1, review_count_after_overflow)

        # E3 owns key destruction through its separately credentialed SQL
        # executor.  This learning-loop test deliberately has no raw-tag
        # mutation seam; the E3 suite covers its fencing/lease race surface.
        from tracebed.stores.pg.lifecycle import MemoryEditRepo

        assert not hasattr(MemoryEditRepo, "select_by_subject_tag")
    finally:
        owner_pool.close()
        if app_pool is not None:
            app_pool.close()
