"""Live P2A hand-off: queue -> terminal archive -> durable job -> reader."""

from __future__ import annotations

import os
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import psycopg
import pytest
from psycopg.conninfo import make_conninfo

from tests.phase2.trace_e2e_support import _enqueue, _event, _Master
from tracebed.crypto.shred import SubjectKeyManager
from tracebed.domain.clock import FakeClock
from tracebed.domain.config import TracebedSettings
from tracebed.domain.enums import TraceOutcomeStatus
from tracebed.domain.ids import RunId
from tracebed.ingest.trace_archive import (
    ARCHIVE_INVALID,
    TraceArchiveDisposition,
    TraceArchiveReader,
    TraceArchiveReadError,
)
from tracebed.ingest.trace_writer import TraceWriter
from tracebed.stores.pg.partitions import create_project_partitions
from tracebed.stores.pg.pool import create_pool, scoped
from tracebed.stores.pg.queue import WorkQueue
from tracebed.stores.pg.repo import Repo
from tracebed.stores.pg.trace_learning import TraceLearningJobStore
from tracebed.stores.tracestore.fs import FsTraceStore
from tracebed.workers.trace_learning import TIER_A_PIPELINE, TIER_A_PIPELINE_VERSION

pytestmark = [pytest.mark.phase2, pytest.mark.integration]


def test_real_terminal_outbox_and_archive_reader_hand_off(
    settings: TracebedSettings, tmp_path: Path, scratch_dsn: str
) -> None:
    """Prove the P2A durability boundary against real RLS, DDL and leases."""
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
        pytest.skip(f"tracebed_app connection unavailable for P2A E2E: {exc.__class__.__name__}")

    try:
        clock = FakeClock(datetime(2026, 1, 1, tzinfo=UTC))
        owner_repo = Repo(owner_pool, clock)
        project_id = owner_repo.create_project("p2a-e2e")
        principal_id = owner_repo.create_principal("api_key", "p2a-e2e", "hash")
        agent_type_id = owner_repo.create_agent_type(project_id, "p2a-e2e-agent")
        owner_repo.register_agent(project_id, principal_id, agent_type_id)
        with owner_pool.connection() as conn:
            create_project_partitions(conn, project_id)

        repo = Repo(app_pool, clock)
        queue = WorkQueue(app_pool, clock, settings.queue)
        store = FsTraceStore(tmp_path / "traces")
        keys = SubjectKeyManager(repo, _Master(), clock)
        writer = TraceWriter(queue, repo, store, keys, clock, settings)
        reader = TraceArchiveReader(repo, store, keys)
        jobs = TraceLearningJobStore(app_pool)

        run_id = RunId(uuid.uuid4())
        ended_at = clock.now() + timedelta(seconds=2)
        terminal_events = [
            (0, _event("run_start", clock.now(), {"query_text": "terminal q"})),
            (
                1,
                _event(
                    "state_note",
                    clock.now() + timedelta(seconds=1),
                    {"subject_tags": ["user:p2a"]},
                ),
            ),
            (2, _event("run_end", ended_at, {"status": "ok"})),
        ]
        _enqueue(queue, project_id, principal_id, agent_type_id, run_id, terminal_events)
        assert writer.run_once() == 3
        row = repo.get_trace_index(project_id, run_id)
        assert row.outcome_status == TraceOutcomeStatus.OK
        assert row.ended_at == ended_at

        # The repository UPSERT is not the sole freeze: direct app-role DML
        # cannot mutate a terminal archive, and its DELETE privilege is
        # revoked on both the parent and child.  The owner probe below shows
        # the trigger remains a DB backstop if a later grant regresses.
        with pytest.raises(psycopg.errors.CheckViolation), scoped(app_pool, project_id) as conn:
            conn.execute(
                "UPDATE trace_index SET started_at = started_at "
                "WHERE project_id = %s AND run_id = %s",
                (project_id.value, run_id.value),
            )
        with (
            pytest.raises(psycopg.errors.InsufficientPrivilege),
            scoped(app_pool, project_id) as conn,
        ):
            conn.execute(
                "DELETE FROM trace_index WHERE project_id = %s AND run_id = %s",
                (project_id.value, run_id.value),
            )
        with pytest.raises(psycopg.errors.CheckViolation), scoped(owner_pool, project_id) as conn:
            conn.execute(
                "DELETE FROM trace_index WHERE project_id = %s AND run_id = %s",
                (project_id.value, run_id.value),
            )

        leases = jobs.claim(project_id, TIER_A_PIPELINE, TIER_A_PIPELINE_VERSION, "p2a-e2e", 10)
        assert len(leases) == 1
        assert leases[0].run_id == run_id
        assert leases[0].trace_ended_at == ended_at
        archive = reader.read_complete(project_id, run_id, expected_ended_at=ended_at)
        assert len(archive.events) == 3
        assert len(archive.trace_digest) == 32
        assert {binding.subject_tag for binding in archive.subject_key_bindings} == {
            "__project__",
            "user:p2a",
        }

        # P2A stops at the durable pending outbox row. P2B owns every fenced
        # terminal result write and finalization proof.
        with scoped(app_pool, project_id) as conn:
            terminal = conn.execute(
                "SELECT state, trace_digest, result_digest, memory_ids FROM trace_learning_job "
                "WHERE project_id = %s AND run_id = %s AND pipeline = %s AND pipeline_version = %s",
                (project_id.value, run_id.value, TIER_A_PIPELINE, TIER_A_PIPELINE_VERSION),
            ).fetchone()
        assert terminal == ("running", None, None, [])

        objects_before = {path: path.read_bytes() for path in (tmp_path / "traces").rglob("*.tbz")}
        _enqueue(queue, project_id, principal_id, agent_type_id, run_id, terminal_events)
        assert writer.run_once() == 0
        assert {
            path: path.read_bytes() for path in (tmp_path / "traces").rglob("*.tbz")
        } == objects_before
        with scoped(app_pool, project_id) as conn:
            assert conn.execute(
                "SELECT count(*) FROM trace_learning_job WHERE project_id = %s",
                (project_id.value,),
            ).fetchone() == (1,)

        # An unseen owner sequence after terminal closure is nacked, not made
        # into a second archive object or job.
        _enqueue(
            queue,
            project_id,
            principal_id,
            agent_type_id,
            run_id,
            [(3, _event("tool_result", ended_at + timedelta(seconds=1), {"ok": True}))],
        )
        assert writer.run_once() == 0
        assert {
            path: path.read_bytes() for path in (tmp_path / "traces").rglob("*.tbz")
        } == objects_before

        gap_run = RunId(uuid.uuid4())
        gap_end = clock.now() + timedelta(seconds=12)
        _enqueue(
            queue,
            project_id,
            principal_id,
            agent_type_id,
            gap_run,
            [
                (0, _event("run_start", clock.now(), {"query_text": "gap q"})),
                (2, _event("run_end", gap_end, {"status": "ok"})),
            ],
        )
        assert writer.run_once() == 2
        assert (
            repo.get_trace_index(project_id, gap_run).outcome_status
            == TraceOutcomeStatus.INCOMPLETE
        )
        assert jobs.claim(project_id, TIER_A_PIPELINE, TIER_A_PIPELINE_VERSION, "p2a-gap", 10) == ()
        _enqueue(
            queue,
            project_id,
            principal_id,
            agent_type_id,
            gap_run,
            [(1, _event("tool_call", clock.now() + timedelta(seconds=1), {}))],
        )
        assert writer.run_once() == 1
        assert repo.get_trace_index(project_id, gap_run).outcome_status == TraceOutcomeStatus.OK
        assert (
            len(jobs.claim(project_id, TIER_A_PIPELINE, TIER_A_PIPELINE_VERSION, "p2a-gap", 10))
            == 1
        )

        def write_tagged_terminal(tag: str, offset: int) -> tuple[RunId, datetime]:
            broken_run = RunId(uuid.uuid4())
            broken_end = clock.now() + timedelta(seconds=20 + offset)
            _enqueue(
                queue,
                project_id,
                principal_id,
                agent_type_id,
                broken_run,
                [
                    (0, _event("run_start", clock.now(), {"query_text": tag})),
                    (1, _event("state_note", clock.now(), {"subject_tags": [tag]})),
                    (2, _event("run_end", broken_end, {"status": "ok"})),
                ],
            )
            assert writer.run_once() == 3
            return broken_run, broken_end

        # A missing live row is not erasure: destroy_subject retains a marked
        # row precisely so the reader can distinguish the two outcomes.
        missing_run, _ = write_tagged_terminal("user:missing-key", 1)
        with scoped(owner_pool, project_id) as conn:
            conn.execute(
                "DELETE FROM subject_key WHERE project_id = %s AND subject_tag = %s",
                (project_id.value, "user:missing-key"),
            )
        with pytest.raises(TraceArchiveReadError) as raised:
            reader.read_complete(project_id, missing_run)
        assert (raised.value.disposition, raised.value.code) == (
            TraceArchiveDisposition.DEAD,
            ARCHIVE_INVALID,
        )

        # A random live key_id similarly fails the authenticated wrap binding;
        # it must not be presented as a privacy tombstone.
        mismatch_run, _ = write_tagged_terminal("user:mismatched-key", 2)
        with scoped(owner_pool, project_id) as conn:
            conn.execute(
                "UPDATE subject_key SET key_id = %s WHERE project_id = %s AND subject_tag = %s",
                (uuid.uuid4(), project_id.value, "user:mismatched-key"),
            )
        with pytest.raises(TraceArchiveReadError) as raised:
            reader.read_complete(project_id, mismatch_run)
        assert (raised.value.disposition, raised.value.code) == (
            TraceArchiveDisposition.DEAD,
            ARCHIVE_INVALID,
        )

        with scoped(app_pool, project_id) as conn:
            count = conn.execute(
                "SELECT count(*) FROM trace_learning_job "
                "WHERE project_id = %(project_id)s AND pipeline = %(pipeline)s "
                "AND pipeline_version = %(pipeline_version)s",
                {
                    "project_id": project_id,
                    "pipeline": TIER_A_PIPELINE,
                    "pipeline_version": TIER_A_PIPELINE_VERSION,
                },
            ).fetchone()
        # Original + gap-fill + the missing-row and key-id corruption probes
        # each schedule exactly one terminal Tier-A job before their reader
        # disposition is evaluated.
        assert count == (4,)
    finally:
        owner_pool.close()
        if app_pool is not None:
            app_pool.close()
