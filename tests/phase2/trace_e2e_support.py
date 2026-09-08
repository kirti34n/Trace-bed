"""Neutral scratch-Postgres helpers shared by trace E2E tests."""
from __future__ import annotations

import uuid
from collections.abc import Iterator
from datetime import datetime
from urllib.parse import urlsplit, urlunsplit

import psycopg
import pytest

from tracebed.domain.ids import AgentTypeId, PrincipalId, ProjectId, RunId
from tracebed.stores.pg.migrate import apply_migrations
from tracebed.stores.pg.queue import TOPIC_TRACE_EVENT, WorkQueue


class _RedactedDsn(str):
    """A usable DSN whose pytest failure rendering never exposes credentials."""

    def __repr__(self) -> str:
        return "<scratch-postgres-dsn>"


class _Master:
    def master_key(self) -> bytes:
        return b"m" * 32


@pytest.fixture
def scratch_dsn(pg: str) -> Iterator[str]:
    db_name = f"tb_trace_e2e_{uuid.uuid4().hex[:16]}"
    admin = psycopg.connect(pg, autocommit=True, connect_timeout=2)
    try:
        admin.execute(f'CREATE DATABASE "{db_name}"')
    except Exception as exc:  # pragma: no cover - environment capability probe
        admin.close()
        pytest.skip(f"cannot create isolated P2A database: {exc.__class__.__name__}")

    dsn = urlunsplit(urlsplit(pg)._replace(path=f"/{db_name}"))
    try:
        apply_migrations(dsn)
        yield _RedactedDsn(dsn)
    finally:
        try:
            admin.execute(
                "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                "WHERE datname = %s AND pid <> pg_backend_pid()",
                (db_name,),
            )
            admin.execute(f'DROP DATABASE IF EXISTS "{db_name}"')
        finally:
            admin.close()


def _payload(
    project_id: ProjectId,
    principal_id: PrincipalId,
    agent_type_id: AgentTypeId,
    run_id: RunId,
    seq: int,
    event: dict[str, object],
) -> dict[str, object]:
    return {
        "project_id": str(project_id),
        "principal_id": str(principal_id),
        "agent_type_id": str(agent_type_id),
        "run_id": str(run_id),
        "seq": seq,
        "event": event,
    }


def _event(type_: str, ts: datetime, payload: dict[str, object]) -> dict[str, object]:
    return {"type": type_, "ts": ts.isoformat(), "payload": payload}


def _enqueue(
    queue: WorkQueue,
    project_id: ProjectId,
    principal_id: PrincipalId,
    agent_type_id: AgentTypeId,
    run_id: RunId,
    events: list[tuple[int, dict[str, object]]],
) -> None:
    for seq, event in events:
        queue.enqueue(
            TOPIC_TRACE_EVENT,
            project_id,
            _payload(project_id, principal_id, agent_type_id, run_id, seq, event),
        )
