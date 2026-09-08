"""B2 removes owner onboarding/project creation from the API listener."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from tracebed.api.deps import AppDeps
from tracebed.api.main import create_app
from tracebed.domain.clock import FakeClock
from tracebed.domain.config import EmbeddingConfig, StorageConfig, TracebedSettings

pytestmark = pytest.mark.phase0


def _client() -> TestClient:
    inert = object()
    deps = AppDeps(
        verifier=inert,  # type: ignore[arg-type]
        resolver=inert,  # type: ignore[arg-type]
        queue=inert,  # type: ignore[arg-type]
        telemetry=inert,  # type: ignore[arg-type]
        memory_reader=inert,  # type: ignore[arg-type]
        exporter=inert,  # type: ignore[arg-type]
        invalidations=inert,  # type: ignore[arg-type]
        retrieval_opener=inert,  # type: ignore[arg-type]
        access_resolver=inert,  # type: ignore[arg-type]
        clock=FakeClock(datetime(2026, 1, 1, tzinfo=UTC)),
    )
    settings = TracebedSettings(
        storage=StorageConfig(pg_dsn="postgresql://unused@unused/unused"),
        embedding=EmbeddingConfig(model_version="test"),
    )
    return TestClient(create_app(settings, deps))


@pytest.mark.parametrize(
    ("path", "body"),
    [
        ("/admin/projects", {"name": "not-an-api-operation"}),
        (
            "/admin/agents/register",
            {"project_id": str(uuid4()), "agent_type": "not-an-api-operation"},
        ),
    ],
)
def test_owner_onboarding_routes_do_not_exist(path: str, body: dict[str, str]) -> None:
    response = _client().post(path, json=body)
    assert response.status_code == 404
