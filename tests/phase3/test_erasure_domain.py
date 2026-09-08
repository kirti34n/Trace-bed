"""Offline invariants for the source-only E3 executor surface."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest
from pydantic import ValidationError

from tracebed.erasure.domain import (
    ErasureLease,
    ErasureSettings,
    ExternalWork,
    StepOutcome,
    StoreResult,
    canonical_manifest,
)

pytestmark = pytest.mark.phase3


def test_manifest_is_exactly_four_canonical_store_categories() -> None:
    manifest = ("graph_age", "trace_fs_v1", "valkey_v1", "vector_qdrant")
    assert canonical_manifest(manifest) == manifest
    with pytest.raises(ValueError):
        canonical_manifest(tuple(reversed(manifest)))
    with pytest.raises(ValueError):
        canonical_manifest(("graph_age", "graph_none", "trace_fs_v1", "valkey_v1"))


def test_opaque_execution_values_validate_shape_and_hide_locators() -> None:
    project_id, request_id, token, work_id, run_id = (uuid4() for _ in range(5))
    lease = ErasureLease(
        project_id,
        request_id,
        "subject",
        "fenced",
        1,
        token,
        datetime.now(UTC),
        1,
    )
    work = ExternalWork(work_id, "run", run_id, 1, 1)
    assert str(project_id) not in repr(lease)
    assert str(request_id) not in repr(lease)
    assert str(token) not in repr(lease)
    assert str(work_id) not in repr(work)
    assert str(run_id) not in repr(work)
    assert StoreResult("ok", 0, b"x" * 32).affected_rows == 0
    assert StepOutcome("crypto_erased", 0, 1, "ok").phase == "crypto_erased"
    with pytest.raises(ValueError):
        ExternalWork(work_id, "project", run_id, 1, 1)
    with pytest.raises(ValueError):
        StoreResult("ok", -1, b"x" * 32)


def test_erasure_settings_has_no_normal_dsn_fallback_or_secret_repr(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("TB_STORAGE__PG_DSN", "postgresql://ordinary:secret@example/db")
    with pytest.raises(ValidationError):
        ErasureSettings()
    monkeypatch.setenv("TB_ERASURE_DB_DSN", "postgresql://erasure:secret@example/db")
    settings = ErasureSettings()
    assert settings.manifest == ("graph_postgres", "trace_fs_v1", "valkey_v1", "vector_postgres")
    assert "secret" not in repr(settings)
    with pytest.raises(ValidationError):
        ErasureSettings(lease_seconds=90, heartbeat_seconds=30)
