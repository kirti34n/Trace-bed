"""M1/M2 checks for lazy API boot and migration-resource selection."""

from __future__ import annotations

import asyncio
import os
from pathlib import Path
from typing import cast

import pytest
from psycopg_pool import ConnectionPool
from pydantic import ValidationError

from tracebed.adapters.embedding.factory import build_embedding_driver
from tracebed.adapters.embedding.hash_local import HashLocalEmbeddingClient
from tracebed.api import main
from tracebed.api.deps import AppDeps
from tracebed.domain.clock import FakeClock
from tracebed.domain.config import (
    HASH_LOCAL_MODEL_ID,
    HASH_LOCAL_MODEL_VERSION,
    EmbeddingConfig,
    StorageConfig,
    TracebedSettings,
)
from tracebed.domain.errors import ConfigError
from tracebed.hotpath.retriever import Retriever
from tracebed.stores.pg.authority_dsn import RuntimeDsn
from tracebed.stores.pg.migrate import MIGRATIONS_DIR, migration_directory, read_all_migrations
from tracebed.stores.pg.reports import ReportsRepo
from tracebed.workers import runner

pytestmark = pytest.mark.phase1


@pytest.fixture
def runtime_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in tuple(os.environ):
        folded = name.casefold()
        if (
            folded.startswith("pg")
            or folded
            in {
                "tb_api_db_dsn",
                "tb_worker_db_dsn",
                "tb_storage__pg_dsn",
                "tb_storage__admin_pg_dsn",
                "tb_storage__owner_pg_dsn",
                "tb_bootstrap_pg_dsn",
                "tb_bootstrap_db_dsn",
                "tb_bootstrap_dsn",
                "tb_onboarding_pg_dsn",
                "tb_onboarding_db_dsn",
                "tb_owner_db_dsn",
                "tb_owner_pg_dsn",
                "tb_admin_db_dsn",
                "tb_admin_pg_dsn",
                "tb_admin_dsn",
                "tb_app_db_dsn",
                "tb_app_pg_dsn",
                "tb_app_password",
                "tb_app_role_password",
                "tb_pg_password",
                "tb_m4_admin_pg_dsn",
                "database_url",
                "postgres_url",
                "postgresql_url",
                "postgres_dsn",
                "db_url",
                "db_dsn",
            }
        ):
            monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv(
        "TB_API_DB_DSN", "postgresql://tracebed_api:test@localhost/tracebed"
    )
    monkeypatch.setenv("TB_EMBEDDING__MODEL_VERSION", "test-pin")


def test_api_and_worker_runtime_config_preserve_non_database_storage_settings(
    runtime_env: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("TB_STORAGE__VALKEY_URL", "valkey://cache.internal:6380/7")
    monkeypatch.setenv("TB_STORAGE__TRACESTORE__DRIVER", "s3")
    monkeypatch.setenv("TB_STORAGE__TRACESTORE__BUCKET", "runtime-traces")
    monkeypatch.setenv("TB_STORAGE__TRACESTORE__ENDPOINT", "https://objects.internal")
    monkeypatch.setenv("TB_STORAGE__TRACESTORE__REGION", "eu-west-1")
    monkeypatch.setenv("TB_STORAGE__PG_CONNECT_TIMEOUT_S", "9")
    monkeypatch.setenv("TB_STORAGE__PG_CHECKOUT_TIMEOUT_S", "2.5")

    api_dsn, api_settings = main._load_api_runtime_configuration()
    assert api_dsn.role == "tracebed_api"
    assert api_settings.storage.pg_dsn is None
    assert api_settings.storage.valkey_url == "valkey://cache.internal:6380/7"
    assert api_settings.storage.tracestore.driver == "s3"
    assert api_settings.storage.tracestore.bucket == "runtime-traces"
    assert api_settings.storage.tracestore.endpoint == "https://objects.internal"
    assert api_settings.storage.tracestore.region == "eu-west-1"
    assert api_settings.storage.pg_connect_timeout_s == 9
    assert api_settings.storage.pg_checkout_timeout_s == 2.5

    monkeypatch.delenv("TB_API_DB_DSN")
    monkeypatch.setenv(
        "TB_WORKER_DB_DSN", "postgresql://tracebed_worker:test@localhost/tracebed"
    )
    worker_dsn, worker_settings = runner._load_worker_runtime_configuration()
    assert worker_dsn.role == "tracebed_worker"
    assert worker_settings.storage.pg_dsn is None
    assert worker_settings.storage == api_settings.storage


def test_env_factory_defers_runtime_dependency_construction(
    runtime_env: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    def forbidden(_: TracebedSettings, __: RuntimeDsn) -> object:
        raise AssertionError("runtime dependencies must not be built by the app factory")

    monkeypatch.setattr(main, "_build_runtime_dependencies", forbidden)
    app = main.create_app_from_env()
    assert app.state.deps is None
    assert app.state.reports_store is None


def test_console_entry_uses_the_lazy_factory(
    runtime_env: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: dict[str, object] = {}

    def fake_run(app: object, **kwargs: object) -> None:
        seen["app"] = app
        seen.update(kwargs)

    import uvicorn

    monkeypatch.setattr(uvicorn, "run", fake_run)
    main.run()
    assert seen == {
        "app": "tracebed.api.main:create_app_from_env",
        "factory": True,
        "host": "0.0.0.0",  # noqa: S104 - assertion of console entry contract
        "port": 8110,
        "workers": 2,
    }


def test_source_checkout_migrations_remain_readable_through_the_resource_api() -> None:
    with migration_directory() as directory:
        assert isinstance(directory, Path)
        assert directory == MIGRATIONS_DIR
    assert [migration.id for migration in read_all_migrations()] == [
        "0001_registries",
        "0002_partitioned",
        "0003_rls",
        "0004_lifecycle",
        "0005_bm25",
        "0006_q_update_ledger",
        "0007_project_provisioning",
        "0008_trace_learning_job",
        "0009_trace_index_terminal_freeze",
        "0010_authority_foundation",
        "0011_authority_cutover",
        "0012_erasure_saga",
        "0013_erasure_deployment",
    ]
    assert all(migration.loaded for migration in read_all_migrations())


def test_hash_local_driver_is_accepted_without_changing_the_gemini_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    defaults = EmbeddingConfig(model_version="pin")
    local = EmbeddingConfig(driver="hash-local")
    assert defaults.driver == "gemini"
    assert local.driver == "hash-local"
    assert local.model_id == HASH_LOCAL_MODEL_ID
    assert local.model_version == HASH_LOCAL_MODEL_VERSION
    settings = TracebedSettings(
        storage=StorageConfig(pg_dsn="postgresql://test:test@localhost/test"),
        embedding=local,
    )
    assert settings.embedding.driver == "hash-local"
    monkeypatch.delenv(settings.llm.api_key_env, raising=False)
    assert isinstance(build_embedding_driver(settings, FakeClock()), HashLocalEmbeddingClient)


def test_hash_local_rejects_an_explicit_nonlocal_identity() -> None:
    with pytest.raises(ValidationError, match="requires fixed"):
        EmbeddingConfig(driver="hash-local", model_version="gemini-pin")

    bypassed = EmbeddingConfig.model_construct(
        driver="hash-local",
        model_id="gemini-embedding-2",
        model_version="gemini-pin",
        dim=8,
    )
    settings = TracebedSettings.model_construct(
        storage=StorageConfig(pg_dsn="postgresql://test:test@localhost/test"),
        embedding=bypassed,
    )
    with pytest.raises(ConfigError, match="requires fixed"):
        build_embedding_driver(settings, FakeClock())


class _CloseRecorder:
    def __init__(self, events: list[str], name: str) -> None:
        self._events = events
        self._name = name

    def close(self) -> None:
        self._events.append(self._name)


def test_runtime_lifespan_closes_retriever_before_pool(
    runtime_env: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    events: list[str] = []
    resources = main._RuntimeResources(
        deps=cast(AppDeps, object()),
        reports_store=cast(ReportsRepo, object()),
        pool=cast(ConnectionPool, _CloseRecorder(events, "pool")),
        activity_pool=cast(ConnectionPool, _CloseRecorder(events, "activity_pool")),
        retriever=cast(Retriever, _CloseRecorder(events, "retriever")),
    )
    monkeypatch.setattr(main, "_build_runtime_dependencies", lambda *_: resources)
    app = main.create_app_from_env()

    async def exercise() -> None:
        async with main._runtime_lifespan(app):
            assert app.state.deps is resources.deps
            assert app.state.runtime_pool is resources.pool

    asyncio.run(exercise())
    assert events == ["retriever", "pool", "activity_pool"]


def test_runtime_lifespan_also_closes_the_activity_pool_last(
    runtime_env: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    events: list[str] = []
    resources = main._RuntimeResources(
        deps=cast(AppDeps, object()),
        reports_store=cast(ReportsRepo, object()),
        pool=cast(ConnectionPool, _CloseRecorder(events, "pool")),
        activity_pool=cast(ConnectionPool, _CloseRecorder(events, "activity_pool")),
        retriever=cast(Retriever, _CloseRecorder(events, "retriever")),
    )
    monkeypatch.setattr(main, "_build_runtime_dependencies", lambda *_: resources)
    app = main.create_app_from_env()

    async def exercise() -> None:
        async with main._runtime_lifespan(app):
            pass

    asyncio.run(exercise())
    assert events == ["retriever", "pool", "activity_pool"]


def test_runtime_construction_failure_closes_retriever_before_pool(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    pool = _CloseRecorder(events, "pool")
    activity_pool = _CloseRecorder(events, "activity_pool")
    retriever = _CloseRecorder(events, "retriever")
    settings = TracebedSettings(
        storage=StorageConfig(pg_dsn="postgresql://test:test@localhost/test"),
        embedding=EmbeddingConfig(model_version="test"),
    )
    monkeypatch.setenv("TB_MASTER_KEY", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")

    monkeypatch.setattr(main, "create_pool", lambda *args, **kwargs: pool)
    monkeypatch.setattr(main, "create_activity_pool", lambda *args, **kwargs: activity_pool)
    monkeypatch.setattr(main, "Repo", lambda *args, **kwargs: object())
    monkeypatch.setattr(main, "AuthorizedWorkQueue", lambda *args, **kwargs: object())
    monkeypatch.setattr(main, "ApiKeyVerifier", lambda *args, **kwargs: object())
    monkeypatch.setattr(main, "ChainVerifier", lambda *args, **kwargs: object())
    monkeypatch.setattr(main, "Telemetry", lambda *args, **kwargs: object())
    monkeypatch.setattr(
        main,
        "_build_pipeline",
        lambda *args, **kwargs: (object(), retriever),
    )

    def fail_reports(*args: object, **kwargs: object) -> object:
        del args, kwargs
        raise RuntimeError("reports construction failed")

    monkeypatch.setattr(main, "ReportsRepo", fail_reports)

    with pytest.raises(RuntimeError, match="reports construction failed"):
        main._build_runtime_dependencies(
            settings, RuntimeDsn("postgresql://tracebed_api:test@localhost/tracebed", "tracebed_api")
        )
    assert events == ["retriever", "pool", "activity_pool"]
