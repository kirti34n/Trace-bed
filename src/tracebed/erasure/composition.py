"""The fixed local-Compose assembly for the separately credentialed executor.

This module is deliberately the only E4 wiring point.  It never consults an
API, worker, owner, or generic application DSN, and it fixes the external
manifest to the four adapters whose deletion proofs are implemented here.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final

from psycopg_pool import ConnectionPool

from tracebed.domain.config import TraceStoreConfig
from tracebed.domain.errors import ConfigError
from tracebed.erasure.domain import ErasureSettings, ExternalStoreCode
from tracebed.erasure.executor import ErasureExecutor, ErasureStatus
from tracebed.erasure.fixed_stores import EmbeddedPrimaryStore
from tracebed.erasure.runner import build_executor
from tracebed.stores.pg.authority_dsn import runtime_dsn_from_environment
from tracebed.stores.pg.erasure_executor import PgErasureExecutorStore
from tracebed.stores.pg.pool import create_pool
from tracebed.stores.pg.runtime_identity import runtime_pool_configure
from tracebed.stores.tracestore.s3 import S3TraceStore
from tracebed.stores.tracestore.s3_erasure import S3TraceEraser
from tracebed.stores.valkey.erasure import FreshValkeyErasureCommands, ValkeyErasureAdapter

__all__ = [
    "COMPOSE_ERASURE_MANIFEST",
    "ErasureRuntime",
    "build_runtime",
    "external_stores_from_environment",
]


COMPOSE_ERASURE_MANIFEST: Final[tuple[ExternalStoreCode, ...]] = (
    "graph_postgres",
    "trace_s3_v1",
    "valkey_v1",
    "vector_postgres",
)
_COMPOSE_ERASURE_SETTINGS: Final[dict[str, str]] = {
    "TB_ERASURE_POLL_SECONDS": "2",
    "TB_ERASURE_LEASE_SECONDS": "90",
    "TB_ERASURE_HEARTBEAT_SECONDS": "20",
    "TB_ERASURE_BATCH_SIZE": "100",
    "TB_ERASURE_EXTERNAL_TIMEOUT_SECONDS": "10",
    "TB_ERASURE_TRACE_STORE": "trace_s3_v1",
    "TB_ERASURE_VECTOR_STORE": "vector_postgres",
    "TB_ERASURE_GRAPH_STORE": "graph_postgres",
}
_ERASURE_RAW_ENV: Final = frozenset(
    {
        "TB_API_DB_DSN",
        "TB_WORKER_DB_DSN",
        "TB_BOOTSTRAP_PG_DSN",
        "TB_ONBOARDING_PG_DSN",
        "TB_OWNER_DB_DSN",
        "TB_OWNER_PG_DSN",
        "TB_APP_DB_DSN",
        "TB_ADMIN_DB_DSN",
        "TB_API_DB_PASSWORD",
        "TB_WORKER_DB_PASSWORD",
        "TB_OWNER_DB_PASSWORD",
        "TB_APP_PASSWORD",
        "TB_ERASURE_DB_PASSWORD",
        "TB_ERASURE_DB_PASSWORD_FILE",
        "TB_S3_ACCESS_KEY",
        "TB_S3_SECRET_KEY",
        "TB_S3_ERASURE_ACCESS_KEY",
        "TB_S3_ERASURE_SECRET_KEY",
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
    }
)
_ERASURE_RAW_ENV_CASEFOLD: Final = frozenset(item.casefold() for item in _ERASURE_RAW_ENV)


def _invalid() -> ConfigError:
    return ConfigError("erasure deployment configuration is invalid")


def _validate_environment(environment: Mapping[str, str]) -> None:
    """Reject ambient credentials before a client/pool can be constructed."""

    try:
        names = tuple(environment)
    except Exception:
        raise _invalid() from None
    if not all(isinstance(name, str) for name in names):
        raise _invalid()
    if any(
        name.casefold() in _ERASURE_RAW_ENV_CASEFOLD or name.casefold().startswith("pg")
        for name in names
    ):
        raise _invalid()


def _trace_store_config(environment: Mapping[str, str]) -> TraceStoreConfig:
    endpoint = environment.get("TB_STORAGE__TRACESTORE__ENDPOINT")
    bucket = environment.get("TB_STORAGE__TRACESTORE__BUCKET")
    region = environment.get("TB_STORAGE__TRACESTORE__REGION")
    if endpoint != "http://seaweedfs:8333" or bucket != "tracebed-traces" or region != "us-east-1":
        raise _invalid()
    if environment.get("TB_STORAGE__TRACESTORE__DRIVER") != "s3":
        raise _invalid()
    if environment.get("TB_STORAGE__TRACESTORE__ACCESS_KEY_ENV") != "TB_S3_ERASURE_ACCESS_KEY_FILE":
        raise _invalid()
    if environment.get("TB_STORAGE__TRACESTORE__SECRET_KEY_ENV") != "TB_S3_ERASURE_SECRET_KEY_FILE":
        raise _invalid()
    return TraceStoreConfig(
        driver="s3",
        endpoint=endpoint,
        bucket=bucket,
        region=region,
        access_key_env="TB_S3_ERASURE_ACCESS_KEY_FILE",
        secret_key_env="TB_S3_ERASURE_SECRET_KEY_FILE",  # noqa: S106 - selector, never secret bytes
    )


def external_stores_from_environment(
    environment: Mapping[str, str] | None = None,
) -> tuple[dict[ExternalStoreCode, object], S3TraceStore]:
    """Build exactly the four Compose store adapters without a generic fallback."""

    values = os.environ if environment is None else environment
    _validate_environment(values)
    valkey_url = values.get("TB_STORAGE__VALKEY_URL")
    if valkey_url != "valkey://valkey:6379/0":
        raise _invalid()
    store = S3TraceStore(_trace_store_config(values))
    stores: dict[ExternalStoreCode, object] = {
        "graph_postgres": EmbeddedPrimaryStore("graph_postgres"),
        "trace_s3_v1": S3TraceEraser(store),
        "valkey_v1": ValkeyErasureAdapter(FreshValkeyErasureCommands(valkey_url)),
        "vector_postgres": EmbeddedPrimaryStore("vector_postgres"),
    }
    return stores, store


@dataclass(slots=True)
class ErasureRuntime:
    """Owned E4 process resources; callers must close them on every exit path."""

    settings: ErasureSettings
    executor: ErasureExecutor
    database: PgErasureExecutorStore
    pool: ConnectionPool
    trace_store: S3TraceStore

    def admission_open(self) -> bool:
        return self.database.admission_open()

    def status(self, request_id: object) -> ErasureStatus | None:
        from uuid import UUID

        if type(request_id) is not UUID:
            raise TypeError("erasure request id is invalid")
        return self.database.inspect(request_id)

    def resume(self, request_id: object) -> None:
        from uuid import UUID

        if type(request_id) is not UUID:
            raise TypeError("erasure request id is invalid")
        self.database.resume_blocked(request_id, "operator_resumed")

    def close(self) -> None:
        try:
            self.pool.close()
        finally:
            self.trace_store.close()


def build_runtime(environment: Mapping[str, str] | None = None) -> ErasureRuntime:
    """Construct the local Compose executor after all identity checks pass."""

    values = os.environ if environment is None else environment
    _validate_environment(values)
    dsn = runtime_dsn_from_environment("tracebed_erasure", values)
    if any(values.get(name) != expected for name, expected in _COMPOSE_ERASURE_SETTINGS.items()):
        raise _invalid()
    try:
        # Do not let a mapping-oriented test accidentally read ambient process
        # variables.  The fixed Compose values were just checked byte-for-byte
        # above; the DSN is the one constructed by the role-only authority
        # parser rather than a free-form application setting.
        settings = ErasureSettings(
            db_dsn=dsn.value,
            poll_seconds=2,
            lease_seconds=90,
            heartbeat_seconds=20,
            batch_size=100,
            external_timeout_seconds=10,
            trace_store="trace_s3_v1",
            vector_store="vector_postgres",
            graph_store="graph_postgres",
        )
    except Exception:
        raise _invalid() from None
    if settings.manifest != COMPOSE_ERASURE_MANIFEST:
        raise _invalid()
    stores, trace_store = external_stores_from_environment(values)
    try:
        pool = create_pool(
            dsn.value,
            min_size=1,
            max_size=2,
            connect_timeout_s=5,
            checkout_timeout_s=5.0,
            configure=runtime_pool_configure("tracebed_erasure"),
        )
        # The heartbeat is already constrained below one third of the lease.
        # Use that same fixed liveness bound server-side: if a crashed
        # container leaves PostgreSQL executing a blocked E4 statement, the
        # transaction cannot retain a request lock through lease takeover.
        database = PgErasureExecutorStore(
            pool,
            statement_timeout_ms=settings.heartbeat_seconds * 1000,
        )
        executor = build_executor(settings, database, stores)
    except Exception:
        trace_store.close()
        raise
    return ErasureRuntime(settings, executor, database, pool, trace_store)
