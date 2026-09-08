"""B3 split-runtime credentials and dependency-ready API surface."""

from __future__ import annotations

import logging
import traceback
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from psycopg import OperationalError

from tracebed.api import main
from tracebed.domain.errors import ConfigError
from tracebed.stores.pg import authority_dsn
from tracebed.stores.pg.authority_dsn import (
    API_DB_DSN_ENV,
    WORKER_DB_DSN_ENV,
    RuntimeDsnError,
    parse_runtime_dsn,
    runtime_dsn_from_environment,
)
from tracebed.stores.pg.runtime_identity import assert_runtime_connection, probe_runtime_readiness

pytestmark = pytest.mark.phase1

_API_DSN = "postgresql://tracebed_api:api-secret@db.example/tracebed"
_WORKER_DSN = "postgresql://tracebed_worker:worker-secret@db.example/tracebed"

_RUNTIME_ENV_CONFLICTS = (
    "TB_WORKER_DB_DSN",
    "TB_STORAGE__PG_DSN",
    "TB_STORAGE__ADMIN_PG_DSN",
    "TB_STORAGE__OWNER_PG_DSN",
    "TB_BOOTSTRAP_PG_DSN",
    "TB_BOOTSTRAP_DB_DSN",
    "TB_BOOTSTRAP_DSN",
    "TB_ONBOARDING_PG_DSN",
    "TB_ONBOARDING_DB_DSN",
    "TB_OWNER_DB_DSN",
    "TB_OWNER_PG_DSN",
    "TB_ADMIN_DB_DSN",
    "TB_ADMIN_PG_DSN",
    "TB_ADMIN_DSN",
    "TB_APP_DB_DSN",
    "TB_APP_PG_DSN",
    "TB_APP_PASSWORD",
    "TB_APP_ROLE_PASSWORD",
    "TB_PG_PASSWORD",
    "TB_M4_ADMIN_PG_DSN",
    "DATABASE_URL",
    "POSTGRES_URL",
    "POSTGRESQL_URL",
    "POSTGRES_DSN",
    "DB_URL",
    "DB_DSN",
    "PGHOST",
    "PGSERVICEFILE",
    "PGSYSCONFDIR",
    "PG_FUTURE_LIBPQ_INPUT",
)


def test_runtime_dsn_requires_the_exact_process_identity_and_redacts_repr() -> None:
    parsed = parse_runtime_dsn(_API_DSN, expected_role="tracebed_api")
    assert parsed.value == _API_DSN
    assert parsed.role == "tracebed_api"
    assert "api-secret" not in repr(parsed)
    with pytest.raises(RuntimeDsnError, match=r"^runtime database credential configuration is invalid$"):
        parse_runtime_dsn(_API_DSN, expected_role="tracebed_worker")


@pytest.mark.parametrize(
    "dsn",
    (
        "postgresql://tracebed_api:se%3Acret@db.example/tracebed",
        "postgres://tracebed_api:se%25cret@db.example:5432/tracebed?sslmode=require&connect_timeout=5",
        "postgresql://tracebed_api:pa%C3%9F@db.example/tracebed?target_session_attrs=read-write",
    ),
)
def test_runtime_dsn_allows_only_unambiguous_libpq_equivalent_passwords_and_transport(
    dsn: str,
) -> None:
    parsed = parse_runtime_dsn(dsn, expected_role="tracebed_api")
    assert parsed.value == dsn
    assert parsed.role == "tracebed_api"


@pytest.mark.parametrize(
    "dsn",
    (
        "postgresql://tracebed_api:@db.example/tracebed",
        "postgresql://tracebed_api:secret@db.example,other.example/tracebed",
        "postgresql://tracebed_api:secret@%64b.example/tracebed",
        "postgresql://tracebed_api:secret@db.example/%74racebed",
        "postgresql://tracebed_api:secret@db.example/tracebed?options=-c%20role%3Dtracebed_owner",
        "postgresql://tracebed_api:secret@db.example/tracebed?service=owner",
        "postgresql://tracebed_api:secret@db.example/tracebed?sslmode=require&SSLMODE=disable",
        "postgresql://tracebed_api:secret@db.example/tracebed?sslmode=require&sslmode=disable",
        "postgresql://tracebed_api:secret@db.example/tracebed?madeup=attacker",
        "postgresql://tracebed_api:secret@db.example/tracebed?%73slmode=require",
        "postgresql://tracebed_api:secret@db.example/tracebed?sslmode=%00",
        "postgresql://tracebed_api:secret@db.example/tracebed?sslmode=%FF",
        "postgresql://tracebed_api:secret@db.example/tracebed?sslmode=%",
        "postgresql://tracebed_api:secret@db.example:99999/tracebed",
        "postgresql://tracebed_api:secret@db.example:not-a-port/tracebed",
        "postgresql://tracebed_%61pi:secret@db.example/tracebed",
        "postgresql://tracebed_api:secret@db.example/%00tracebed",
        "postgresql://tracebed_api:secret@db.example/tracebed#fragment",
    ),
)
def test_runtime_dsn_rejects_ambiguous_or_indirected_urls(dsn: str) -> None:
    with pytest.raises(RuntimeDsnError, match=r"^runtime database credential configuration is invalid$"):
        parse_runtime_dsn(dsn, expected_role="tracebed_api")


@pytest.mark.parametrize(
    "dsn, secret",
    (
        ("postgresql://tracebed_api:super-secret-%ZZ@db.example/tracebed", "super-secret-%ZZ"),
        ("postgresql://tracebed_api:super-secret@db.example:99999/tracebed", "super-secret"),
        ("postgresql://tracebed_api:super-secret@attacker-host/tracebed?madeup=attacker-text", "attacker-text"),
    ),
)
def test_runtime_dsn_errors_never_render_secrets_or_attacker_text(
    dsn: str, secret: str, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    with pytest.raises(RuntimeDsnError) as raised:
        parse_runtime_dsn(dsn, expected_role="tracebed_api")

    error = raised.value
    transcript = "\n".join(
        (
            str(error),
            repr(error),
            "".join(traceback.format_exception(error)),
            *(record.getMessage() for record in caplog.records),
        )
    )
    assert str(error) == "runtime database credential configuration is invalid"
    assert secret not in transcript
    assert "attacker-text" not in transcript
    assert error.__cause__ is None


@pytest.mark.parametrize(
    "environment",
    (
        {},
        {API_DB_DSN_ENV: _API_DSN, WORKER_DB_DSN_ENV: _WORKER_DSN},
        {API_DB_DSN_ENV: _API_DSN, "TB_STORAGE__PG_DSN": _WORKER_DSN},
        {API_DB_DSN_ENV: _API_DSN, "TB_BOOTSTRAP_PG_DSN": _WORKER_DSN},
        {API_DB_DSN_ENV: _API_DSN, "TB_STORAGE__ADMIN_PG_DSN": _WORKER_DSN},
        {API_DB_DSN_ENV: _API_DSN, "TB_ADMIN_DB_DSN": _WORKER_DSN},
        {API_DB_DSN_ENV: _API_DSN, "TB_ONBOARDING_PG_DSN": _WORKER_DSN},
    ),
)
def test_runtime_environment_rejects_legacy_or_cross_process_secrets(
    environment: Mapping[str, str]
) -> None:
    with pytest.raises(RuntimeDsnError, match=r"^runtime database credential configuration is invalid$"):
        runtime_dsn_from_environment("tracebed_api", environment)


@pytest.mark.parametrize(
    "conflict_name",
    (
        *_RUNTIME_ENV_CONFLICTS,
        *(name.lower() for name in _RUNTIME_ENV_CONFLICTS),
        "tb_api_db_dsn",
        "Tb_Api_Db_Dsn",
    ),
)
def test_runtime_environment_is_casefold_exclusive_before_libpq_parsing(
    conflict_name: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    environment = {API_DB_DSN_ENV: _API_DSN, conflict_name: "attacker-value"}
    parser_calls: list[str] = []

    def forbidden_libpq_parse(value: str) -> dict[str, str]:
        parser_calls.append(value)
        raise AssertionError("invalid ambient environment reached libpq parsing")

    monkeypatch.setattr(authority_dsn, "conninfo_to_dict", forbidden_libpq_parse)
    with pytest.raises(RuntimeDsnError, match=r"^runtime database credential configuration is invalid$"):
        runtime_dsn_from_environment("tracebed_api", environment)
    assert parser_calls == []


def test_runtime_environment_requires_one_exact_cased_own_key_before_libpq(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    parser_calls: list[str] = []

    def forbidden_libpq_parse(value: str) -> dict[str, str]:
        parser_calls.append(value)
        raise AssertionError("case-variant credential reached libpq parsing")

    monkeypatch.setattr(authority_dsn, "conninfo_to_dict", forbidden_libpq_parse)
    environment = {
        API_DB_DSN_ENV: _API_DSN,
        "tb_api_db_dsn": "postgresql://tracebed_api:duplicate@db.example/tracebed",
    }
    with pytest.raises(RuntimeDsnError, match=r"^runtime database credential configuration is invalid$"):
        runtime_dsn_from_environment("tracebed_api", environment)
    assert parser_calls == []


def test_worker_environment_accepts_only_worker_secret() -> None:
    parsed = runtime_dsn_from_environment("tracebed_worker", {WORKER_DB_DSN_ENV: _WORKER_DSN})
    assert parsed.role == "tracebed_worker"


class _Cursor:
    def __init__(self, row: tuple[str | None, ...]) -> None:
        self._row = row

    def fetchone(self) -> tuple[str | None, ...]:
        return self._row


class _Connection:
    def __init__(self, identity: tuple[str | None, ...]) -> None:
        self._identity = identity
        self.queries: list[str] = []

    def execute(self, query: str) -> _Cursor:
        self.queries.append(query)
        if len(self.queries) == 1:
            return _Cursor(self._identity)
        return _Cursor(())


def test_runtime_connection_check_requires_matching_login_and_clean_project_guc() -> None:
    connection = _Connection(("tracebed_api", "tracebed_api", ""))
    assert_runtime_connection(connection, expected_role="tracebed_api")
    assert len(connection.queries) == 2

    with pytest.raises(Exception, match="runtime database identity or readiness check failed"):
        assert_runtime_connection(
            _Connection(("tracebed_worker", "tracebed_worker", "project-leak")),
            expected_role="tracebed_api",
        )


def test_runtime_identity_failure_suppresses_driver_secret_context() -> None:
    class _FailingConnection:
        def execute(self, query: str) -> _Cursor:
            del query
            raise OperationalError("driver secret and attacker context")

    with pytest.raises(ConfigError) as raised:
        assert_runtime_connection(_FailingConnection(), expected_role="tracebed_api")

    error = raised.value
    transcript = "\n".join((str(error), repr(error), "".join(traceback.format_exception(error))))
    assert str(error) == "runtime database identity or readiness check failed"
    assert "driver secret" not in transcript
    assert error.__cause__ is None


def test_serving_readiness_checks_all_idle_pool_connections_before_borrowing_one() -> None:
    events: list[str] = []

    class ProbeConnection(_Connection):
        @contextmanager
        def transaction(self) -> Iterator[ProbeConnection]:
            events.append("transaction")
            yield self

    class ProbePool:
        def check(self) -> None:
            events.append("check")

        @contextmanager
        def connection(self) -> Iterator[ProbeConnection]:
            events.append("borrow")
            yield ProbeConnection(("tracebed_api", "tracebed_api", ""))

    probe_runtime_readiness(ProbePool(), expected_role="tracebed_api")  # type: ignore[arg-type]

    assert events[:3] == ["check", "borrow", "transaction"]


def test_readyz_is_dependency_backed_while_healthz_is_liveness_only(settings: Any) -> None:
    app = main._create_base_app(settings)
    with TestClient(app) as client:
        assert client.get("/healthz").json() == {"status": "ok"}
        response = client.get("/readyz")
        assert response.status_code == 503
        assert response.json() == {"status": "not ready"}


def test_compose_readyz_requires_its_mounted_token_before_dependency_probe(
    settings: Any, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    token_file = tmp_path / "readyz_token"
    token_file.write_text("probe-token\n", encoding="utf-8")
    monkeypatch.setattr(main, "_COMPOSE_READY_TOKEN_FILE", str(token_file))
    monkeypatch.setenv(main._COMPOSE_READY_TOKEN_ENV, str(token_file))
    app = main._create_base_app(settings)
    calls: list[str] = []
    app.state.runtime_readiness = lambda: calls.append("checked")

    with TestClient(app) as client:
        assert client.get("/healthz").status_code == 200
        assert client.get("/readyz").status_code == 401
        assert client.get("/readyz", headers={"X-Tracebed-Readiness": "wrong"}).status_code == 401
        assert client.get("/readyz", headers={"X-Tracebed-Readiness": "probe-token"}).status_code == 200
    assert calls == ["checked"]
