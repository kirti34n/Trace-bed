"""Focused M3 checks for database and S3 one-shot bootstrap services."""

from __future__ import annotations

import tomllib
from collections import deque
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import parse_qsl, urlsplit

import httpx
import psycopg
import pytest

from tracebed.domain.config import TraceStoreConfig
from tracebed.domain.errors import ConfigError
from tracebed.stores.pg import bootstrap
from tracebed.stores.tracestore import provision
from tracebed.stores.tracestore.provision import ensure_bucket

pytestmark = pytest.mark.phase1


class _RecordingCursor:
    def __init__(
        self,
        rows: deque[tuple[object, ...] | None],
        memberships: list[tuple[object, ...]],
        calls: list[tuple[object, object]],
    ) -> None:
        self._rows = rows
        self._memberships = memberships
        self._calls = calls

    def execute(self, query: object, params: object = None) -> None:
        self._calls.append((query, params))

    def fetchone(self) -> tuple[object, ...] | None:
        return self._rows.popleft()

    def fetchall(self) -> list[tuple[object, ...]]:
        return list(self._memberships)


class _RecordingConnection:
    def __init__(
        self,
        rows: deque[tuple[object, ...] | None],
        memberships: list[tuple[object, ...]] | None = None,
    ) -> None:
        self.calls: list[tuple[object, object]] = []
        self._rows = rows
        self._memberships = memberships if memberships is not None else []
        self.info = SimpleNamespace(dbname="tracebed")

    @contextmanager
    def cursor(self) -> Iterator[_RecordingCursor]:
        yield _RecordingCursor(self._rows, self._memberships, self.calls)

    @contextmanager
    def transaction(self) -> Iterator[None]:
        yield


class _SqlstateStartupError(psycopg.OperationalError):
    """A startup error whose server SQLSTATE must outrank rendered text."""

    def __init__(self, message: str, sqlstate: str) -> None:
        self._test_sqlstate = sqlstate
        super().__init__(message)

    @property
    def sqlstate(self) -> str:
        return self._test_sqlstate


def test_ensure_app_role_reapplies_nonprivileged_nobypassrls_attributes() -> None:
    conn = _RecordingConnection(
        deque(
            [
                (False,),
                (0,),
                (True, False, False, False, False, False, False, -1, False, True),
            ]
        )
    )

    bootstrap.ensure_app_role(conn, "app-password")  # type: ignore[arg-type]

    rendered = "\n".join(repr(query) for query, _ in conn.calls)
    assert "CREATE ROLE" in rendered
    assert "ALTER ROLE" in rendered
    assert "NOBYPASSRLS" in rendered
    assert "NOSUPERUSER" in rendered
    assert "NOINHERIT" in rendered
    assert all(
        not isinstance(query, str) or "app-password" not in query for query, _ in conn.calls
    )


def test_ensure_app_role_removes_a_privileged_parent_membership() -> None:
    conn = _RecordingConnection(
        deque(
            [
                (True,),
                (0,),
                (True, False, False, False, False, False, False, -1, False, True),
            ]
        ),
        memberships=[("bypassrls_parent",)],
    )

    bootstrap.ensure_app_role(conn, "app-password")  # type: ignore[arg-type]

    rendered = "\n".join(repr(query) for query, _ in conn.calls)
    assert "REVOKE" in rendered
    assert "bypassrls_parent" in rendered
    assert "tracebed_app" in rendered


def test_ensure_app_role_fails_if_a_parent_membership_remains() -> None:
    conn = _RecordingConnection(
        deque([(True,), (1,)]), memberships=[("bypassrls_parent",)]
    )

    with pytest.raises(RuntimeError, match="retains a privileged role membership"):
        bootstrap.ensure_app_role(conn, "app-password")  # type: ignore[arg-type]


def test_foundation_group_membership_fails_without_a_revoke_mutation() -> None:
    expected = (False, False, False, False, False, False, False, -1, True, True)
    conn = _RecordingConnection(deque([(True,), expected, (1,), (0,)]))

    with pytest.raises(RuntimeError, match="foundation group retains"):
        bootstrap.ensure_foundation_roles(conn)  # type: ignore[arg-type]

    rendered = "\n".join(repr(query) for query, _ in conn.calls)
    assert "REVOKE" not in rendered


def test_foundation_validation_fails_before_creating_an_earlier_missing_group() -> None:
    """Existing unsafe groups fail without an autocommit partial foundation."""

    unsafe = (False, False, False, False, True, False, False, -1, True, True)
    conn = _RecordingConnection(deque([(False,), (True,), unsafe, (0,), (0,)]))

    with pytest.raises(RuntimeError, match="required attributes"):
        bootstrap.ensure_foundation_roles(conn)  # type: ignore[arg-type]

    rendered = "\n".join(repr(query) for query, _ in conn.calls)
    assert "CREATE ROLE" not in rendered
    assert "REVOKE" not in rendered


def test_foundation_group_ownership_fails_without_creation_or_reassignment() -> None:
    expected = (False, False, False, False, False, False, False, -1, True, True)
    conn = _RecordingConnection(deque([(True,), expected, (0,), (1,)]))

    with pytest.raises(RuntimeError, match="owns database objects"):
        bootstrap.ensure_foundation_roles(conn)  # type: ignore[arg-type]

    rendered = "\n".join(repr(query) for query, _ in conn.calls)
    assert "CREATE ROLE" not in rendered
    assert "REASSIGN OWNED" not in rendered
    assert "DROP OWNED" not in rendered


def test_latest_bootstrap_refuses_an_inheriting_legacy_role_before_repair() -> None:
    """The 0011 evidence gate must see, not normalize, legacy role drift."""

    # The helper gathers all immutable-role evidence before rejecting it.
    conn = _RecordingConnection(
        deque(
            [
                (True,),
                (False, False, False, False, True, False, False, -1, True, True),
                (0,),
                (True, True),
            ]
        )
    )

    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr(bootstrap, "_protected_role_acls_are_clean", lambda *_args, **_kwargs: True)

    with pytest.raises(RuntimeError, match="pre-cutover attributes"):
        bootstrap._ensure_app_role_for_latest_migration(conn, "app-password")  # type: ignore[arg-type]

    try:
        rendered = "\n".join(repr(query) for query, _ in conn.calls)
        assert "CREATE ROLE" not in rendered
        assert "ALTER ROLE" not in rendered
    finally:
        monkeypatch.undo()


def test_bootstrap_serializes_role_migrations_and_partition_repair(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    conn = _RecordingConnection(deque())
    events: list[str] = []

    @contextmanager
    def fake_connect(dsn: str, *, autocommit: bool) -> Iterator[_RecordingConnection]:
        assert dsn.startswith("postgresql://tracebed_owner:owner-password@localhost/owner?")
        assert "tracebed.cluster_scope%3Ddedicated" in dsn
        assert "tracebed.ingress_quarantined%3Don" in dsn or "tracebed.ingress_quarantined=on" in dsn
        assert autocommit is True
        yield conn

    monkeypatch.setattr(bootstrap.psycopg, "connect", fake_connect)
    monkeypatch.setattr(
        bootstrap, "_ensure_app_role_for_latest_migration", lambda *_: events.append("role")
    )
    monkeypatch.setattr(bootstrap, "ensure_foundation_roles", lambda *_: events.append("groups"))
    monkeypatch.setattr(bootstrap, "_ensure_dedicated_cluster_inventory", lambda *_: events.append("inventory"))
    monkeypatch.setattr(bootstrap, "_ensure_protected_role_settings_clean", lambda *_: events.append("settings"))
    monkeypatch.setattr(bootstrap, "_ensure_prepared_transactions_clean", lambda *_: events.append("prepared"))
    monkeypatch.setattr(
        bootstrap, "_validate_existing_app_role_for_latest_migration", lambda *_: events.append("existing-app")
    )
    monkeypatch.setattr(
        bootstrap, "_validate_existing_foundation_roles", lambda *_: events.append("existing-groups")
    )
    monkeypatch.setattr(
        bootstrap, "_validate_existing_split_roles_for_latest_migration", lambda *_: events.append("existing-split")
    )
    monkeypatch.setattr(bootstrap, "quarantine_legacy_app_for_cutover", lambda *_, **__: None)
    monkeypatch.setattr(bootstrap, "apply_migrations", lambda *_args, **_kwargs: events.append("migrations"))
    monkeypatch.setattr(bootstrap, "ensure_schema_current", lambda _: events.append("partitions"))
    monkeypatch.setattr(bootstrap, "_cutover_present", lambda _: False)

    bootstrap.bootstrap_database(
        "postgresql://tracebed_owner:owner-password@localhost/owner",
        "app-password",
        "api-password",
        "worker-password",
        "dedicated",
        ingress_quarantined=True,
    )

    assert events == [
        "inventory",
        "prepared",
        "settings",
        "existing-app",
        "existing-groups",
        "existing-split",
        "role",
        "groups",
        "prepared",
        "migrations",
        "partitions",
    ]
    assert conn.calls[0][0] == "SELECT pg_advisory_lock(%s)"
    assert conn.calls[0][1] == (bootstrap.BOOTSTRAP_LOCK_KEY,)
    assert conn.calls[-1][0] == "SELECT pg_advisory_unlock(%s)"
    assert conn.calls[-1][1] == (bootstrap.BOOTSTRAP_LOCK_KEY,)


def test_bootstrap_cli_does_not_render_a_secret_on_failure(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    secret = "not-for-diagnostics"
    monkeypatch.setenv("TB_BOOTSTRAP_PG_DSN", "owner-dsn")
    monkeypatch.setenv("TB_APP_PASSWORD", secret)

    def fail(*_: object) -> None:
        raise RuntimeError(secret)

    monkeypatch.setattr(bootstrap, "bootstrap_database", fail)

    assert bootstrap.main() == 1
    assert secret not in capsys.readouterr().err


def test_latest_bootstrap_rejects_missing_cluster_attestation_before_connecting(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A shared/fifth-database topology cannot leave cluster-global roles behind."""

    def unexpected_connect(*_: object, **__: object) -> object:
        raise AssertionError("bootstrap connected before dedicated-cluster preflight")

    monkeypatch.setattr(bootstrap.psycopg, "connect", unexpected_connect)
    with pytest.raises(ConfigError, match="TB_PG_CLUSTER_SCOPE"):
        bootstrap.bootstrap_database("dbname=owner", "app", "api", "worker", "")


@pytest.mark.parametrize("attestation", [False, "true", "TRUE", None])
def test_latest_bootstrap_rejects_nonexact_ingress_attestation_before_connecting(
    monkeypatch: pytest.MonkeyPatch, attestation: object
) -> None:
    """The operator assertion is a strict input fence, not a truthy flag."""

    def unexpected_connect(*_: object, **__: object) -> object:
        raise AssertionError("bootstrap connected before ingress attestation preflight")

    monkeypatch.setattr(bootstrap.psycopg, "connect", unexpected_connect)
    with pytest.raises(ConfigError, match="TB_0011_INGRESS_QUARANTINED"):
        bootstrap.bootstrap_database(
            "dbname=owner user=tracebed_owner",
            "app",
            "api",
            "worker",
            "dedicated",
            ingress_quarantined=attestation,  # type: ignore[arg-type]
        )


@pytest.mark.parametrize("action", ("", "ROLLBACK-0011", "apply-0011"))
def test_bootstrap_rejects_unknown_action_before_connecting(
    monkeypatch: pytest.MonkeyPatch, action: str
) -> None:
    def unexpected_connect(*_: object, **__: object) -> object:
        raise AssertionError("bootstrap connected before action preflight")

    monkeypatch.setattr(bootstrap.psycopg, "connect", unexpected_connect)
    with pytest.raises(ConfigError, match="TB_DB_BOOTSTRAP_ACTION"):
        bootstrap.bootstrap_database(
            "dbname=owner user=tracebed_owner",
            "app",
            "api",
            "worker",
            "dedicated",
            ingress_quarantined=True,
            action=action,
        )


def test_rollback_action_requires_ingress_before_connecting(monkeypatch: pytest.MonkeyPatch) -> None:
    def unexpected_connect(*_: object, **__: object) -> object:
        raise AssertionError("rollback connected before ingress preflight")

    monkeypatch.setattr(bootstrap.psycopg, "connect", unexpected_connect)
    with pytest.raises(ConfigError, match="TB_0011_INGRESS_QUARANTINED"):
        bootstrap.bootstrap_database(
            "dbname=owner user=tracebed_owner",
            "app",
            "api",
            "worker",
            "dedicated",
            action="rollback-0011",
        )


def test_rollback_action_runs_only_the_quarantine_then_exact_yoyo_step(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    conn = _RecordingConnection(deque())
    events: list[str] = []

    @contextmanager
    def fake_connect(dsn: str, *, autocommit: bool) -> Iterator[_RecordingConnection]:
        assert "tracebed.ingress_quarantined" in dsn
        assert autocommit is True
        yield conn

    monkeypatch.setattr(bootstrap.psycopg, "connect", fake_connect)
    monkeypatch.setattr(
        bootstrap, "_rollback_0011_from_quarantine", lambda *_args, **_kwargs: events.append("rollback")
    )
    monkeypatch.setattr(bootstrap, "apply_migrations", lambda _: pytest.fail("apply must not run"))
    monkeypatch.setattr(bootstrap, "ensure_schema_current", lambda _: pytest.fail("repair must not run"))
    monkeypatch.setattr(
        bootstrap, "_cleanup_stale_credential_probes", lambda _: pytest.fail("cleanup must not run")
    )

    bootstrap.bootstrap_database(
        "postgresql://tracebed_owner:owner-password@localhost/owner",
        "app",
        "api",
        "worker",
        "dedicated",
        ingress_quarantined=True,
        action="rollback-0011",
    )

    assert events == ["rollback"]
    assert conn.calls[0][0] == "SELECT pg_advisory_lock(%s)"
    assert conn.calls[-1][0] == "SELECT pg_advisory_unlock(%s)"


@pytest.mark.parametrize(
    "owner_dsn",
    (
        "dbname=owner user=tracebed_owner host=localhost",
        "postgresql://tracebed_owner@localhost",
        "https://tracebed_owner@localhost/owner",
        "mysql://tracebed_owner@localhost/owner",
        "postgresql://tracebed_owner:owner-password@localhost:5432/owner?user=shadow",
        "postgresql://tracebed_owner:owner-password@localhost:5432/owner?PASSWORD=shadow",
        "postgresql://tracebed_owner:owner-password@localhost:5432/owner?host=shadow",
        "postgresql://tracebed_owner:owner-password@localhost:5432/owner?hostaddr=127.0.0.2",
        "postgresql://tracebed_owner:owner-password@localhost:5432/owner?port=6432",
        "postgresql://tracebed_owner:owner-password@localhost:5432/owner?dbname=shadow",
        "postgresql://tracebed_owner:owner-password@localhost:5432/owner?database=shadow",
        "postgresql://tracebed_owner:owner-password@localhost:5432/owner?service=shadow",
        "postgresql://tracebed_owner:owner-password@localhost:5432/owner?servicefile=/tmp/rogue",
        "postgresql://tracebed_owner:owner-password@localhost:5432/owner?passfile=/tmp/rogue",
        "postgresql://tracebed_owner:owner-password@localhost:5432/owner?%75ser=shadow",
        "postgresql://tracebed_owner:owner-password@localhost:5432/owner?sslmode=require&SSLMODE=disable",
        "postgresql://tracebed_owner:owner-password@localhost:5432/owner?options=-c%20search_path%3Drogue",
        "postgresql://tracebed_owner:owner-password@primary,standby:5432/owner",
        "postgresql://tracebed_owner:owner-password@primary%2Cstandby:5432/owner",
        "postgresql://tracebed_owner:owner-password@primary%2cstandby:5432/owner",
        "postgresql://tracebed_owner:owner-password@primary%252Cstandby:5432/owner",
        "postgresql://tracebed_owner:owner-password@local%2Ehost:5432/owner",
        "postgresql://tracebed_owner:owner-password@localhost:5432/owner,shadow",
        "postgresql://tracebed_owner:owner-password@localhost:5432/owner%2Fshadow",
        "postgresql://tracebed_owner:owner-password@localhost:5432/owner%252Fshadow",
        "postgresql://tracebed_owner:owner-password@localhost:/owner",
        "postgresql://tracebed_owner@shadow@localhost:5432/owner",
    ),
    ids=(
        "keyword-conninfo",
        "missing-database",
        "https",
        "mysql",
        "query-user",
        "query-password-case",
        "query-host",
        "query-hostaddr",
        "query-port",
        "query-dbname",
        "query-database",
        "query-service",
        "query-servicefile",
        "query-passfile",
        "query-percent-user",
        "query-duplicate-transport-key",
        "query-options",
        "raw-multi-host",
        "encoded-multi-host-uppercase",
        "encoded-multi-host-lowercase",
        "double-encoded-multi-host",
        "encoded-host-dot",
        "raw-database-comma",
        "encoded-database-separator",
        "double-encoded-database-separator",
        "empty-port",
        "ambiguous-user",
    ),
)
@pytest.mark.parametrize("action", ("apply", "rollback-0011"))
def test_authority_bootstrap_rejects_non_url_or_incomplete_owner_dsn_before_any_side_effect(
    monkeypatch: pytest.MonkeyPatch, owner_dsn: str, action: str
) -> None:
    """Both actions refuse a DSN the atomic runner cannot represent before connect."""

    calls: list[str] = []

    def unexpected_connect(*_: object, **__: object) -> object:
        calls.append("connect")
        raise AssertionError("authority bootstrap connected before owner URL validation")

    def unexpected_side_effect(*_: object, **__: object) -> None:
        calls.append("mutation")
        raise AssertionError("authority bootstrap mutated before owner URL validation")

    monkeypatch.setattr(bootstrap.psycopg, "connect", unexpected_connect)
    monkeypatch.setattr(bootstrap, "quarantine_legacy_app_for_cutover", unexpected_side_effect)
    monkeypatch.setattr(bootstrap, "_cleanup_stale_credential_probes", unexpected_side_effect)
    monkeypatch.setattr(bootstrap, "apply_migrations", unexpected_side_effect)

    with pytest.raises(ConfigError, match=r"(PostgreSQL URL|non-empty database)"):
        bootstrap.bootstrap_database(
            owner_dsn,
            "app-password",
            "api-password",
            "worker-password",
            "dedicated",
            ingress_quarantined=True,
            action=action,
        )
    assert calls == []


def test_authority_owner_dsn_rejects_caller_options_and_builds_trusted_fence() -> None:
    with pytest.raises(ConfigError, match="PostgreSQL URL"):
        bootstrap._dedicated_cluster_dsn(
            "postgresql://tracebed_owner:owner-password@localhost/owner?"
            "options=-c%20search_path%3Drogue",
            "dedicated",
            ingress_quarantined=True,
        )

    dsn = bootstrap._dedicated_cluster_dsn(
        "postgresql://tracebed_owner:owner-password@localhost/owner",
        "dedicated",
        ingress_quarantined=True,
    )
    assert [value for key, value in parse_qsl(urlsplit(dsn).query) if key == "options"] == [
        "-c tracebed.cluster_scope=dedicated -c tracebed.ingress_quarantined=on "
        "-c search_path=public,pg_catalog"
    ]


def test_cutover_0012_republishes_active_e4_without_reentering_c12(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An active E4 upgrade keeps its authenticated successor epoch."""

    events: list[object] = []
    monkeypatch.setattr(bootstrap, "_erasure_deployment_present", lambda _: True)
    monkeypatch.setattr(
        bootstrap, "_ensure_exact_yoyo_history", lambda _conn, **kwargs: events.append(kwargs["tip"])
    )
    monkeypatch.setattr(bootstrap, "_ensure_e4_receipt", lambda _: events.append("receipt"))
    monkeypatch.setattr(
        bootstrap,
        "_erasure_deployment_state",
        lambda _: (object(), object(), object(), None),
    )
    monkeypatch.setattr(
        bootstrap,
        "_run_authority_admission_action",
        lambda _conn, *, action: events.append(action),
    )
    monkeypatch.setattr(
        bootstrap, "_ensure_erasure_deployment_drained", lambda _: events.append("drained")
    )
    monkeypatch.setattr(
        bootstrap,
        "_erasure_cutover_present",
        lambda _: pytest.fail("active E4 must not re-enter the c12 cutover"),
    )

    bootstrap._cutover_0012(  # type: ignore[arg-type]
        object(),
        owner_dsn="postgresql://tracebed_owner:owner-password@localhost/tracebed",
        api_password="api-password",
        worker_password="worker-password",
        compose_v1=False,
        open_admission=False,
    )

    assert events == [
        "0013_erasure_deployment",
        "receipt",
        "admission-assert-closed",
        "drained",
    ]


@pytest.mark.parametrize("sqlstate", ("57P01", "08006", "53300"))
def test_startup_probe_never_uses_auth_text_when_sqlstate_is_non_auth(
    monkeypatch: pytest.MonkeyPatch, sqlstate: str
) -> None:
    """Shutdown, connection, and capacity errors are never negative-proof evidence."""

    error = _SqlstateStartupError(
        'connection failed: FATAL:  password authentication failed for user "tracebed_api"',
        sqlstate,
    )

    def reject(_: str) -> None:
        raise error

    monkeypatch.setattr(bootstrap.psycopg, "connect", reject)
    with pytest.raises(_SqlstateStartupError):
        bootstrap._require_credential_rejected(
            "dbname=tracebed", "tracebed_api", "not-a-secret", permit_disabled_role=True
        )
    with pytest.raises(_SqlstateStartupError):
        bootstrap._require_distinct_probe_credentials(
            "dbname=tracebed",
            api_probe_role="tracebed_api",
            api_password="api-password",
            worker_probe_role="tracebed_worker",
            worker_password="worker-password",
        )


def test_startup_probe_accepts_only_exact_sqlstate_or_full_libpq_rendering() -> None:
    password_failure = _SqlstateStartupError("anything", "28P01")
    disabled_role = _SqlstateStartupError("anything", "28000")
    assert bootstrap._is_expected_startup_rejection(
        password_failure, "tracebed_api", permit_disabled_role=False
    )
    assert not bootstrap._is_expected_startup_rejection(
        disabled_role, "tracebed_app", permit_disabled_role=False
    )
    assert bootstrap._is_expected_startup_rejection(
        disabled_role, "tracebed_app", permit_disabled_role=True
    )

    exact_fallback = psycopg.OperationalError(
        'connection failed: connection to server at "127.0.0.1", port 5432 failed: '
        'FATAL:  password authentication failed for user "tracebed_api"'
    )
    assert bootstrap._is_expected_startup_rejection(
        exact_fallback, "tracebed_api", permit_disabled_role=False
    )
    assert not bootstrap._is_expected_startup_rejection(
        psycopg.OperationalError(
            'proxy said: FATAL:  password authentication failed for user "tracebed_api"'
        ),
        "tracebed_api",
        permit_disabled_role=False,
    )

    exact_compose_legacy_hba_rejection = psycopg.OperationalError(
        'connection failed: connection to server at "10.77.10.2", port 5432 failed: '
        'FATAL:  pg_hba.conf rejects connection for host "10.77.10.3", '
        'user "tracebed_app", database "tracebed", no encryption'
    )
    assert bootstrap._is_expected_startup_rejection(
        exact_compose_legacy_hba_rejection, "tracebed_app", permit_disabled_role=True
    )
    assert not bootstrap._is_expected_startup_rejection(
        psycopg.OperationalError(
            'connection failed: connection to server at "10.77.10.99", port 5432 failed: '
            'FATAL:  pg_hba.conf rejects connection for host "10.77.10.3", '
            'user "tracebed_app", database "tracebed", no encryption'
        ),
        "tracebed_app",
        permit_disabled_role=True,
    )


def test_packaging_declares_both_one_shot_console_commands() -> None:
    pyproject = tomllib.loads((Path(__file__).parents[2] / "pyproject.toml").read_text())
    scripts = pyproject["project"]["scripts"]
    assert scripts["tracebed-db-bootstrap"] == "tracebed.stores.pg.bootstrap:main"
    assert scripts["tracebed-s3-init"] == "tracebed.stores.tracestore.provision:main"


def test_compose_s3_credentials_are_secret_file_only_and_generated_in_tmpfs() -> None:
    repo_root = Path(__file__).parents[2]
    compose = (repo_root / "docker" / "compose.yaml").read_text(encoding="utf-8")
    entrypoint = (repo_root / "docker" / "seaweedfs" / "entrypoint.sh").read_text(
        encoding="utf-8"
    )

    assert not (repo_root / "docker" / "seaweedfs" / "s3.json").exists()
    assert "TB_S3_ACCESS_KEY:" not in compose
    assert "TB_S3_SECRET_KEY:" not in compose
    assert "s3_runtime_secret_key:" in compose
    assert "tmpfs:" in compose
    assert "http://127.0.0.1:8333/" in compose
    assert "2[0-9][0-9]|403" in compose
    assert "http://127.0.0.1:9333/cluster/status" not in compose
    assert 'config_file="$config_dir/s3.json"' in entrypoint
    assert "chmod 600" in entrypoint
    assert '"-s3.config=/run/tracebed-s3/s3.json"' in compose
    assert '"name":"tracebed-s3-init"' in entrypoint
    assert '"name":"tracebed-s3-admin"' not in entrypoint
    assert "s3_admin_access_key" not in compose
    assert "s3_admin_secret_key" not in compose
    assert '"name":"tracebed-s3-runtime"' in entrypoint
    assert '"Write:tracebed-traces"' in entrypoint
    assert '"Admin:tracebed-traces"' not in entrypoint


@pytest.fixture
def s3_config(monkeypatch: pytest.MonkeyPatch) -> TraceStoreConfig:
    monkeypatch.setenv("TB_S3_ACCESS_KEY", "access")
    monkeypatch.setenv("TB_S3_SECRET_KEY", "secret")
    return TraceStoreConfig(driver="s3", endpoint="http://s3.invalid", bucket="tracebed-test")


def test_bucket_creation_conflict_is_verified_by_a_second_signed_head(
    s3_config: TraceStoreConfig,
) -> None:
    seen: list[str] = []
    responses = deque(
        [
            (404, b""),
            (409, b""),
            (200, b""),
            (200, b"<VersioningConfiguration><Status>Suspended</Status></VersioningConfiguration>"),
            (200, b""),
            (200, b"<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>"),
        ]
    )

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.method)
        assert request.headers["Authorization"].startswith("AWS4-HMAC-SHA256 ")
        status, content = responses.popleft()
        return httpx.Response(status, content=content)

    client = httpx.Client(transport=httpx.MockTransport(handler))
    ensure_bucket(s3_config, http=client)

    assert seen == ["HEAD", "PUT", "HEAD", "GET", "PUT", "GET"]


@pytest.mark.parametrize(("status", "attempts"), [(401, 1), (403, 1), (500, 4)])
def test_bucket_head_auth_and_server_failures_are_propagated(
    monkeypatch: pytest.MonkeyPatch, s3_config: TraceStoreConfig, status: int, attempts: int
) -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.method)
        return httpx.Response(status)

    client = httpx.Client(transport=httpx.MockTransport(handler))
    monkeypatch.setattr(provision.time, "sleep", lambda _: None)
    with pytest.raises(httpx.HTTPStatusError):
        ensure_bucket(s3_config, http=client)
    assert seen == ["HEAD"] * attempts


def test_bucket_conflict_is_not_accepted_without_a_successful_rehead(
    s3_config: TraceStoreConfig,
) -> None:
    responses = deque([404, 409, 403])

    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(responses.popleft())

    with pytest.raises(httpx.HTTPStatusError):
        ensure_bucket(s3_config, http=httpx.Client(transport=httpx.MockTransport(handler)))


def test_s3_init_cli_does_not_render_a_secret_on_failure(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    secret = "not-for-diagnostics"

    def fail(*_: object) -> None:
        raise RuntimeError(secret)

    monkeypatch.setattr(provision, "ensure_bucket", fail)

    assert provision.main() == 1
    assert secret not in capsys.readouterr().err
