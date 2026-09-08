"""Closed Compose-v1 topology and secret-entrypoint tests."""

from __future__ import annotations

import os
from collections.abc import Callable
from pathlib import Path

import pytest

from tracebed import compose_runtime, runtime_ready

pytestmark = pytest.mark.phase1

_GENERATED_SECRET_ENV = (
    "TB_API_DB_DSN",
    "TB_WORKER_DB_DSN",
    "TB_ERASURE_DB_DSN",
    "TB_BOOTSTRAP_PG_DSN",
    "TB_ONBOARDING_PG_DSN",
    "TB_APP_PASSWORD",
    "TB_API_DB_PASSWORD",
    "TB_WORKER_DB_PASSWORD",
    "TB_ERASURE_DB_PASSWORD",
    "TB_HOLDOUT_SALT",
    "TB_MASTER_KEY",
    "TB_ADMIN_KEY",
)


@pytest.fixture(autouse=True)
def _remove_generated_secret_environment() -> object:
    """Entry points must not leak test-only generated values across examples."""

    for name in _GENERATED_SECRET_ENV:
        os.environ.pop(name, None)
    yield
    for name in _GENERATED_SECRET_ENV:
        os.environ.pop(name, None)


def _write_secret_files(tmp_path: Path) -> None:
    for name, value in {
        "api_db_password": "api-db-secret",
        "worker_db_password": "worker-db-secret",
        "erasure_db_password": "erasure-db-secret",
        "owner_db_password": "owner-db-secret",
        "app_db_password": "app-db-secret",
        "s3_runtime_access_key": "runtime-access",
        "s3_runtime_secret_key": "runtime-secret",
        "s3_erasure_access_key": "erasure-access",
        "s3_erasure_secret_key": "erasure-secret",
        "s3_init_access_key": "init-access",
        "s3_init_secret_key": "init-secret",
        "holdout_salt": "holdout-value",
        "master_key": "master-value",
        "admin_key": "admin-value",
    }.items():
        target = tmp_path / name
        target.write_text(f"{value}\n", encoding="utf-8")
        target.chmod(0o444)


def _set_runtime_file_environment(
    monkeypatch: pytest.MonkeyPatch, role: str, directory: Path
) -> None:
    secret_name = "api_db_password" if role == "tracebed_api" else "worker_db_password"
    db_variable = (
        "TB_API_DB_PASSWORD_FILE" if role == "tracebed_api" else "TB_WORKER_DB_PASSWORD_FILE"
    )
    monkeypatch.setenv(db_variable, str(directory / secret_name))
    settings = (
        compose_runtime._API_RUNTIME_FILE_SETTINGS
        if role == "tracebed_api"
        else compose_runtime._COMMON_RUNTIME_FILE_SETTINGS
    )
    for env_name, name in settings:
        monkeypatch.setenv(env_name, str(directory / name))


def _set_erasure_file_environment(monkeypatch: pytest.MonkeyPatch, directory: Path) -> None:
    monkeypatch.setenv("TB_ERASURE_DB_PASSWORD_FILE", str(directory / "erasure_db_password"))
    for env_name, name in compose_runtime._ERASURE_RUNTIME_FILE_SETTINGS:
        monkeypatch.setenv(env_name, str(directory / name))


@pytest.mark.parametrize(
    ("role", "function", "command", "dsn_name", "password"),
    (
        (
            "tracebed_api",
            compose_runtime.api_main,
            "tracebed-api",
            "TB_API_DB_DSN",
            "api-db-secret",
        ),
        (
            "tracebed_worker",
            compose_runtime.worker_main,
            "tracebed-worker",
            "TB_WORKER_DB_DSN",
            "worker-db-secret",
        ),
    ),
)
def test_runtime_entrypoints_construct_only_their_own_fixed_dsn(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    role: str,
    function: Callable[[], int],
    command: str,
    dsn_name: str,
    password: str,
) -> None:
    _write_secret_files(tmp_path)
    monkeypatch.setattr(compose_runtime, "_SECRETS_DIR", tmp_path)
    _set_runtime_file_environment(monkeypatch, role, tmp_path)
    seen: list[tuple[str, tuple[str, ...]]] = []

    def fake_exec(program: str, argv: tuple[str, ...]) -> None:
        seen.append((program, argv))

    monkeypatch.setattr(compose_runtime.os, "execvp", fake_exec)
    assert function() == 1
    assert seen == [(command, (command,))]
    assert (
        os.environ[dsn_name]
        == f"postgresql://{role}:{password}@postgres-{role.removeprefix('tracebed_')}:5432/tracebed"
    )
    other = "TB_WORKER_DB_DSN" if dsn_name == "TB_API_DB_DSN" else "TB_API_DB_DSN"
    assert other not in os.environ
    assert os.environ["TB_HOLDOUT_SALT"] == "holdout-value"
    assert os.environ["TB_MASTER_KEY"] == "master-value"
    if role == "tracebed_api":
        assert os.environ["TB_ADMIN_KEY"] == "admin-value"
    else:
        assert "TB_ADMIN_KEY" not in os.environ


@pytest.mark.parametrize(
    ("role", "function", "ready_function", "dsn_name"),
    (
        ("tracebed_api", compose_runtime.api_ready_main, "api_main", "TB_API_DB_DSN"),
        (
            "tracebed_worker",
            compose_runtime.worker_ready_main,
            "worker_main",
            "TB_WORKER_DB_DSN",
        ),
    ),
)
def test_compose_readiness_reconstructs_only_its_own_dsn_for_a_fresh_exec_process(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    role: str,
    function: Callable[[], int],
    ready_function: str,
    dsn_name: str,
) -> None:
    _write_secret_files(tmp_path)
    monkeypatch.setattr(compose_runtime, "_SECRETS_DIR", tmp_path)
    _set_runtime_file_environment(monkeypatch, role, tmp_path)
    seen: list[str] = []
    monkeypatch.setattr(runtime_ready, ready_function, lambda: seen.append(role) or 0)

    assert function() == 0
    assert seen == [role]
    assert os.environ[dsn_name].startswith(f"postgresql://{role}:")
    opposite = "TB_WORKER_DB_DSN" if dsn_name == "TB_API_DB_DSN" else "TB_API_DB_DSN"
    assert opposite not in os.environ


def test_api_healthcheck_combines_fresh_api_role_and_authenticated_loopback_readiness(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _write_secret_files(tmp_path)
    readiness_token = tmp_path / "readyz_token"
    readiness_token.write_text("mounted-readiness-token\n", encoding="utf-8")
    readiness_token.chmod(0o444)
    monkeypatch.setattr(compose_runtime, "_SECRETS_DIR", tmp_path)
    monkeypatch.setenv("TB_READYZ_TOKEN_FILE", str(readiness_token))
    checks: list[tuple[str, bool]] = []
    requests: list[compose_runtime.Request] = []

    monkeypatch.setattr(
        compose_runtime,
        "_runtime_ready_main",
        lambda role, *, serving: checks.append((role, serving)) or 0,
    )

    class _Response:
        def __enter__(self) -> _Response:
            return self

        def __exit__(self, *_: object) -> None:
            return None

        def read(self) -> bytes:
            return b'{"status":"ready"}'

    def _urlopen(request: compose_runtime.Request, *, timeout: float) -> _Response:
        requests.append(request)
        assert timeout == 3.0
        return _Response()

    monkeypatch.setattr(compose_runtime, "urlopen", _urlopen)

    assert compose_runtime.api_health_main() == 0
    assert checks == [("tracebed_api", True)]
    assert len(requests) == 1
    assert requests[0].full_url == "http://127.0.0.1:8110/readyz"
    assert requests[0].get_header("X-tracebed-readiness") == "mounted-readiness-token"


def test_api_healthcheck_accepts_a_two_second_plus_readyz_response_only_at_the_aligned_bound(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _write_secret_files(tmp_path)
    readiness_token = tmp_path / "readyz_token"
    readiness_token.write_text("mounted-readiness-token\n", encoding="utf-8")
    readiness_token.chmod(0o444)
    monkeypatch.setattr(compose_runtime, "_SECRETS_DIR", tmp_path)
    monkeypatch.setenv("TB_READYZ_TOKEN_FILE", str(readiness_token))
    checks: list[tuple[str, bool]] = []

    monkeypatch.setattr(
        compose_runtime,
        "_runtime_ready_main",
        lambda role, *, serving: checks.append((role, serving)) or 0,
    )

    class _Response:
        def __enter__(self) -> _Response:
            return self

        def __exit__(self, *_: object) -> None:
            return None

        def read(self) -> bytes:
            return b'{"status":"ready"}'

    def _two_point_one_second_response(
        _request: compose_runtime.Request, *, timeout: float
    ) -> _Response:
        if timeout < 2.1:
            raise TimeoutError("simulated two-point-one-second readiness response")
        return _Response()

    monkeypatch.setattr(compose_runtime, "urlopen", _two_point_one_second_response)

    assert compose_runtime.api_health_main() == 0
    monkeypatch.setattr(compose_runtime, "_API_HEALTH_READYZ_TIMEOUT_S", 2.0)
    assert compose_runtime.api_health_main() == 1
    assert capsys.readouterr().err == "tracebed-compose-api-health failed\n"
    assert checks == [("tracebed_api", True), ("tracebed_api", True)]


def test_api_healthcheck_stops_before_loopback_when_fresh_api_role_readiness_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(compose_runtime, "_runtime_ready_main", lambda *_args, **_kwargs: 1)
    monkeypatch.setattr(
        compose_runtime,
        "_probe_api_readyz",
        lambda: pytest.fail("must not call /readyz after failed database readiness"),
    )

    assert compose_runtime.api_health_main() == 1


@pytest.mark.parametrize(
    ("role", "function", "ready_function", "dsn_name"),
    (
        (
            "tracebed_api",
            compose_runtime.api_prepublication_ready_main,
            "api_prepublication_main",
            "TB_API_DB_DSN",
        ),
        (
            "tracebed_worker",
            compose_runtime.worker_prepublication_ready_main,
            "worker_prepublication_main",
            "TB_WORKER_DB_DSN",
        ),
    ),
)
def test_closed_controller_probe_reconstructs_only_its_own_runtime_dsn(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    role: str,
    function: Callable[[], int],
    ready_function: str,
    dsn_name: str,
) -> None:
    _write_secret_files(tmp_path)
    monkeypatch.setattr(compose_runtime, "_SECRETS_DIR", tmp_path)
    _set_runtime_file_environment(monkeypatch, role, tmp_path)
    seen: list[str] = []
    monkeypatch.setattr(runtime_ready, ready_function, lambda: seen.append(role) or 0)

    assert function() == 0
    assert seen == [role]
    assert os.environ[dsn_name].startswith(f"postgresql://{role}:")


@pytest.mark.parametrize("bad_name", ("TB_API_DB_DSN", "TB_S3_SECRET_KEY", "TB_HOLDOUT_SALT"))
def test_runtime_entrypoints_reject_direct_credentials_before_exec(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, bad_name: str
) -> None:
    _write_secret_files(tmp_path)
    monkeypatch.setattr(compose_runtime, "_SECRETS_DIR", tmp_path)
    _set_runtime_file_environment(monkeypatch, "tracebed_api", tmp_path)
    monkeypatch.setenv(bad_name, "attacker-secret")
    monkeypatch.setattr(compose_runtime.os, "execvp", lambda *_: pytest.fail("must not exec"))
    assert compose_runtime.api_main() == 1


@pytest.mark.parametrize(
    ("function", "argv", "command", "expected_arguments"),
    (
        (
            compose_runtime.erasure_once_main,
            ["tracebed-compose-erasure-once", "00000000-0000-0000-0000-000000000001"],
            "tracebed-erasure-once",
            ("00000000-0000-0000-0000-000000000001",),
        ),
        (
            compose_runtime.erasure_resume_main,
            [
                "tracebed-compose-erasure-resume",
                "00000000-0000-0000-0000-000000000001",
                "operator_resumed",
            ],
            "tracebed-erasure-resume",
            ("00000000-0000-0000-0000-000000000001", "operator_resumed"),
        ),
    ),
)
def test_compose_erasure_request_helpers_rebuild_only_the_erasure_identity(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    function: Callable[[], int],
    argv: list[str],
    command: str,
    expected_arguments: tuple[str, ...],
) -> None:
    _write_secret_files(tmp_path)
    monkeypatch.setattr(compose_runtime, "_SECRETS_DIR", tmp_path)
    _set_erasure_file_environment(monkeypatch, tmp_path)
    monkeypatch.setattr(compose_runtime.sys, "argv", argv)
    seen: list[tuple[str, tuple[str, ...]]] = []
    monkeypatch.setattr(
        compose_runtime.os, "execvp", lambda program, args: seen.append((program, args))
    )

    assert function() == 1
    assert seen == [(command, (command, *expected_arguments))]
    assert os.environ["TB_ERASURE_DB_DSN"] == (
        "postgresql://tracebed_erasure:erasure-db-secret@postgres-erasure:5432/tracebed"
    )
    assert "TB_ERASURE_DB_PASSWORD_FILE" not in os.environ


@pytest.mark.parametrize(
    ("function", "argv"),
    (
        (compose_runtime.erasure_once_main, ["tracebed-compose-erasure-once", "not-a-uuid"]),
        (
            compose_runtime.erasure_resume_main,
            ["tracebed-compose-erasure-resume", "00000000-0000-0000-0000-000000000001", "wrong"],
        ),
    ),
)
def test_compose_erasure_request_helpers_reject_noncanonical_public_arguments(
    monkeypatch: pytest.MonkeyPatch, function: Callable[[], int], argv: list[str]
) -> None:
    monkeypatch.setattr(compose_runtime.sys, "argv", argv)
    monkeypatch.setattr(compose_runtime.os, "execvp", lambda *_: pytest.fail("must not exec"))

    assert function() == 1


def test_bootstrap_reads_named_secrets_and_selects_only_compose_hba_profile(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _write_secret_files(tmp_path)
    monkeypatch.setattr(compose_runtime, "_SECRETS_DIR", tmp_path)
    for env_name, secret_name in (
        ("TB_OWNER_DB_PASSWORD_FILE", "owner_db_password"),
        ("TB_APP_DB_PASSWORD_FILE", "app_db_password"),
        ("TB_API_DB_PASSWORD_FILE", "api_db_password"),
        ("TB_WORKER_DB_PASSWORD_FILE", "worker_db_password"),
        ("TB_ERASURE_DB_PASSWORD_FILE", "erasure_db_password"),
    ):
        monkeypatch.setenv(env_name, str(tmp_path / secret_name))
    seen: list[str] = []
    monkeypatch.setattr(compose_runtime.os, "execvp", lambda command, _: seen.append(command))

    assert compose_runtime.bootstrap_main() == 1
    assert seen == ["tracebed-db-bootstrap"]
    assert os.environ["TB_BOOTSTRAP_PG_DSN"].startswith(
        "postgresql://tracebed_owner:owner-db-secret@postgres-admin:5432/tracebed"
    )
    assert os.environ["TB_PG_HBA_PROFILE"] == "compose-v1"


def test_onboarding_entrypoint_constructs_its_owner_dsn_from_the_named_secret(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _write_secret_files(tmp_path)
    monkeypatch.setattr(compose_runtime, "_SECRETS_DIR", tmp_path)
    monkeypatch.setenv("TB_OWNER_DB_PASSWORD_FILE", str(tmp_path / "owner_db_password"))
    seen: list[str] = []
    monkeypatch.setattr(compose_runtime.os, "execvp", lambda command, _: seen.append(command))

    assert compose_runtime.onboarding_main() == 1
    assert seen == ["tracebed-onboard-agent"]
    assert os.environ["TB_ONBOARDING_PG_DSN"].startswith(
        "postgresql://tracebed_owner:owner-db-secret@postgres-admin:5432/tracebed"
    )


def test_onboarding_entrypoint_rejects_an_ambient_owner_dsn_before_exec(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _write_secret_files(tmp_path)
    monkeypatch.setattr(compose_runtime, "_SECRETS_DIR", tmp_path)
    monkeypatch.setenv("TB_OWNER_DB_PASSWORD_FILE", str(tmp_path / "owner_db_password"))
    monkeypatch.setenv("TB_ONBOARDING_PG_DSN", "attacker-secret")
    monkeypatch.setattr(compose_runtime.os, "execvp", lambda *_: pytest.fail("must not exec"))

    assert compose_runtime.onboarding_main() == 1


def test_compose_declares_fixed_network_memberships_and_no_plaintext_s3_json() -> None:
    root = Path(__file__).parents[2]
    compose = (root / "docker" / "compose.yaml").read_text(encoding="utf-8")
    assert not (root / "docker" / "seaweedfs" / "s3.json").exists()
    assert "TB_S3_ACCESS_KEY:" not in compose
    assert "TB_S3_SECRET_KEY:" not in compose
    assert (
        "127.0.0.1:${TB_API_HOST_PORT:?TB_API_HOST_PORT must be an unused loopback port}:8110"
        in compose
    )
    assert (
        "127.0.0.1:${TB_DASHBOARD_HOST_PORT:?TB_DASHBOARD_HOST_PORT must be an unused loopback port}:8111"
        in compose
    )
    for subnet, addresses in {
        "10.77.10.0/29": ("10.77.10.2", "10.77.10.3"),
        "10.77.11.0/29": ("10.77.11.2", "10.77.11.3", "10.77.11.4"),
        "10.77.12.0/29": ("10.77.12.2", "10.77.12.3", "10.77.12.4"),
        "10.77.13.0/29": ("10.77.13.2", "10.77.13.3"),
        "10.77.14.0/28": ("10.77.14.2", "10.77.14.3", "10.77.14.4", "10.77.14.5", "10.77.14.6"),
        "10.77.15.0/29": ("10.77.15.2", "10.77.15.3", "10.77.15.4"),
    }.items():
        assert subnet in compose
        assert all(address in compose for address in addresses)
    for network in ("pg-admin", "pg-api", "pg-worker", "pg-probe", "runtime-data"):
        assert f"  {network}:\n    internal: true" in compose
    dashboard = compose.split("\n  dashboard:\n", 1)[1]
    assert "edge:" in dashboard
    assert "condition: service_healthy" in dashboard.split("\nvolumes:\n", 1)[0]


def test_worker_has_no_api_admin_or_readiness_secret_mount() -> None:
    """The worker entrypoint receives only worker/runtime data material."""

    root = Path(__file__).parents[2]
    compose = (root / "docker" / "compose.yaml").read_text(encoding="utf-8")
    worker = compose.split("\n  worker:\n", 1)[1].split("\n  dashboard:\n", 1)[0]
    api = compose.split("\n  api:\n", 1)[1].split("\n  worker:\n", 1)[0]
    assert "admin_key" not in worker
    assert "readyz_token" not in worker
    assert "TB_ADMIN_KEY_FILE" not in worker
    assert "TB_READYZ_TOKEN_FILE" not in worker
    assert "admin_key" in api and "readyz_token" in api
    assert 'test: ["CMD", "tracebed-compose-api-health"]' in api
    assert "timeout: 10s" in api
    assert "CMD-SHELL" not in api
    assert (
        compose_runtime._COMMON_RUNTIME_FILE_SETTINGS != compose_runtime._API_RUNTIME_FILE_SETTINGS
    )
