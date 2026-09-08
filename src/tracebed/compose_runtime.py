"""Closed Compose-v1 secret-file entrypoints.

These commands are intentionally not generic deployment configuration.  They
consume named Docker-secret files, construct only the fixed in-topology DSN
for the process they launch, and execute the installed application command.
"""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path
from typing import Final, Literal
from urllib.parse import quote
from urllib.request import Request, urlopen
from uuid import UUID

from tracebed.domain.errors import ConfigError

_SECRETS_DIR: Final = Path("/run/secrets")
_DATABASE: Final = "tracebed"
_PORT: Final = 5432
# The Compose health command has a fixed ten-second outer deadline.  Its
# authenticated serving probe uses the same three-second per-attempt bound as
# the acceptance readiness check; it does not retry within one health command.
_API_HEALTH_READYZ_TIMEOUT_S: Final = 3.0
_ROLE_HOSTS: Final = {
    "tracebed_api": "postgres-api",
    "tracebed_worker": "postgres-worker",
    "tracebed_erasure": "postgres-erasure",
    "tracebed_owner": "postgres-admin",
}
_ROLE_PASSWORD_FILE_ENV: Final = {
    "tracebed_api": "TB_API_DB_PASSWORD_FILE",
    "tracebed_worker": "TB_WORKER_DB_PASSWORD_FILE",
    "tracebed_erasure": "TB_ERASURE_DB_PASSWORD_FILE",
    "tracebed_owner": "TB_OWNER_DB_PASSWORD_FILE",
}
_ROLE_SECRET_NAMES: Final = {
    "tracebed_api": "api_db_password",
    "tracebed_worker": "worker_db_password",
    "tracebed_erasure": "erasure_db_password",
    "tracebed_owner": "owner_db_password",
}
_RUNTIME_DSN_ENV: Final = {
    "tracebed_api": "TB_API_DB_DSN",
    "tracebed_worker": "TB_WORKER_DB_DSN",
    "tracebed_erasure": "TB_ERASURE_DB_DSN",
}
_RAW_DATABASE_ENV: Final = frozenset(
    (
        "TB_API_DB_DSN",
        "TB_WORKER_DB_DSN",
        "TB_ERASURE_DB_DSN",
        "TB_BOOTSTRAP_PG_DSN",
        "TB_ONBOARDING_PG_DSN",
        "TB_API_DB_PASSWORD",
        "TB_WORKER_DB_PASSWORD",
        "TB_ERASURE_DB_PASSWORD",
        "TB_OWNER_DB_PASSWORD",
        "TB_APP_PASSWORD",
        "POSTGRES_PASSWORD",
    )
)
_RAW_OBJECT_STORE_ENV: Final = frozenset(
    (
        "TB_S3_ACCESS_KEY",
        "TB_S3_SECRET_KEY",
        "TB_S3_ERASURE_ACCESS_KEY",
        "TB_S3_ERASURE_SECRET_KEY",
        "TB_HOLDOUT_SALT",
        "TB_MASTER_KEY",
        "TB_ADMIN_KEY",
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
    )
)
_RAW_CREDENTIAL_ENV_CASEFOLD: Final = frozenset(
    name.casefold() for name in (*_RAW_DATABASE_ENV, *_RAW_OBJECT_STORE_ENV)
)
_COMMON_RUNTIME_FILE_SETTINGS: Final = (
    ("TB_S3_RUNTIME_ACCESS_KEY_FILE", "s3_runtime_access_key"),
    ("TB_S3_RUNTIME_SECRET_KEY_FILE", "s3_runtime_secret_key"),
    ("TB_HOLDOUT_SALT_FILE", "holdout_salt"),
    ("TB_MASTER_KEY_FILE", "master_key"),
)
_API_RUNTIME_FILE_SETTINGS: Final = (
    *_COMMON_RUNTIME_FILE_SETTINGS,
    ("TB_ADMIN_KEY_FILE", "admin_key"),
)
_ERASURE_RUNTIME_FILE_SETTINGS: Final = (
    ("TB_S3_ERASURE_ACCESS_KEY_FILE", "s3_erasure_access_key"),
    ("TB_S3_ERASURE_SECRET_KEY_FILE", "s3_erasure_secret_key"),
)

_RuntimeRole = Literal["tracebed_api", "tracebed_worker", "tracebed_erasure"]
_DatabaseRole = Literal["tracebed_api", "tracebed_worker", "tracebed_erasure", "tracebed_owner"]


def _compose_error() -> ConfigError:
    return ConfigError("Compose-v1 secret configuration is invalid")


def _reject_direct_credentials(*, allow_database: bool = False) -> None:
    forbidden = (
        _RAW_OBJECT_STORE_ENV if allow_database else (_RAW_OBJECT_STORE_ENV | _RAW_DATABASE_ENV)
    )
    if any(
        name.casefold() in {item.casefold() for item in forbidden}
        or name.casefold().startswith("pg")
        for name in os.environ
    ):
        raise _compose_error()


def _read_named_secret(env_name: str, secret_name: str) -> str:
    path_value = os.environ.get(env_name)
    expected = _SECRETS_DIR / secret_name
    if path_value != str(expected):
        raise _compose_error()
    try:
        before = expected.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or stat.S_ISLNK(before.st_mode)
            or stat.S_IMODE(before.st_mode) != 0o444
            or before.st_nlink != 1
        ):
            raise OSError
        descriptor = os.open(expected, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            after = os.fstat(descriptor)
            if (
                not stat.S_ISREG(after.st_mode)
                or after.st_ino != before.st_ino
                or after.st_dev != before.st_dev
                or after.st_nlink != 1
                or stat.S_IMODE(after.st_mode) != 0o444
            ):
                raise OSError
            value = os.read(descriptor, after.st_size + 1).decode("utf-8")
        finally:
            os.close(descriptor)
    except (OSError, UnicodeDecodeError):
        raise _compose_error() from None
    if value.endswith("\n"):
        value = value[:-1]
    if not value or "\n" in value or "\r" in value or "\x00" in value:
        raise _compose_error()
    return value


def _database_dsn(role: _DatabaseRole, password: str) -> str:
    return f"postgresql://{role}:{quote(password, safe='')}@{_ROLE_HOSTS[role]}:{_PORT}/{_DATABASE}"


def _exec(command: str, arguments: tuple[str, ...] = ()) -> None:
    os.execvp(command, (command, *arguments))  # noqa: S606 - fixed installed entrypoint only


def _runtime_entrypoint(role: _RuntimeRole, command: str, arguments: tuple[str, ...] = ()) -> int:
    _reject_direct_credentials()
    password = _read_named_secret(_ROLE_PASSWORD_FILE_ENV[role], _ROLE_SECRET_NAMES[role])
    file_settings = (
        _API_RUNTIME_FILE_SETTINGS
        if role == "tracebed_api"
        else _COMMON_RUNTIME_FILE_SETTINGS
        if role == "tracebed_worker"
        else _ERASURE_RUNTIME_FILE_SETTINGS
    )
    secret_values = {
        env_name: _read_named_secret(env_name, secret_name)
        for env_name, secret_name in file_settings
    }
    os.environ.pop(_ROLE_PASSWORD_FILE_ENV[role], None)
    os.environ[_RUNTIME_DSN_ENV[role]] = _database_dsn(role, password)
    access_key_env = (
        "TB_S3_ERASURE_ACCESS_KEY_FILE"
        if role == "tracebed_erasure"
        else "TB_S3_RUNTIME_ACCESS_KEY_FILE"
    )
    secret_key_env = (
        "TB_S3_ERASURE_SECRET_KEY_FILE"
        if role == "tracebed_erasure"
        else "TB_S3_RUNTIME_SECRET_KEY_FILE"
    )
    os.environ["TB_STORAGE__TRACESTORE__ACCESS_KEY_ENV"] = access_key_env
    os.environ["TB_STORAGE__TRACESTORE__SECRET_KEY_ENV"] = secret_key_env
    # The application-level providers predate file references.  The wrapper
    # turns named, mounted secrets into process-local values immediately before
    # exec; Compose never renders their plaintext and callers cannot inject
    # them through the environment.
    if role != "tracebed_erasure":
        os.environ["TB_HOLDOUT_SALT"] = secret_values["TB_HOLDOUT_SALT_FILE"]
        os.environ["TB_MASTER_KEY"] = secret_values["TB_MASTER_KEY_FILE"]
    if role == "tracebed_api":
        os.environ["TB_ADMIN_KEY"] = secret_values["TB_ADMIN_KEY_FILE"]
    _exec(command, arguments)
    return 1  # pragma: no cover - os.execvp never returns


def api_main() -> int:
    """Run the API with only its fixed API-network credential."""

    try:
        return _runtime_entrypoint("tracebed_api", "tracebed-api")
    except Exception:
        print("tracebed-compose-api failed", file=sys.stderr)
        return 1


def worker_main() -> int:
    """Run the worker with only its fixed worker-network credential."""

    try:
        return _runtime_entrypoint("tracebed_worker", "tracebed-worker")
    except Exception:
        print("tracebed-compose-worker failed", file=sys.stderr)
        return 1


def erasure_main() -> int:
    """Run the separately credentialed E4 erasure executor."""

    try:
        return _runtime_entrypoint("tracebed_erasure", "tracebed-erasure-worker")
    except Exception:
        print("tracebed-compose-erasure failed", file=sys.stderr)
        return 1


def _canonical_erasure_request_id(arguments: list[str]) -> str:
    """Accept exactly one canonical request identifier for a Compose helper."""

    if len(arguments) != 1:
        raise _compose_error()
    raw = arguments[0]
    try:
        request_id = UUID(raw)
    except (TypeError, ValueError):
        raise _compose_error() from None
    if str(request_id) != raw:
        raise _compose_error()
    return raw


def erasure_once_main() -> int:
    """Run one bounded request after reconstructing only the erasure identity.

    ``docker exec`` starts a fresh process with Compose's secret-file paths,
    not PID 1's process-private DSN.  This fixed wrapper reconstructs that
    identity before dispatching the public request-ID-only command.
    """

    try:
        request_id = _canonical_erasure_request_id(sys.argv[1:])
        return _runtime_entrypoint("tracebed_erasure", "tracebed-erasure-once", (request_id,))
    except Exception:
        print("tracebed-compose-erasure-once failed", file=sys.stderr)
        return 1


def erasure_resume_main() -> int:
    """Resume one operator-blocked request through the same erasure identity."""

    try:
        arguments = sys.argv[1:]
        if len(arguments) != 2 or arguments[1] != "operator_resumed":
            raise _compose_error()
        request_id = _canonical_erasure_request_id(arguments[:1])
        return _runtime_entrypoint(
            "tracebed_erasure", "tracebed-erasure-resume", (request_id, "operator_resumed")
        )
    except Exception:
        print("tracebed-compose-erasure-resume failed", file=sys.stderr)
        return 1


def worker_drain_main() -> int:
    """Run the physical worker-identity drain counter with worker-only secrets."""

    try:
        return _runtime_entrypoint("tracebed_worker", "tracebed-worker-drain")
    except Exception:
        print("tracebed-compose-worker-drain failed", file=sys.stderr)
        return 1


def _runtime_ready_main(role: _RuntimeRole, *, serving: bool) -> int:
    """Run a fresh readiness probe with this service's named DB secret only.

    Docker healthchecks are separate ``exec`` processes, so they cannot
    inherit the process-local DSN assembled by ``_runtime_entrypoint``.  This
    uses the same closed role/secret mapping rather than adding a plaintext
    DSN to the rendered Compose environment.
    """

    _reject_direct_credentials()
    password = _read_named_secret(_ROLE_PASSWORD_FILE_ENV[role], _ROLE_SECRET_NAMES[role])
    if role == "tracebed_erasure":
        _read_named_secret("TB_S3_ERASURE_ACCESS_KEY_FILE", "s3_erasure_access_key")
        _read_named_secret("TB_S3_ERASURE_SECRET_KEY_FILE", "s3_erasure_secret_key")
        os.environ["TB_STORAGE__TRACESTORE__ACCESS_KEY_ENV"] = "TB_S3_ERASURE_ACCESS_KEY_FILE"
        os.environ["TB_STORAGE__TRACESTORE__SECRET_KEY_ENV"] = "TB_S3_ERASURE_SECRET_KEY_FILE"  # noqa: S105
    os.environ.pop(_ROLE_PASSWORD_FILE_ENV[role], None)
    os.environ[_RUNTIME_DSN_ENV[role]] = _database_dsn(role, password)
    if role == "tracebed_api":
        from tracebed.runtime_ready import api_main, api_prepublication_main

        return api_main() if serving else api_prepublication_main()
    if role == "tracebed_worker":
        from tracebed.runtime_ready import worker_main, worker_prepublication_main

        return worker_main() if serving else worker_prepublication_main()
    from tracebed.runtime_ready import erasure_main, erasure_prepublication_main

    return erasure_main() if serving else erasure_prepublication_main()


def api_ready_main() -> int:
    """Run the API healthcheck against a fresh API-role connection."""

    try:
        return _runtime_ready_main("tracebed_api", serving=True)
    except Exception:
        print("tracebed-compose-api-ready failed", file=sys.stderr)
        return 1


def _probe_api_readyz() -> None:
    """Call the local dependency readiness route with its mounted-only token."""

    token = _read_named_secret("TB_READYZ_TOKEN_FILE", "readyz_token")
    request = Request(
        "http://127.0.0.1:8110/readyz",
        headers={"X-Tracebed-Readiness": token},
    )
    with urlopen(  # noqa: S310 - fixed loopback readiness endpoint
        request, timeout=_API_HEALTH_READYZ_TIMEOUT_S
    ) as response:
        response.read()


def api_health_main() -> int:
    """Run both API-role DB readiness and authenticated local serving readiness.

    This is a single, exec-form Compose healthcheck command.  It deliberately
    reads the readiness token only from the mounted Docker secret and never
    renders it in the Compose environment or logs it.
    """

    try:
        if _runtime_ready_main("tracebed_api", serving=True) != 0:
            return 1
        _probe_api_readyz()
    except Exception:
        print("tracebed-compose-api-health failed", file=sys.stderr)
        return 1
    return 0


def worker_ready_main() -> int:
    """Run the worker healthcheck against a fresh worker-role connection."""

    try:
        return _runtime_ready_main("tracebed_worker", serving=True)
    except Exception:
        print("tracebed-compose-worker-ready failed", file=sys.stderr)
        return 1


def erasure_ready_main() -> int:
    """Run fresh serving readiness with only the erasure DB secret."""

    try:
        return _runtime_ready_main("tracebed_erasure", serving=True)
    except Exception:
        print("tracebed-compose-erasure-ready failed", file=sys.stderr)
        return 1


def api_prepublication_ready_main() -> int:
    """Run the closed-controller API identity/profile probe."""

    try:
        return _runtime_ready_main("tracebed_api", serving=False)
    except Exception:
        print("tracebed-compose-api-prepublication-ready failed", file=sys.stderr)
        return 1


def worker_prepublication_ready_main() -> int:
    """Run the closed-controller worker identity/profile probe."""

    try:
        return _runtime_ready_main("tracebed_worker", serving=False)
    except Exception:
        print("tracebed-compose-worker-prepublication-ready failed", file=sys.stderr)
        return 1


def erasure_prepublication_ready_main() -> int:
    """Run the closed-controller erasure identity/dependency probe."""

    try:
        return _runtime_ready_main("tracebed_erasure", serving=False)
    except Exception:
        print("tracebed-compose-erasure-prepublication-ready failed", file=sys.stderr)
        return 1


def bootstrap_main() -> int:
    """Run the owner-only bootstrap with all named DB secret files once."""

    try:
        _reject_direct_credentials()
        owner_password = _read_named_secret("TB_OWNER_DB_PASSWORD_FILE", "owner_db_password")
        app_password = _read_named_secret("TB_APP_DB_PASSWORD_FILE", "app_db_password")
        api_password = _read_named_secret("TB_API_DB_PASSWORD_FILE", "api_db_password")
        worker_password = _read_named_secret("TB_WORKER_DB_PASSWORD_FILE", "worker_db_password")
        erasure_password = _read_named_secret("TB_ERASURE_DB_PASSWORD_FILE", "erasure_db_password")
        for env_name in (
            "TB_OWNER_DB_PASSWORD_FILE",
            "TB_APP_DB_PASSWORD_FILE",
            "TB_API_DB_PASSWORD_FILE",
            "TB_WORKER_DB_PASSWORD_FILE",
            "TB_ERASURE_DB_PASSWORD_FILE",
        ):
            os.environ.pop(env_name, None)
        os.environ["TB_BOOTSTRAP_PG_DSN"] = _database_dsn("tracebed_owner", owner_password)
        os.environ["TB_APP_PASSWORD"] = app_password
        os.environ["TB_API_DB_PASSWORD"] = api_password
        os.environ["TB_WORKER_DB_PASSWORD"] = worker_password
        os.environ["TB_ERASURE_DB_PASSWORD"] = erasure_password
        os.environ["TB_PG_CLUSTER_SCOPE"] = "dedicated"
        os.environ["TB_PG_HBA_PROFILE"] = "compose-v1"
        _exec("tracebed-db-bootstrap")
    except Exception:
        print("tracebed-compose-bootstrap failed", file=sys.stderr)
        return 1
    return 1  # pragma: no cover - os.execvp never returns


def onboarding_main() -> int:
    """Run the installed owner-only onboarding console from its named secret.

    This is intentionally a one-shot helper for ``docker compose run`` and
    never a long-running service or an API dependency.  It accepts the
    onboarding command's public configuration fields, but replaces any
    ambient owner DSN with the sole fixed admin-network endpoint assembled
    from the mounted owner password.
    """

    try:
        _reject_direct_credentials()
        owner_password = _read_named_secret("TB_OWNER_DB_PASSWORD_FILE", "owner_db_password")
        os.environ.pop("TB_OWNER_DB_PASSWORD_FILE", None)
        os.environ["TB_ONBOARDING_PG_DSN"] = _database_dsn("tracebed_owner", owner_password)
        _exec("tracebed-onboard-agent")
    except Exception:
        print("tracebed-compose-onboard failed", file=sys.stderr)
        return 1
    return 1  # pragma: no cover - os.execvp never returns


def s3_init_main() -> int:
    """Run S3 initialization from named file references, never raw key envs."""

    try:
        _reject_direct_credentials()
        _read_named_secret("TB_S3_INIT_ACCESS_KEY_FILE", "s3_init_access_key")
        _read_named_secret("TB_S3_INIT_SECRET_KEY_FILE", "s3_init_secret_key")
        os.environ["TB_STORAGE__TRACESTORE__ACCESS_KEY_ENV"] = "TB_S3_INIT_ACCESS_KEY_FILE"
        os.environ["TB_STORAGE__TRACESTORE__SECRET_KEY_ENV"] = "TB_S3_INIT_SECRET_KEY_FILE"  # noqa: S105
        _exec("tracebed-s3-init")
    except Exception:
        print("tracebed-compose-s3-init failed", file=sys.stderr)
        return 1
    return 1  # pragma: no cover - os.execvp never returns
