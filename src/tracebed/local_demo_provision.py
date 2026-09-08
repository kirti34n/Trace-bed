"""Owner-only, bounded provisioning and evidence seeding for the local demo."""

from __future__ import annotations

import base64
import json
import os
import re
import stat
import sys
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from importlib.resources import files
from pathlib import Path
from typing import Final
from urllib.parse import quote
from uuid import UUID, uuid5

import httpx
from psycopg_pool import ConnectionPool

from tracebed.domain.canonical import canonical_json, sha256_hex
from tracebed.domain.clock import SystemClock
from tracebed.domain.ids import AgentTypeId, PrincipalId, ProjectId
from tracebed.edge.local_demo import _KEY_RE
from tracebed.stores.pg.local_demo import LocalDemoOwnerStore
from tracebed.stores.pg.pool import create_pool
from tracebed.stores.pg.provisioning import ProjectProvisioner

__all__ = ["DemoProvisionError", "SeedRun", "load_seed_manifest", "main", "seed_public_api"]

_SECRET_DIR: Final = Path("/run/secrets")
_OWNER_SECRET: Final = "owner_db_password"  # noqa: S105 - mounted-secret filename.
_MASTER_SECRET: Final = "master_key"  # noqa: S105 - mounted-secret filename.
_DEMO_KEY_ENV: Final = "TB_DEMO_API_KEY_SECRET_FILE"
_DEMO_KEY_SECRET: Final = "demo_api_key_secret"  # noqa: S105 - mounted-secret filename.
_PROJECT_NAME_ENV: Final = "TB_DEMO_PROJECT_NAME"
_DEFAULT_PROJECT_NAME: Final = "tracebed-local-demo"
_API_URL: Final = "http://api:8110"
_PROJECT_NAME_RE: Final = re.compile(r"\A[a-z][a-z0-9-]{2,63}\Z")
_RUN_NAMESPACE: Final = UUID("8d31add7-43f7-5a6f-8e05-56ea1110d0b6")
_POLL_ATTEMPTS: Final = 30
_POLL_SECONDS: Final = 1.0


class DemoProvisionError(RuntimeError):
    """Opaque error at the owner/secret boundary."""


@dataclass(frozen=True, slots=True)
class SeedRun:
    run_id: UUID
    label: str
    status: str
    facts: str


@dataclass(frozen=True, slots=True)
class _FixedMaster:
    value: bytes

    def master_key(self) -> bytes:
        return self.value


def _read_fixed_secret(path: Path, *, expected_name: str) -> str:
    """Read one mounted secret only after rejecting links/writable paths."""

    if not path.is_absolute() or path.name != expected_name:
        raise DemoProvisionError("local demo configuration is invalid")
    try:
        parent = path.parent.lstat()
    except OSError:
        raise DemoProvisionError("local demo configuration is invalid") from None
    if (
        not stat.S_ISDIR(parent.st_mode)
        or stat.S_ISLNK(parent.st_mode)
        or stat.S_IMODE(parent.st_mode) & 0o022
    ):
        raise DemoProvisionError("local demo configuration is invalid")
    try:
        before = path.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or stat.S_IMODE(before.st_mode) & 0o022
            or before.st_nlink != 1
        ):
            raise OSError
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            after = os.fstat(descriptor)
            raw = os.read(descriptor, 4097)
        finally:
            os.close(descriptor)
    except OSError:
        raise DemoProvisionError("local demo configuration is invalid") from None
    if (after.st_dev, after.st_ino, after.st_mode, after.st_nlink) != (
        before.st_dev,
        before.st_ino,
        before.st_mode,
        before.st_nlink,
    ) or len(raw) > 4096:
        raise DemoProvisionError("local demo configuration is invalid")
    try:
        value = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise DemoProvisionError("local demo configuration is invalid") from None
    if value.endswith("\n"):
        value = value[:-1]
    if not value or "\n" in value or "\r" in value:
        raise DemoProvisionError("local demo configuration is invalid")
    return value


def _demo_api_key_from_environment(environment: Mapping[str, str]) -> str:
    value = environment.get(_DEMO_KEY_ENV)
    expected = _SECRET_DIR / _DEMO_KEY_SECRET
    if value != str(expected):
        raise DemoProvisionError("local demo configuration is invalid")
    key = _read_fixed_secret(expected, expected_name=_DEMO_KEY_SECRET)
    if not _KEY_RE.fullmatch(key):
        raise DemoProvisionError("local demo configuration is invalid")
    return key


def _master_from_environment(environment: Mapping[str, str]) -> _FixedMaster:
    if environment.get("TB_MASTER_KEY_FILE") != str(_SECRET_DIR / _MASTER_SECRET):
        raise DemoProvisionError("local demo configuration is invalid")
    try:
        value = base64.b64decode(
            _read_fixed_secret(_SECRET_DIR / _MASTER_SECRET, expected_name=_MASTER_SECRET),
            validate=True,
        )
    except ValueError as exc:
        raise DemoProvisionError("local demo configuration is invalid") from exc
    if len(value) != 32:
        raise DemoProvisionError("local demo configuration is invalid")
    return _FixedMaster(value)


def _owner_pool(environment: Mapping[str, str]) -> ConnectionPool:
    if environment.get("TB_OWNER_DB_PASSWORD_FILE") != str(_SECRET_DIR / _OWNER_SECRET):
        raise DemoProvisionError("local demo configuration is invalid")
    password = _read_fixed_secret(_SECRET_DIR / _OWNER_SECRET, expected_name=_OWNER_SECRET)
    return create_pool(
        "postgresql://tracebed_owner:" + quote(password, safe="") + "@postgres-admin:5432/tracebed"
    )


def load_seed_manifest() -> tuple[SeedRun, ...]:
    try:
        raw = (
            files("tracebed").joinpath("_demo", "validation-runs.json").read_text(encoding="utf-8")
        )
    except FileNotFoundError:
        raw = (Path(__file__).resolve().parents[2] / "demo" / "validation-runs.json").read_text(
            encoding="utf-8"
        )
    try:
        decoded = json.loads(raw)
        rows = (
            decoded["runs"]
            if isinstance(decoded, dict)
            and decoded.get("schema_version") == 1
            and decoded.get("mode") == "local_demo"
            else None
        )
        if not isinstance(rows, list) or not rows:
            raise ValueError
        result = tuple(
            SeedRun(UUID(entry["run_id"]), entry["label"], entry["status"], entry["facts"])
            for entry in rows
            if isinstance(entry, dict)
            and isinstance(entry.get("label"), str)
            and entry.get("status") in {"passed", "failed"}
            and isinstance(entry.get("facts"), str)
        )
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise DemoProvisionError("local demo seed manifest is invalid") from exc
    if (
        len(result) != len(rows)
        or len({row.run_id for row in result}) != len(result)
        or any(
            row.run_id
            != uuid5(
                _RUN_NAMESPACE,
                canonical_json(
                    {"facts": row.facts, "label": row.label, "status": row.status, "version": 1}
                ).decode("utf-8"),
            )
            for row in result
        )
    ):
        raise DemoProvisionError("local demo seed manifest is invalid")
    return result


def _ensure_principal(
    pool: ConnectionPool, project_id: ProjectId, api_key: str
) -> tuple[PrincipalId, AgentTypeId]:
    key_id, key_secret = api_key.removeprefix("tb_sk_").split(".", 1)
    try:
        return LocalDemoOwnerStore(pool, SystemClock()).ensure_api_principal(
            project_id, key_id, key_secret, "tracebed-local-demo"
        )
    except ValueError as exc:
        raise DemoProvisionError("local demo principal conflicts") from exc


def ensure_demo_owner_state(
    environment: Mapping[str, str],
) -> tuple[ProjectId, PrincipalId, AgentTypeId, str]:
    name = environment.get(_PROJECT_NAME_ENV, _DEFAULT_PROJECT_NAME)
    if not _PROJECT_NAME_RE.fullmatch(name):
        raise DemoProvisionError("local demo configuration is invalid")
    api_key = _demo_api_key_from_environment(environment)
    pool = _owner_pool(environment)
    try:
        request = {"kind": "local-demo", "name": name, "version": 1}
        project = ProjectProvisioner(
            pool, _master_from_environment(environment), SystemClock()
        ).provision_project(
            name=name,
            retention_policy=None,
            idempotency_key_hash=sha256_hex(
                canonical_json({"key": "tracebed-local-demo-v1", "name": name})
            ),
            request_hash=sha256_hex(canonical_json(request)),
        )
        principal, agent = _ensure_principal(pool, project, api_key)
        return project, principal, agent, api_key
    finally:
        pool.close()


def _trace_events(runs: tuple[SeedRun, ...], timestamp: str) -> dict[str, object]:
    events: list[dict[str, object]] = []
    for run in runs:
        events.extend(
            (
                {
                    "run_id": str(run.run_id),
                    "seq": 0,
                    "event": {
                        "type": "run_start",
                        "ts": timestamp,
                        "payload": {
                            "query_text": run.label,
                            "workflow_template": "local-demo-validation",
                            "tool_manifest": [],
                            "arm": "memory_on",
                        },
                    },
                },
                {
                    "run_id": str(run.run_id),
                    "seq": 1,
                    "event": {
                        "type": "state_note",
                        "ts": timestamp,
                        "payload": {"provenance": "imported_after_execution", "facts": run.facts},
                    },
                },
                {
                    "run_id": str(run.run_id),
                    "seq": 2,
                    "event": {
                        "type": "run_end",
                        "ts": timestamp,
                        "payload": {"status": "ok" if run.status == "passed" else "error"},
                    },
                },
            )
        )
    return {"events": events}


def seed_public_api(
    api_key: str,
    runs: tuple[SeedRun, ...],
    *,
    client: httpx.Client,
    sleep: Callable[[float], None] = time.sleep,
) -> None:
    """Seed only through public data/export endpoints and await trace authority."""

    timestamp = "2026-08-27T00:00:00+00:00"
    response = client.post(
        "/v1/trace/batch", json=_trace_events(runs, timestamp), headers={"X-API-Key": api_key}
    )
    if response.status_code != 202:
        raise DemoProvisionError("local demo seeding failed")
    wanted = {str(run.run_id): "ok" if run.status == "passed" else "error" for run in runs}
    for _ in range(_POLL_ATTEMPTS):
        response = client.get("/export/project", headers={"X-API-Key": api_key})
        if response.status_code != 200:
            raise DemoProvisionError("local demo seeding failed")
        observed: dict[str, str] = {}
        for line in response.text.splitlines():
            try:
                row = json.loads(line)
                if row.get("table") == "trace_index":
                    outcome = row["row"].get("outcome_status")
                    run_id = row["row"]["run_id"]
                    if not isinstance(outcome, str) or not isinstance(run_id, str):
                        raise TypeError
                    observed[run_id] = outcome
            except (AttributeError, KeyError, TypeError, json.JSONDecodeError):
                raise DemoProvisionError("local demo seeding failed") from None
        if all(observed.get(run_id) == outcome for run_id, outcome in wanted.items()):
            return
        sleep(_POLL_SECONDS)
    raise DemoProvisionError("local demo seeding timed out")


def owner_main() -> None:
    try:
        project, principal, agent, _ = ensure_demo_owner_state(os.environ)
    except Exception:
        print("local demo provisioning failed", file=sys.stderr)
        raise SystemExit(1) from None
    print(
        json.dumps(
            {
                "project_id": str(project.value),
                "principal_id": str(principal.value),
                "agent_type_id": str(agent.value),
            }
        )
    )


def seed_main() -> None:
    try:
        api_key = _demo_api_key_from_environment(os.environ)
        with httpx.Client(base_url=_API_URL, timeout=httpx.Timeout(5.0), trust_env=False) as client:
            seed_public_api(api_key, load_seed_manifest(), client=client)
    except Exception:
        print("local demo seeding failed", file=sys.stderr)
        raise SystemExit(1) from None


main = owner_main
