#!/usr/bin/env python3
"""Closed, reproducible lifecycle for the intentionally local Tracebed demo."""

from __future__ import annotations

import argparse
import base64
import importlib.util
import json
import os
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from socket import AF_INET, SOCK_STREAM, socket
from types import ModuleType
from typing import Final, cast
from uuid import uuid4

from tracebed.compose_secrets import COMPOSE_SECRET_FILES

ROOT: Final = Path(__file__).resolve().parents[1]
STATE_ROOT: Final = ROOT / ".tracebed-demo"
STATE_FILE: Final = STATE_ROOT / "state.json"
SECRETS: Final = STATE_ROOT / "secrets"
DEMO_SECRET: Final = STATE_ROOT / "demo-secret"
BASE: Final = ROOT / "docker" / "compose.yaml"
OVERLAY: Final = ROOT / "docker" / "compose.demo.yaml"
SECRET_NAMES: Final = tuple(COMPOSE_SECRET_FILES.values())
SUSTAINED_SERVICES: Final = frozenset(
    {"postgres", "valkey", "seaweedfs", "api", "edge", "worker", "erasure", "dashboard"}
)
SCHEMA: Final = 1
_PHASES: Final = frozenset({"new", "recovering", "active", "stopped"})
_COMPOSE_SHORT_VERSION: Final = re.compile(r"\Av?(?P<major>[0-9]+)\.[0-9]+\.[0-9]+\Z")


class LocalDemoError(RuntimeError):
    """Opaque launcher failure; paths, commands, and secret values stay private."""


def _private(path: Path, mode: int) -> None:
    path.mkdir(mode=mode, exist_ok=True)
    metadata = path.lstat()
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != mode
        or metadata.st_uid != os.geteuid()
        or metadata.st_gid != os.getegid()
    ):
        raise LocalDemoError("local demo state is invalid")


def _existing_private(path: Path, mode: int) -> None:
    try:
        metadata = path.lstat()
    except OSError:
        raise LocalDemoError("local demo state is invalid") from None
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != mode
        or metadata.st_uid != os.geteuid()
        or metadata.st_gid != os.getegid()
    ):
        raise LocalDemoError("local demo state is invalid")


def _leaf(path: Path) -> None:
    item = path.lstat()
    if (
        not stat.S_ISREG(item.st_mode)
        or stat.S_ISLNK(item.st_mode)
        or item.st_nlink != 1
        or stat.S_IMODE(item.st_mode) != 0o444
        or item.st_uid != os.geteuid()
        or item.st_gid != os.getegid()
    ):
        raise LocalDemoError("local demo state is invalid")


def _write_secret(path: Path, value: str) -> None:
    """Create an immutable leaf without ever passing its value to a child."""

    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o444)
        os.fchmod(descriptor, 0o444)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(value + "\n")
            handle.flush()
            os.fsync(handle.fileno())
    except OSError:
        raise LocalDemoError("local demo state is invalid") from None
    _leaf(path)


def _unused_port() -> int:
    with socket(AF_INET, SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def _port_available(port: int) -> bool:
    if type(port) is not int or not 1024 <= port <= 65535:
        return False
    with socket(AF_INET, SOCK_STREAM) as probe:
        try:
            probe.bind(("127.0.0.1", port))
        except OSError:
            return False
    return True


def _source_identity() -> dict[str, object]:
    metadata = ROOT.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise LocalDemoError("local demo state is invalid")
    return {"path": str(ROOT), "device": metadata.st_dev, "inode": metadata.st_ino}


def _base_env(project: str, api_port: int, dashboard_port: int) -> dict[str, str]:
    env = {
        "COMPOSE_PROJECT_NAME": project,
        "TB_API_HOST_PORT": str(api_port),
        "TB_DASHBOARD_HOST_PORT": str(dashboard_port),
    }
    env.update({env_name: str(SECRETS / leaf) for env_name, leaf in COMPOSE_SECRET_FILES.items()})
    return env


def _state_port(state: dict[str, object], name: str) -> int:
    value = state.get(name)
    if type(value) is not int or not 1024 <= value <= 65535:
        raise LocalDemoError("local demo state is invalid")
    return value


def _write_state(state: dict[str, object]) -> None:
    """Atomically replace the non-secret 0600 state receipt."""

    _existing_private(STATE_ROOT, 0o700)
    temporary: Path | None = None
    try:
        descriptor, temporary_name = tempfile.mkstemp(prefix=".state-", dir=STATE_ROOT)
        temporary = Path(temporary_name)
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(json.dumps(state, sort_keys=True, separators=(",", ":")))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, STATE_FILE)
        temporary = None
        directory = os.open(STATE_ROOT, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except OSError:
        raise LocalDemoError("local demo state is invalid") from None
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()


def _create_state() -> dict[str, object]:
    _private(STATE_ROOT, 0o700)
    _private(SECRETS, 0o700)
    _private(DEMO_SECRET, 0o700)
    if any(SECRETS.iterdir()) or any(DEMO_SECRET.iterdir()) or STATE_FILE.exists():
        raise LocalDemoError("local demo state is invalid")
    for name in SECRET_NAMES:
        _write_secret(
            SECRETS / name,
            base64.b64encode(secrets.token_bytes(32)).decode("ascii")
            if name == "master_key"
            else secrets.token_urlsafe(32),
        )
    _write_secret(
        DEMO_SECRET / "demo_api_key_secret", f"tb_sk_{uuid4().hex}.{secrets.token_urlsafe(32)}"
    )
    project = "tracebed-demo-" + uuid4().hex[:12]
    api_port, dashboard_port = _unused_port(), _unused_port()
    while dashboard_port == api_port:
        dashboard_port = _unused_port()
    state: dict[str, object] = {
        "schema": SCHEMA,
        "phase": "new",
        "project": project,
        "api_port": api_port,
        "dashboard_port": dashboard_port,
        "origin": f"http://127.0.0.1:{dashboard_port}",
        "source": _source_identity(),
    }
    _write_state(state)
    return state


def _load_state() -> dict[str, object]:
    try:
        _existing_private(STATE_ROOT, 0o700)
        _existing_private(SECRETS, 0o700)
        _existing_private(DEMO_SECRET, 0o700)
        state_metadata = STATE_FILE.lstat()
        if (
            not stat.S_ISREG(state_metadata.st_mode)
            or stat.S_ISLNK(state_metadata.st_mode)
            or state_metadata.st_nlink != 1
            or stat.S_IMODE(state_metadata.st_mode) != 0o600
            or state_metadata.st_uid != os.geteuid()
            or state_metadata.st_gid != os.getegid()
        ):
            raise ValueError
        value = json.loads(STATE_FILE.read_text(encoding="utf-8"))
        if (
            not isinstance(value, dict)
            or value.get("schema") != SCHEMA
            or value.get("source") != _source_identity()
            or value.get("phase") not in _PHASES
        ):
            raise ValueError
        project = value.get("project")
        if (
            not isinstance(project, str)
            or not project.startswith("tracebed-demo-")
            or not project.islower()
            or not project.replace("-", "").isalnum()
        ):
            raise ValueError
        if {item.name for item in SECRETS.iterdir()} != set(SECRET_NAMES) or {
            item.name for item in DEMO_SECRET.iterdir()
        } != {"demo_api_key_secret"}:
            raise ValueError
        for name in SECRET_NAMES:
            _leaf(SECRETS / name)
        _leaf(DEMO_SECRET / "demo_api_key_secret")
        api_port, dashboard_port = (
            _state_port(value, "api_port"),
            _state_port(value, "dashboard_port"),
        )
        if (
            api_port == dashboard_port
            or value.get("origin") != f"http://127.0.0.1:{dashboard_port}"
        ):
            raise ValueError
        return cast(dict[str, object], value)
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        raise LocalDemoError("local demo state is invalid") from None


def _overlay_env(state: dict[str, object]) -> dict[str, str]:
    env = _base_env(
        str(state["project"]), _state_port(state, "api_port"), _state_port(state, "dashboard_port")
    )
    env.update(
        {
            "TB_DEMO_API_KEY_SECRET_FILE": str(DEMO_SECRET / "demo_api_key_secret"),
            "TB_LOCAL_DEMO_ORIGIN": str(state["origin"]),
            "TB_DEMO_PROJECT_NAME": "tracebed-local-demo",
            "COMPOSE_PROFILES": "local-demo-provision",
        }
    )
    return env


def _compose(
    state: dict[str, object], *args: str, overlay: bool = False, result: bool = False
) -> subprocess.CompletedProcess[str] | None:
    """Run only a fixed Compose shape; all output remains private."""

    command = ["docker", "compose", "--project-directory", str(ROOT), "--file", str(BASE)]
    if overlay:
        command.extend(("--file", str(OVERLAY)))
    command.extend(("--project-name", str(state["project"]), *args))
    environment = {
        name: value
        for name, value in os.environ.items()
        if not name.startswith("TB_") and name not in {"COMPOSE_PROJECT_NAME", "COMPOSE_PROFILES"}
    }
    environment.update(
        _overlay_env(state)
        if overlay
        else _base_env(
            str(state["project"]),
            _state_port(state, "api_port"),
            _state_port(state, "dashboard_port"),
        )
    )
    try:
        completed = subprocess.run(  # noqa: S603 - entirely closed command surface above.
            command, check=True, text=True, capture_output=True, env=environment
        )
    except (OSError, subprocess.CalledProcessError):
        raise LocalDemoError("local demo operation failed") from None
    return completed if result else None


def _controller() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "tracebed_compose_stack", ROOT / "scripts" / "compose_stack.py"
    )
    if spec is None or spec.loader is None:
        raise LocalDemoError("local demo operation failed")
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except Exception:
        raise LocalDemoError("local demo operation failed") from None
    return module


def _validate_host() -> None:
    if sys.platform != "linux" or sys.version_info[:2] != (3, 13):
        raise LocalDemoError("local demo host is unsupported")
    docker = shutil.which("docker")
    if docker is None or shutil.which("ip") is None:
        raise LocalDemoError("local demo host is unsupported")
    try:
        result = subprocess.run(  # noqa: S603 - docker path was resolved from the trusted host PATH.
            (docker, "compose", "version", "--short"), check=True, text=True, capture_output=True
        )
    except (OSError, subprocess.CalledProcessError):
        raise LocalDemoError("local demo host is unsupported") from None
    version = _COMPOSE_SHORT_VERSION.fullmatch(result.stdout.strip())
    if version is None or int(version["major"]) < 2:
        raise LocalDemoError("local demo host is unsupported")


@contextmanager
def _base_controller_environment(state: dict[str, object]) -> Iterator[None]:
    """Give the base controller precisely its 16 secret selectors, never demo."""

    original = dict(os.environ)
    try:
        for name in tuple(os.environ):
            if name.startswith("TB_") or name in {"COMPOSE_PROJECT_NAME", "COMPOSE_PROFILES"}:
                os.environ.pop(name)
        os.environ.update(
            _base_env(
                str(state["project"]),
                _state_port(state, "api_port"),
                _state_port(state, "dashboard_port"),
            )
        )
        yield
    finally:
        os.environ.clear()
        os.environ.update(original)


def _assert_sustained_topology(
    state: dict[str, object], controller: ModuleType | None = None
) -> None:
    """Require exactly eight normal services, healthy wherever a healthcheck exists."""

    completed = _compose(state, "ps", "--format", "json", overlay=True, result=True)
    assert completed is not None
    try:
        rows = _compose_ps_rows(completed.stdout)
        if len(rows) != len(SUSTAINED_SERVICES):
            raise ValueError
        services: set[str] = set()
        for row in rows:
            if not isinstance(row, dict):
                raise ValueError
            service, state_value, health = (
                row.get("Service"),
                row.get("State"),
                row.get("Health", ""),
            )
            if (
                not isinstance(service, str)
                or not isinstance(state_value, str)
                or not isinstance(health, str)
                or state_value.lower() != "running"
                or (health and health.lower() != "healthy")
            ):
                raise ValueError
            services.add(service)
        if services != SUSTAINED_SERVICES:
            raise ValueError
        (controller if controller is not None else _controller())._validate_host_network_isolation(
            str(state["project"])
        )
    except (TypeError, ValueError, json.JSONDecodeError):
        raise LocalDemoError("local demo operation failed") from None


def _compose_ps_rows(output: str) -> list[dict[str, object]]:
    """Parse the documented Compose JSON array/object or JSONL object forms."""

    if not output.strip():
        raise ValueError
    try:
        parsed = json.loads(output)
    except json.JSONDecodeError:
        lines = output.splitlines()
        if not lines or any(not line.strip() for line in lines):
            raise ValueError from None
        parsed = [json.loads(line) for line in lines]
    rows = parsed if isinstance(parsed, list) else [parsed]
    if not rows or any(not isinstance(row, dict) for row in rows):
        raise ValueError
    return rows


def _set_phase(state: dict[str, object], phase: str) -> None:
    if phase not in _PHASES:
        raise LocalDemoError("local demo state is invalid")
    state["phase"] = phase
    _write_state(state)


def start() -> str:
    _validate_host()
    existed = STATE_FILE.exists()
    state = _load_state() if existed else _create_state()
    if state["phase"] in {"new", "stopped"} and (
        not _port_available(_state_port(state, "api_port"))
        or not _port_available(_state_port(state, "dashboard_port"))
    ):
        raise LocalDemoError("local demo ports are unavailable")
    controller = _controller()
    try:
        with _base_controller_environment(state), controller._controller_lifecycle_lock():
            if state["phase"] in {"active", "recovering"}:
                controller._upgrade()
            else:
                controller._start()
            _set_phase(state, "recovering")
            _compose(state, "run", "--build", "--rm", "demo-provision", overlay=True)
            _compose(
                state,
                "up",
                "--build",
                "--detach",
                "--wait",
                "--force-recreate",
                "edge",
                overlay=True,
            )
            _compose(state, "run", "--build", "--rm", "demo-data", overlay=True)
            _compose(
                state, "up", "--detach", "--wait", "--force-recreate", "dashboard", overlay=True
            )
            _assert_sustained_topology(state, controller)
            _set_phase(state, "active")
    except LocalDemoError:
        raise
    except Exception:
        raise LocalDemoError("local demo operation failed") from None
    return str(state["origin"])


def status() -> tuple[str, str]:
    state = _load_state()
    try:
        if state["phase"] == "active":
            _assert_sustained_topology(state)
    except LocalDemoError:
        raise
    except Exception:
        raise LocalDemoError("local demo operation failed") from None
    return str(state["origin"]), str(state["phase"])


def stop() -> None:
    state = _load_state()
    if state["phase"] == "stopped":
        return
    controller = _controller()
    try:
        with _base_controller_environment(state), controller._controller_lifecycle_lock():
            controller._validate_rendered_configuration()
            controller._fence_and_drain_runtime()
            _compose(state, "down", "--remove-orphans", overlay=True)
            _set_phase(state, "stopped")
    except LocalDemoError:
        raise
    except Exception:
        raise LocalDemoError("local demo operation failed") from None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the closed Tracebed local demo")
    parser.add_argument("command", choices=("start", "status", "stop"))
    args = parser.parse_args(argv)
    try:
        if args.command == "start":
            print(start())
        elif args.command == "status":
            origin, phase = status()
            print(f"{origin} ({phase})")
        else:
            stop()
    except LocalDemoError:
        print("local demo operation failed", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
