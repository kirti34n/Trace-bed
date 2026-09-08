"""Focused contract tests for the closed local-demo host launcher."""

from __future__ import annotations

import importlib.util
import json
import os
import stat
import subprocess
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace

import pytest


def _launcher() -> object:
    path = Path(__file__).parents[2] / "scripts" / "local_demo.py"
    spec = importlib.util.spec_from_file_location("tracebed_local_demo_launcher", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def demo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> object:
    module = _launcher()
    root = tmp_path / "checkout"
    root.mkdir()
    state_root = root / ".tracebed-demo"
    monkeypatch.setattr(module, "ROOT", root)
    monkeypatch.setattr(module, "STATE_ROOT", state_root)
    monkeypatch.setattr(module, "STATE_FILE", state_root / "state.json")
    monkeypatch.setattr(module, "SECRETS", state_root / "secrets")
    monkeypatch.setattr(module, "DEMO_SECRET", state_root / "demo-secret")
    monkeypatch.setattr(module, "BASE", root / "docker" / "compose.yaml")
    monkeypatch.setattr(module, "OVERLAY", root / "docker" / "compose.demo.yaml")
    return module


def test_create_state_has_exact_private_nonsecret_receipt_and_secret_tree(demo: object) -> None:
    state = demo._create_state()

    assert state["phase"] == "new"
    assert stat.S_IMODE(demo.STATE_ROOT.stat().st_mode) == 0o700
    assert stat.S_IMODE(demo.SECRETS.stat().st_mode) == 0o700
    assert stat.S_IMODE(demo.DEMO_SECRET.stat().st_mode) == 0o700
    assert stat.S_IMODE(demo.STATE_FILE.stat().st_mode) == 0o600
    assert {item.name for item in demo.SECRETS.iterdir()} == set(demo.SECRET_NAMES)
    assert {item.name for item in demo.DEMO_SECRET.iterdir()} == {"demo_api_key_secret"}
    assert all(stat.S_IMODE(item.stat().st_mode) == 0o444 for item in demo.SECRETS.iterdir())
    assert all(item.stat().st_nlink == 1 for item in demo.SECRETS.iterdir())
    assert "tb_sk_" not in demo.STATE_FILE.read_text(encoding="utf-8")
    assert "master_key" not in demo.STATE_FILE.read_text(encoding="utf-8")


def test_load_state_rejects_extra_secret_or_occupied_stopped_port(demo: object) -> None:
    state = demo._create_state()
    (demo.SECRETS / "unexpected").write_text("x", encoding="utf-8")
    with pytest.raises(demo.LocalDemoError):
        demo._load_state()
    (demo.SECRETS / "unexpected").unlink()
    state["phase"] = "stopped"
    demo._write_state(state)
    assert demo._port_available(state["api_port"])


def test_compose_is_project_scoped_and_only_overlay_receives_demo_selector(
    demo: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    state = demo._create_state()
    calls: list[tuple[list[str], dict[str, str]]] = []

    def run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append((command, kwargs["env"]))
        return subprocess.CompletedProcess(command, 0, stdout="[]", stderr="")

    monkeypatch.setattr(demo.subprocess, "run", run)
    demo._compose(state, "ps")
    demo._compose(state, "ps", overlay=True)
    base_command, base_env = calls[0]
    overlay_command, overlay_env = calls[1]
    assert base_command[:3] == ["docker", "compose", "--project-directory"]
    assert "--project-name" in base_command and state["project"] in base_command
    assert str(demo.OVERLAY) not in base_command
    assert str(demo.OVERLAY) in overlay_command
    assert "TB_DEMO_API_KEY_SECRET_FILE" not in base_env
    assert {key for key in base_env if key.startswith("TB_") and key.endswith("_FILE")} == set(
        demo.COMPOSE_SECRET_FILES
    )
    assert overlay_env["TB_DEMO_API_KEY_SECRET_FILE"].endswith("demo_api_key_secret")


def test_base_controller_environment_strips_all_inherited_tracebed_knobs(
    demo: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    state = demo._create_state()
    monkeypatch.setenv("TB_DEMO_API_KEY_SECRET_FILE", "not-a-secret-path")
    monkeypatch.setenv("TB_UNRELATED", "must-not-reach-base")
    monkeypatch.setenv("COMPOSE_PROFILES", "local-demo-provision")
    with demo._base_controller_environment(state):
        assert {
            key for key in os.environ if key.startswith("TB_") and key.endswith("_FILE")
        } == set(demo.COMPOSE_SECRET_FILES)
        assert "TB_UNRELATED" not in os.environ
        assert "COMPOSE_PROFILES" not in os.environ


def test_start_uses_controller_mode_by_persisted_phase_and_commits_active_only_after_topology(
    demo: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    state = demo._create_state()
    events: list[str] = []
    controller = SimpleNamespace(
        _controller_lifecycle_lock=lambda: nullcontext(),
        _start=lambda: events.append("start"),
        _upgrade=lambda: events.append("upgrade"),
    )
    monkeypatch.setattr(demo, "_validate_host", lambda: None)
    monkeypatch.setattr(demo, "_controller", lambda: controller)
    monkeypatch.setattr(demo, "_compose", lambda *_args, **_kwargs: events.append("compose"))
    monkeypatch.setattr(
        demo, "_assert_sustained_topology", lambda *_args: events.append("topology")
    )

    assert demo.start() == state["origin"]
    assert events[0] == "start"
    assert demo._load_state()["phase"] == "active"
    events.clear()
    assert demo.start() == state["origin"]
    assert events[0] == "upgrade"


def test_failed_overlay_is_retried_as_recovery_upgrade(
    demo: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    demo._create_state()
    events: list[str] = []
    controller = SimpleNamespace(
        _controller_lifecycle_lock=lambda: nullcontext(),
        _start=lambda: events.append("start"),
        _upgrade=lambda: events.append("upgrade"),
    )
    monkeypatch.setattr(demo, "_validate_host", lambda: None)
    monkeypatch.setattr(demo, "_controller", lambda: controller)
    monkeypatch.setattr(
        demo, "_assert_sustained_topology", lambda *_args: events.append("topology")
    )

    def failed_compose(_state: object, *arguments: str, **_kwargs: object) -> None:
        if arguments[-1] == "demo-provision":
            raise demo.LocalDemoError("failed")

    monkeypatch.setattr(demo, "_compose", failed_compose)
    with pytest.raises(demo.LocalDemoError):
        demo.start()
    assert demo._load_state()["phase"] == "recovering"

    monkeypatch.setattr(demo, "_compose", lambda *_args, **_kwargs: events.append("compose"))
    assert demo.start().startswith("http://127.0.0.1:")
    assert events.count("upgrade") == 1


def test_sustained_assertion_checks_compose_health_before_controller_network_attestation(
    demo: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    state = demo._create_state()
    events: list[str] = []
    rows = [
        {"Service": service, "State": "running", "Health": "healthy"}
        for service in sorted(demo.SUSTAINED_SERVICES)
    ]
    controller = SimpleNamespace(
        _validate_host_network_isolation=lambda project: events.append("network:" + project)
    )
    monkeypatch.setattr(
        demo,
        "_compose",
        lambda *_args, **_kwargs: (
            events.append("ps")
            or subprocess.CompletedProcess(["docker"], 0, stdout=json.dumps(rows), stderr="")
        ),
    )

    demo._assert_sustained_topology(state, controller)
    assert events == ["ps", "network:" + state["project"]]


def test_compose_ps_rows_accepts_array_single_object_and_json_lines(demo: object) -> None:
    row = {"Service": "api", "State": "running"}
    assert demo._compose_ps_rows(json.dumps([row])) == [row]
    assert demo._compose_ps_rows(json.dumps(row)) == [row]
    assert demo._compose_ps_rows(json.dumps(row) + "\n" + json.dumps(row)) == [row, row]


@pytest.mark.parametrize(
    "output", ["", "\n", "{not-json}", '{"Service":"api"}\n\n{"State":"running"}']
)
def test_compose_ps_rows_rejects_blank_or_malformed_output(demo: object, output: str) -> None:
    with pytest.raises(ValueError):
        demo._compose_ps_rows(output)


def test_sustained_topology_rejects_duplicate_compose_service(
    demo: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    state = demo._create_state()
    services = sorted(demo.SUSTAINED_SERVICES)
    rows = [
        {"Service": service, "State": "running", "Health": "healthy"}
        for service in (*services[:-1], services[0])
    ]
    monkeypatch.setattr(
        demo,
        "_compose",
        lambda *_args, **_kwargs: subprocess.CompletedProcess(
            ["docker"], 0, stdout=json.dumps(rows), stderr=""
        ),
    )
    with pytest.raises(demo.LocalDemoError):
        demo._assert_sustained_topology(
            state, SimpleNamespace(_validate_host_network_isolation=lambda _project: None)
        )


def test_host_prerequisite_refuses_non_linux(demo: object, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(demo.sys, "platform", "darwin")
    with pytest.raises(demo.LocalDemoError):
        demo._validate_host()


@pytest.mark.parametrize("version", ["v5.3.1", "2.27.0"])
def test_host_prerequisite_accepts_compose_short_major_two_or_newer(
    demo: object, monkeypatch: pytest.MonkeyPatch, version: str
) -> None:
    monkeypatch.setattr(demo.shutil, "which", lambda command: f"/usr/bin/{command}")
    monkeypatch.setattr(
        demo.subprocess,
        "run",
        lambda command, **_kwargs: subprocess.CompletedProcess(
            command, 0, stdout=version + "\n", stderr=""
        ),
    )
    demo._validate_host()


@pytest.mark.parametrize(
    "version", ["v1.29.2", "Docker Compose version v5.3.1", "v5", "v5.3.1\nextra"]
)
def test_host_prerequisite_rejects_old_or_malformed_compose_output(
    demo: object, monkeypatch: pytest.MonkeyPatch, version: str
) -> None:
    monkeypatch.setattr(demo.shutil, "which", lambda command: f"/usr/bin/{command}")
    monkeypatch.setattr(
        demo.subprocess,
        "run",
        lambda command, **_kwargs: subprocess.CompletedProcess(
            command, 0, stdout=version, stderr=""
        ),
    )
    with pytest.raises(demo.LocalDemoError):
        demo._validate_host()


def test_stop_fences_before_fixed_down_and_preserves_volumes(
    demo: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    state = demo._create_state()
    state["phase"] = "active"
    demo._write_state(state)
    events: list[str] = []
    controller = SimpleNamespace(
        _controller_lifecycle_lock=lambda: nullcontext(),
        _validate_rendered_configuration=lambda: events.append("validate"),
        _fence_and_drain_runtime=lambda: events.append("fence"),
    )
    monkeypatch.setattr(demo, "_controller", lambda: controller)
    monkeypatch.setattr(
        demo,
        "_compose",
        lambda _state, *arguments, **_kwargs: events.append(" ".join(arguments)),
    )

    demo.stop()
    assert events == ["validate", "fence", "down --remove-orphans"]
    assert "--volumes" not in events[-1]
    assert demo._load_state()["phase"] == "stopped"
    demo.stop()
    assert events == ["validate", "fence", "down --remove-orphans"]


def test_load_state_rejects_foreign_owned_files(
    demo: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    demo._create_state()
    current_uid = os.geteuid()
    monkeypatch.setattr(demo.os, "geteuid", lambda: current_uid + 1)
    with pytest.raises(demo.LocalDemoError):
        demo._load_state()


def test_main_never_echoes_secret_on_failure(
    demo: object, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(
        demo, "start", lambda: (_ for _ in ()).throw(demo.LocalDemoError("tb_sk_secret"))
    )
    assert demo.main(["start"]) == 1
    captured = capsys.readouterr()
    assert "tb_sk_" not in captured.out + captured.err
    assert captured.err == "local demo operation failed\n"
