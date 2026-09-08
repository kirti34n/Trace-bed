"""Regression checks for the wheel-artifact smoke command."""

from __future__ import annotations

import importlib.util
import io
import tarfile
import tomllib
import zipfile
from pathlib import Path
from types import ModuleType

import pytest

pytestmark = pytest.mark.phase1
_REPO_ROOT = Path(__file__).resolve().parents[2]
_SCRIPT = _REPO_ROOT / "scripts" / "artifact_smoke.py"


def _load_smoke_module() -> ModuleType:
    spec = importlib.util.spec_from_file_location("artifact_smoke", _SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _write_wheel_layout(smoke: ModuleType, wheel: Path, console_entries: dict[str, str]) -> None:
    with zipfile.ZipFile(wheel, "w") as archive:
        for migration in smoke._MIGRATION_FILES:  # type: ignore[attr-defined]
            archive.writestr(f"tracebed/_migrations/{migration}", "-- test migration\n")
        for path in smoke._LOCAL_DEMO_MANIFESTS:  # type: ignore[attr-defined]
            archive.writestr(path, "{}")
        entry_points = "[console_scripts]\n" + "".join(
            f"{command} = {target}\n" for command, target in console_entries.items()
        )
        archive.writestr("tracebed-0.1.0.dist-info/entry_points.txt", entry_points)


def test_relative_wheelhouse_is_resolved_before_the_isolated_cwd(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    smoke = _load_smoke_module()
    wheel = tmp_path / "tracebed-test.whl"
    wheel.touch()
    sdist = tmp_path / "tracebed-test.tar.gz"
    sdist.touch()
    wheelhouse = tmp_path / "wheelhouse"
    wheelhouse.mkdir()
    captured: list[tuple[Path, Path | None, Path | None]] = []

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(smoke, "_assert_wheel_layout", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(smoke, "_assert_sdist_layout", lambda *_args, **_kwargs: None)

    def capture_install(
        artifact: Path, *, wheelhouse: Path | None, zipped_wheel: Path | None = None
    ) -> None:
        captured.append((artifact, wheelhouse, zipped_wheel))

    monkeypatch.setattr(smoke, "_install_and_probe_artifact", capture_install)

    assert smoke.main([wheel.name, sdist.name, "--wheelhouse", wheelhouse.name]) == 0
    assert captured == [
        (wheel.resolve(), wheelhouse.resolve(), wheel.resolve()),
        (sdist.resolve(), wheelhouse.resolve(), None),
    ]


def test_wheel_metadata_requires_every_runtime_console_entry(tmp_path: Path) -> None:
    smoke = _load_smoke_module()
    expected = dict(smoke._CONSOLE_ENTRIES)  # type: ignore[attr-defined]
    complete_wheel = tmp_path / "complete.whl"
    _write_wheel_layout(smoke, complete_wheel, expected)
    smoke._assert_wheel_layout(complete_wheel)  # type: ignore[attr-defined]

    missing_bootstrap = dict(expected)
    del missing_bootstrap["tracebed-db-bootstrap"]
    incomplete_wheel = tmp_path / "missing-bootstrap.whl"
    _write_wheel_layout(smoke, incomplete_wheel, missing_bootstrap)

    with pytest.raises(RuntimeError, match="tracebed-db-bootstrap"):
        smoke._assert_wheel_layout(incomplete_wheel)  # type: ignore[attr-defined]


def test_local_demo_wheel_asset_has_a_matching_container_build_input() -> None:
    dockerfile = (_REPO_ROOT / "docker" / "api.Dockerfile").read_text(encoding="utf-8")
    pyproject = (_REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert "COPY demo ./demo" in dockerfile
    assert '"demo" = "tracebed/_demo"' in pyproject


def test_controller_only_console_entry_inventory_covers_all_e4_wrappers() -> None:
    """Acceptance invokes these installed wrappers, not checkout modules."""

    smoke = _load_smoke_module()
    required = {
        "tracebed-compose-worker-drain": "tracebed.compose_runtime:worker_drain_main",
        "tracebed-compose-erasure-once": "tracebed.compose_runtime:erasure_once_main",
        "tracebed-compose-erasure-resume": "tracebed.compose_runtime:erasure_resume_main",
    }
    project_scripts = tomllib.loads((_REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))[
        "project"
    ]["scripts"]
    assert {name: project_scripts[name] for name in required} == required
    assert {name: smoke._CONSOLE_ENTRIES[name] for name in required} == required  # type: ignore[attr-defined]

    probe = smoke._migration_probe(expected_origin="/artifact", zipped=False)  # type: ignore[attr-defined]
    for target in required.values():
        assert target.rsplit(":", 1)[1] in probe


def _write_release_critical_wheel(smoke: ModuleType, wheel: Path) -> None:
    with zipfile.ZipFile(wheel, "w") as archive:
        for path in smoke._LOCAL_DEMO_MANIFESTS:  # type: ignore[attr-defined]
            archive.writestr(path, "{}")
        source_inventory = smoke._AUTHORITY_ARTIFACT_SOURCES  # type: ignore[attr-defined]
        for artifact_path, source_path in source_inventory.items():
            archive.writestr(artifact_path, source_path.read_bytes())
        for migration in smoke._MIGRATION_FILES:  # type: ignore[attr-defined]
            artifact_path = f"tracebed/_migrations/{migration}"
            if artifact_path not in source_inventory:
                archive.writestr(artifact_path, "-- test migration\n")
        archive.writestr(
            "tracebed-0.1.0.dist-info/entry_points.txt",
            "[console_scripts]\n"
            + "".join(
                f"{command} = {target}\n"
                for command, target in smoke._CONSOLE_ENTRIES.items()  # type: ignore[attr-defined]
            ),
        )


def _write_release_critical_sdist(smoke: ModuleType, sdist: Path) -> None:
    with tarfile.open(sdist, "w:gz") as archive:
        for wheel_path, source_path in smoke._AUTHORITY_ARTIFACT_SOURCES.items():  # type: ignore[attr-defined]
            payload = source_path.read_bytes()
            relative_path = smoke._sdist_relative_path(wheel_path)  # type: ignore[attr-defined]
            member = tarfile.TarInfo(f"tracebed-test/{relative_path}")
            member.size = len(payload)
            archive.addfile(member, io.BytesIO(payload))


def test_release_critical_inventory_covers_b3_and_b4_runtime_boundaries(tmp_path: Path) -> None:
    smoke = _load_smoke_module()
    expected_paths = {
        "tracebed/stores/pg/authority_dsn.py",
        "tracebed/stores/pg/runtime_identity.py",
        "tracebed/stores/pg/pool.py",
        "tracebed/stores/pg/activity.py",
        "tracebed/stores/pg/hba.py",
        "tracebed/api/main.py",
        "tracebed/workers/runner.py",
        "tracebed/workers/ready.py",
        "tracebed/domain/config.py",
        "tracebed/compose_runtime.py",
        "tracebed/runtime_ready.py",
        "tracebed/stores/tracestore/s3.py",
        "tracebed/erasure/executor.py",
        "tracebed/erasure/runner.py",
        "tracebed/stores/pg/erasure_executor.py",
        "tracebed/stores/tracestore/erasure.py",
        "tracebed/stores/tracestore/s3_erasure.py",
        "tracebed/stores/valkey/erasure.py",
        "tracebed/domain/deadline.py",
        "tracebed/api/retrieval_admission.py",
    }
    source_inventory = smoke._AUTHORITY_ARTIFACT_SOURCES  # type: ignore[attr-defined]
    assert expected_paths <= set(source_inventory)

    hashes = smoke._authority_artifact_hashes()  # type: ignore[attr-defined]
    wheel = tmp_path / "critical.whl"
    _write_release_critical_wheel(smoke, wheel)
    smoke._assert_wheel_layout(wheel, authority_hashes=hashes)  # type: ignore[attr-defined]

    sdist = tmp_path / "critical.tar.gz"
    _write_release_critical_sdist(smoke, sdist)
    smoke._assert_sdist_layout(sdist, authority_hashes=hashes)  # type: ignore[attr-defined]


def test_release_critical_inventory_rejects_duplicate_wheel_source_entry(tmp_path: Path) -> None:
    smoke = _load_smoke_module()
    hashes = smoke._authority_artifact_hashes()  # type: ignore[attr-defined]
    wheel = tmp_path / "duplicate.whl"
    _write_release_critical_wheel(smoke, wheel)
    with pytest.warns(UserWarning, match="Duplicate name"), zipfile.ZipFile(wheel, "a") as archive:
        archive.writestr("tracebed/stores/pg/authority_dsn.py", b"stale duplicate")

    with pytest.raises(RuntimeError, match="exactly one entry"):
        smoke._assert_wheel_layout(wheel, authority_hashes=hashes)  # type: ignore[attr-defined]
