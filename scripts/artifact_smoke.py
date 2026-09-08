#!/usr/bin/env python3
"""Smoke check a built Tracebed wheel in an isolated, dependency-complete env.

By default pip resolves the wheel's declared runtime dependencies through its
configured indexes/cache; this is intentionally *not* an offline claim. Pass
``--wheelhouse`` only when a complete local dependency wheelhouse is supplied;
that mode uses ``--no-index``. Both modes clear checkout import paths, install
the artifact into a temporary virtual environment, and prove imports resolve
to the installed wheel rather than the source tree.
"""

from __future__ import annotations

import argparse
import configparser
import hashlib
import os
import subprocess
import sys
import tarfile
import tempfile
import venv
import zipfile
from pathlib import Path

_MIGRATION_FILES = (
    "0001_registries.rollback.sql",
    "0001_registries.sql",
    "0002_partitioned.rollback.sql",
    "0002_partitioned.sql",
    "0003_rls.rollback.sql",
    "0003_rls.sql",
    "0004_lifecycle.rollback.sql",
    "0004_lifecycle.sql",
    "0005_bm25.rollback.sql",
    "0005_bm25.sql",
    "0006_q_update_ledger.rollback.sql",
    "0006_q_update_ledger.sql",
    "0007_project_provisioning.rollback.sql",
    "0007_project_provisioning.sql",
    "0008_trace_learning_job.rollback.sql",
    "0008_trace_learning_job.sql",
    "0009_trace_index_terminal_freeze.rollback.sql",
    "0009_trace_index_terminal_freeze.sql",
    "0010_authority_foundation.rollback.sql",
    "0010_authority_foundation.sql",
    "0011_authority_cutover.rollback.sql",
    "0011_authority_cutover.sql",
    "0012_erasure_saga.rollback.sql",
    "0012_erasure_saga.sql",
    "0013_erasure_deployment.rollback.sql",
    "0013_erasure_deployment.sql",
    "yoyo.ini",
)
_CONSOLE_ENTRIES = {
    "tracebed-api": "tracebed.api.main:run",
    "tracebed-edge": "tracebed.edge.main:run",
    "tracebed-local-demo-edge": "tracebed.edge.local_demo:run",
    "tracebed-local-demo-provision": "tracebed.local_demo_provision:owner_main",
    "tracebed-local-demo-seed": "tracebed.local_demo_provision:seed_main",
    "tracebed-db-bootstrap": "tracebed.stores.pg.bootstrap:main",
    "tracebed-s3-init": "tracebed.stores.tracestore.provision:main",
    "tracebed-worker": "tracebed.workers.runner:run",
    "tracebed-onboard-agent": "tracebed.stores.pg.onboarding:main",
    "tracebed-compose-api": "tracebed.compose_runtime:api_main",
    "tracebed-compose-api-ready": "tracebed.compose_runtime:api_ready_main",
    "tracebed-compose-api-health": "tracebed.compose_runtime:api_health_main",
    "tracebed-compose-api-prepublication-ready": "tracebed.compose_runtime:api_prepublication_ready_main",
    "tracebed-compose-bootstrap": "tracebed.compose_runtime:bootstrap_main",
    "tracebed-compose-s3-init": "tracebed.compose_runtime:s3_init_main",
    "tracebed-compose-worker": "tracebed.compose_runtime:worker_main",
    "tracebed-compose-worker-drain": "tracebed.compose_runtime:worker_drain_main",
    "tracebed-compose-worker-ready": "tracebed.compose_runtime:worker_ready_main",
    "tracebed-compose-worker-prepublication-ready": "tracebed.compose_runtime:worker_prepublication_ready_main",
    "tracebed-compose-erasure": "tracebed.compose_runtime:erasure_main",
    "tracebed-compose-erasure-once": "tracebed.compose_runtime:erasure_once_main",
    "tracebed-compose-erasure-resume": "tracebed.compose_runtime:erasure_resume_main",
    "tracebed-compose-erasure-ready": "tracebed.compose_runtime:erasure_ready_main",
    "tracebed-compose-erasure-prepublication-ready": "tracebed.compose_runtime:erasure_prepublication_ready_main",
    "tracebed-api-ready": "tracebed.runtime_ready:api_main",
    "tracebed-worker-ready": "tracebed.workers.ready:main",
    "tracebed-erasure-worker": "tracebed.erasure.runner:run",
    "tracebed-erasure-once": "tracebed.erasure.cli:once_main",
    "tracebed-erasure-status": "tracebed.erasure.cli:status_main",
    "tracebed-erasure-resume": "tracebed.erasure.cli:resume_main",
}
_LOCAL_DEMO_MANIFESTS = ("tracebed/_demo/validation-runs.json",)
_REPO_ROOT = Path(__file__).resolve().parents[1]
_AUTHORITY_ARTIFACT_SOURCES = {
    "tracebed/_migrations/0010_authority_foundation.rollback.sql": (
        _REPO_ROOT / "migrations/0010_authority_foundation.rollback.sql"
    ),
    "tracebed/_migrations/0010_authority_foundation.sql": (
        _REPO_ROOT / "migrations/0010_authority_foundation.sql"
    ),
    "tracebed/_migrations/0011_authority_cutover.rollback.sql": (
        _REPO_ROOT / "migrations/0011_authority_cutover.rollback.sql"
    ),
    "tracebed/_migrations/0011_authority_cutover.sql": (
        _REPO_ROOT / "migrations/0011_authority_cutover.sql"
    ),
    "tracebed/_migrations/0012_erasure_saga.rollback.sql": (
        _REPO_ROOT / "migrations/0012_erasure_saga.rollback.sql"
    ),
    "tracebed/_migrations/0012_erasure_saga.sql": (_REPO_ROOT / "migrations/0012_erasure_saga.sql"),
    "tracebed/_migrations/0013_erasure_deployment.rollback.sql": (
        _REPO_ROOT / "migrations/0013_erasure_deployment.rollback.sql"
    ),
    "tracebed/_migrations/0013_erasure_deployment.sql": (
        _REPO_ROOT / "migrations/0013_erasure_deployment.sql"
    ),
    "tracebed/stores/pg/bootstrap.py": _REPO_ROOT / "src/tracebed/stores/pg/bootstrap.py",
    # B3 runtime-boundary code is just as release-critical as the cutover SQL:
    # the installed API/worker must reject ambiguous ambient credentials before
    # any pool is constructed.  Keep this deliberately explicit rather than
    # globbing ``src`` so an inventory addition is a conscious release review.
    "tracebed/stores/pg/authority_dsn.py": _REPO_ROOT / "src/tracebed/stores/pg/authority_dsn.py",
    "tracebed/stores/pg/runtime_identity.py": _REPO_ROOT
    / "src/tracebed/stores/pg/runtime_identity.py",
    "tracebed/stores/pg/pool.py": _REPO_ROOT / "src/tracebed/stores/pg/pool.py",
    "tracebed/stores/pg/activity.py": _REPO_ROOT / "src/tracebed/stores/pg/activity.py",
    "tracebed/stores/pg/hba.py": _REPO_ROOT / "src/tracebed/stores/pg/hba.py",
    # E1's strict archive parser and digest primitive are security contract
    # assets: an installed wheel must not fall back to a stale v1-only
    # decoder or a differently framed subject hash.
    "tracebed/crypto/subject_digest.py": _REPO_ROOT / "src/tracebed/crypto/subject_digest.py",
    "tracebed/crypto/envelope.py": _REPO_ROOT / "src/tracebed/crypto/envelope.py",
    "tracebed/crypto/shred.py": _REPO_ROOT / "src/tracebed/crypto/shred.py",
    "tracebed/ingest/trace_archive.py": _REPO_ROOT / "src/tracebed/ingest/trace_archive.py",
    "tracebed/stores/pg/trace_learning.py": _REPO_ROOT / "src/tracebed/stores/pg/trace_learning.py",
    "tracebed/stores/pg/repo.py": _REPO_ROOT / "src/tracebed/stores/pg/repo.py",
    "tracebed/stores/pg/rows.py": _REPO_ROOT / "src/tracebed/stores/pg/rows.py",
    "tracebed/api/main.py": _REPO_ROOT / "src/tracebed/api/main.py",
    "tracebed/workers/runner.py": _REPO_ROOT / "src/tracebed/workers/runner.py",
    "tracebed/workers/ready.py": _REPO_ROOT / "src/tracebed/workers/ready.py",
    "tracebed/domain/config.py": _REPO_ROOT / "src/tracebed/domain/config.py",
    "tracebed/compose_runtime.py": _REPO_ROOT / "src/tracebed/compose_runtime.py",
    "tracebed/runtime_ready.py": _REPO_ROOT / "src/tracebed/runtime_ready.py",
    "tracebed/stores/tracestore/s3.py": _REPO_ROOT / "src/tracebed/stores/tracestore/s3.py",
    "tracebed/stores/tracestore/provision.py": _REPO_ROOT
    / "src/tracebed/stores/tracestore/provision.py",
    # E3 stays deliberately outside the ordinary worker/import graph.  Pin
    # its standalone entrypoints and destructive-only adapters so a built
    # artifact cannot silently ship a stale coordinator or timeout policy.
    "tracebed/domain/errors.py": _REPO_ROOT / "src/tracebed/domain/errors.py",
    # Request admission and its neutral budget protocol jointly enforce the
    # installed API's bounded outstanding-work contract.  They are explicit
    # assets so an artifact cannot silently omit a newer source copy.
    "tracebed/domain/deadline.py": _REPO_ROOT / "src/tracebed/domain/deadline.py",
    "tracebed/api/retrieval_admission.py": _REPO_ROOT / "src/tracebed/api/retrieval_admission.py",
    "tracebed/api/deps.py": _REPO_ROOT / "src/tracebed/api/deps.py",
    "tracebed/api/routes_v1.py": _REPO_ROOT / "src/tracebed/api/routes_v1.py",
    "tracebed/erasure/__init__.py": _REPO_ROOT / "src/tracebed/erasure/__init__.py",
    "tracebed/erasure/cli.py": _REPO_ROOT / "src/tracebed/erasure/cli.py",
    "tracebed/erasure/domain.py": _REPO_ROOT / "src/tracebed/erasure/domain.py",
    "tracebed/erasure/executor.py": _REPO_ROOT / "src/tracebed/erasure/executor.py",
    "tracebed/erasure/fixed_stores.py": _REPO_ROOT / "src/tracebed/erasure/fixed_stores.py",
    "tracebed/erasure/ports.py": _REPO_ROOT / "src/tracebed/erasure/ports.py",
    "tracebed/erasure/runner.py": _REPO_ROOT / "src/tracebed/erasure/runner.py",
    "tracebed/erasure/composition.py": _REPO_ROOT / "src/tracebed/erasure/composition.py",
    "tracebed/erasure/readiness.py": _REPO_ROOT / "src/tracebed/erasure/readiness.py",
    "tracebed/stores/pg/erasure_executor.py": _REPO_ROOT
    / "src/tracebed/stores/pg/erasure_executor.py",
    "tracebed/stores/pg/erasure.py": _REPO_ROOT / "src/tracebed/stores/pg/erasure.py",
    "tracebed/stores/tracestore/erasure.py": _REPO_ROOT
    / "src/tracebed/stores/tracestore/erasure.py",
    "tracebed/stores/tracestore/s3_erasure.py": _REPO_ROOT
    / "src/tracebed/stores/tracestore/s3_erasure.py",
    "tracebed/stores/valkey/erasure.py": _REPO_ROOT / "src/tracebed/stores/valkey/erasure.py",
    "tracebed/stores/vector/erasure.py": _REPO_ROOT / "src/tracebed/stores/vector/erasure.py",
    "tracebed/stores/graph/erasure.py": _REPO_ROOT / "src/tracebed/stores/graph/erasure.py",
}


def _python_in(venv_dir: Path) -> Path:
    return venv_dir / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")


def _console_in(venv_dir: Path, command: str) -> Path:
    """Return one installed console wrapper without assuming a source checkout."""
    executable = f"Scripts/{command}.exe" if sys.platform == "win32" else f"bin/{command}"
    return venv_dir / executable


def _clean_environment() -> dict[str, str]:
    """Remove checkout-oriented imports before invoking the artifact interpreter."""
    environment = os.environ.copy()
    for name in ("PYTHONPATH", "PYTHONHOME", "VIRTUAL_ENV"):
        environment.pop(name, None)
    environment["PIP_DISABLE_PIP_VERSION_CHECK"] = "1"
    environment["PIP_NO_INPUT"] = "1"
    return environment


def _authority_artifact_hashes() -> dict[str, str]:
    """Pin release-critical authority and runtime sources to checkout bytes."""

    return {
        artifact_path: hashlib.sha256(source_path.read_bytes()).hexdigest()
        for artifact_path, source_path in _AUTHORITY_ARTIFACT_SOURCES.items()
    }


def _assert_wheel_layout(wheel: Path, *, authority_hashes: dict[str, str] | None = None) -> None:
    with zipfile.ZipFile(wheel) as archive:
        names = archive.namelist()
        name_set = set(names)
        missing = [
            f"tracebed/_migrations/{name}"
            for name in _MIGRATION_FILES
            if f"tracebed/_migrations/{name}" not in name_set
        ]
        if missing:
            raise RuntimeError(f"wheel omits packaged migration assets: {', '.join(missing)}")
        if any(path not in name_set for path in _LOCAL_DEMO_MANIFESTS):
            raise RuntimeError("wheel omits packaged local demo manifest")
        entry_points = [name for name in names if name.endswith(".dist-info/entry_points.txt")]
        if len(entry_points) != 1:
            raise RuntimeError("wheel must contain exactly one dist-info entry_points.txt")
        parser = configparser.ConfigParser()
        parser.read_string(archive.read(entry_points[0]).decode("utf-8"))
        for command, target in _CONSOLE_ENTRIES.items():
            if parser.get("console_scripts", command, fallback="") != target:
                raise RuntimeError(f"wheel console entry must be {command + ' = ' + target!r}")
        if authority_hashes is not None:
            for artifact_path, expected_hash in authority_hashes.items():
                occurrences = names.count(artifact_path)
                if occurrences != 1:
                    raise RuntimeError(
                        "wheel authority artifact must have exactly one entry: " + artifact_path
                    )
                try:
                    observed = hashlib.sha256(archive.read(artifact_path)).hexdigest()
                except KeyError as exc:
                    raise RuntimeError(f"wheel omits authority artifact: {artifact_path}") from exc
                if observed != expected_hash:
                    raise RuntimeError(f"wheel authority artifact hash mismatch: {artifact_path}")


def _sdist_relative_path(wheel_path: str) -> str:
    """Map one wheel package path to its exact source-distribution location."""

    if wheel_path.startswith("tracebed/_migrations/"):
        return "migrations/" + Path(wheel_path).name
    return "src/" + wheel_path


def _assert_sdist_layout(sdist: Path, *, authority_hashes: dict[str, str]) -> None:
    """Require an exact one-entry, byte-identical source inventory in the sdist."""

    with tarfile.open(sdist, "r:gz") as archive:
        members = tuple(member for member in archive.getmembers() if member.isfile())
        names = tuple(member.name for member in members)
        source_roots: set[str] = set()
        for wheel_path, expected_hash in authority_hashes.items():
            relative_path = _sdist_relative_path(wheel_path)
            matches = [name for name in names if name.endswith("/" + relative_path)]
            if len(matches) != 1:
                raise RuntimeError(
                    "sdist authority artifact must have exactly one entry: " + relative_path
                )
            source_root, separator, observed_relative_path = matches[0].partition("/")
            if (
                not separator
                or not source_root
                or "/" in source_root
                or observed_relative_path != relative_path
            ):
                raise RuntimeError("sdist authority artifact path is not exact: " + relative_path)
            source_roots.add(source_root)
            member = archive.extractfile(matches[0])
            if member is None:  # pragma: no cover - tarfile reported a file but cannot read it
                raise RuntimeError(f"sdist omits authority artifact: {relative_path}")
            observed = hashlib.sha256(member.read()).hexdigest()
            if observed != expected_hash:
                raise RuntimeError(f"sdist authority artifact hash mismatch: {relative_path}")
        if len(source_roots) != 1:
            raise RuntimeError("sdist authority artifacts must share one source root")


def _migration_probe(*, expected_origin: str, zipped: bool) -> str:
    """Return a self-contained artifact-interpreter probe.

    yoyo loads both a migration's forward SQL and its companion rollback SQL
    lazily. Reading every resource and then calling ``read_all_migrations``
    verifies the migration context remains usable through that lazy load.
    """
    origin_setup = (
        "wheel = Path(sys.argv[1]).resolve()\nsys.path.insert(0, str(wheel))\n" if zipped else ""
    )
    expected_origin_literal = repr(expected_origin)
    return f"""
import sys
from pathlib import Path

{origin_setup}import tracebed
module_path = str(Path(tracebed.__file__).resolve())
expected_origin = {expected_origin_literal}
if expected_origin not in module_path:
    raise SystemExit(f"tracebed imported from {{module_path}}, expected {{expected_origin}}")

from tracebed.api.main import create_app_from_env
from tracebed.compose_runtime import api_main as compose_api_main
from tracebed.compose_runtime import api_health_main as compose_api_health_main
from tracebed.compose_runtime import api_prepublication_ready_main as compose_api_prepublication_ready_main
from tracebed.compose_runtime import api_ready_main as compose_api_ready_main
from tracebed.compose_runtime import bootstrap_main as compose_bootstrap_main
from tracebed.compose_runtime import erasure_main as compose_erasure_main
from tracebed.compose_runtime import erasure_once_main as compose_erasure_once_main
from tracebed.compose_runtime import erasure_prepublication_ready_main as compose_erasure_prepublication_ready_main
from tracebed.compose_runtime import erasure_ready_main as compose_erasure_ready_main
from tracebed.compose_runtime import erasure_resume_main as compose_erasure_resume_main
from tracebed.compose_runtime import s3_init_main as compose_s3_init_main
from tracebed.compose_runtime import worker_main as compose_worker_main
from tracebed.compose_runtime import worker_drain_main as compose_worker_drain_main
from tracebed.compose_runtime import worker_prepublication_ready_main as compose_worker_prepublication_ready_main
from tracebed.compose_runtime import worker_ready_main as compose_worker_ready_main
from tracebed.erasure.cli import once_main as erasure_once_main
from tracebed.erasure.cli import resume_main as erasure_resume_main
from tracebed.erasure.cli import status_main as erasure_status_main
from tracebed.erasure.runner import run as erasure_worker_run
from tracebed.erasure.readiness import probe_erasure_readiness
from tracebed.runtime_ready import api_main as api_ready_main
from tracebed.stores.pg.bootstrap import main as bootstrap_main
from tracebed.stores.pg.hba import attest_compose_v1_hba
from tracebed.stores.pg.migrate import migration_directory, read_all_migrations
from tracebed.stores.pg.runtime_identity import probe_runtime_readiness
from tracebed.stores.tracestore.provision import main as s3_init_main
from tracebed.workers.ready import main as worker_ready_main
from tracebed.workers.runner import run as worker_run

if not all(
    callable(entry)
    for entry in (
        create_app_from_env,
        bootstrap_main,
        probe_runtime_readiness,
        s3_init_main,
        worker_run,
        compose_api_main,
        compose_api_health_main,
        compose_api_prepublication_ready_main,
        compose_api_ready_main,
        compose_bootstrap_main,
        compose_erasure_main,
        compose_erasure_once_main,
        compose_erasure_prepublication_ready_main,
        compose_erasure_ready_main,
        compose_erasure_resume_main,
        compose_s3_init_main,
        compose_worker_main,
        compose_worker_drain_main,
        compose_worker_prepublication_ready_main,
        compose_worker_ready_main,
        api_ready_main,
        worker_ready_main,
        erasure_worker_run,
        erasure_once_main,
        erasure_status_main,
        erasure_resume_main,
        probe_erasure_readiness,
        attest_compose_v1_hba,
    )
):
    raise SystemExit("an installed console-entry module did not import its callable")

app = create_app_from_env()
if app.state.deps is not None:
    raise SystemExit("lazy app factory constructed runtime dependencies")

with migration_directory() as directory:
    expected = {list(_MIGRATION_FILES)!r}
    missing = [name for name in expected if not directory.joinpath(name).is_file()]
    if missing:
        raise SystemExit("missing packaged migrations: " + ", ".join(missing))
    for name in expected:
        directory.joinpath(name).read_text(encoding="utf-8")

migrations = read_all_migrations()
if not migrations or not all(migration.loaded and migration.steps for migration in migrations):
    raise SystemExit("yoyo did not eagerly load every migration")
for migration in migrations:
    if not any(getattr(step.step, "_rollback", None) for step in migration.steps):
        raise SystemExit(f"migration {{migration.id}} has no loaded rollback SQL")
"""


def _runtime_environment_probe() -> str:
    """Return an installed-artifact probe for every fail-closed env family."""

    return """
import os

from tracebed.api.main import create_app_from_env
from tracebed.stores.pg import authority_dsn
from tracebed.stores.pg.authority_dsn import RuntimeDsnError, runtime_dsn_from_environment
from tracebed.workers.runner import _load_worker_runtime_configuration

credentials = {
    "tracebed_api": ("TB_API_DB_DSN", "postgresql://tracebed_api:api-smoke@db.example/tracebed"),
    "tracebed_worker": (
        "TB_WORKER_DB_DSN",
        "postgresql://tracebed_worker:worker-smoke@db.example/tracebed",
    ),
    "tracebed_erasure": (
        "TB_ERASURE_DB_DSN",
        "postgresql://tracebed_erasure:erasure-smoke@db.example/tracebed",
    ),
}

def rejected(role, environment):
    original_parser = authority_dsn.conninfo_to_dict
    parser_calls = []
    def parser_must_not_run(value):
        parser_calls.append(value)
        raise AssertionError("rejected ambient environment reached libpq")
    authority_dsn.conninfo_to_dict = parser_must_not_run
    try:
        try:
            runtime_dsn_from_environment(role, environment)
        except RuntimeDsnError:
            pass
        else:
            raise SystemExit("unsafe runtime environment was accepted")
    finally:
        authority_dsn.conninfo_to_dict = original_parser
    if parser_calls:
        raise SystemExit("unsafe runtime environment reached libpq")

for role, (own_key, own_dsn) in credentials.items():
    other = [(key, dsn) for candidate, (key, dsn) in credentials.items() if candidate != role]
    rejected(role, {})
    for other_key, other_dsn in other:
        rejected(role, {other_key: other_dsn})
        rejected(role, {own_key: own_dsn, other_key: other_dsn})
    rejected(role, {own_key.lower(): own_dsn})
    rejected(role, {own_key: own_dsn, own_key.lower(): own_dsn})
    for name in authority_dsn._RUNTIME_FORBIDDEN_ENV:
        rejected(role, {own_key: own_dsn, name: "ambient-secret"})
        rejected(role, {own_key: own_dsn, name.lower(): "ambient-secret"})
    for name in (
        "PGHOST",
        "PGSERVICEFILE",
        "PGSYSCONFDIR",
        "PG_FUTURE_LIBPQ_INPUT",
        "pghost",
        "Pg_Future_Libpq_Input",
    ):
        rejected(role, {own_key: own_dsn, name: "ambient-secret"})

api_key, api_dsn = credentials["tracebed_api"]
os.environ.clear()
os.environ.update({api_key: api_dsn, "TB_EMBEDDING__MODEL_VERSION": "smoke-pin"})
app = create_app_from_env()
if app.state.runtime_dsn.role != "tracebed_api":
    raise SystemExit("installed API factory did not load the API credential")

worker_key, worker_dsn = credentials["tracebed_worker"]
os.environ.clear()
os.environ.update({worker_key: worker_dsn, "TB_EMBEDDING__MODEL_VERSION": "smoke-pin"})
worker_runtime_dsn, worker_settings = _load_worker_runtime_configuration()
if worker_runtime_dsn.role != "tracebed_worker" or worker_settings.storage.pg_dsn is not None:
    raise SystemExit("installed worker runtime boundary did not load the worker credential")
"""


def _run_probe(
    python: Path,
    probe: str,
    *,
    environment: dict[str, str],
    cwd: Path,
    wheel: Path | None = None,
) -> None:
    command = [str(python), "-c", probe]
    if wheel is not None:
        command.append(str(wheel))
    subprocess.run(  # noqa: S603 -- fixed venv interpreter and artifact-only probe
        command,
        check=True,
        cwd=cwd,
        env=environment,
    )


def _runtime_probe_environment(environment: dict[str, str]) -> dict[str, str]:
    """Strip inherited DB/libpq controls for the intentional exclusive probe."""

    forbidden = {
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
    return {
        name: value
        for name, value in environment.items()
        if not (name.casefold() in forbidden or name.casefold().startswith("pg"))
    }


def _install_and_probe_artifact(
    artifact: Path,
    *,
    wheelhouse: Path | None,
    zipped_wheel: Path | None = None,
) -> None:
    """Install one wheel or sdist in isolation and exercise runtime boundaries."""

    with tempfile.TemporaryDirectory(prefix="tracebed-artifact-smoke-") as temporary:
        temporary_dir = Path(temporary)
        venv_dir = temporary_dir / "venv"
        venv.EnvBuilder(with_pip=True, clear=True).create(venv_dir)
        python = _python_in(venv_dir)
        environment = _clean_environment()

        install_command = [
            str(python),
            "-m",
            "pip",
            "install",
            "--disable-pip-version-check",
        ]
        if wheelhouse is not None:
            install_command.extend(["--no-index", "--find-links", str(wheelhouse)])
        install_command.append(str(artifact))
        subprocess.run(  # noqa: S603 -- explicit artifact and optional user-provided wheelhouse
            install_command,
            check=True,
            cwd=temporary_dir,
            env=environment,
        )

        probe_environment = _runtime_probe_environment(environment) | {
            "TB_API_DB_DSN": "postgresql://tracebed_api:smoke@invalid/tracebed",
            "TB_EMBEDDING__MODEL_VERSION": "smoke-pin",
        }
        _run_probe(
            python,
            _migration_probe(expected_origin=str(venv_dir.resolve()), zipped=False),
            environment=probe_environment,
            cwd=temporary_dir,
        )
        _run_probe(
            python, _runtime_environment_probe(), environment=probe_environment, cwd=temporary_dir
        )
        if zipped_wheel is not None:
            _run_probe(
                python,
                _migration_probe(expected_origin=str(zipped_wheel), zipped=True),
                environment=probe_environment,
                cwd=temporary_dir,
                wheel=zipped_wheel,
            )
        missing_commands = [
            command for command in _CONSOLE_ENTRIES if not _console_in(venv_dir, command).is_file()
        ]
        if missing_commands:
            raise RuntimeError(
                "wheel installation did not create console command(s): "
                + ", ".join(missing_commands)
            )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="verify built Tracebed wheel and sdist artifacts")
    parser.add_argument("wheel", type=Path, help="path to a tracebed wheel")
    parser.add_argument("sdist", type=Path, help="path to a tracebed source distribution")
    parser.add_argument(
        "--wheelhouse",
        type=Path,
        help="complete local dependency wheelhouse; enables pip --no-index for an offline run",
    )
    args = parser.parse_args(argv)
    wheel = args.wheel.resolve()
    if not wheel.is_file() or wheel.suffix != ".whl":
        parser.error(f"not a wheel file: {wheel}")
    sdist = args.sdist.resolve()
    if not sdist.is_file() or not sdist.name.endswith(".tar.gz"):
        parser.error(f"not a source distribution: {sdist}")
    if args.wheelhouse is not None and not args.wheelhouse.is_dir():
        parser.error(f"not a wheelhouse directory: {args.wheelhouse}")
    # `_install_and_probe` deliberately changes cwd to a temporary directory
    # before invoking pip. Resolve here so a caller's relative wheelhouse is
    # still the requested directory rather than a path under that temp dir.
    wheelhouse = args.wheelhouse.resolve() if args.wheelhouse is not None else None

    authority_hashes = _authority_artifact_hashes()
    _assert_wheel_layout(wheel, authority_hashes=authority_hashes)
    _assert_sdist_layout(sdist, authority_hashes=authority_hashes)
    _install_and_probe_artifact(wheel, wheelhouse=wheelhouse, zipped_wheel=wheel)
    _install_and_probe_artifact(sdist, wheelhouse=wheelhouse)
    print(f"artifact smoke passed: {wheel.name}, {sdist.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
