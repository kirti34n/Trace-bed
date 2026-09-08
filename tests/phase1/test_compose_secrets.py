"""Host-side Compose secret source validation is fail-closed before Docker."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from tracebed.compose_secrets import COMPOSE_SECRET_FILES, validate_compose_secret_source
from tracebed.domain.errors import ConfigError

pytestmark = pytest.mark.phase1


def _source(tmp_path: Path) -> dict[str, str]:
    directory = tmp_path / "secrets"
    directory.mkdir()
    directory.chmod(0o700)
    environment: dict[str, str] = {}
    for env_name, leaf_name in COMPOSE_SECRET_FILES.items():
        target = directory / leaf_name
        target.write_text("opaque-value\n", encoding="utf-8")
        target.chmod(0o444)
        environment[env_name] = str(target)
    return environment


def test_exact_private_source_is_accepted(tmp_path: Path) -> None:
    environment = _source(tmp_path)
    assert validate_compose_secret_source(environment) == Path(environment["TB_API_DB_PASSWORD_FILE"]).parent


@pytest.mark.parametrize("mode", (0o755, 0o770, 0o600))
def test_private_directory_requires_exact_owner_mode(tmp_path: Path, mode: int) -> None:
    environment = _source(tmp_path)
    directory = Path(environment["TB_API_DB_PASSWORD_FILE"]).parent
    directory.chmod(mode)
    try:
        with pytest.raises(ConfigError, match="invalid"):
            validate_compose_secret_source(environment)
    finally:
        # Pytest owns the parent cleanup; restore traversal permission after
        # proving the validator rejects every non-0700 source directory.
        directory.chmod(0o700)


def test_extra_leaf_and_unknown_selector_are_rejected(tmp_path: Path) -> None:
    environment = _source(tmp_path)
    directory = Path(environment["TB_API_DB_PASSWORD_FILE"]).parent
    extra = directory / "unexpected"
    extra.write_text("opaque\n", encoding="utf-8")
    extra.chmod(0o444)
    with pytest.raises(ConfigError, match="invalid"):
        validate_compose_secret_source(environment)
    extra.unlink()
    environment["TB_UNRELATED_FILE"] = str(directory / "unexpected")
    with pytest.raises(ConfigError, match="invalid"):
        validate_compose_secret_source(environment)


def test_symlink_and_hardlink_source_are_rejected(tmp_path: Path) -> None:
    environment = _source(tmp_path)
    directory = Path(environment["TB_API_DB_PASSWORD_FILE"]).parent
    target = directory / "api_db_password"
    replacement = directory / "replacement"
    replacement.write_text("opaque\n", encoding="utf-8")
    replacement.chmod(0o444)
    target.unlink()
    target.symlink_to(replacement)
    with pytest.raises(ConfigError, match="invalid"):
        validate_compose_secret_source(environment)

    target.unlink()
    os.link(replacement, target)
    # The replacement is a second hard link to the selected leaf.  It must
    # fail rather than becoming a silently accepted additional source object.
    with pytest.raises(ConfigError, match="invalid"):
        validate_compose_secret_source(environment)


def test_leaf_mode_and_name_are_exact(tmp_path: Path) -> None:
    environment = _source(tmp_path)
    directory = Path(environment["TB_API_DB_PASSWORD_FILE"]).parent
    (directory / "master_key").chmod(0o400)
    with pytest.raises(ConfigError, match="invalid"):
        validate_compose_secret_source(environment)
    (directory / "master_key").chmod(0o444)
    environment["TB_MASTER_KEY_FILE"] = str(directory / "wrong-name")
    with pytest.raises(ConfigError, match="invalid"):
        validate_compose_secret_source(environment)


def test_noncanonical_source_path_is_rejected_before_any_secret_open(tmp_path: Path) -> None:
    environment = _source(tmp_path)
    for env_name, value in tuple(environment.items()):
        exact = Path(value)
        environment[env_name] = str(exact.parent / ".." / exact.parent.name / exact.name)
    with pytest.raises(ConfigError, match="invalid"):
        validate_compose_secret_source(environment)
