"""Strict host-side validation for the closed Compose-v1 secret source.

Compose consumes host secret *files* before a container exists.  Validate the
complete source tree before issuing even ``docker compose config`` so a
symlink, replacement race, or inherited alternate credential cannot reach a
Docker API call or rendered configuration.
"""

from __future__ import annotations

import os
import stat
from collections.abc import Mapping
from pathlib import Path
from typing import Final

from tracebed.domain.errors import ConfigError

__all__ = ["COMPOSE_SECRET_FILES", "validate_compose_secret_source"]


COMPOSE_SECRET_FILES: Final[dict[str, str]] = {
    "TB_OWNER_DB_PASSWORD_FILE": "owner_db_password",
    "TB_APP_DB_PASSWORD_FILE": "app_db_password",
    "TB_API_DB_PASSWORD_FILE": "api_db_password",
    "TB_WORKER_DB_PASSWORD_FILE": "worker_db_password",
    "TB_ERASURE_DB_PASSWORD_FILE": "erasure_db_password",
    "TB_S3_SIGNING_KEY_FILE": "s3_signing_key",
    "TB_S3_INIT_ACCESS_KEY_FILE": "s3_init_access_key",
    "TB_S3_INIT_SECRET_KEY_FILE": "s3_init_secret_key",
    "TB_S3_RUNTIME_ACCESS_KEY_FILE": "s3_runtime_access_key",
    "TB_S3_RUNTIME_SECRET_KEY_FILE": "s3_runtime_secret_key",
    "TB_S3_ERASURE_ACCESS_KEY_FILE": "s3_erasure_access_key",
    "TB_S3_ERASURE_SECRET_KEY_FILE": "s3_erasure_secret_key",
    "TB_HOLDOUT_SALT_FILE": "holdout_salt",
    "TB_MASTER_KEY_FILE": "master_key",
    "TB_ADMIN_KEY_FILE": "admin_key",
    "TB_READYZ_TOKEN_FILE": "readyz_token",
}


def _invalid() -> ConfigError:
    """Keep host paths and secret contents out of diagnostics."""

    return ConfigError("Compose-v1 secret source is invalid")


def _lstat_path_components(path: Path) -> None:
    """Reject symlinks in every supplied absolute path component."""

    # A syntactically alternate ``..``/``.`` path would make the source
    # directory identity depend on filesystem resolution.  The controller
    # must authenticate one canonical, private directory before it reaches
    # Docker, so reject that ambiguity rather than normalising it silently.
    if not path.is_absolute() or any(component in {".", ".."} for component in path.parts):
        raise _invalid()
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        try:
            metadata = current.lstat()
        except OSError:
            raise _invalid() from None
        if stat.S_ISLNK(metadata.st_mode):
            raise _invalid()


def _validated_private_directory(paths: Mapping[str, Path]) -> Path:
    """Return the one exact 0700 owner directory containing every leaf."""

    directories = {path.parent for path in paths.values()}
    if len(directories) != 1:
        raise _invalid()
    directory = next(iter(directories))
    _lstat_path_components(directory)
    try:
        metadata = directory.lstat()
    except OSError:
        raise _invalid() from None
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o700
        or metadata.st_uid != os.geteuid()
        or metadata.st_gid != os.getegid()
    ):
        raise _invalid()
    return directory


def _validate_leaf(path: Path, *, expected_name: str, directory: Path) -> None:
    """Authenticate an exact regular 0444 leaf with no name/link race."""

    if path.parent != directory or path.name != expected_name:
        raise _invalid()
    _lstat_path_components(path)
    try:
        before = path.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or stat.S_ISLNK(before.st_mode)
            or stat.S_IMODE(before.st_mode) != 0o444
            or before.st_nlink != 1
            or before.st_uid != os.geteuid()
            or before.st_gid != os.getegid()
        ):
            raise OSError
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
    except OSError:
        raise _invalid() from None
    if (
        after.st_dev != before.st_dev
        or after.st_ino != before.st_ino
        or after.st_mode != before.st_mode
        or after.st_uid != before.st_uid
        or after.st_gid != before.st_gid
        or after.st_nlink != before.st_nlink
    ):
        raise _invalid()


def validate_compose_secret_source(environment: Mapping[str, str]) -> Path:
    """Validate the complete closed secret directory before Docker mutation.

    The environment must contain every fixed ``*_FILE`` selector, no unknown
    Tracebed file selector, and no extra leaf in the private directory.  The
    returned path is intentionally useful only for callers that need an
    opaque source identity; no secret values are ever read or returned.
    """

    supplied_file_names = {name for name in environment if name.startswith("TB_") and name.endswith("_FILE")}
    if supplied_file_names != set(COMPOSE_SECRET_FILES):
        raise _invalid()
    paths: dict[str, Path] = {}
    for env_name, leaf_name in COMPOSE_SECRET_FILES.items():
        value = environment.get(env_name)
        if not isinstance(value, str) or not value:
            raise _invalid()
        paths[env_name] = Path(value)
        if paths[env_name].name != leaf_name:
            raise _invalid()
    directory = _validated_private_directory(paths)
    try:
        actual_names = {entry.name for entry in directory.iterdir()}
    except OSError:
        raise _invalid() from None
    if actual_names != set(COMPOSE_SECRET_FILES.values()):
        raise _invalid()
    for env_name, leaf_name in COMPOSE_SECRET_FILES.items():
        _validate_leaf(paths[env_name], expected_name=leaf_name, directory=directory)
    return directory
