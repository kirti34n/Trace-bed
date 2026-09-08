#!/usr/bin/env python3
"""Create and verify a deterministic, hash-bound release manifest.

This script deliberately has no network or publication capability.  A release
workflow uses it to bind a version/tag to the exact files built once in that
workflow, and a later protected human gate verifies those same bytes again.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import tomllib
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
_VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[a-z]+[0-9]+)?(?:\.post[0-9]+)?$")
_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


def _error(message: str) -> ValueError:
    return ValueError(f"release manifest: {message}")


def _relative(path: Path, *, root: Path = ROOT) -> str:
    resolved = path.resolve()
    try:
        return resolved.relative_to(root.resolve()).as_posix()
    except ValueError as exc:
        raise _error(f"artifact is outside the repository: {path}") from exc


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def release_version(*, root: Path = ROOT) -> str:
    with (root / "pyproject.toml").open("rb") as handle:
        project = tomllib.load(handle)["project"]
    version = project.get("version")
    if not isinstance(version, str) or not _VERSION.fullmatch(version):
        raise _error("pyproject.toml project.version must be a normalized release version")
    return version


def dashboard_version(*, root: Path = ROOT) -> str:
    raw = json.loads((root / "dashboard" / "package.json").read_text(encoding="utf-8"))
    version = raw.get("version")
    if not isinstance(version, str) or not _VERSION.fullmatch(version):
        raise _error("dashboard/package.json version must be a normalized release version")
    return version


def validate_versions(*, tag: str | None, root: Path = ROOT) -> str:
    version = release_version(root=root)
    if dashboard_version(root=root) != version:
        raise _error("Python and dashboard versions differ")
    if tag is not None and tag != f"v{version}":
        raise _error(f"tag must be exactly v{version}, got {tag!r}")
    return version


def _source(*, repository: str, ref: str, commit: str, tag: str) -> dict[str, str]:
    if not _REPOSITORY.fullmatch(repository):
        raise _error("repository must be an owner/name identifier")
    if ref != f"refs/tags/{tag}":
        raise _error("ref must be the exact refs/tags/<tag> reference")
    if _COMMIT.fullmatch(commit) is None:
        raise _error("commit must be a lowercase 40-character SHA")
    return {"repository": repository, "ref": ref, "commit": commit}


def make_manifest(
    *,
    tag: str,
    artifacts: Iterable[Path],
    repository: str,
    ref: str,
    commit: str,
    root: Path = ROOT,
    candidate_root: Path | None = None,
) -> dict[str, Any]:
    version = validate_versions(tag=tag, root=root)
    seen: set[str] = set()
    records: list[dict[str, str]] = []
    candidate_root = candidate_root or root
    for artifact in artifacts:
        if not artifact.is_file():
            raise _error(f"artifact is missing or not a file: {artifact}")
        name = _relative(artifact, root=candidate_root)
        if name in seen:
            raise _error(f"artifact was specified more than once: {name}")
        seen.add(name)
        records.append({"path": name, "sha256": _sha256(artifact)})
    if not records:
        raise _error("at least one artifact is required")
    return {
        "schema_version": 1,
        "project": "tracebed",
        "version": version,
        "tag": tag,
        "source": _source(repository=repository, ref=ref, commit=commit, tag=tag),
        "artifacts": sorted(records, key=lambda record: record["path"]),
    }


def write_manifest(destination: Path, manifest: dict[str, Any]) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def verify_manifest(
    path: Path,
    *,
    root: Path = ROOT,
    candidate_root: Path | None = None,
    repository: str | None = None,
    ref: str | None = None,
    commit: str | None = None,
    check_metadata: bool = True,
) -> None:
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise _error(f"cannot read manifest: {exc}") from exc
    if not isinstance(manifest, dict) or manifest.get("schema_version") != 1:
        raise _error("unsupported manifest schema")
    if manifest.get("project") != "tracebed":
        raise _error("manifest project must be tracebed")
    tag = manifest.get("tag")
    version = manifest.get("version")
    if not isinstance(tag, str) or not isinstance(version, str):
        raise _error("manifest must contain string tag and version")
    if check_metadata and validate_versions(tag=tag, root=root) != version:
        raise _error("manifest version does not match repository metadata")
    source = manifest.get("source")
    if not isinstance(source, dict):
        raise _error("manifest source must be an object")
    expected_source = _source(
        repository=str(source.get("repository", "")),
        ref=str(source.get("ref", "")),
        commit=str(source.get("commit", "")),
        tag=tag,
    )
    supplied = (repository, ref, commit)
    if any(value is not None for value in supplied):
        if not all(isinstance(value, str) for value in supplied):
            raise _error("repository, ref, and commit must be supplied together")
        supplied_source = _source(
            repository=repository or "", ref=ref or "", commit=commit or "", tag=tag
        )
        if expected_source != supplied_source:
            raise _error("manifest source does not match the expected repository/ref/commit")
    candidate_root = candidate_root or root
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        raise _error("manifest artifacts must be a non-empty list")
    observed: set[str] = set()
    for record in artifacts:
        if not isinstance(record, dict):
            raise _error("manifest artifact must be an object")
        name, expected = record.get("path"), record.get("sha256")
        if (
            not isinstance(name, str)
            or not isinstance(expected, str)
            or re.fullmatch(r"[0-9a-f]{64}", expected) is None
        ):
            raise _error("manifest artifact must have a path and lowercase SHA-256 digest")
        candidate = candidate_root / name
        if _relative(candidate, root=candidate_root) != name or name in observed:
            raise _error(f"manifest has invalid or duplicate artifact path: {name!r}")
        observed.add(name)
        if not candidate.is_file() or _sha256(candidate) != expected:
            raise _error(f"artifact digest mismatch: {name}")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_subparsers(dest="action", required=True)
    check = actions.add_parser("check", help="verify metadata and an optional exact tag")
    check.add_argument("--tag")
    write = actions.add_parser("write", help="write a manifest for built artifacts")
    write.add_argument("--tag", required=True)
    write.add_argument("--repository", required=True)
    write.add_argument("--ref", required=True)
    write.add_argument("--commit", required=True)
    write.add_argument("--candidate-root", type=Path)
    write.add_argument("--output", type=Path, required=True)
    write.add_argument("--artifact", type=Path, action="append", required=True)
    verify = actions.add_parser("verify", help="verify an existing manifest against artifact bytes")
    verify.add_argument("--manifest", type=Path, required=True)
    verify.add_argument("--repository")
    verify.add_argument("--ref")
    verify.add_argument("--commit")
    verify.add_argument("--no-metadata-check", action="store_true")
    verify.add_argument("--candidate-root", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.action == "check":
            print(validate_versions(tag=args.tag))
        elif args.action == "write":
            write_manifest(
                args.output,
                make_manifest(
                    tag=args.tag,
                    artifacts=args.artifact,
                    repository=args.repository,
                    ref=args.ref,
                    commit=args.commit,
                    candidate_root=args.candidate_root,
                ),
            )
        else:
            verify_manifest(
                args.manifest,
                repository=args.repository,
                ref=args.ref,
                commit=args.commit,
                check_metadata=not args.no_metadata_check,
                candidate_root=args.candidate_root,
            )
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised through the command boundary
    raise SystemExit(main())
