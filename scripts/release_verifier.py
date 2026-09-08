#!/usr/bin/env python3
"""Stdlib-only verifier shipped beside a candidate release evidence bundle."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import sys
from collections.abc import Sequence
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import release_manifest


def _require_sbom(path: Path, *, kind: str) -> tuple[int, str]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if kind == "spdx":
        valid = (
            raw.get("SPDXID") == "SPDXRef-DOCUMENT"
            and isinstance(raw.get("name"), str)
            and isinstance(raw.get("documentNamespace"), str)
            and isinstance(raw.get("packages"), list)
            and len(raw["packages"]) > 1
            and isinstance(raw.get("relationships"), list)
            and raw["relationships"]
        )
    else:
        valid = (
            raw.get("bomFormat") == "CycloneDX"
            and isinstance(raw.get("specVersion"), str)
            and isinstance(raw.get("metadata"), dict)
            and isinstance(raw["metadata"].get("component"), dict)
            and isinstance(raw["metadata"]["component"].get("name"), str)
            and isinstance(raw.get("components"), list)
            and len(raw["components"]) > 1
        )
    if not valid:
        raise ValueError(f"invalid {kind} SBOM: {path}")
    count = len(raw["packages"] if kind == "spdx" else raw["components"])
    root = raw["name"] if kind == "spdx" else raw["metadata"]["component"].get("name")
    if not isinstance(root, str):
        raise ValueError(f"invalid {kind} SBOM root: {path}")
    return count, root


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify_evidence(root: Path, *, repository: str, ref: str, commit: str) -> None:
    release_manifest.verify_manifest(
        root / "release-manifest.json",
        root=root,
        repository=repository,
        ref=ref,
        commit=commit,
        check_metadata=False,
    )
    counts: dict[str, tuple[tuple[int, str], tuple[int, str]]] = {}
    for payload in ("image", "python", "dashboard"):
        counts[payload] = (
            _require_sbom(root / "sbom" / f"{payload}.spdx.json", kind="spdx"),
            _require_sbom(root / "sbom" / f"{payload}.cyclonedx.json", kind="cyclonedx"),
        )
    reports = {report.name for report in (root / "vulnerabilities").glob("*.json")}
    if reports != {"image.json", "python.json", "dashboard.json"}:
        raise ValueError("must contain exactly image, python, and dashboard vulnerability reports")
    for name in reports:
        raw = json.loads((root / "vulnerabilities" / name).read_text(encoding="utf-8"))
        descriptor = raw.get("descriptor") if isinstance(raw, dict) else None
        source = raw.get("source") if isinstance(raw, dict) else None
        if (
            not isinstance(raw, dict)
            or not isinstance(raw.get("matches", []), list)
            or not isinstance(descriptor, dict)
            or descriptor.get("name") != "grype"
            or not isinstance(descriptor.get("version"), str)
            or not isinstance(source, dict)
        ):
            raise ValueError(f"invalid vulnerability report: {name}")
    bindings = json.loads((root / "tool-metadata" / "sbom-bindings.json").read_text(encoding="utf-8"))
    payloads = bindings.get("payloads") if isinstance(bindings, dict) else None
    if (
        not isinstance(bindings, dict)
        or set(bindings) != {"schema_version", "version", "payloads"}
        or bindings.get("schema_version") != 1
        or bindings.get("version") != ref.removeprefix("refs/tags/v")
        or not isinstance(payloads, dict)
        or set(payloads) != {"image", "python", "dashboard"}
    ):
        raise ValueError("SBOM bindings must describe exactly image, python, and dashboard")
    for name, binding in payloads.items():
        required = {
            "path", "sha256", "spdx", "cyclonedx", "vulnerability_report",
            "severity_threshold", "scan_configuration", "spdx_package_count",
            "cyclonedx_component_count", "spdx_root", "cyclonedx_root",
        }
        allowed = required | ({"equivalent_sdist"} if name == "python" else set())
        if not isinstance(binding, dict) or set(binding) != allowed:
            raise ValueError(f"invalid SBOM binding: {name}")
        expected_path = (
            f"tracebed-api-{bindings['version']}.tar"
            if name == "image"
            else f"tracebed-dashboard-{bindings['version']}.tar.gz"
            if name == "dashboard"
            else None
        )
        if expected_path is not None and binding.get("path") != expected_path:
            raise ValueError(f"SBOM binding exact payload path mismatch: {name}")
        if name == "python" and (
            not isinstance(binding.get("path"), str)
            or not binding["path"].startswith("python/")
            or not binding["path"].endswith(".whl")
        ):
            raise ValueError("Python wheel binding must be candidate-relative python/<wheel>")
        artifact = root / str(binding.get("path", ""))
        if not artifact.is_file() or binding.get("sha256") != _sha256(artifact):
            raise ValueError(f"SBOM binding payload mismatch: {name}")
        if binding.get("spdx") != f"sbom/{name}.spdx.json" or binding.get("cyclonedx") != f"sbom/{name}.cyclonedx.json":
            raise ValueError(f"SBOM binding paths mismatch: {name}")
        if binding.get("vulnerability_report") != f"vulnerabilities/{name}.json":
            raise ValueError(f"vulnerability binding path mismatch: {name}")
        if (
            binding.get("severity_threshold") != "high"
            or binding.get("scan_configuration") != {"fail_on_severity": "high"}
        ):
            raise ValueError(f"vulnerability threshold mismatch: {name}")
        expected_counts = counts[name]
        if (
            binding.get("spdx_package_count"),
            binding.get("cyclonedx_component_count"),
        ) != (expected_counts[0][0], expected_counts[1][0]):
            raise ValueError(f"SBOM binding counts are invalid: {name}")
        if (binding.get("spdx_root"), binding.get("cyclonedx_root")) != (
            expected_counts[0][1],
            expected_counts[1][1],
        ):
            raise ValueError(f"SBOM binding roots are invalid: {name}")
        report = json.loads((root / "vulnerabilities" / f"{name}.json").read_text(encoding="utf-8"))
        spdx = json.loads((root / "sbom" / f"{name}.spdx.json").read_text(encoding="utf-8"))
        cdx = json.loads((root / "sbom" / f"{name}.cyclonedx.json").read_text(encoding="utf-8"))
        spdx_identities = {(item.get("name"), item.get("versionInfo")) for item in spdx.get("packages", []) if isinstance(item, dict)}
        cdx_identities = {(item.get("name"), item.get("version")) for item in cdx.get("components", []) if isinstance(item, dict)}
        if name in {"image", "python"} and (("tracebed", bindings.get("version")) not in spdx_identities or ("tracebed", bindings.get("version")) not in cdx_identities):
            raise ValueError(f"Tracebed identity/version missing from {name} SBOM")
        if name == "dashboard":
            production = {"react", "react-dom", "react-router-dom"}
            if not production.issubset({item[0] for item in spdx_identities}) or not production.issubset({item[0] for item in cdx_identities}):
                raise ValueError("dashboard production identities missing from SBOM")
            lock = json.loads((root / "package-lock.json").read_text(encoding="utf-8"))
            locked = {
                package: lock["packages"][f"node_modules/{package}"]["version"]
                for package in production
            }
            if any((package, version) not in spdx_identities or (package, version) not in cdx_identities for package, version in locked.items()):
                raise ValueError("dashboard locked dependency versions missing from SBOM")
        source = report.get("source", {})
        if name == "image":
            expected_target = f"tracebed-api:{bindings.get('version')}"
            source_ok = isinstance(source, dict) and isinstance(source.get("target"), dict) and source["target"].get("userInput") == expected_target
        else:
            expected_target = "release-runtime/python" if name == "python" else "release-runtime/dashboard"
            source_ok = isinstance(source, dict) and source.get("type") == "directory" and source.get("target") == expected_target
        if (
            report.get("descriptor", {}).get("version") != "0.104.0"
            or not source_ok
        ):
            raise ValueError(f"vulnerability report target/version mismatch: {name}")
    sdist = payloads["python"].get("equivalent_sdist")
    if not isinstance(sdist, dict) or sdist.get("offline_smoke") != "passed":
        raise ValueError("Python sdist equivalence evidence is missing")
    sdist_path = root / str(sdist.get("path", ""))
    if not sdist_path.is_file() or sdist.get("sha256") != _sha256(sdist_path):
        raise ValueError("Python sdist equivalence evidence is not hash-bound")
    tools = json.loads((root / "tool-metadata" / "tools.json").read_text(encoding="utf-8"))
    required_tools = {"uv", "node", "syft", "grype", "npm", "docker", "pip", "build_python", "hatchling", "actionlint", "grype_db_sha256", "grype_db"}
    if not isinstance(tools, dict) or required_tools - set(tools):
        raise ValueError("tool metadata is incomplete")
    expected_versions = {
        "uv": "0.11.21",
        "node": "v20.19.0",
        "syft": "1.38.0",
        "grype": "0.104.0",
        "pip": "26.2",
        "hatchling": "1.29.0",
        "actionlint": "1.7.7",
    }
    version_patterns = {
        "uv": r"^uv 0\.11\.21$",
        "node": r"^v20\.19\.0$",
        "syft": r"(?m)^Version:\s+1\.38\.0$",
        "grype": r"(?m)^Version:\s+0\.104\.0$",
        "pip": r"^pip 26\.2 \([^\n]+\)$",
        "hatchling": r"^1\.29\.0$",
        "actionlint": r"(?m)^1\.7\.7(?:\s|$)",
    }
    if any(not re.search(version_patterns[key], str(tools[key])) for key in expected_versions):
        raise ValueError("tool metadata does not record the pinned observed versions")
    if (
        not re.fullmatch(r"Python 3\.13\.\d+", str(tools["build_python"]).strip())
        or not re.fullmatch(r"\d+\.\d+\.\d+", str(tools["npm"]).strip())
        or not re.fullmatch(r"Docker version \d+\.\d+\.\d+, build [0-9A-Za-z]+", str(tools["docker"]).strip())
    ):
        raise ValueError("build Python/npm/docker metadata is not normalized and pinned")
    database = root / "tool-metadata" / "grype-db.json"
    if not database.is_file() or tools.get("grype_db_sha256") != _sha256(database):
        raise ValueError("Grype database metadata is not hash-bound")
    db_status = tools.get("grype_db")
    if (
        not isinstance(db_status, dict)
        or db_status.get("status") != "verified"
        or db_status.get("valid") is not True
        or not all(db_status.get(key) for key in ("schemaVersion", "from", "built", "path"))
    ):
        raise ValueError("Grype database status metadata is incomplete")
    checksums = parse_qs(urlparse(str(db_status["from"])).query).get("checksum", [])
    archive_sha256 = checksums[0].removeprefix("sha256:") if len(checksums) == 1 else ""
    db_file = (root / str(db_status["path"])).resolve()
    if (
        len(archive_sha256) != 64
        or db_status.get("archive_sha256") != archive_sha256
        or db_file.parent != (root / "tool-metadata").resolve()
        or db_file.name != "grype-db.sqlite"
        or not db_file.is_file()
        or db_status.get("sqlite_sha256") != _sha256(db_file)
    ):
        raise ValueError("Grype archive and SQLite digest evidence is invalid")


def verify_provenance(path: Path, *, repository: str, ref: str, commit: str) -> None:
    """Require the signed GH-attestation payload to name the exact source tuple.

    Signature and certificate verification remain the GitHub CLI's job. This
    check binds the verified payload to the repository, immutable tag ref, and
    commit rather than accepting a valid attestation from another revision.
    """

    raw = json.loads(path.read_text(encoding="utf-8"))
    payloads: list[str] = [json.dumps(raw, sort_keys=True)]
    if isinstance(raw, dict) and isinstance(raw.get("payload"), str):
        try:
            payloads.append(base64.b64decode(raw["payload"] + "===").decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise ValueError("provenance DSSE payload is not valid base64 UTF-8") from exc
    text = "\n".join(payloads)
    expected_repo = f"github.com/{repository}"
    workflow = f".github/workflows/release.yml@{ref}"
    if commit not in text or ref not in text or expected_repo not in text or workflow not in text:
        raise ValueError("provenance payload does not bind the exact workflow/repository/ref/commit")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="action", required=True)
    evidence = subparsers.add_parser("evidence")
    evidence.add_argument("--root", type=Path, required=True)
    provenance = subparsers.add_parser("provenance")
    provenance.add_argument("--path", type=Path, required=True)
    for command in (evidence, provenance):
        command.add_argument("--repository", required=True)
        command.add_argument("--ref", required=True)
        command.add_argument("--commit", required=True)
    args = parser.parse_args(argv)
    try:
        if args.action == "evidence":
            verify_evidence(args.root, repository=args.repository, ref=args.ref, commit=args.commit)
        else:
            verify_provenance(
                args.path, repository=args.repository, ref=args.ref, commit=args.commit
            )
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"release verifier: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
