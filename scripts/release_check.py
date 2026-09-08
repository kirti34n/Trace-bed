#!/usr/bin/env python3
"""Fail closed on the source-controlled release and workflow contract.

This checker is intentionally structural.  GitHub environment protection,
trusted-publisher ownership, and release destinations are human-controlled
settings, so the source contract refuses to claim that they are configured.
"""

from __future__ import annotations

import argparse
import re
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import cast

import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
_USES = re.compile(
    r"^\s*(?:-\s*)?uses:\s*[^@\s]+@(?P<sha>[0-9a-f]{40})\s+#\s+v[^\s]+\s*$",
    re.MULTILINE,
)
_ANY_USES = re.compile(r"^\s*(?:-\s*)?uses:\s*", re.MULTILINE)
_UNPINNED_USES = re.compile(r"^\s*(?:-\s*)?uses:\s*[^@\s]+@(?P<ref>[^\s#]+)", re.MULTILINE)


def _error(message: str) -> ValueError:
    return ValueError(f"release check: {message}")


def _workflow_text(name: str) -> str:
    path = WORKFLOWS / name
    if not path.is_file():
        raise _error(f"missing workflow: {path.relative_to(ROOT)}")
    return path.read_text(encoding="utf-8")


def validate_action_pins() -> None:
    files = sorted(WORKFLOWS.glob("*.yml")) + sorted(WORKFLOWS.glob("*.yaml"))
    if not files:
        raise _error("no GitHub workflows found")
    for path in files:
        text = path.read_text(encoding="utf-8")
        uses_lines = list(_ANY_USES.finditer(text))
        pins = list(_USES.finditer(text))
        refs = list(_UNPINNED_USES.finditer(text))
        if len(uses_lines) != len(refs) or len(refs) != len(pins):
            raise _error(
                f"every action in {path.relative_to(ROOT)} must use a full SHA and version comment"
            )


def _workflow() -> dict[object, object]:
    try:
        loaded = yaml.safe_load(_workflow_text("release.yml"))
    except yaml.YAMLError as exc:
        raise _error(f"release.yml is invalid YAML: {exc}") from exc
    if not isinstance(loaded, dict):
        raise _error("release.yml must be a YAML mapping")
    return cast(dict[object, object], loaded)


def _job(workflow: dict[object, object], name: str) -> dict[object, object]:
    jobs = workflow.get("jobs")
    if not isinstance(jobs, dict) or not isinstance(jobs.get(name), dict):
        raise _error(f"release workflow is missing job {name!r}")
    return cast(dict[object, object], jobs[name])


def _commands(job: dict[object, object]) -> str:
    steps = job.get("steps", [])
    if not isinstance(steps, list):
        raise _error("workflow job steps must be a list")
    return "\n".join(str(step.get("run", "")) for step in steps if isinstance(step, dict))


def _steps_using(job: dict[object, object], action: str) -> list[dict[object, object]]:
    steps = job.get("steps", [])
    if not isinstance(steps, list):
        raise _error("workflow job steps must be a list")
    return [
        cast(dict[object, object], step)
        for step in steps
        if isinstance(step, dict) and str(step.get("uses", "")).startswith(action + "@")
    ]


def validate_release_workflow() -> None:
    workflow = _workflow()
    build = _job(workflow, "build-test-scan")
    signer = _job(workflow, "attest-sign-verify")
    human = _job(workflow, "human-publication-gate")
    policy = _job(workflow, "policy")
    dispatch = workflow.get(True)  # YAML 1.1 decodes the unquoted `on` key as true.
    if not isinstance(dispatch, dict) or "push" not in dispatch or "workflow_dispatch" not in dispatch:
        raise _error("release workflow must support tag push and explicit existing-tag dispatch")
    forbidden = ("twine upload", "npm publish", "docker push", "gh release create")
    commands = "\n".join(_commands(job) for job in (policy, build, signer, human))
    present = [command for command in forbidden if command in commands]
    if present:
        raise _error(
            f"release workflow must not publish before a human configures a destination: {present}"
        )
    if build.get("permissions") != {"contents": "read"}:
        raise _error("build-test-scan must have only contents: read")
    if signer.get("permissions") != {
        "id-token": "write",
        "attestations": "write",
        "actions": "read",
    }:
        raise _error(
            "attest-sign-verify must have only OIDC, attestations, and artifact-read scope"
        )
    if signer.get("environment") != "tracebed-release-signing":
        raise _error("OIDC signer must require protected tracebed-release-signing approval")
    if human.get("environment") != "tracebed-release":
        raise _error("human-publication-gate must use the tracebed-release environment")
    human_commands = _commands(human)
    if ".venv/" in human_commands or "uv sync" in human_commands or "checkout" in str(human):
        raise _error("fresh human verifier must use only runner stdlib and immutable evidence")
    signer_commands = _commands(signer)
    if "release-candidate/release_verifier.py" in signer_commands:
        raise _error("OIDC signer must not execute candidate-controlled verifier code")
    if "fresh-subjects.txt" not in human_commands or "manifest subject digest mismatch" not in human_commands:
        raise _error("fresh human gate must derive and hash-check its own manifest subject list")
    if "verification/subjects.txt" not in signer_commands:
        raise _error("OIDC signer must use its fixed manifest-derived subject list")
    if "verification/subjects.sha256" not in signer_commands or "subject-checksums" not in str(signer):
        raise _error("OIDC signer must attest the complete manifest inventory through checksums")
    if "subject-path" in str(signer):
        raise _error("OIDC signer must not use a glob-expanded attestation inventory")
    for expected in ("--source-ref", "--source-digest", "--format json"):
        if expected not in signer_commands or expected not in human_commands:
            raise _error(f"both verifier gates must use exact source-bound attestation control: {expected}")
    if "--source-repository" in commands or "attestation download" in commands:
        raise _error("workflow must use supported GitHub attestation verification/download semantics")
    downloads = _steps_using(signer, "actions/download-artifact")
    if len(downloads) != 1 or cast(dict[object, object], downloads[0].get("with", {})).get("path") != "release-candidate":
        raise _error("OIDC signer must download the candidate to its declared immutable root")
    upload = _steps_using(signer, "actions/upload-artifact")
    if len(upload) != 1:
        raise _error("OIDC signer must retain exactly one immutable evidence artifact")
    upload_with = cast(dict[object, object], upload[0].get("with", {}))
    if "release-candidate" not in str(upload_with.get("path", "")) or "verification" not in str(upload_with.get("path", "")):
        raise _error("retained release evidence must contain candidate bytes and external verification")
    if _steps_using(build, "anchore/sbom-action") or _steps_using(build, "anchore/scan-action"):
        raise _error("candidate must scan only with the independently checksum-verified Syft and Grype")
    if "actionlint" not in _commands(build):
        raise _error("candidate build must run actionlint")
    required_gates = (
        "npm test",
        "dashboard/scripts/license_check.mjs --self-test",
        "scripts/image_check.py --self-test",
        "harness/guessed_reward.py",
        "scripts/compose_acceptance.py",
        "--wheelhouse release-candidate/wheelhouse",
        "--no-emit-project",
        "--require-hashes",
        "release-runtime/sdist",
        "release-tools/grype\" db status -o json",
        "sbom-bindings.json",
        "npm test --prefix dashboard",
        "SYFT_CHECKSUM_LINUX_X64",
        "GRYPE_CHECKSUM_LINUX_X64",
        "importlib.metadata import version",
        "--fail-on high",
        "dir:release-runtime/dashboard",
        "--output json=release-candidate/vulnerabilities/dashboard.json",
        "--source-name tracebed-api --source-version \"$RELEASE_VERSION\"",
        "--source-name tracebed-python-runtime --source-version \"$RELEASE_VERSION\"",
        "--source-name tracebed-dashboard-runtime --source-version \"$RELEASE_VERSION\"",
    )
    missing_gates = [gate for gate in required_gates if gate not in _commands(build)]
    if missing_gates:
        raise _error(f"candidate gate set is incomplete: {', '.join(missing_gates)}")
    policy_commands = _commands(policy)
    if "refs/tags/${{ env.RELEASE_TAG }}" not in str(policy):
        raise _error("policy checkout must explicitly use the requested tag ref")
    if 'test "$GITHUB_REF" = "refs/tags/${RELEASE_TAG}"' not in policy_commands:
        raise _error("policy must reject dispatch or branch refs that are not the requested tag ref")
    if "git rev-parse" not in policy_commands or "GITHUB_SHA" not in policy_commands:
        raise _error("policy must prove peeled tag, checkout HEAD, and GitHub SHA agree")
    installer_names = [
        str(step.get("name", ""))
        for job in (signer, human)
        for step in cast(list[object], job.get("steps", []))
        if isinstance(step, dict)
    ]
    if installer_names.count("Install exact GitHub CLI") != 2 or commands.count("release-gh/bin/gh") < 4:
        raise _error("every GitHub-attestation job must checksum-install and use the exact GH CLI")
    for expected in ("GH_CHECKSUM_LINUX_X64", "verificationResult", "subjectAlternativeName", "buildDefinition"):
        if expected not in signer_commands or expected not in human_commands:
            raise _error(f"both attestation gates must structurally verify {expected}")
    if "GO_VERSION" in str(workflow) or "go version" in commands:
        raise _error("release workflow must not rely on an unused mutable Go runner toolchain")
    if "paths.append((root / \"release-manifest.json\").as_posix())" not in signer_commands or "paths.append((root / \"release-manifest.json\").as_posix())" not in human_commands:
        raise _error("manifest must be a distinct fixed signing and verification subject")
    exact_inline_controls = (
        "tag/version must be exactly bound to RELEASE_REF",
        "SBOM binding exact schema/path mismatch",
        "scan_configuration",
        "fail_on_severity",
        "SBOM binding payload/count/root mismatch",
        "archive_sha256",
        "sqlite_sha256",
        "dashboard locked dependency versions",
        "raw Grype DB/status reconciliation",
        "Grype DB archive checksum mismatch",
        "Grype DB SQLite digest/path mismatch",
        "Grype report semantics/configuration mismatch",
        "Grype match schema/severity blocker mismatch",
        "Python wheel/sdist equivalence binding mismatch",
        "locked tool identity evidence mismatch",
        '"uv":r"^uv 0\\.11\\.21 \\(x86_64-unknown-linux-gnu\\)$"',
    )
    missing_inline_controls = [
        control
        for control in exact_inline_controls
        if control not in signer_commands or control not in human_commands
    ]
    if missing_inline_controls:
        raise _error(
            "both protected inline stdlib validators must enforce exact release evidence: "
            + ", ".join(missing_inline_controls)
        )
    if "fresh human bundle closure mismatch" not in human_commands:
        raise _error("human validator must reject an unexpected or missing .bundle inventory")


def validate_policy_documents() -> None:
    required = (
        ROOT / "docs" / "RELEASE-POLICY.md",
        ROOT / "repository-settings" / "security-exceptions.md",
        ROOT / "NOTICE",
        ROOT / "THIRD_PARTY_NOTICES.md",
    )
    missing = [str(path.relative_to(ROOT)) for path in required if not path.is_file()]
    if missing:
        raise _error(f"missing release policy documents: {', '.join(missing)}")
    exceptions = (ROOT / "repository-settings" / "security-exceptions.md").read_text(
        encoding="utf-8"
    )
    if "No exceptions are approved" not in exceptions:
        raise _error("security exceptions file must fail closed when no approved exception exists")
    checklist = (ROOT / "repository-settings" / "release-checklist.md").read_text(encoding="utf-8")
    for environment in ("tracebed-release-signing", "tracebed-release"):
        if environment not in checklist or "not configured" not in checklist:
            raise _error("release checklist must honestly require both unconfigured protected environments")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="validate the source release contract")
    args = parser.parse_args(argv)
    if not args.check:
        parser.error("--check is required")
    try:
        validate_action_pins()
        validate_release_workflow()
        validate_policy_documents()
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print("release source contract is current")
    return 0


if __name__ == "__main__":  # pragma: no cover - command boundary
    raise SystemExit(main())
