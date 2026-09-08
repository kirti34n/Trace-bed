"""Source-contract checks for the deliberately non-publishing release workflow."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import subprocess
import sys
import textwrap
from pathlib import Path
from types import ModuleType

import pytest

pytestmark = pytest.mark.phase0
ROOT = Path(__file__).resolve().parents[2]


def _load(name: str) -> ModuleType:
    path = ROOT / "scripts" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _metadata_root(
    tmp_path: Path, *, python_version: str = "0.1.0", dashboard_version: str = "0.1.0"
) -> Path:
    (tmp_path / "dashboard").mkdir(parents=True)
    (tmp_path / "pyproject.toml").write_text(
        f"[project]\nname = 'tracebed'\nversion = '{python_version}'\n", encoding="utf-8"
    )
    (tmp_path / "dashboard" / "package.json").write_text(
        json.dumps({"version": dashboard_version}), encoding="utf-8"
    )
    return tmp_path


def test_release_source_contract_is_current() -> None:
    checker = _load("release_check")
    checker.validate_action_pins()
    checker.validate_release_workflow()
    checker.validate_policy_documents()


def test_action_pin_check_rejects_an_unpinned_or_unversioned_action(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    checker = _load("release_check")
    workflows = tmp_path / "workflows"
    workflows.mkdir()
    (workflows / "bad.yml").write_text(
        "jobs:\n  test:\n    steps:\n      - uses: actions/checkout@v4\n", encoding="utf-8"
    )
    monkeypatch.setattr(checker, "ROOT", tmp_path)
    monkeypatch.setattr(checker, "WORKFLOWS", workflows)
    with pytest.raises(ValueError, match="full SHA"):
        checker.validate_action_pins()


def test_release_workflow_has_no_implicit_publication_and_uses_a_human_gate() -> None:
    workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    assert "environment: tracebed-release" in workflow
    assert "Stop before publication" in workflow
    for forbidden in ("twine upload", "npm publish", "docker push", "gh release create"):
        assert forbidden not in workflow


def test_manifest_binds_version_tag_and_artifact_bytes(tmp_path: Path) -> None:
    manifest_module = _load("release_manifest")
    root = _metadata_root(tmp_path)
    artifact = root / "release-dist" / "tracebed.whl"
    artifact.parent.mkdir()
    artifact.write_bytes(b"candidate-v1")
    manifest = manifest_module.make_manifest(
        tag="v0.1.0",
        artifacts=[artifact],
        repository="example/tracebed",
        ref="refs/tags/v0.1.0",
        commit="a" * 40,
        root=root,
    )
    path = root / "release-dist" / "release-manifest.json"
    manifest_module.write_manifest(path, manifest)
    manifest_module.verify_manifest(
        path,
        root=root,
        repository="example/tracebed",
        ref="refs/tags/v0.1.0",
        commit="a" * 40,
    )

    artifact.write_bytes(b"candidate-tampered")
    with pytest.raises(ValueError, match="digest mismatch"):
        manifest_module.verify_manifest(
            path,
            root=root,
            repository="example/tracebed",
            ref="refs/tags/v0.1.0",
            commit="a" * 40,
        )


def test_manifest_rejects_version_or_tag_drift(tmp_path: Path) -> None:
    manifest_module = _load("release_manifest")
    root = _metadata_root(tmp_path / "mismatch", dashboard_version="0.1.1")
    with pytest.raises(ValueError, match="versions differ"):
        manifest_module.validate_versions(tag="v0.1.0", root=root)

    root = _metadata_root(tmp_path / "tag", dashboard_version="0.1.0")
    with pytest.raises(ValueError, match="tag must be exactly"):
        manifest_module.validate_versions(tag="v0.1.1", root=root)


def test_manifest_rejects_a_source_tuple_mismatch(tmp_path: Path) -> None:
    manifest_module = _load("release_manifest")
    root = _metadata_root(tmp_path)
    artifact = root / "candidate.bin"
    artifact.write_bytes(b"candidate")
    manifest = manifest_module.make_manifest(
        tag="v0.1.0",
        artifacts=[artifact],
        repository="example/tracebed",
        ref="refs/tags/v0.1.0",
        commit="a" * 40,
        root=root,
    )
    path = root / "manifest.json"
    manifest_module.write_manifest(path, manifest)
    with pytest.raises(ValueError, match="source does not match"):
        manifest_module.verify_manifest(
            path,
            root=root,
            repository="example/tracebed",
            ref="refs/tags/v0.1.0",
            commit="b" * 40,
        )


def test_manifest_paths_are_portable_when_the_candidate_bundle_moves(tmp_path: Path) -> None:
    manifest_module = _load("release_manifest")
    root = _metadata_root(tmp_path / "checkout")
    candidate = root / "release-candidate"
    candidate.mkdir()
    artifact = candidate / "payload.bin"
    artifact.write_bytes(b"candidate")
    manifest = manifest_module.make_manifest(
        tag="v0.1.0",
        artifacts=[artifact],
        repository="example/tracebed",
        ref="refs/tags/v0.1.0",
        commit="a" * 40,
        root=root,
        candidate_root=candidate,
    )
    manifest_path = candidate / "release-manifest.json"
    manifest_module.write_manifest(manifest_path, manifest)
    moved = tmp_path / "fresh-runner"
    moved.mkdir()
    (moved / "payload.bin").write_bytes(artifact.read_bytes())
    (moved / "release-manifest.json").write_bytes(manifest_path.read_bytes())
    manifest_module.verify_manifest(
        moved / "release-manifest.json",
        root=root,
        candidate_root=moved,
        repository="example/tracebed",
        ref="refs/tags/v0.1.0",
        commit="a" * 40,
        check_metadata=False,
    )
    result = subprocess.run(  # noqa: S603 -- fixed repository verifier and temporary fixture
        [
            sys.executable,
            str(ROOT / "scripts" / "release_manifest.py"),
            "verify",
            "--manifest",
            str(moved / "release-manifest.json"),
            "--candidate-root",
            str(moved),
            "--repository",
            "example/tracebed",
            "--ref",
            "refs/tags/v0.1.0",
            "--commit",
            "a" * 40,
            "--no-metadata-check",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr


def test_stdlib_provenance_verifier_rejects_a_foreign_ref_or_commit(tmp_path: Path) -> None:
    payload = tmp_path / "provenance.json"
    payload.write_text(
        json.dumps(
            {
                "repository": "github.com/example/tracebed",
                "ref": "refs/tags/v0.1.0",
                "sha": "a" * 40,
            }
        ),
        encoding="utf-8",
    )
    result = subprocess.run(  # noqa: S603 -- fixed repository verifier and temporary fixture
        [
            sys.executable,
            str(ROOT / "scripts" / "release_verifier.py"),
            "provenance",
            "--path",
            str(payload),
            "--repository",
            "example/tracebed",
            "--ref",
            "refs/tags/v0.1.0",
            "--commit",
            "b" * 40,
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 1
    assert "exact workflow/repository/ref/commit" in result.stderr


def test_release_contract_rejects_candidate_verifier_in_oidc_job_and_unsupported_gh_flags(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    checker = _load("release_check")
    original = checker._workflow_text

    def unsafe(_: str) -> str:
        return (
            str(original("release.yml"))
            .replace(
                "while IFS= read -r artifact; do cosign sign-blob",
                "python3 release-candidate/release_verifier.py evidence\n          while IFS= read -r artifact; do cosign sign-blob",
                1,
            )
            .replace("--source-ref", "--source-repository", 1)
        )

    monkeypatch.setattr(checker, "_workflow_text", unsafe)
    with pytest.raises(ValueError, match=r"OIDC signer|source-bound attestation|supported GitHub"):
        checker.validate_release_workflow()


def test_release_workflow_uses_exact_cli_scanners_and_structured_attestation_results() -> None:
    workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    assert "attestation download" not in workflow
    assert "GO_VERSION" not in workflow
    assert workflow.count("Install exact GitHub CLI") == 2
    assert workflow.count("release-gh/bin/gh") >= 4
    assert "GRYPE_CHECKSUM_LINUX_X64" in workflow
    assert "SYFT_CHECKSUM_LINUX_X64" in workflow
    assert "subjectAlternativeName" in workflow
    assert "buildDefinition" in workflow
    assert 'paths.append((root / "release-manifest.json").as_posix())' in workflow
    assert (
        'dir:release-runtime/dashboard" --fail-on high --output json=release-candidate/vulnerabilities/dashboard.json'
        in workflow
    )
    assert 'dir:release-runtime/dashboard" --fail-on high -o json >' not in workflow


def test_all_six_syft_outputs_bind_the_stable_source_identity_and_release_version() -> None:
    workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    for source_name in ("tracebed-api", "tracebed-python-runtime", "tracebed-dashboard-runtime"):
        command = f'--source-name {source_name} --source-version "$RELEASE_VERSION"'
        assert workflow.count(command) == 2


def test_both_protected_validators_keep_every_release_evidence_family() -> None:
    workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    signer = workflow[
        workflow.index(
            "Independently validate manifest inventory before attestation"
        ) : workflow.index("id: provenance")
    ]
    human = workflow[
        workflow.index("Fresh-runner stdlib verification before human stop gate") : workflow.index(
            "Stop before publication"
        )
    ]
    for family in (
        "candidate closure",
        "SBOM binding",
        "Grype match schema",
        "archive_sha256",
        "sqlite_sha256",
        "dashboard locked dependency versions",
        "raw Grype DB",
        "Python wheel/sdist",
        "locked tool identity",
    ):
        assert family in signer
        assert family in human


def _protected_validator(workflow: str, marker: str) -> str:
    """Extract the stdlib-only heredoc a protected job actually executes."""
    section = workflow[workflow.index(marker) :]
    start = section.index("python3 - <<'PY'") + len("python3 - <<'PY'")
    end = section.index("\n          PY", start)
    return textwrap.dedent(section[start:end])


def _write_protected_validator_fixture(root: Path, *, bundles: bool) -> None:
    """Small but complete candidate tree for execution, not substring, coverage."""
    candidate = root / "release-candidate"
    (root / "verification").mkdir(parents=True, exist_ok=True)
    for directory in ("python", "sbom", "vulnerabilities", "tool-metadata"):
        (candidate / directory).mkdir(parents=True, exist_ok=True)
    version = "0.1.0"
    payloads = {
        "image": f"tracebed-api-{version}.tar",
        "python": "python/tracebed-0.1.0-py3-none-any.whl",
        "dashboard": f"tracebed-dashboard-{version}.tar.gz",
    }
    for relative in payloads.values():
        (candidate / relative).write_bytes(relative.encode())
    (candidate / "python" / "tracebed-0.1.0.tar.gz").write_bytes(b"sdist")
    (candidate / "package-lock.json").write_text(
        json.dumps(
            {
                "packages": {
                    f"node_modules/{name}": {"version": "1.0.0"}
                    for name in ("react", "react-dom", "react-router-dom")
                }
            }
        ),
        encoding="utf-8",
    )
    bindings: dict[str, object] = {"schema_version": 1, "version": version, "payloads": {}}
    roots = {
        "image": ("tracebed-api", "container"),
        "python": ("tracebed-python-runtime", "file"),
        "dashboard": ("tracebed-dashboard-runtime", "file"),
    }
    for payload, relative in payloads.items():
        root_name, root_type = roots[payload]
        identities = (
            [{"name": "tracebed", "versionInfo": version}]
            if payload in {"image", "python"}
            else [
                {"name": name, "versionInfo": "1.0.0"}
                for name in ("react", "react-dom", "react-router-dom")
            ]
        )
        components = [{"name": item["name"], "version": item["versionInfo"]} for item in identities]
        spdx = {
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": root_name,
            "documentNamespace": f"https://example.invalid/{payload}",
            "packages": identities,
            "relationships": [{"spdxElementId": "SPDXRef-DOCUMENT"}],
        }
        cdx = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "metadata": {
                "component": {
                    "name": root_name,
                    "version": version,
                    "type": root_type,
                }
            },
            "components": components,
        }
        cdx_root = root_name
        (candidate / "sbom" / f"{payload}.spdx.json").write_text(json.dumps(spdx), encoding="utf-8")
        (candidate / "sbom" / f"{payload}.cyclonedx.json").write_text(
            json.dumps(cdx), encoding="utf-8"
        )
        source = (
            {"target": {"userInput": f"tracebed-api:{version}"}}
            if payload == "image"
            else {"type": "directory", "target": f"release-runtime/{payload}"}
        )
        (candidate / "vulnerabilities" / f"{payload}.json").write_text(
            json.dumps(
                {
                    "descriptor": {
                        "name": "grype",
                        "version": "0.104.0",
                        "configuration": {"fail-on-severity": "high"},
                    },
                    "source": source,
                    "matches": [],
                }
            ),
            encoding="utf-8",
        )
        digest = hashlib.sha256((candidate / relative).read_bytes()).hexdigest()
        binding = {
            "path": relative,
            "sha256": digest,
            "spdx": f"sbom/{payload}.spdx.json",
            "cyclonedx": f"sbom/{payload}.cyclonedx.json",
            "vulnerability_report": f"vulnerabilities/{payload}.json",
            "severity_threshold": "high",
            "scan_configuration": {"fail_on_severity": "high"},
            "spdx_package_count": len(identities),
            "cyclonedx_component_count": len(components),
            "spdx_root": spdx["name"],
            "cyclonedx_root": cdx_root,
        }
        if payload == "python":
            sdist = candidate / "python" / "tracebed-0.1.0.tar.gz"
            binding["equivalent_sdist"] = {
                "path": "python/tracebed-0.1.0.tar.gz",
                "sha256": hashlib.sha256(sdist.read_bytes()).hexdigest(),
                "offline_smoke": "passed",
            }
        bindings["payloads"][payload] = binding  # type: ignore[index]
    (candidate / "tool-metadata" / "sbom-bindings.json").write_text(
        json.dumps(bindings), encoding="utf-8"
    )
    (candidate / "tool-metadata" / "grype-db.sqlite").write_bytes(b"sqlite")
    db = {
        "valid": True,
        "schemaVersion": "6",
        "from": "https://example.invalid/db?checksum=sha256:" + "a" * 64,
        "built": "2026-08-27T00:00:00Z",
        "path": str(candidate / "tool-metadata" / "grype-db.sqlite"),
    }
    db_path = candidate / "tool-metadata" / "grype-db.json"
    db_path.write_text(json.dumps(db), encoding="utf-8")
    tools = {
        "uv": "uv 0.11.21 (x86_64-unknown-linux-gnu)",
        "node": "v20.19.0",
        "syft": "Version: 1.38.0",
        "grype": "Version: 0.104.0",
        "npm": "10.8.2",
        "docker": "Docker version 29.6.2, build dfc4efb",
        "pip": "pip 26.2 (/tmp/pip)",
        "build_python": "Python 3.13.14",
        "hatchling": "1.29.0",
        "actionlint": "1.7.7",
        "grype_db_sha256": hashlib.sha256(db_path.read_bytes()).hexdigest(),
        "grype_db": {
            "valid": True,
            "status": "verified",
            "from": db["from"],
            "schemaVersion": "6",
            "built": db["built"],
            "path": "tool-metadata/grype-db.sqlite",
            "archive_sha256": "a" * 64,
            "sqlite_sha256": hashlib.sha256(
                (candidate / "tool-metadata" / "grype-db.sqlite").read_bytes()
            ).hexdigest(),
        },
    }
    (candidate / "tool-metadata" / "tools.json").write_text(json.dumps(tools), encoding="utf-8")
    artifacts = [
        {
            "path": path.relative_to(candidate).as_posix(),
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        }
        for path in sorted(candidate.rglob("*"))
        if path.is_file()
    ]
    manifest = {
        "schema_version": 1,
        "project": "tracebed",
        "version": version,
        "tag": "v0.1.0",
        "source": {"repository": "example/tracebed", "ref": "refs/tags/v0.1.0", "commit": "a" * 40},
        "artifacts": artifacts,
    }
    (candidate / "release-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    if bundles:
        for path in [*candidate.rglob("*"), candidate / "release-manifest.json"]:
            if path.is_file() and not path.name.endswith(".bundle"):
                path.with_name(path.name + ".bundle").write_bytes(b"bundle")


def test_protected_inline_validators_execute_against_complete_evidence(tmp_path: Path) -> None:
    workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    env = {
        "RELEASE_REPOSITORY": "example/tracebed",
        "RELEASE_REF": "refs/tags/v0.1.0",
        "RELEASE_COMMIT": "a" * 40,
        "BUILD_PYTHON_VERSION": "3.13.14",
        "NPM_VERSION": "10.8.2",
        "DOCKER_IDENTITY": "Docker version 29.6.2, build dfc4efb",
    }
    signer_root = tmp_path / "signer"
    _write_protected_validator_fixture(signer_root, bundles=False)
    signer = _protected_validator(
        workflow, "Independently validate manifest inventory before attestation"
    )
    result = subprocess.run(  # noqa: S603 -- extracts the repository-controlled inline gate
        [sys.executable, "-c", signer],
        cwd=signer_root,
        env=env,
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize(
    ("validator_name", "bundles", "expected_error"),
    (
        (
            "Independently validate manifest inventory before attestation",
            False,
            "locked tool identity evidence mismatch",
        ),
        (
            "Fresh-runner stdlib verification before human stop gate",
            True,
            "fresh locked tool identity evidence mismatch",
        ),
    ),
)
def test_protected_inline_validators_reject_stale_pip_evidence(
    tmp_path: Path, validator_name: str, bundles: bool, expected_error: str
) -> None:
    """Each independently embedded release gate rejects the superseded dev-tool pin."""

    workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    env = {
        "RELEASE_REPOSITORY": "example/tracebed",
        "RELEASE_REF": "refs/tags/v0.1.0",
        "RELEASE_COMMIT": "a" * 40,
        "BUILD_PYTHON_VERSION": "3.13.14",
        "NPM_VERSION": "10.8.2",
        "DOCKER_IDENTITY": "Docker version 29.6.2, build dfc4efb",
    }
    root = tmp_path / "stale-pip"
    _write_protected_validator_fixture(root, bundles=bundles)
    validator = _protected_validator(workflow, validator_name)
    baseline = subprocess.run(  # noqa: S603 -- extracts the repository-controlled inline gate
        [sys.executable, "-c", validator],
        cwd=root,
        env=env,
        check=False,
        capture_output=True,
        text=True,
    )
    assert baseline.returncode == 0, baseline.stderr

    candidate = root / "release-candidate"
    tools_path = candidate / "tool-metadata" / "tools.json"
    tools = json.loads(tools_path.read_text(encoding="utf-8"))
    tools["pip"] = "pip 25.1.1 (/tmp/pip)"
    tools_path.write_text(json.dumps(tools), encoding="utf-8")
    _refresh_fixture_manifest(candidate)

    result = subprocess.run(  # noqa: S603 -- extracts the repository-controlled inline gate
        [sys.executable, "-c", validator],
        cwd=root,
        env=env,
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 1
    assert expected_error in result.stderr


def test_inline_binding_and_human_bundle_fixtures_reject_tampering(tmp_path: Path) -> None:
    workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    env = {
        "RELEASE_REPOSITORY": "example/tracebed",
        "RELEASE_REF": "refs/tags/v0.1.0",
        "RELEASE_COMMIT": "a" * 40,
        "BUILD_PYTHON_VERSION": "3.13.14",
        "NPM_VERSION": "10.8.2",
        "DOCKER_IDENTITY": "Docker version 29.6.2, build dfc4efb",
    }
    binding_root = tmp_path / "binding"
    _write_protected_validator_fixture(binding_root, bundles=False)
    candidate = binding_root / "release-candidate"
    binding_path = candidate / "tool-metadata" / "sbom-bindings.json"
    bindings = json.loads(binding_path.read_text(encoding="utf-8"))
    bindings["payloads"]["python"]["path"] = "tracebed-0.1.0-py3-none-any.whl"
    binding_path.write_text(json.dumps(bindings), encoding="utf-8")
    manifest_path = candidate / "release-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    for artifact in manifest["artifacts"]:
        if artifact["path"] == "tool-metadata/sbom-bindings.json":
            artifact["sha256"] = hashlib.sha256(binding_path.read_bytes()).hexdigest()
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    signer = _protected_validator(
        workflow, "Independently validate manifest inventory before attestation"
    )
    result = subprocess.run(  # noqa: S603 -- extracts the repository-controlled inline gate
        [sys.executable, "-c", signer],
        cwd=binding_root,
        env=env,
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 1
    assert "SBOM binding exact schema/path mismatch" in result.stderr

    bundle_root = tmp_path / "bundle"
    _write_protected_validator_fixture(bundle_root, bundles=True)
    (bundle_root / "release-candidate" / "unexpected.bundle").write_bytes(b"unexpected")
    human = _protected_validator(
        workflow, "Fresh-runner stdlib verification before human stop gate"
    )
    result = subprocess.run(  # noqa: S603 -- extracts the repository-controlled inline gate
        [sys.executable, "-c", human],
        cwd=bundle_root,
        env=env,
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 1
    assert "fresh human bundle closure mismatch" in result.stderr
    human_root = tmp_path / "human"
    _write_protected_validator_fixture(human_root, bundles=True)
    human = _protected_validator(
        workflow, "Fresh-runner stdlib verification before human stop gate"
    )
    result = subprocess.run(  # noqa: S603 -- extracts the repository-controlled inline gate
        [sys.executable, "-c", human],
        cwd=human_root,
        env=env,
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr


def _refresh_fixture_manifest(candidate: Path) -> None:
    manifest_path = candidate / "release-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    for artifact in manifest["artifacts"]:
        path = candidate / artifact["path"]
        artifact["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")


def _mutate_validator_fixture(candidate: Path, mutation: str) -> None:
    if mutation == "raw_db":
        path = candidate / "tool-metadata" / "grype-db.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        data["valid"] = False
    elif mutation == "raw_hash":
        path = candidate / "tool-metadata" / "tools.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        data["grype_db_sha256"] = "0" * 64
    elif mutation == "archive":
        path = candidate / "tool-metadata" / "grype-db.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        data["from"] += "&checksum=sha256:" + "b" * 64
    elif mutation == "sqlite":
        (candidate / "tool-metadata" / "grype-db.sqlite").write_bytes(b"tampered")
        _refresh_fixture_manifest(candidate)
        return
    elif mutation.startswith("report_"):
        path = candidate / "vulnerabilities" / "image.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        if mutation == "report_config":
            data["descriptor"]["configuration"] = {}
        elif mutation == "report_shape":
            data["matches"] = ["not-a-match"]
        else:
            data["matches"] = [{"vulnerability": {"severity": "critical"}}]
    elif mutation.startswith("sbom_"):
        path = candidate / "sbom" / "image.cyclonedx.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        if mutation == "sbom_schema":
            data["specVersion"] = "1.5"
        elif mutation in {"sbom_count", "sbom_root"}:
            binding_path = candidate / "tool-metadata" / "sbom-bindings.json"
            bindings = json.loads(binding_path.read_text(encoding="utf-8"))
            field = "cyclonedx_component_count" if mutation == "sbom_count" else "cyclonedx_root"
            bindings["payloads"]["image"][field] = 999 if mutation == "sbom_count" else "wrong-root"
            binding_path.write_text(json.dumps(bindings), encoding="utf-8")
            _refresh_fixture_manifest(candidate)
            return
        elif mutation == "sbom_root_name":
            data["metadata"]["component"]["name"] = "forged-image"
            spdx_path = candidate / "sbom" / "image.spdx.json"
            spdx = json.loads(spdx_path.read_text(encoding="utf-8"))
            spdx["name"] = "forged-image"
            spdx_path.write_text(json.dumps(spdx), encoding="utf-8")
            binding_path = candidate / "tool-metadata" / "sbom-bindings.json"
            bindings = json.loads(binding_path.read_text(encoding="utf-8"))
            bindings["payloads"]["image"]["spdx_root"] = "forged-image"
            bindings["payloads"]["image"]["cyclonedx_root"] = "forged-image"
            binding_path.write_text(json.dumps(bindings), encoding="utf-8")
        elif mutation == "sbom_root_version":
            data["metadata"]["component"]["version"] = "9.9.9"
        else:
            data["metadata"]["component"]["type"] = "application"
    elif mutation == "tools":
        path = candidate / "tool-metadata" / "tools.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        data["docker"] = "Docker version 0.0.0, build bad"
    elif mutation.startswith("uv_"):
        path = candidate / "tool-metadata" / "tools.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        if mutation == "uv_missing":
            del data["uv"]
        elif mutation == "uv_platform":
            data["uv"] = "uv 0.11.21 (aarch64-unknown-linux-gnu)"
        else:
            data["uv"] = "uv 0.11.20 (x86_64-unknown-linux-gnu)"
    elif mutation == "sdist":
        path = candidate / "tool-metadata" / "sbom-bindings.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        data["payloads"]["python"]["equivalent_sdist"]["offline_smoke"] = "failed"
    else:
        raise AssertionError(f"unknown mutation {mutation}")
    path.write_text(json.dumps(data), encoding="utf-8")
    _refresh_fixture_manifest(candidate)


@pytest.mark.parametrize(
    "mutation",
    (
        "raw_db",
        "raw_hash",
        "archive",
        "sqlite",
        "report_config",
        "report_shape",
        "report_blocker",
        "sbom_schema",
        "sbom_count",
        "sbom_root",
        "sbom_root_name",
        "sbom_root_version",
        "sbom_root_type",
        "tools",
        "uv_missing",
        "uv_platform",
        "uv_version",
        "sdist",
    ),
)
def test_both_inline_validators_reject_each_locked_evidence_mutation(
    tmp_path: Path, mutation: str
) -> None:
    workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    base_env = {
        "RELEASE_REPOSITORY": "example/tracebed",
        "RELEASE_REF": "refs/tags/v0.1.0",
        "RELEASE_COMMIT": "a" * 40,
        "BUILD_PYTHON_VERSION": "3.13.14",
        "NPM_VERSION": "10.8.2",
        "DOCKER_IDENTITY": "Docker version 29.6.2, build dfc4efb",
    }
    for gate, marker, bundles in (
        ("signer", "Independently validate manifest inventory before attestation", False),
        ("human", "Fresh-runner stdlib verification before human stop gate", True),
    ):
        root = tmp_path / mutation / gate
        _write_protected_validator_fixture(root, bundles=bundles)
        _mutate_validator_fixture(root / "release-candidate", mutation)
        script = _protected_validator(workflow, marker)
        result = subprocess.run(  # noqa: S603 -- extracts the repository-controlled inline gate
            [sys.executable, "-c", script],
            cwd=root,
            env=base_env,
            check=False,
            capture_output=True,
            text=True,
        )
        assert result.returncode == 1, f"{gate}/{mutation} unexpectedly passed: {result.stderr}"


@pytest.mark.parametrize(
    "marker",
    (
        "Independently validate manifest inventory before attestation",
        "Fresh-runner stdlib verification before human stop gate",
    ),
)
def test_both_inline_validators_reject_a_ref_tag_binding_mismatch(
    tmp_path: Path, marker: str
) -> None:
    workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    root = tmp_path / marker[:5]
    _write_protected_validator_fixture(root, bundles=marker.startswith("Fresh"))
    env = {
        "RELEASE_REPOSITORY": "example/tracebed",
        "RELEASE_REF": "refs/tags/v0.1.1",
        "RELEASE_COMMIT": "a" * 40,
        "BUILD_PYTHON_VERSION": "3.13.14",
        "NPM_VERSION": "10.8.2",
        "DOCKER_IDENTITY": "Docker version 29.6.2, build dfc4efb",
    }
    result = subprocess.run(  # noqa: S603 -- extracts the repository-controlled inline gate
        [sys.executable, "-c", _protected_validator(workflow, marker)],
        cwd=root,
        env=env,
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 1


def test_producer_normalized_actual_uv_evidence_passes_both_protected_validators(
    tmp_path: Path,
) -> None:
    """The producer's `.strip()` observation is accepted without altering raw evidence."""
    workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    observed = subprocess.check_output(["uv", "--version"], text=True).strip()  # noqa: S607 -- producer invokes the locked uv command
    assert observed == "uv 0.11.21 (x86_64-unknown-linux-gnu)"
    env = {
        "RELEASE_REPOSITORY": "example/tracebed",
        "RELEASE_REF": "refs/tags/v0.1.0",
        "RELEASE_COMMIT": "a" * 40,
        "BUILD_PYTHON_VERSION": "3.13.14",
        "NPM_VERSION": "10.8.2",
        "DOCKER_IDENTITY": "Docker version 29.6.2, build dfc4efb",
    }
    for gate, marker, bundles in (
        ("signer", "Independently validate manifest inventory before attestation", False),
        ("human", "Fresh-runner stdlib verification before human stop gate", True),
    ):
        root = tmp_path / gate
        _write_protected_validator_fixture(root, bundles=bundles)
        candidate = root / "release-candidate"
        tools_path = candidate / "tool-metadata" / "tools.json"
        tools = json.loads(tools_path.read_text(encoding="utf-8"))
        tools["uv"] = observed
        tools_path.write_text(json.dumps(tools), encoding="utf-8")
        _refresh_fixture_manifest(candidate)
        result = subprocess.run(  # noqa: S603 -- extracts the repository-controlled inline gate
            [sys.executable, "-c", _protected_validator(workflow, marker)],
            cwd=root,
            env=env,
            check=False,
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, result.stderr


def test_sbom_verifier_requires_real_root_and_component_schema(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.syspath_prepend(str(ROOT / "scripts"))
    verifier = _load("release_verifier")
    invalid = tmp_path / "invalid.json"
    invalid.write_text(
        json.dumps({"SPDXID": "SPDXRef-DOCUMENT", "packages": [{}], "relationships": [{}]}),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="invalid spdx SBOM"):
        verifier._require_sbom(invalid, kind="spdx")
    valid = tmp_path / "valid.json"
    valid.write_text(
        json.dumps(
            {
                "SPDXID": "SPDXRef-DOCUMENT",
                "name": "tracebed-runtime",
                "documentNamespace": "https://example.invalid/sbom",
                "packages": [{}, {}],
                "relationships": [{}],
            }
        ),
        encoding="utf-8",
    )
    assert verifier._require_sbom(valid, kind="spdx") == (2, "tracebed-runtime")


def test_notice_collector_requires_all_notice_files_and_never_substitutes_placeholder(
    tmp_path: Path,
) -> None:
    notices = _load("release_notices")
    package = tmp_path / "package"
    package.mkdir()
    with pytest.raises(ValueError, match="no LICENSE/COPYING/NOTICE"):
        notices._license_text(package)
    (package / "LICENSE").write_text("Apache", encoding="utf-8")
    (package / "NOTICE.third-party").write_text("Notice", encoding="utf-8")
    (package / "COPYING.LESSER").write_text("LGPL", encoding="utf-8")
    collected = notices._license_text(package)
    assert "Apache" in collected
    assert "Notice" in collected
    assert "LGPL" in collected
    assert "not bundled" not in collected.lower()
