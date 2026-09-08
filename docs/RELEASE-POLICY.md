# Release evidence and publication policy

This repository contains a source-controlled candidate-release workflow, not a
configured distribution channel or release authority. It is intentionally
fail-closed: an existing immutable `refs/tags/vX.Y.Z` must peel to the exact
checked-out commit and match `GITHUB_SHA`; the tag must exactly match both
package manifests; locked Python and npm dependency graphs must install; tests,
licence, static, artifact, image-policy, harness, and Compose checks must pass;
and the workflow builds each Python, dashboard, and container payload once.

The workflow generates separate SPDX and CycloneDX SBOMs for the image, locked
Python environment, and locked dashboard dependency graph. It scans each graph,
retains machine-readable vulnerability reports and pinned tool-version metadata,
and blocks known `high` and `critical` findings. No exception is currently approved.
Any future exception must be explicit, time-limited, reviewed by the accountable
security and release authorities, and recorded in
[`repository-settings/security-exceptions.md`](../repository-settings/security-exceptions.md).
This source policy does not itself configure those people, permissions, or a
scanner waiver mechanism.

Each payload, SBOM, resolved third-party notice inventory, vulnerability report,
and tool record is hash-bound in a portable manifest rooted at the candidate
bundle (not the checkout path). The manifest records the exact repository, tag
ref, and peeled commit. The build/test/scan runner has only `contents: read`.
The distinct `tracebed-release-signing` protected environment must approve the
minimal OIDC/attestation job before it receives immutable artifacts; the later
`tracebed-release` environment needs separate protected reviewers before any
human publication decision. Neither reviewer set nor the required tag-protection
rule is configured by this source snapshot. That job
does not execute candidate-provided verification code. It signs the fixed,
manifest-derived subject list and stores provenance verification outside that
subject tree. Both it and the fresh human gate use the GitHub CLI's supported
repository, certificate identity, source ref, source digest, and JSON output
checks. The `tracebed-release` environment remains the final human stop gate.

The wheelhouse is generated from hash-locked runtime and build requirements
without the editable project entry, then is used to install and smoke-test both
the wheel and sdist offline. SBOM bindings tie each of the image, installed
Python runtime, and installed dashboard runtime graphs to its payload digest.
Exactly those three graphs are scanned at the `high` threshold. Grype database
state/digest/time and the pinned tool/runtime versions are retained as
machine-readable, manifest-bound evidence.

There is deliberately no `twine upload`, `npm publish`, container push, GitHub
release creation, or trusted-publisher destination in the workflow. After a
human approves the protected gate, the workflow stops. A release authority must
review the retained evidence, configure a verified destination using GitHub OIDC
trusted publishing or equivalent documented keyless identity, and perform the
publication under the approved operating process. Do not add a long-lived token
to make this workflow publish.

The artifact smoke inventory deliberately names deadline admission and its neutral budget
protocol alongside authority/runtime sources. This ensures a built wheel and sdist contain the
same reviewed request-boundary code as the checkout; it is an artifact-parity check, not proof of
deployment behavior or hard cancellation.

## Local candidate checks

Run these checks from a fresh repository root after installing the locked
development dependencies:

```bash
uv run python scripts/release_check.py --check
uv run python scripts/release_manifest.py check --tag v0.1.0
uv run python scripts/capability_check.py --check
```

`release_manifest.py` can write and verify a source-bound artifact hash manifest,
but it does not build, sign, scan, upload, or publish anything. The protected
gate uses only runner `python3` and the immutable evidence artifact, not a
checkout virtual environment. Candidate evidence is not a production-readiness,
security-assurance, support, or deployment claim.
