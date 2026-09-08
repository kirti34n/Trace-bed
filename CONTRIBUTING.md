# Contributing to Tracebed

Contributions are welcome as proposed changes, but this repository does not currently promise a
review time, merge authority, or release path. Do not assume that opening an issue or pull request
creates a support relationship.

## Before changing code or documentation

1. Read [README.md](README.md), [PLAN.md](PLAN.md), [docs/CAPABILITIES.md](docs/CAPABILITIES.md),
   [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md), and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
2. Keep changes narrowly scoped and do not commit credentials, production data, raw traces, or
   personal data.
3. Add or update focused tests where behavior changes, and state the environment required to run
   them.
4. Update the capability contract when a change affects a claimed capability, its state, its
   evidence locations, or its limits.

## Capability-contract workflow

`docs/capabilities.toml` is the editable source. `docs/CAPABILITIES.md` is generated. After
editing the TOML, run:

```bash
uv run python scripts/capability_check.py --write
uv run python scripts/capability_check.py --check
```

The checker establishes only that the generated document matches the TOML and its cited paths
exist. It does not validate a deployment or authorize a release.

## Pull requests

Explain the problem, intended boundary, tests run, tests not run, documentation changes, and any
security or data-lifecycle impact. Do not use a pull request to claim production readiness without
the accountable human approvals and evidence in the release checklist.

If the change adds a host integration, the adopter owns its acceptance testing and operational
documentation. This repository ships interface definitions, not a promised host implementation.

## Release-related changes

Keep Python package version and `dashboard/package.json` version identical.
Candidate version tags are exact `vX.Y.Z` forms and are checked against both
files. Changes to workflows, dependency locks, package metadata, notices, or
release evidence must update [docs/RELEASE-POLICY.md](docs/RELEASE-POLICY.md)
and pass:

```bash
uv run python scripts/release_check.py --check
uv run python scripts/release_manifest.py check --tag v0.1.0
```

Do not add a registry token, publication destination, or a fictional reviewer to
source control. Publishing remains a protected human decision described in the
repository settings checklist.

## Decision-making

Current governance limits are in [GOVERNANCE.md](GOVERNANCE.md). Until human maintainers configure
ownership and review policy, no contributor should infer authority from a filename, historical
commit, or automated check.
