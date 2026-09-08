# Release and repository-settings checklist

> Complete this checklist with accountable humans and deployment-specific evidence. Checking a
> source-level test is not enough to establish production readiness.

## Ownership and collaboration

- [ ] A human organization has named its maintainers, merge authority, and release approvers.
- [ ] `.github/CODEOWNERS` has real owners for the paths that require review.
- [ ] Branch and tag protection require the intended reviews and passing checks; release tags may
      be created or moved only by the accountable release authority.
- [ ] Issue/PR triage, conduct enforcement, and support routes are published and staffed.

## Security and supply chain

- [ ] A private security-reporting channel and response policy are configured in the repository host.
- [ ] Security ownership, dependency-update process, and vulnerability triage are documented.
- [ ] Release artifacts have the required provenance/signing and a verification procedure.
- [ ] Both `tracebed-release-signing` (before OIDC) and `tracebed-release` (before any human
      publication decision) have distinct accountable protected-environment reviewers. Both remain
      not configured by this source snapshot.
- [ ] Any GitHub OIDC trusted-publisher subject/destination is configured and independently
      verified; this source snapshot configures neither an identity nor a destination.
- [ ] High/critical vulnerability handling follows `security-exceptions.md`; any exception is
      approved, time-limited, mitigated, and recorded before publication.
- [ ] Secrets are managed outside version control and rotation/revocation has been tested.
- [ ] A deployment-specific threat assessment and appropriate independent review have been completed.

## Data and operations

- [ ] Data categories, lawful/authorized use, retention, deletion, backup, export, and provider
      obligations are documented for the deployment.
- [ ] Authentication, authorization, project scoping, least-privilege roles, network controls, and
      audit logging have been tested in the target environment.
- [ ] Capacity, failure modes, recovery, monitoring, alerting, on-call ownership, and rollback have
      been exercised for the enabled components.
- [ ] Host integrations and any model/provider data transfer have deployment-owned acceptance tests.

## Capability and release decision

- [ ] `uv run python scripts/capability_check.py --check` passes and the states/limits are accurate.
- [ ] Test results identify their environments and known exclusions.
- [ ] A human release authority has reviewed remaining risks and explicitly approved the release.
- [ ] Release notes, supported versions, and support/security contacts are accurate before publication.
- [ ] The retained release evidence has been re-verified under the protected human gate; only then
      may an approved operator publish to a configured destination.
