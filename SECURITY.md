# Security policy

Tracebed does not currently publish a security contact, supported release channel, response-time
commitment, or vulnerability-reward program. No person, team, or private reporting address is
invented by this document.

The source-controlled release-evidence workflow uses short-lived GitHub OIDC
identity for candidate signing and provenance only. It does not establish a
security contact, a supported release channel, or a configured trusted publisher.
See [docs/RELEASE-POLICY.md](docs/RELEASE-POLICY.md) for the fail-closed release
boundary and [repository-settings/security-exceptions.md](repository-settings/security-exceptions.md)
for the currently empty vulnerability-exception register.

## Before public deployment or release

A responsible human organization must configure a private reporting channel, name the people or
team accountable for triage, set acknowledgement and remediation expectations, and publish the
chosen process here. Configure the corresponding repository-host security settings where
available. Track those steps in [repository-settings/release-checklist.md](repository-settings/release-checklist.md).

## Until a private channel is configured

Do not include exploit details, credentials, personal data, raw execution traces, or other
sensitive material in public issues. If you need to report a potentially sensitive problem, use a
private channel already established by the organization operating the relevant deployment. This
repository cannot promise a response until a maintainer-owned channel is published.

## Scope and disclosure

The source tree, build/release process, bundled development configuration, and deployment
integrations are all relevant to security review. Deployments have additional scope: credentials,
network controls, data stores, model providers, and host adapters. Follow coordinated disclosure
requirements set by the accountable organization; do not disclose material that could put users or
deployments at risk before that process exists.

See [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md) and
[docs/CAPABILITIES.md](docs/CAPABILITIES.md). Neither is an assurance report.
