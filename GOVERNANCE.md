# Governance

Tracebed has no named maintainer group, steering body, voting process, or release authority
published in this repository. This is intentional: the repository must not fabricate people,
teams, or contact channels.

## Current rule

Automated checks and historical commits can provide technical evidence, but they do not grant
authority to merge, release, approve a security exception, or make a support commitment. Those
actions require an accountable human organization.

The repository can request the `tracebed-release-signing` and `tracebed-release`
protected environments during a candidate workflow, but source cannot configure
their reviewers, tag/branch rules, or trusted-publisher ownership. Neither
environment is currently configured by this snapshot. An approval is meaningful
only after accountable humans configure and operate those settings.

## Required before formal operation

That organization should publish:

- who can triage issues, merge changes, approve releases, and respond to security reports;
- how conflicts, conduct reports, and security exceptions are handled and appealed;
- branch protection, review, signing/provenance, and dependency-update policy;
- the supported versions and release/deprecation policy; and
- contact paths that it is prepared to operate.

The repository-host settings to configure are listed in
[repository-settings/release-checklist.md](repository-settings/release-checklist.md). Once those
human decisions exist, replace this statement with the approved governance policy rather than
implying that a placeholder is functional.
