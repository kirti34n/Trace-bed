## Summary

Describe the problem and the bounded change.

## Validation

- [ ] I listed tests/checks run and their environment.
- [ ] I listed tests/checks not run and why.
- [ ] I did not include credentials, raw traces, personal data, or other sensitive material.

## Capability and risk impact

- [ ] I reviewed `docs/capabilities.toml`; any changed claim, state, evidence, or limit is updated.
- [ ] I ran `uv run python scripts/capability_check.py --check` if the contract or generated view changed.
- [ ] I updated `docs/DATA-LIFECYCLE.md` and/or `docs/THREAT-MODEL.md` if data or trust boundaries changed.
- [ ] I described any deployment, security, or release decision that still needs accountable human approval.

## Notes for reviewers

Do not approve a production-readiness, support, security, or governance claim without the human
authority and evidence required by `repository-settings/release-checklist.md`.
