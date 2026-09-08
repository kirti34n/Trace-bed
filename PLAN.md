# Tracebed roadmap and evidence plan

This document describes work that could make Tracebed a useful execution-derived learning
sidecar. It is not a release plan, a statement of deployed behavior, or evidence that a capability
is safe to operate. The current, machine-readable capability states are in
[`docs/capabilities.toml`](docs/capabilities.toml); its generated view is
[`docs/CAPABILITIES.md`](docs/CAPABILITIES.md).

## Product boundary

Tracebed is intended to sit beside an agent system. The host owns invocation, authorization,
business outcomes, and final use of any returned context. Tracebed is intended to handle a
bounded subset of execution evidence and derived memory. It must not be represented as:

- a general knowledge-base or document-RAG product;
- an agent runtime or policy engine;
- an authoritative source of instructions for a model;
- proof of agent quality, safety, compliance, or business outcomes; or
- a production-ready service without deployment-specific evidence and accountable approval.

## Capability vocabulary

Each work item must update the capability contract rather than using an unqualified “done”.

| State | Required meaning |
|---|---|
| `implemented_unverified` | Code and focused tests exist; no deployment, load, or adversarial validation is implied. |
| `blocked` | A known control, operating, or validation gap prevents a responsible readiness claim. |
| `partial` | A dependency, integration, evidence source, or validation path is still incomplete. |
| `interface_only` | A port exists, but a deployment must supply and validate the implementation. |
| `not_assessed` | No independent assurance is claimed. |
| `not_ready` | A production-readiness claim is explicitly out of scope. |

## Work streams

### 1. Evidence intake and data governance

Maintain a narrow event schema, clear source attribution, project scoping, and reviewable
retention/deletion behavior. Before expanding intake, establish what a host can reliably supply
and what data it is authorized to send. Update [DATA-LIFECYCLE.md](docs/DATA-LIFECYCLE.md) when
the data contract changes.

### 2. Derived-memory safety

Treat every derived memory as fallible data. Require provenance, scopes, lifecycle controls, and
bounded retrieval. Validate that a context block is visibly data to the host, but do not market
formatting as a complete prompt-injection defense. Threat assumptions belong in
[THREAT-MODEL.md](docs/THREAT-MODEL.md).

### 3. Learning-loop evidence

Do not infer learning from component presence. For each proposed worker path, identify the
deployment-owned inputs, the expected output, failure behavior, metrics, and a test or evaluation
that can falsify the result. Keep it `partial` until the full path is demonstrated in its intended
environment.

### 4. Host integration

Keep host behavior behind typed ports. This repository does not ship a host-specific adapter.
An adopter must own adapter code, secrets, identity mapping, acceptance tests, and incident
handling. The source interface reference is [ADAPTER-GUIDE.md](docs/ADAPTER-GUIDE.md).

### 5. Release governance

Before any release claim, a responsible human organization must configure code ownership,
security reporting, issue handling, branch protections, review requirements, release signing or
provenance as appropriate, and a supported-contact path. The repository deliberately does not
invent those identities or settings. See
[repository-settings/release-checklist.md](repository-settings/release-checklist.md).

## Evidence gates

Work should stop rather than silently overclaim when any of these is missing:

1. A capability state and its limits in `docs/capabilities.toml`.
2. A reproducible check that exercises the changed behavior, with its environment stated.
3. A documented data-lifecycle and threat-model update when data, trust, or retention changes.
4. An accountable human decision for external deployment, security response, or release actions.

`python scripts/capability_check.py --check` verifies only that the generated capability document
matches the source contract. It is deliberately not a release gate.

## Near-term priorities

1. Verify actual end-to-end behavior in a controlled non-production environment and record the
   limits of that evidence.
2. Define the host integration contract and acceptance tests for a real adopter without adding
   host-specific assumptions to core code.
3. Establish ownership, security reporting, support, and release criteria before any public
   operational commitment.
4. Commission appropriate independent review before making security or compliance claims.

Historical build specifications and audits may help explain past decisions, but they are not
current capability evidence. They are labeled accordingly where retained.
