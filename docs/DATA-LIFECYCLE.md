# Tracebed data lifecycle

## Scope of this document

This document describes source-level data paths and questions an operator must answer. It does not
turn database records into a complete security or operator audit sink, prove host delivery of a
selected context, or establish retention/deletion behavior for backups and external providers.

PostgreSQL is the durable queue and system-of-record surface. Valkey is cache/runtime data. The
SDK buffer is bounded process memory and may lose work under terminal failure or overflow.

> This lifecycle is a design and deployment checklist. It does not assert that a particular
> deployment captures every event, retains data for a stated period, or satisfies a legal regime.

Tracebed is intended to learn from execution-derived evidence. The deployment owner decides what
can be sent to the sidecar, what it means, and whether it may be retained or used for later
context. Do not treat this document as legal advice.

## Intended lifecycle

| Stage | Intended handling | Deployment-owner decision |
|---|---|---|
| Collection | A host submits run events and outcome signals through an integration boundary. | Which events are necessary, permitted, minimized, and correctly attributed. |
| Ingest | Events are validated and queued for processing. | Authentication, rate limits, rejection behavior, and audit logging. |
| Evidence storage | Raw execution evidence may be retained separately from derived memory. | Encryption, data locality, access control, retention period, backup behavior, and restoration tests. |
| Derivation | Background logic may create candidate memories from evidence. | Whether the derivation is enabled, model/provider controls, review criteria, and provenance requirements. |
| Retrieval | A host may request a bounded block of derived context or receive no block. | Identity/scoping, use in prompts, monitoring, and safe fallback behavior. |
| Review and change | Candidates may be reviewed, revised, retired, or disabled. | Who can act, what is logged, escalation, and rollback. |
| Deletion | Evidence and derivatives should be discoverable by the required scope or subject. | Deletion/erasure semantics, verification, backup expiry, and legal holds. |

## Data categories to inventory before use

- Host, project, principal, and agent identifiers.
- Run metadata, event payloads, tool input/output references, and outcome signals.
- Raw trace objects and their encryption keys or key references.
- Derived memory text, embeddings, scores, status history, and provenance links.
- Operational metadata such as timestamps, metrics, logs, queue records, and exports.

An identifier can become sensitive when combined with context. Treat raw traces and derived
memories as potentially sensitive until a deployment-specific classification says otherwise.

## Retention, access, and deletion

There is no repository-wide retention schedule. A deployment must define one for each data class,
including replicas, backups, observability systems, and third-party processors. It must also define
which identities authorize access, export, correction, disablement, and deletion.

Before enabling a data path, test the requested deletion or erasure behavior against the actual
stores and backup policy. A source-level deletion method or encrypted-storage design is not by
itself proof that a deployed copy is inaccessible.

## E2 erasure request and fencing boundary

E2 accepts a project-scoped, authenticated erasure request for either one strictly validated
subject tag or a whole project. It derives and stores only the subject digest, records immutable
request attribution from the active grant, fences the target and its currently known run/memory
closure atomically, then returns `202` only after the durable state is `fenced`. A request is not
evidence of deletion, completion, or external-system action.

While an erasure request is active, ordinary project writes are globally quiesced by the shared
activity gate and durable project/run/subject fences. Search, admin reads, reports, exports, and
worker writes must recheck the same fences through their final disclosed byte or side effect.
New subject association is server-derived from the authenticated run/memory binding; it is never
accepted as caller-provided project, grant, principal, digest, or request attribution. Unknown or
unbound material is explicitly project-attributed rather than silently treated as unscoped.

E2 intentionally does **not** execute erasure saga phases beyond `fenced`, physically delete data,
destroy subject keys through a public path, delete from object stores or third parties, provision an
erasure database login, or claim deletion from backups, operational logs, exports, or external
systems. Every accepted E2 request therefore reports the fixed, sorted limitation codes
`backups`, `external_systems`, `legacy_v1_metadata`, `operational_logs`, and `unbound_data`.
They are deployment-owner obligations and scope disclosures, not completion evidence.

A pre-activity E2 rollback is possible only through the closed/drained owner lifecycle. Any request,
runtime binding, v2 key/envelope, closure/fence transition, protected E2 activity, or ERASURE_REQUEST
grant makes that rollback unavailable. An ordinary startup does not cross this boundary: c12 requires
the explicit `cutover-0012` lifecycle action, and its pre-activity rollback requires
`rollback-0012`.

## E3 source executor and completion evidence

The unreleased c12 source also contains an E3 executor surface. It is deliberately separate from
the API and ordinary worker: only a separately credentialed deployment executor may claim a
fenced request. A claim freezes one sorted four-store manifest, records a short lease generation,
and advances a chained, append-only receipt sequence. The durable order is key destruction,
sealed trace-target enumeration, a fixed primary-store purge, delete-plus-independent-absence
verification for every manifest store, then one atomic verify/complete transaction.

Subject erasure conservatively removes every known co-mingled run and its memory closure; it does
not claim selective preservation inside a shared run or derived external index. A project request
also drops its authenticated project-bound primary partitions and leaves only minimum authority,
request, receipt, checkpoint, and destroyed-key tombstones. The `subject_key` project partition is
explicitly retained: every row was cryptographically destroyed before purge and remains durable
evidence rather than a deletable data leaf. After a project tombstone, the exact
requesting credential can read only its own bounded terminal request status; it no longer restores
normal project access.

E4 adds a local Compose activation epoch around this executor: a separately credentialed
`tracebed_erasure` login, exact HBA route, scoped S3 identity, versioning requirement, and bounded
prepublication delete-marker/version and Valkey absence proofs. It does not change the public
limitations: `backups`, `external_systems`, `legacy_v1_metadata`, `operational_logs`, and
`unbound_data` remain in force, and reaching `scope_complete` does not waive them. In particular,
the acceptance-only S3 `403` object-lock-shaped fault is refusal handling evidence, not a legal
hold, retention, backup-expiry, or post-restore absence claim.

## Change control

Update this document, [THREAT-MODEL.md](THREAT-MODEL.md), and
[`capabilities.toml`](capabilities.toml) when a change alters collected data, data recipients,
retention, trust boundaries, or derivation behavior. Human approval and deployment evidence are
required for any material expansion.

## Local-demo imported evidence

The loopback demo seeds only the versioned Validation Runs manifest through the public trace API.
Each run is labelled as imported after execution and uses a synthetic recorded timestamp so the UI
does not imply native agent telemetry. It does not seed retrieval, memory, or feedback behavior.
Its stopped lifecycle preserves state and named volumes; there is no reset claim. The fixed Compose
subnets are intentionally single-instance per supported Linux host and collision checks refuse a
conflicting route or IPAM range.
