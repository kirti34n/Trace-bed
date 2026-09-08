# Tracebed threat model

> This is a threat-model starting point, not a security assessment, penetration test, compliance
> attestation, or guarantee. The capability contract records independent security assurance as
> `not_assessed`.

## Assets and security objectives

The relevant assets may include raw execution traces, derived memories, embeddings, credentials,
encryption material, project/principal mappings, queue contents, exports, configuration, and
operational logs. A deployment should protect confidentiality, integrity, availability, and
appropriate deletion of each asset according to its own risk assessment.

The intended security objectives are to keep data within authorized project scopes, preserve
provenance for derived content, avoid treating memory as instruction, and let a host abstain or
fall back when the sidecar is unavailable. These are design objectives—not a certification that
they hold in a particular environment.

## Trust boundaries

| Boundary | Examples | Questions to answer before use |
|---|---|---|
| Host to sidecar | SDK, API, adapter ports | How is the caller authenticated and scoped? Which fields are trusted, derived, or rejected? |
| Sidecar to data stores | Database, queue, object store, cache | Which service account can read/write each class? Are network and encryption controls tested? |
| Sidecar to model/provider | Embedding or background model service | Which data leaves the environment, under which contract, and with what logging/redaction? |
| Operator to control surfaces | Admin, exports, review actions | Who is authorized, how is access reviewed, and what is audited? |
| Repository to release channel | CI, package, container, Git hosting | Who approves changes and releases, and how is provenance established? |
| E3 executor to destructive stores | Dedicated DB role, filesystem/S3, Valkey, vector, graph credentials | Can a lease-limited executor delete and independently prove absence without exposing locators or provider errors? |
| Loopback local demo | Browser, dashboard proxy, local edge, separate demo key | Is publication limited to the exact loopback Host/Origin and fixed Docker ingress boundary, without exposing the demo key to browser code? |

## Threats to assess

- Forged or mis-scoped identity causing cross-project access.
- Sensitive data in traces, derived memory, logs, exports, backups, or third-party providers.
- Prompt injection or malicious execution content influencing a later host run.
- Poisoned outcomes or repeated submissions distorting derived memory or scores.
- Replay, duplicate, oversized, or malformed event traffic exhausting resources or corrupting
  attribution.
- Compromised dependency, CI credential, package, image, operator account, or adapter.
- Missing deletion propagation, incomplete backup expiry, or mistaken legal-hold behavior.
- Retrieval or background failures that create availability, cost, or integrity surprises.
- A rogue external writer, object lock/legal hold, bucket-versioning ambiguity, or cache/index
  repopulation making an erasure proof incomplete.
- Reuse of an API/ordinary-worker credential for destructive erasure, or logging a subject, trace
  locator, lease token, receipt digest, endpoint, or provider exception during an erasure failure.

## E3-specific trust assumptions

The source executor assumes a future production deployment provisions a separate database login and the
minimum destructive credentials for its configured manifest. It treats every external delete as
unproven until a second absence check succeeds, and it fails closed on unsafe filesystem paths,
ambiguous S3 versioning, object-lock/legal-hold refusal, unavailable adapters, or a lost lease.
E4 supplies an authenticated local-Compose epoch for implementation and prepublication evidence only; it is not a production deployment, external-store authorization, backup deletion, or legal-hold control.

The repository does not provision that production login, networking, object-store policy, or a defense
against a rogue writer holding independent store credentials. Those are deployment trust
boundaries and retain the `blocked` capability state.

## Required deployment responses

For each enabled path, document the threat owner, controls, residual risk, monitoring signal,
incident action, and verification evidence. Apply least privilege, secret rotation, input limits,
network segmentation, scoped authorization, and audit logging where appropriate to the deployment.
Test failure and recovery paths, not only the happy path.

## External model-provider operation

Tracebed can be configured with an operator-paid OpenAI-compatible endpoint, including the default
Gemini-compatible endpoint. The configured embedding driver can send retrieval query text to its
`/embeddings` endpoint; background judge/distiller use is separate and is not evidence of an
enabled learning loop. Treat every configured provider as a data recipient until the deployment
owner documents the exact endpoint, model/version, key custody, request content, retention terms,
regional handling, spend controls, and incident response. Arbitrary compatible-endpoint behavior
is not validated by this repository.

Do not rely on text delimiters, type hints, source inspection, or passing unit tests as a complete
defense against hostile content or a substitute for independent review. See
[SECURITY.md](../SECURITY.md) for the repository's current reporting limitation.

## Local-demo boundary

The local demo has a deliberately narrow DNS-rebinding boundary: the edge requires one exact
`http://127.0.0.1:<port>` Host and Origin, the fixed dashboard peer, and the Docker gateway used
for loopback-published browser traffic. It holds a separate API key server-side and mints an opaque
HttpOnly browser cookie. It does not expose that key, browser-readable session id, or production
OIDC configuration. This is source/test evidence for a local Docker path only, not a public-origin,
TLS, reverse-proxy, or production-session assurance.
