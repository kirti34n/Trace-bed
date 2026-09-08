# Tracebed operations

> These are planning notes for local evaluation and deployment design. They are not a production
> runbook, support commitment, availability claim, or evidence that a supplied configuration is
> safe for a particular environment.

## Navigation

- [Local evaluation](#local-evaluation)
- [Owner onboarding](#owner-onboarding-for-an-existing-project)
- [SDK and request bounds](#sdk-and-request-bounds)
- [Model-provider configuration](#model-provider-configuration)
- [Loopback-only local demo](#loopback-only-local-demo)

## SDK and request bounds

The SDK keeps a bounded in-process FIFO. Its write calls append work without HTTP or JSON
serialization on the host path. A flush leases work, freezes the payload on first send, and
retains retryable failures for a later flush pass. `FlushReport.pending` includes leased and
queued work; a fully leased buffer rejects a new item rather than evicting in-flight work.

This does not provide durable client spooling, exactly-once ingress, a bounded run-sequence map,
or strict cancellation of in-progress native I/O. Server request deadlines are cooperative
absolute budgets: each boundary checks remaining time before beginning new work and narrows
database/query timeouts where supported. A pool health check, HTTP read already under way,
synchronous parsing, or provider call may finish after a request has stopped waiting.

An isolated authority/restart acceptance sequence observed one unlabeled 503 and one feedback 500
after 5004 ms; a later full run passed without a runtime change. Their cause remains unknown. Do
not treat the later run or the API-health timeout correction as evidence that either observation is
resolved.

## Model-provider configuration

Embedding and background generation share `LLMProviderConfig.base_url` and the operator-managed
key environment variable named by `api_key_env` (default `TB_LLM_API_KEY`). The default `gemini`
embedding driver sends query text to its OpenAI-compatible `/embeddings` endpoint under the
retrieval embedding sub-budget. `TB_EMBEDDING__MODEL_VERSION` is locally recorded metadata, not a
remote-version attestation: the client sends only model and input. Its configured 768-dimensional
pin is also not included in that request. Google's [embedding guide](https://ai.google.dev/gemini-api/docs/embeddings)
documents a default 3072-dimensional output and a separate output-dimensionality control. No paid
request has established that Gemini's OpenAI-compatible endpoint accepts the corresponding
control, so live Gemini compatibility and dimension validation remain open release work. The
default endpoint is Gemini's OpenAI-compatible API. A configured alternative endpoint is not a
repository-validated compatibility claim.

This source configuration does not activate a complete learned-memory loop. Operators must assess
provider data egress, cost, rate limits, credentials, model pinning, and approval policy before
enabling any background use. The retrieval hot path does not call a generative provider, but it
can call the configured embedding provider. `hash-local` avoids network calls for offline use and
is not a semantic-model substitute.

## Local evaluation

Use an isolated environment and non-production data. Review the configuration model, migrations,
and service definitions before running them. For Compose-v1 authority-runtime credentials, use
only the supported secret-file paths; never put those values in this repository, an issue report,
or a test fixture. This file-only rule does not prohibit direct-process provider configuration:
the embedding or generation client reads the operator-selected environment variable named by
`LLMProviderConfig.api_key_env` (default `TB_LLM_API_KEY`). Keep that provider key out of source,
shell history, reports, and Compose authority-runtime containers unless a deployment owner has
explicitly designed its handling.

The following is a typical development sequence, not a deployment instruction:

```bash
uv sync --locked --extra dev
uv run python scripts/capability_check.py --check
uv run pytest -q
```

Some repository tests and services require local dependencies or configuration that are not
available in every environment. Record the actual environment, results, and exclusions whenever
using a run as evidence.

## Owner onboarding for an existing project

The installed `tracebed-onboard-agent` command creates one **new** registered principal, agent
type, and explicit grants in one owner transaction. It is an owner-only one-shot command, not an
HTTP endpoint or a long-running service. It does not replay an earlier registration: retries after
an unknown result need operator investigation rather than assuming idempotency.

This repository currently has no supported public operator CLI or HTTP route for creating the
initial standalone project. Run this procedure only after an owner-controlled provisioning process
has supplied the project UUID. The loopback demo's internal provisioning is not that general
operator workflow and does not issue a reusable SDK credential.

For an API principal with the `data` role, obtain the project UUID, a non-secret key identifier,
and a random secret from the operator's secret-management process. Set them in the current
operator session without placing the secret in shell history or the command line:

```bash
export TB_ONBOARDING_PROJECT_ID='<existing-project-uuid>'
export TB_ONBOARDING_AGENT_TYPE='your-agent-type'
export TB_ONBOARDING_PRINCIPAL_KIND='api_key'
# Use a nonempty operator-generated UUID hex value; it must not contain a dot.
export TB_ONBOARDING_API_KEY_ID='<operator-generated-uuid-hex>'
# Populate this from the operator's secret-management process.
export TB_ONBOARDING_API_KEY_SECRET
export TB_ONBOARDING_GRANTS='[{"role":"data"}]'
```

Run the command from the repository root against the existing controller project only. Set
`COMPOSE_PROJECT_NAME` to that exact project before invoking it; the parameter expansion rejects a
missing value rather than accidentally creating a new Compose project. Reuse the same validated
named-secret environment supplied to the controller. Passing only onboarding environment names
avoids placing their values in the Docker command line. The wrapper derives its database route from
the mounted owner password; do not set `TB_ONBOARDING_PG_DSN` yourself. This is not a raw-Compose
repair path for a loopback demo or an incomplete deployment.

```bash
docker compose \
  --project-directory . \
  --file docker/compose.yaml \
  --project-name "${COMPOSE_PROJECT_NAME:?set this to the existing controller project}" \
  run --rm --no-deps \
  -e TB_ONBOARDING_PROJECT_ID \
  -e TB_ONBOARDING_AGENT_TYPE \
  -e TB_ONBOARDING_PRINCIPAL_KIND \
  -e TB_ONBOARDING_API_KEY_ID \
  -e TB_ONBOARDING_API_KEY_SECRET \
  -e TB_ONBOARDING_GRANTS \
  --entrypoint tracebed-compose-onboard db-bootstrap
```

The command prints public `principal_id` and `agent_type_id`. Preserve the API credential through
the operator's secret manager as `tb_sk_<key-id>.<secret>`; the command does not print it. A
`feedback` grant additionally requires its allowed `feedback_source`. Do not treat successful
registration as evidence that a deployment identity boundary, provider configuration, or host
integration is production-ready.

## Compose-v1 authority-cutover receipt

The supported local topology is Compose-v1 only. It uses the checked, ordered
`docker/postgres/pg_hba.conf` profile and requires `TB_PG_HBA_PROFILE=compose-v1` inside the
owner-only bootstrap container. Bootstrap reloads and attests the live `hba_file` and parsed
`pg_hba_file_rules` before publication, active retry, and rollback. The former
`TB_0011_INGRESS_QUARANTINED` environment override is rejected; it is not a routing proof.
The final activation transaction takes the cutover singleton lock and re-attests the already
loaded profile immediately before it publishes the two runtime logins; fresh physical probes run
after publication. A mismatch quarantines both runtime roles and their sessions. The HBA bind
mount is read-only to containers. Concurrent host-root mutation of that mounted file is outside
this local Compose security boundary and is not claimed as protected.

Run the closed lifecycle controller (`uv run python scripts/compose_stack.py start`, `upgrade`, or
`rollback`) with named local secret-file paths. It has no arbitrary host/HBA endpoint mode. The
bootstrap records the in-session migration receipt only after the exact Compose-v1 HBA proof and
requires the legacy application credential to fail a real login attempt after existing sessions
have been terminated.

The Compose bootstrap process derives its fixed owner-only route from
`TB_OWNER_DB_PASSWORD_FILE`; no bootstrap DSN, plaintext password, endpoint, or free-form HBA
input is accepted. The API and worker mount only their own password file and build their fixed
in-network route at process start. API-only `admin_key` and readiness-token files are not mounted
in the worker. Before any Docker mutation the controller accepts exactly one euid/egid-owned 0700
secret directory with the fixed 0444, non-symlink, single-link leaf set. The controller rejects
arbitrary external topology modes. On supported Linux hosts it also requires the `ip` utility and
refuses every Docker-network or host-route overlap with the fixed `10.77.10.0/29` through
`10.77.16.0/29` ranges before it can create a Compose resource. Hosts where that route inspection
cannot run are an unsupported Compose-v1 prerequisite failure, not a best-effort launch.

The authority catalog has a durable admission singleton. Every authorized queue write, retrieval
run-open, and invalidation transaction holds a shared lock on an open admission row. Upgrade or
rollback stops dashboard/API, stops the erasure executor and waits for its live lease to release or
expire, then closes admission, leaves worker running to drain all v1 work (including leased rows),
and finally stops it before the owner proof. Failure leaves admission closed. It reopens only after HBA/bootstrap/S3
success and immediately before healthy runtime publication. Runtime processes are first started
while closed and prove their fixed identity/profile through an internal controller-only readiness
path; `/readyz` and worker serving health additionally require the singleton to be open. The
owner `admission-open` action is the controller's final publication mutation, with no subsequent
fallible health probe. Any earlier publication failure stops the partial runtime and owner-proves
that admission remained closed.

`start` is only for a zero-state or owner-proven idle, drained, closed stack. It refuses any
existing API/worker/erasure/dashboard container, runtime session, or open/non-provable admission receipt
and directs the operator to `upgrade`; it never repurposes an unknown partial runtime. A current
project's fixed ranges receive no host-route exemption merely from Compose labels: the controller
authenticates all seven exact bridge networks, IPAM/gateway/internal flags, static service
attachments, container identity, and the corresponding Linux bridge device before accepting an
exact main-table route. Malformed, partial, relabelled, foreign-attached, duplicate, or
policy-table overlap is refused.

After a successful pre-activity E4 rollback, the controller restores only a closed-ready ordinary
worker so its next supported `upgrade` can authenticate and drain it before republishing. API,
dashboard, and erasure remain stopped and admission remains closed. A post-activity **0013**
rollback refusal independently re-authenticates the still-active E4 receipt, recorded executor
activity, published role shape, and closed admission before restoring that same worker for
`upgrade` recovery. An ambiguous owner-call failure is not treated as this certified refusal and
leaves the worker absent/fenced. Direct Compose removal or restart is not a recovery path.

This source-controlled Compose-v1 proof is not evidence for an arbitrary external HBA, firewall,
load balancer, TLS termination, or topology. Those controls are unsupported here and must be
independently designed and verified by a deployment owner. Run mutation through the closed
Compose lifecycle controller; the upstream yoyo CLI is read-only (`yoyo list`) only. The
repository wrapper adds an invocation receipt after live HBA proof, so a direct mutable yoyo
invocation is intentionally rejected before the authority migration takes locks. That receipt
protects against an accidental unsupported runner, not against a database owner setting an
arbitrary custom GUC.
The in-process trusted-DSN marker used to carry that receipt is likewise an internal accidental-
path guard: Python code in the same process can forge it, so it is not an authorization boundary.

## Pre-activity 0011 rollback

Rollback is a recovery operation for an activated cutover with no recorded authority activity. It
does not reopen the legacy application credential. The closed controller first stops dashboard and
API, closes admission and drains through the real worker identity, then stops worker and invokes
the one-shot owner bootstrap with the exact Compose-v1 HBA proof.
It has no rollback argument for a password, DSN, host, or other topology input.

The action commits a durable `NOLOGIN` quarantine for the retired legacy application identity and
the current API and worker runtime identities, terminates existing sessions, and proves each
configured credential is refused before it invokes exactly the repository-owned atomic 0011
rollback. It also authenticates the complete ordered yoyo
history through 0011 before it can create that quarantine, so an unknown, missing, or forged
migration-log row requires investigation rather than a role mutation. A yoyo or probe failure leaves
that outage fence and receipt in place; repeat the same action after resolving the cause. There is deliberately no
cancel-quarantine or automatic LOGIN compensation. A direct yoyo rollback without the live HBA
proof, Tracebed atomic-runner receipt, and committed quarantine is rejected. The receipt guards
against accidentally using an unsupported invocation; it is not proof against a database owner
setting a custom GUC.

## Deployment decisions a human owner must make

- Establish an identity model, project boundaries, service accounts, and least-privilege database
  roles that match the deployment.
- Decide which event fields may be captured, where raw evidence resides, how it is encrypted, and
  how retention, export, and deletion requests are handled.
- Set network boundaries, TLS, secret rotation, backup/restore testing, monitoring, alerting, and
  incident response appropriate to the environment.
- Review worker scheduling, rate limits, resource budgets, and failure behavior before enabling
  derived-memory or retrieval paths.
- Run a deployment-specific security review and use the release checklist before making a public
  reliability or security claim.

See [DATA-LIFECYCLE.md](DATA-LIFECYCLE.md), [THREAT-MODEL.md](THREAT-MODEL.md), and
[repository-settings/release-checklist.md](../repository-settings/release-checklist.md). The
capability contract classifies this repository as `not_ready` for production readiness.

## Loopback-only local demo

Use `uv run python scripts/local_demo.py start`, `status`, and `stop` as the only supported demo
commands. The launcher creates a private `.tracebed-demo/` secret/state tree, publishes the
dashboard only on a chosen `127.0.0.1` port, and persists no secret in its state receipt. It uses
the normal controller under its lifecycle lock, then runs separate owner provisioning and
ingress-only data-seeding one-shots.

The local edge accepts the exact loopback Host and Origin plus its fixed dashboard peer and Docker
loopback gateway. This blocks Host/Origin rebinding in the supported Docker publication boundary;
it is not a general reverse-proxy or public-DNS deployment pattern. The demo evidence is imported
after execution with a synthetic recorded timestamp and must not be represented as native telemetry.

`stop` fences admission and drains before fixed `down --remove-orphans`; it deliberately preserves
state and named volumes. There is no reset command. Do not delete the state directory or use raw
Compose to recover it. Only one fixed-subnet instance is supported per Linux host; the controller
rejects route/IPAM collisions. The base controller's host-route proof is a supported-Linux control,
not a claim about non-Linux deployments.

## E4 local Compose erasure deployment epoch

E4 adds a local-only Compose activation path. Migration `0013_erasure_deployment` first stages
`tracebed_erasure` as `NOLOGIN`, pins an E4 privilege/schema manifest to the latest c12 receipt,
and records a chained deployment receipt. The bootstrap container attests the committed HBA bytes,
publishes a SCRAM verifier over its own `pg-erasure` route, rejects both a cross credential and a
cross route, then records activation. A crash before that marker is retried only after the login is
quarantined to `NOLOGIN PASSWORD NULL` and its sessions are terminated.

The executor has exactly one database route (`postgres-erasure`, `10.77.16.0/29`) and one
runtime-data attachment (`10.77.14.7`). It mounts only its database password and its scoped S3
pair. Its manifest is fixed to `graph_postgres`, `trace_s3_v1`, `valkey_v1`, and
`vector_postgres`; it waits without claiming while admission is closed. Serving health is
non-destructive. Before final publication, controller-only readiness requires S3 bucket versioning
to be `Enabled`, performs a bounded version/delete-marker absence proof, and runs a bounded
nonexistent-key Valkey `UNLINK`. Seaweed's scoped erasure identity has `Read`, `List`, and
`Write` only; Seaweed's coarse `Write` permission may include object creation, so this is not a
claim of a delete-only S3 primitive.

`tracebed-erasure-worker`, `tracebed-erasure-once`, `tracebed-erasure-status`, and
`tracebed-erasure-resume` accept bounded request IDs only (and the fixed `operator_resumed` code
for resume). Resume is an append-only chained receipt, not a direct state edit. A `P0014` closure
change is recorded as `closure_changed`; the next eligible lease repeats the revision-sensitive
pass rather than weakening closure evidence.

This is local Compose activation evidence only. It makes no backup, legal-hold, OIDC, dashboard,
release, production-readiness, compliance, or post-restore-absence claim.
