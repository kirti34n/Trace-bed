# `adapters/atom/` — the Atom integration seam

This package is documentation with type signatures attached. It contains **no integration
code** — that is an explicit decision recorded in `PLAN.md` §4 ("`atom/` — documented
interface stubs ONLY — the human writes the integration"), not an oversight or a placeholder
waiting to be filled in by a future chunk. Every class in `stubs.py` raises
`NotImplementedError` the moment it is constructed.

Read this file, then `../../../docs/ADAPTER-GUIDE.md` (the port-by-port contract), before
writing a single line of real Atom integration code.

## Why stubs, not a real adapter

Tracebed is designed to run fully featured against zero host (PLAN.md §1). Every
Atom-specific concern is already one of the eight `adapters.ports` Protocols, each with a
working shipped default. Writing a "reference" Atom implementation here would do one of two
things, both worse than not writing it:

- get frozen into this repo's test suite and CI, so a change to Atom's actual GATE mux
  shape, Keycloak realm layout, or builder-backend event format silently stops being
  reflected here, and the "reference" becomes actively misleading; or
- never be exercised against a real Atom deployment at all (this repo has neither Docker
  nor a GATE instance available to it), so it would be untested code shipped as if it were
  tested.

The human integrating Tracebed into Atom has both things this package cannot have: a live
GATE/builder-backend/Keycloak realm to test against, and the authority to change this
repo's actual adapter wiring (`api/main.py`'s `run()`) once that integration exists.

## What is stubbed, and what is not

| Atom component | Tracebed port | Stub |
|---|---|---|
| Keycloak / NHI | `PrincipalPort` | `AtomKeycloakPrincipalPort` |
| GATE muxes | `LLMProviderPort` | `AtomGateLLMProvider` |
| GATE muxes | `EmbeddingPort` | `AtomGateEmbeddingProvider` |
| builder-backend | `InvalidationPort` | `AtomBuilderInvalidationSource` |
| workflow-backend | `FeedbackPort` (downstream) | `AtomWorkflowFeedbackAdapter` |
| AgentArmor | `FeedbackPort` (downstream) | `AtomAgentArmorFeedbackAdapter` |
| policy-executor | `FeedbackPort` (verdict) | `AtomPolicyExecutorVerdictAdapter` |
| MinIO audit | `AuditSinkPort` | `AtomMinioAuditSink` |

Two ports are **deliberately not stubbed** — the shipped default already covers Atom's shape
with configuration alone, and a stub class here would be a worse starting point than the real
code it would wrap:

- **`ProjectResolverPort`.** Backed by the `agent_registration` registry table, populated by
  calling `POST /admin/agents/register` — an admin API call, not a port implementation.
  Whichever Atom component provisions a new agent (most likely GATE, at the point it first
  registers an agent's endpoint) calls that route; no Atom code needs to satisfy this
  Protocol itself.
- **`TraceStorePort`.** `stores.tracestore.s3.S3TraceStore` already speaks plain S3 REST
  against MinIO or SeaweedFS with no MinIO SDK dependency (MinIO's own OSS repo was archived
  2026-04-25 — D-036). Pointing `TraceStoreConfig` at Atom's existing MinIO bucket is
  configuration:

  ```
  TB_STORAGE__TRACESTORE__DRIVER=s3
  TB_STORAGE__TRACESTORE__ENDPOINT=<atom's MinIO endpoint>
  TB_STORAGE__TRACESTORE__BUCKET=<a bucket dedicated to Tracebed traces>
  ```

  See `docs/ADAPTER-GUIDE.md`'s `TraceStorePort` section for why the bucket should be
  dedicated (crypto-shredding and object-lock policy both apply at the bucket, not the key).

## One port with a real gap: `AuditSinkPort`

`AtomMinioAuditSink`'s docstring names this explicitly: no concrete `AuditSinkPort`
implementation exists anywhere in this codebase today, shipped default included. PLAN.md's
default ("JSON-lines to stdout plus a Postgres audit table") has no Postgres writer built
yet. This is reported as a contract_gap in `docs/ADAPTER-GUIDE.md`'s `AuditSinkPort` section,
not silently worked around here — writing a working sink in this chunk would be scope this
chunk's file list does not cover (`stores/pg/repo.py` is owned by a different chunk), and a
stub that quietly "worked" via an in-memory buffer would hide that gap instead of naming it.

## Using this package

1. Read `docs/ADAPTER-GUIDE.md` for the port(s) you are implementing: what the shipped
   default does, what your implementation must guarantee, and the failure mode if it
   doesn't.
2. Copy the relevant stub class's signature — not its body — into your own module, outside
   this repo's `adapters/atom/` package. Nothing in `src/tracebed/` outside this package
   imports it, and no gate in `harness/` does either. The one importer is
   `tests/phase4/test_archetype_configs.py::TestAtomStubs`, which imports it precisely to
   assert that it stays inert: every exported class refuses construction with
   `NotImplementedError`, and every port method it declares matches the live
   `adapters.ports` Protocol signature by AST comparison — so a stub can neither become
   accidentally usable nor quietly drift from the port it documents.
3. Wire your real implementation into `api/main.py`'s `run()` / `workers/runner.py`'s `run()`
   the same way `docker/compose.yaml`'s `api` service wires the shipped defaults — through
   `domain/config.py` fields and `AppDeps`, never by editing a hot-path or worker module to
   special-case "when running inside Atom".
