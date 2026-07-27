# Tracebed — Memory Flow & Lifecycle

> Read path, write path, learning loop, and the full lifecycle of a single memory —
> from the trace it stands on to the day it is retired.
>
> Rev. 2026-07-25 · API `:8110` · Dashboard `:8111`
> Rendered version: `MEMORY-FLOW.html`

Tracebed watches every agent run, derives lessons from what actually happened, and
refuses to put anything into an agent's context until it has earned the space.

**Budgets at a glance**

| Parameter | Value | On miss |
|---|---|---|
| Total retrieval | 300 ms p99 | static prefix only, then nothing |
| Query embed | 200 ms | degrade to lexical-only |
| Abstention target | ≥ 50% of runs | inject zero dynamic tokens |
| Memory envelope | 1,200 tokens | 700 static prefix · 500 dynamic |

---

## 1. Orientation — four planes

Nothing in the hot read plane thinks. It searches, scores, and either injects or abstains
inside a fixed budget, then gets out of the way. Everything that reasons runs behind it,
in batch, reading raw traces — never summaries of summaries.

```mermaid
flowchart TB
  AG["Agent runtime"]

  subgraph HOT["1 · HOT READ — sync, 300ms p99, zero LLM calls"]
    RET["Retrieve → score → abstain or assemble"]
  end

  subgraph ING["2 · INGEST — async, never awaited"]
    TS[("Trace archive<br/>the bedrock")]
  end

  subgraph BG["3 · BACKGROUND — batch workers"]
    LEARN["Extract · distil · validate · score<br/>consolidate · invalidate · rebuild prefix"]
    ST[("Memory store<br/>governed, project-partitioned")]
  end

  subgraph CTL["4 · CONTROL"]
    OPS["Dashboard · kill switch · spend ledger"]
  end

  AG -->|"retrieve(agent, run_ctx)"| RET
  RET -->|"context_block + run_id"| AG
  AG -. "trace events · outcomes" .-> TS
  TS -->|"raw evidence — the only<br/>distillation source"| LEARN
  LEARN -->|"governed writes"| ST
  ST -->|"validated rows only"| RET
  ST -->|"vault · review queue"| OPS
  TS -->|"provenance drill-down"| OPS
  OPS -->|"auto-disable · caps · human edits"| ST
```

The workers inside plane 3 are enumerated in [§4](#4-the-learning-loop); the detailed
wiring of the read and write paths is [§2](#2-read-path--one-run) and
[§3](#3-write-path--the-trace-is-the-bedrock).

---

## 2. Read path — one run

The recommended attachment inside Atom is an audit-only fifth GATE mux modelled on
`aegisGate:8084`, with GATE performing the injection. GATE already resolves the agent
endpoint and rewrites the request, so memory reaches production agents with **zero
agent-code changes** — no codegen prompt edits, no new lint patterns.

```mermaid
sequenceDiagram
  autonumber
  participant C as Caller
  participant G as GATE :8080
  participant TB as Tracebed :8110
  participant PG as Postgres 18
  participant VK as Valkey
  participant GEM as Gemini
  participant A as Agent container

  C->>G: POST /agents/{name}/invoke
  G->>TB: POST /v1/retrieve (principal, agent, run_ctx)
  Note over TB: project_id resolved SERVER-SIDE<br/>from authenticated principal.<br/>Never caller-asserted.
  TB->>TB: mint run_id
  TB->>PG: fetch static prefix (prebuilt at consolidation)
  TB->>VK: embed-cache lookup
  alt cache miss
    TB->>GEM: embed query context (200ms timeout)
    GEM-->>TB: vector
  else timeout or error
    TB->>TB: degrade to lexical-only
  end
  TB->>PG: BM25 (vchord_bm25 + pg_tokenizer, DF via lexemes tsvector) + ANN (pgvector), project-scoped, FORCE RLS
  TB->>TB: RRF order → calibrated score → abstention + rarity gate
  alt abstain (target ≥50% of runs)
    TB-->>G: run_id + static prefix only
  else inject
    TB->>TB: budget fill · dedup · render as labelled data
    TB->>PG: write injection_log (run_id, memory_id, tokens, slot)
    TB-->>G: run_id + context_block
  end
  Note over G,A: memory block is placed LAST,<br/>after all cacheable content —<br/>otherwise it invalidates the prompt cache.
  G->>A: invoke (definition · prefix · … · MEMORY block)
  A->>G: LLM + tool calls → :8083 → Gemini
  A-->>G: result
  G-->>C: result
  A-)TB: trace events (fire-and-forget)
```

> **Load-bearing.** Abstention is *not* computed from the RRF score. RRF discards score
> magnitudes by construction — its output encodes consensus **rank**, not relevance, and a
> rank cannot be thresholded for "good enough to inject". RRF orders the candidates; the
> inject/abstain decision comes from calibrated raw signals: normalised BM25 score and
> cosine similarity.

---

## 3. Write path — the trace is the bedrock

Everything writes to the trace first. Memory is derived; run content never writes memory
directly. Nothing on the write side is awaited by the agent runtime, and an outcome event
joins its trace by `run_id` whenever it lands — an analyst disposition two days later
simply attaches.

```mermaid
flowchart LR
  A["Agent / GATE"] -->|"trace(event) — fire & forget,<br/>never awaited"| Q["Postgres queue<br/>SKIP LOCKED"]
  H["Human task resolved<br/>Deployment approve/reject<br/>Downstream event"] -->|"feedback(run_id, outcome)"| Q
  Q -->|"claim batch, at-least-once"| TW["Trace writer"]
  TW -->|"payload, encrypted<br/>per subject key"| BLOB[("Trace archive<br/>byte-immutable")]
  TW -->|"queryable index row"| IDX["trace_index<br/>+ submitter_principal<br/>+ input_signature_hash"]
  TW -->|"one row per subject<br/>seen in the run"| SUBJ["trace_subject<br/>run_id · subject_tag"]
  TW -->|"outcome row"| OE["outcome_event<br/>+ authenticated principal"]
  OE -. "joins by run_id —<br/>hours or days later" .-> IDX
  IDX -->|"derivation pool +<br/>credit-assignment ledger"| W["Background workers"]
  SUBJ -.->|"makes delete-by-subject<br/>an indexed query"| BLOB
```

---

## 4. The learning loop

Two lanes. The operational lane is pure code — parsers over execution signals — so it works
on projects where nobody ever grades the work. The quality lane exists only where a
feedback adapter does.

| Worker | Reads | Produces | Model | Cadence |
|---|---|---|---|---|
| **Extractors** | raw traces | Tier A operational lessons, derived state | none | near-real-time |
| **Distiller** | raw traces | Tier B quality lessons, episodic exemplars, semantic conclusions | Gemini 3.1 Pro | batch, novelty-gated |
| **Shadow validator** | quarantined + later outcomes | promotion to candidate | Gemini 3.1 Pro | on matching outcome |
| **Scorer** | outcome → trace → injection_log | Q updates | Gemini 3.1 Pro | ≤1 update / memory / day |
| **Consolidator** | the vault | merge, dedup, contradiction, decay, archive | none | nightly, per project |
| **Invalidator** | events, TTL, usage | stale marks, two-strike retirement | none | continuous |
| **Prefix builder** | validated + pinned | static prefix per agent-type | none | after each sweep |

> **Spec correction.** The Q update as specified in `MEMORY_PLAN.md` §9 punishes success:
> it feeds the adapter *weight* in as the reward. From the mandated start of Q = 0.5, a
> successful downstream event (weight 0.3) yields `r − Q = −0.2` and **lowers** the score.
> The weight expresses how much the signal is *trusted*, not how good the outcome was.
> Corrected form:
>
> ```
> Q ← clamp01(Q + α · w · c · (r − Q))
> ```
>
> where `r` is outcome polarity in [0,1] and `w` modulates the learning rate.

---

## 5. The life of one memory

One reconciled state machine — the spec shipped two that disagreed (§8's diagram vs §12's
status enum). Transitions are the **only** way status changes; there is no administrative
bypass in code.

```mermaid
stateDiagram-v2
  direction TB
  [*] --> Trace: every run, async
  Trace --> Extracted: parser (Tier A) / distiller (Tier B)

  Extracted --> Rejected: scan fail — injection pattern,<br/>secret, schema, incomplete provenance
  Extracted --> Candidate: Tier A · template+enum only<br/>cap 1 note per run
  Extracted --> Quarantined: Tier B · content-derived

  Quarantined --> Candidate: shadow confirmed<br/>(2 distinct runs · 1 for failures)
  Quarantined --> Candidate: provenance IS a human verdict
  Quarantined --> Rejected: contradicted by outcomes

  Candidate --> Validated: promotion predicate met · Q starts 0.5
  Validated --> Superseded: contradiction w/ equal or<br/>stronger provenance (link kept)
  Validated --> Stale: invalidation event · TTL ·<br/>revalidation fail at age R
  Stale --> Validated: re-verify pass
  Stale --> Retired: two strikes
  Validated --> Retired: Q < 0.25 after ≥4 scored uses<br/>AND ≥K distinct principals
  Validated --> Archived: decay floor 0.15 reached
  Archived --> Validated: operator restore

  Rejected --> [*]
  Retired --> [*]
```

**State legend**

| State | Meaning |
|---|---|
| `quarantined` | content-derived, **never injected** under any condition |
| `candidate` | injectable, rendered with a lower-trust label |
| `validated` | in the static prefix and the dynamic slice |
| `superseded` | validity window closed, link kept for temporal queries |
| `stale` / `archived` | out of retrieval, recoverable |
| `retired` / `rejected` | terminal |

> **Disabled at launch.** The "corroborated by 2+ independent traces" shortcut ships
> switched **off**. Independence cannot be computed from the original schema — with only
> `run_id` to distinguish rows it degrades to "submitted twice", a two-call bypass of
> shadow validation. Published measurement (GovMem, arXiv:2607.02579) puts naive
> count-based corroboration at a **0.597 false-promotion rate**. The skip re-enables once
> independence means differing `submitter_principal` **and** differing
> `input_signature_hash` cluster.

---

## 6. How a memory earns and loses its place

| Stage | Trigger | Effect on Q | Guard |
|---|---|---|---|
| Promotion | predicate met | `= 0.50` | provenance complete, or rejected at insert |
| Positive outcome | verdict · correction · downstream | `+ α·w·c·(1 − Q)` | unambiguous outcomes only |
| Negative outcome | verdict · correction · downstream | `− α·w·c·Q` | ≥ K distinct authenticated principals |
| Ambiguous / implicit | regenerated, abandoned, rephrased | no change | logged on trace, never scored |
| Idle decay | one week unused | `× 0.95` | archive at floor 0.15 |
| Retirement | Q < 0.25, ≥4 scored uses | terminal | else routed to the review queue |

The principal threshold on negative outcomes closes a live hole. Run the specified
arithmetic with `c ≈ 1` and `r = 0`: `0.5 → 0.35 → 0.245 → 0.172 → 0.120`. Four scored
uses — exactly the retirement precondition — at one update per day means **four calendar
days to retire any memory an attacker chooses**, using outcomes the system is designed to
trust precisely because they are unambiguous.

**Feedback adapters**

| Adapter | Example | Weight `w` | Role |
|---|---|---|---|
| Explicit verdict | analyst approve/reject with reasoning | 1.0 | gold; rejection reasons feed the distiller |
| Correction | human edits output before use; the diff is the signal | 0.8 | per-project integration |
| Downstream event | ticket closed, case reopened, alert re-fired | 0.3 | weak, delayed, joins whenever it arrives |
| Implicit behaviour | regenerated, abandoned, retried | 0.0 | logged only — a guessed reward is worse than none |

---

## 7. Staleness, erasure, and the end of a project

Forgetting is a subsystem, not cleanup. The success criterion is that the vault
**plateaus** while run volume keeps growing — that is what keeps per-project cost flat.

```mermaid
flowchart TB
  subgraph DRIFT["Drift defences — five triggers, one destination"]
    OK["validated"]
    EV["Platform event<br/>tool changed · fact updated · template edited"] -->|"provenance selector matches"| STALE
    TTL["TTL class expiry<br/>intel: days · environment: months"] -->|"valid_to has passed"| STALE
    REV["Usage-triggered revalidation<br/>retrieved while older than R = 30d"] -->|"async re-verify fails"| STALE
    OK -->|"new fact, equal or<br/>stronger provenance"| SUP["superseded<br/>validity window closed, link kept"]
    OK -->|"one week with no retrieval"| DEC["decay × 0.95"]
    DEC -->|"back in use"| OK
    DEC -->|"floor 0.15 reached"| ARCH["archived<br/>out of retrieval, recoverable"]
    STALE["stale — first strike"] -->|"re-verify passes"| OK
    STALE -->|"second independent failure"| RET["retired — terminal"]
    ARCH -->|"operator restore"| OK
  end

  subgraph ERASE["Erasure — two mechanisms"]
    SUB["Delete by subject"] -->|"look up trace_subject,<br/>destroy that subject's content key"| KEY["key destroyed"]
    KEY -->|"ciphertext now unreadable"| RESULT["trace object stays byte-immutable<br/>provenance chain of every<br/>derived memory stays intact"]
    PROJ["Project deleted"] -->|"LIST partition drop"| DROP["O(1) — every row,<br/>index and trace gone at once"]
  end
```

Crypto-shredding resolves a genuine contradiction in the spec: the trace is
*simultaneously* the erasure target and the audit record. Encrypting payloads under a
per-subject key means erasure is key destruction — the object stays byte-immutable, the
provenance chain of every derived memory survives, and the subject's data becomes
unreadable.

---

## 8. The boundary — what a host implements

Tracebed is a standalone service. Everything host-specific sits behind a port with a
working default, so integration is configuration plus a handful of adapter
implementations — never a fork.

Port names below are the ones in the code (`src/tracebed/adapters/ports.py`, plus
`stores/tracestore/__init__.py`), not prose names. They were all eight wrong in an earlier
version of this table — `PrincipalResolver` for `PrincipalPort`, `ObjectStore` for
`TraceStorePort`, and so on — which matters more here than anywhere else in this document,
because the user's instruction is "you create the standalone service, I will integrate with
Atom myself" and this table is the contract that integration is written against.

| Port (module) | What it answers | Default in the box | Atom implementation |
|---|---|---|---|
| `PrincipalPort` (`adapters.ports`) | who is calling | OIDC / JWKS · API key | Keycloak realm `atom`, NHI client |
| `ProjectResolverPort` (`adapters.ports`) | which project this principal belongs to | registry table, set at registration | Atom project entity |
| `FeedbackPort` (`adapters.ports`) | what counts as an outcome | verdict · correction · downstream | `/tasks/{id}/resolve`, deployment review |
| `InvalidationPort` (`adapters.ports`) | what changed in the world | HTTP webhook + polling | tool/spec/template change events |
| `LLMProviderPort` (`adapters.ports`) | generation for the workers | Gemini, OpenAI-compatible | LiteLLM via `gate:8083` |
| `EmbeddingPort` (`adapters.ports`) | vectors | Gemini (`onnx-local` is declared but raises — D-107) | Gemini; the local driver is not implemented |
| `TraceStorePort` (`stores.tracestore`) | where traces live | filesystem · S3-compatible | SeaweedFS or existing bucket |
| `AuditSinkPort` (`adapters.ports`) | where decisions are recorded | **nothing yet** — see below | HMAC-signed events |

`AuditSinkPort` has **zero implementations** in this tree and no migration creates an audit
table, so "Postgres + structured stdout" — which this table used to advertise as the default —
does not exist. No governance action (a kill-switch decision, an operator edit, a quarantine) is
recorded anywhere today. It is listed with a size in PLAN.md's known-gaps section; until it
lands, treat the audit column of any integration plan as unimplemented rather than pluggable.

**Integration options, ranked**

1. **Fifth GATE mux, GATE-side injection** — *recommended*. Audit-only, modelled on
   `aegisGate:8084`. No agent-code changes, no codegen prompt edits, ADR-009 satisfied
   literally. Costs Go changes in `gate/`.
2. **SDK inside the agent** — works, but reaches production agents through an LLM-written
   call checked by a regex lint, and misses CLI-scaffolded agents entirely.
3. **Memory as a tool behind `/tools/{name}/invoke`** — *rejected*. AgentArmor's 5 s
   pre-call timeout alone is 16× the whole retrieval budget, and it hands the model the
   decision of *when* to retrieve, which destroys the abstention economics.

---

*See also: `../PLAN.md` (architecture and phases), `../DECISIONS.md` (why each choice was
made), `../PHASE-0.md` (the executable task breakdown).*
