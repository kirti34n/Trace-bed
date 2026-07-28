<div align="center">

# Tracebed

**Project-scoped learning memory for AI agents.**

Memory whose purpose is that agents *get better at their job over time* — not a knowledge base
with a vector index bolted on.

[![tests](https://img.shields.io/badge/tests-4%2C420%20passed%20%C2%B7%20live%20stack-2ea44f)](#testing)
[![mypy](https://img.shields.io/badge/mypy--strict-clean%20%C2%B7%20158%20files-2ea44f)](#testing)
[![ruff](https://img.shields.io/badge/ruff-clean-2ea44f)](#testing)
[![isolation](https://img.shields.io/badge/cross--project%20leak%20suite-7%2F7%20live-2ea44f)](#the-eight-invariants)
[![python](https://img.shields.io/badge/python-3.13-3776ab)](#quick-start)
[![postgres](https://img.shields.io/badge/postgres-18%20%2B%20pgvector%20%2B%20vchord__bm25-336791)](#quick-start)
[![licence](https://img.shields.io/badge/licence-Apache--2.0-blue)](#licence)

</div>

---

## What Tracebed is

Every agent run writes a raw trace. Background workers distil those traces into governed memories.
A fail-open hot path injects only the memories that have earned the right to occupy context.

It is memory **of running**, not a knowledge base. It stores conclusions, lessons, exemplars and
baselines derived from execution — never documents. Every derived memory points down to the raw
trace that produced it, and any row without complete provenance is **rejected at insert**.

```mermaid
flowchart TB
  AG["Agent runtime + SDK"]
  subgraph HOT["1 · HOT READ — sync, 300ms p99, zero generative LLM calls"]
    RET["retrieve → fuse → abstain or assemble → render"]
  end
  subgraph ING["2 · INGEST — async, never awaited"]
    TS[("Trace archive<br/>the bedrock")]
  end
  subgraph BG["3 · BACKGROUND — batch workers"]
    LEARN["extract · distil · validate · score<br/>consolidate · invalidate · rebuild prefix"]
    ST[("Memory store<br/>governed, project-partitioned")]
  end
  subgraph CTL["4 · CONTROL"]
    OPS["Dashboard · kill switch · spend ledger"]
  end
  AG -->|"retrieve(agent_type, run_ctx)"| RET
  RET -->|"context_block + run_id"| AG
  AG -. "trace events · outcomes" .-> TS
  TS -->|"raw evidence — the only<br/>distillation source"| LEARN
  LEARN -->|"governed writes"| ST
  ST -->|"validated rows only"| RET
  ST -->|"vault · review queue"| OPS
  TS -->|"provenance drill-down"| OPS
  OPS -->|"auto-disable · caps · human edits"| ST
```

**Four planes.** A synchronous hot-read plane on a 300 ms p99 budget with no generative LLM call in
its import graph. An ingest plane where every write is fire-and-forget. A background plane of batch
workers that do the actual learning against the trace archive. A control plane: dashboard, kill
switch, spend ledger.

**Two lanes.** An LLM-free operational lane that works everywhere, and a quality lane that exists
only where a feedback adapter exists. *A guessed reward is worse than none*, so ambiguous signals
are logged and never scored.

**Two trust tiers.** Tier A is parser-derived and structural. Tier B is content-derived and
quarantined until confirmed by ≥2 runs from **distinct principals *and* distinct input-signature
clusters** — both, because either alone is trivially forged.

**The project is the wall.** `project_id` is derived server-side from the authenticated principal
and is *never* accepted from a caller. Isolation is enforced three ways at once — a typed repository
with no scope-less constructor, `FORCE ROW LEVEL SECURITY`, and LIST partitioning — and the
cross-project leak suite proves it against a live database under the non-privileged application role.

---

## Status

Tracebed's signature is calibrated honesty: it states plainly what runs, what is verified, and what
is deliberately not-yet-running. The stack **runs against a real Postgres 18** — migrations apply,
the full suite (offline **and** integration) is green against the live database, and cross-project
isolation is *proven*, not merely asserted against SQL text.

**Working and verified against the live stack**

- **The schema.** `migrations/0001`–`0006` apply cleanly to Postgres 18; roles, RLS, LIST partitions
  and per-project indexes are provisioned per project.
- **Cross-project isolation.** The 7-probe leak suite passes under the `NOBYPASSRLS` `tracebed_app`
  role: a connection scoped to one project sees **zero** of another's rows across every partitioned
  table. (The owner bypasses RLS and would hide a leak — so the suite refuses to run as the owner.)
- **Hybrid retrieval.** True BM25 lexical ranking via the `vchord_bm25` extension (with
  `pg_tokenizer`), ANN via pgvector `halfvec`, fused with RRF and gated by abstention
  (rarity / cosine / BM25). Per-term document frequency for the rarity gate is read from a `lexemes`
  `tsvector` column via `@@`/`plainto_tsquery` — **not** from `vchord_bm25`, which exposes no IDF
  accessor. The extensions ship in migration `0001`; the tokenizer config and `content_bm25` column
  in `0005` (the mandated `pg_textsearch` was a phantom extension, replaced — D-140).
- **The learning-plane store layer.** All seven worker store ports are implemented under `stores/pg/`
  and wired onto the `LearningPlane` composition root, so each worker can be constructed against its
  live store.
- **The periodic scheduler.** `build_scheduled_jobs` schedules three per-project jobs — `embedder`,
  `sweeps`, `prefix_builder` — plus `gc` **process-wide** (queue health is unpartitioned, so
  iterating projects would report the same numbers N times). A fourth per-project job,
  `corroboration`, joins them only when the host supplies a `CorroborationCandidateSource`; the
  deployed `run()` passes `None`. The builder **refuses to return** if any worker is dropped without
  a recorded reason.

**Complete but deliberately not-yet-running**

Several stages that turn recorded evidence into a validated memory are logic-complete and have live
stores, yet stay **unscheduled on purpose** — because their remaining driver is not this
repository's to invent, and *a worker scheduled-but-inert is worse than one honestly unscheduled.*
Each is named with its exact blocker in `workers/composition.py::UNSCHEDULED_WORKERS`, and
`build_scheduled_jobs` refuses to return if a worker is dropped without one. The blockers fall into
three honest categories:

- **Host-supplied ports** you provide at deployment: `RevalidationCheckPort` (what counts as
  re-verified is deliberately your policy — D-113), `ContributionJudgePort`,
  `TracePrincipalLookupPort`, `LLMProviderPort`.
- **Under-specified evidence schemas** — a decision left open, not a guess made: the
  promotion/retirement `select_*` predicates, the scorer's outcome→trace→injection→memory candidate
  join (M7), an `invalidation_event` drain cursor, a day-bucketed lift feed for the kill switch.
- **One store still to design:** `MemoryLinkStorePort` for the consolidator.

`python harness/closed_loop.py` walks all **nine hops** of the learning loop end-to-end and passes —
the loop **composes**. It runs against in-memory fakes (using the same production functions and
`Protocol`s) and prints every unscheduled worker beside the blocker that stops it, so "the loop
composes" is never mistaken for "the learning plane is live for these stages." That distinction is
the one this section exists to convey.

Full requirements audit: [`docs/FIDELITY-AUDIT.md`](docs/FIDELITY-AUDIT.md). Architecture and open
work, one item at a time: [`PLAN.md`](PLAN.md) §11.

---

## The eight invariants

The load-bearing promises. Each has a proving test; the audit checked whether each test would
actually go red if the invariant broke.

| # | Invariant | Enforced by | Proof |
|---|---|---|---|
| 1 | **Hot-path purity** — no generative client reachable from `hotpath/` | `scripts/purity_check.py`, import-graph reachability with a third-party allowlist | CI-blocking |
| 2 | **Fail-open, budgeted** — 300 ms p99, degradation ladder, never blocks a run | `hotpath/pipeline.py` + `budget.py`; client wait on the arms **and** server `statement_timeout` across both arms and the assembly stage | 6-way fail-open drill |
| 3 | **Render-as-data** — memory enters context as a labelled data block, never instructions | `hotpath/templates.py` closed grammar | 40-payload fuzz corpus |
| 4 | **Project isolation** — enforced at query construction, in RLS, and in partitioning | Typed repo + `FORCE ROW LEVEL SECURITY` + LIST partitions | **7-probe leak suite, green on the live DB under `tracebed_app`** |
| 5 | **Async writes** — nothing on the write side is awaited | SDK ring buffer | 0.04 ms p99 with the API down |
| 6 | **Provenance-complete-or-rejected** | `validate_provenance` before the statement is built + `NOT NULL` backstop | Exhaustive class × field matrix |
| 7 | **Tier B quarantine** — nothing content-derived is retrievable until confirmed | One state machine, no admin bypass | 4-probe red team, verified on the live DB |
| 8 | **No guessed rewards** — `Q ← clamp01(Q + α·w·c·(r − Q))` | `workers/scorer.py`, `w = 0` short-circuits | Verified by hand arithmetic |

> **On invariant 3, stated plainly:** render-as-data is a *governance* control, not an anti-poisoning
> one. Delimiting is the weakest spotlighting variant — ~50% ASR reduction non-adaptive, >95% ASR
> adaptive ([arXiv:2403.14720](https://arxiv.org/abs/2403.14720)). The code says so where an engineer
> will read it.
>
> **On invariants 6–7, precisely:** provenance completeness (`validate_provenance` + the `NOT NULL`
> backstop) and status membership are enforced as *mechanism* at the insert door; the state
> machine's *creation* guard is enforced by convention — it holds because callers route through
> `apply()` first, not because `insert_memory_item` re-checks it (see [Current gaps](#current-gaps) §3).

---

## Quick start

Postgres is on **5442** and Valkey on **6389** so the stack cannot collide with anything already
running on your machine. The compose Postgres image bundles `pgvector`, `vchord_bm25` and
`pg_tokenizer`; the latter two require `shared_preload_libraries` (pgvector does not), already set
in `docker/compose.yaml`.

```bash
uv venv --python 3.13 .venv && source .venv/bin/activate
uv pip install -e ".[dev]"

docker compose -f docker/compose.yaml up -d          # PG18 (pgvector + vchord_bm25) + Valkey + SeaweedFS
export TB_STORAGE__PG_DSN="postgresql://tracebed_owner:tracebed_dev_only@localhost:5442/tracebed"
python -m tracebed.stores.pg.migrate apply           # applies 0001..0006 (roles are created by initdb)

export TB_STORAGE__VALKEY_URL="valkey://localhost:6389/0" TB_EMBEDDING__MODEL_VERSION=dev-pin
pytest -q                                            # 4,420 passed · 1 skipped (S3 env-gated)
python harness/closed_loop.py                        # the learning loop, composed, with its scope note
```

The migration runner is a small CLI — `python -m tracebed.stores.pg.migrate <command>`:

| Command | Effect |
|---|---|
| `apply` | Apply every unapplied migration `0001..0006` in order |
| `list` | Show each migration and whether it is applied |
| `rollback` | Roll back the most recently applied migration |
| `rollback-all` | Roll back every migration (teardown) |

<details>
<summary><b>Dashboard</b> — React 18 + Vite + TypeScript + Tailwind on :8111</summary>

```bash
cd dashboard
npm ci
npm run dev            # proxies /v1, /admin and /export to :8110
npm run build
node scripts/license_check.mjs
```

No view is fixture-backed — every one is live or honestly empty;
[`dashboard/README.md`](dashboard/README.md) has the exact per-view table.

</details>

Ports: API **8110**, dashboard **8111**, Postgres **5442**, Valkey **6389**, S3 **8333**.

---

## Testing

The full suite runs offline **and** against the live stack; RLS-sensitive tests connect as the
non-privileged `tracebed_app` role (the owner bypasses RLS and would hide a leak).

```bash
pytest -q                            # 4,420 passed · 1 skipped, against live PG + Valkey
mypy                                 # --strict, 158 files, clean
ruff check src tests harness scripts # clean
python scripts/license_check.py      # dependency policy (Apache/permissive + one logged LGPL)
python scripts/raw_sql_lint.py       # no SQL execution outside stores/pg/
python scripts/purity_check.py       # invariant 1, by import-graph reachability
```

Full run against the live stack: **4,420 passed / 1 skipped (S3 env-gated) / 0 failed**;
`mypy --strict` clean on **158 files**; `ruff` clean; the cross-project leak suite **7/7** under the
`NOBYPASSRLS` `tracebed_app` role.

Each gate script carries a `--self-test` proving it actually bites — written that way after two of
them shipped defects that made them pass on input they should have rejected.

---

## Repository layout

```
src/tracebed/
  domain/        newtypes, the ONE state machine, config, canonical hashing, signatures
  core/scans/    the shared gate suite — every write path must present a ScanVerdict
  crypto/        per-subject crypto-shredding (erasure that coexists with an immutable archive)
  stores/pg/     typed repo, RLS, partitions, migrations, search (BM25 + ANN), the worker stores
  stores/valkey/ working memory + tool cache, key schema tb:{project_id}:…
  hotpath/       retriever · fusion · abstention · assembler · renderer   [purity-gated]
  ingest/        trace_writer · outcome_intake
  workers/       extractors · distiller · scorer · shadow_validator · killswitch · composition · scheduler
  api/           FastAPI :8110
  sdk/           fire-and-forget client, ring buffer
  adapters/      ports + shipped defaults; adapters/atom/ is STUBS AND DOCS ONLY
dashboard/       React 18 + Vite + TS + Tailwind (:8111)
harness/         leak suite · red team · soak · benches · the closed-loop drill · gate runners
migrations/      plain SQL, yoyo   (0001 registries · 0002 partitions · 0003 RLS · 0004 lifecycle · 0005 BM25 · 0006 Q-ledger)
```

---

## Documentation

| Document | What it is |
|---|---|
| [`PLAN.md`](PLAN.md) | Architecture, the eight invariants, the data model, the config surface, five phases. **Authoritative.** |
| [`docs/FIDELITY-AUDIT.md`](docs/FIDELITY-AUDIT.md) | 472 promises audited against the original spec, with the current-state verdict per item. |
| [`docs/BMAD-EVALUATION.md`](docs/BMAD-EVALUATION.md) | The independent BMAD evaluation pass and the defects it surfaced. |
| [`DECISIONS.md`](DECISIONS.md) | Append-only decision log; a reversal is superseded, never edited. |
| [`docs/OPERATIONS.md`](docs/OPERATIONS.md) | Running it: migrations, the partition ceiling, erasure, reading a lift report. |
| [`docs/ADAPTER-GUIDE.md`](docs/ADAPTER-GUIDE.md) | Implementing each host-supplied port. |
| [`docs/MEMORY-FLOW.md`](docs/MEMORY-FLOW.md) | Read path, write path, lifecycle, host integration. Diagrams. |
| [`docs/ARCHETYPE-CONFIGS.md`](docs/ARCHETYPE-CONFIGS.md) | Three real starting configurations, each field annotated with *why*. |
| [`docs/PHASE0-CONTRACT.md`](docs/PHASE0-CONTRACT.md) | The isolation/security contract fixed in Phase 0 — the retrofit-expensive decisions. |
| [`docs/SESSION-HANDOFF.md`](docs/SESSION-HANDOFF.md) | Where the repo lives, its verified state, and what to do next. |

---

## Design decisions worth knowing

<details>
<summary><b>Six bugs found in the original specification, and what shipped instead</b></summary>

<br>

| # | The spec said | Why it was wrong | What shipped |
|---|---|---|---|
| 1 | Feed the adapter **weight** in as the reward | From Q=0.5 a *successful* event (w=0.3) gives `r−Q=−0.2` and **lowers** the score | `Q ← clamp01(Q + α·w·c·(r−Q))`; weight scales the *learning rate*. 0.5 → **0.545** where the old formula gave 0.44 |
| 2 | Use `ts_rank` for the lexical arm | nDCG@10 **0.07** vs BM25's **0.69** on BEIR SciFact; the rarity gate *is* an IDF computation `ts_rank` cannot provide | True BM25 via **`vchord_bm25`** on Postgres 18; the rarity gate reads document frequency from a `tsvector` column |
| 3 | Vault must **observe** a plateau in a 30-day soak | `ln(0.3)/ln(0.95) ≈ 164 days`. Arithmetically unpassable | A trend assertion plus a computed projected plateau date |
| 4 | Threshold **RRF output** for abstention | Rank is not a relevance magnitude — rank 1 of a bad set looks identical to rank 1 of a good one | Abstention from calibrated raw signals; the fused object exposes no thresholdable scalar |
| 5 | Static prefix placed **after** dynamic memory | Destroys prompt-cache economics on *every* call | `placement: "append_last"` — the dynamic block goes last |
| 6 | A state diagram *and* a status enum | Two different machines | One state machine; the transition table is the test source |

*The mandated `pg_textsearch` extension was a seventh phantom — it does not exist. Replaced by
`vchord_bm25` + `pg_tokenizer` (D-140).*

</details>

<details>
<summary><b>Stack choices that were forced, not preferred</b></summary>

<br>

- **Postgres 18** — `vchord_bm25` (true BM25) needs it, and BM25 replaced `ts_rank` for the reason above. The mandated `pg_textsearch` was a phantom extension; document frequency for the rarity gate comes from a `lexemes` `tsvector` column via `@@`/`plainto_tsquery`, not from `vchord_bm25` (which exposes no IDF accessor).
- **Valkey, not Redis** — Redis relicensed to RSALv2/SSPL, which the licence gate denies.
- **SeaweedFS, not MinIO** — MinIO's OSS repo was archived; the driver speaks *generic S3* and imports no vendor SDK, so legacy MinIO still works.
- **psycopg 3** — the mandated driver; its LGPL-3.0 licence rides the policy's one conditional tier with a written rationale.
- **Gemini by default**, behind `LLMProviderPort` / `EmbeddingPort`. Any OpenAI-compatible gateway is one config line.

</details>

<details>
<summary><b>What Tracebed will never do</b></summary>

<br>

- Cross-project retrieval or aggregation of memory content — including "anonymised" aggregation.
  *(Spend and latency metering may roll up to org: billing metadata, the one explicit exemption.)*
- Accept `project_id`, feedback weights, or holdout arm assignment from any caller.
- Concatenate memory text into system-prompt instructions.
- Change a status outside the state machine. **No admin bypass exists in code.**
- Make a synchronous generative-LLM call that an agent runtime waits on.
- Store or execute runnable code; do knowledge-base RAG over documents.
- Score from ambiguous signals, unpinned models, or across scoring epochs.
- Swap the embedding model silently — re-embedding is an explicit, versioned migration.

</details>

---

## Current gaps

Stated here rather than left to be discovered; full detail in [`PLAN.md`](PLAN.md) §11 and the
per-worker reasons in `workers/composition.py::UNSCHEDULED_WORKERS`.

1. **The stages from "evidence recorded" to "validated" are not yet scheduled.** Their stores exist
   and are wired, but `revalidation`, `scorer`, `shadow_validator`, `distiller`, `promotion`,
   `invalidator`, `killswitch`, `consolidator` and `derived_state` each await a host-supplied port, an
   under-specified evidence schema, or (consolidator) one store still to design (`MemoryLinkStorePort`).
   See [Status](#status).
2. **The 300 ms p99 is not yet load-proven.** The fail-open drill's stalls come from a `FakeClock`;
   the bound is wired end-to-end (client wait on the arms + server `statement_timeout` across both
   arms and the assembly stage) but wants a populated vector arm under real load to measure.
3. **The insert door enforces creation guards by convention, not mechanism.** `insert_memory_item`
   checks status membership and provenance fields, not the state machine's creation guard; the guard
   holds on callers that route through `apply()` first.
4. **`adapters/atom/` is stubs and docs only** — host integration is intentionally left to the host.

---

## Licence

[Apache-2.0](LICENSE). Every Python dependency clears `scripts/license_policy.toml` and every npm
dependency clears `dashboard/scripts/license_check.mjs` — both enforced as **CI step 1**, because a
dependency tree is cheapest to reject before anything is built on top of it.
