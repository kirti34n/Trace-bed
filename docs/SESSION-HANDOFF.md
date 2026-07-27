# Session handoff

Everything a fresh session needs to continue Tracebed without re-deriving it. Written after the
live-database bring-up. **If the numbers below disagree with what you measure, trust your
measurement and update this file** — a stale handoff is worse than none, because it gets believed.

---

## 1. Where things are

| | |
|---|---|
| Working copy | `/home/kirito/Trace-bed` (WSL2, Ubuntu, native ext4 — not `/mnt/c`) |
| Remote | https://github.com/kirti34n/Trace-bed |
| Branch | `live-db-bringup` (six commits ahead of `main` at `ff618bf`; merged into `main` in this session) |
| venv | `uv`-managed CPython 3.13 — always use `.venv/bin/python`, never bare `python3` |
| Stack | `docker/compose.yaml`: Postgres 18 (pgvector + vchord_bm25) on **5442**, Valkey on **6389**, SeaweedFS on **8333** |

**Docker in this WSL session:** the daemon runs, but if a shell predates the `docker` group, prefix
commands with `sg docker -c '…'`, or `wsl --shutdown` + reopen so `docker` works bare.

```bash
cd ~/Trace-bed
export TB_STORAGE__PG_DSN="postgresql://tracebed_owner:tracebed_dev_only@localhost:5442/tracebed"
export TB_STORAGE__VALKEY_URL="valkey://localhost:6389/0" TB_EMBEDDING__MODEL_VERSION=dev-pin
.venv/bin/python -m tracebed.stores.pg.migrate apply     # 0001..0006 (now a real CLI)
.venv/bin/python -m pytest -q
```

---

## 2. Verified state

Measured against the live stack (fresh `down -v` → migrate → run):

| Check | Result |
|---|---|
| `pytest -q` (offline + integration) | **4,420 passed, 1 skipped** (S3 env-gated), 0 failed |
| `mypy` (strict) | clean, **158 source files** |
| `ruff check src tests harness scripts` | clean |
| Cross-project leak suite (probes 1–7, as `tracebed_app`) | **7/7** — isolation holds on a real DB |
| Migrations `0001`–`0006` | apply cleanly to Postgres 18 |
| `harness/closed_loop.py` | 9/9 hops (composes, against fakes — prints its own scope note) |

---

## 3. What this session did (six commits, all pushed)

1. **Live DB bring-up + greened the never-run suite.** Fixed the PG18 compose volume mount
   (docker-library #1259) so the stack boots; migrations now apply against real Postgres; the
   integration + isolation suites ran for the first time. Fixed a real `WorkQueue.claim()` bug
   (`UPDATE … RETURNING` doesn't preserve a subquery's `ORDER BY`) plus a batch of never-run test bugs.
2. **BM25 lexical arm (D-140).** The mandated `pg_textsearch` was a phantom; replaced with real
   `vchord_bm25` + `pg_tokenizer` (migration `0005`). Document frequency for the rarity gate comes from
   the `lexemes` tsvector. Adversarial review caught — and this fixed — a schema-`USAGE`/`SELECT` grant
   gap that broke every insert/search under the app role.
3. **Wired the 11 workers' Postgres store ports** (migration `0006`, `memory_q_update` ledger). Seven
   new stores under `stores/pg/`, each `scoped()` + explicit `project_id`, isolation-tested as
   `tracebed_app`. Constructed on `LearningPlane` in `workers/composition.py`.
4. **Scheduled `sweeps` + `prefix_builder`** via the reused `ConfigResolver` + new
   `Repo.list_agent_type_ids` + a Valkey `StaticPrefixCachePort`. Kept the host-/spec-blocked workers
   honestly unscheduled.
5. **Added a real `migrate` CLI** and brought the README + this handoff current for the merge.
6. **Hardened the isolation tests + swept stale `pg_textsearch` prose** (`ff618bf`). Made the four
   Postgres-store isolation tests discriminative — seed both projects under the owner (BYPASSRLS)
   pool so a dropped `project_id` predicate goes red — and replaced phantom-`pg_textsearch` /
   "nothing has run against a real DB" prose across the reference docs with the real `vchord_bm25` +
   `pg_tokenizer` story (genuinely historical passages kept behind dated superseding notes).

---

## 4. What to do next

- **Unschedule-blocked workers need spec/host decisions, not more wiring.** Each is named with its
  blocker in `workers/composition.py::UNSCHEDULED_WORKERS`: host ports (`RevalidationCheckPort` D-113,
  `ContributionJudgePort`, `TracePrincipalLookupPort`, `LLMProviderPort`), under-specified evidence
  schemas (promotion `select_*`, the scorer M7 join, an `invalidation_event` drain cursor, a
  day-bucketed lift feed), and one store to design (`MemoryLinkStorePort` for the consolidator).
- **Review follow-ups (open):** the `shadow_validator` `is_failure_lesson` fail-safe (needs a trusted
  column, a schema decision); the gate runners (`harness/phase*_gate.py`) still emit hardcoded "no
  Docker/Postgres, tests skip" boilerplate that is false when run against a live stack — the reports
  were regenerated in `ff618bf` but the runners' caveat must be made conditional on the real stack.
- **Review follow-ups (closed in `ff618bf`, see §3.6):** the isolation-test-fidelity gaps are closed —
  the four Postgres-store tests (`scoring`, `shadow_validator`, `memory_lifecycle`, `derived_state`)
  now seed both projects under the owner pool and go red if a `project_id` predicate is dropped; and
  the stale `pg_textsearch` prose has been swept from `PLAN.md` / `PHASE-0.md` /
  `docs/{FIDELITY-AUDIT,MEMORY-FLOW,OPERATIONS}.md`.
- **Nobody has read this code by hand.** Agents wrote, audited, and adversarially reviewed it; the
  reviews found real bugs, but a human read of the hot path, state machine and isolation layer is
  still owed.

---

## 5. Bugs worth not reintroducing

- **The owner DSN bypasses RLS.** `tracebed_owner` is `SUPERUSER`/`BYPASSRLS`; the test `pg` fixture
  uses it (tests self-migrate, which needs the owner). Any test that asserts an RLS wall must derive a
  `tracebed_app` connection (`make_conninfo(dsn, user="tracebed_app", …)`) — otherwise it proves
  nothing, and green stays green while isolation is broken.
- **Extension functions run SECURITY INVOKER.** `vchord_bm25`/`pg_tokenizer` `tokenize()` reads config
  tables under the *caller's* privileges, so the app role needs `USAGE` on the schemas **and** `SELECT`
  on `tokenizer_catalog`'s tables — schema `USAGE` alone raises "permission denied for table tokenizer".
- **`plainto_tsquery` empties English stopwords.** A naive document-frequency count returns 0 for
  stopwords, which the rarity gate would read as maximally rare — report empty-tsquery terms at full
  corpus frequency instead.
- **A worker scheduled-but-inert is worse than honestly unscheduled.** `build_scheduled_jobs` refuses
  to return if a worker is dropped without a recorded reason; keep `validate_worker_coverage` passing.

---

## 6. Documents, in reading order

| Document | Read it for |
|---|---|
| [`README.md`](../README.md) | What Tracebed is; status; quick start |
| [`PLAN.md`](../PLAN.md) | Authoritative architecture, invariants, data model, config. §11 = open work |
| [`docs/FIDELITY-AUDIT.md`](FIDELITY-AUDIT.md) | 472 requirements audited against spec |
| [`DECISIONS.md`](../DECISIONS.md) | Append-only decision log — supersede, never edit |
| [`docs/OPERATIONS.md`](OPERATIONS.md) | Running it: migrations, partitions, erasure |
| [`docs/MEMORY-FLOW.md`](MEMORY-FLOW.md) | Read path, write path, lifecycle diagrams |
