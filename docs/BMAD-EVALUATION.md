# BMAD v6.10.0 evaluation — measured against this repository's existing review methodology

**Date:** 2026-07-27
**Evaluator:** independent pass; every finding below was re-opened against the actual source before
being classified. Line references were read, not inferred.

**What was compared.** Two review methods were run over the same three surfaces:

| Surface | Files |
|---|---|
| A — hot-path retrieval | `src/tracebed/hotpath/pipeline.py`, `budget.py`, `holdout.py` |
| B — memory state machine | `src/tracebed/domain/state_machine.py` |
| C — persistence + RLS gateway | `src/tracebed/stores/pg/repo.py`, `pool.py` |

- **BMAD arm:** two skills per surface (`bmad-review-adversarial-general` "Blind Hunter", and an
  Edge Case Hunter), prompts verbatim, "at least ten issues" floor, halts on zero.
- **Control arm:** this repository's existing methodology — schema-constrained findings with
  severity, mechanism-vs-convention classification, and *applied* mutation testing against the real
  test suite.

**Classification scheme.** `REAL-NEW` (genuine defect nobody had found) · `REAL-KNOWN` (genuine but
already in `docs/FIDELITY-AUDIT.md` or the eight items in PLAN §11) · `MISREAD` (the code does not
say what the finding claims, or the stated trigger path does not exist) · `FABRICATED` ·
`STYLE` (real but cosmetic — no behavioural consequence) · `DUP` (BMAD's two layers reported the
same defect twice; counted once).

---

## 1. Headline numbers

| | BMAD | Control |
|---|---:|---:|
| Raw findings emitted | **118** | **13** |
| Intra-arm duplicates (same defect, two layers) | 23 | 0 |
| **Distinct findings** | **95** | **13** |
| REAL-NEW | 60 (63%) | 10 (77%) |
| REAL-KNOWN | 3 | 3 |
| MISREAD | 10 (11%) | 0 |
| FABRICATED | 0 | 0 |
| STYLE | 22 (23%) | 0 |
| REAL-NEW that the control arm *also* found | 6 | 6 |
| **Novel vs. control AND the 472-item fidelity audit** | **54** | **5** |
| Findings a sceptical engineer would schedule work for | ~15 | ~8 |

Two numbers matter more than the totals. BMAD's **precision** is 63% actionable with a 34%
noise floor (MISREAD + STYLE). The control's is 77% with a **zero** noise floor and every claim
backed by an applied mutation with a recorded test result. But BMAD's **recall** is roughly six
times the control's on the same surfaces, and the recall is not padding: 54 distinct real defects
that neither the control nor a nine-auditor, 472-promise fidelity audit had found.

---

## 2. Per-surface classification

### Surface A — hot path (`pipeline.py`, `budget.py`, `holdout.py`)

BMAD emitted 35 findings across two layers (16 + 19); 7 were the same defect twice → **28 distinct**.

| # | Finding (abbrev.) | Class | Verification |
|---|---|---|---|
| A1 | Total budget is cooperative: checked only *between* stages; nothing bounds `retriever.retrieve` or `assembly.run` | **REAL-NEW** | `retriever.py:205` calls `lexical_future.result()` with no timeout; `pool.py:109-114` sets no `statement_timeout`; `grep statement_timeout src/` → one docstring only. Half-disclosed: `assembly.py:31-37` names the assembly half as a known limitation, the retriever half is undisclosed |
| A2 | `_embed_bounded` can emit `embed_timeout_ms=0`; `model_copy` bypasses `Field(ge=1)` | **REAL-NEW** | `pipeline.py:662-665`; two independent clock reads (603 vs 662); `config.py:177` `ge=1`; pydantic v2 `model_copy(update=)` does not re-validate |
| A3 | `_result`'s fallback `RetrieveResult` is itself unguarded | STYLE | True as read; both failing fields (`run_id.value`, `empty_context_block()`) are re-evaluated, but no input reaches it — control reached the same conclusion independently |
| A4 | Holdout arm is escapable: `session_id` is caller-supplied, `arm` is echoed back | **REAL-NEW** (also control #1) | `pipeline.py:520-532`, `events.py:296` |
| A5 | `OutcomeCode.HOLDOUT` overwrites `store_error`/`timeout_prefix_only` | **REAL-NEW** (also control #4) | `pipeline.py:437` runs after both 395-400 and 401-412 |
| A6 | Six bare `except Exception` + two `suppress`, none logging or counting anything | **REAL-NEW** (minor) | 15 modules in `src/` use `logging`; `hotpath/pipeline.py` uses none. `store_error` is the only surviving evidence for four distinct causes |
| A7 | Clock reads inside the ladder unguarded → "two clock failures, two different outcomes" | **MISREAD** | Both paths record `store_error` (entry: `mono_start is None` leaves the default; mid-ladder: caught at 401). The claimed asymmetry does not exist |
| A8 | `budget.py` docstring says no method reports elapsed; `elapsed_ms()` exists | STYLE | Docstring precision only |
| A9 | `Deadline.total_budget_ms` is a writable attribute | STYLE | True; the object never escapes `_run_ladder` |
| A10 | Non-positive budget → `store_error` on 100% of traffic | **MISREAD** | Unreachable: `ConfigResolver.effective` rebuilds every section through `model_validate`, and `total_budget_ms`/`embed_timeout_ms` carry `ge=1`. A bad override raises `ConfigError` before `Deadline` is constructed |
| A11 | `_latency_ms` writes 0 into the same column as real measurements | STYLE | Real, documented as deliberate; the affected rows are almost always `store_error` and therefore filterable |
| A12 | `holdout_salt` unvalidated on the constructor → empty salt silently disables the kill switch forever | **REAL-NEW** (minor) | `pipeline.py:330` vs `holdout.py:81-82`; the `except` at 385 defaults to `MEMORY_ON` with no telemetry difference |
| A13 | No salt rotation/versioning; no salt fingerprint on the row | **REAL-NEW** (minor) | `holdout.py:49-63`; the contaminated interval cannot be excluded after the fact |
| A14 | `injection_log` rows written for holdout runs the agent never received | **REAL-NEW** (also control #2) | `pipeline.py:470` unconditional; control's version is stronger — it names the three consumers (`forensics.py:145,191`, `reports.py:546`) |
| A15 | Third budget check discards `assembled.injections` → asymmetric exclusion from lift | **MISREAD** | Exclusion is symmetric: a timed-out `memory_on` run also placed nothing and also has no injection row, so both buckets drop it equally |
| A16 | Retriever result read field-by-field with no shape check, unlike `StaticPrefixPort` | **MISREAD** | The asymmetry is explained by position: the retriever's result is inside the ladder catch-all (fail-open by design); the prefix value flows toward the Pydantic response |
| A17 | A NaN clock reading disables the budget entirely (`nan <= 0` is False) and records `latency_ms=0` on an `injected` row | **REAL-NEW** (theoretical) | Arithmetic verified: `min(200.0, nan) == 200.0`, `300 - nan <= 0` is False, `int(nan)` raises → `_latency_ms` returns 0 |
| A18 | Assembly seam may return a ladder outcome code; no membership check | **REAL-NEW** (theoretical) | `pipeline.py:635-637` |
| A19 | `INJECTED` with `injections=()` (or the inverse) is never cross-checked | **REAL-NEW** (minor) | `CandidateSetResult.injections` defaults to `()` |
| A20 | `injections=None` recorder → no `injection_log` ever, no startup refusal | **REAL-NEW** (minor) | Wired in `api/main.py:228`, so latent |
| A21 | `_timeout_prefix_only` makes an unbounded prefix round trip *after* the budget is blown | **REAL-NEW** (latent) | No deadline parameter; prefix cache unwired today |
| A22 | Prefix-served memories reach the prompt with **no `injection_log` row** | **REAL-NEW** (latent, good) | `_LadderResult.injections` keeps its `()` default at 690-696; `workers.lift` treats `timeout_prefix_only` as proof nothing was placed |
| A23 | `killswitch_overlay` has no enforcement point on the prefix rung (`cfg` is not passed) | **REAL-NEW** (latent, good) | The only rung returning content without passing through the assembly seam, which is where the overlay is applied (`assembly.py:171-176`) |
| A24 | `_session_key` returns `session_id` unstripped; `"abc"` vs `" abc "` are different arms | **REAL-NEW** (minor) | `pipeline.py:530-531` — `.strip()` used only for the emptiness test |
| A25 | `holdout_pct` is not in the digest → an operator edit re-randomises mid-session | **REAL-NEW** (minor) | `holdout.py:94-97` |
| A26 | A far-future `now_ms` pins `ids._last_ms` process-globally, poisoning every later id | **REAL-NEW** (theoretical) | `ids.py:130-160`: the `ms < _last_ms` branch makes all later mints inherit the wrong millisecond |
| A27 | Telemetry failure leaves `injection_log` rows with **no `retrieval_event` row** | **REAL-NEW** | `_finish` writes injections first (470) then suppresses the telemetry exception (733). Violates the file's own "exactly one `retrieval_event` row per call on every path" and drops the run from the lift join |
| A28 | `latency_ms` is measured *after* the injection INSERT and *before* the telemetry INSERT | **REAL-NEW** | `pipeline.py:470-476`: the number backing the 300 ms p99 includes a DB write that happens only on injected runs |

**Surface A totals — BMAD:** 28 distinct · REAL-NEW 20 · MISREAD 4 · STYLE 4 · REAL-KNOWN 0.

**Control on Surface A:** 5 findings · REAL-NEW 4 · REAL-KNOWN 1.
Control-unique and *not* found by BMAD: the "holdout never disables working memory" guarantee is a
mechanism on `holdout.py` (an AST import scan) and pure convention on `pipeline.py`, which is the
module that now acts on the arm — and `harness/phase1_gate.py:329-360` certifies that clause by
pooling a test file (`test_working_memory.py`) that contains zero occurrences of "holdout".
That is a **gate-integrity** finding; nothing in BMAD's instruction set looks at gates or tests.
Control's jit.py finding is self-disclosed in `jit.py:63-69` and control says so.

### Surface B — state machine (`domain/state_machine.py`)

BMAD emitted 34 findings (16 + 18); 6 duplicates → **28 distinct**.

| # | Finding (abbrev.) | Class | Verification |
|---|---|---|---|
| B1 | `TransitionLimits.archive_floor` is read by no guard; the real comparison lives in `sweeps.py:258` | **REAL-NEW** (control noted the same as a convention) | `_guard_validated_to_archived:616` reads the caller's boolean |
| B2 | `retire_q_threshold = 1.0` is config-reachable and makes the quality gate vacuous | **REAL-NEW** | `__post_init__:198-206` floors every **int** threshold and only range-checks the two floats; `1.0` passes and `q >= 1.0` is false for every real q |
| B3 | Promotion uses a bare `promotion_distinct_principals` int while quarantine exit runs the clique | **REAL-NEW** (minor) | `:563` vs `:535` |
| B4 | `same_cluster` is non-transitive; chained rewordings evade it | STYLE | The framing is confused (two confirmations need no chain) and the underlying limit is inherent to any near-dup threshold; evading it still leaves the distinct-run and distinct-principal legs |
| B5 | `ABSENT_SIGNATURE` (40 zero bytes) is automatically "a distinct cluster" from every real signature | **REAL-NEW** (strong) | `signatures.py:39` `bytes(40)` → trailing simhash 0 → hamming ≈ 32 > `SAME_CLUSTER_MAX_HAMMING`; `ShadowConfirmation.__post_init__` validates length only; `independence.build_confirmations:122-154` drops nothing for the sentinel; `ingest/trace_writer.py:656` writes it |
| B6 | Only 8 of the 40 signature bytes participate in independence | **MISREAD** | Direction is fail-**closed**: ignoring the 32 structured bytes makes more pairs "same cluster", i.e. harder to promote, not easier |
| B7 | Truncation at 256 + step-budget abort make verdicts order-dependent | STYLE | True; both bounds only shrink the result, and the caller's order is the only variable |
| B8 | `SUPERSEDED`/`RETIRED`/`PINNED` are terminal-except-erasure, contradicting "tombstoned is the only terminal status" | **REAL-NEW** (spec-level) | Enumerated the table at `:755-772`; correct. Faithful to PLAN §5, but the docstring claim is false as written and a wrongly-superseded memory's only lever is crypto-shred |
| B9 | `PINNED` is retrievable with zero ongoing governance | **REAL-KNOWN** | Named as D-014 in the file itself; fidelity audit S25 covers pinned |
| B10 | `scan_reflag` is read by one guard; a re-scan flagging a **validated** row has no expressible transition | **REAL-NEW** | Traced every outgoing `validated` edge: contradiction, invalidation/TTL/revalidation, decay, q+K, erasure. None consults `scan_reflag` |
| B11 | `stale -> validated` is one caller boolean, skipping all five promotion checks | **REAL-NEW** (minor) | `:651-657`. The missing PROPOSAL re-check is harmless (a PROPOSAL row can never reach `validated`, so never `stale`); the missing contradiction/scan-repass checks are real |
| B12 | `_TRANSITIONS` (the private dict `apply()` actually reads) is mutable by import | STYLE | True, and a fair critique of the CONTRACT ADDENDUM's rhetoric, but any module that can import a private name can monkeypatch `apply` itself |
| B13 | `apply()` takes `current` from the caller; no compare-and-swap | **MISREAD** | `stores/pg/lifecycle.py:151` binds `AND status = %(expected_from)s` and raises `StaleStatusTransition` — the sole persist path is a real CAS |
| B14 | `GuardOutcome` has no `__post_init__`; approvals carry no rationale | STYLE | True; every success returns `reason=""` |
| B15 | Eleven guards accept `limits` and never use it | STYLE | BMAD itself calls this lint-grade |
| B16 | Contract-addendum comment stranded 11 lines from its subject; `_guard_ttl_expired` defined after callers | STYLE | Cosmetic |
| B17 | `provenance_class` as a plain `str` defeats the `is`-based D-023 refusals while the `in`-based creation guard admits it | **MISREAD** | The asymmetry is real and worth knowing, but the stated trigger does not exist: `Provenance.from_json` (`memory.py:93`) coerces through `ProvenanceClass(...)` and raises on anything unknown; `shadow_validator.py:230` reads that coerced value |
| B18 | NaN `q_value` slips past `q >= threshold` and gets the memory retired | **REAL-NEW** (theoretical) | `TransitionEvidence` applies no finiteness check while `TransitionLimits` does |
| B19 | `_guard_none_to_pinned` requires neither `scan_passed` nor `provenance_complete` | **REAL-NEW** | Verified against the other two creation edges, which require both. `PINNED` is in `RETRIEVABLE_STATUSES` |
| B20 | Tombstone from any status on one unqualified boolean | STYLE | By design (erasure must reach everything) |
| B21 | `open_contradiction` / `scan_repass` are checked on `candidate -> validated` and on neither other edge into `validated` | **REAL-NEW** (minor) | `:651-657` and `:673-715` |
| B22 | Whether a passing re-verification resets `strike_count` is undefined by the machine | **REAL-NEW** (minor) | No edge emits, clears, or bounds it |
| B23 | Quarantine exit yields Tier B candidates while `:78` says "candidate: Tier A only" | **MISREAD** | Consistent by design: `search.py:181-182`'s SQL predicate is `status = ANY(...) AND (status <> 'candidate' OR trust_tier = 'A')`, so Tier B candidates are simply not retrievable until `validated` |
| B24 | Failure-lesson relaxation rests on two caller-supplied fields | STYLE | `mem_type` is fixed at creation |
| B25 | Self-corroboration is not excluded (no author principal in evidence) | **MISREAD** | `shadow_validator.py:302-322` subtracts the memory's own origin runs and their correlates before the machine is called |
| B26 | `apply(X, X)` raises the same `IllegalTransition` as a genuinely illegal edge | STYLE | True; the self-edge case is handled outside `apply()` by `LifecycleTransitionWrite` |
| B27 | `status_changed_at` in the future → negative age → TTL never fires | **REAL-NEW** (minor) | `_guard_ttl_expired:739`; only tz-awareness is validated |
| B28 | The human-verdict skip is **unreachable**: no creation edge admits `HUMAN_VERDICT` and no transition changes `provenance_class` | **REAL-NEW** (good) | Creation edges admit PARSER / DISTILLER+PROPOSAL / OPERATOR only (`:756-758`); `shadow_validator.py:230` reads the stored class. Extends fidelity audit S26, which found the `AND` but not the unreachability |

**Surface B totals — BMAD:** 28 distinct · REAL-NEW 13 · REAL-KNOWN 1 · MISREAD 5 · STYLE 9.

**Control on Surface B:** 3 findings · REAL-NEW 2 · REAL-KNOWN 1.
Control-unique, and **BMAD found neither**:
- the `validated -> archived` decay branch is arithmetically unreachable under shipped defaults —
  `0.15 + 0.35·0.95^w` stays strictly above `0.15` in IEEE754 until **w ≈ 737 idle weeks**
  (14.2 years); every test covering the branch sets `decay_pct_per_idle_week=100`. Re-derived
  independently here and confirmed against `sweeps.py:214-217,258`;
- two status-write contracts with unequal enforcement — `MemoryStatusWrite` validates, the
  `LifecycleTransitionWrite` shape the four workers actually emit has no `__post_init__` at all,
  and decay's intentional self-edge cannot route through the validating writer.

Control's `last_retrieved_at` finding is **REAL-KNOWN** (fidelity audit S21 states it verbatim);
its incremental contribution is the operator-report angle (`reports.py:478-484` orders by
`COALESCE(last_retrieved_at, created_at)`, so the surface that would reveal the inversion reports
the same wrong number).

### Surface C — persistence (`stores/pg/repo.py`, `pool.py`)

BMAD emitted 49 findings (17 + 32); 10 duplicates → **39 distinct**. Abridged (full classification
of all 39 was performed; only the non-obvious calls are shown).

| # | Finding (abbrev.) | Class | Verification |
|---|---|---|---|
| C1 | `ScopedRepo` has no lifetime invalidation — a handle escaping `Repo.tx` runs on a returned pooled connection | **REAL-NEW** | `repo.py:1636-1662`, `tx` at 454-462: the token proves provenance at construction, nothing proves liveness |
| C2 | `iter_export_rows` is a generator, so the GUC statement runs at first `next()` and the connection is pinned for the consumer's lifetime | STYLE | Real, but stated in its own docstring ("callers must exhaust or `.close()` it") |
| C3 | `SELECT * FROM {table}` in the export ships `embedding halfvec(768)` and `lexemes tsvector` | **REAL-NEW** (good) | `repo.py:1626` vs the three-reason rationale for `_MEMORY_ITEM_COLUMNS` at 254-266; columns confirmed at `0002:53,56`. Not in the fidelity audit |
| C4 | `_EXPORT_TABLES` is 5 tables; `review_queue`, `invalidation_event`, `memory_link`, `subject_key`, `spend_ledger`, … are omitted | **REAL-NEW** | `repo.py:161-167`. For an auditability product, an export without the review queue or invalidation log is not an export of what the agent learned and why |
| C5 | `project_config` / `agent_type_config` / `killswitch_state` are read through `scoped()` with no RLS policy behind them | **REAL-KNOWN** | Fidelity audit **S17** states exactly this. Also the control's headline #1 — the control's *incremental* value is the mutation evidence (three predicate deletions survive 2609 tests) |
| C6 | `agent_registration` is written `_unscoped` with a caller-supplied `project_id` and is outside RLS | REAL-KNOWN | `0003_rls.sql:50-54` deliberately excludes the 0001 registries and says so |
| C7 | The `trace_index` upsert's `DO UPDATE` overwrites `submitter_principal`, `agent_type_id` and `input_signature_hash` unconditionally from `EXCLUDED` | **REAL-NEW** (strong) | `repo.py:206-215`. `arm`, `started_at` and `outcome_status` all received careful monotonicity rules; these three did not — and these are precisely the columns `workers/independence.py:124-153` resolves a shadow confirmation's principal and signature cluster from |
| C8 | `resolve_project` joins neither `principal.revoked_at` nor `project.deleted_at`/`status` | **REAL-NEW** (also control #4) | `repo.py:466-485` vs `list_project_ids:577` and `partitions.py:58` |
| C9 | `_scalar_count` raises `NotFound` (a 404) for an internal query failure | **REAL-NEW** (minor) | `repo.py:337-343`; body differs from `_NOT_FOUND_MESSAGE` |
| C10 | Advisory-lock class convention violated by its own second user | STYLE | The two key spaces do not collide (control verified this independently) |
| C11 | Proposal-cap lock keys on `hashtext()` — 32-bit, and an undocumented internal with no cross-version stability guarantee | **REAL-NEW** (minor) | `repo.py:887-890` |
| C12 | Every list read clamps at `MAX_ROW_LIMIT` with no cursor, offset, total, or has-more | **REAL-NEW** | `list_memories` takes `limit` only (`repo.py:935-941`); rows 1001+ are unreachable and the caller is not told the view is partial |
| C13 | `list_memories(statuses=None)` defaults to every status | STYLE | Admin surface; the fail-open shape it fixed was the `[]` case |
| C14 | Proposal caps are opt-in by call site: `insert_memory_item` / `ScopedRepo.insert_memory_item` never inspect the provenance class and never take the cap lock | **REAL-NEW** | `repo.py:726-738`, `1664-1671` vs `855-911` |
| C15 | Pool sets no `statement_timeout`, no `connect_timeout`, no `idle_in_transaction_session_timeout`; nothing translates `PoolTimeout`; nothing verifies the role lacks `BYPASSRLS` | **REAL-NEW** | `pool.py:109-114`; `ConnectionPool(open=True)` does not wait for connectivity, so its docstring's "failures surface at startup" is false. This is also the missing half of A1 |
| C16 | `insert_subject_key` has no conflict handling; `get_subject_key` does not branch on `destroyed_at` | **REAL-NEW** (minor) | `repo.py:1350-1365`; a shredded subject returns a populated row whose `wrapped_kek` is empty |
| C17 | `_unscoped` is private by convention; the allowlist is edited by whoever adds the method | STYLE | The control's version of this point (ScopedRepo outside every introspection gate) is stronger and mutation-backed |
| C18 | `retrieval_event`'s PK forbids the multiple rows per run that the arm-subquery comment asserts | STYLE | The constraint is already documented in `jit.py:54-58`; the residue is a wrong comment and a dead `ORDER BY … LIMIT 1` |
| C19 | `insert_proposal_within_caps` never compares its `run_id`/`day` arguments against `item.provenance.run_id` / the clock | **REAL-NEW** (latent) | The sole caller (`agent_control.py:476-487`) passes both consistently, so this is a defensive gap, not a live bug |
| C20 | The four proposal queries carry no `status` predicate — retired/archived proposals consume cap budget forever and are returned as duplicates | **REAL-NEW** (minor) | `repo.py:280-294` |
| C21 | A project with no partitions: writes raise raw Postgres errors, reads return empty — a destroyed project and an empty one are indistinguishable on the export surface | **REAL-NEW** | Partially overlaps control #4 (which reaches the same place from the registry side) |
| C22 | `get_killswitch_overlay`'s `IS NOT DISTINCT FROM` makes a **project-wide** kill-switch row invisible to every agent-scoped resolution | **REAL-NEW** (strong) | `repo.py:1559-1574`; `0001:127-141` declares a NULL `agent_type_id` to be the project-wide overlay; `config.py:765` calls it exactly once with the resolved `agent_type_id`; `list_killswitch_state` still shows the row. The control fails **open** while the governance reader reports it applied |
| C23 | `outcome_status` merge special-cases only `PENDING` (1 of 5 members); `ended_at` prefers `EXCLUDED` while `started_at` prefers the stored value | **REAL-NEW** (minor) | `repo.py:223-226,214` — under out-of-order replay an `ok` run can be flipped back to `error` and its `ended_at` dragged backwards |
| C24 | `arm = COALESCE(subquery, trace_index.arm)` can change a stored arm | **MISREAD** | `retrieval_event`'s PK is `(project_id, run_id)` and nothing updates it, so the subquery result is stable per run. This also contradicts BMAD's own C18 |
| C25 | The standalone `Repo.upsert_trace_index` never takes the C-32 advisory lock (it lives behind `get_trace_index(for_update=True)`) | **REAL-NEW** (latent) | `repo.py:976-983` vs `997-1014`; `trace_writer` uses the safe sequence |
| C26 | `ScopedRepo` mirrors 9 of ~30 builders; anything else inside a `tx` checks out a second pooled connection | **REAL-NEW** (minor) | Deadlock at `max_size` concurrent transactions; also a read that cannot see the outer transaction's uncommitted rows |
| C27 | One NaN `cost_usd` poisons a `spend_ledger` cell permanently and the daily LLM cap never trips again | **REAL-NEW** (theoretical) | `repo.py:1238-1272` binds an unchecked `float`; Postgres `numeric` accepts NaN; `float(Decimal('NaN'))` → `nan`, and `nan >= cap` is False |
| C28 | `_json_safe` passes non-finite floats through → `json.dumps` emits bare `NaN`, i.e. invalid NDJSON mid-body after a 200 | **REAL-NEW** (minor) | `repo.py:353-376`; `retrieval_event.top_score` and `injection_log.score` are `double precision` with no CHECK |
| C29 | `injection_log`'s `ON CONFLICT (project_id, run_id, memory_id) DO NOTHING` silently drops a second injection of the same memory in one run | **REAL-NEW** | `repo.py:1224`. `jit.py:59-62` explicitly claims the opposite — that a JIT injection "gets its own row without colliding with anything the ordinary retrieval wrote for the same run" |
| C30 | `insert_outcome_event`'s `DO NOTHING` lets the first submission of an `event_id` pin the reward signal `r`; a divergent replay is dropped and reported as benign | **REAL-NEW** (minor) | `repo.py:1135-1168` |
| C31 | `get_principal_by_external_ref`'s docstring asserts `UNIQUE (kind, external_ref)`; the migration declares `UNIQUE (external_ref)` | **REAL-NEW** (also control #5) | `0001:47-56` |
| C32 | Naive datetimes are rejected on the read side (`find_runs_missing_sentinel`) and unchecked on every write side | STYLE (minor real) | `repo.py:1040-1057` vs `426-440`, `1155-1165` |
| C33 | `insert_memory_item` has no `UniqueViolation` handling for a caller-supplied `item.id`; `create_agent_type`/`register_agent` catch `UniqueViolation` but not `ForeignKeyViolation`; `insert_review_item` has no idempotency key; `mark_run_incomplete` cannot distinguish "raced" from "no such run" | **REAL-NEW** ×4 (all minor) | Verified individually |
| C34 | `scoped()` validates the *type* of `project_id`, not its provenance; enum substitution guard checks only leftover placeholders | STYLE ×2 | `agent_registration.principal_id` being the PK is what actually makes derivation sound (control's mechanism note) |

**Surface C totals — BMAD:** 39 distinct · REAL-NEW 27 · REAL-KNOWN 2 · MISREAD 1 · STYLE 9.

**Control on Surface C:** 5 findings · REAL-NEW 4 · REAL-KNOWN 1.
Control-unique, and **BMAD found neither**:
- `test_every_scoped_statement_carries_the_project_id_predicate` never inspects the SQL — it
  short-circuits on `params.get("project_id")`, so five separate deletions of the `WHERE project_id`
  predicate survive 2609 tests. The test written to defend the primary isolation control cannot fail
  for the reason it was written;
- `ScopedRepo` is outside every introspection gate (`_public_method_names` enumerates `Repo` only),
  mutation-verified with M9 (a caller-supplied `project_id` override on `ScopedRepo.get_memory_by_id`
  survives the whole suite).

---

## 3. The quota effect, measured

BMAD's adversarial skill mandates "at least ten issues" and halts on zero. The control has no quota.

| Surface | BMAD raw | BMAD distinct | REAL-NEW | STYLE+MISREAD | Control | Control REAL-NEW |
|---|---:|---:|---:|---:|---:|---:|
| A hot path | 35 | 28 | 20 | 8 (29%) | 5 | 4 |
| B state machine | 34 | 28 | 13 | 14 (50%) | 3 | 2 |
| C persistence | 49 | 39 | 27 | 10 (26%) | 5 | 4 |
| **Total** | **118** | **95** | **60** | **32 (34%)** | **13** | **10** |

**The honest reading: the quota did both.**

*It manufactured filler.* Every layer cleared the floor of ten by 60–220%, and the surplus is where
the noise is. On Surface B — the smallest file, 838 lines, and the most heavily tested — half of the
distinct output is STYLE or MISREAD. BMAD's own notes admit three items there ("unused `limits`
params", "misplaced addendum comment", "`_guard_ttl_expired` placement") "would probably not have
been raised without the floor". The pattern is consistent: the first 8–10 items of each layer are
substantive, and the tail degrades into docstring precision and Python-can't-enforce-this
observations. Two findings are also internally contradictory (C18 asserts a run cannot have two
`retrieval_event` rows; C24's premise requires that it can).

*It also forced genuine depth the control missed.* The control produced 13 findings and stopped;
BMAD produced 60 real ones. Crucially, the extra recall is not concentrated in the noise — some of
the sharpest findings in this whole evaluation (C22 project-wide kill switch, C7 trace_index
authorship overwrite, B5 `ABSENT_SIGNATURE`, C3 `SELECT *` export, A28 latency-measurement window)
sit in positions 11–17 of their layers, i.e. **inside the quota-driven tail**. A pass that stopped
at "the interesting ones" would not have reached them. The Edge Case Hunter layer in particular —
mechanical branch enumeration over enum members, float domains, optional constructor ports, and
two-clock-read races — is what produced A2, A17, A26, B18, C27 and C28, and none of that class of
finding appears anywhere in the control's output or in the fidelity audit.

Two structural defects of BMAD's instruction set showed up in the measurement, and BMAD's own
subagents flagged both unprompted:

1. **"Descriptions only, no severity, priority, or ranking."** A fail-open exception escape and a
   comment being eleven lines from its subject are rendered as peers. On a 39-item list for one
   file, that is the difference between usable and unusable output. Two of the six layers ordered
   by severity anyway, in explicit violation of the skill, "because a flat unordered list of
   sixteen items is not usable output".
2. **No verification step.** Nothing in the skill would have caught a plausible-sounding false
   claim. Four of the ten MISREADs (A7, A10, B13, B23) are exactly that shape — internally coherent
   prose that the code contradicts. Three subagents chose to open supporting files anyway and said
   so; a faithful, target-file-only execution would have shipped more false claims and missed B5
   and B1 entirely.

---

## 4. What BMAD found that the control and the 472-item fidelity audit both missed

These are the deliverable. Ordered by what a sceptical engineer would schedule first.

1. **The hot path has no cancellation anywhere.** `hotpath/retriever.py:205` calls
   `lexical_future.result()` with no timeout, and `stores/pg/pool.py:109-114` sets no
   `statement_timeout`, `connect_timeout` or `idle_in_transaction_session_timeout`. The 300 ms
   budget is checked before each stage and can never fire *during* one, so a stalled Postgres or
   embedding host blocks the agent's run for the full underlying socket timeout. PLAN §2 invariant
   2's "a run never blocks or fails because of Tracebed" is enforced against exceptions only.
   `assembly.py:31-37` discloses this for the assembly seam and calls it remaining work; the
   retriever and pool halves are undisclosed. *(A1 + C15)*

2. **`get_killswitch_overlay` cannot see a project-wide kill switch.** `0001:127-141` defines a
   NULL `agent_type_id` row as the project-wide overlay for that mem_type; the query filters
   `agent_type_id IS NOT DISTINCT FROM %(agent_type_id)s`, and `config.py:765` calls it exactly once
   with the resolved agent_type_id. A project-wide disablement is therefore never applied, while
   `list_killswitch_state` and `GET /admin/killswitch_state` show it as set. The one control an
   operator has for "stop using this memory type" fails open and the audit surface reports it
   applied. Latent only because nothing writes `killswitch_state` yet (audit S15). *(C22)*

3. **The `trace_index` upsert rewrites the independence evidence.** `DO UPDATE` sets
   `submitter_principal` and `input_signature_hash` unconditionally from `EXCLUDED`, while `arm`,
   `started_at` and `outcome_status` all received deliberate monotonicity rules. Those two columns
   are precisely what `workers/independence.py:124-153` resolves a `ShadowConfirmation`'s principal
   and signature cluster from, so any later batch carrying an existing `run_id` rewrites the
   D-020 corroboration evidence for that run. *(C7)*

4. **`ABSENT_SIGNATURE` reads as maximally independent evidence.** `signatures.ABSENT_SIGNATURE`
   is `bytes(40)`, written by `ingest/trace_writer.py:656` for a run with no `run_start`. Its
   trailing simhash is 0, roughly 32 bits from any real signature, so `same_cluster` is False
   against everything real — a run whose input was never recorded automatically satisfies the
   input-signature-cluster leg of D-020's independence proof. `build_confirmations` validates length
   only. Missing evidence reads as independent evidence. *(B5)*

5. **`/export/project` ships the embedding vector and tsvector.** `iter_export_rows` uses
   `SELECT * FROM {table}` while the same file spends twelve lines explaining why `memory_item` must
   be read through an explicit column list — reason (3) being "it makes the projection auditable —
   what leaves the repository is a fixed list". The one path that actually leaves the repository has
   no such list, and any column a future migration adds joins the export with no review. *(C3)*

6. **The 300 ms p99 is measured over the wrong window.** `_finish` writes `injection_log` first,
   *then* evaluates `latency_ms=self._latency_ms(mono_start)` as an argument to the telemetry call.
   The number includes a database INSERT that happens only on injected runs and excludes the
   `retrieval_event` INSERT and response construction — so measured latency is biased upward for
   injected runs and downward for abstaining ones, which is exactly the comparison the ladder's
   evidence rests on. *(A28)*

7. **A telemetry outage orphans injection rows.** Same ordering: injections are written first and
   the telemetry exception is suppressed, so a run can have `injection_log` rows and no
   `retrieval_event` row. That violates `_finish`'s own stated invariant ("exactly one
   `retrieval_event` row per call on every path") and silently drops the run from the lift join,
   which needs `arm` and `outcome_code` from `retrieval_event`. *(A27)*

8. **`_embed_bounded` can produce the degenerate value its docstring says is impossible.**
   `total_exceeded()` and `embed_sub_budget_ms()` are two separate clock reads; if the budget crosses
   zero between them the second returns `0.0`, `math.ceil` gives `0`, and `model_copy(update=...)`
   writes it into `RetrievalConfig` **without re-running** the `Field(ge=1)` validator. *(A2)*

9. **`injection_log`'s conflict rule contradicts `jit.py`'s stated design.** `ON CONFLICT
   (project_id, run_id, memory_id) DO NOTHING` silently discards the second injection of the same
   memory in one run; `jit.py:59-62` asserts that a JIT injection "gets its own row without
   colliding with anything the ordinary retrieval wrote for the same run". Token accounting and
   blast-radius counts both read low, with no signal that a row was dropped. *(C29)*

10. **PLAN §5's human-verdict route out of quarantine is dead code.** The skip requires
    `provenance_class is HUMAN_VERDICT`; no creation edge admits that class and no transition
    changes it, so no row the table can produce can ever take it. The fidelity audit's S26 found the
    `AND` and classified it as an unlogged tightening; it is stronger than that — the alternative
    route does not exist. *(B28)*

11. **`retirement.q_threshold` is a config-reachable weakening of the class the int floors close.**
    `TransitionLimits.__post_init__` floors seven integer thresholds against exactly this attack and
    then range-checks the two floats only. `q_threshold = 1.0` is inside `[0,1]` and makes the
    quality half of the retirement predicate vacuous for every real q. *(B2)*

12. **"Our scanner improved" has no expressible transition.** `scan_reflag` is read by exactly one
    guard (`candidate -> quarantined`). A re-scan that flags an already-`validated` or `pinned` row
    — the ordinary case of deploying a new secret/PII rule against the existing corpus — has no edge
    available; the caller must manufacture an invalidation event or a contradiction. *(B10)*

13. **Operator-created `pinned` rows skip the content scan.** `_guard_none_to_pinned` checks
    provenance class, the operator flag and `mem_type`, and requires neither `scan_passed` nor
    `provenance_complete` — the only creation edge reaching `RETRIEVABLE_STATUSES` without a scan.
    *(B19)*

14. **Every operator list view truncates silently at 1,000 rows** with no cursor, offset, total or
    has-more flag. For a product whose thesis is that an operator can see everything the agent
    learned, a project with 1,001 memories yields a view indistinguishable from a complete one.
    *(C12)*

15. **Proposal caps are opt-in by call site.** Neither `insert_memory_item` nor
    `ScopedRepo.insert_memory_item` inspects the provenance class or takes
    `PROPOSAL_CAP_LOCK_CLASS`, so D-023's per-run and per-day ceilings apply only to callers that
    remember to use `insert_proposal_within_caps` — which also never checks its `run_id`/`day`
    arguments against `item.provenance.run_id` and the clock. *(C14 + C19)*

16. **`ScopedRepo` has no lifetime invalidation** — a handle escaping its `Repo.tx` block executes
    one project's SQL, with that project's id bound as a parameter, on a pooled connection whose GUC
    may now belong to another project. The `_SCOPED_REPO_TOKEN` gate proves provenance, never
    liveness. *(C1)*

17. **The static-prefix rung, when it is built, will serve memories with no `injection_log` row and
    with no kill-switch overlay applied** — the only rung that returns content without passing
    through the assembly seam, where both are handled. Worth fixing in `prefix_builder` before it
    ships, not after. *(A22 + A23)*

Also worth logging as lower-priority real defects: `spend_add` accepts a non-finite `cost_usd` that
would poison a ledger cell permanently and silently disable the daily LLM cap (C27); `_json_safe`
passes non-finite floats to `json.dumps`, producing invalid NDJSON mid-body after a 200 (C28);
`_EXPORT_TABLES` omits `review_queue` and `invalidation_event` (C4); an empty `holdout_salt` silently
disables the kill switch forever with no telemetry difference (A12); the `hotpath` package emits no
log line or counter from any of its eight swallowed exception paths while 15 other modules use
`logging` (A6).

**And, for even-handedness: what the control found that BMAD did not.** Five items, and they are
of a kind BMAD structurally cannot reach because it reviews code and not the evidence around it:
the `validated -> archived` branch being arithmetically unreachable for 737 idle weeks under shipped
defaults; the two status-write contracts with unequal enforcement; the isolation test that asserts
on the params dict instead of the SQL (five predicate deletions survive 2,609 tests); `ScopedRepo`
being outside every introspection gate; and the Phase-1 gate certifying "working memory unaffected in
holdout arm" by citing a test file that never mentions holdout. Four of those five are findings about
*tests and gates*, not about source — and mutation testing is what produced them.

---

## 5. BMAD as a tool for this repository

### 5.1 Which of the 46 skills would earn their keep here

Roughly 35 of the 46 are greenfield planning: PRD, epics, stories, sprint planning, market research,
product brief, architecture-from-scratch. Tracebed has a 60 KB PLAN.md, 119 decision records, a
completed five-phase build, a frozen Phase-0 contract, and 79 in-code `CONTRACT GAP` comments. Those
skills would either duplicate artifacts that exist or, worse, generate a second set of planning
documents that disagrees with the first — in a repository whose *stated* audit problem
(FIDELITY-AUDIT §1) is already that two summary documents drifted out of step with the code.
They are actively negative here.

What is worth keeping is narrow:

- **The Edge Case Hunter prompt.** This is the real product. Mechanical enumeration of enum members
  against every guard that inspects them, float domain boundaries (NaN/inf/negative/zero), two-read
  races on any value derived after a check, optional constructor ports in both states, and integrity
  error classes checked against the actual DDL rather than the docstring's description of it. It
  produced findings 4, 6, 8 and half of the C-surface list above. Nothing in this repo's current
  methodology does this systematically.
- **The Blind Hunter's "take the author's own stated rules seriously and check where the code
  violates them" heuristic.** Findings 5, 9, 10 and 3 are all of that shape: a docstring or DDL
  comment asserting a property, and the code next to it not having it. This repository is unusually
  vulnerable to that failure mode precisely *because* its comments are so good — a reviewer who
  trusts the prose finds nothing. BMAD's own subagent noted this explicitly and noted that the
  skill's "assume the author was clueless" framing is counterproductive on code of this quality.

Everything else — the planning suite, the story/epic decomposition, the sprint tooling — has no job
here.

### 5.2 `bmad-code-review`'s architecture vs. what this repo already does

BMAD's orchestration is three parallel subagent layers with structured triage. That is a real
strength and it is visible in the numbers: parallel independent passes are why 118 findings came out
of three surfaces, and why the two layers on each surface caught disjoint defect classes (adversarial
prose-vs-code on one side, mechanical branch enumeration on the other). The 23 intra-arm duplicates
are the cost of that parallelism, and 23/118 is a cheap price.

What is genuinely better in BMAD's design:
- **Parallel heterogeneous layers.** Two different attack shapes over the same file found almost
  disjoint sets. This repo's methodology is a single (excellent) reviewer archetype.
- **A floor that forces the tail.** Uncomfortable to admit, but measured: five of this evaluation's
  seventeen novel findings sit in positions 11+ of their layer.

What is worse, and it is not close:
- **No severity, no ranking.** The skill forbids it. The output is unusable as-is on a 39-item
  surface, and two of six subagents broke the rule to make their output readable.
- **No verification step.** 10 MISREADs out of 95, all of them plausible-sounding. This repo's
  methodology has adversarial verification built in and produced zero.
- **No mutation testing.** BMAD never runs the test suite. Every one of the control's unique
  findings came from applying a mutation and observing that the suite stayed green. BMAD cannot
  distinguish "this guard is defended" from "this guard has no test", which on a
  security-and-governance product is the question that matters most.
- **No mechanism-vs-convention axis.** BMAD reports defects; the control reports whether a
  *guarantee* is structural or conventional. For a product sold on auditability, the second is the
  more valuable classification and BMAD has no vocabulary for it.
- **No gate/test-integrity reach.** Four of the control's five unique findings are about tests and
  gates. BMAD looked at source only.

### 5.3 Cost of adoption

2.2 MB of skills, 46 entries in `.claude/skills`, a `_bmad/` config tree, and — the real cost — a
second methodology alongside the existing one. This repository currently has exactly one review
discipline, and its documented systemic failure is *drift between parallel descriptions of the same
system*. Installing 46 skills of which ~35 assert a greenfield planning lifecycle that contradicts
PLAN.md's phase model would add a second, louder description. The `.claude/skills` namespace is
shared and unranked, so the planning skills will also be surfaced to future sessions that have no
business using them.

### 5.4 Recommendation: **adopt specific skills — two of forty-six**

Port the Edge Case Hunter prompt and the Blind Hunter's docstring-vs-code heuristic into this
repository's existing review skill as two additional layers, run in parallel with the current
adversarial-plus-mutation pass, and keep this repo's schema (severity, mechanism-vs-convention,
mutations-tried, verification-before-report) as the output contract for all of them. Do not install
the BMAD package. The justification a sceptic should accept is arithmetic, not enthusiasm: BMAD
surfaced 54 real defects on three files that a nine-auditor, 472-promise fidelity audit and a
mutation-tested control pass had both already cleared — including a kill switch that silently fails
open, an export that ships raw embedding vectors, and an independence check that treats missing
evidence as independent evidence — and it did so with 34% noise, no severity ranking, no
verification, and no ability to tell a defended guard from an untested one. The recall is worth
importing; the methodology is not, because everything BMAD lacks is exactly what this repository's
existing discipline already supplies. Take the two prompts, run them inside the existing harness,
and leave the other forty-four on the shelf.

---

## 6. Method note

Every BMAD and control finding above was re-opened against the source before classification.
Files read in full: `hotpath/pipeline.py`, `hotpath/budget.py`, `hotpath/holdout.py`,
`domain/state_machine.py`, `stores/pg/pool.py`; read in relevant part: `stores/pg/repo.py` (head,
caps, telemetry/injection, config/killswitch/export, `ScopedRepo`), `stores/pg/lifecycle.py`,
`stores/pg/search.py`, `domain/config.py`, `domain/signatures.py`, `domain/ids.py`,
`domain/memory.py`, `workers/sweeps.py`, `workers/independence.py`, `hotpath/jit.py`,
`hotpath/assembly.py`, `hotpath/retriever.py`, `workflow/agent_control.py`,
`migrations/0001_registries.sql`, `migrations/0002_partitioned.sql`, and `docs/FIDELITY-AUDIT.md`.
Control's numerical claim about the 737-idle-week archive crossing was re-derived independently and
confirmed. No source file was modified by this evaluation.
