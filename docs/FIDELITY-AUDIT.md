# Fidelity Audit — Tracebed (project "Strata")

**Question:** how true is the built system to what was originally asked for, and where it is not,
was the deviation deliberate and logged, or silent?

**Authorities, in order:** `CLAUDE_CODE_PROMPT.md` (build prompt) → `MEMORY_PLAN.md` (original
spec) → `PLAN.md` (successor plan, wins by design) → `DECISIONS.md` (94 entries, the audit trail
that was supposed to justify every disagreement).

**Method:** nine auditors, one fidelity dimension each, 472 discrete promises checked against code
rather than docstrings. Findings deduplicated and re-verified here. Read-only pass; nothing was
edited. Claims below carry `file:line`.

---

## 1. Verdict

The **rules** were built with unusual fidelity and the **runtime** was not. Every invariant, guard,
formula, threshold and template the two plans name exists as correct, typed, tested code: the state
machine matches PLAN §5 row for row (`domain/state_machine.py:753-770`), the composite score is
0.40/0.30/0.15/0.15 read from config, the renderer is a closed grammar fuzzed against a 40-payload
corpus, provenance-or-rejection fires before the INSERT is built, the project wall is a type-level
constraint checked by signature introspection, and all six of PLAN.md's "known corrections" to the
original spec shipped exactly as logged. Where the plan overrode the spec on substance it was
usually logged and usually right — D-011 fixes a Q formula that arithmetically punished success,
D-010 relaxes an unmeetable 100 ms budget into an observable degradation ladder, D-019 removes
attacker bytes from Tier A notes. **But the learning half of the system is a library, not a
service.** There is no `UPDATE memory_item` statement anywhere in `src/` (`workers/edit_ops.py:204`
says so outright); `workers/runner.py:422` starts the worker process with `handlers={}`;
`memory_link`, `derived_state`, `killswitch_state` and `scoring_epoch` are created, partitioned and
RLS-protected with no writer at all; `insert_memory_item` writes no embedding, so the ANN arm of
"hybrid retrieval" can never have data; nothing appends `shadow_confirm_runs`, the only non-human
route out of quarantine; and retrieval filters on `project_id` and status and on nothing else, so
§5's scope model is unenforced. A deployed Tracebed today ingests traces and outcome events
faithfully and learns nothing from either. Around that, three process failures: **not one of the
five mandated phase STOPs occurred** (all six gate reports were generated inside 58 seconds, 11:27:48
→ 11:28:45 on 2026-07-26, after Phase 4 was complete), **the repository has zero commits**
(`git rev-list --all --count` = 0), which makes the test-first mandate and DECISIONS.md's
append-only guarantee permanently unauditable, and **the audit trail's last two entries are now
false** — D-093 rejects three report routes that exist at `api/reports.py:181,442,522` and D-094
declares three dashboard views deleted that are present and routed at `dashboard/src/App.tsx:74-76`,
with no superseding entry. Net: strong specification fidelity, weak wiring fidelity, and a
disclosure layer that is honest per-site (79 in-code `CONTRACT GAP` comments) but systematically
incomplete in the two summaries a reader actually consults — PLAN.md's "none of them silent" open-items
list and DECISIONS.md itself.

---

## 2. Scorecard

Counts are per-dimension classifications of all items checked. Items not called out individually by
an auditor are counted as MATCHES. The right-hand columns double-count issues that span dimensions;
the deduplicated distinct-issue counts are given below the table.

| # | Dimension | Checked | Matches | Logged dev. | **Silent dev.** | Missing | Extra | Unverif. | Strength |
|---|---|---:|---:|---:|---:|---:|---:|---:|---|
| 1 | Build prompt: 12 hard rules, layout, phase STOPs, never-build list | 38 | 20 | 5 | **8** | 4 | 1 | 0 | mixed |
| 2 | MEMORY_PLAN §§1–9 (types, scope, hot path, write path, learning) | 42 | 16 | 5 | **7** | 13 | 0 | 1 | **weak** |
| 3 | MEMORY_PLAN §§10–19 (lifecycle, stack, security, tunables, surface) | 74 | 53 | 6 | **8** | 7 | 0 | 0 | mixed |
| 4 | PLAN §2 — the eight load-bearing invariants | 26 | 21 | 1 | **3** | 0 | 0 | 1 | **strong** |
| 5 | PLAN §5/§6 — data model, DDL, state machine, config surface | 122 | 105 | 4 | **6** | 5 | 2 | 0 | **strong** |
| 6 | PLAN §7/§8/§9 — five phases, 32 gate clauses, cuttables, backlog | 74 | 54 | 2 | **12** | 4 | 2 | 0 | **weak** |
| 7 | PLAN §10 never-do list, security posture, Atom seam | 23 | 11 | 1 | **8** | 3 | 0 | 0 | mixed |
| 8 | DECISIONS.md integrity + gate-report honesty | 47 | 26 | 1 | **17** | 1 | 0 | 2 | **weak** |
| 9 | The user's own spoken instructions (9 directives) | 26 | 19 | 0 | **3** | 3 | 0 | 1 | mixed |
| | **TOTALS** | **472** | **325** | **25** | **72** | **40** | **5** | **5** | |

**Deduplicated:** 72 raw silent deviations collapse to **49 distinct issues**; 40 raw missing items
collapse to **23 distinct**; 5 extra items collapse to **6 distinct** (one auditor's EXTRA was
another's unlogged placement). Ratio that matters: **25 logged deviations against 49 silent ones —
the audit trail captured roughly one deviation in three.**

---

## 3. The eight invariants (PLAN §2)

Security reviewers start here. "Mechanism" means a structural control that an implementation change
cannot quietly route around; "convention" means the code is correct today and nothing would catch it
becoming wrong.

| # | Invariant | Mechanism or convention | Proving test | Does it bite? |
|---|---|---|---|---|
| 1 | No generative LLM client reachable from `hotpath/` | **Mechanism** — `scripts/purity_check.py:172-206` is a real AST reachability walk; CI step 3 (`.github/workflows/ci.yml:37-40`) | `--self-test` + gate | **Yes, verified by mutation.** An auditor injected `import openai` into `hotpath/assembler.py` (3 violations, exit 1) and a purely *transitive* edge via an allowlisted module (`stores/pg/search.py → workers/scorer`) — also caught. Two documented narrowings: `--root` is a dead flag (`purity_check.py:242-270` parses it and iterates a hardcoded `hotpath` glob), and "no provider SDK" is an **11-name denylist** (`:47-60`) — `import groq` in `hotpath/` passes. |
| 2 | Fail open, 300 ms budget | **Mechanism for the ladder, convention for the number** | `tests/phase1/test_degradation_ladder.py` (44 tests), `harness/failopen_drill.py` | Ladder: yes — each rung maps to a guard in `hotpath/pipeline.py:360-410,546-580` and D-061 records that removing each one turns a test red. **The 300 ms p99 is proven by nothing**: every stall is `FakeClock.advance()`, nothing kills Postgres, D-035(a) made the bench non-gating, and D-062(d) admits the bench's vector arm measures zero rows. |
| 3 | Render as data | **Mechanism**, the best-designed control in the tree | `tests/phase1/test_renderer_property.py` (89 tests, 40+ payload corpus at `tests/fixtures/injection_payloads/payloads.jsonl`) | Yes. Closed grammar + `json.dumps(..., ensure_ascii=True)` means no payload can emit a line break, forge a header, or smuggle a bidi override. `renderer.py:70` is the only producer of a non-empty context block, so there is no second path in. Correctly *disclaimed* as an anti-poisoning control in five places (D-026). |
| 4 | Project isolation impossible at query construction | **Mechanism for `Repo`, convention for `ReportsRepo`** | `tests/phase0/test_repo_scoping.py:70` (introspects the *type*, not the name), `test_repo_isolation_offline.py:333,343,390`, `scripts/raw_sql_lint.py` (CI step 2) | For `Repo`: yes, three independent layers. **Two holes:** `ReportsRepo`'s seven builders over partitioned tables (`stores/pg/reports.py:237-537`) have no GUC-first/predicate test at all; and leak-suite probe 4 (`harness/leak_suite/test_leaks.py:293-302`) greps route paths for the substring `"dashboard"` — the dashboard shipped and talks to `/admin/*` and `/v1/*`, so the tripwire can never fire, yet `gate_report_full.md` reports it PASS and asserts "no dashboard app exists in this tree yet". |
| 5 | Async writes, ≤1 ms p99 | **Mechanism** | `tests/phase0/test_sdk_client.py:221` measures a real p99 with a dead server | Yes. Measured 0.041 ms trace / 0.018 ms feedback. Honest scope limit: it proves the SDK boundary; a server handler that started awaiting a write would not turn it red. |
| 6 | Provenance-complete or rejected | **Mechanism**, in the strongest available form | `tests/phase0/test_repo_provenance.py:73,92,154`; `test_repo_isolation_offline.py:435` asserts **no SQL statement is issued at all** | Yes. `repo.py:708-719` runs `validate_provenance` → `content_hash` → `verify_verdict` in fixed order with neither exception caught; `domain/memory.py:139` treats `()` as absent. |
| 7 | Tier B quarantine, no admin bypass | **Mechanism for transitions, absent for creation** | `tests/phase0/test_state_machine.py:785,829,871,884` — illegal edges generated as the exhaustive product; the table's immutability is itself tested | Transitions: yes, the strongest suite in the repo. **Creation: no.** `Repo.insert_memory_item` validates provenance and the scan verdict and then binds `item.status.value` straight through (`repo.py:721-782`); `migrations/0002_partitioned.sql:45-49` CHECKs against all nine statuses. A caller can insert a directly-retrievable `validated` row having never called `apply()` — while `domain/memory.py:155-158` and `:168-170` both assert "the repository re-checks that the status is a legal creation status". It does not. |
| 8 | No guessed rewards | **Mechanism**, all three clauses | `harness/guessed_reward.py:102,143,178` (row-level equality); `tests/phase3/test_scorer_q_update.py:167,265,464`; `tests/phase0/test_api_scope.py:359` (422 on a caller `weight`) | Yes, and fail-closed beyond the promise (negative/NaN/>1 configured weights resolve to 0 rather than inverting Q, `workers/scorer.py:211-250`). **But** the harness has no `def test_*` and is not named `test_*.py`, so pytest never collects it, its only caller is `phase3_gate.py`, and no CI job runs that gate — so the prompt's "CI-blocking from Phase 3 on" is unmet. |

**Auditor disagreement, resolved.** Dimension 4 rated invariant 7 MATCHES and dimension 7 rated the
never-do clause "change a memory's status outside the state machine" MATCHES; dimension 1 called the
unguarded insert a critical bypass. **I side with dimension 1.** Both readings are factually correct
at different layers — the transition table genuinely is immutable and untamperable, and no status
*write* exists anywhere — but a creation path that accepts `Status.VALIDATED` with no re-check is
exactly the door the invariant names, and the code asserts in two docstrings that the door is shut.
Dimension 7's "MATCHES, vacuously, because no write exists at all" is the sharper framing of the
same tree.

---

## 4. Silent deviations

The findings that matter. A logged deviation is a decision; a silent one is an accident. 49 distinct,
grouped by kind.

### 4.1 Process and audit trail

**S1 — The five phase STOPs never happened.** The prompt made human approval a precondition for each
next phase and D-035 (`DECISIONS.md:109`) records "the five phase STOPs remain non-negotiable". All
six gate reports were generated inside 58 seconds *after* Phase 4 was complete: `11:27:48`, `11:27:51`,
`11:27:56`, `11:28:00`, `11:28:45`, `11:28:45`. Each still ends with retroactive STOP text
(`gate_report_phase0.md:136`, `phase1:100`, `phase2:123`, `phase3:152`, `phase4:181`). No approval
record exists in any form. Consequence: every decision from roughly D-038 onward — the hot path, both
learning lanes, promotion, the kill switch, all of Phase 4 — was made without the review that was
supposed to gate it. `gate_report_phase3.md:143` conditions its own central "never reaches validated"
clause and was built past in the same minute.

**S2 — DECISIONS.md's last two entries are false about the shipped tree.** D-093 (`DECISIONS.md:378`)
rejects alternative (b) verbatim: adding `/admin/lift/report`, `/admin/staleness/report`,
`/admin/consolidation/diffs` "— rejected: … a second author of a governing number whose first author
is `workers/killswitch.py`." All three exist (`api/reports.py:181,442,522`) and `api/reports.py:159`
`_bh_adjusted_p_values` is a second Benjamini-Hochberg implementation alongside
`workers/killswitch.py:264` — precisely the hazard named. D-094 (`:385`) states three dashboard views
"are removed" and "the nav loses Lift, Consolidation and Staleness"; all three are present, routed
(`dashboard/src/App.tsx:30-32,74-76`) and in the nav (`components/Layout.tsx:52-74`), with mtimes ~1 h
after D-094 was written. The reversal is explained only in a TypeScript comment (`App.tsx:9`). The
file ends at D-094; nothing supersedes either. **An auditor reading DECISIONS.md alone gets the wrong
system.**

**S3 — Zero commits.** `git rev-list --all --count` = 0; every path untracked. Beyond hygiene, this
makes the prompt's "for each hard rule, the test exists and fails before the implementation" and
DECISIONS.md's own "never edit an entry; supersede with a new one" **permanently unverifiable**. No
entry waives the commit discipline.

**S4 — CI runs one-third of the suite.** `.github/workflows/ci.yml:49` is `pytest -m "phase0 and not
integration"` (1,587 of 3,721 collected); the integration job runs only `harness/phase0_gate.py:132`.
Never executed in CI: the negative probes (`harness/negative_probes/`, phase1), the render property
tests (phase1), the red team (phase3), the guessed-reward drill, and gates phase1–phase4 — four of the
six harnesses the prompt named as running "on every commit", and the one the prompt named CI-blocking
by rule 5. Only the latency-bench exclusion is logged (D-035(a)).

**S5 — 32 of 94 DECISIONS entries are malformed against the file's own header** ("Decision · Context ·
Alternatives considered · Rationale · Date"), concentrated in D-009…D-038; three ids are out of file
order (D-046 before D-045; D-050 before D-048/D-049), which removes the one structural signal a reader
could use to sanity-check append-only in the absence of git history. `harness/phase4_gate.py:198-216`,
which prints "DECISIONS.md current — PASS", checks only heading uniqueness and the presence of a
`**Date ` field.

**S6 — A second, unindexed audit trail.** 79 `CONTRACT GAP` comments across ~40 files record exactly
the class of thing DECISIONS.md exists for — e.g. `workers/killswitch.py:61-63` (the BH alpha and
confidence level live as module constants because "PLAN.md §6 has no field for the FDR level", in
direct tension with hard rule 12). Nothing maps the 79 to the 94, so "is DECISIONS.md complete" is not
answerable by anyone.

**S7 — Undeclared dependencies.** `prometheus-client>=0.21` (`pyproject.toml:27`, runtime),
`pytest-asyncio`, `types-pyyaml` appear in no DECISIONS entry, against hard rule 10 and D-036's "every
future addition gets its own entry with license". Conversely D-036 lists `onnxruntime` as the
secondary embedding driver and it is absent from `pyproject.toml` entirely — so D-036's inventory is
itself wrong in both directions.

**S8 — PLAN.md's build-status appendix is stale and its "none of them silent" list is incomplete.** It
records 3,592 passed / 139 mypy files against the verified 3,680 / 142, and its six open items omit
the four largest gaps in the tree (no status-write path; no writers for `memory_link`, `derived_state`,
`killswitch_state`, `scoring_epoch`; the unwired static prefix; the non-withholding holdout).

**S9 — Container images are outside every gate.** `scripts/license_check.py:214` walks
`importlib.metadata.distributions()` only. `docker/compose.yaml:20` pins
`tensorchord/vchord-suite:pg18-latest` — an image named in no DECISIONS or PLAN entry, on a floating
tag. Rule 9's three named AGPL hazards (pg_search, MinIO, Redis) are all infrastructure, i.e. exactly
the category enforcement does not reach.

**S10 — Mis-cited decision numbers in source.** `stores/tracestore/s3.py:6` and `sigv4.py:6` attribute
MinIO's archival to "D-036" (it is D-006); `stores/vector/qdrant.py:43,63` cite "D-036's sibling" for
what is D-070; `stores/vector/base.py:37` cites an entry with no id.

**S11 — A fabricated verbatim citation.** `harness/test_consolidation_regression.py:19-20` reads
`"""PLAN.md §7 Phase 2 gate, verbatim: "20 facts across 30 sweeps, retention reported per sweep and
asserted at 100%."` That string appears in neither plan.

### 4.2 Correctness and security

**S12 — Retrieval has no scope filter.** Every statement in `stores/pg/search.py:144-205` filters on
`project_id` and the retrievability predicate only; `CandidateRow` (`:274-294`) does not even carry
`scope_type`/`scope_id`. `api/routes_v1.py:105-106` parses `workflow_template` and `user_ref` into
`RunContext` and nothing reads them. **A user-scoped memory written for user A is retrievable by any
agent serving any user in the same project.** MEMORY_PLAN §5's whole ownership model is unenforced.
Nothing in DECISIONS.md mentions it.

**S13 — Callers set their own experiment arm.** `ingest/trace_writer.py:291` reads `arm` out of the
caller-supplied `run_start` payload; `stores/pg/repo.py:213-216` makes a declared `holdout` **sticky**
(`CASE WHEN EXCLUDED.arm = 'holdout' THEN 'holdout' …`); `stores/pg/reports.py:281` feeds
`ti.arm` — the caller-controlled column — into the stratified lift, *while already joining*
`retrieval_event`, whose `arm` is server-derived. PLAN §10 forbids "accept … arm assignment from any
caller" in those words, and `PHASE0-CONTRACT.md:1490` claims it does not happen while `:401` specifies
the mechanism that does.

**S14 — The holdout arm is not memory-off.** `hotpath/pipeline.py:379-424` computes `arm` and then runs
the identical ladder and returns the rendered block on both arms; `OutcomeCode.HOLDOUT` is never
emitted. Recorded in `workers/lift.py:53-60` and `gate_report_phase3.md:145`; not in DECISIONS.md, and
D-027 specifies the opposite. Combined with S13 and S15 the earn-your-context loop is inert end to end.

**S15 — Kill-switch decisions cannot be persisted and nobody is notified.** `workers/killswitch.py:66-75`
records that `write_killswitch_state` has no implementation; `grep 'INSERT INTO killswitch_state' src/`
returns nothing. `AuditSinkPort` has zero implementations and no migration creates an audit table, so
the "notifies the developer with the evidence" half of the spec has no channel at all — while
`docs/MEMORY-FLOW.md §8` advertises "Default in the box: Postgres + structured stdout".

**S16 — The embedding-pin guard is never called.** `adapters/embedding/pinning.py:6-9` claims
`assert_pin_matches` "is what makes [silent model swap] structurally impossible rather than merely
forbidden: any code path that reads a stored row's stamped identity before using its vector calls it
first." It has **zero production call sites** — only its definition, its re-export, and its test. No
module reads `embedding_model_id`/`_version`; `stores/pg/search.py:164-172` has no pin predicate. A
docstring asserting a property the code does not have.

**S17 — Three registries carrying project data are unpartitioned and un-RLS'd.** PLAN §5 prints
`project_config`, `agent_type_config` and `killswitch_state` under the heading "Learning plane (ALL
partitioned)". All three are created unpartitioned in `migrations/0001_registries.sql:110-148` and
receive no RLS (`grep` over `0003_rls.sql` returns nothing). Invariant 4's backstop does not cover
per-project governance data.

**S18 — The RLS policy text differs from the plan** — `NULLIF(current_setting('tracebed.project_id',
true), '')::uuid` (`migrations/0003_rls.sql:86`) rather than PLAN §5's literal form. The change is
correct and well argued at `:12-37`, and the migration itself says at `:20-21` "This deviation needs a
DECISIONS.md entry at merge; it is reported, not silent." No such entry exists.

**S19 — `propose_memory` has no mode check.** PLAN §3's own API contract says "agent_control mode
only". `api/routes_v1.py:170-177` enqueues for any authenticated principal, and
`workflow/agent_control.py` has no mode gate. The `memory.mode` / per-type opt-in surface MEMORY_PLAN
§16 specifies does not exist anywhere (`grep static_control src/` → 0), so there is nothing for a
check to read. Blast radius is bounded by D-023's caps; the access control is not there.

**S20 — Supersession is not implemented.** `valid_to` is written only at insert; nothing closes a
validity window, and `memory_link` has **no INSERT and no SELECT anywhere in `src/`** (the single
occurrence in `stores/pg/` is the table name in a tuple). PLAN §5 row 9 and §8 improvement 1 ("flag
derived descendants via `memory_link`") both depend on it.

**S21 — Revalidation is inverted.** MEMORY_PLAN §10.4 specifies *usage*-triggered revalidation ("the
retrieval itself is the trigger, so cost tracks usage, not vault size").
`workers/revalidation.py:81-82` computes due-when-**idle** for R days in a periodic batch — cost now
tracks vault size, the exact property the design avoided. Compounding: nothing writes
`last_retrieved_at`, so the reference is always `created_at`, and a passing re-verification writes
`last_revalidated_at`, which the due-test never reads — so every validated row re-verifies forever.

**S22 — `scoring_epoch` is inert.** `epoch_id` appears in no partitioned table
(`grep epoch_id migrations/*.sql` → only `scoring_epoch`'s own PK at `0001:97`); nothing inserts an
epoch row; `Repo` has no epoch accessor (`workers/epochs.py:34-36`). So PLAN §5's "every Q update and
shadow confirmation records epoch_id; cross-epoch comparison is rejected" and D-008's "stamped on every
scored artifact" are both unimplemented, and `/admin/lift/report` will report
`scoring_epoch_id: null` for every point forever (`stores/pg/reports.py:21-24,340-356`).

**S23 — The ANN arm is dead by construction.** `Repo._impl_insert_memory_item` (`repo.py:733-746`)
inserts 27 columns and none of them is `embedding`, `embedding_model_id`, `embedding_model_version` or
`lexemes`; `stores/vector/pgvector.py:82-105` `upsert()` unconditionally raises. "Hybrid retrieval"
degenerates permanently to the lexical arm. PLAN.md logs the `upsert` half only, not the missing
insert parameter.

**S24 — Distilled semantic memory has the wrong shape.** `workers/distiller.py:793-812` builds
`NewMemoryItem` with no `subject_tag`, no `valid_from`, no `valid_to`, and `scope_type` hard-coded to
`AGENT_TYPE` — so entity verdicts and environment facts, which §5 makes project-shared, land at
agent-type scope with none of the bi-temporal metadata §4 calls first-class.

**S25 — Preference memory is unreachable.** Creation works (`workers/edit_ops.py:319-348`), but
`pinned` is excluded from every search arm by design (D-050b) and the static prefix that was supposed
to carry it is unwired (see M5). A preference created today can never reach any agent's context.

**S26 — `candidate → validated` requires human-verdict *and* corroboration.** `domain/state_machine.py:523-527`
ANDs `has_verified_human_verdict` with `provenance_class is HUMAN_VERDICT`; PLAN §5 offers the human
verdict as an alternative (OR). A tightening, not a hole — but unlogged.

**S27 — The blackboard's three-status merge protocol collapsed.** `stores/pg/blackboard.py:240` binds
`STATUS_COMMITTED` and that is the only status value ever written; there is no `proposed` row, no
`rejected`, and no branch-merge operation. MEMORY_PLAN §11 specifies propose → orchestrator validates
→ flip status in a transaction. D-088 covers only the column types.

### 4.3 Configuration and enforcement drift

**S28 — `embedding.secondary_driver` was renamed and then made unreachable.** PLAN §6 names the field;
the code has `driver: Literal["gemini","onnx-local"]` (`domain/config.py:137-145`) with no log entry —
and `api/main.py:210-213` raises `ConfigError` unconditionally for `onnx-local` ("needs an injected
tokenizer, which no deployment in this repository names yet"). D-007's "fully supported secondary for
air-gapped deployments" and PLAN's "swappable by one config line" are both false in the direction that
matters: the offline escape hatch D-008 sells to customers who will not send query text off-box.

**S29 — `killswitch.correction` is decorative.** `domain/config.py:354` holds
`"benjamini-hochberg"`; its only reader is `api/reports.py:317`, which echoes the string into a report
body. The real FDR machinery uses `workers.lift.DEFAULT_BH_ALPHA`/`DEFAULT_CONFIDENCE`. An operator is
told they control the multiple-comparison method and they control a label.

**S30 — `scoring.contribution_rubric` does not exist.** PLAN §6 names it (`judge ∈ {0, 0.5, 1.0}`,
temperature 0). The values live as module constants at `workers/contribution_judge.py:230,357` — the
"magic numbers in code" §6's header forbids. Compare D-089, which found, fixed and logged exactly this
defect for `abstention.target_abstention_pct`; the same discipline was not applied here.

**S31 — Dead config on the deployment surface.** `dashboard.port` (`config.py:100-103`) has zero Python
readers; the real port is a literal in `dashboard/vite.config.ts:19,29` and `docker/compose.yaml:136`.
`api.workers` (`config.py:96`) has zero readers anywhere — setting `TB_API__WORKERS=8` produces neither
workers nor an error.

**S32 — `purity_check.py --root` is a dead flag** (`:242-270` parses `args.root`, then iterates a
hardcoded `hotpath` glob), so retrieval-adjacent surfaces — including `workflow/prefetch.py`, which
sits on the retrieval path — cannot be checked by the gate that is supposed to check them.

### 4.4 Gate reports that measure the wrong thing

**S33 — Every "Known gaps" section is a hardcoded tuple, and three entries are now false.**
`_KNOWN_GAPS` is a literal constant in each gate script (e.g. `harness/phase1_gate.py:433`,
`phase4_gate.py:536`), derived from nothing and pinned by no test. Re-running reproduces false text
verbatim: `phase1_gate.py:468` claims `abstention.target_abstention_pct` is "absent from
AbstentionConfig" when `domain/config.py:196` defines it (D-089 fixed it); `phase4_gate.py:572-576`
claims `blackboard_entry.value_ref/status` are NULLable with `author_agent` typed `text` and that three
`AgentControlRepoPort` methods are missing, all four fixed by D-087/D-088 (`migrations/0002:251-254`,
`repo.py:788,798,819`).

**S34 — The verdict rule inverts the information.** Phases 2 and 3 read **PASS** and Phases 0, 1 and 4
read INCOMPLETE — but `tests/phase3/` contains *zero* integration-marked tests and neither phase's
worker ports have any Postgres implementation. The phases with the least real-stack exposure get the
greenest verdicts, because the rule keys on skipped tests.

**S35 — Gate clauses substituted for adjacent, weaker ones.** `harness/phase0_gate.py:313-323` uses the
word itself: the clause "memory_item insert without a ScanVerdict raises" is replaced by "it's a
required positional argument, so it's a TypeError by construction", which does not touch the failure
mode the clause guards (a verdict issued for different content). Phase 0 clause 1's "fake-runtime run →
complete queryable trace" is proven by two unit suites (`:243-260`), never end to end. Phase 2 clause
1's first half ("seeded failure traces → expected Tier A notes") has **no affirmative assertion at
all** (`phase2_gate.py:267-313` covers only the zero-passthrough half). Phase 0's "SDK overhead ≤1 ms
p99 with queue stopped" was run as `mode=fakes` with `run_end` (32.7 ms) and `retrieve` (17.0 ms)
excluded — both numbers are printed at `gate_report_phase0.md:36-39`, so it is half-disclosed.

**S36 — Simulated inputs reported as measurements.** `gate_report_phase2.md` clause 5 asserts sweep
cost is "independent of trace volume: True" — `harness/sweep_cost.py:11-13` calls `trace_row_count` "an
inert label the sweeps never read", and `:55-57` splits the vault "evenly and exactly" across three
statuses so the linearity is a construction. `gate_report_phase3.md` clause 8 concludes "memory is an
enhancer" from `dependence_test.py:111,116` `BASE_CAPABILITY=0.85` / `BOOSTED_CAPABILITY=0.95` — the
simulation's own inputs. Clause 5 reports lift "+0.0923, p=0.0231 → SIGNIFICANT POSITIVE" with no N and
no "simulated" marker. Each caveat exists in the same report's known-gaps prose; none appears beside the
number.

**S37 — `gate_report_phase4.md` clause 6 prints "DECISIONS.md current — PASS" while quoting D-094 as the
highest entry** — the decision the shipped tree had already reversed (S2).

**S38 — D-035(a) describes behaviour never built.** "The latency bench … reports at every gate." It
reports at exactly one: `grep -c 'latency bench'` → phase0 = 0, phase1 = 4, phase2/3/4 = 0. Only
`phase1_gate.py` imports it.

**S39 — Three "CUTTABLE" improvements are not cuttable.** PLAN §8 promises "cutting it removes a bounded
module and its tests, nothing else." Deleting `harness/dependence_test.py` breaks
`phase3_gate.py:513` (which the runner's own docstring elevates to CI-blocking); deleting
`workers/safety_lift.py` breaks `tests/phase3/test_killswitch.py:38` and `test_lift.py:61-68`; deleting
`hotpath/jit.py` breaks `tests/phase1/test_assembly.py:562` and `tests/phase0/test_config.py:139`.

**S40 — Dashboard views rendered from the wrong or empty source.** `stores/pg/reports.py:501-505`
`consolidation_diffs` reads `derived_state` — the per-agent baseline table, not a merge/supersede
record — and its own docstring admits "no writer exists yet … so this returns an empty page today".
`q_trajectory` (`:317-380`) emits "one point per scored `memory_item` row" against a column nothing
updates, presented as a trajectory.

**S41 — Forensics has two disconnected halves.** `workers/forensics.py` is reachable from no route
(`grep forensic src/tracebed/api/` → 0), while `dashboard/src/views/Forensics.tsx:106` re-implements a
subset of the blast-radius walk in TypeScript over the `/export/project` NDJSON dump. The
`memory_link` step is inoperable on both sides (S20).

**S42 — `harness/consolidation_regression.py` is never invoked by the gate that owns it** (`grep -c` in
`phase2_gate.py` → 0), and none of its six tracked classname keywords match it.

**S43 — `docs/MEMORY-FLOW.md` §8 names every port wrong** — 8 for 8 (`PrincipalResolver` vs
`PrincipalPort`, `ObjectStore` vs `TraceStorePort`, …). This is the boundary contract the user's "I will
integrate with Atom myself" instruction makes load-bearing.

**S44 — D-030's justification document does not exist.** It waives the ReMe shim because the delta "is
documented in the adapter guide instead". `"ReMe"` appears three times in the entire repo:
`DECISIONS.md:94`, `:95`, `PLAN.md:512`. `docs/ADAPTER-GUIDE.md` contains zero occurrences.

**S45–S49** (lower consequence, evidence held in the dimension reports): Phase 3's lift gate weakened
from a pass/fail quality gate to a reporting requirement; the archetype taxonomy substituted (three
*deployment* archetypes for MEMORY_PLAN §16's seven *agent* archetypes); budget "dedup against content
already in context" has no wire field or port and is candidate-vs-candidate only
(`hotpath/assembler.py:76-84`); `prefetch_for` accepted at `api/models.py:96` and dropped at
`routes_v1.py:100-110` while `PrefetchingRetriever` is wired nowhere; the phase-4 known-gap pointer
"see the untracked-failures section" dangles because that section renders only when failures exist
(`phase4_gate.py:836`).

---

## 5. Missing — promised, not built

23 distinct. The first four are one failure with four faces and they dominate everything else.

| # | Promise | Evidence |
|---|---|---|
| M1 | **Any status write.** The §5 state machine, Q updates, decay, strikes, promotion, retirement, archiving, pinning, crypto-shred tombstoning | No `UPDATE memory_item` in `src/`; `workers/edit_ops.py:203-205` states it. `persist_status` is a Protocol whose only implementations are three test fakes (`tests/phase3/test_edit_ops.py:129`, `test_forensics.py:106`, `tests/phase4/test_preferences.py:138`) |
| M2 | **A running worker plane.** Extractors, distiller, scorer, shadow validator, consolidator, invalidator, prefix builder, kill switch, sweeps, gc, scheduler | `workers/runner.py:422` — `handlers={}`; the docstring at `:338-361` lists each as "deliberately NOT constructed here". `api/main.py` constructs none either |
| M3 | **Postgres implementations for the worker ports** — `MemoryLifecycleRepoPort`, `ScorerRepoPort`, `ShadowValidatorRepoPort`, `PromotionRepoPort`, `KillswitchStorePort`, `DerivedStateStorePort`, `ForensicsRepoPort`, `MemoryEditRepoPort`, `ReviewQueueRepoPort`, `EpochStorePort` | Each declared only in the worker that consumes it; `gate_report_full.md:396,553` confirms none exists |
| M4 | **Writers for four §5 tables** — `memory_link`, `derived_state`, `killswitch_state`, `scoring_epoch` (plus `agent_type_config`) | Enumerated `INSERT INTO` across `stores/`: 19 tables, none of these |
| M5 | Static prefix delivery (pinned preferences + top validated lessons) | `hotpath/pipeline.py:539-589` never consults `_static_prefix` on the happy path; `api/main.py:249-257` passes no `static_prefix=` at all, so even the timeout rung returns an empty block. No class implements `StaticPrefixPort` |
| M6 | Shadow-confirmation producer (the only non-human exit from quarantine) | Nothing appends `shadow_confirm_runs`; `ShadowValidatorRepoPort` declares only `select_quarantined`/`persist` |
| M7 | Credit assignment: outcome → trace → injection_log → memories | Both ends written, no query joins them (`workers/lift.py` docstring); `run_scorer_batch` has no production caller |
| M8 | Episodic memory (case summaries, exemplars, conversation summaries, routing records) | The enum value is occupied by Tier A operational notes (`workers/extractors/tool_failure.py:40`); `distiller.py:161` refuses episodic; `hotpath/assembly.py:100` renders those notes under "EXEMPLARS" |
| M9 | Contradiction detection ("never last-write-wins") | `workers/consolidator.py:34-40` explicitly refuses semantic comparison; `open_contradiction` is a caller-supplied field |
| M10 | Session-scoped / paused-workflow working memory (the "lifetime knob") | `stores/valkey/keys.py:136` keys on `RunId` only; `SessionConfig` has only `idle_ttl_min` and `offload_threshold_tokens`; `session_id` reaches no store |
| M11 | `AuditSinkPort` default ("JSON-lines to stdout + Postgres audit table") | Zero implementations; no audit table in any migration; `workers/killswitch.py`'s optional `audit=` parameter has zero call sites |
| M12 | Memory edit/quarantine write routes (`POST /admin/memory/{id}/quarantine`, pin/delete/merge/correct) | `api/admin.py` has exactly two POSTs: `/admin/projects`, `/admin/agents/register` |
| M13 | `memory.mode` + per-type opt-in developer surface (MEMORY_PLAN §16) | `grep static_control src/` → 0; no `MemoryMode` type; PLAN §6 dropped it too, unlogged |
| M14 | Memory TTL classes | Column and state-machine evidence flag exist; no producer, no duration config, no sweep |
| M15 | Export-hook suggestion event (the one permitted piece of the skill carve-out) | `grep -i skill src/` → 0 hits |
| M16 | Policy-suggestion channel (§1 invariant 3's affirmative half) | `grep -i 'policy.suggest' src/ dashboard/ docs/` → 0 |
| M17 | JIT second retrieval checkpoint | `hotpath/jit.py` built; `sdk/client.py:310-314` still `return None` with a stale "trigger logic is Phase 2" docstring; no wiring anywhere |
| M18 | Durable `routing_record` | No table in any migration; `workflow/routing.py:31-45` is process-local, unbounded, empty after restart (logged in PLAN.md:470) |
| M19 | Per-project trace retention | `project.retention_policy` is written at creation and read by nothing |
| M20 | Blackboard death + trace summary at run end | No cleanup, no TTL, no GC path, no summary writer |
| M21 | `scoring.contribution_rubric` config field | See S30 |
| M22 | Workflow-scope credit rule ("never guess per-agent blame") | Only implementation is `harness/workflow_scope.py:151-200`; nothing in `src/` inspects `scope_type` when scoring |
| M23 | Small commits per component | Zero commits |

---

## 6. Extra — built, never asked for

Unrequested surface area the user now owns and must maintain.

| # | Item | Size / evidence | Judgement |
|---|---|---|---|
| E1 | `dashboard/src/views/{Overview,Health,Projects,Settings}.tsx` | ~90 KB of TSX in neither plan | The most consequential. `Projects.tsx` and `Settings.tsx` surface admin registry provisioning and bootstrap-key credential paste-in — a governance surface no document asked the dashboard to own |
| E2 | `src/tracebed/workflow/` (`agent_control`, `blackboard`, `prefetch`, `routing`) | In neither the prompt's layout nor PLAN §4 (`grep 'workflow/' PLAN.md` → 0) | Prompt-mandated Phase 4 *function* in unlisted *placement*. Low risk, unlogged |
| E3 | Phase 3 gate assertion 8 (dependence drill) made CI-blocking | `phase3_gate.py:497-529`; appears in no PLAN §7 gate clause | This is the mechanism by which a "CUTTABLE" improvement stopped being cuttable (S39) |
| E4 | `promotion.min_distinct_principals` as overridable config | `config.py:276`, `promotion` is in `OVERRIDABLE_SECTIONS` | PLAN §5 states the count as a literal. Floored at 2 so it can only be raised — bounded, but it moves a governance threshold into `project_config` |
| E5 | `api.workers` | `config.py:96`, zero readers | Dead knob on the deployment surface |
| E6 | Top-level `docs/` (7 files incl. a checked-in `MEMORY-FLOW.html`) | Absent from PLAN §4's tree | Arguably implied by the Phase 4 "operator docs" task |

---

## 7. The user's own spoken instructions

| # | Instruction | Verdict | Evidence |
|---|---|---|---|
| 1 | "You create the standalone service, I will integrate with Atom myself" | **Honoured** | `adapters/atom/` is README + `__init__` + `stubs.py`; all 8 classes raise `NotImplementedError` in `__init__`, and the three `FeedbackPort` stubs declare an explicit no-arg `__init__` purely so a `@runtime_checkable` isinstance check cannot silently pass them (`stubs.py:22-28`). `tests/phase4/test_archetype_configs.py:657` asserts none can be constructed. `grep -i atom src/` outside the package → only the substring "atomic" |
| 2 | `project_id` server-side from the authenticated principal, never caller-asserted | **Honoured** | Four layers: `ProjectScope` constructible only by `Repo.resolve_project`; every `/v1/*` model `extra="forbid"` with no `project_id`; every admin/report read takes `ScopeDep`; `dashboard/src/api/client.ts:111-129` carries a recursive client-side `assertNoProjectId` guard. Sole exception is `POST /admin/agents/register` behind `require_admin_key` — provisioning, not scope assertion |
| 3 | "Replace ReMe — just make sure we are not losing anything" | **Violated** | Nobody ever checked. D-030 waives the shim by citing a parity write-up in the adapter guide that does not exist (S44). The honest answer: a deployed Tracebed loses everything ReMe actually did — ReMe wrote session-end conversation summaries and handed them back next session; Tracebed has no cross-session memory (M10) and no reachable learning worker (M2), so traces go in and nothing comes out |
| 4 | "We will use Gemini" / "whatever is more accurate" / swappable by one config line | **Partial** | Gemini defaults are correct and match what Atom's own LiteLLM routes to (`config.py:137-155`). Generation swap is genuinely one line. **Embedding swap is not** — `driver='onnx-local'` raises `ConfigError` unconditionally (`api/main.py:210-213`), and `onnxruntime` is not a declared dependency (S28) |
| 5 | "Make it good for all, no number-one focus" | **Honoured** | `grep -i 'soc\|bfsi\|analyst\|fraud' src/*.py` → one hit, a quotation inside a docstring. `general_purpose.toml` is the shipped default; the SOC-shaped lift sim is in `harness/`, where the prompt put it |
| 6 | "Our focus is security and governance" | **Partial** | The preventive half is strong (invariants 3, 6, 7, 8; scan-verdict-required inserts; closed render grammar). The **accountability half does not exist**: no audit sink, no audit table, no governance event is recorded anywhere (S15, M11) — and `MEMORY-FLOW.md §8` advertises a default that is not there |
| 7 | "Standalone UI like the other services" | **Honoured** | React 18.3.1 / Vite 5.4 / TS 5.5 / Tailwind 3.4 / react-router-dom ^6.26.2 — the same stack and near-identical versions as Atom's own frontend; own Dockerfile on :8111 served by nginx rather than `vite preview`, which is better than Atom's production image |
| 8 | "100k runs/day is a stress premise that could become real" | **Honoured (design), unmeasured (fact)** | Every unbounded read paginated; `/export/project` uses a server-side named cursor with `itersize=500` (`repo.py:1588-1606`); the 1,000-project partition ceiling is documented with a migration path; the queue implements `_XMIN_HORIZON_SQL` (`stores/pg/queue.py:184-211`) for exactly the buffer-cache coupling the user named; `high_volume.toml` moves batch size and lease together and refuses to move two governance knobs that look like throughput knobs. **But** nothing sweeps the vault at runtime (M2), so accumulation is unbounded regardless of what the bench would have shown |
| 9 | 300 ms p99 / 200 ms embed | **Honoured as defaults, unproven as facts** | `config.py:176-177`, read on the hot path, sub-budget clamped to the remaining total (`hotpath/budget.py:47-90`), logged as D-010 with the degradation ladder. No p99 has ever been measured on this machine |

---

## 8. Gate-report honesty

**What is genuinely good, and rare.** `gate_report_full.md:7` takes the *weakest* phase verdict —
"never an average, never 'most phases passed'". Every report defines INCOMPLETE as explicitly not a
pass. Phase 0 breaks assertion 2 down per-probe, showing 5 of 7 probe classes SKIPPED-NO-STACK under a
row that is itself labelled SKIPPED rather than PASS. Phase 3 leads its gaps with the D-086
conditioning of its own most load-bearing clause. Phase 4 admits clause 3 has no owning pytest file.
Across five reports, **no PASS was asserted for something that did not execute.**

**Where they overstate.** Five ways, all evidenced in §4.4: the known-gaps sections are hardcoded and
three entries are now false (S33) — a reviewer reads fixed problems as open ones and, worse, trusts the
section as a live inventory; the verdict rule gives PASS to the two phases with the least real-stack
exposure (S34); four gate clauses were satisfied by adjacent, weaker properties, one of which the
runner itself calls "adjacent" (S35); three headline numbers restate simulation inputs (S36); and clause
6 prints "DECISIONS.md current — PASS" while quoting a decision the tree had reversed (S37). The
pattern is consistent: the reports are scrupulous about *skips* and careless about *substitutions* —
they will not call an unrun test green, but they will call a different test the right test.

---

## 9. Unverifiable without the stack

Running Docker/Postgres would newly prove — or disprove — exactly these. Everything else in this
document was decidable from the tree.

1. **Cross-project isolation at runtime.** 7 leak-probe groups are integration-marked
   (`harness/leak_suite/test_leaks.py:124,191,210,266,343,403,462`). The single most load-bearing
   clause — "repo bypass with the RLS GUC unset returns zero rows" (`:462`) — has never executed.
   Whether `FORCE ROW LEVEL SECURITY` is effective also depends on the service role genuinely being
   non-owner and non-`BYPASSRLS`, which `0003_rls.sql:144-156` sets conditionally.
   *Note: probe 4 would remain unproven even with Docker — it is a dead tripwire (§3, invariant 4).*
2. **Whether the `pg_textsearch` SQL surface exists as assumed.** D-050(a) states plainly that
   `content @@@ query` and `bm25_score(content, query)` are inferred from the index access-method name
   and never verified. The entire lexical arm — and with it the IDF basis for the rarity gate — rests
   on that inference. Also unverified: `halfvec(768)`, the HNSW `halfvec_cosine_ops` opclass, and
   whether the per-project partition templates produce constraints matching their parents.
3. **Any latency number.** No p99 for the real pipeline exists anywhere in the repo. Even with
   Postgres, the bench's vector arm would measure zero rows (S23), so a green bench would prove the
   lexical path only.
4. **Whether the §10 lifecycle arithmetic behaves against real rows.** Every Phase 2/3 drill ran against
   in-memory doubles, so the soak's plateau projection and the sweep-cost scaling claim are properties
   of a simulator (S36). And because no write path exists (M1), the store-side half of the write path
   has never been exercised even in principle — a database alone would not fix this.
5. **Whether the three restored report routes return correct numbers.** They read
   `retrieval_event`, `injection_log` and `derived_state`; the last has no writer, and the BH
   recomputation cannot be compared against `workers/killswitch.py` without a stack.
6. **Whether the LLM-dependent workers behave against a real endpoint** — distiller, contribution judge,
   shadow validator all run against offline fakes; no network call was made and the Gemini model ids
   were not resolved.
7. **The licence of `tensorchord/vchord-suite:pg18-latest`.** Not guessed. The verifiable finding is
   that no gate covers container images either way (S9).
8. **Whether the eight load-bearing invariant tests were written before their implementations** (D-035(b)),
   and **whether DECISIONS.md was ever edited in place**. Both need git history. Both are unverifiable
   now and will remain so.

---

## 10. What I would fix first

Ranked by (harm if unfixed) × (cheapness of the fix). Effort is engineer-days for someone who knows
this tree.

| Rank | Fix | Why first | Effort |
|---|---|---|---|
| 1 | **Write the truth into `DECISIONS.md`** — supersede D-093/D-094 (S2), add entries for the ~20 unlogged deviations in §4 that are real decisions (S12–S31), and rewrite PLAN.md's "none of them silent" list to name M1–M6 | Costs nothing, unblocks everyone, and is the failure that made every other finding harder to see. Right now the audit trail actively misleads | 0.5 d |
| 2 | **Fix the three false known-gaps and stop hardcoding them** (S33) — derive each gap from the run, or add a test that fails when a gap string stops being true | A stale gap list is worse than no gap list; a reviewer trusts it *instead of* the code. Small, and it prevents recurrence | 0.5 d |
| 3 | **Close the insert-side state bypass** (invariant 7 / §3) — re-check `item.status` against a legal-creation set in `insert_memory_item`, and either narrow the DB CHECK or add a partial constraint | The docstrings at `domain/memory.py:155-158,168-170` already promise this. It is a ~10-line change that turns the tree's strongest invariant from partly-true to true | 0.5 d |
| 4 | **Stop accepting `arm` from callers** (S13) — drop `payload["arm"]` in `trace_writer.py:291`, source it from `retrieval_event.arm`, and switch `reports.py:281` to `re.arm` | Directly violates PLAN §10, and it is the input to the governing lift number. Small and self-contained | 0.5 d |
| 5 | **Add the `scope_type`/`scope_id` predicate to every retrieval arm** (S12) — plus the columns on `CandidateRow`, plus a leak probe | This is the only finding with a plausible cross-user data-exposure path inside a project. It is a schema-complete change; the columns already exist | 1–2 d |
| 6 | **Build the status-write path** (M1) — `Repo.update_memory_status` + `q_value`/`strike_count`/`last_retrieved_at`/`shadow_confirm_runs`, driven only from `state_machine.apply` | Everything in Phases 2–3 is downstream of this. Until it exists, "the system learns" is false | 3–5 d |
| 7 | **Implement the worker-port Postgres adapters and construct the workers** (M2, M3, M4) — the six repo ports, writers for `memory_link`/`derived_state`/`killswitch_state`/`scoring_epoch`, and real `handlers` in `workers/runner.py` | The largest single block, and the one that turns the library into a service. Should be scheduled as its own phase with a real STOP | 10–15 d |
| 8 | **Wire the static prefix and the embedding write** (M5, S23) — pass `static_prefix=` in `api/main.py`, implement `StaticPrefixPort`, add embedding columns to the INSERT, implement `PgVectorStore.upsert` | Makes preference memory reachable and the ANN arm non-dead. Both are small next to #7 and unblock the latency bench meaning anything | 2–3 d |
| 9 | **Widen CI to the whole suite** (S4) — run phase1–4 and the four named harnesses; make the guessed-reward drill collectable | The prompt named these CI-blocking. Cheap, and it stops the next regression from being silent | 1 d |
| 10 | **Ship an audit sink** (M11, S15) — the stdout JSON-lines half at minimum, plus the table, plus passing `audit=` where the ports already accept it | The user named governance a top-two priority and there is currently no record of any governance action | 1–2 d |
| 11 | **Answer the ReMe question in writing** (S44, instruction 3) — an actual parity table: what ReMe did, what Tracebed does, what is lost, what replaces it | The user asked for this explicitly and nobody has ever answered it. Cannot be honestly written until #6–#8 land, which is itself the answer | 0.5 d after #8 |
| 12 | **Decide on the extras** (E1–E6) — keep or delete the four unrequested dashboard views, especially `Settings.tsx`'s credential paste-in; make the three CUTTABLE improvements actually cuttable (S39) | Scope creep is surface area the user maintains forever. Cheapest to resolve now, while it is still four files | 1 d |
| 13 | **Commit the tree** (M23) | Not a code fix, but every future audit of this repo is degraded until there is history | 0.1 d |

---

## 11. Remediation (2026-07-26, after the audit)

The audit above was read-only. This section records what a remediation pass then changed, what it
logged instead of changing, and what it deliberately left. **Nothing in §1–§10 was edited** — a
finding that was fixed is still described as it was found, and this section is the only place that
says so. Verified numbers after the pass are at the end.

### 11.1 Fixed in code

| Finding | What changed | Why fix rather than log |
|---|---|---|
| **Invariant 7, creation half** (§3 row 7) | `domain.state_machine.LEGAL_CREATION_STATUSES` derived from the `(None, X)` edges, plus `assert_legal_creation_status`, enforced in `NewMemoryItem.__post_init__` AND all three `Repo` insert paths. `latency_bench` now seeds Tier-A `candidate` rows and asserts the promotion it would rather do. D-096. | Two docstrings already promised this check. ~10 lines, and it turns the tree's strongest invariant from partly-true to true. |
| **S12 — retrieval has no scope filter** | `CandidateRow` carries `scope_type`/`scope_id` with no default, `fetch_candidates` selects them, and both injection paths drop rows `domain.visibility.scope_visible` refuses. Exhaustive over `ScopeType` via `assert_never`. `tests/phase1/test_scope_visibility.py` (16 tests) + 2 JIT-path tests. D-097. | The only finding with a plausible cross-user exposure path inside a project. Fail-closed: workflow- and user-scoped memories are now visible to nothing until a resolver exists, which is a narrowing and is logged as one. |
| **S13 — callers set their own experiment arm** | `TraceIndexUpsert.arm` deleted; the upsert derives `trace_index.arm` from `retrieval_event.arm` (server-written) on both branches; `reports.lift_observations` stratifies on `re.arm`. D-098. | PLAN §10 forbids it verbatim and it is the input to the governing lift number. A shape that cannot carry the value cannot smuggle it. |
| **S14 — the holdout arm is not memory-off** | The pipeline shadow-retrieves (ladder runs, `injection_log` rows still written) then stamps `OutcomeCode.HOLDOUT` and returns an empty block. D-099. | Without it every lift figure compared memory-on against memory-on. The shadow half is kept because `workers.lift.is_shadow_control` needs the injection rows. |
| **S29/S30 — governed thresholds as module constants** | `killswitch.fdr_alpha`, `killswitch.confidence_level`, `scoring.contribution_rubric`, `scoring.contribution_judge_temperature` added; the workers now read them; `tests/phase0/test_config.py` pins each pair and asserts the rubric is immutable. D-100. | Hard rule 12, and D-089 had already set the precedent for exactly this defect. |
| **Invariant 1 on convention** (§3 row 1) | `purity_check.py` now uses an ALLOWLIST of third-party top-level packages (4 names + stdlib) instead of an 11-name denylist, and `--root` actually selects what is walked — the default set adds `tracebed.workflow.prefetch`. `--self-test` proves both halves (a `groq` import is rejected; `psycopg`/`hashlib` are not). D-101. | The audit proved by mutation that `import groq` passed. An allowlist closes the open-ended half of the invariant. |
| **Invariant 4's dead tripwire** (§3 row 4, S33-adjacent) | Leak probe 4 rewritten: it extracts the `/v1/*` and `/admin/*` paths `dashboard/src` actually calls, asserts each is registered, asserts each refuses an unauthenticated caller, and asserts no B identifier appears in an A-authenticated 200. D-102. | The old probe could never fire, and the full gate reported it PASS while asserting the dashboard does not exist. |
| **Invariant 4 for `ReportsRepo`** (§3 row 4) | New `tests/phase0/test_reports_isolation_offline.py`: exhaustive call table, GUC-first, project-id predicate present, no `SELECT *`. Mutation-verified (swapping one `scoped()` for a bare connection turns it red). | The seven builders over partitioned tables had no such test at all; `Repo` has three layers. |
| **Invariant 8 not collectable** (§3 row 8) | `tests/phase3/test_guessed_reward_drill.py` runs the real drill and asserts each clause separately. | The prompt makes invariant 8 CI-blocking; a drill pytest never collected is a script. |
| **S4 — CI runs one-third of the suite** | Static job runs `pytest -m "not integration"` plus four offline harnesses; the integration job runs phase 0–4 gates and `full_gate` and uploads all reports. D-103. | The prompt named these CI-blocking. |
| **S33 — hardcoded known-gaps, three of them false** | Three false entries deleted; `tests/phase4/test_known_gaps_are_current.py` pins each mechanically-checkable claim in both directions. D-108. | A stale gap list is trusted instead of the code. The second direction is what stops the next one. |
| **S37/S5 — the DECISIONS check is heading-deep** | `phase4_gate` now validates all five mandated fields for every entry after D-094 (legacy set frozen and named). D-110. | The rule can still be obeyed going forward; rewriting 32 legacy entries would violate the file's own append-only rule. |
| **S35/S36 — clause substitution and simulated numbers** | Phase 0 clause 3 is now backed by two NAMED tests exercising the real failure mode (a verdict issued for other content is refused with zero SQL) and FAILS if either stops being selected; Phase 2's sweep-cost and Phase 3's dependence + lift clauses print a `SIMULATED` note beside the number, and the sweep-cost clause states which half of it is a construction. D-117. | A gate must never measure something adjacent to its clause. Two remaining substitutions are named, not fixed — see §11.4. |
| **S34 — the verdict rule inverts the information** | Phases 2 and 3 now print, beside their PASS, that they contribute no integration-marked tests and that none of the worker ports their clauses exercise has a Postgres implementation. | Changing the verdict would be dishonest in the other direction (the clauses did execute); the disclosure belongs next to the verdict, not 300 lines below it. |
| **S7/S9 — dependency and image inventories** | `license_check.py --dependency-audit` fails if a `pyproject.toml` dependency is not named in DECISIONS.md; new `scripts/image_policy.toml` + `scripts/image_check.py` fail on an undeclared container image, a policy/compose tag drift, or an unacknowledged floating tag. Both wired into CI. D-104, D-109. | Both inventories had already drifted once; a check costs less than the next audit. |
| **S10/S11/S16/S43 — false citations and docstrings** | `s3.py`/`sigv4.py` now cite D-006, `qdrant.py`/`base.py` cite D-070; the fabricated "PLAN.md §7 Phase 2 gate, verbatim" quotation is replaced with what §8 actually says; `pinning.py`'s "structurally impossible" claim is corrected to name its zero production call sites; `MEMORY-FLOW.md` §8 names all eight ports correctly and states that `AuditSinkPort` has no implementation. | A docstring asserting a property the code lacks is the specific failure this audit was about. |
| **S44 — the ReMe answer nobody wrote** | `docs/ADAPTER-GUIDE.md` gains a parity section: what ReMe did, what Tracebed does, what is lost (session-to-session recall), and three specific things to do before calling it replaced. | The user asked for it explicitly and D-030 cited a document that did not exist. |
| **S8 — PLAN.md's stale appendix and incomplete open-items list** | Build status refreshed to the verified numbers; the "none of them silent" heading removed and pointed at the new §11; §8's CUTTABLE promise corrected to name exactly which three improvements are no longer cuttable and why. | The summary a reader consults was the thing that was wrong. |

**One behavioural consequence worth stating plainly.** With S14 fixed, `killswitch.holdout_pct`
does what it says: at the shipped default, **5% of production retrievals now return an empty
context block** and a `retrieval_event` row stamped `holdout`. That is the specified design (the
kill switch cannot measure lift without a control) and it was not true before. It also surfaced
six places — four test modules and two harnesses — that constructed a `Pipeline` with random
agent-type ids and the 5% default, and would therefore have failed roughly one run in twenty at
random. Each now pins `holdout_pct=0` with a comment saying why, and the arm's own behaviour is
tested where it belongs (`tests/phase1/test_pipeline.py`, `harness/dependence_test.py`). The full
suite was run five times consecutively to confirm the flakiness is gone.

### 11.2 Logged rather than fixed (the deviation was the right call, or the fix is not bounded)

23 new DECISIONS entries, D-095…D-117. The ones that are decisions rather than fixes:

* **D-095** supersedes D-093 and D-094 — the three report routes and three dashboard views exist.
  The audit trail's last two entries were false about the shipped tree; neither is edited (the file
  is append-only), and D-093's real hazard (two Benjamini-Hochberg implementations) is carried
  forward as an open item with its mitigation named: the route cannot act.
* **D-105** RLS policy text (`NULLIF` form) — the migration itself demanded an entry and never got
  one. The deviation is correct: deny-on-unset is the fail-closed reading.
* **D-106** `candidate → validated` requires human verdict AND corroboration — a tightening; it
  cannot promote anything the plan's reading would refuse.
* **D-107** `embedding.driver` rename plus `onnx-local` raising — the air-gapped escape hatch
  D-007/D-008 sell does not work, and failing loudly at startup is the only honest behaviour for an
  unimplemented privacy control.
* **D-111** the five phase STOPs did not happen and the tree has no commits — recorded, not
  remediable. Everything from ~D-038 onward was decided without the review meant to gate it.
* **D-112** points at PLAN.md §11's full gap list.
* **D-113** revalidation inverted from usage- to idle-triggered; **D-114** the blackboard's
  three-status merge protocol collapsed to one; **D-115** deployment archetypes substituted for
  §16's seven agent archetypes; **D-116** `propose_memory` has no mode check (and nothing exists for
  a check to read).

### 11.3 Recorded in PLAN.md §11 for the user to decide

All 23 MISSING items with rough sizes (M1–M24 there), all six EXTRA items, and the process failure.
The four faces of one absence — no status write, no worker plane, no worker-port adapters, no
writers for four §5 tables — lead the list, because until they exist "the system learns" is false.
**Not built here deliberately:** the audit sizes the worker plane alone at 10–15 engineer-days, and
building it without a STOP would repeat exactly the failure D-111 records.

### 11.4 Deliberately not fixed, and why

* **The SQL-side scope predicate.** D-097 filters in the assembler, which closes the exposure on
  both injection paths. The arms still return ids for rows the caller may not see. The better
  control is a `scope_type`/`scope_id` conjunct in `lexical_arm`/`vector_arm`, which needs an agent
  identity in every port signature and every test double. Open item in §11.2 of PLAN.md.
* **Phase 0 clause 1** ("fake-runtime run → complete queryable trace") is still proven by two unit
  suites rather than end to end, and **Phase 2 clause 1's first half** ("seeded failure traces →
  expected Tier A notes") still has no affirmative assertion. Both need fixtures that do not exist;
  named in D-117 and PLAN.md §11 rather than papered over.
* **`api.workers` and `dashboard.port`** (E5) are still dead config. The instruction for EXTRA items
  is to record, not delete; both are in PLAN.md §11.3 for the user's decision.
* **Cuttability of improvements 1, 2 and 5** (S39) is not restored. PLAN §8 now states plainly which
  are no longer cuttable and what each deletion would break, rather than repeating a promise the
  tree does not keep.
* **The 300 ms p99** (§3 row 2) is still proven by nothing: every stall is `FakeClock.advance()`,
  and the bench's vector arm would measure zero rows because there is still no embedding write. No
  amount of offline work changes that; it needs Postgres and M8.
* **The three false-by-judgement known-gap entries** — the ones that say "a human must decide this
  at the STOP" — are left as prose and excluded from the new test by name. They cannot be
  mechanically falsified, and pretending otherwise would be the same defect wearing a lab coat.

### 11.5 Verified after the pass

```
pytest -q                          3,754 passed / 41 skipped / 0 failed   (was 3,680 / 41)
mypy                               clean, 143 source files                (was clean, 142)
ruff check src tests harness scripts   clean
scripts/license_check.py           PASS (49 distributions)
scripts/license_check.py --dependency-audit   PASS  (new)
scripts/raw_sql_lint.py            PASS
scripts/purity_check.py            PASS — hotpath + workflow.prefetch, allowlist (new coverage)
scripts/image_check.py             PASS (5 image references, all declared)  (new)
harness/full_gate.py               INCOMPLETE  (phase0 INCOMPLETE, phase1 INCOMPLETE,
                                    phase2 PASS, phase3 PASS, phase4 INCOMPLETE)
dashboard: tsc clean · eslint clean · vite build ok · npm licences PASS (343 packages)
```

The INCOMPLETE verdicts are unchanged and have the same cause as before: this machine has no
Docker/Postgres/Valkey. No verdict improved as a result of this pass, and none regressed. The test
count rose by 74 (scope visibility, the reports isolation suite, the creation-status matrix, the
guessed-reward drill, the known-gaps currency tests, the config pins, and two JIT scope tests).


---

*Audit performed 2026-07-26 against the working tree at `C:/Users/kirti/Music/Strata` (275 Python
files / 87,030 lines, 6 SQL migrations, 30 TS/TSX files / 9,844 lines; 3,680 tests passing, 41 skipped;
mypy --strict clean on 142 files). Read-only: no file was modified. The `INCOMPLETE` gate verdicts
caused by the absence of Docker/Postgres on this machine are known, documented, and were not
re-litigated.*

*Remediation performed the same day and recorded in §11 above; §1–§10 describe the tree as the
audit found it and were deliberately left unedited, so the two halves of this document can be
read against each other.*
