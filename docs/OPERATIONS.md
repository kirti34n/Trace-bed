# Tracebed — Operations Guide

> Running Tracebed: migrations, partitions and the 1,000-project ceiling, the spend cap, the
> kill switch and its lift report, the review queue, erasure, backup/restore, and what each
> gate report means.
>
> Rev. 2026-07-26 · API `:8110` · Dashboard `:8111` · Companion to `docs/ADAPTER-GUIDE.md`
> (the integration seam) and `docs/MEMORY-FLOW.md` (the read/write/lifecycle model).

---

## 1. Bringing the stack up

Local dev stack (`docker/compose.yaml`): Postgres 18 (`tensorchord/vchord-suite:pg18-latest`
— pgvector + `pg_textsearch` bundled; **image tags are unverified**, this file was authored
on a machine with no Docker daemon, confirm on first `docker compose up` and pin by digest),
Valkey 8, SeaweedFS (generic S3 target for the trace store), and — only under the `full`
profile — the `api` and `dashboard` containers:

```bash
docker compose -f docker/compose.yaml up -d                  # postgres, valkey, seaweedfs
docker compose -f docker/compose.yaml --profile full up -d    # + api, dashboard
```

Ports are deliberately non-default so they never collide with a host service already running
on the standard ports: Postgres on `5442` (not `5432`), Valkey on `6389` (not `6379`),
SeaweedFS S3 on `8333`. Tracebed's own API is `8110`, the dashboard `8111` — both PLAN.md
defaults, unmoved.

Environment, split by what actually happens when it is absent — the "if absent" column is
not decoration. Four of these five abort startup (three for both process types, one for the
API only) and the fifth deliberately does not; a flat "required environment" list hides that
difference until a deployment finds it the hard way.

| Variable | Required by | If absent |
|---|---|---|
| `TB_STORAGE__PG_DSN` | `tracebed-api`, `tracebed-worker` | `TracebedSettings()` raises `ValidationError` — `StorageConfig.pg_dsn` has no default. Process does not start. |
| `TB_EMBEDDING__MODEL_VERSION` | `tracebed-api`, `tracebed-worker` | Same: `EmbeddingConfig.model_version` has no default, deliberately (an unpinned embedding version would be stamped onto every row it embedded). Process does not start. |
| `TB_MASTER_KEY` | `tracebed-api`, `tracebed-worker` | `crypto.shred.EnvMasterKeyProvider.__init__` raises `MasterKeyMissing` — it validates eagerly, so a broken crypto seam is found at startup, never the first time a trace is written. Base64, exactly 32 bytes. **The name has no `TB_CRYPTO__` prefix and is not a `TracebedSettings` field** (C-15: settings objects get `repr()`'d into logs, and key material must not be one accidental `str(settings)` from a leak). `docker/compose.yaml` sets exactly this name; it previously set `TB_CRYPTO__MASTER_KEY`, which nothing read, and the `full`-profile `api` container aborted with `MasterKeyMissing` even when a key was supplied. Fixed at the Phase 4 integration pass. |
| `TB_HOLDOUT_SALT` | `tracebed-api` only | `hotpath.holdout.read_salt` raises `LookupError` inside `_build_pipeline` and the API does not start; `workers.runner.run()` never reads it. Uncaught on purpose: an unsalted arm assignment is *predictable* rather than merely weak, so the lift the kill switch reads is compromised from the first request. Not the compose file's `dev-salt-change-me` in anything but local dev. |
| `TB_ADMIN_KEY` | neither — **optional** | The API starts, and every `/admin/*` route answers a uniform 401 (`api.main._resolve_admin_key_hash` returns `None`). Set it to bootstrap the first `POST /admin/projects` / `POST /admin/agents/register` before any OIDC or API-key principal exists; a process with no need for `/admin/*` (a read-replica dashboard, say) must still boot, which is why this one is not fatal. |

`TB_LLM_API_KEY` (`LLMProviderConfig.api_key_env`) and `TB_S3_ACCESS_KEY` /
`TB_S3_SECRET_KEY` (`TraceStoreConfig`) follow the same pattern as `TB_ADMIN_KEY` — read from
the environment by name, not modelled as settings fields, and needed only by the deployments
that actually reach the provider or bucket they name.

Entry points (`pyproject.toml`): `tracebed-api` (`tracebed.api.main:run`) and
`tracebed-worker` (`tracebed.workers.runner:run`) — one process type for the sync API, one
for the async worker loop. Both read the same `TracebedSettings`, but as the table above
shows they do **not** need the same environment: the API additionally requires the holdout
salt, because it is the process that assigns arms.

## 2. Migrations

CI, the phase gates, and `tests/phase0/test_migrations.py` all call
`tracebed.stores.pg.migrate.apply_migrations(dsn)` / `rollback_migrations(dsn)` /
`current_revision(dsn)` directly — never a subprocess shelling out to the `yoyo` CLI — so the
exact same code path runs the migration tree in every environment, including CI.

```python
from tracebed.stores.pg.migrate import apply_migrations
apply_migrations(dsn)   # dsn = TB_STORAGE__PG_DSN
```

For interactive/manual use against a local database, `migrations/yoyo.ini` is provided for
the `yoyo` CLI directly (it deliberately has no `database =` line committed — a checked-in
DSN reads as a checked-in credential):

```bash
yoyo apply    -c migrations/yoyo.ini --database "$TB_STORAGE__PG_DSN"
yoyo rollback -c migrations/yoyo.ini --database "$TB_STORAGE__PG_DSN"
yoyo list     -c migrations/yoyo.ini --database "$TB_STORAGE__PG_DSN"
```

Three migrations ship: `0001_registries.sql` (project/principal/agent_type/agent_registration,
embedding/scoring-epoch pins, config tables — unpartitioned, small), `0002_partitioned.sql`
(the full learning-plane DDL, `LIST PARTITION BY (project_id)`, plus `work_queue`/
`dead_letter`), `0003_rls.sql` (`ENABLE ROW LEVEL SECURITY` + `FORCE ROW LEVEL SECURITY` on
every partitioned table, and the app role's grants — the app role is **not** table owner and
holds **no** `BYPASSRLS`). Each has a matching `.rollback.sql`. Migrations are plain SQL by
design (D-034: "Alembic drags SQLAlchemy against the lean-deps rule; a first-party runner
reinvents ordering/locking yoyo already solved") — there is no ORM layer to fight when reading
them.

New projects and DDL drift both go through `stores.pg.partitions`, not a fourth migration file
per project — see below.

## 3. Partitions, the 1,000-project ceiling, and the HASH migration path

`stores.pg.partitions.create_project_partitions` provisions one partition per project per
learning-plane table (`stores.pg.ddl.PARTITIONED_TABLES`, ~13 tables) at project-creation
time, under migration/admin privileges — never through the RLS-scoped app connection `Repo`
uses. `ensure_schema_current` re-runs the same DDL for every *existing* project when the
partition/RLS/grant/index shape changes, so new and existing projects can never drift from
each other. `drop_project` is the deletion mechanism: `DETACH`/`DROP` across all ~13 tables in
one transaction — O(1) per table, not a `DELETE` that has to visit every row.

**Documented ceiling: 1,000 projects per instance** (≈13,000 partitions total). This is not a
soft guideline — the Postgres query planner considers every partition of every partitioned
table referenced in a plan even when partition pruning eliminates most of them at execution
time, and planning time degrades measurably once a table's partition count reaches the low
thousands. Approaching this ceiling shows up as rising query-planning latency across *every*
partitioned-table query, project-independent — it is a whole-instance symptom, not a
per-project one, and it will not announce itself as an error.

**Migration path past the ceiling.** New deployments approaching 1,000 projects switch
`PARTITION BY LIST (project_id)` to `PARTITION BY HASH (project_id)` in the DDL. Project
deletion becomes a bulk `DELETE FROM t WHERE project_id = $1` per table instead of
`DETACH`/`DROP` — slower per deletion, but partition count stops scaling with project count
at all. The public API (`create_project_partitions` / `drop_project` / `ensure_schema_current`)
does not change across that switch (D-017: "the repository hides the strategy") — nothing
outside `stores/pg/` should ever branch on which partitioning strategy a deployment uses. **A
deployment operator's job when approaching the ceiling is choosing to make this switch on a
new deployment**, not migrating a live one in place — DECISIONS.md does not describe an
in-place LIST→HASH migration for an already-populated instance, and inventing one is exactly
the kind of quiet workaround PLAN.md §10 forbids; treat "past the ceiling" as a capacity
planning signal to provision a second instance or a HASH-partitioned one, not a live migration
to perform under load.

## 4. Spend cap

`workers.spend.SpendMeter` records every LLM call into `spend_ledger`, rolled up by
`(project, UTC day, worker, model)` — bucketed on the **UTC calendar day** always, computed
from `Clock.now()`, never local time, so "spend for 2026-07-25" means the same 24-hour window
in every deployment timezone. `SpendConfig.daily_llm_cap_usd` (default 25.0/project/day) is
the threshold `CapStatus.exceeded` reports against.

`workers.spend_enforce.SpendEnforcer` is what actually *acts* on that status: on cap,
background workers pause and an alert fires — **the hot path is structurally unaffected**.
This is not a convention; `scripts/purity_check.py` proves no `workers` module (this one
included) is reachable from `hotpath/`'s import graph, and `hotpath.pipeline.Pipeline` has no
constructor dependency that is, or reaches, a spend meter. There is no value of "spend today"
that changes what `Pipeline.retrieve()` returns. A cap that took down retrieval would turn a
billing event into an outage — PLAN.md §6 is explicit that this must not happen.

**Deliberate exemption (PLAN.md §10):** org-level rollup of spend/token/latency is billing
metadata and is the *one* explicit exception to the cross-project aggregation ban. Nothing
else — memory content, memory-derived statistics, "anonymized" aggregates — gets the same
exemption. If you build an org-rollup dashboard, it must read only `spend_ledger` (and its
telemetry siblings), scoped project-by-project and summed outside the query layer, never a
query that aggregates memory content across projects.

## 5. The kill switch and its lift report

`workers.killswitch` auto-disables one `(agent_type_id, mem_type)` cell — never a whole
project, never a whole mem_type across every agent type — when **all three** of these hold,
independently checked so an operator (and every test) can see which one, if any, is missing:

1. **Lower confidence bound < 0**, from `workers.lift.LiftEstimate.lower_bound` — never the
   point estimate. A `-0.01` point estimate with a `[-0.30, +0.28]` interval is not the same
   evidence as `-0.01` with a tight interval, and the trigger reads the bound, not the centre.
2. **Sustained for `killswitch.window_days`** (default 14): the bound must be adverse on
   *every* day of an unbroken trailing window, not merely on the day being evaluated.
3. **Minimum cell N (`killswitch.min_cell_n`, default 200) on every one of those days.** A
   "sustained" run of days with too few observations to trust is thin data agreeing with
   itself, not evidence.

A fourth control — Benjamini-Hochberg correction across the whole agent-type × mem-type grid
— exists because even when every cell clears the three conditions above at nominal alpha,
testing many cells simultaneously produces roughly one false positive per window by chance
alone.

**Reading the lift report correctly is the whole point.** `workers.lift` never compares "every
`memory_on` run" against "every `holdout` run" — `abstention.target_abstention_pct` is ≥50 by
design, so most calls in *either* arm abstain or degrade, and averaging that noise into two
buckets computes the difference between two clouds of nothing. The corrected comparison is
runs where **something was actually injected** (`arm=memory_on`, `injection_log` rows exist)
against **shadow-retrieved holdout** runs (`arm=holdout`, retrieval ran and *would* have
placed a memory), stratified per `(agent_type_id, mem_type)` cell. When you read a lift
report:

- Look at the **lower confidence bound** per cell, not an aggregate number — a pooled
  estimate across agent types averages out "helps type A, hurts type B" into "no effect",
  which is the same failure at a different grain.
- `"operational lane only"` — i.e., the quality lane showing no measurable lift anywhere — is
  a **documented passing outcome** (PLAN.md §7 Phase 3 gate), not a sign something is broken.
  2026 evidence at the time this was written says it is the likely result; do not chase a
  positive number that isn't there.
- A triggered cell writes exactly one `killswitch_state` row for that `(agent_type_id,
  mem_type)` — check `evidence` on that row for the three booleans above plus the BH-corrected
  q-value, not just the fact that it fired.
- There is **no automatic re-enable**. Recovery is an operator action
  (`record_override`, tagged `evidence["source"] == "operator_override"`, distinguishable
  from an automatic trigger's `"auto_killswitch"`) — and a known limitation applies: a
  standing override is not re-checked before the next automatic evaluation, so a cell that
  still meets the trigger condition will be disabled again on the next tick. Re-running the
  evaluation right after an override without also fixing the underlying cause will look like
  the override "didn't take."

`workers.safety_lift` (CUTTABLE improvement 2) runs the identical sustained-window/min-N/BH
machinery against policy-violation rate instead of task-quality lift, with the adverse
direction flipped (`AdverseDirection.HIGHER`, not `LOWER`) — a benign accumulation of
retrieved content can degrade safety with no attacker present, and render-as-data does nothing
to stop that kind of drift because it is statistical, not an injection attack.

## 6. The review queue

Five kinds of row land in `review_queue`, each with a `reason` string naming the memory (or
key), the numbers involved, and the threshold that was **not** met — written for a human to
act on, not as an error code:

1. **Scan rejections** — `core.scans.scan` refused content outright.
2. **Open contradictions** — `candidate → validated`'s `open_contradiction` guard is blocking
   promotion and neither the weaker- nor equal/stronger-provenance edge resolves it; nothing
   in the state machine will ever clear this automatically.
3. **K−1 retirement candidates** — `validated → retired`'s guard is satisfied on Q and
   scored-use-count but refuses on distinct-principal count below K
   (`retirement.min_distinct_principals`, D-021) — routed here instead of auto-retired.
4. **Clamp-binding alerts** — `derived_state`'s movement clamp bound three consecutive updates
   (`derived.clamp_alert_consecutive`).
5. **Divergence alarms** — the fast (24h) and slow (30d) reference values for a derived-state
   key have diverged past `derived.divergence_alarm_pct`.

Plus, from Recall & Rollback (`workers.forensics`, CUTTABLE improvement 1): the contained
memory itself, each re-opened outcome, and each derived descendant — one row per affected
item, so a blast-radius report is actionable item-by-item, not one opaque summary row.

**A live containment gap, reported rather than fixed** (see `workers/forensics.py`'s own
docstring): `domain.state_machine.TRANSITIONS` has no `validated → quarantined` edge, so a
poisoned memory discovered at `validated` is contained via the nearest *legal* edge that
removes it from `RETRIEVABLE_STATUSES` — usually `validated → stale`. But `stale → validated`
is a legal edge `workers.revalidation` takes **unattended** whenever its verifier re-verifies,
and a locally-correct poisoned memory (the classic OEP shape) is exactly the kind that
re-verifies. `BlastRadiusReport.containment_reversible_by` names every status a background
worker can walk the row back to — **check this field**; a non-empty tuple means the
containment does not hold unattended and a human decision (an operator edit, or a fix to
`domain/state_machine.py`) is required before treating the memory as actually contained.

## 7. Erasure — delete-by-subject and crypto-shredding

`workers.edit_ops.delete_by_subject` is the operator-facing erasure entry point. It does two
independent things, both erasure:

1. **`crypto.shred.SubjectKeyManager.destroy_subject`** destroys that subject's KEK. Every
   trace-payload section tagged with the subject becomes cryptographically unreadable —
   `destroyed_at` is set, `wrapped_kek` is overwritten with `b""`. **This is irreversible by
   design.** There is no "undo" for a destroyed KEK; the ciphertext it protected is
   permanently unrecoverable the instant this call returns. Before calling this in production,
   be certain the subject_tag is correct — there is no confirmation step below this call, and
   none should be added here (a confirmation step belongs in the dashboard/API layer calling
   this, not in the destructive primitive itself).
2. Every governed `memory_item` carrying that `subject_tag` is additionally tombstoned through
   `state_machine.apply()` (`erasure_or_approved_delete=True`, the `*→tombstoned` wildcard row)
   — never a direct status write. A memory reaching `tombstoned` any other way is, by
   construction, not possible (PLAN.md §10: "no admin bypass exists in code").

**What survives, deliberately.** The trace object's bytes are never rewritten — crypto-
shredding resolves the genuine contradiction between "the trace is the erasure target" and
"the trace is the audit record" by encrypting payload *sections* under per-subject keys, so
destroying a key makes exactly that subject's content unreadable while the object stays
byte-immutable and the provenance chain of every derived memory (which points at the
still-existing object, just now with unreadable sections) stays intact. `trace_subject` rows
make "which runs mention this subject" an indexed lookup, not a full-corpus scan, which is
what makes delete-by-subject tractable at all.

**Project deletion** (`stores.pg.partitions.drop_project`) is the other, coarser erasure
mechanism: `DETACH`/`DROP` across every partitioned table, O(1) per table — every row, index,
and (if the trace store driver supports `delete_project`) trace object gone at once. Use this
for "this project is over, remove everything", not as a substitute for delete-by-subject when
only one subject's data needs to go.

## 8. Backup and restore

**Because destroying a subject KEK is irreversible by design, a backup strategy built around
"restore the whole database from yesterday's snapshot" silently un-erases every subject
erased since that snapshot.** This is the one operational hazard this document exists to name
explicitly: a restore is not a neutral rollback here the way it is for an ordinary OLTP
database, because "the erasure took effect" and "the backup predates the erasure" are two
facts that actively conflict, and a naive restore resolves that conflict by making the
erasure not have happened.

Practical guidance, in order of preference:

1. **Prefer point-in-time recovery to a moment after the erasure, not a full nightly
   snapshot from before it**, whenever the two are in tension. If a subject was erased at
   14:00 and a restore target is 09:00 the same day, that restore reintroduces a wrapped KEK
   this system has already told a data-subject was destroyed.
2. **Back up `subject_key` and the rest of the registry/learning plane on the same cadence and
   as one consistent snapshot.** A backup regime that snapshots `subject_key` less frequently
   than the tables whose content it protects can restore ciphertext with no key at all (a
   correctness bug, not a security one — that data was already supposed to be unreadable) or,
   the more dangerous direction, restore a key that has since been destroyed alongside content
   that was supposed to stay shredded.
3. **`TB_MASTER_KEY` is not itself in Postgres and is not covered by a database
   backup.** Losing it makes every wrapped subject KEK in every backup permanently
   unusable — indistinguishable, from the data's perspective, from every subject having been
   erased simultaneously. Back it up through whatever secret-management system your
   deployment already uses for other root secrets, separately from the database backup
   pipeline, and test restoring it independently of a database restore drill.
4. **Treat a restore as an event that needs its own audit entry** naming the snapshot time and
   which erasures (if any) fall between the snapshot and the restore, once `AuditSinkPort` has
   a real implementation (see `docs/ADAPTER-GUIDE.md`'s `AuditSinkPort` section for the
   current gap) — this document cannot make that check automatic today, only name it as a
   required step for whoever runs a restore in the meantime.

## 9. Gate reports — what PASS, FAIL, SKIPPED-NO-STACK, and INCOMPLETE-DATA mean

Every phase gate (`harness/phase{0,1,2,3}_gate.py`) runs its phase's full `pytest -m phaseN`
selection once — never two separate runs that could disagree with each other — plus the
static gates (`scripts/license_check.py`, `scripts/raw_sql_lint.py`, `scripts/purity_check.py`)
and, where a bare pass/fail can't carry the needed number, direct calls into the relevant
`harness/*.py` module (lift sim, ledger audit, guessed-reward drill, redteam probes, ...).
Every individual assertion in the resulting `gate_report_phaseN.md` is exactly one of four
verdicts — **the report must not lie**, so there is no fifth, softer verdict:

- **`PASS`** — every test/call backing this assertion ran and passed.
- **`FAIL`** — at least one test/call backing it ran and failed. Always a genuine defect;
  never something to explain away in the report itself.
- **`SKIPPED-NO-STACK`** — at least one test backing it is `@pytest.mark.integration` and could
  not run because Postgres/Valkey/S3 is unavailable (this build environment has none of the
  three), and *none* of the ones that did run failed. This is expected and correct on a
  machine with no Docker — it is not a silent pass, it is an honest "untested here."
- **`INCOMPLETE-DATA`** — this gate runner found **zero** tests matching the assertion's
  selector at all. This is different from `SKIPPED-NO-STACK` on purpose: it usually means a
  grouping keyword in the gate runner itself has drifted from a test file it's supposed to
  select — a defect in the gate report, not a legitimate "no stack available" skip. It must
  never be silently folded into `SKIPPED-NO-STACK`.

**The overall gate verdict is `PASS` only when every individual assertion is `PASS`.** Any
`SKIPPED-NO-STACK` or `INCOMPLETE-DATA` anywhere makes the overall verdict `INCOMPLETE` — this
is why this repository's own baseline, in this environment, reads `harness/phase0_gate.py →
INCOMPLETE 6/7` and `harness/phase1_gate.py → INCOMPLETE 6/7`: the leak suite and the latency
bench both need a live Postgres this build environment does not have, and reporting them as
`PASS` anyway would be exactly the lie this section exists to rule out. **`INCOMPLETE` is not
`PASS`, and a report claiming otherwise is the defect, not the environment.**

Phase 2 and Phase 3 gates (`phase2_gate.py` → `PASS 7/7`, `phase3_gate.py` → `PASS 9/9`) run
fully offline against fakes — their invariants (staleness injection, guessed-reward, red-team
probes, ledger reconciliation) do not need a live store, which is why they can reach a real
`PASS` in this same environment while Phase 0/1's leak suite and latency bench cannot.

---

*See also: `docs/ADAPTER-GUIDE.md` (the port contract this operations model plugs into),
`docs/MEMORY-FLOW.md` (the read/write/lifecycle model), `docs/ARCHETYPE-CONFIGS.md`
(starting configurations for common deployment shapes), `PLAN.md` §5–§7 (data model and
phase gates in full), `DECISIONS.md` (why each threshold and mechanism is what it is).*
