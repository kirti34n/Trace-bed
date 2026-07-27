# Tracebed — Archetype Configurations

> Three real starting `TracebedSettings` configurations: `general_purpose` (the shipped
> defaults), `bfsi_soc` (conservative — high abstention, strict promotion, low spend), and
> `high_volume` (~100k runs/day — tighter budgets, bigger batches, more aggressive sweeps).
>
> Rev. 2026-07-26 · Files: `docs/archetypes/{general_purpose,bfsi_soc,high_volume}.toml` ·
> Loaded and validated by `tests/phase4/test_archetype_configs.py`.

## How to use these files

Each `.toml` file loads directly into `tracebed.domain.config.TracebedSettings`:

```python
import tomllib
from tracebed.domain.config import TracebedSettings

with open("docs/archetypes/bfsi_soc.toml", "rb") as fh:
    settings = TracebedSettings(**tomllib.load(fh))
```

Two fields are placeholders in every archetype — `[storage].pg_dsn` and
`[embedding].model_version` — because `domain/config.py` gives neither a default (a process
that started with a guessed DSN or an unpinned embedding version would be a much worse
failure than one that refuses to start at all).

**Read this before deciding how to supply them.** Constructor keyword arguments outrank
environment variables in `pydantic-settings` (`init_settings` is the highest-priority source;
`env_settings` sits below it). So in the snippet above, a `[storage].pg_dsn` line in the TOML
**wins over** `TB_STORAGE__PG_DSN`, it is not overridden by it. There are exactly two correct
ways to supply these values, and mixing them silently picks the file:

1. **Replace the placeholders in your copy of the file**, and let the file be the source of
   truth. (Recommended if you are checking the archetype into your own deployment repo — but
   then do not put a real DSN in it; point it at a secret-templating step.)
2. **Delete the `[storage]` and `[embedding]` blocks from your copy** and set
   `TB_STORAGE__PG_DSN` / `TB_EMBEDDING__MODEL_VERSION` in the environment. With the keys
   absent from the mapping, `env_settings` supplies them.

Doing neither — leaving `"CHANGEME"` in the file *and* setting the environment variable — is
the failure this note exists to prevent. `pg_dsn` fails loudly (nothing connects), but
`model_version = "CHANGEME"` fails **silently**: it is stamped onto
`memory_item.embedding_model_id`/`embedding_model_version` for every row that gets embedded,
and the only way back from a vault pinned to a fictional version is the explicit re-embedding
migration PLAN.md §10 describes. `TestSettingsSourcePrecedence` (in
`tests/phase4/test_archetype_configs.py`) pins this ordering against the installed
`pydantic-settings`, so if the library ever reverses it, this paragraph fails CI instead of
becoming quietly wrong.

Everything else in an archetype file is a **starting point** for `TracebedSettings` — the
deployment-level process defaults. Per-project or per-agent-type tuning on top of an
archetype still goes through `project_config`/`agent_type_config` dotted overrides
(`PLAN.md` §6, C-03) at runtime, layered on whichever archetype the deployment started from;
it does not mean maintaining a fourth `.toml` file.

**Every field an archetype sets differs from the shipped default, and carries an inline `#`
comment explaining WHY.** A field absent from the file inherits the shipped default — see
`src/tracebed/domain/config.py` for what each one resolves to. An archetype never restates a
field at its default value, and `TestArchetypeOverridesActuallyDiffer` enforces that: a
restated default makes the *real* diff invisible, needs keeping in sync with `config.py`
twice as often for no benefit, and — the actual hazard — silently pins the old number on the
day the default moves.

## The three archetypes

### `general_purpose` — the shipped defaults

Nothing overridden beyond the two required placeholders. Start here unless something about
your deployment specifically argues for one of the other two profiles below. Every other
archetype in this directory is defined *relative to this one* — `bfsi_soc.toml` and
`high_volume.toml`'s own comments say "default X, this archetype uses Y" rather than
restating what "default" means each time.

### `bfsi_soc` — conservative: high abstention, strict promotion, low spend

For regulated or SOC-shaped agent fleets, where an incorrectly-trusted memory is more
expensive than a slower vault or a fuller review queue.

| Field | Default | `bfsi_soc` | Why |
|---|---|---|---|
| `abstention.cos_threshold` | 0.60 | 0.72 | fewer, higher-confidence injections |
| `abstention.bm25_norm_threshold` | 0.50 | 0.62 | same, lexical arm |
| `abstention.rarity_min_corpus_docs` | 200 | 400 | trust a young/narrow corpus less, not more |
| `promotion.min_outcomes` | 2 | 3 | one more corroborating outcome before `validated` |
| `promotion.min_distinct_principals` | 2 | 3 | one more distinct principal before `validated` |
| `retirement.min_distinct_principals` | 3 | 5 | K: harder for a few feedback sources to retire unilaterally |
| `lifecycle.quarantine_ttl_days` | 30 | 20 | unconfirmed content-derived memory resolves faster |
| `scoring.alpha` | 0.3 | 0.15 | any single outcome moves Q less |
| `proposals.per_project_daily_cap` | 50 | 15 | smaller moderation/review load per project |
| `killswitch.min_cell_n` | 200 | 300 | higher statistical bar before trusting a lift reading |
| `spend.daily_llm_cap_usd` | 25.0 | 8.0 | smaller, more tightly-scoped fleets expected |

### `high_volume` — ~100k runs/day: tighter budgets, bigger batches, more aggressive sweeps

For a fleet where run volume itself is the dominant cost and latency driver.

| Field | Default | `high_volume` | Why |
|---|---|---|---|
| `retrieval.total_budget_ms` | 300 | 220 | p99 latency compounds directly into infra cost at this volume |
| `retrieval.embed_timeout_ms` | 200 | 120 | degrade to lexical-only sooner rather than hold connections open |
| `retrieval.hnsw_max_scan_tuples` | 20000 | 8000 | bound per-query ANN scan cost directly |
| `budget.total_tokens` | 1200 | 900 | smaller context envelope bounds marginal token cost fleet-wide |
| `budget.static_prefix` | 700 | 500 | the static/dynamic split stays proportional to the shipped default |
| `budget.static_prefix_prefs` | 200 | 150 | prefs/lessons split inside the smaller prefix, same proportion |
| `budget.static_prefix_lessons` | 500 | 350 | same |
| `budget.dynamic` | 500 | 400 | the dynamic block shrinks with the envelope, not instead of it |
| `lifecycle.quarantine_ttl_days` | 30 | 14 | unconfirmed memory resolves before the backlog scales with volume |
| `lifecycle.candidate_ttl_days` | 45 | 21 | same reasoning |
| `lifecycle.decay_pct_per_idle_week` | 5 | 8 | faster idle decay keeps a naturally larger vault from growing unbounded |
| `proposals.per_project_daily_cap` | 50 | 200 | higher legitimate volume, still capped |
| `killswitch.min_cell_n` | 200 | 500 | cells fill faster at this volume; raise the floor to keep it meaningful |
| `abstention.rarity_min_corpus_docs` | 200 | 500 | corpus crosses the default floor quickly at this volume |
| `spend.daily_llm_cap_usd` | 25.0 | 150.0 | proportionally higher legitimate distiller/judge spend |
| `queue.batch_size` | 100 | 500 | amortise fixed per-claim `SKIP LOCKED` overhead |
| `queue.lease_seconds` | 30 | 45 | a bigger batch needs a longer lease to avoid re-claim churn |

**Two fields this archetype deliberately does *not* touch**, both because they look like
throughput knobs and are governance controls:

- `scoring.updates_per_memory_per_day` stays 1 (D-083). It bounds how fast one feedback
  source can walk one memory's Q, and D-021 sizes its four-calendar-day retirement window on
  it being 1.
- `derived.keep_versions` stays 20. `workers.derived_state` seeds the divergence alarm's
  **slow reference** from the earliest still-retained version (D-075), so retention is the
  reach of the only watchdog that catches a patient baseline-poisoning walk — and this is the
  archetype where a key updates most often per day, so 10 versions could be hours rather than
  weeks of history. An earlier revision of `high_volume.toml` lowered it to 10 with the
  comment "debugging depth is the only thing traded away"; that was false, and
  `TestInvariantFloors::test_derived_keep_versions_is_never_lowered` now makes it
  unrepeatable.

## Invariant floors this test enforces (and why they are floors, not defaults)

`tests/phase4/test_archetype_configs.py::TestInvariantFloors` asserts every archetype clears
these, in addition to loading and validating:

- **`promotion.min_distinct_principals >= 2`** and **`retirement.min_distinct_principals
  (K) >= 2`.** `domain/config.py` places no `Field` constraint on either — nothing stops a
  hand-edited config from setting K to 1 or 0. A floor of 1 defeats the entire reason D-021 /
  invariant 7 require a *distinct*-principal count at all: a single principal could promote or
  retire a memory unilaterally either way, which is exactly the Sybil-shaped hole those
  thresholds exist to close.
- **`promotion.min_outcomes >= 1`**, **`promotion.failure_lesson_outcomes >= 1`**,
  **`retirement.min_scored_uses >= 1`.** A zero here makes the corresponding transition
  unconditional on the one piece of evidence it is supposed to require.
- **`killswitch.min_cell_n >= 200`.** PLAN.md's own stated statistical floor
  (`killswitch.min_cell_n`'s documented default) is 200 for a reason
  `workers.killswitch`'s docstring states directly: "a 'sustained' run of days with too few
  observations to trust is not evidence, it is thin data that happens to agree with itself."
  An archetype is free to raise this bar (both `bfsi_soc` and `high_volume` do, for different
  reasons — see the tables above) but never to lower it below the point where the kill switch
  stops meaning anything.
- **`derived.keep_versions` is never below the shipped default.** It is not a storage knob:
  `workers.derived_state` seeds the divergence alarm's slow reference from the earliest
  still-retained version (D-075), so lowering retention shortens the only window in which a
  patient baseline walk is detectable, with nothing anywhere reporting the reduced coverage.
- **`scoring.q_start > lifecycle.archive_floor`.** Enforced by `EffectiveConfig`'s own
  cross-section validator (exercised through `ConfigResolver.effective()`, not merely at
  `TracebedSettings` construction) — a seed at or below the archive floor archives every
  `validated` memory on its first idle sweep, silently emptying the vault. No archetype here
  changes either field from the shipped default, and the test both checks the pair directly
  and confirms `ConfigResolver.effective()` does not raise `ConfigError` for any of the three.

None of these floors is a ceiling: an archetype (or a `project_config` override on top of
one) is always free to be *more* conservative than the floor. The test only refuses a
direction that quietly defeats the invariant the field exists to enforce.

---

*See also: `docs/OPERATIONS.md` §5 (reading the kill switch and its lift report against
whichever archetype is deployed), `docs/ADAPTER-GUIDE.md` (the ports these settings do not
cover — deployment-level sections are intentionally outside `OVERRIDABLE_SECTIONS`),
`src/tracebed/domain/config.py` (the source of truth every field above is copied from).*
