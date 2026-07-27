# Tracebed dashboard

React 18 + Vite + TypeScript (strict) + Tailwind, served on `:8111`.
The operator console for Tracebed: PLAN.md §3 (stack), §5–§7 (what each view
is for).

```
npm ci           # not `install` — the licence gate judges the locked tree
npm run dev      # :8111, proxies /v1 /admin /export to :8110 (vite.config.ts)
npm run build    # tsc --noEmit && vite build -> dist/
npm run lint     # eslint . --max-warnings 0

node scripts/license_check.mjs --self-test   # prove the licence gate bites
node scripts/license_check.mjs               # gate the resolved npm tree
```

All four run in CI as the `dashboard` job (`.github/workflows/ci.yml`), in
that order — licence gate first, for the same reason the Python `static` job
runs its licence gate first: a dependency tree is cheapest to reject before
anything is built on top of it.

Docker: `docker/dashboard.Dockerfile` builds `dist/` and serves it via
`nginx.conf`, which reverse-proxies `/v1`, `/admin` and `/export` to the `api`
compose service on `:8110`.

There is **no test harness**. No Vitest, no RTL, no `*.test.*` file anywhere
under `dashboard/`. Verification is `tsc` + `eslint` + `vite build` + the
licence gate, and nothing else. This is a real gap, not an omission from this
document — see "Known weaknesses" at the end.

---

## Which views are live, and against what

This is the table to check first. **No view in this tree is fixture-backed.**
Every hand-authored fixture was deleted; there is no code path in any view
that renders a number the server did not send. But "live" is not one thing,
and the distinction below is load-bearing:

- **Aggregate route** — a purpose-built server-side endpoint. Paginated or
  windowed, computed by the server, no client-side derivation.
- **Export-derived** — the view streams `GET /export/project` (the whole
  project as NDJSON: five tables, no filters, no pagination) and derives its
  table in the browser. `useExportRows` caps at `maxRows` (default 5000) and
  exposes `truncated: boolean`; **every** view below that uses it renders that
  flag. These views are live but partial by construction, and slower and
  heavier than they need to be.
- **Empty by construction** — the route is real, tested and scoped, but no
  writer exists anywhere in the codebase to put rows behind it. It returns an
  honest empty page on every build shipped today.

| View | Route | Data source | What an operator does here |
|---|---|---|---|
| **Overview** | `/export/project`, `/admin/killswitch_state`, `/admin/review_queue`, `/admin/spend` | mixed (aggregate + export-derived) | First screen of the morning. Answers "did anything change overnight" — kill-switch state, open review items, spend, vault counts. Every tile is badged `Live data`. |
| **Injections** | `/export/project` | export-derived | Trace what was actually placed into a prompt, and follow a row to the memory that produced it. |
| **Abstention** | `/export/project` | export-derived | Confirm the retriever is abstaining as designed (≥50% by PLAN.md §6). A *low* abstention rate is the alarming reading, not a high one. |
| **Health** | `/healthz`, `/export/project` | mixed | Liveness plus queue/worker freshness. Where you look when a number elsewhere stops moving. |
| **Memory Vault** | `/export/project` | export-derived | Browse and filter the vault by status/tier/type; the entry point to any individual memory. |
| **Memory Detail** | `/admin/memory/{id}`, `/export/project` | mixed | The only place a memory's provenance is readable. This is what makes a row governable rather than merely visible. |
| **Vault Trend** | `/export/project` | export-derived | Watch vault composition move over time — is the candidate pool growing faster than validation can clear it. |
| **Staleness** | `/admin/staleness/report` | aggregate route | Audit invalidation. Which events fired, what they plausibly matched, which memories are overdue for revalidation and were never staled. |
| **Consolidation** | `/admin/consolidation/diffs` | aggregate route, **empty by construction** | Would show what a consolidation sweep added, amended and removed. Nothing writes sweeps today (see gap 3), so it renders an empty page and says why on the page. |
| **Review Queue** | `/admin/review_queue` | aggregate route | Work the queue: what has been escalated for human judgement, and what is still open. |
| **Forensics** | `/export/project` | export-derived | Blast-radius scan: given a subject or memory id, what else is implicated. |
| **Lift & Q** | `/admin/lift/report` | aggregate route | **The view an operator quotes in a meeting.** Stratified lift per (agent type, memory type) with CI, N and BH-adjusted significance, plus a population snapshot of every scored memory's Q. |
| **Kill Switch** | `/admin/killswitch_state` | aggregate route, **read-only** | See what the kill switch actually decided and on what evidence. There is no write route — nothing here can arm or disarm it. |
| **Spend** | `/admin/spend` | aggregate route | Budget consumption by day. |
| **Registry** | `/admin/whoami`, `/admin/projects`, `/admin/agents/register` | aggregate route + admin writes | Provision a project, register an agent type, see which scope the current credential resolves to. |
| **Settings** | `/admin/whoami`, `/admin/config` | aggregate route | Paste credentials; read this project's resolved configuration. |

### Three purpose-built routes currently have no consumer

Honest and worth fixing, because each one exists specifically to replace an
export-derived view above:

| Route | Should replace | Status |
|---|---|---|
| `GET /admin/memory` (`MemoryListOut`, paginated) | **Memory Vault**'s full-export stream | unused; `useMemoryList` has zero callers |
| `GET /admin/injections` (paginated, project-scoped) | **Injections**' full-export stream | unused; view still streams the export |
| `GET /admin/invalidations` (`InvalidationListOut`) | nothing directly — **Staleness** uses the richer report route instead | unused; `useInvalidations` has zero callers |

Each of the three views involved is separately audited, works, and discloses
its own 5000-row truncation, so none of them is *wrong* — they are just
pulling an entire project export to render one table when a purpose-built
route is sitting there. Rewriting them was outside the blast radius of the
work that added the routes.

---

## The API surface

`src/tracebed/api/routes_v1.py`, `admin.py` and `reports.py` are the real
routes — the complete surface, from every `@router.*` decorator in the repo:

| Route | Auth | What it does |
|---|---|---|
| `POST /v1/retrieve` | principal | sync, budgeted retrieval |
| `POST /v1/trace`, `/v1/trace/batch` | principal | 202, enqueue only |
| `POST /v1/feedback` | principal | 202, enqueue only |
| `POST /v1/propose_memory` | principal | 202, enqueue only |
| `POST /v1/invalidation` | principal | 202, synchronous single-row insert |
| `POST /admin/projects` | admin key | create project + partitions + KEK |
| `POST /admin/agents/register` | admin key | create agent_type/principal/registration |
| `GET /admin/whoami` | principal | the scope this credential resolves to |
| `GET /admin/memory` | principal | paginated memory list |
| `GET /admin/memory/{id}` | principal | one memory item, by id |
| `GET /admin/review_queue` | principal | review items, open or all |
| `GET /admin/killswitch_state` | principal | recorded kill-switch decisions + evidence |
| `GET /admin/invalidations` | principal | invalidation events |
| `GET /admin/spend` | principal | spend by day |
| `GET /admin/config` | principal | this project's resolved config |
| `GET /admin/lift/report` | principal | stratified lift + Q snapshot + methodology |
| `GET /admin/staleness/report` | principal | invalidation evidence + revalidation candidates |
| `GET /admin/consolidation/diffs` | principal | `derived_state` deltas (no writer yet) |
| `GET /admin/injections` | principal | paginated injection feed |
| `GET /export/project` | principal | NDJSON dump of the whole project (5 tables, no filters, no pagination) |
| `GET /healthz` | none | liveness |

**No request may carry a `project_id`.** The server derives scope from the
principal, and `client.ts`'s `assertNoProjectId` walks every request body
recursively in dev builds and throws if it finds one. Exactly one call site is
allowlisted — `useRegisterAgent` / `POST /admin/agents/register` — because
that route is an admin *naming* the project being provisioned, not a data
route reading within one.

`src/api/types.ts` mirrors the wire types by hand from `domain/enums.py`,
`domain/state_machine.py`, `domain/events.py`, `domain/memory.py`,
`api/models.py`, `api/models_reports.py`, `stores/pg/rows.py`. If the Python
source changes a spelling, this file has to change with it — nothing here is
independently authoritative, and a mismatch is invisible to `tsc`.

---

## Design tokens (`src/index.css` + `tailwind.config.ts`)

Every colour a component uses is a semantic Tailwind class resolving to a CSS
variable, defined once, with a light and a dark value. **Never** reach for a
raw Tailwind colour (`bg-green-500`, `text-indigo-600`, …) at a call site —
that is what makes "quarantined never reads like validated" a property of the
token table instead of something every author has to remember.

| Token group | Classes | Meaning |
|---|---|---|
| Surface | `bg-bg`, `bg-surface`, `bg-surface-raised`, `border-border`, `border-border-strong` | Page background, card background, raised/hover background, hairline and stronger border |
| Text | `text-text`, `text-text-muted`, `text-text-faint` | Primary, secondary, tertiary text |
| Accent / danger | `bg-accent` / `text-accent-contrast`, `bg-danger` / `text-danger-contrast` | Primary actions, focus; destructive actions |
| Focus | `ring-focus` | The one visible focus ring, applied globally via `:focus-visible` in `index.css` |
| Status (9) | `bg-status-{name}-bg`, `text-status-{name}-fg`, `border-status-{name}-border` for `name` in `quarantined, candidate, validated, superseded, stale, retired, archived, pinned, tombstoned` | Memory lifecycle state (`domain/state_machine.py`'s `Status`). Always paired with an icon + label in `StatusBadge` — never colour alone. |
| Tier | `text-tier-a`, `text-tier-b` (+ `border-tier-a`/`b`, solid vs dashed border) | Trust tier A (structural) vs B (content-derived) |
| Risk | `text-risk-low/med/high` | Reserved for a future safety/lift view (PLAN.md §8 improvement 2) |
| Chart | `stroke-chart-line`, `fill-chart-band`, `stroke-chart-grid`, `fill-chart-axis` | `Chart.tsx`'s line, confidence band, gridlines, axis labels |

Dark mode: `tailwind.config.ts` uses `darkMode: "class"`. `lib/theme.ts`
toggles a `.dark` class on `<html>`, persisted to `localStorage["tb:theme"]`;
`index.html` has an inline pre-paint script that applies the persisted (or OS)
preference before React mounts, so there is no flash.

### Non-negotiable rendering rules

These are properties of the views, enforced by review rather than by a linter,
and every one of them exists because breaking it produces a plausible-looking
lie rather than a visible bug:

1. **Never render a computed figure without its confidence interval and its
   N.** Below `min_cell_n` (200 per arm), render an explicit refusal — the
   words "Insufficient data" and the actual N — never a bare bound.
2. **Never draw a continuous line across a scoring-epoch boundary.** Values
   scored by different judge models are not comparable on one ruler.
3. **Never draw a line through points that are not a series.** `Lift & Q`'s Q
   section is one point per *memory*, not one memory over time, so it is drawn
   as an unconnected scatter (`Chart`'s `mode: "points"`). A line there would
   render "Q is trending up" out of data containing no trend.
4. **Never encode status in colour alone.** Word first, then icon, then
   colour. `Chart` legends reproduce marker shape and dash pattern, not hue.
5. **Loading, empty, error and no-permission states on every view.** Empty is
   the *common* case, not the edge case.
6. **Row keys are server-issued ids**, never array indices.
7. **Full payloads live in keyboard-reachable `<details>`**, never in a
   `title` attribute.

---

## Component contracts

### `Table<T>` (`src/components/Table.tsx`)

```ts
interface ColumnDef<T> {
  key: string;
  header: string;
  render: (row: T) => ReactNode;
  sortValue?: (row: T) => string | number | null;   // omit => unsortable column
  align?: "left" | "right" | "center";
  width?: string;         // e.g. "12ch" — set for every id/status/numeric column
  numeric?: boolean;      // right-aligns + tabular-nums
}
interface TableProps<T> {
  columns: ColumnDef<T>[];
  rows: T[];
  getRowId: (row: T) => string;
  loading?: boolean;              // skeleton rows at the SAME cell height as real rows
  loadingRowCount?: number;       // default 8
  onRowClick?: (row: T) => void;
  density?: "comfortable" | "compact";
  caption: string;                // required; screen-reader-only <caption>
  initialSort?: { key: string; direction: "asc" | "desc" };
  maxHeight?: string;             // caps body height so the sticky header has a scroll ancestor
}
```

Sticky header, tabular-nums numeric columns, roving-tabindex keyboard
navigation (`ArrowUp`/`ArrowDown`/`Home`/`End`/`Enter`), click-to-sort with an
`aria-sort` announcement, skeleton loading at fixed row height. `sortValue`
returning `null` sorts last in **both** directions — a refused cell has no
magnitude to rank by.

### `StatusBadge` / `TrustTierBadge` (`src/components/StatusBadge.tsx`)

```ts
function StatusBadge(props: { status: Status; className?: string }): JSX.Element;
function TrustTierBadge(props: { tier: TrustTier; className?: string }): JSX.Element;
```

One file, because tier and status are always shown side by side. Every status
renders a fixed icon **and** label, never colour alone. Tier additionally
varies border style (solid A, dashed B) as a second non-colour signal.

### `Chart` (`src/components/Chart.tsx`)

```ts
type ChartMarkerShape = "circle" | "square" | "diamond" | "none";

interface ChartSeries {
  label: string;
  points: { x: number; y: number }[];
  colorClassName?: string;
  strokeDasharray?: string;      // second, non-colour channel for telling series apart
  marker?: ChartMarkerShape;     // third channel; reproduced in the legend
  mode?: "line" | "points";      // "points" NEVER draws a connecting path
}
interface ChartBand { label: string; points: { x: number; yLow: number; yHigh: number }[] }
interface ChartProps {
  series: ChartSeries[];
  band?: ChartBand;                          // confidence band — REQUIRED for any lift view
  width?: number; height?: number;           // viewBox units, default 640x240, scales via CSS
  xTickFormat?: (x: number) => string;
  yTickFormat?: (y: number) => string;
  yDomain?: [number, number];
  ariaLabel: string;                         // required
}
```

Hand-rolled SVG, no charting dependency. A series with fewer than two points
renders its markers only, never a degenerate invisible path. The `figcaption`
legend reproduces dash pattern and marker shape, so the chart survives
greyscale printing and colour-vision deficiency.

`mode: "points"` exists specifically so "these values are not a series" is
expressible in the type rather than being a convention an author can forget.

### `EmptyState` / `ErrorState`

```ts
function EmptyState(props: {
  title: string; description?: string; icon?: ReactNode;
  action?: { label: string; onClick: () => void }; bordered?: boolean;
}): JSX.Element;

function ErrorState(props: { error: unknown; onRetry?: () => void; title?: string }): JSX.Element;
```

`ErrorState` switches copy on `ApiError.kind` (`unauthorized`, `forbidden`,
`not_found`, `conflict`, `validation`, `server`, `network`, `cancelled`), so a
view never invents its own error copy. `unauthorized` and `forbidden` are the
**no-permission** state: they render with zero data behind them.

### `ConfirmDialog` (`src/components/ConfirmDialog.tsx`)

```ts
interface ConfirmDialogImpact { label: string; value: string | number }
interface ConfirmDialogReasonField {
  label: string; placeholder?: string; required?: boolean;
}
interface ConfirmDialogProps {
  open: boolean; title: string; description?: string;
  impact: ConfirmDialogImpact[];       // REQUIRED — shown before the confirm button
  reasonField?: ConfirmDialogReasonField;
  confirmLabel?: string; cancelLabel?: string;
  tone?: "danger" | "default";
  busy?: boolean;
  onConfirm: (reason?: string) => void; onCancel: () => void;
}
```

Focus-trapped (Tab/Shift+Tab cycle inside), `Escape` cancels, focus returns to
the trigger on close, rendered via `createPortal` to `document.body` so it is
never clipped by an ancestor's `overflow`. `impact` is required because a
confirmation that does not say what it will affect is a speed bump, not a
safeguard.

---

## API layer (`src/api/`)

- **`client.ts`** — the only module that calls `fetch`. Exports `get`,
  `postJson`, `postAdmin`, `streamNdjson`, `ApiError`, `credentials`, and
  `assertNoProjectId`.
- **`types.ts`** — wire types, transcribed by hand.
- **`hooks.ts`** — `useQuery`/`useMutation` generics plus one named hook per
  route. No react-query/SWR dependency. `useExportRows` streams
  `GET /export/project`, caps at `maxRows` (default 5000) and exposes
  `truncated` — a view built on it **must** surface that flag rather than
  present a partial vault as complete.

Ad hoc reads (the three report routes) call `useQuery<T>` + `get<T>` directly
with a locally-declared response interface transcribed from
`api/models_reports.py`. This is deliberate but not ideal: see weakness 2.

### Auth

No login route exists. **Settings** lets an operator paste the bearer token or
`tb_sk_...` API key their `POST /admin/agents/register` minted, plus the
bootstrap admin key. `client.ts`'s `credentials` is the only reader/writer of
`localStorage["tb:auth:principal"]` and `localStorage["tb:auth:admin_key"]`.
`Layout.tsx`'s top bar shows whether a credential is set (polls on window
focus, since Settings writes via a plain module rather than a shared store).

---

## Dependency licence policy (`scripts/license_check.mjs`)

Mirrors `scripts/license_check.py`'s discipline: walks the **resolved** tree in
`node_modules` (not the declared one), an unknown licence **fails**, a
conditional licence passes only when that specific package is named with a
written rationale, and `--self-test` proves the gate rejects what it claims to.

The policy lives inside the `.mjs` rather than beside `license_policy.toml`
because Node has no standard-library TOML parser, and a licence gate that needs
a dependency in order to check dependencies has a hole in it.

Current verdict: **343 packages, 341 allowed, 2 conditional (named), 0 denied,
0 unknown.** The two conditionals are both build-time-only *data* packages,
neither of which reaches `dist/`:

| Package | Licence | Why it is accepted |
|---|---|---|
| `caniuse-lite` | CC-BY-4.0 | Browser-support data consulted by autoprefixer/browserslist at build time. Never copied into `dist/`, so the attribution obligation does not attach to the shipped artefact. |
| `language-subtag-registry` | CC0-1.0 | IANA subtag data used by `eslint-plugin-jsx-a11y`. Lint-time only. CC0 is a public-domain dedication carrying no obligation regardless. |

`type-fest`'s `(MIT OR CC0-1.0)` resolves through its MIT branch and needs no
entry. Note that a denied atom loses even when OR-ed with a permissive one
(`MIT OR SSPL-1.0` → denied): we cannot tell which branch a downstream
consumer will rely on.

---

## Known weaknesses

Stated here rather than discovered later.

1. **No test harness at all.** No Vitest, no RTL, no render test. The three
   most recent view rebuilds shipped with runtime contract mismatches against
   the backend — a view expecting `report.trend` where the server sends
   `report.window` — and `tsc`, `eslint` and `vite build` all passed clean
   through every one of them, because a locally-declared interface that
   disagrees with the server is not a type error. **A single render test per
   view against a recorded response body would have caught all three.** This
   is the highest-value missing thing in this directory.
2. **Three independently-drifting local response types.** `LiftReportOut`,
   `StalenessReportOut` and `ConsolidationDiffsOut` are declared inside their
   own view files rather than in `types.ts`, so nothing forces them to stay
   consistent with each other or with `api/models_reports.py`. They should be
   promoted into `types.ts` with named hooks in `hooks.ts`.
3. **`Consolidation` renders an empty page on every build shipped today.**
   `workers/consolidator.py`'s per-sweep `DeltaRecord` has no store, and
   `derived_state` — the only table shaped to fit — has no writer either. The
   route is real and tested; nothing populates it. The wire carries
   `sweep_deltas_available: false` so "this project ran no sweeps" and
   "nothing in this system records sweeps" do not render identically.
4. **`Lift & Q`'s methodology constants are process defaults, not this
   project's resolved config.** `methodology.source == "process_default"` and
   the page warns about it, but a project that overrode
   `killswitch.min_cell_n` sees this report judge cells against 200 while the
   kill switch judges them against the override.
5. **`Kill Switch` is read-only.** No write route exists, so the confirmed,
   blast-radius-shown governing action the view is designed around cannot be
   performed from the dashboard.
6. **Eight views call `useExportRows`**, and for five of them (Injections,
   Abstention, Memory Vault, Vault Trend, Forensics) the whole-project export
   is the *only* data source — an entire NDJSON dump streamed and filtered in
   the browser to render one table, capped at 5000 rows. Purpose-built routes
   already exist for two of the five (see the unused-routes table above).
7. **No `project_id` is ever displayed as a matter of course.**
   `GET /admin/whoami` exists and **Registry**/**Settings** use it, but the
   shell does not show which project the current credential resolves to, so
   a screenshot from one project is indistinguishable from another's.
