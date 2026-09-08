# Tracebed dashboard

React 18 + Vite + TypeScript (strict) + Tailwind, served on `:8111`.

> **Same-origin BFF session surface.** The browser sends only same-origin requests with
> `credentials: "same-origin"`. Browser JavaScript never handles a bearer token, API key, or
> session identifier. The browser does hold and automatically sends the opaque HttpOnly cookie;
> JavaScript cannot read it. `GET /auth/session` exposes session state and an in-memory
> synchronizer token; `GET /auth/login` starts navigation; `POST /auth/logout` requires
> `X-CSRF-Token`. The server and edge remain the authorization boundary.
>
> **No validated erasure workflow.** This UI cannot establish deletion or right-to-erasure
> across data stores, derived records, exports, logs, or backups. Do not make erasure,
> retention, export-completeness, or compliance promises from its screens; see the blocked
> capability contract entries for those gaps.

```
npm ci           # not `install` — the licence gate judges the locked tree
npm run dev      # :8111, proxies only approved BFF routes to edge :8120
npm run build    # tsc --noEmit && vite build -> dist/
npm run lint     # eslint . --max-warnings 0
npm test          # Vitest + React Testing Library, jsdom

node scripts/license_check.mjs --self-test   # prove the licence gate bites
node scripts/license_check.mjs               # gate the resolved npm tree
```

Run these local checks in the order shown when changing the dashboard. They provide build and
source-quality evidence only; they do not validate a deployment or its authorization boundary.

The dashboard Dockerfile builds `dist/` and serves it via `nginx.conf`. Any reverse proxy,
identity integration, and API routing policy are deployment-owned.

Focused Vitest/RTL coverage exercises session transport, CSRF mutation headers,
same-origin path rejection, no browser-held auth state, status-specific error rendering,
cursor-page loading/empty states, stale-page clearing, escaped content, and semantic tables.

---

## Local development views and their source paths

This is a source inventory of paths that the local development UI can render. It is not proof
that a route is deployed, authorized at an edge, complete, or appropriate for an operator. No
view should be interpreted as a compliance record or a production monitoring console.

- **Aggregate route** — a purpose-built server-side endpoint. Paginated or
  windowed, computed by the server, no client-side derivation.
- **Export-derived** — the view streams `GET /export/project` (the whole
  project as NDJSON: five tables, no filters, no pagination) and derives its
  table in the browser. `useExportRows` accepts only an edge response marked
  `X-Tracebed-Export-Completeness: complete` with a valid maximum-byte bound;
  a bounded, over-limit, or aborted stream renders an error with no partial
  rows. It caps a complete stream at `maxRows` (default 5000), cancels the
  reader, and exposes `truncated: boolean`; **every** view below that uses it
  renders that flag. These views are partial by construction, and slower and
  heavier than they need to be.
- **Empty by construction** — the route is real, tested and scoped, but no
  writer exists anywhere in the codebase to put rows behind it. It returns an
  honest empty page on every build shipped today.

| View | Route | Data source | What an operator does here |
|---|---|---|---|
| **Overview** | `/export/project`, `/admin/killswitch_state`, `/admin/review_queue`, `/admin/spend` | mixed (aggregate + export-derived) | Local source view for kill-switch state, review items, spend, and vault counts. It is not an operational attestation. |
| **Injections** | `/admin/injections`, `/admin/memory/{id}` | paginated server feed | Browse page by page, then inspect the current memory state. Trace-index joins are unavailable and stated as such. |
| **Abstention** | `/export/project` | export-derived | Local source view of recorded abstention fields. Its totals may be truncated and are not a deployment metric. |
| **Health** | `/healthz`, `/export/project` | mixed | Liveness plus queue/worker freshness. Where you look when a number elsewhere stops moving. |
| **Memory Vault** | `/admin/memory` | cursor-paginated server list | Browse a 100-row server page at a time. The opaque `next_cursor` controls Older/Newer traversal; page counts are never vault totals. |
| **Memory Detail** | `/admin/memory/{id}`, `/export/project` | mixed | The only place a memory's provenance is readable. This is what makes a row governable rather than merely visible. |
| **Vault Trend** | `/export/project` | export-derived | Watch vault composition move over time — is the candidate pool growing faster than validation can clear it. |
| **Staleness** | `/admin/staleness/report` | aggregate route | Audit invalidation. Which events fired, what they plausibly matched, which memories are overdue for revalidation and were never staled. |
| **Consolidation** | `/admin/consolidation/diffs` | aggregate route, **empty by construction** | Would show what a consolidation sweep added, amended and removed. Nothing writes sweeps today (see gap 1), so it renders an empty page and says why on the page. |
| **Review Queue** | `/admin/review_queue` | aggregate route | Work the queue: what has been escalated for human judgement, and what is still open. |
| **Forensics** | `/export/project` | export-derived | Blast-radius scan: given a subject or memory id, what else is implicated. |
| **Lift & Q** | `/admin/lift/report` | aggregate route | Local source view of stratified lift and Q fields. It is not an independently validated performance or governance report. |
| **Kill Switch** | `/admin/killswitch_state` | aggregate route, **read-only** | See what the kill switch actually decided and on what evidence. There is no write route — nothing here can arm or disarm it. |
| **Spend** | `/admin/spend` | aggregate route | Budget consumption by day. |
| **Registry** | `/admin/whoami` | aggregate route | See the session-derived scope; owner onboarding is outside the browser surface. |
| **Settings** | `/auth/session`, `/auth/login`, `/auth/logout`, `/admin/whoami`, `/admin/config` | BFF session + aggregate routes | Inspect session state, sign in/out, and read this scope's configuration. |
| **Validation Runs** | `/auth/demo-manifest`, `/export/project` | local-demo manifest + authoritative trace index | Loopback demo only; joins imported evidence labels to exported terminal run rows. |

### Purpose-built list routes

| Route | Should replace | Status |
|---|---|---|
| `GET /admin/memory` (`MemoryListOut`, cursor-paginated) | **Memory Vault** | consumed by `useMemoryList`; opaque `next_cursor` is retained only for page traversal |
| `GET /admin/injections` (paginated, project-scoped) | **Injections** | consumed by `useInjections`; explicit offset controls page traversal |
| `GET /admin/invalidations` (`InvalidationListOut`) | nothing directly — **Staleness** uses the richer report route instead | unused; `useInvalidations` has zero callers |

The remaining export-derived views retain their explicit row-cap/truncation disclosure. This does
not establish export authorization or completeness.

---

## The API surface

`src/tracebed/api/routes_v1.py`, `admin.py` and `reports.py` are source locations for the
routes represented by this UI. This list is not a deployed API inventory or authorization proof:

| Route | Auth | What it does |
|---|---|---|
| `GET /auth/session` | BFF cookie | returns only `authenticated` and the synchronizer token (`null` when anonymous) |
| `GET /auth/login` | none | BFF/identity navigation entry; not an XHR credential exchange |
| `POST /auth/logout` | BFF cookie + CSRF | clears the BFF session; browser sends `X-CSRF-Token` |
| `POST /v1/retrieve` | principal | sync, budgeted retrieval |
| `POST /v1/trace`, `/v1/trace/batch` | principal | 202, enqueue only |
| `POST /v1/feedback` | principal | 202, enqueue only |
| `POST /v1/propose_memory` | principal | 202, enqueue only |
| `POST /v1/invalidation` | principal | 202, synchronous single-row insert |
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

The local demo key has exactly `data`, `admin`, and `export` grants. It cannot make feedback
writes without a source-bound feedback grant. Erasure is deliberately not presented as a completed
browser workflow; dashboard screens do not prove deletion, retention, or export compliance.

The client source attempts to reject caller-provided `project_id` values in development builds.
That client-side behavior is not an authorization control: RBAC, project scoping, and privileged
route behavior require server-side and deployment-specific validation.

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
| Risk | `text-risk-low/med/high` | Reserved for a future safety/lift view. |
| Chart | `stroke-chart-line`, `fill-chart-band`, `stroke-chart-grid`, `fill-chart-axis` | `Chart.tsx`'s line, confidence band, gridlines, axis labels |

Dark mode: `tailwind.config.ts` uses `darkMode: "class"`. `lib/theme.ts`
toggles a `.dark` class on `<html>`, persisted to `localStorage["tb:theme"]`;
the same-origin `theme-bootstrap.ts` module applies the persisted (or OS)
preference before the React entrypoint. No inline script or CSP
`unsafe-inline` exception is needed.

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
  `postJson`, `streamNdjson`, `ApiError`, BFF session functions, and the
  module-memory synchronizer-token setter.
- **`types.ts`** — wire types, transcribed by hand.
- **`hooks.ts`** — `useQuery`/`useMutation` generics plus one named hook per
  route. No react-query/SWR dependency. `useExportRows` streams
  `GET /export/project`, caps at `maxRows` (default 5000) and exposes
  `truncated` — a view built on it **must** surface that flag rather than
  present a partial vault as complete.

The report response types and their named hooks live here too, rather than being
redeclared in view files. The BFF/session layer is UX only; API and edge checks
remain authoritative.

---

## Dependency licence policy (`scripts/license_check.mjs`)

Mirrors `scripts/license_check.py`'s discipline: walks the **resolved** tree in
`node_modules` (not the declared one), an unknown licence **fails**, a
conditional licence passes only when that specific package is named with a
written rationale, and `--self-test` proves the gate rejects what it claims to.

The policy lives inside the `.mjs` rather than beside `license_policy.toml`
because Node has no standard-library TOML parser, and a licence gate that needs
a dependency in order to check dependencies has a hole in it.

The source policy contains two named conditional build-time data packages. This documentation
does not make a current dependency inventory, SBOM, provenance, or release-assurance claim:

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

1. **`Consolidation` has an unpopulated source path.**
   `workers/consolidator.py`'s per-sweep `DeltaRecord` has no store, and
   `derived_state` — the only table shaped to fit — has no writer either. The
   route is real and tested; nothing populates it. The wire carries
   `sweep_deltas_available: false` so "this project ran no sweeps" and
   "nothing in this system records sweeps" do not render identically.
2. **`Lift & Q`'s methodology constants are process defaults, not this
   project's resolved config.** `methodology.source == "process_default"` and
   the page warns about it, but a project that overrode
   `killswitch.min_cell_n` sees this report judge cells against 200 while the
   kill switch judges them against the override.
3. **`Kill Switch` is read-only.** No write route exists, so the confirmed,
   blast-radius-shown governing action the view is designed around cannot be
   performed from the dashboard.
4. **Export-derived views remain.** Abstention, Vault Trend, Forensics,
   Overview, Health and Memory Detail still use bounded project exports where
   no dedicated join/report route exists. Each retained view discloses the
   cap and truncation; Injections and Memory Vault no longer use that path.
5. **Frontend authorization is not an authorization control.** The shell
   reflects `GET /admin/whoami` for every view and clears view state on a
   session transition, but API/edge enforcement and deployment validation
   remain required.
