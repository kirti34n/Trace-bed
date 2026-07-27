import { useMemo, useState } from "react";
import { get } from "../api/client";
import { useQuery } from "../api/hooks";
import { Chart, type ChartMarkerShape, type ChartSeries } from "../components/Chart";
import { EmptyState } from "../components/EmptyState";
import { ErrorState } from "../components/ErrorState";
import { Table, type ColumnDef } from "../components/Table";
import {
  formatDateTime,
  formatEstimateWithCI,
  formatFloat,
  formatInt,
  truncateId,
} from "../lib/format";
import type { MemType } from "../api/types";

// THE MOST DANGEROUS VIEW IN THE PRODUCT — this is the one an operator quotes
// in a meeting. Every number here that claims memory "helped" or "hurt" is a
// STRATIFIED lift: runs where something was actually injected (arm=memory_on,
// a memory placed) against shadow-retrieved holdout runs (workers/lift.py's
// D-027 correction) — never the naive "every memory_on run vs every holdout
// run" comparison, which averages two clouds of noise (>=50% abstention by
// design, PLAN.md §6) and calls the difference "lift". That label is repeated
// on the table and the chart, not just here, because a screenshot of either
// travels without this paragraph.
//
// NOTHING ON THIS PAGE IS EVER HAND-AUTHORED. An earlier build of this view
// fell back to an illustrative fixture when the route 404'd or the network
// failed, behind a banner. That route now exists (api/reports.py), so the
// justification is gone — and the failure mode never was acceptable on this
// page in particular: a fixture banner scrolls off the top of a long report,
// and a screenshot of the lift table below it carries invented numbers with
// nothing to mark them as invented. Every error state here renders ErrorState.
//
// The interfaces below are transcribed from src/tracebed/api/models_reports.py
// field for field — LiftReportOut / LiftWindowOut / LiftMethodologyOut /
// LiftCellOut / QTrajectoryOut / QTrajectoryPointOut. They are NOT a guess at
// a shape; when the two disagree, that file is right and this one is a bug.

// --------------------------------------------------------------------- //
// Wire contract for GET /admin/lift/report (api/models_reports.py).
// --------------------------------------------------------------------- //

interface LiftWindowOut {
  since: string;
  days: number;
  observations_considered: number;
  /** True when the server's observation join came back at its cap, so every
   * N below is a LOWER BOUND on the window's real N, not the window's N. */
  observations_truncated: boolean;
  observations_cap: number;
}

interface LiftMethodologyOut {
  min_cell_n: number;
  killswitch_window_days: number;
  correction: string;
  confidence: number;
  bh_alpha: number;
  bh_hypotheses: number;
  /** `"process_default"` means these are the server's compiled-in defaults,
   * NOT this project's resolved config — see the server model's own note on
   * why it cannot resolve overrides for this report yet. Rendered as that
   * distinction, never as "this deployment's configured values". */
  source: string;
}

interface LiftCellOut {
  agent_type_id: string;
  mem_type: MemType;
  n_treatment: number;
  n_control: number;
  min_cell_n: number;
  /** True whenever either arm is below `min_cell_n`, INCLUDING the degenerate
   * case where no interval was computable at all. This view refuses to render
   * a figure for such a cell; the server still sends what it has so that a
   * server-side omission and a genuinely-zero estimate stay distinguishable. */
  insufficient: boolean;
  point_estimate: number | null;
  lower_bound: number | null;
  upper_bound: number | null;
  confidence: number | null;
  p_value: number | null;
  /** `null` for every insufficient cell — the cell still counted as a
   * hypothesis in the correction (methodology.bh_hypotheses), it just has no
   * adjusted value to show beside an estimate that is being refused. */
  bh_adjusted_p: number | null;
}

interface QTrajectoryPointOut {
  agent_type_id: string;
  mem_type: MemType;
  memory_id: string;
  q_value: number;
  confidence: number;
  scored_use_count: number;
  observed_at: string;
  /** INFERRED by the server as the nearest scoring_epoch.started_at at or
   * before `observed_at` — memory_item has no epoch column to read. `null`
   * when no epoch precedes the point at all. Never dropped for being null. */
  scoring_epoch_id: number | null;
}

interface QTrajectoryOut {
  items: QTrajectoryPointOut[];
  limit: number;
  offset: number;
  returned: number;
}

interface LiftReportOut {
  window: LiftWindowOut;
  methodology: LiftMethodologyOut;
  cells: LiftCellOut[];
  q_trajectory: QTrajectoryOut;
}

// --------------------------------------------------------------------- //
// Section: methodology + window provenance
// --------------------------------------------------------------------- //

function MethodologySection({
  window,
  methodology,
}: {
  window: LiftWindowOut;
  methodology: LiftMethodologyOut;
}) {
  const isProcessDefault = methodology.source === "process_default";
  return (
    <section className="rounded-lg border border-border bg-surface p-4">
      <h2 className="text-sm font-semibold text-text">Methodology</h2>
      <dl className="mt-2 grid grid-cols-2 gap-x-6 gap-y-1.5 text-xs sm:grid-cols-4">
        <div>
          <dt className="text-text-muted">Report window</dt>
          <dd className="font-mono text-text">{formatInt(window.days)} days</dd>
        </div>
        <div>
          <dt className="text-text-muted">Min cell N (per arm)</dt>
          <dd className="font-mono text-text">{formatInt(methodology.min_cell_n)}</dd>
        </div>
        <div>
          <dt className="text-text-muted">Confidence level</dt>
          <dd className="font-mono text-text">
            {formatFloat(methodology.confidence * 100, 0)}%
          </dd>
        </div>
        <div>
          <dt className="text-text-muted">Correction</dt>
          <dd className="font-mono text-text">
            {methodology.correction} @ α={formatFloat(methodology.bh_alpha, 2)}
          </dd>
        </div>
      </dl>
      <p className="mt-2 text-xs text-text-muted">
        {formatInt(methodology.bh_hypotheses)} cell(s) entered the correction as hypotheses.
        The kill switch&rsquo;s own sustained window is{" "}
        {formatInt(methodology.killswitch_window_days)} days &mdash; that trigger is evaluated
        by <code className="font-mono">workers/killswitch.py</code>, not here; this report is
        one pooled estimate per cell over the {formatInt(window.days)}-day window above.
      </p>
      {isProcessDefault && (
        <p className="mt-2 text-xs text-text-faint">
          These constants are the server&rsquo;s compiled-in process defaults, not this
          project&rsquo;s resolved configuration. A project that has overridden{" "}
          <code className="font-mono">killswitch.min_cell_n</code> in{" "}
          <code className="font-mono">project_config</code> will see its cells judged against
          the default here while the kill switch judges them against the override. Check the
          Settings view for this project&rsquo;s stored overrides before quoting a threshold.
        </p>
      )}
      {window.observations_truncated && (
        <p className="mt-3 rounded-md border border-status-quarantined-border bg-status-quarantined-bg px-3 py-2 text-xs text-status-quarantined-fg">
          <strong className="font-semibold">Partial window.</strong> The server&rsquo;s
          observation join came back at its cap of{" "}
          {formatInt(window.observations_cap)} rows, so every N below is a{" "}
          <em>lower bound</em> on this cell&rsquo;s real sample size, not its sample size. Read
          each interval as computed from an unknown fraction of the window &mdash; narrow the{" "}
          <code className="font-mono">days</code> parameter until this notice disappears before
          quoting any figure on this page.
        </p>
      )}
      {!window.observations_truncated && (
        <p className="mt-2 text-xs text-text-faint">
          Computed from {formatInt(window.observations_considered)} (run, memory-type)
          observation(s) since {formatDateTime(window.since)} &mdash; the whole window, not a
          truncated slice of it.
        </p>
      )}
    </section>
  );
}

// --------------------------------------------------------------------- //
// Section: stratified lift table
// --------------------------------------------------------------------- //

function cellKey(c: { agent_type_id: string; mem_type: MemType }): string {
  return `${c.agent_type_id}::${c.mem_type}`;
}

/** A cell is renderable as a figure only when it cleared min_cell_n in BOTH
 * arms AND the server actually computed all three numbers. Anything else is a
 * refusal, never a bare bound: an estimate of -0.01 and an estimate of -0.01
 * with a [-0.30, +0.28] interval around it are not the same evidence, and
 * neither is a figure whose denominator is 40 runs. */
function renderableEstimate(
  row: LiftCellOut
): { point: number; low: number; high: number; n: number; confidence: number } | null {
  if (row.insufficient) return null;
  if (row.point_estimate === null || row.lower_bound === null || row.upper_bound === null) {
    return null;
  }
  return {
    point: row.point_estimate,
    low: row.lower_bound,
    high: row.upper_bound,
    // The conservative arm: a cell is only as well-measured as its smaller
    // side, and quoting the larger one flatters the figure.
    n: Math.min(row.n_treatment, row.n_control),
    confidence: row.confidence ?? 0.95,
  };
}

function LiftCellsTable({ cells }: { cells: LiftCellOut[] }) {
  const columns: ColumnDef<LiftCellOut>[] = [
    {
      key: "agent_type_id",
      header: "Agent type",
      width: "22ch",
      render: (row) => (
        <span className="font-mono text-xs text-text" title={row.agent_type_id}>
          {truncateId(row.agent_type_id)}
        </span>
      ),
      sortValue: (row) => row.agent_type_id,
    },
    {
      key: "mem_type",
      header: "Memory type",
      width: "13ch",
      render: (row) => row.mem_type,
      sortValue: (row) => row.mem_type,
    },
    {
      key: "n",
      header: "N (treatment / holdout)",
      width: "20ch",
      numeric: true,
      render: (row) => `${formatInt(row.n_treatment)} / ${formatInt(row.n_control)}`,
      sortValue: (row) => Math.min(row.n_treatment, row.n_control),
    },
    {
      key: "estimate",
      header: "Stratified lift (task outcome)",
      render: (row) => {
        const estimate = renderableEstimate(row);
        if (estimate === null) {
          return (
            <span className="text-status-quarantined-fg">
              Insufficient data &mdash; n={formatInt(row.n_treatment)}/
              {formatInt(row.n_control)}, needs &ge;{formatInt(row.min_cell_n)} in both arms
            </span>
          );
        }
        return (
          <span className="font-mono text-xs text-text">
            {formatEstimateWithCI(estimate.point, estimate.low, estimate.high, estimate.n, {
              confidence: estimate.confidence,
            })}
          </span>
        );
      },
      // Nulls sort last in both directions (Table's own contract), which is
      // what a refused cell should do — it has no magnitude to rank by.
      sortValue: (row) => renderableEstimate(row)?.low ?? null,
    },
    {
      key: "bh",
      header: "Adjusted significance",
      width: "24ch",
      // Word first, never colour alone: an operator with any colour vision
      // reads "Significant" / "Not significant" identically.
      render: (row) => {
        if (row.bh_adjusted_p === null) {
          return <span className="text-text-faint">Not evaluated (insufficient N)</span>;
        }
        return (
          <span className="text-text">
            {row.bh_adjusted_p <= 0.05 ? "Significant" : "Not significant"} (adjusted p=
            {formatFloat(row.bh_adjusted_p, 3)})
          </span>
        );
      },
      sortValue: (row) => row.bh_adjusted_p,
    },
  ];

  return (
    <Table
      caption="Stratified lift per (agent type, memory type) cell: runs where something was actually injected versus shadow-retrieved holdout runs, with confidence interval, N, and Benjamini-Hochberg-adjusted significance"
      columns={columns}
      rows={cells}
      getRowId={(row) => cellKey(row)}
      initialSort={{ key: "n", direction: "desc" }}
    />
  );
}

/** A null result is a RESULT. PLAN.md §7 Phase 3 treats "no measurable lift"
 * as a documented, expected outcome of this experiment, so it is rendered in
 * neutral surface tones — never the quarantined/danger palette a reader parses
 * as "something is broken". Styling an expected negative as a failure is how a
 * dashboard talks an operator into disabling a feature that is merely unproven. */
function NullResultNote({ cells }: { cells: LiftCellOut[] }) {
  const measurable = cells.filter((c) => !c.insufficient);
  if (measurable.length === 0) return null;
  const anySignificant = measurable.some(
    (c) => c.bh_adjusted_p !== null && c.bh_adjusted_p <= 0.05
  );
  if (anySignificant) return null;
  return (
    <p className="mt-3 rounded-md border border-border bg-surface px-3 py-2 text-xs text-text-muted">
      No cell in this window shows a statistically significant effect after the
      Benjamini-Hochberg correction, in either direction. That is a documented, expected
      outcome (PLAN.md §7 Phase 3), not a regression and not a failure of the memory system
      &mdash; it means this window does not yet carry enough evidence to say memory helped or
      hurt for any cell. Cells marked insufficient are not counted here at all.
    </p>
  );
}

// --------------------------------------------------------------------- //
// Section: Q values.
//
// NOT a trajectory, and the whole section is built around saying so. The
// server returns ONE point per scored memory — memory_item stores a single
// current q_value with no history table anywhere in the schema — so
// consecutive points belong to DIFFERENT memories. A line through them would
// render "Q is trending up" out of data that contains no trend, which is the
// same class of lie as a lift figure with no interval. Points are drawn as a
// scatter (mode: "points"), split into one series per scoring epoch, and the
// epoch is a server-side inference rather than a stored fact — labelled as
// such at the point of use.
// --------------------------------------------------------------------- //

const KNOWN_EPOCH_MARKERS: ChartMarkerShape[] = ["circle", "square", "diamond"];
const UNKNOWN_EPOCH_MARKER: ChartMarkerShape = "diamond";

function epochSeries(points: QTrajectoryPointOut[]): ChartSeries[] {
  const epochs: (number | null)[] = [];
  for (const p of points) {
    if (!epochs.some((e) => e === p.scoring_epoch_id)) epochs.push(p.scoring_epoch_id);
  }
  const known = epochs.filter((e): e is number => e !== null).sort((a, b) => a - b);
  return epochs
    .slice()
    .sort((a, b) => {
      if (a === null) return 1;
      if (b === null) return -1;
      return a - b;
    })
    .map((epoch) => {
      const isUnknown = epoch === null;
      const idx = isUnknown ? -1 : known.indexOf(epoch);
      return {
        label: isUnknown
          ? "No epoch precedes these points"
          : `Scoring epoch ${formatInt(epoch)} (inferred)`,
        points: points
          .filter((p) => p.scoring_epoch_id === epoch)
          .map((p) => ({ x: Date.parse(p.observed_at), y: p.q_value })),
        // Marker shape, not colour, is what separates the series — a legend
        // whose only channel is hue fails for a reader with a colour-vision
        // deficiency and in a greyscale print of the same screenshot.
        marker: isUnknown
          ? UNKNOWN_EPOCH_MARKER
          // `?? "circle"` rather than a cast: `noUncheckedIndexedAccess` widens
          // every index access to `| undefined`, and a cast there would keep
          // compiling if the array were ever emptied or re-typed underneath it.
          : (KNOWN_EPOCH_MARKERS[idx % KNOWN_EPOCH_MARKERS.length] ?? "circle"),
        mode: "points" as const,
      };
    });
}

function QScatter({ points }: { points: QTrajectoryPointOut[] }) {
  const series = useMemo(() => epochSeries(points), [points]);
  const hasUnknownEpoch = points.some((p) => p.scoring_epoch_id === null);
  return (
    <div className="rounded-lg border border-border bg-surface p-4">
      <Chart
        ariaLabel="Current Q value of each scored memory against when it was last scored, drawn as unconnected points grouped by scoring epoch. No line is drawn: consecutive points belong to different memories, not to one memory over time."
        series={series}
        yDomain={[0, 1]}
        xTickFormat={(x) => new Date(x).toISOString().slice(0, 10)}
        yTickFormat={(y) => formatFloat(y, 2)}
      />
      <p className="mt-2 text-xs text-text-muted">
        Points, not a line, deliberately. Each mark is one memory&rsquo;s{" "}
        <em>current</em> Q against when it was last scored &mdash; consecutive marks are
        different memories, so joining them would draw a trend this data does not contain.
      </p>
      {hasUnknownEpoch && (
        <p className="mt-1 text-xs text-text-muted">
          Some points fall before any recorded scoring epoch and are grouped separately rather
          than folded into the nearest one. They are drawn, never dropped.
        </p>
      )}
    </div>
  );
}

function QPointsTable({ points }: { points: QTrajectoryPointOut[] }) {
  const columns: ColumnDef<QTrajectoryPointOut>[] = [
    {
      key: "memory_id",
      header: "Memory",
      width: "16ch",
      render: (row) => (
        <span className="font-mono text-xs text-text" title={row.memory_id}>
          {truncateId(row.memory_id)}
        </span>
      ),
      sortValue: (row) => row.memory_id,
    },
    {
      key: "agent_type_id",
      header: "Agent type",
      width: "16ch",
      render: (row) => (
        <span className="font-mono text-xs text-text-muted" title={row.agent_type_id}>
          {truncateId(row.agent_type_id)}
        </span>
      ),
      sortValue: (row) => row.agent_type_id,
    },
    {
      key: "mem_type",
      header: "Type",
      width: "12ch",
      render: (row) => row.mem_type,
      sortValue: (row) => row.mem_type,
    },
    {
      key: "q_value",
      header: "Q",
      width: "9ch",
      numeric: true,
      render: (row) => formatFloat(row.q_value, 3),
      sortValue: (row) => row.q_value,
    },
    {
      key: "confidence",
      header: "Confidence",
      width: "12ch",
      numeric: true,
      render: (row) => formatFloat(row.confidence, 3),
      sortValue: (row) => row.confidence,
    },
    {
      key: "scored_use_count",
      header: "Scored uses (N)",
      width: "15ch",
      numeric: true,
      // A Q with no N behind it is not a measurement — this column is why the
      // scatter above is legible at all, and it is never omitted.
      render: (row) => formatInt(row.scored_use_count),
      sortValue: (row) => row.scored_use_count,
    },
    {
      key: "observed_at",
      header: "Last scored (UTC)",
      width: "22ch",
      render: (row) => <span title={row.observed_at}>{formatDateTime(row.observed_at)}</span>,
      sortValue: (row) => row.observed_at,
    },
    {
      key: "epoch",
      header: "Scoring epoch",
      width: "18ch",
      render: (row) =>
        row.scoring_epoch_id === null ? (
          <span className="text-text-faint">none precedes this point</span>
        ) : (
          <span className="text-text">
            {formatInt(row.scoring_epoch_id)}{" "}
            <span className="text-text-faint">(inferred)</span>
          </span>
        ),
      sortValue: (row) => row.scoring_epoch_id,
    },
  ];

  return (
    <Table
      caption="Every scored memory's current Q value, its confidence, how many scored uses it rests on, when it was last scored, and the scoring epoch the server inferred for that timestamp"
      columns={columns}
      rows={points}
      getRowId={(row) => row.memory_id}
      initialSort={{ key: "observed_at", direction: "desc" }}
      maxHeight="60vh"
    />
  );
}

function QSection({ trajectory }: { trajectory: QTrajectoryOut }) {
  const [view, setView] = useState<"table" | "scatter">("table");
  const points = trajectory.items;
  const pageIsFull = trajectory.returned >= trajectory.limit;

  return (
    <div className="space-y-3">
      <div className="rounded-md border border-border bg-surface px-3 py-2 text-xs text-text-muted">
        <strong className="font-semibold text-text">This is a snapshot, not a history.</strong>{" "}
        <code className="font-mono">memory_item</code> stores one current{" "}
        <code className="font-mono">q_value</code> per memory and no table anywhere in this
        schema records a Q update, so no view can plot how any individual Q got where it is.
        What is below is one point per scored memory. The scoring epoch on each point is{" "}
        <em>inferred</em> by the server as the nearest epoch starting at or before the
        memory&rsquo;s <code className="font-mono">last_scored_at</code> &mdash; it is not read
        off a stored column, because none exists. Two points in different epochs were scored by
        different judge models and their Q values are not comparable on one ruler.
      </div>

      {points.length === 0 ? (
        <EmptyState
          title="No memory in this project has been scored yet"
          description="Every memory_item still carries its seeded q_value with no last_scored_at. A young project, or one whose scoring workers have not run, looks exactly like this — it is not an error."
        />
      ) : (
        <>
          <div className="flex flex-wrap items-center gap-2">
            <label htmlFor="q-view-select" className="text-xs font-medium text-text-muted">
              View
            </label>
            <select
              id="q-view-select"
              value={view}
              onChange={(e) => setView(e.target.value === "scatter" ? "scatter" : "table")}
              className="rounded-md border border-border bg-surface px-2 py-1 text-xs text-text"
            >
              <option value="table">Table (every memory, with its N)</option>
              <option value="scatter">Scatter by scoring epoch</option>
            </select>
            <span className="text-xs text-text-faint">
              {formatInt(trajectory.returned)} memory(ies) shown
              {pageIsFull &&
                ` — this is a full page of ${formatInt(trajectory.limit)}, so more exist beyond it`}
            </span>
          </div>
          {view === "scatter" ? (
            <QScatter points={points} />
          ) : (
            <QPointsTable points={points} />
          )}
        </>
      )}
    </div>
  );
}

// --------------------------------------------------------------------- //
// Page
// --------------------------------------------------------------------- //

export default function LiftAndQ() {
  const query = useQuery<LiftReportOut>(
    (signal) => get<LiftReportOut>("/admin/lift/report", { signal }),
    "/admin/lift/report"
  );
  const report = query.data;

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-lg font-semibold text-text">Lift &amp; Q</h1>
        <p className="mt-1 max-w-3xl text-sm text-text-muted">
          Stratified lift &mdash; runs where something was actually injected versus
          shadow-retrieved holdout runs &mdash; and the current Q value of every scored memory.
          Every figure here carries its confidence interval and its N; a cell below the minimum
          reads &ldquo;insufficient data&rdquo;, never a bare number.
        </p>
      </div>

      {query.status === "error" ? (
        <ErrorState error={query.error} onRetry={query.reload} />
      ) : query.status === "loading" || query.status === "idle" ? (
        <div
          role="status"
          aria-label="Loading lift report"
          className="h-64 animate-pulse rounded-lg border border-border bg-surface"
        />
      ) : report === undefined ? (
        <EmptyState
          title="The server returned no report body"
          description="GET /admin/lift/report answered successfully with an empty body. Nothing can be inferred about this project's lift from that — treat it as a server-side fault, not as a measurement."
        />
      ) : (
        <>
          <MethodologySection window={report.window} methodology={report.methodology} />

          <section>
            <h2 className="mb-3 text-sm font-semibold text-text">Stratified lift by cell</h2>
            {report.cells.length === 0 ? (
              <EmptyState
                title="No (agent type, memory type) cell was observed in this window"
                description="No run in the window both exercised memory and recorded a scored outcome, in either arm. Expected for a young project, or for a window shorter than the feedback loop that produces outcome events — it is not the same as 'memory did not help'."
              />
            ) : (
              <>
                <LiftCellsTable cells={report.cells} />
                <NullResultNote cells={report.cells} />
              </>
            )}
          </section>

          <section>
            <h2 className="mb-3 text-sm font-semibold text-text">Q values by memory</h2>
            <QSection trajectory={report.q_trajectory} />
          </section>

          <section className="rounded-lg border border-border bg-surface p-4">
            <h2 className="text-sm font-semibold text-text">What is not on this page</h2>
            <ul className="mt-2 space-y-1.5 text-xs text-text-muted">
              <li>
                <strong className="font-medium text-text">A day-by-day lift trend.</strong> The
                kill switch&rsquo;s trigger needs one lift snapshot per cell per calendar day
                for {formatInt(report.methodology.killswitch_window_days)} consecutive days.
                Nothing in this system persists those daily snapshots &mdash;{" "}
                <code className="font-mono">workers/killswitch.py</code> computes them in
                memory and writes only the decisions it reaches. A trend line drawn here would
                have to be re-derived by this browser from raw events, making the dashboard a
                second author of a governing number whose method could drift from the
                worker&rsquo;s. See the Kill Switch view for what actually fired.
              </li>
              <li>
                <strong className="font-medium text-text">
                  Whether any cell is kill-switch eligible.
                </strong>{" "}
                The adjusted p-values above are corrected across the cells{" "}
                <em>in this response</em> over{" "}
                <em>this</em> window. The trigger is a different question over a different
                window, and only <code className="font-mono">workers/killswitch.py</code>{" "}
                answers it. Nothing on this page should be read as "this cell is about to be
                disabled".
              </li>
              <li>
                <strong className="font-medium text-text">A per-lane split.</strong> Lift is
                stratified by (agent type, memory type) &mdash; the two axes{" "}
                <code className="font-mono">workers/lift.py</code> actually uses. Lane is a
                property of a memory, not of a cell, and a cell can contain memories from both
                lanes; splitting the table by it here would attach a label to a number that was
                never computed under it.
              </li>
              <li>
                <strong className="font-medium text-text">
                  Policy-violation rate memory-on vs memory-off.
                </strong>{" "}
                PLAN.md §8 improvement 2 measures it alongside task quality, through{" "}
                <code className="font-mono">workers/safety_lift.py</code>, which has no read
                route.
              </li>
            </ul>
          </section>
        </>
      )}
    </div>
  );
}
