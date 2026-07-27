import { useEffect, useState, type ReactNode } from "react";
import { get, ApiError } from "../api/client";
import { useExportRows } from "../api/hooks";
import type { OutcomeCode, RetrievalEventExportRow } from "../api/types";
import { OUTCOME_CODES } from "../api/types";
import { EmptyState } from "../components/EmptyState";
import { ErrorState } from "../components/ErrorState";
import { Table, type ColumnDef } from "../components/Table";
import { formatDurationMs, formatInt, formatPercent } from "../lib/format";

// "Is the service well" — two real sources, and an explicit account of what
// this console cannot answer:
//
// 1. API reachability: real. `GET /healthz` (contract §9.3) is a genuine
//    liveness probe, called through api/client.ts's `get` like every other
//    route — no fetch() outside that module (task rule 3).
// 2. Retrieval/embed latency and the degradation-ladder outcome mix: real,
//    computed client-side from `GET /export/project`'s retrieval_event rows
//    (useExportRows, the same bounded/truncated NDJSON dump every other view
//    without a dedicated aggregate route has to use).
// Everything on this page is one of those two. The queue/dead-letter/xmin/
// heartbeat panels that used to sit below them were rendered from constants
// and have been removed; the closing section names each one and says where the
// real answer lives instead.
//
// The governing rule on this page is the task brief's first defect class:
// never present a computed number without its N. A "p99" over eleven rows is
// the maximum of eleven rows wearing a percentile's name, and an operator who
// reads it as an SLO measurement has been misled by this UI, not by the data.
// Hence the sample floors below, and hence the refusal to colour a latency
// tile against its budget when the sample it came from is a truncated,
// export-ordered (NOT trailing-window) slice.

const RETRIEVAL_BUDGET_MS = 300; // retrieval.total_budget_ms default (PLAN.md §6)
const EMBED_SUBBUDGET_MS = 200; // retrieval.embed_timeout_ms default (PLAN.md §6)
const EXPORT_ROW_CAP = 8000;

// Sample floors. A percentile's rank must land strictly inside the sample for
// the statistic to describe a distribution rather than its extreme: at n<100
// the 99th percentile IS the maximum observation, so we refuse to print one.
const MIN_N_P50 = 20;
const MIN_N_P99 = 100;

/** Nearest-rank percentile (the definition an SLO means): the smallest value
 * below which at least p of the sample falls. */
function percentile(sortedAsc: readonly number[], p: number): number | null {
  if (sortedAsc.length === 0) return null;
  const rank = Math.ceil(p * sortedAsc.length);
  const idx = Math.min(sortedAsc.length - 1, Math.max(0, rank - 1));
  return sortedAsc[idx] ?? null;
}

interface HealthzResult {
  status: string;
  latencyMs: number;
}

function useHealthz(): { status: "loading" | "success" | "error"; data: HealthzResult | undefined; error: ApiError | undefined; reload: () => void } {
  const [state, setState] = useState<{ status: "loading" | "success" | "error"; data: HealthzResult | undefined; error: ApiError | undefined }>({
    status: "loading",
    data: undefined,
    error: undefined,
  });
  const [generation, setGeneration] = useState(0);

  useEffect(() => {
    const controller = new AbortController();
    setState({ status: "loading", data: undefined, error: undefined });
    const start = performance.now();
    get<{ status: string }>("/healthz", { signal: controller.signal })
      .then((result) => {
        setState({ status: "success", data: { status: result.status, latencyMs: performance.now() - start }, error: undefined });
      })
      .catch((err: unknown) => {
        if (err instanceof ApiError && err.kind === "cancelled") return;
        setState({ status: "error", data: undefined, error: err instanceof ApiError ? err : new ApiError("network", "unknown error") });
      });
    return () => controller.abort();
  }, [generation]);

  return { ...state, reload: () => setGeneration((g) => g + 1) };
}

interface StatTileProps {
  label: string;
  value: string;
  sublabel?: string;
  tone?: "low" | "med" | "high";
  /** Always supplied alongside `tone`: colour is never the only carrier of a
   * verdict (task brief — operators with colour-vision deficiency read this). */
  toneLabel?: string;
}

function StatTile({ label, value, sublabel, tone, toneLabel }: StatTileProps) {
  const toneClass = tone === "high" ? "text-risk-high" : tone === "med" ? "text-risk-med" : tone === "low" ? "text-risk-low" : "text-text";
  return (
    <div className="rounded-lg border border-border bg-surface px-4 py-3">
      <p className="text-xs font-medium uppercase tracking-wide text-text-muted">{label}</p>
      <p className={`mt-1 text-2xl font-semibold tabular-nums ${toneClass}`}>{value}</p>
      {toneLabel !== undefined && <p className={`mt-0.5 text-xs font-semibold ${toneClass}`}>{toneLabel}</p>}
      {sublabel !== undefined && <p className="mt-0.5 text-xs text-text-faint">{sublabel}</p>}
    </div>
  );
}

function ApiLivenessSection() {
  const { status, data, error, reload } = useHealthz();
  return (
    <section>
      <h2 className="mb-2 text-sm font-semibold text-text">API reachability</h2>
      {status === "loading" && (
        <div className="rounded-lg border border-border bg-surface px-4 py-3 text-sm text-text-muted">
          Calling <code className="font-mono">GET /healthz</code>…
        </div>
      )}
      {status === "error" && <ErrorState error={error} onRetry={reload} title="Cannot reach GET /healthz" />}
      {status === "success" && data !== undefined && (
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          <StatTile
            label="Liveness"
            value={data.status === "ok" ? "OK" : data.status}
            tone={data.status === "ok" ? "low" : "high"}
            toneLabel={data.status === "ok" ? "Responding" : "Unexpected status body"}
          />
          <StatTile
            label="Round-trip latency"
            value={formatDurationMs(data.latencyMs)}
            sublabel="this browser → API :8110 /healthz — one sample, not a percentile, and not the retrieval budget below"
          />
        </div>
      )}
    </section>
  );
}

type OutcomeMeaning = "working" | "caution" | "degraded";

const MEANING_LABEL: Record<OutcomeMeaning, string> = {
  working: "System working",
  caution: "Deliberate caution",
  degraded: "Ladder engaged",
};

interface OutcomeMeta {
  label: string;
  /** Meaning is spelled out in words next to every count — an abstention is
   * the system working, and must never read like the ladder engaging just
   * because both happen to be non-green. */
  meaning: OutcomeMeaning;
  /** Badge classes (bg + fg + border). */
  classes: string;
  /** Solid fill for the share bar. A 15%-alpha fill would render the failure
   * segments nearly invisible against the surface — i.e. would understate
   * exactly the outcomes an operator is here to find. */
  barClass: string;
}

const OUTCOME_META: Record<OutcomeCode, OutcomeMeta> = {
  injected: {
    label: "Injected",
    meaning: "working",
    classes: "bg-status-validated-bg text-status-validated-fg border-status-validated-border",
    barClass: "bg-status-validated-border",
  },
  holdout: {
    label: "Holdout (sampled out, by design)",
    meaning: "working",
    classes: "bg-status-pinned-bg text-status-pinned-fg border-status-pinned-border",
    barClass: "bg-status-pinned-border",
  },
  abstained_threshold: {
    label: "Abstained (threshold)",
    meaning: "caution",
    classes: "bg-status-candidate-bg text-status-candidate-fg border-status-candidate-border",
    barClass: "bg-status-candidate-border",
  },
  abstained_rarity: {
    label: "Abstained (rarity)",
    meaning: "caution",
    classes: "bg-status-candidate-bg text-status-candidate-fg border-status-candidate-border",
    barClass: "bg-status-candidate-fg",
  },
  empty_result: {
    label: "Empty result",
    meaning: "caution",
    classes: "bg-status-archived-bg text-status-archived-fg border-status-archived-border",
    barClass: "bg-status-archived-border",
  },
  degraded_lexical: {
    label: "Degraded — lexical only",
    meaning: "degraded",
    classes: "bg-status-stale-bg text-status-stale-fg border-status-stale-border",
    barClass: "bg-status-stale-border",
  },
  timeout_prefix_only: {
    label: "Timeout — prefix only",
    meaning: "degraded",
    classes: "bg-status-quarantined-bg text-status-quarantined-fg border-status-quarantined-border",
    barClass: "bg-status-quarantined-border",
  },
  store_error: {
    label: "Store error",
    meaning: "degraded",
    classes: "bg-status-tombstoned-bg text-status-tombstoned-fg border-status-tombstoned-border",
    barClass: "bg-danger",
  },
};

interface DayBucket {
  day: string;
  n: number;
  p50: number | null;
  p99: number | null;
}

function SectionShell({ children }: { children: ReactNode }) {
  return (
    <section className="space-y-3">
      <h2 className="text-sm font-semibold text-text">Retrieval latency and degradation mix</h2>
      {children}
    </section>
  );
}

function LatencyAndDegradationSection() {
  const { status, rows, truncated, error, reload } = useExportRows(["retrieval_event"], EXPORT_ROW_CAP);

  const retrievalRows: RetrievalEventExportRow[] = [];
  for (const r of rows) {
    if (r.table === "retrieval_event") retrievalRows.push(r.row);
  }

  if (status === "loading") {
    return (
      <SectionShell>
        <div className="rounded-lg border border-border bg-surface px-4 py-6 text-sm text-text-muted">Loading retrieval_event rows…</div>
      </SectionShell>
    );
  }
  if (status === "error") {
    // ErrorState already distinguishes 401 (no credential) and 403 (credential
    // with no agent_registration) from a genuine server fault, so the
    // no-permission state is a real branch here, not a generic failure.
    return (
      <SectionShell>
        <ErrorState error={error} onRetry={reload} />
      </SectionShell>
    );
  }
  if (retrievalRows.length === 0) {
    return (
      <SectionShell>
        <EmptyState
          title="No retrieval_event rows yet"
          description="Nothing has called POST /v1/retrieve for this project — latency and degradation-mix figures have nothing to compute from. This is the expected state for a young project, not an error."
        />
      </SectionShell>
    );
  }

  const totalOutcomes = retrievalRows.length;

  // A truncated export is an ARBITRARY slice in whatever order
  // Repo.iter_export_rows yields (there is no time filter and no pagination on
  // GET /export/project), NOT the most recent window. Percentiles and mix
  // shares from it therefore cannot be compared to an SLO budget, so we
  // withhold the pass/fail colouring entirely rather than let a green tile
  // assert compliance the sample cannot support.
  const sampleIsRepresentative = !truncated;

  const latencies = retrievalRows.map((r) => r.latency_ms).sort((a, b) => a - b);
  const embedLatencies = retrievalRows
    .map((r) => r.embed_latency_ms)
    .filter((v): v is number => v !== null)
    .sort((a, b) => a - b);
  const embedSkipped = totalOutcomes - embedLatencies.length;

  const byDay = new Map<string, number[]>();
  for (const r of retrievalRows) {
    const day = r.created_at.slice(0, 10);
    const arr = byDay.get(day) ?? [];
    arr.push(r.latency_ms);
    byDay.set(day, arr);
  }
  const dayBuckets: DayBucket[] = Array.from(byDay.entries())
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([day, values]) => {
      const sorted = [...values].sort((a, b) => a - b);
      return {
        day,
        n: sorted.length,
        p50: sorted.length >= MIN_N_P50 ? percentile(sorted, 0.5) : null,
        p99: sorted.length >= MIN_N_P99 ? percentile(sorted, 0.99) : null,
      };
    });

  const outcomeCounts: Record<OutcomeCode, number> = {
    injected: 0,
    holdout: 0,
    abstained_threshold: 0,
    abstained_rarity: 0,
    empty_result: 0,
    degraded_lexical: 0,
    timeout_prefix_only: 0,
    store_error: 0,
  };
  for (const r of retrievalRows) outcomeCounts[r.outcome_code] += 1;
  const presentCodes = OUTCOME_CODES.filter((code) => outcomeCounts[code] > 0);

  const mixSummary = presentCodes
    .map((code) => `${OUTCOME_META[code].label} ${formatPercent(outcomeCounts[code] / totalOutcomes)}`)
    .join("; ");

  const dayColumns: ColumnDef<DayBucket>[] = [
    { key: "day", header: "Day (UTC)", width: "14ch", render: (row) => row.day, sortValue: (row) => row.day },
    { key: "n", header: "Retrievals (n)", numeric: true, width: "14ch", render: (row) => formatInt(row.n), sortValue: (row) => row.n },
    {
      key: "p50",
      header: "p50",
      numeric: true,
      width: "16ch",
      render: (row) =>
        row.p50 === null ? <span className="text-text-faint">n &lt; {MIN_N_P50}</span> : formatDurationMs(row.p50),
      sortValue: (row) => row.p50,
    },
    {
      key: "p99",
      header: "p99",
      numeric: true,
      width: "16ch",
      render: (row) =>
        row.p99 === null ? (
          <span className="text-text-faint">n &lt; {MIN_N_P99}</span>
        ) : (
          <span className={sampleIsRepresentative && row.p99 > RETRIEVAL_BUDGET_MS ? "font-semibold text-risk-high" : undefined}>
            {formatDurationMs(row.p99)}
            {sampleIsRepresentative && row.p99 > RETRIEVAL_BUDGET_MS ? " — over budget" : ""}
          </span>
        ),
      sortValue: (row) => row.p99,
    },
  ];

  return (
    <SectionShell>
      <p className="text-xs text-text-muted">
        Computed from {formatInt(totalOutcomes)} exported <code className="font-mono">retrieval_event</code> row
        {totalOutcomes === 1 ? "" : "s"}. A percentile is shown only where the sample supports it: p50 needs n ≥{" "}
        {MIN_N_P50}, p99 needs n ≥ {MIN_N_P99}. Below those floors the cell says so instead of printing the sample
        maximum under a percentile's name.
      </p>

      {truncated && (
        <div
          role="status"
          className="rounded-md border border-status-quarantined-border/70 bg-status-quarantined-bg/50 px-3 py-2 text-xs text-status-quarantined-fg"
        >
          <span className="font-semibold">Truncated sample — do not read these as SLO numbers.</span>{" "}
          <code className="font-mono">GET /export/project</code> has no time filter and no pagination, so this view
          stopped after {formatInt(EXPORT_ROW_CAP)} rows in export order. That is an arbitrary slice, not the most
          recent window, so budget pass/fail colouring is suppressed below and the mix shares are the shares of this
          slice only.
        </div>
      )}

      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <PercentileTile
          label="Retrieval p50"
          sorted={latencies}
          p={0.5}
          minN={MIN_N_P50}
          budgetMs={RETRIEVAL_BUDGET_MS}
          budgetLabel="total budget"
          scored={false}
        />
        <PercentileTile
          label="Retrieval p99"
          sorted={latencies}
          p={0.99}
          minN={MIN_N_P99}
          budgetMs={RETRIEVAL_BUDGET_MS}
          budgetLabel="total budget"
          scored={sampleIsRepresentative}
        />
        <PercentileTile
          label="Embed p50 (sub-budget)"
          sorted={embedLatencies}
          p={0.5}
          minN={MIN_N_P50}
          budgetMs={EMBED_SUBBUDGET_MS}
          budgetLabel="embed sub-budget"
          scored={false}
          extraNote={`${formatInt(embedSkipped)} of ${formatInt(totalOutcomes)} runs recorded no embed latency (lexical-only, prefix-only or store error) and are excluded`}
        />
        <PercentileTile
          label="Embed p99 (sub-budget)"
          sorted={embedLatencies}
          p={0.99}
          minN={MIN_N_P99}
          budgetMs={EMBED_SUBBUDGET_MS}
          budgetLabel="embed sub-budget"
          scored={sampleIsRepresentative}
          extraNote={`excludes the ${formatInt(embedSkipped)} run${embedSkipped === 1 ? "" : "s"} with no embed step`}
        />
      </div>

      <div className="space-y-2">
        <h3 className="text-sm font-semibold text-text">Retrieval latency by day</h3>
        <p className="text-xs text-text-muted">
          A table, not a line chart, on purpose: the export has gaps on days with no traffic, and a line drawn across
          a gap asserts continuity the data does not have. Every row carries its own n.
        </p>
        <Table
          caption="Per-day retrieval latency percentiles with the sample size each was computed from"
          columns={dayColumns}
          rows={dayBuckets}
          getRowId={(row) => row.day}
          initialSort={{ key: "day", direction: "desc" }}
          density="compact"
          maxHeight="320px"
        />
      </div>

      <div className="rounded-lg border border-border bg-surface p-4">
        <h3 className="text-sm font-semibold text-text">Degradation-ladder outcome mix</h3>
        <p className="mt-0.5 text-xs text-text-muted">
          The fail-open ladder in one view. Each row is labelled with what it means, in words: injected and holdout
          are the system working as intended, abstentions are deliberate caution (PLAN.md §6 targets ≥50% abstention
          — a high abstention share is health, not failure), and only degraded/timeout/store_error are the ladder
          actually engaging.
        </p>
        <div
          className="mt-3 flex h-3 w-full overflow-hidden rounded-full border border-border"
          aria-hidden="true"
          title={mixSummary}
        >
          {presentCodes.map((code) => (
            <div
              key={code}
              className={OUTCOME_META[code].barClass}
              style={{ width: `${(outcomeCounts[code] / totalOutcomes) * 100}%` }}
            />
          ))}
        </div>
        <dl className="mt-3 grid grid-cols-1 gap-1.5 sm:grid-cols-2">
          {presentCodes.map((code) => (
            <div key={code} className="flex items-center justify-between gap-2 text-sm">
              <dt className="flex min-w-0 items-center gap-2">
                <span className={`inline-flex shrink-0 items-center rounded-full border px-2 py-0.5 text-xs font-medium ${OUTCOME_META[code].classes}`}>
                  {OUTCOME_META[code].label}
                </span>
                <span className="truncate text-xs text-text-faint">{MEANING_LABEL[OUTCOME_META[code].meaning]}</span>
              </dt>
              <dd className="shrink-0 tabular-nums text-text-muted">
                {formatInt(outcomeCounts[code])} ({formatPercent(outcomeCounts[code] / totalOutcomes)})
              </dd>
            </div>
          ))}
        </dl>
      </div>
    </SectionShell>
  );
}

function PercentileTile({
  label,
  sorted,
  p,
  minN,
  budgetMs,
  budgetLabel,
  scored,
  extraNote,
}: {
  label: string;
  sorted: readonly number[];
  p: number;
  minN: number;
  budgetMs: number;
  budgetLabel: string;
  /** When false the tile prints the number but refuses to grade it against
   * the budget — a verdict the sample cannot support is worse than none. */
  scored: boolean;
  extraNote?: string;
}) {
  const n = sorted.length;
  const suffix = extraNote === undefined ? "" : ` · ${extraNote}`;

  if (n < minN) {
    return (
      <StatTile
        label={label}
        value="—"
        sublabel={`n=${formatInt(n)}, needs n ≥ ${formatInt(minN)} — a percentile from fewer samples is just the extreme observation${suffix}`}
      />
    );
  }

  const value = percentile(sorted, p);
  if (value === null) {
    return <StatTile label={label} value="—" sublabel={`n=${formatInt(n)}${suffix}`} />;
  }

  const over = value > budgetMs;
  const near = value > budgetMs * 0.8;
  return (
    <StatTile
      label={label}
      value={formatDurationMs(value)}
      tone={scored ? (over ? "high" : near ? "med" : "low") : undefined}
      toneLabel={scored ? (over ? "Over budget" : near ? "Near budget" : "Within budget") : "Not graded — sample truncated"}
      sublabel={`n=${formatInt(n)} · ${budgetLabel} ${formatDurationMs(budgetMs)}${suffix}`}
    />
  );
}

// --------------------------------------------------------------------- //
// What used to be here, and why it is not.
//
// Queue depth and age, dead-letter count, the xmin-horizon figure and worker
// heartbeats were all rendered from constants, because none of them has a data
// source. `work_queue` and `dead_letter` are unpartitioned (contract §5.3 —
// project_id rides in the row so consumers re-scope, but the table itself is
// instance-wide), so a route over them would report every tenant's backlog to
// every tenant. PLAN.md §5 defines no worker-heartbeat table at all, and no
// process writes one. The xmin horizon is a Postgres-instance property.
//
// All four are real operational concerns — PLAN.md §3 explicitly flags the
// queue's xmin bloat as a hot-path latency risk — and all four belong to
// instance-level monitoring, not to a project-scoped console. Naming them here
// is the honest form; drawing them from a constant was not.
// --------------------------------------------------------------------- //

function NotHereSection() {
  return (
    <section className="rounded-lg border border-border bg-surface p-4">
      <h2 className="text-sm font-semibold text-text">Not measured by this console</h2>
      <ul className="mt-2 space-y-1.5 text-xs text-text-muted">
        <li>
          <strong className="font-medium text-text">Queue depth, age and dead letters.</strong>{" "}
          <code className="font-mono">work_queue</code> and{" "}
          <code className="font-mono">dead_letter</code> are unpartitioned and instance-wide; a
          route over them would report other tenants&rsquo; backlog. Watch them from the database
          or the process metrics, not from here.
        </li>
        <li>
          <strong className="font-medium text-text">Worker heartbeats.</strong> No heartbeat table
          exists in PLAN.md §5 and no worker writes one, so &ldquo;is the distiller alive&rdquo; is
          not a question any route can answer. The nearest real proxy this console has is the Spend
          view: a quality-lane worker that ran recently has a ledger row.
        </li>
        <li>
          <strong className="font-medium text-text">xmin horizon on the queue table.</strong> A
          Postgres-instance property, and the one PLAN.md §3 names as a hot-path latency risk
          because the queue and the vector index share one buffer cache. It needs instance
          monitoring with a threshold an operator sets; PLAN.md §6 defines no such field, so this
          console would be inventing both the number and the alarm.
        </li>
      </ul>
    </section>
  );
}

export default function Health() {
  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-lg font-semibold text-text">Health</h1>
        <p className="mt-1 max-w-3xl text-sm text-text-muted">
          Whether the API answers, and what the hot read path has actually been costing. Every
          latency figure carries the sample it was computed from; percentiles below their sample
          floor are withheld rather than printed as the maximum wearing a percentile&rsquo;s name.
        </p>
      </div>
      <ApiLivenessSection />
      <LatencyAndDegradationSection />
      <NotHereSection />
    </div>
  );
}
