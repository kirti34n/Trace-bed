import { useMemo, type ReactNode } from "react";
import {
  useExportRows,
  useKillswitchState,
  useReviewQueue,
  useSpend,
} from "../api/hooks";
import { Table, type ColumnDef } from "../components/Table";
import { StatusBadge } from "../components/StatusBadge";
import { Chart } from "../components/Chart";
import { EmptyState } from "../components/EmptyState";
import { ErrorState } from "../components/ErrorState";
import {
  formatDateTime,
  formatDurationMs,
  formatInt,
  formatCostUsd,
  formatPercent,
  truncateId,
} from "../lib/format";
import {
  RETRIEVABLE_STATUSES,
  STATUSES,
  type MemoryItemExportRow,
  type OutcomeCode,
  type RetrievalEventExportRow,
  type Status,
} from "../api/types";

// The operator's first screen. Two very different data qualities live on this
// page and every section says which it is in the section header itself, not
// in a shared banner at the top — an operator deciding whether to trust a
// number must never have to remember a disclaimer they read three scrolls ago:
//
//   - REAL: computed client-side from GET /export/project's memory_item and
//     retrieval_event rows (the only routes exposing this data at all,
//     contract §9.3). No time-window param exists, so "volume" here is
//     "however many rows this project has ever written, up to the row cap" —
//     labelled as such, never presented as a live rolling window.
//   - REAL, from the control-plane read routes (D-093): the kill-switch
//     state, the spend ledger and the review queue. Every one of these three
//     was a hand-authored fixture until those routes existed; none of them is
//     now. There is no fixture data left on this page.
//
// The per-section "Live data" badge is kept even though every section now
// carries it: it is the thing a reader looks for, and its absence on a future
// section is what should be conspicuous.
//
// Two separate export calls, not one combined call requesting both tables:
// useExportRows' row cap applies across whichever tables are requested
// together, in stream order — asking for memory_item and retrieval_event in
// the same call risks one table's rows crowding out the other's before the
// cap is hit. Two independent capped/truncation-flagged streams avoid that
// bias at the cost of two full-project scans instead of one.

const EXPORT_ROW_CAP = 8000;

// A p99 estimated from a handful of samples is just the maximum wearing a
// percentile's name. Below this many samples the tile reports the maximum and
// says so, rather than printing a confident-looking "p99".
const MIN_P99_SAMPLES = 100;

// The Overview's three control-plane cards are summaries, not the views.
// Each pulls a short window / short page and points onward rather than
// duplicating the full table a dedicated view already renders.
const OVERVIEW_SPEND_DAYS = 7;
const OVERVIEW_REVIEW_LIMIT = 50;

const DAY_MS = 86_400_000;
const MAX_CHART_DAYS = 90;

function utcDayBucket(iso: string): string {
  // admin.py's _json_safe emits UTC ISO-8601, so slicing yields a UTC day.
  // Every label says "UTC" for that reason — an unqualified "day" boundary is
  // wrong by hours for most operators reading this screen.
  return iso.length >= 10 ? iso.slice(0, 10) : iso;
}

function isoDayToUtcMs(day: string): number {
  const parts = day.split("-");
  const y = Number(parts[0]);
  const m = Number(parts[1]);
  const d = Number(parts[2]);
  if (!Number.isFinite(y) || !Number.isFinite(m) || !Number.isFinite(d)) return Number.NaN;
  return Date.UTC(y, m - 1, d);
}

function utcMsToIsoDay(ms: number): string {
  return new Date(ms).toISOString().slice(0, 10);
}

/** Days with zero rows must occupy real horizontal space; indexing the x-axis
 * by "days that happen to have data" draws a continuous line across a silence
 * and claims a continuity the data does not have. */
function denseDays(firstDay: string, lastDay: string, maxDays: number): string[] {
  const start = isoDayToUtcMs(firstDay);
  const end = isoDayToUtcMs(lastDay);
  if (Number.isNaN(start) || Number.isNaN(end) || end < start) return [];
  const spanDays = Math.floor((end - start) / DAY_MS) + 1;
  const shown = Math.min(spanDays, maxDays);
  const firstShownMs = end - (shown - 1) * DAY_MS;
  return Array.from({ length: shown }, (_, i) => utcMsToIsoDay(firstShownMs + i * DAY_MS));
}

function percentileSorted(valuesAsc: readonly number[], q: number): number | null {
  if (valuesAsc.length === 0) return null;
  const idx = Math.min(valuesAsc.length - 1, Math.max(0, Math.ceil(q * valuesAsc.length) - 1));
  return valuesAsc[idx] ?? null;
}

// Outcome codes are deliberately NOT rendered as one merged bar (task brief:
// "these mean very different things and must not be one bar"). Each gets its
// own fixed label, its own row, and a colour reused from the status token set
// purely for guaranteed-distinct, theme-aware, already-contrast-audited hues —
// this is NOT claiming an outcome code IS a memory status, just borrowing the
// pairing instead of inventing a second colour scale. Every row also carries
// its label as text, so colour is never the only encoding.
const OUTCOME_META: Record<
  OutcomeCode,
  { label: string; hint: string; chipClasses: string; barClass: string }
> = {
  injected: {
    label: "Injected",
    hint: "Memory context was assembled and appended to the run.",
    chipClasses: "bg-status-validated-bg text-status-validated-fg border-status-validated-border",
    barClass: "bg-status-validated-fg",
  },
  abstained_threshold: {
    label: "Abstained — threshold",
    hint: "Best candidate scored below the similarity/BM25 threshold. The system declining to inject is correct behaviour, not a fault.",
    chipClasses: "bg-status-candidate-bg text-status-candidate-fg border-status-candidate-border",
    barClass: "bg-status-candidate-fg",
  },
  abstained_rarity: {
    label: "Abstained — rarity",
    hint: "Rarity gate declined. Includes cold-start young-corpus abstention — the wire protocol has no separate cold-start code (see the Abstention view).",
    chipClasses: "bg-status-pinned-bg text-status-pinned-fg border-status-pinned-border",
    barClass: "bg-status-pinned-fg",
  },
  empty_result: {
    label: "Empty result",
    hint: "No candidates existed to score at all.",
    chipClasses: "bg-status-archived-bg text-status-archived-fg border-status-archived-border",
    barClass: "bg-status-archived-fg",
  },
  degraded_lexical: {
    label: "Degraded — lexical only",
    hint: "The 200ms embedding sub-budget was exceeded; retrieval fell back to BM25-only.",
    chipClasses: "bg-status-stale-bg text-status-stale-fg border-status-stale-border",
    barClass: "bg-status-stale-fg",
  },
  timeout_prefix_only: {
    label: "Timeout — prefix only",
    hint: "The 300ms total retrieval budget was exceeded; only the static prefix was served. This is the system failing, not abstaining.",
    chipClasses:
      "bg-status-quarantined-bg text-status-quarantined-fg border-status-quarantined-border",
    barClass: "bg-status-quarantined-fg",
  },
  store_error: {
    label: "Store error",
    hint: "The memory store errored; the run received nothing (fail-open). This is the system failing, not abstaining.",
    chipClasses:
      "bg-status-tombstoned-bg text-status-tombstoned-fg border-status-tombstoned-border",
    barClass: "bg-status-tombstoned-fg",
  },
  holdout: {
    label: "Holdout arm",
    hint: "This run was sampled into the holdout arm for lift measurement; memory was withheld deliberately.",
    chipClasses:
      "bg-status-superseded-bg text-status-superseded-fg border-status-superseded-border",
    barClass: "bg-status-superseded-fg",
  },
};

const OUTCOME_ORDER: OutcomeCode[] = [
  "injected",
  "abstained_threshold",
  "abstained_rarity",
  "empty_result",
  "degraded_lexical",
  "timeout_prefix_only",
  "store_error",
  "holdout",
];

function SectionHeader({
  title,
  badge,
  description,
}: {
  title: string;
  badge: "live" | "fixture";
  description: string;
}) {
  return (
    <div className="mb-3">
      <h2 className="flex flex-wrap items-center gap-2 text-sm font-semibold text-text">
        {title}
        <span
          className={
            "rounded-full border px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide " +
            (badge === "live"
              ? "border-status-validated-border bg-status-validated-bg text-status-validated-fg"
              : "border-status-candidate-border bg-status-candidate-bg text-status-candidate-fg")
          }
        >
          {badge === "live" ? "Live data" : "Fixture — no route"}
        </span>
      </h2>
      <p className="mt-0.5 max-w-2xl text-xs text-text-muted">{description}</p>
    </div>
  );
}

function StatTile({
  label,
  value,
  sublabel,
  tone,
}: {
  label: string;
  value: string;
  sublabel?: string;
  tone?: "danger" | "warn";
}) {
  return (
    <div
      className={
        "rounded-lg border px-4 py-3 " +
        (tone === "danger"
          ? "border-status-tombstoned-border bg-status-tombstoned-bg"
          : tone === "warn"
            ? "border-status-quarantined-border bg-status-quarantined-bg"
            : "border-border bg-surface")
      }
    >
      <p className="text-xs font-medium uppercase tracking-wide text-text-muted">{label}</p>
      <p className="mt-1 text-2xl font-semibold tabular-nums text-text">{value}</p>
      {sublabel !== undefined && <p className="mt-0.5 text-xs text-text-faint">{sublabel}</p>}
    </div>
  );
}


// --------------------------------------------------------------------- //
// The three control-plane summaries. Each is its own component with its own
// query so one failing route (a 403 on a credential without project scope,
// say) collapses one card instead of the whole page — and so each renders its
// own loading / empty / error state rather than sharing a page-level one that
// could not say which read failed.
// --------------------------------------------------------------------- //

function CardShell({ children }: { children: ReactNode }) {
  return <div className="rounded-lg border border-border bg-surface p-4">{children}</div>;
}

function CardSkeleton({ label }: { label: string }) {
  return (
    <div
      role="status"
      aria-label={label}
      className="h-32 animate-pulse rounded-lg border border-border bg-surface"
    />
  );
}

function KillswitchSummary() {
  const query = useKillswitchState();
  if (query.status === "error") return <ErrorState error={query.error} onRetry={query.reload} />;
  if (query.status !== "success") return <CardSkeleton label="Loading kill-switch state" />;

  const cells = query.data?.cells ?? [];
  if (cells.length === 0) {
    return (
      <EmptyState
        title="No kill-switch decision recorded"
        description="killswitch_state is empty for this project. That means nothing has been auto-disabled and no operator override has been recorded — it does not mean every memory type has been measured and passed."
      />
    );
  }
  const disabled = cells.filter((c) => c.disabled);
  return (
    <CardShell>
      <p className="text-sm text-text">
        <span className="font-semibold tabular-nums">{formatInt(disabled.length)}</span> of{" "}
        {formatInt(cells.length)} recorded cell(s) currently disabled.
      </p>
      <ul className="mt-3 space-y-2">
        {cells.slice(0, 4).map((c) => (
          <li
            key={`${c.agent_type_id ?? "project-wide"}-${c.mem_type}-${c.changed_at}`}
            className={
              "flex items-start justify-between gap-3 rounded-md border px-3 py-2 " +
              (c.disabled
                ? "border-status-tombstoned-border bg-status-tombstoned-bg"
                : "border-border bg-bg")
            }
          >
            <div className="min-w-0">
              <p className="truncate text-sm font-medium text-text">
                {c.agent_type_id === null ? "All agent types" : truncateId(c.agent_type_id)} ·{" "}
                {c.mem_type}
              </p>
              <p className="text-xs text-text-faint">changed {formatDateTime(c.changed_at)}</p>
            </div>
            {/* A word, not a colour: "DISABLED" is legible to an operator with
                any colour vision, and the row tint is the redundant channel. */}
            <span
              className={
                "shrink-0 rounded-full border px-2 py-0.5 text-xs font-semibold " +
                (c.disabled
                  ? "border-status-tombstoned-border text-status-tombstoned-fg"
                  : "border-border-strong text-text-muted")
              }
            >
              {c.disabled ? "DISABLED" : "Enabled"}
            </span>
          </li>
        ))}
      </ul>
      {cells.length > 4 && (
        <p className="mt-2 text-xs text-text-muted">
          Showing the 4 most recent of {formatInt(cells.length)}. The Kill Switch view has all of
          them with their recorded evidence.
        </p>
      )}
    </CardShell>
  );
}

function SpendSummary() {
  const query = useSpend(OVERVIEW_SPEND_DAYS);
  if (query.status === "error") return <ErrorState error={query.error} onRetry={query.reload} />;
  if (query.status !== "success") return <CardSkeleton label="Loading spend ledger" />;

  const cells = query.data?.cells ?? [];
  if (cells.length === 0) {
    return (
      <EmptyState
        title="No LLM spend recorded"
        description={`spend_ledger has no rows on or after ${query.data?.since ?? "the window start"}. Expected for a project whose quality-lane workers have not run — the operational lane is LLM-free and never writes here.`}
      />
    );
  }
  const total = cells.reduce((acc, c) => acc + c.cost_usd, 0);
  const days = new Set(cells.map((c) => c.day)).size;
  const workers = new Set(cells.map((c) => c.worker)).size;
  return (
    <CardShell>
      <p className="text-2xl font-semibold tabular-nums text-text">{formatCostUsd(total)}</p>
      {/* Never a bare total: the window and the number of days that actually
          carried spend are what make it readable. $10 across one day and $10
          across seven are different operational pictures. */}
      <p className="mt-1 text-xs text-text-muted">
        across {formatInt(days)} of {formatInt(query.data?.days ?? OVERVIEW_SPEND_DAYS)} UTC days
        since {query.data?.since}, {formatInt(workers)} worker(s)
      </p>
      <p className="mt-2 text-xs text-text-faint">
        No cap gauge is drawn: spend.daily_llm_cap_usd resolves from process defaults the dashboard
        cannot read, so a gauge here would be measured against a documented default rather than
        this deployment&rsquo;s configured value.
      </p>
    </CardShell>
  );
}

function ReviewSummary() {
  const query = useReviewQueue(false, OVERVIEW_REVIEW_LIMIT);
  if (query.status === "error") return <ErrorState error={query.error} onRetry={query.reload} />;
  if (query.status !== "success") return <CardSkeleton label="Loading review queue" />;

  const items = query.data?.items ?? [];
  if (items.length === 0) {
    return (
      <EmptyState
        title="No open review items"
        description="Nothing is waiting on a human decision. The queue fills when a retirement is blocked below the distinct-principal threshold, or a candidate re-flags on a scan re-pass."
      />
    );
  }
  const atLimit = (query.data?.returned ?? 0) >= (query.data?.limit ?? OVERVIEW_REVIEW_LIMIT);
  return (
    <CardShell>
      <p className="mb-2 text-xs text-text-muted">
        {atLimit ? "At least " : ""}
        {formatInt(items.length)} open item(s)
        {atLimit ? " — the page limit was reached, so this is a lower bound." : "."}
      </p>
      <ul className="space-y-2">
        {items.slice(0, 5).map((item) => (
          <li
            key={item.item_id}
            className="rounded-md border border-status-quarantined-border bg-status-quarantined-bg px-3 py-2 text-sm text-status-quarantined-fg"
          >
            <span className="font-medium">{item.reason}</span>
            <span className="ml-2 text-xs opacity-80">
              opened {formatDateTime(item.opened_at)}
              {item.memory_id !== null ? (
                <span title={item.memory_id}> · memory {truncateId(item.memory_id)}</span>
              ) : null}
            </span>
          </li>
        ))}
      </ul>
      {items.length > 5 && (
        <p className="mt-2 text-xs text-text-muted">
          Showing 5 of {formatInt(items.length)}. The Review Queue view has all of them.
        </p>
      )}
    </CardShell>
  );
}

export default function Overview() {
  const memoryExport = useExportRows(["memory_item"], EXPORT_ROW_CAP);
  const retrievalExport = useExportRows(["retrieval_event"], EXPORT_ROW_CAP);

  const memoryRows = useMemo(
    () =>
      memoryExport.rows.flatMap((r): MemoryItemExportRow[] =>
        r.table === "memory_item" ? [r.row] : []
      ),
    [memoryExport.rows]
  );
  const retrievalRows = useMemo(
    () =>
      retrievalExport.rows.flatMap((r): RetrievalEventExportRow[] =>
        r.table === "retrieval_event" ? [r.row] : []
      ),
    [retrievalExport.rows]
  );

  const statusCounts = useMemo(() => {
    const counts = new Map<Status, number>(STATUSES.map((s) => [s, 0]));
    for (const row of memoryRows) counts.set(row.status, (counts.get(row.status) ?? 0) + 1);
    return counts;
  }, [memoryRows]);

  const quarantinedTierB = useMemo(
    () => memoryRows.filter((r) => r.status === "quarantined" && r.trust_tier === "B").length,
    [memoryRows]
  );

  const outcomeCounts = useMemo(() => {
    const counts = new Map<OutcomeCode, number>(OUTCOME_ORDER.map((c) => [c, 0]));
    for (const row of retrievalRows)
      counts.set(row.outcome_code, (counts.get(row.outcome_code) ?? 0) + 1);
    return counts;
  }, [retrievalRows]);

  const latencyStats = useMemo(() => {
    const sorted = retrievalRows.map((r) => r.latency_ms).sort((a, b) => a - b);
    return {
      p99: percentileSorted(sorted, 0.99),
      max: sorted.length > 0 ? sorted[sorted.length - 1] ?? null : null,
      count: sorted.length,
    };
  }, [retrievalRows]);

  const latencyIsP99 = latencyStats.count >= MIN_P99_SAMPLES;
  const latencyValue = latencyIsP99 ? latencyStats.p99 : latencyStats.max;

  const dailyVolume = useMemo(() => {
    const byDay = new Map<string, number>();
    for (const row of retrievalRows) {
      const day = utcDayBucket(row.created_at);
      byDay.set(day, (byDay.get(day) ?? 0) + 1);
    }
    const days = [...byDay.keys()].sort((a, b) => a.localeCompare(b));
    const first = days[0];
    const last = days[days.length - 1];
    if (first === undefined || last === undefined) return { days: [] as string[], counts: [] as number[] };
    const axis = denseDays(first, last, MAX_CHART_DAYS);
    return { days: axis, counts: axis.map((d) => byDay.get(d) ?? 0) };
  }, [retrievalRows]);

  const volumeSeries = useMemo(
    () => dailyVolume.counts.map((count, i) => ({ x: i, y: count })),
    [dailyVolume]
  );

  const totalOutcomes = retrievalRows.length;
  const totalVaultSize = memoryRows.length;

  const statusColumns: ColumnDef<[Status, number]>[] = [
    {
      key: "status",
      header: "Status",
      width: "18ch",
      render: ([status]) => <StatusBadge status={status} />,
      sortValue: ([status]) => status,
    },
    {
      key: "retrievable",
      header: "Reaches a prompt?",
      width: "20ch",
      // Not colour-coded: a word is unambiguous where a green dot is not, and
      // "can this row still be injected into an agent" is the single most
      // consequential fact about a status on this page.
      render: ([status]) =>
        RETRIEVABLE_STATUSES.has(status) ? (
          <span className="text-text">Yes — retrievable</span>
        ) : (
          <span className="text-text-muted">No — never served</span>
        ),
      sortValue: ([status]) => (RETRIEVABLE_STATUSES.has(status) ? 0 : 1),
    },
    {
      key: "count",
      header: "Count",
      numeric: true,
      width: "10ch",
      render: ([, count]) => formatInt(count),
      sortValue: ([, count]) => count,
    },
    {
      key: "share",
      header: "Share of vault",
      numeric: true,
      width: "14ch",
      render: ([, count]) => (totalVaultSize > 0 ? formatPercent(count / totalVaultSize) : "—"),
      sortValue: ([, count]) => (totalVaultSize > 0 ? count / totalVaultSize : 0),
    },
  ];

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-lg font-semibold text-text">Overview</h1>
        <p className="mt-1 text-sm text-text-muted">
          Fleet activity, vault composition, and governance state at a glance.
        </p>
      </div>

      <section>
        <SectionHeader
          title="Retrieval volume & latency"
          badge="live"
          description="From every retrieval_event and memory_item row exported for this project. No time-window filter exists on /export/project, so these are all-time totals up to the export row cap — not a rolling window."
        />
        {retrievalExport.status === "error" ? (
          <ErrorState error={retrievalExport.error} onRetry={retrievalExport.reload} />
        ) : memoryExport.status === "error" ? (
          <ErrorState error={memoryExport.error} onRetry={memoryExport.reload} />
        ) : retrievalExport.status === "loading" || memoryExport.status === "loading" ? (
          <div
            role="status"
            aria-label="Loading retrieval telemetry"
            className="grid grid-cols-2 gap-3 sm:grid-cols-4"
          >
            {Array.from({ length: 4 }, (_, i) => (
              <div
                key={i}
                className="h-[70px] animate-pulse rounded-lg border border-border bg-surface"
              />
            ))}
          </div>
        ) : retrievalRows.length === 0 && totalVaultSize === 0 ? (
          <EmptyState
            title="Nothing recorded for this project yet"
            description="No retrieval events and no memory items. That is the expected state for a project that has just been registered — nothing here is broken."
          />
        ) : (
          <>
            <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
              <StatTile
                label="Total retrievals"
                value={formatInt(totalOutcomes)}
                sublabel="all-time, exported"
              />
              <StatTile
                label={latencyIsP99 ? "p99 latency" : "Max latency"}
                value={latencyValue !== null ? formatDurationMs(latencyValue) : "—"}
                sublabel={
                  latencyValue === null
                    ? "no retrieval events"
                    : latencyIsP99
                      ? `budget 300ms · n=${formatInt(latencyStats.count)}`
                      : `budget 300ms · n=${formatInt(latencyStats.count)} — under ${formatInt(MIN_P99_SAMPLES)} samples a p99 is just the maximum, so the maximum is what is shown`
                }
                // Only a real p99 can breach a p99 budget. Warning on the
                // maximum of a handful of calls would light this tile up for
                // every project whose first request was a cold start.
                tone={latencyIsP99 && latencyValue !== null && latencyValue > 300 ? "warn" : undefined}
              />
              <StatTile
                label="Vault size"
                value={formatInt(totalVaultSize)}
                sublabel="memory_item rows, every status"
              />
              <StatTile
                label="Quarantined Tier B"
                value={formatInt(quarantinedTierB)}
                sublabel="content-derived, not retrievable until corroborated"
                tone={quarantinedTierB > 0 ? "warn" : undefined}
              />
            </div>
            {memoryExport.truncated && (
              <p className="mt-2 text-xs text-status-quarantined-fg">
                Vault size is a lower bound — the export stream hit its{" "}
                {formatInt(EXPORT_ROW_CAP)}-row cap before finishing.
              </p>
            )}
            {retrievalExport.truncated && (
              <p className="mt-1 text-xs text-status-quarantined-fg">
                Retrieval volume is a lower bound — the export stream hit its{" "}
                {formatInt(EXPORT_ROW_CAP)}-row cap before finishing.
              </p>
            )}
            {volumeSeries.length > 1 && (
              <div className="mt-4 rounded-lg border border-border bg-surface p-4">
                <h3 className="text-xs font-semibold uppercase tracking-wide text-text-muted">
                  Retrievals per UTC day
                </h3>
                <p className="mt-0.5 text-xs text-text-faint">
                  {dailyVolume.days[0]} → {dailyVolume.days[dailyVolume.days.length - 1]} · days with
                  no retrievals are plotted as zero, so a gap in activity reads as a gap.
                </p>
                <div className="mt-2">
                  <Chart
                    ariaLabel="Line chart of retrieval count per UTC day on a continuous calendar axis, computed from exported retrieval_event rows"
                    series={[{ label: "Retrievals", points: volumeSeries }]}
                    xTickFormat={(x) => dailyVolume.days[Math.round(x)]?.slice(5) ?? ""}
                    yTickFormat={(y) => formatInt(y)}
                  />
                </div>
              </div>
            )}
          </>
        )}
      </section>

      <section>
        <SectionHeader
          title="Outcome code mix"
          badge="live"
          description="Every outcome code shown separately — injected, abstained, degraded, timed out and holdout mean very different things and are never collapsed into one bar or one rate."
        />
        {retrievalExport.status === "error" ? (
          <ErrorState error={retrievalExport.error} onRetry={retrievalExport.reload} />
        ) : retrievalExport.status === "loading" ? (
          <div
            role="status"
            aria-label="Loading outcome code mix"
            className="h-40 animate-pulse rounded-lg border border-border bg-surface"
          />
        ) : totalOutcomes === 0 ? (
          <EmptyState
            title="No outcomes to break down yet"
            description="Every /v1/retrieve call writes one retrieval_event row; none exist for this project so far."
          />
        ) : (
          <div className="rounded-lg border border-border bg-surface p-4">
            <p className="mb-3 text-xs text-text-muted">
              n={formatInt(totalOutcomes)} retrieval events. Shares are of that total.
            </p>
            <div className="space-y-1.5">
              {OUTCOME_ORDER.map((code) => {
                const count = outcomeCounts.get(code) ?? 0;
                const pct = totalOutcomes > 0 ? count / totalOutcomes : 0;
                const meta = OUTCOME_META[code];
                return (
                  <div key={code} className="flex items-center gap-3">
                    <span
                      className={`w-52 shrink-0 truncate rounded-full border px-2 py-0.5 text-xs font-medium ${meta.chipClasses}`}
                    >
                      {meta.label}
                    </span>
                    <div
                      className="h-2 flex-1 overflow-hidden rounded-full bg-border"
                      aria-hidden="true"
                    >
                      <div
                        className={`h-full rounded-full ${meta.barClass}`}
                        style={{ width: `${Math.max(pct * 100, count > 0 ? 1.5 : 0)}%` }}
                      />
                    </div>
                    <span className="w-28 shrink-0 text-right text-xs tabular-nums text-text-muted">
                      {formatInt(count)} · {formatPercent(pct)}
                    </span>
                  </div>
                );
              })}
            </div>
            {/* A <details> glossary rather than title= tooltips: a hover-only
                hint is unreachable by keyboard and unreliable for screen
                readers, and these definitions are the difference between
                reading abstention as healthy and reading it as an outage. */}
            <details className="mt-4 border-t border-border pt-3">
              <summary className="cursor-pointer text-xs font-medium text-text-muted hover:text-text">
                What each outcome code means
              </summary>
              <dl className="mt-2 space-y-1.5">
                {OUTCOME_ORDER.map((code) => (
                  <div key={code} className="text-xs">
                    <dt className="font-medium text-text">{OUTCOME_META[code].label}</dt>
                    <dd className="text-text-muted">{OUTCOME_META[code].hint}</dd>
                  </div>
                ))}
              </dl>
            </details>
          </div>
        )}
      </section>

      <section>
        <SectionHeader
          title="Vault size by status"
          badge="live"
          description="Current memory_item counts per lifecycle status, and whether that status can still reach an agent's prompt."
        />
        {memoryExport.status === "error" ? (
          <ErrorState error={memoryExport.error} onRetry={memoryExport.reload} />
        ) : memoryExport.status === "success" && totalVaultSize === 0 ? (
          <EmptyState
            title="Vault is empty"
            description="No memory_item rows exist for this project yet — expected for a young project; nothing here is broken."
          />
        ) : (
          <Table
            caption="Memory vault item counts grouped by lifecycle status, with whether each status is retrievable"
            columns={statusColumns}
            rows={[...statusCounts.entries()]}
            getRowId={([status]) => status}
            loading={memoryExport.status === "loading"}
            initialSort={{ key: "count", direction: "desc" }}
          />
        )}
      </section>

      <div className="grid gap-6 lg:grid-cols-2">
        <section>
          <SectionHeader
            title="Kill switch state"
            badge="live"
            description="Every killswitch_state row recorded for this project (GET /admin/killswitch_state). An empty result means no kill-switch decision has ever been recorded — it does NOT mean everything is enabled."
          />
          <KillswitchSummary />
        </section>

        <section>
          <SectionHeader
            title="Spend, last 7 days"
            badge="live"
            description="This project's spend_ledger cells for the seven UTC days ending today (GET /admin/spend). The daily cap is a server-side config value the dashboard cannot read, so no cap gauge is drawn here — the Spend view explains why."
          />
          <SpendSummary />
        </section>
      </div>

      <section>
        <SectionHeader
          title="Open review items"
          badge="live"
          description="Unresolved review_queue rows (GET /admin/review_queue). These are the decisions the machine refused to make on its own — a retirement below the distinct-principal threshold, a scan re-flag on a candidate re-pass."
        />
        <ReviewSummary />
      </section>
    </div>
  );
}
