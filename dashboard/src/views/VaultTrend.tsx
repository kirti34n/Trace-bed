import { useMemo } from "react";
import { useExportRows } from "../api/hooks";
import { Table, type ColumnDef } from "../components/Table";
import { StatusBadge } from "../components/StatusBadge";
import { Chart } from "../components/Chart";
import { EmptyState } from "../components/EmptyState";
import { ErrorState } from "../components/ErrorState";
import { formatInt, formatPercent } from "../lib/format";
import {
  MEM_TYPES,
  RETRIEVABLE_STATUSES,
  STATUSES,
  type MemType,
  type MemoryItemExportRow,
  type Status,
} from "../api/types";

// Vault size over time by status and mem_type, net growth rate, new vs merged
// (task brief). The Phase 2 soak gate (PLAN.md §7) asserts net vault growth
// decelerates week-over-week — this is the view a human watches that on, so
// the week-over-week figure has to mean what the gate means by it.
//
// Three structural limits on what is computable from GET /export/project,
// all called out on the page itself rather than papered over:
//
//   1. `memory_item.created_at` is immutable, so "new items per day" is a real
//      historical series. `status` is each row's CURRENT status, not a history
//      — an item created 40 days ago and validated since appears under
//      "validated" on its creation day, not under whatever status it held
//      then. The by-status figures are therefore a snapshot, never a
//      point-in-time reconstruction; no status-change history is exported.
//   2. Because exits (archive, retire, tombstone) have no timestamped history,
//      this view measures GROSS creation per week, not the gate's NET active
//      vault. It says so wherever the number appears.
//   3. "New vs merged" needs `memory_link` (relation `derived_from` is how the
//      consolidator's incremental deltas would show up). `memory_link` has no
//      export table and no route at all, so "merged" is reported as not
//      observable — never guessed at, never shown as a fabricated zero.
//
// Weeks are real 7-calendar-day windows anchored on the first creation date,
// INCLUDING weeks with zero creations. Bucketing "seven entries of the
// days-that-happen-to-have-data list" would make a week a variable-length
// period and turn week-over-week growth — the gate's own metric — into a
// number computed over incomparable denominators.

const EXPORT_ROW_CAP = 8000;
const DAY_MS = 86_400_000;
const WEEK_DAYS = 7;
const MAX_CHART_DAYS = 90;
const MAX_WEEKS = 104;

// A "decelerating" verdict off a single week-to-week delta is noise; the gate
// wants a sustained trend. Below this many weeks the view refuses to call it.
const MIN_WEEKS_FOR_TREND = 3;

const MEM_TYPE_META: Record<MemType, { label: string; strokeClass: string }> = {
  episodic: { label: "Episodic", strokeClass: "stroke-status-candidate-fg" },
  semantic: { label: "Semantic", strokeClass: "stroke-status-validated-fg" },
  lesson: { label: "Lesson", strokeClass: "stroke-status-pinned-fg" },
  preference: { label: "Preference", strokeClass: "stroke-status-stale-fg" },
};

function utcDayBucket(iso: string): string {
  // admin.py's _json_safe emits UTC ISO-8601; slicing yields a UTC day, which
  // is what every "day"/"week" label on this page is qualified with.
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

function denseDays(firstDay: string, lastDay: string, maxDays: number): string[] {
  const start = isoDayToUtcMs(firstDay);
  const end = isoDayToUtcMs(lastDay);
  if (Number.isNaN(start) || Number.isNaN(end) || end < start) return [];
  const spanDays = Math.floor((end - start) / DAY_MS) + 1;
  const shown = Math.min(spanDays, maxDays);
  const firstShownMs = end - (shown - 1) * DAY_MS;
  return Array.from({ length: shown }, (_, i) => utcMsToIsoDay(firstShownMs + i * DAY_MS));
}

function emptyMemTypeCounts(): Record<MemType, number> {
  return { episodic: 0, semantic: 0, lesson: 0, preference: 0 };
}

interface DayAgg {
  total: number;
  byType: Record<MemType, number>;
}

interface WeekRow {
  weekStart: string;
  weekLabel: string;
  newItems: number;
  cumulative: number;
  prevItems: number | null;
  changePct: number | null;
}

function StatTile({
  label,
  value,
  sublabel,
}: {
  label: string;
  value: string;
  sublabel?: string;
}) {
  return (
    <div className="rounded-lg border border-border bg-surface px-4 py-3">
      <p className="text-xs font-medium uppercase tracking-wide text-text-muted">{label}</p>
      <p className="mt-1 text-2xl font-semibold tabular-nums text-text">{value}</p>
      {sublabel !== undefined && <p className="mt-0.5 text-xs text-text-faint">{sublabel}</p>}
    </div>
  );
}

export default function VaultTrend() {
  const memoryExport = useExportRows(["memory_item"], EXPORT_ROW_CAP);

  const rows = useMemo(
    () =>
      memoryExport.rows.flatMap((r): MemoryItemExportRow[] =>
        r.table === "memory_item" ? [r.row] : []
      ),
    [memoryExport.rows]
  );

  const byDay = useMemo(() => {
    const map = new Map<string, DayAgg>();
    for (const row of rows) {
      const day = utcDayBucket(row.created_at);
      const existing = map.get(day) ?? { total: 0, byType: emptyMemTypeCounts() };
      existing.total += 1;
      existing.byType[row.mem_type] += 1;
      map.set(day, existing);
    }
    return map;
  }, [rows]);

  const sortedDays = useMemo(() => [...byDay.keys()].sort((a, b) => a.localeCompare(b)), [byDay]);

  // Chart axis: a dense calendar range, so a month with no creations is a
  // month-wide flat stretch rather than a single invisible step.
  const chartDays = useMemo(() => {
    const first = sortedDays[0];
    const last = sortedDays[sortedDays.length - 1];
    if (first === undefined || last === undefined) return [];
    return denseDays(first, last, MAX_CHART_DAYS);
  }, [sortedDays]);

  // Cumulative must count everything created BEFORE the visible window too,
  // otherwise a truncated axis silently restates the vault as smaller than it
  // is at the left edge of the chart.
  const cumulativeSeries = useMemo(() => {
    const firstShown = chartDays[0];
    if (firstShown === undefined) return [];
    let running = 0;
    for (const day of sortedDays) {
      if (day.localeCompare(firstShown) < 0) running += byDay.get(day)?.total ?? 0;
    }
    return chartDays.map((day, i) => {
      running += byDay.get(day)?.total ?? 0;
      return { x: i, y: running };
    });
  }, [byDay, chartDays, sortedDays]);

  const memTypeSeries = MEM_TYPES.map((memType) => ({
    label: MEM_TYPE_META[memType].label,
    colorClassName: MEM_TYPE_META[memType].strokeClass,
    points: chartDays.map((day, i) => ({ x: i, y: byDay.get(day)?.byType[memType] ?? 0 })),
  }));

  const weekRows: WeekRow[] = useMemo(() => {
    const anchorDay = sortedDays[0];
    const lastDay = sortedDays[sortedDays.length - 1];
    if (anchorDay === undefined || lastDay === undefined) return [];
    const anchorMs = isoDayToUtcMs(anchorDay);
    const lastMs = isoDayToUtcMs(lastDay);
    if (Number.isNaN(anchorMs) || Number.isNaN(lastMs)) return [];

    const totalWeeks = Math.floor((lastMs - anchorMs) / (WEEK_DAYS * DAY_MS)) + 1;
    const buckets = new Array<number>(Math.min(totalWeeks, MAX_WEEKS)).fill(0);
    for (const [day, agg] of byDay) {
      const ms = isoDayToUtcMs(day);
      if (Number.isNaN(ms)) continue;
      const index = Math.floor((ms - anchorMs) / (WEEK_DAYS * DAY_MS));
      if (index >= 0 && index < buckets.length) buckets[index] = (buckets[index] ?? 0) + agg.total;
    }

    let cumulative = 0;
    return buckets.map((newItems, i) => {
      cumulative += newItems;
      const startMs = anchorMs + i * WEEK_DAYS * DAY_MS;
      const endMs = startMs + (WEEK_DAYS - 1) * DAY_MS;
      const prevItems = i > 0 ? (buckets[i - 1] ?? 0) : null;
      // A previous week of zero has no defined percentage change; showing
      // "+∞%" or "0%" would both be inventions.
      const changePct =
        prevItems !== null && prevItems > 0 ? (newItems - prevItems) / prevItems : null;
      return {
        weekStart: utcMsToIsoDay(startMs),
        weekLabel: `${utcMsToIsoDay(startMs)} – ${utcMsToIsoDay(endMs)}`,
        newItems,
        cumulative,
        prevItems,
        changePct,
      };
    });
  }, [byDay, sortedDays]);

  const latestWeek = weekRows[weekRows.length - 1];
  const trend = useMemo(() => {
    if (weekRows.length < MIN_WEEKS_FOR_TREND) return null;
    const tail = weekRows.slice(-MIN_WEEKS_FOR_TREND);
    let strictlyDecreasing = true;
    for (let i = 1; i < tail.length; i += 1) {
      if ((tail[i]?.newItems ?? 0) >= (tail[i - 1]?.newItems ?? 0)) strictlyDecreasing = false;
    }
    return { strictlyDecreasing, weeks: tail.length };
  }, [weekRows]);

  const statusCounts = useMemo(() => {
    const counts = new Map<Status, number>(STATUSES.map((s) => [s, 0]));
    for (const row of rows) counts.set(row.status, (counts.get(row.status) ?? 0) + 1);
    return counts;
  }, [rows]);

  const retrievableCount = useMemo(
    () => rows.filter((r) => RETRIEVABLE_STATUSES.has(r.status)).length,
    [rows]
  );

  const chartRangeLabel =
    chartDays.length > 0 ? `${chartDays[0]} → ${chartDays[chartDays.length - 1]} (UTC)` : "";

  const weekColumns: ColumnDef<WeekRow>[] = [
    {
      key: "week",
      header: "Week (UTC, from first creation)",
      width: "26ch",
      render: (r) => r.weekLabel,
      sortValue: (r) => r.weekStart,
    },
    {
      key: "new",
      header: "New items",
      numeric: true,
      width: "11ch",
      render: (r) => formatInt(r.newItems),
      sortValue: (r) => r.newItems,
    },
    {
      key: "cumulative",
      header: "Cumulative created",
      numeric: true,
      width: "16ch",
      render: (r) => formatInt(r.cumulative),
      sortValue: (r) => r.cumulative,
    },
    {
      key: "change",
      header: "vs previous week",
      numeric: true,
      width: "20ch",
      render: (r) =>
        r.changePct !== null ? (
          <div>
            <div>{formatPercent(r.changePct)}</div>
            <div className="text-xs text-text-faint">
              {formatInt(r.prevItems ?? 0)} → {formatInt(r.newItems)}
            </div>
          </div>
        ) : (
          <span className="text-text-faint">
            {r.prevItems === null ? "first week" : "prev week was 0"}
          </span>
        ),
      sortValue: (r) => r.changePct,
    },
  ];

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-lg font-semibold text-text">Vault trend</h1>
        <p className="mt-1 text-sm text-text-muted">
          Vault growth over time, by creation cohort and mem_type — where the Phase 2 soak gate's "net
          growth rate strictly decreasing week-over-week" gets watched by a human.
        </p>
      </div>

      <div className="rounded-md border border-status-candidate-border bg-status-candidate-bg px-4 py-3 text-xs text-status-candidate-fg">
        This page measures <strong className="font-semibold">gross creation</strong>, not the gate's{" "}
        <strong className="font-semibold">net</strong> active vault. Archive, retire and tombstone
        exits carry no timestamped history in any export, so they cannot be subtracted week by week.
        Treat the week-over-week figure as an upper bound on net growth, and read the gate's own soak
        report for the authoritative number.
      </div>

      {memoryExport.status === "error" ? (
        <ErrorState error={memoryExport.error} onRetry={memoryExport.reload} />
      ) : memoryExport.status === "loading" ? (
        <div role="status" aria-label="Loading vault trend" className="grid grid-cols-2 gap-3 sm:grid-cols-4">
          {Array.from({ length: 4 }, (_, i) => (
            <div key={i} className="h-[70px] animate-pulse rounded-lg border border-border bg-surface" />
          ))}
        </div>
      ) : rows.length === 0 ? (
        <EmptyState
          title="Vault is empty"
          description="No memory_item rows exist for this project yet — expected for a young project, and there is nothing to trend until items are written."
        />
      ) : (
        <>
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
            <StatTile
              label="Items ever created"
              value={formatInt(rows.length)}
              sublabel="every exported memory_item row, all statuses"
            />
            <StatTile
              label="Currently retrievable"
              value={formatInt(retrievableCount)}
              sublabel={
                rows.length > 0
                  ? `${formatPercent(retrievableCount / rows.length)} of created — validated, candidate or pinned`
                  : undefined
              }
            />
            <StatTile
              label="Merged (via memory_link)"
              value="Not observable"
              sublabel="memory_link has no export table and no route — see Contract gaps"
            />
            <StatTile
              label="Latest week vs previous"
              value={
                latestWeek !== undefined && latestWeek.changePct !== null
                  ? formatPercent(latestWeek.changePct)
                  : "—"
              }
              sublabel={
                latestWeek === undefined
                  ? undefined
                  : latestWeek.changePct !== null
                    ? `${formatInt(latestWeek.prevItems ?? 0)} → ${formatInt(latestWeek.newItems)} new items · ${latestWeek.weekLabel}`
                    : `${formatInt(latestWeek.newItems)} new items this week; no comparable previous week`
              }
            />
          </div>

          {trend !== null ? (
            <p
              className={
                "text-xs " +
                (trend.strictlyDecreasing ? "text-status-validated-fg" : "text-text-muted")
              }
            >
              {trend.strictlyDecreasing
                ? `Gross creation is strictly decreasing across the last ${formatInt(trend.weeks)} weeks. That is the direction the Phase 2 soak gate wants — but the gate reads NET growth, which this page cannot compute.`
                : `Gross creation is not strictly decreasing across the last ${formatInt(trend.weeks)} weeks.`}
            </p>
          ) : (
            <p className="text-xs text-text-muted">
              Fewer than {formatInt(MIN_WEEKS_FOR_TREND)} weeks of creation history — too little to
              call a trend in either direction.
            </p>
          )}

          {memoryExport.truncated && (
            <p className="text-xs text-status-quarantined-fg">
              This trend hit its {formatInt(EXPORT_ROW_CAP)}-row export cap before finishing. Which
              rows were dropped is not controllable from the client, so every count here is a lower
              bound and the week-over-week figure may be computed on an incomplete week (see Contract
              gaps).
            </p>
          )}

          {chartDays.length > 1 && (
            <div className="grid gap-4 lg:grid-cols-2">
              <div className="rounded-lg border border-border bg-surface p-4">
                <h3 className="text-xs font-semibold uppercase tracking-wide text-text-muted">
                  Cumulative items created
                </h3>
                <p className="mt-0.5 text-xs text-text-faint">
                  {chartRangeLabel} · includes everything created before this window, so the left edge
                  is not a reset to zero.
                </p>
                <div className="mt-2">
                  <Chart
                    ariaLabel="Line chart of cumulative memory_item count over a continuous calendar axis, by creation date"
                    series={[{ label: "Cumulative created", points: cumulativeSeries }]}
                    xTickFormat={(x) => chartDays[Math.round(x)]?.slice(5) ?? ""}
                    yTickFormat={(y) => formatInt(y)}
                  />
                </div>
              </div>
              <div className="rounded-lg border border-border bg-surface p-4">
                <h3 className="text-xs font-semibold uppercase tracking-wide text-text-muted">
                  New items per UTC day, by mem_type
                </h3>
                <p className="mt-0.5 text-xs text-text-faint">
                  {chartRangeLabel} · days with no creations are plotted as zero.
                </p>
                <div className="mt-2">
                  <Chart
                    ariaLabel="Line chart of new memory items per UTC day on a continuous calendar axis, one line per mem_type: episodic, semantic, lesson, preference"
                    series={memTypeSeries}
                    xTickFormat={(x) => chartDays[Math.round(x)]?.slice(5) ?? ""}
                    yTickFormat={(y) => formatInt(y)}
                  />
                </div>
              </div>
            </div>
          )}

          <section>
            <h2 className="mb-2 text-sm font-semibold text-text">Gross creation by week</h2>
            <p className="mb-2 text-xs text-text-muted">
              Weeks are fixed 7-day UTC windows anchored on this project's first creation date, and
              weeks with zero creations are included — a variable-length bucket would make the
              week-over-week percentage a comparison between different-sized periods.
            </p>
            <Table
              caption="New memory items per fixed seven-day window, cumulative total created, and change against the previous week"
              columns={weekColumns}
              rows={weekRows}
              getRowId={(r) => r.weekStart}
              initialSort={{ key: "week", direction: "desc" }}
              maxHeight="60vh"
            />
          </section>

          <section>
            <h2 className="mb-2 text-sm font-semibold text-text">Current status snapshot</h2>
            <p className="mb-2 text-xs text-text-muted">
              Counts as of now, not as of any point in the trend above — the export carries each row's
              current status only, with no transition history.
            </p>
            <div className="space-y-3 rounded-lg border border-border bg-surface p-4">
              <div>
                <h3 className="mb-1.5 text-xs font-semibold uppercase tracking-wide text-text-muted">
                  Retrievable — can reach an agent's prompt
                </h3>
                <ul className="flex flex-wrap gap-3">
                  {STATUSES.filter((s) => RETRIEVABLE_STATUSES.has(s)).map((status) => (
                    <li key={status} className="inline-flex items-center gap-1.5">
                      <StatusBadge status={status} />
                      <span className="text-xs tabular-nums text-text-muted">
                        {formatInt(statusCounts.get(status) ?? 0)}
                      </span>
                    </li>
                  ))}
                </ul>
              </div>
              <div className="border-t border-border pt-3">
                <h3 className="mb-1.5 text-xs font-semibold uppercase tracking-wide text-text-muted">
                  Not retrievable — never served, whatever the count
                </h3>
                <ul className="flex flex-wrap gap-3">
                  {STATUSES.filter((s) => !RETRIEVABLE_STATUSES.has(s)).map((status) => (
                    <li key={status} className="inline-flex items-center gap-1.5">
                      <StatusBadge status={status} />
                      <span className="text-xs tabular-nums text-text-muted">
                        {formatInt(statusCounts.get(status) ?? 0)}
                      </span>
                    </li>
                  ))}
                </ul>
              </div>
            </div>
          </section>
        </>
      )}
    </div>
  );
}
