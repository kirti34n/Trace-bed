import { useMemo } from "react";
import { useExportRows } from "../api/hooks";
import { Table, type ColumnDef } from "../components/Table";
import { Chart } from "../components/Chart";
import { EmptyState } from "../components/EmptyState";
import { ErrorState } from "../components/ErrorState";
import { formatInt, formatPercent } from "../lib/format";
import type { OutcomeCode, RetrievalEventExportRow } from "../api/types";

// Abstention rate over time, broken down by reason (task brief). The task
// brief is explicit about the one thing this view must never do: style a
// high abstention rate as a failure. Abstention is the gate correctly
// declining to inject context it isn't confident about — an operator who
// "fixes" a healthy high rate by lowering thresholds has just disabled
// Tracebed's main defence against injecting noise.
//
// THE DEFINITION (this is the part that has to be right, PLAN.md §5:
// retrieval_event "distinguishes abstention (system working) from timeout
// (system failing)"). The eight outcome codes are NOT one population:
//
//   ELIGIBLE (the gate ran and reached a decision) —
//     injected, abstained_threshold, abstained_rarity, empty_result
//   NOT ELIGIBLE —
//     holdout             the arm was withheld deliberately; the gate never ran
//     timeout_prefix_only the system FAILED its 300ms budget
//     store_error         the system FAILED
//     degraded_lexical    retrieval completed on the lexical arm only; the
//                         wire protocol records the degradation INSTEAD of the
//                         gate's decision, so whether it injected is not
//                         recoverable from this row
//
// abstention rate = (threshold + rarity + empty_result) / eligible. Putting
// timeouts, store errors or holdout runs in that ratio would report a failing
// system and a healthy one with the same number — the exact confusion the
// retrieval_event table exists to prevent. Failures and holdout are therefore
// reported in their own panel, with their own (non-green) styling, and are
// never summed into anything called "abstention".
//
// Reason granularity is bounded by what the wire protocol distinguishes
// (domain/enums.py's OutcomeCode): "cold-start" (abstention.rarity_min_corpus_docs
// — a young corpus abstains conservatively) has NO separate wire code, so it
// is indistinguishable from an ordinary rarity abstention. Reported as a
// contract gap rather than fabricated as a fourth series.

const EXPORT_ROW_CAP = 8000;

// Dense calendar axis. Duplicated in Overview/VaultTrend rather than shared:
// a new lib/ file is outside this chunk's file list, and a silently-diverging
// copy is a smaller risk than an out-of-contract file.
const DAY_MS = 86_400_000;
const MAX_CHART_DAYS = 90;

/** Days with no rows at all must occupy real horizontal space, otherwise a
 * three-month silence renders as one pixel of slope and the chart claims a
 * continuity the data does not have. */
function denseDays(firstDay: string, lastDay: string, maxDays: number): string[] {
  const start = isoDayToUtcMs(firstDay);
  const end = isoDayToUtcMs(lastDay);
  if (Number.isNaN(start) || Number.isNaN(end) || end < start) return [];
  const spanDays = Math.floor((end - start) / DAY_MS) + 1;
  const shown = Math.min(spanDays, maxDays);
  const firstShownMs = end - (shown - 1) * DAY_MS;
  return Array.from({ length: shown }, (_, i) => utcMsToIsoDay(firstShownMs + i * DAY_MS));
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

function utcDayBucket(iso: string): string {
  // admin.py's _json_safe emits UTC ISO-8601, so slicing is a UTC day. Every
  // label in this view says "UTC" for exactly that reason — an operator in
  // IST reading an unqualified "day" boundary would be wrong by 5.5 hours.
  return iso.length >= 10 ? iso.slice(0, 10) : iso;
}

/** Wilson score interval — the interval that stays inside [0,1] and stays
 * honest at the small day-level counts this view routinely has. A rate
 * rendered without it is a rate an operator will over-read. */
function wilsonInterval(successes: number, n: number): [number, number] | null {
  if (n <= 0) return null;
  const z = 1.96;
  const p = successes / n;
  const denom = 1 + (z * z) / n;
  const centre = p + (z * z) / (2 * n);
  const margin = z * Math.sqrt((p * (1 - p)) / n + (z * z) / (4 * n * n));
  return [Math.max(0, (centre - margin) / denom), Math.min(1, (centre + margin) / denom)];
}

type Reason = "abstained_threshold" | "abstained_rarity" | "empty_result";
const REASONS: Reason[] = ["abstained_threshold", "abstained_rarity", "empty_result"];
const REASON_META: Record<Reason, { label: string; strokeClass: string; hint: string }> = {
  abstained_threshold: {
    label: "Threshold",
    strokeClass: "stroke-status-candidate-fg",
    hint: "Best candidate scored below the similarity/BM25 threshold, so nothing was injected.",
  },
  abstained_rarity: {
    label: "Rarity (incl. cold-start)",
    strokeClass: "stroke-status-pinned-fg",
    hint: "Rarity gate declined. This also covers young-corpus cold-start abstention — the wire protocol has no separate code for that case.",
  },
  empty_result: {
    label: "Empty result",
    strokeClass: "stroke-status-archived-fg",
    hint: "No candidates existed to score at all — usually an empty or narrowly-scoped vault, not a threshold decision.",
  },
};

type NonEligible = "degraded_lexical" | "timeout_prefix_only" | "store_error" | "holdout";
const NON_ELIGIBLE: NonEligible[] = [
  "degraded_lexical",
  "timeout_prefix_only",
  "store_error",
  "holdout",
];
const NON_ELIGIBLE_META: Record<
  NonEligible,
  { label: string; strokeClass: string; chipClasses: string; hint: string }
> = {
  degraded_lexical: {
    label: "Degraded — lexical only",
    strokeClass: "stroke-status-stale-fg",
    chipClasses: "border-status-stale-border bg-status-stale-bg text-status-stale-fg",
    hint: "The 200ms embedding sub-budget was exceeded and retrieval fell back to BM25 only. The row records the degradation instead of the gate's decision, so these runs are excluded from the abstention ratio in both directions.",
  },
  timeout_prefix_only: {
    label: "Timeout — prefix only",
    strokeClass: "stroke-status-quarantined-fg",
    chipClasses:
      "border-status-quarantined-border bg-status-quarantined-bg text-status-quarantined-fg",
    hint: "The 300ms total budget was exceeded and only the static prefix was served. This is the system FAILING, not abstaining.",
  },
  store_error: {
    label: "Store error",
    strokeClass: "stroke-status-tombstoned-fg",
    chipClasses:
      "border-status-tombstoned-border bg-status-tombstoned-bg text-status-tombstoned-fg",
    hint: "The memory store errored and the run received nothing (fail-open). This is the system FAILING, not abstaining.",
  },
  holdout: {
    label: "Holdout arm",
    strokeClass: "stroke-status-superseded-fg",
    chipClasses:
      "border-status-superseded-border bg-status-superseded-bg text-status-superseded-fg",
    hint: "Sampled into the holdout arm for lift measurement. Memory was withheld on purpose; the gate never ran.",
  },
};

interface DayRow {
  day: string;
  eligible: number;
  injected: number;
  abstained_threshold: number;
  abstained_rarity: number;
  empty_result: number;
  degraded_lexical: number;
  timeout_prefix_only: number;
  store_error: number;
  holdout: number;
}

function emptyDayRow(day: string): DayRow {
  return {
    day,
    eligible: 0,
    injected: 0,
    abstained_threshold: 0,
    abstained_rarity: 0,
    empty_result: 0,
    degraded_lexical: 0,
    timeout_prefix_only: 0,
    store_error: 0,
    holdout: 0,
  };
}

function abstainedOf(row: DayRow): number {
  return row.abstained_threshold + row.abstained_rarity + row.empty_result;
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
  tone?: "neutral" | "attention";
}) {
  return (
    <div
      className={
        "rounded-lg border px-4 py-3 " +
        (tone === "attention"
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

export default function Abstention() {
  const retrievalExport = useExportRows(["retrieval_event"], EXPORT_ROW_CAP);

  const rows = useMemo(
    () =>
      retrievalExport.rows.flatMap((r): RetrievalEventExportRow[] =>
        r.table === "retrieval_event" ? [r.row] : []
      ),
    [retrievalExport.rows]
  );

  const byDay = useMemo(() => {
    const map = new Map<string, DayRow>();
    for (const row of rows) {
      const day = utcDayBucket(row.created_at);
      const existing = map.get(day) ?? emptyDayRow(day);
      const code: OutcomeCode = row.outcome_code;
      if (code === "injected") {
        existing.injected += 1;
        existing.eligible += 1;
      } else if (code === "abstained_threshold") {
        existing.abstained_threshold += 1;
        existing.eligible += 1;
      } else if (code === "abstained_rarity") {
        existing.abstained_rarity += 1;
        existing.eligible += 1;
      } else if (code === "empty_result") {
        existing.empty_result += 1;
        existing.eligible += 1;
      } else {
        existing[code] += 1;
      }
      map.set(day, existing);
    }
    return [...map.values()].sort((a, b) => a.day.localeCompare(b.day));
  }, [rows]);

  const totals = useMemo(() => {
    const t = emptyDayRow("");
    for (const d of byDay) {
      t.eligible += d.eligible;
      t.injected += d.injected;
      t.abstained_threshold += d.abstained_threshold;
      t.abstained_rarity += d.abstained_rarity;
      t.empty_result += d.empty_result;
      t.degraded_lexical += d.degraded_lexical;
      t.timeout_prefix_only += d.timeout_prefix_only;
      t.store_error += d.store_error;
      t.holdout += d.holdout;
    }
    return t;
  }, [byDay]);

  const totalAbstained = abstainedOf(totals);
  const overallRate = totals.eligible > 0 ? totalAbstained / totals.eligible : null;
  const overallCI = wilsonInterval(totalAbstained, totals.eligible);
  const failures = totals.timeout_prefix_only + totals.store_error;

  // A dense, gap-preserving calendar axis, capped at MAX_CHART_DAYS so a
  // multi-year export does not silently become a 2000-point path.
  const chartDays = useMemo(() => {
    const first = byDay[0]?.day;
    const last = byDay[byDay.length - 1]?.day;
    if (first === undefined || last === undefined) return [];
    return denseDays(first, last, MAX_CHART_DAYS);
  }, [byDay]);

  const chartRows = useMemo(() => {
    const index = new Map(byDay.map((d) => [d.day, d]));
    return chartDays.map((day) => index.get(day) ?? emptyDayRow(day));
  }, [byDay, chartDays]);

  const reasonSeries = REASONS.map((reason) => ({
    label: REASON_META[reason].label,
    colorClassName: REASON_META[reason].strokeClass,
    points: chartRows.map((d, i) => ({ x: i, y: d[reason] })),
  }));

  const nonEligibleSeries = NON_ELIGIBLE.map((code) => ({
    label: NON_ELIGIBLE_META[code].label,
    colorClassName: NON_ELIGIBLE_META[code].strokeClass,
    points: chartRows.map((d, i) => ({ x: i, y: d[code] })),
  }));

  const chartRangeLabel =
    chartDays.length > 0 ? `${chartDays[0]} → ${chartDays[chartDays.length - 1]} (UTC)` : "";

  const columns: ColumnDef<DayRow>[] = [
    { key: "day", header: "Day (UTC)", width: "12ch", render: (r) => r.day, sortValue: (r) => r.day },
    {
      key: "eligible",
      header: "Eligible",
      numeric: true,
      width: "10ch",
      render: (r) => formatInt(r.eligible),
      sortValue: (r) => r.eligible,
    },
    {
      key: "injected",
      header: "Injected",
      numeric: true,
      width: "10ch",
      render: (r) => formatInt(r.injected),
      sortValue: (r) => r.injected,
    },
    {
      key: "abstained_threshold",
      header: "Threshold",
      numeric: true,
      width: "11ch",
      render: (r) => formatInt(r.abstained_threshold),
      sortValue: (r) => r.abstained_threshold,
    },
    {
      key: "abstained_rarity",
      header: "Rarity",
      numeric: true,
      width: "9ch",
      render: (r) => formatInt(r.abstained_rarity),
      sortValue: (r) => r.abstained_rarity,
    },
    {
      key: "empty_result",
      header: "Empty",
      numeric: true,
      width: "9ch",
      render: (r) => formatInt(r.empty_result),
      sortValue: (r) => r.empty_result,
    },
    {
      key: "rate",
      header: "Abstention rate (95% CI)",
      numeric: true,
      width: "22ch",
      render: (r) => {
        if (r.eligible === 0) {
          return <span className="text-text-faint">no eligible runs</span>;
        }
        const rate = abstainedOf(r) / r.eligible;
        const ci = wilsonInterval(abstainedOf(r), r.eligible);
        return (
          <div>
            <div>{formatPercent(rate)}</div>
            <div className="text-xs text-text-faint">
              {ci !== null ? `${formatPercent(ci[0])}–${formatPercent(ci[1])}` : "—"} · n=
              {formatInt(r.eligible)}
            </div>
          </div>
        );
      },
      sortValue: (r) => (r.eligible > 0 ? abstainedOf(r) / r.eligible : null),
    },
    {
      key: "degraded_lexical",
      header: "Degraded",
      numeric: true,
      width: "11ch",
      render: (r) => formatInt(r.degraded_lexical),
      sortValue: (r) => r.degraded_lexical,
    },
    {
      key: "failed",
      header: "Failed",
      numeric: true,
      width: "9ch",
      render: (r) => formatInt(r.timeout_prefix_only + r.store_error),
      sortValue: (r) => r.timeout_prefix_only + r.store_error,
    },
    {
      key: "holdout",
      header: "Holdout",
      numeric: true,
      width: "10ch",
      render: (r) => formatInt(r.holdout),
      sortValue: (r) => r.holdout,
    },
  ];

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-lg font-semibold text-text">Abstention</h1>
        <p className="mt-1 text-sm text-text-muted">
          How often the retriever declines to inject, and why — over time, by reason, measured only
          across runs where the abstention gate actually ran.
        </p>
      </div>

      <div className="rounded-md border border-status-validated-border bg-status-validated-bg px-4 py-3 text-sm text-status-validated-fg">
        <p>
          <strong className="font-semibold">A high abstention rate is not, by itself, a problem.</strong>{" "}
          It means the gate is correctly declining to inject context it is not confident about — the
          system's main defence against putting noise into an agent's context. Do not lower{" "}
          <code className="font-mono text-xs">abstention.cos_threshold</code> or the rarity gate to
          make this number smaller; that disables the defence rather than fixing anything.
        </p>
        <p className="mt-2 text-xs">
          Denominator: <strong className="font-semibold">eligible runs only</strong> — injected +
          threshold + rarity + empty_result. Holdout runs, budget timeouts, store errors and
          lexical-degraded runs are excluded, because a failing system and a healthy one must never
          produce the same number here. Those four are counted in their own panel below.
        </p>
      </div>

      {retrievalExport.status === "error" ? (
        <ErrorState error={retrievalExport.error} onRetry={retrievalExport.reload} />
      ) : retrievalExport.status === "loading" ? (
        <div role="status" aria-label="Loading abstention data" className="grid grid-cols-2 gap-3 sm:grid-cols-4">
          {Array.from({ length: 4 }, (_, i) => (
            <div key={i} className="h-[70px] animate-pulse rounded-lg border border-border bg-surface" />
          ))}
        </div>
      ) : rows.length === 0 ? (
        <EmptyState
          title="No retrieval events yet"
          description="Nothing to break down until this project has made at least one /v1/retrieve call. For a project that has just been registered this is the expected state."
        />
      ) : (
        <>
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
            <StatTile
              label="Abstention rate"
              value={overallRate !== null ? formatPercent(overallRate) : "no eligible runs"}
              sublabel={
                overallCI !== null
                  ? `95% CI ${formatPercent(overallCI[0])}–${formatPercent(overallCI[1])} · n=${formatInt(totals.eligible)} eligible`
                  : `n=0 eligible runs of ${formatInt(rows.length)} exported`
              }
            />
            <StatTile
              label="Threshold"
              value={formatInt(totals.abstained_threshold)}
              sublabel={
                totals.eligible > 0
                  ? `${formatPercent(totals.abstained_threshold / totals.eligible)} of eligible`
                  : undefined
              }
            />
            <StatTile
              label="Rarity (incl. cold-start)"
              value={formatInt(totals.abstained_rarity)}
              sublabel={
                totals.eligible > 0
                  ? `${formatPercent(totals.abstained_rarity / totals.eligible)} of eligible`
                  : undefined
              }
            />
            <StatTile
              label="Empty result"
              value={formatInt(totals.empty_result)}
              sublabel={
                totals.eligible > 0
                  ? `${formatPercent(totals.empty_result / totals.eligible)} of eligible`
                  : undefined
              }
            />
          </div>

          {retrievalExport.truncated && (
            <p className="text-xs text-status-quarantined-fg">
              This breakdown hit its {formatInt(EXPORT_ROW_CAP)}-row export cap before finishing — older
              days may be missing, so every count here is a lower bound and the rate is computed over a
              partial window (see Contract gaps).
            </p>
          )}

          <section className="rounded-lg border border-border bg-surface p-4">
            <h2 className="text-sm font-semibold text-text">
              Not counted as abstention: holdout, degradation and failure
            </h2>
            <p className="mt-1 text-xs text-text-muted">
              These four codes are excluded from the ratio above. Timeouts and store errors are the
              system failing its budget; holdout runs were withheld deliberately for lift measurement;
              lexical-degraded runs record the degradation instead of the gate's decision.
            </p>
            <dl className="mt-3 grid gap-2 sm:grid-cols-2">
              {NON_ELIGIBLE.map((code) => {
                const meta = NON_ELIGIBLE_META[code];
                const count = totals[code];
                return (
                  <div
                    key={code}
                    className={`rounded-md border px-3 py-2 ${meta.chipClasses}`}
                  >
                    <div className="flex items-baseline justify-between gap-3">
                      <dt className="text-sm font-medium">{meta.label}</dt>
                      <dd className="shrink-0 text-sm font-semibold tabular-nums">
                        {formatInt(count)}
                      </dd>
                    </div>
                    <p className="mt-0.5 text-xs opacity-90">{meta.hint}</p>
                  </div>
                );
              })}
            </dl>
            {failures > 0 && (
              <p className="mt-3 text-xs font-medium text-status-quarantined-fg">
                {formatInt(failures)} run(s) hit a budget timeout or a store error. Unlike abstention,
                that is the system failing and is worth investigating.
              </p>
            )}
          </section>

          {chartRows.length > 1 && (
            <div className="grid gap-4 lg:grid-cols-2">
              <div className="rounded-lg border border-border bg-surface p-4">
                <h3 className="text-xs font-semibold uppercase tracking-wide text-text-muted">
                  Abstentions per day, by reason
                </h3>
                <p className="mt-0.5 text-xs text-text-faint">{chartRangeLabel}</p>
                <div className="mt-2">
                  <Chart
                    ariaLabel="Line chart of daily abstention counts on a continuous calendar axis, one line per reason: threshold, rarity, empty result"
                    series={reasonSeries}
                    xTickFormat={(x) => chartDays[Math.round(x)]?.slice(5) ?? ""}
                    yTickFormat={(y) => formatInt(y)}
                  />
                </div>
              </div>
              <div className="rounded-lg border border-border bg-surface p-4">
                <h3 className="text-xs font-semibold uppercase tracking-wide text-text-muted">
                  Excluded outcomes per day
                </h3>
                <p className="mt-0.5 text-xs text-text-faint">{chartRangeLabel}</p>
                <div className="mt-2">
                  <Chart
                    ariaLabel="Line chart of daily counts for holdout, lexical-degraded, timeout and store-error runs on a continuous calendar axis"
                    series={nonEligibleSeries}
                    xTickFormat={(x) => chartDays[Math.round(x)]?.slice(5) ?? ""}
                    yTickFormat={(y) => formatInt(y)}
                  />
                </div>
              </div>
            </div>
          )}

          <section>
            <h2 className="mb-2 text-sm font-semibold text-text">Per-day breakdown</h2>
            <p className="mb-2 text-xs text-text-muted">
              Days are UTC calendar days, taken from each row's <code className="font-mono">created_at</code>.
              Every rate carries its Wilson 95% interval and its n — on a young project a single day
              often holds a handful of runs, where a bare percentage would read far more precisely
              than the data supports.
            </p>
            <Table
              caption="Daily retrieval outcome counts, abstention rate with 95% confidence interval, and excluded outcome counts"
              columns={columns}
              rows={byDay}
              getRowId={(r) => r.day}
              initialSort={{ key: "day", direction: "desc" }}
              maxHeight="60vh"
            />
          </section>
        </>
      )}
    </div>
  );
}
