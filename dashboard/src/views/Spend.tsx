import { useMemo, useState } from "react";
import { useSpend } from "../api/hooks";
import { Chart } from "../components/Chart";
import { Table, type ColumnDef } from "../components/Table";
import { EmptyState } from "../components/EmptyState";
import { ErrorState } from "../components/ErrorState";
import { formatCostUsd, formatInt } from "../lib/format";
import type { SpendCellOut } from "../api/types";

// The LLM spend ledger, live from GET /admin/spend (D-093).
//
// Three things this view deliberately does NOT do:
//
//  1. It draws no cap gauge. `spend.daily_llm_cap_usd` (PLAN.md §6, default
//     25.0/project/day) resolves from process defaults layered under
//     project_config; only the OVERRIDE layers are readable over HTTP, so on
//     a deployment that never set an override the dashboard cannot know the
//     cap in force. A gauge drawn against the documented default would read as
//     this deployment's configured limit, which is exactly the class of
//     confident-looking wrong number this console must not produce. If a
//     project_config override exists, the Settings view shows it as an
//     override — that is the honest form of the same information.
//
//  2. It does not roll up across projects. PLAN.md §10 exempts spend metering
//     from the cross-project aggregation ban as billing metadata, but that
//     exemption belongs to a billing job; the route the dashboard calls is
//     project-scoped like every other, so there is nothing here to roll up.
//
//  3. It does not name the operational-lane workers as spenders. `invalidator`
//     and `prefix_builder` are LLM-free (PLAN.md §3's two-lane split) — they
//     make no generative call and can never appear in a spend_ledger row, so
//     a spend cap does not pause them and this page never implies it does.

const WINDOW_OPTIONS = [7, 30, 90] as const;
type WindowDays = (typeof WINDOW_OPTIONS)[number];

const DAY_MS = 86_400_000;

function isoDayToUtcMs(day: string): number {
  const [y, m, d] = day.split("-").map(Number);
  if (y === undefined || m === undefined || d === undefined) return Number.NaN;
  if (!Number.isFinite(y) || !Number.isFinite(m) || !Number.isFinite(d)) return Number.NaN;
  return Date.UTC(y, m - 1, d);
}

function utcMsToIsoDay(ms: number): string {
  return new Date(ms).toISOString().slice(0, 10);
}

/** The x-axis is every UTC day in the requested window, INCLUDING days with no
 * spend. Indexing by "days that have a ledger row" would draw a continuous
 * line across a week of silence and imply spend that did not happen. */
function denseWindow(since: string, days: number): string[] {
  const start = isoDayToUtcMs(since);
  if (Number.isNaN(start)) return [];
  return Array.from({ length: days }, (_, i) => utcMsToIsoDay(start + i * DAY_MS));
}

interface WorkerRollup {
  worker: string;
  models: number;
  daysWithSpend: number;
  tokensIn: number;
  tokensOut: number;
  costUsd: number;
}

export default function Spend() {
  const [days, setDays] = useState<WindowDays>(30);
  const query = useSpend(days);

  const cells: SpendCellOut[] = useMemo(() => query.data?.cells ?? [], [query.data]);
  const since = query.data?.since ?? "";
  const windowDays = query.data?.days ?? days;

  const total = useMemo(() => cells.reduce((acc, c) => acc + c.cost_usd, 0), [cells]);

  const byDay = useMemo(() => {
    const map = new Map<string, number>();
    for (const c of cells) map.set(c.day, (map.get(c.day) ?? 0) + c.cost_usd);
    return map;
  }, [cells]);

  const axis = useMemo(() => denseWindow(since, windowDays), [since, windowDays]);
  const series = useMemo(
    () => axis.map((day, i) => ({ x: i, y: byDay.get(day) ?? 0 })),
    [axis, byDay]
  );

  const byWorker = useMemo((): WorkerRollup[] => {
    const map = new Map<string, WorkerRollup & { modelSet: Set<string>; daySet: Set<string> }>();
    for (const c of cells) {
      let entry = map.get(c.worker);
      if (entry === undefined) {
        entry = {
          worker: c.worker,
          models: 0,
          daysWithSpend: 0,
          tokensIn: 0,
          tokensOut: 0,
          costUsd: 0,
          modelSet: new Set(),
          daySet: new Set(),
        };
        map.set(c.worker, entry);
      }
      entry.tokensIn += c.tokens_in;
      entry.tokensOut += c.tokens_out;
      entry.costUsd += c.cost_usd;
      entry.modelSet.add(c.model_id);
      entry.daySet.add(c.day);
    }
    return [...map.values()].map((e) => ({
      worker: e.worker,
      models: e.modelSet.size,
      daysWithSpend: e.daySet.size,
      tokensIn: e.tokensIn,
      tokensOut: e.tokensOut,
      costUsd: e.costUsd,
    }));
  }, [cells]);

  const daysWithSpend = byDay.size;

  const workerColumns: ColumnDef<WorkerRollup>[] = [
    {
      key: "worker",
      header: "Worker",
      width: "24ch",
      render: (row) => <span className="font-medium text-text">{row.worker}</span>,
      sortValue: (row) => row.worker,
    },
    {
      key: "cost",
      header: "Cost",
      numeric: true,
      width: "14ch",
      render: (row) => formatCostUsd(row.costUsd),
      sortValue: (row) => row.costUsd,
    },
    {
      key: "days",
      header: "Days with spend",
      numeric: true,
      width: "18ch",
      // The denominator matters: $10 on one day and $10 across thirty are
      // different operational pictures that a bare total collapses.
      render: (row) => `${formatInt(row.daysWithSpend)} / ${formatInt(windowDays)}`,
      sortValue: (row) => row.daysWithSpend,
    },
    {
      key: "models",
      header: "Models",
      numeric: true,
      width: "11ch",
      render: (row) => formatInt(row.models),
      sortValue: (row) => row.models,
    },
    {
      key: "tokens_in",
      header: "Tokens in",
      numeric: true,
      width: "14ch",
      render: (row) => formatInt(row.tokensIn),
      sortValue: (row) => row.tokensIn,
    },
    {
      key: "tokens_out",
      header: "Tokens out",
      numeric: true,
      width: "14ch",
      render: (row) => formatInt(row.tokensOut),
      sortValue: (row) => row.tokensOut,
    },
  ];

  const cellColumns: ColumnDef<SpendCellOut>[] = [
    {
      key: "day",
      header: "Day (UTC)",
      width: "14ch",
      render: (row) => <span className="tabular-nums">{row.day}</span>,
      sortValue: (row) => row.day,
    },
    {
      key: "worker",
      header: "Worker",
      width: "20ch",
      render: (row) => row.worker,
      sortValue: (row) => row.worker,
    },
    {
      key: "model_id",
      header: "Model",
      width: "22ch",
      render: (row) => <span className="font-mono text-xs">{row.model_id}</span>,
      sortValue: (row) => row.model_id,
    },
    {
      key: "tokens_in",
      header: "Tokens in",
      numeric: true,
      width: "13ch",
      render: (row) => formatInt(row.tokens_in),
      sortValue: (row) => row.tokens_in,
    },
    {
      key: "tokens_out",
      header: "Tokens out",
      numeric: true,
      width: "13ch",
      render: (row) => formatInt(row.tokens_out),
      sortValue: (row) => row.tokens_out,
    },
    {
      key: "cost",
      header: "Cost",
      numeric: true,
      width: "13ch",
      render: (row) => formatCostUsd(row.cost_usd),
      sortValue: (row) => row.cost_usd,
    },
  ];

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="text-lg font-semibold text-text">Spend</h1>
          <p className="mt-1 max-w-3xl text-sm text-text-muted">
            Generative-model cost booked against this project, live from{" "}
            <code className="font-mono text-xs">GET /admin/spend</code>. Only quality-lane workers
            appear here: the operational lane is LLM-free and never writes a ledger row.
          </p>
        </div>
        <fieldset className="flex items-center gap-1.5">
          <legend className="sr-only">Spend window</legend>
          {WINDOW_OPTIONS.map((d) => (
            <button
              key={d}
              type="button"
              onClick={() => setDays(d)}
              aria-pressed={days === d}
              className={
                "rounded-md border px-2.5 py-1 text-xs font-medium transition-colors " +
                (days === d
                  ? "border-accent bg-accent/10 text-accent"
                  : "border-border-strong text-text-muted hover:text-text")
              }
            >
              {days === d && <span aria-hidden="true">✓ </span>}
              {d}d
            </button>
          ))}
        </fieldset>
      </div>

      {query.status === "error" ? (
        <ErrorState error={query.error} onRetry={query.reload} />
      ) : query.status === "loading" ? (
        <div
          role="status"
          aria-label="Loading spend ledger"
          className="h-40 animate-pulse rounded-lg border border-border bg-surface"
        />
      ) : cells.length === 0 ? (
        <EmptyState
          title="No LLM spend recorded in this window"
          description={`spend_ledger has no rows on or after ${since || "the window start"}. That is the expected state for a project whose distiller, contribution judge, shadow validator and consolidator have not run — every one of those is a quality-lane worker, and the quality lane only exists where a feedback adapter does.`}
        />
      ) : (
        <>
          <div className="grid gap-3 sm:grid-cols-3">
            <div className="rounded-lg border border-border bg-surface px-4 py-3">
              <p className="text-xs font-medium uppercase tracking-wide text-text-muted">
                Total cost
              </p>
              <p className="mt-1 text-2xl font-semibold tabular-nums text-text">
                {formatCostUsd(total)}
              </p>
              <p className="mt-0.5 text-xs text-text-faint">
                {formatInt(windowDays)} UTC days from {since}
              </p>
            </div>
            <div className="rounded-lg border border-border bg-surface px-4 py-3">
              <p className="text-xs font-medium uppercase tracking-wide text-text-muted">
                Days with spend
              </p>
              <p className="mt-1 text-2xl font-semibold tabular-nums text-text">
                {formatInt(daysWithSpend)} / {formatInt(windowDays)}
              </p>
              <p className="mt-0.5 text-xs text-text-faint">
                mean over days that spent:{" "}
                {daysWithSpend > 0 ? formatCostUsd(total / daysWithSpend) : "—"}
              </p>
            </div>
            <div className="rounded-lg border border-border bg-surface px-4 py-3">
              <p className="text-xs font-medium uppercase tracking-wide text-text-muted">
                Workers billing
              </p>
              <p className="mt-1 text-2xl font-semibold tabular-nums text-text">
                {formatInt(byWorker.length)}
              </p>
              <p className="mt-0.5 text-xs text-text-faint">
                {formatInt(cells.length)} ledger cell(s) in window
              </p>
            </div>
          </div>

          <section className="rounded-lg border border-border bg-surface p-4">
            <h2 className="text-sm font-semibold text-text">Cost per UTC day</h2>
            <p className="mt-0.5 text-xs text-text-muted">
              Every day in the window is plotted, including days with no spend — a gap in
              generative work reads as a gap, not as a straight line between two busy days.
            </p>
            <div className="mt-3">
              <Chart
                ariaLabel={`Line chart of daily generative spend in US dollars across ${windowDays} UTC days beginning ${since}`}
                series={[{ label: "Cost (USD)", points: series }]}
                xTickFormat={(x) => axis[Math.round(x)]?.slice(5) ?? ""}
                yTickFormat={(y) => formatCostUsd(y)}
              />
            </div>
          </section>

          <section>
            <h2 className="mb-2 text-sm font-semibold text-text">By worker</h2>
            <Table
              caption="Generative spend rolled up per worker for the selected window, with the number of days each worker actually billed on"
              columns={workerColumns}
              rows={byWorker}
              getRowId={(row) => row.worker}
              initialSort={{ key: "cost", direction: "desc" }}
            />
          </section>

          <section>
            <h2 className="mb-2 text-sm font-semibold text-text">Ledger cells</h2>
            <p className="mb-2 text-xs text-text-muted">
              One row per (day, worker, model) cell — the ledger&rsquo;s own primary key.
            </p>
            <Table
              caption="Individual spend_ledger cells for the selected window"
              columns={cellColumns}
              rows={cells}
              getRowId={(row) => `${row.day}:${row.worker}:${row.model_id}`}
              density="compact"
              initialSort={{ key: "day", direction: "desc" }}
              maxHeight="360px"
            />
          </section>

          <p className="text-xs text-text-muted">
            <strong className="font-semibold text-text">No cap gauge is drawn.</strong>{" "}
            <code className="font-mono">spend.daily_llm_cap_usd</code> resolves from process
            defaults that no route exposes; only the project/agent-type override layers are
            readable (see Settings). Drawing a gauge against PLAN.md&rsquo;s documented default
            would report a number nobody configured as this deployment&rsquo;s limit. When the cap
            does bind, it pauses the generative workers named above and alerts — the hot path is
            unaffected, because invariant 1 forbids a generative client on it at all.
          </p>
        </>
      )}
    </div>
  );
}
