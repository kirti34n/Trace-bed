import { useMemo, useState } from "react";
import { useExportRows } from "../api/hooks";
import { EmptyState } from "../components/EmptyState";
import { ErrorState } from "../components/ErrorState";
import { ConfirmDialog } from "../components/ConfirmDialog";
import { StatusBadge, TrustTierBadge } from "../components/StatusBadge";
import type {
  ExportRow,
  InjectionLogExportRow,
  MemoryItemExportRow,
  OutcomeEventExportRow,
  TraceIndexExportRow,
} from "../api/types";
import { formatDateTime, formatFloat, formatInt, formatRelativeTime, truncateId } from "../lib/format";

// Recall & Rollback (PLAN.md §8 improvement 1) — the headline differentiator,
// and the view with the widest contract gap: memory_link is not exposed at all
// (no table, no route), and PLAN.md §3 names `POST
// /admin/memory/{id}/quarantine` as an admin route, but src/tracebed/api/
// admin.py does not implement it.
//
// "Every run it touched" and "every outcome on those runs" are REAL —
// injection_log and outcome_event both exist in GET /export/project and are
// joined here by run_id/memory_id. Two things this view will NOT do with them:
//
//  1. Present them as totals. They come off a capped, unpaginated NDJSON dump
//     of the whole project, so when the cap binds every figure is a floor and
//     says so — including inside the confirmation dialog, since an operator
//     sizes an incident from exactly these numbers.
//  2. Fill the memory_link gap with a plausible descendant chain. This panel is
//     where someone decides how far a poisoned memory spread; an invented
//     chain rendered beside a real run list is read as a real one, so the gap
//     is displayed as a gap.

const MAX_ROWS = 4000;

// Concrete per-table narrowing functions rather than one generic helper:
// `Extract<ExportRow, { table: T }>` with an unresolved generic `T` produces
// two structurally-incompatible instantiations under this TS version
// (TS2719) — a plain literal comparison narrows the discriminated union
// correctly and needs no cast at all.
function memoryItemRows(all: ExportRow[]): MemoryItemExportRow[] {
  const out: MemoryItemExportRow[] = [];
  for (const entry of all) {
    if (entry.table === "memory_item") out.push(entry.row);
  }
  return out;
}
function injectionLogRowsOf(all: ExportRow[]): InjectionLogExportRow[] {
  const out: InjectionLogExportRow[] = [];
  for (const entry of all) {
    if (entry.table === "injection_log") out.push(entry.row);
  }
  return out;
}
function traceIndexRowsOf(all: ExportRow[]): TraceIndexExportRow[] {
  const out: TraceIndexExportRow[] = [];
  for (const entry of all) {
    if (entry.table === "trace_index") out.push(entry.row);
  }
  return out;
}
function outcomeEventRowsOf(all: ExportRow[]): OutcomeEventExportRow[] {
  const out: OutcomeEventExportRow[] = [];
  for (const entry of all) {
    if (entry.table === "outcome_event") out.push(entry.row);
  }
  return out;
}

/** A blast-radius figure computed over a capped export snapshot is a FLOOR,
 * not a total. Rendering "12" when the truth may be 900 is the specific way a
 * forensics report misleads: the operator sizes the incident from it. When the
 * cap bound, every count here renders "≥ N" and says why. */
function StatTile({
  label,
  value,
  bounded,
  note,
}: {
  label: string;
  value: number;
  bounded: boolean;
  note: string;
}) {
  return (
    <div className="rounded-lg border border-border bg-surface px-4 py-3">
      <div className="flex items-center justify-between gap-2">
        <p className="text-xs font-medium uppercase tracking-wide text-text-muted">{label}</p>
        {bounded && (
          <span className="rounded bg-status-quarantined-bg px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-status-quarantined-fg">
            floor
          </span>
        )}
      </div>
      <p className="mt-1 text-2xl font-semibold tabular-nums text-text">
        {bounded ? "≥ " : ""}
        {formatInt(value)}
      </p>
      <p className="mt-1 text-[11px] leading-snug text-text-muted">{note}</p>
    </div>
  );
}

export default function Forensics() {
  const enrichment = useExportRows(
    ["memory_item", "injection_log", "trace_index", "outcome_event"],
    MAX_ROWS
  );
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [acknowledged, setAcknowledged] = useState(false);

  const memories = useMemo(() => memoryItemRows(enrichment.rows), [enrichment.rows]);
  const MAX_MATCHES = 8;
  const allMatches = useMemo(() => {
    const term = search.trim().toLowerCase();
    if (term.length === 0) return [];
    return memories.filter((m) => m.content.toLowerCase().includes(term) || m.id.includes(term));
  }, [memories, search]);
  const matches = useMemo(() => allMatches.slice(0, MAX_MATCHES), [allMatches]);

  const selected = useMemo(() => memories.find((m) => m.id === selectedId) ?? null, [memories, selectedId]);

  const directRuns = useMemo((): InjectionLogExportRow[] => {
    if (selectedId === null) return [];
    return injectionLogRowsOf(enrichment.rows).filter((r) => r.memory_id === selectedId);
  }, [enrichment.rows, selectedId]);

  const runIds = useMemo(() => new Set(directRuns.map((r) => r.run_id)), [directRuns]);

  const matchedTraces = useMemo((): TraceIndexExportRow[] => {
    if (runIds.size === 0) return [];
    return traceIndexRowsOf(enrichment.rows).filter((r) => runIds.has(r.run_id));
  }, [enrichment.rows, runIds]);

  const matchedOutcomes = useMemo((): OutcomeEventExportRow[] => {
    if (runIds.size === 0) return [];
    return outcomeEventRowsOf(enrichment.rows).filter((r) => runIds.has(r.run_id));
  }, [enrichment.rows, runIds]);

  const outcomeStatusByRun = useMemo(() => {
    const map = new Map<string, TraceIndexExportRow>();
    for (const t of matchedTraces) map.set(t.run_id, t);
    return map;
  }, [matchedTraces]);

  // Runs whose injection_log row is in the snapshot but whose trace_index row
  // is not: the two counts are not interchangeable and the difference is a
  // visibility gap, not a data-quality signal about the project.
  const unresolvedTraceRuns = runIds.size - matchedTraces.length;
  const bounded = enrichment.truncated;

  if (enrichment.status === "error") {
    return <ErrorState error={enrichment.error} onRetry={enrichment.reload} title="Couldn't load forensics data" />;
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-lg font-semibold text-text">Forensics — Recall &amp; Rollback</h1>
        <p className="mt-1 text-sm text-text-muted">
          Pick a memory to see its blast radius: every run it touched, every affected outcome, and —
          once a poisoned memory reached <code className="font-mono">validated</code> — how far the
          damage could reach.
        </p>
      </div>

      <div className="space-y-2">
        <div className="rounded-md border border-status-candidate-border/60 bg-status-candidate-bg/40 px-3 py-2 text-xs text-status-candidate-fg">
          Runs touched and outcomes below are real — <code className="font-mono">injection_log</code> and{" "}
          <code className="font-mono">outcome_event</code> rows from{" "}
          <code className="font-mono">GET /export/project</code>, joined by{" "}
          <code className="font-mono">run_id</code>. Derived descendants cannot be computed at all:{" "}
          <code className="font-mono">memory_link</code> has no export table and no route (PLAN.md §8
          improvement 1 has zero API surface). The quarantine action below cannot be sent: PLAN.md §3
          names <code className="font-mono">POST /admin/memory/{"{id}"}/quarantine</code> but{" "}
          <code className="font-mono">admin.py</code> does not implement it.
        </div>
        {bounded && (
          <div
            role="status"
            className="rounded-md border border-status-quarantined-border/60 bg-status-quarantined-bg/40 px-3 py-2 text-xs text-status-quarantined-fg"
          >
            <strong>The export snapshot hit its {MAX_ROWS.toLocaleString()}-row cap.</strong>{" "}
            <code className="font-mono">GET /export/project</code> streams every table for the whole
            project with no filter or pagination, so this page sees only the prefix of that stream.
            Every blast-radius figure below is therefore a <strong>lower bound</strong> — size an
            incident from it only as a minimum, never as a total.
          </div>
        )}
      </div>

      <div className="rounded-lg border border-border bg-surface p-4">
        <label className="block space-y-1">
          <span className="text-xs font-semibold uppercase tracking-wide text-text-muted">
            Find a memory (searches this export snapshot by content or id)
          </span>
          <input
            type="search"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="e.g. “circuit-break” or a memory id…"
            className="w-full max-w-lg rounded-md border border-border-strong bg-bg px-3 py-1.5 text-sm text-text placeholder:text-text-faint"
          />
        </label>
        {search.trim().length > 0 && allMatches.length === 0 && enrichment.status === "success" && (
          <p role="status" className="mt-2 text-xs text-text-muted">
            No memory in this snapshot matches “{search.trim()}”. There is no server-side search
            endpoint, so this only searched the {memories.length.toLocaleString()} memory_item rows the
            export cap let through.
          </p>
        )}
        {allMatches.length > matches.length && (
          <p className="mt-2 text-xs text-text-muted">
            Showing the first {matches.length} of {allMatches.length} matches — narrow the term to see
            the rest.
          </p>
        )}
        {matches.length > 0 && (
          <ul className="mt-2 max-w-lg divide-y divide-border rounded-md border border-border">
            {matches.map((m) => (
              <li key={m.id}>
                <button
                  type="button"
                  onClick={() => {
                    setSelectedId(m.id);
                    setSearch("");
                    setAcknowledged(false);
                  }}
                  className="flex w-full items-center gap-2 px-3 py-2 text-left text-sm hover:bg-surface-raised"
                >
                  <StatusBadge status={m.status} />
                  <TrustTierBadge tier={m.trust_tier} />
                  <span className="line-clamp-1 flex-1 text-text">{m.content}</span>
                </button>
              </li>
            ))}
          </ul>
        )}
      </div>

      {selected === null ? (
        enrichment.status === "loading" ? (
          <div className="h-40 animate-pulse rounded-lg bg-border" />
        ) : (
          <EmptyState
            title="Pick a memory to inspect its blast radius"
            description="Search above by content or id — results come from this project's export snapshot."
          />
        )
      ) : (
        <>
          <div className="rounded-lg border border-border bg-surface p-4">
            <div className="flex flex-wrap items-center gap-2">
              <StatusBadge status={selected.status} />
              <TrustTierBadge tier={selected.trust_tier} />
              <span className="font-mono text-xs text-text-faint" title={selected.id}>
                {truncateId(selected.id)}
              </span>
              <span className="text-xs text-text-faint">
                Q {formatFloat(selected.q_value)}{" "}
                {selected.scored_use_count === 0 ? "(unscored — q_start seed)" : `(n=${selected.scored_use_count})`}
              </span>
            </div>
            {/* The memory under forensic review is, by hypothesis, the suspect
                one. Its text is quoted, never presented as a statement. */}
            <div
              className={
                "mt-2 max-w-2xl rounded-md border p-3 " +
                (selected.status === "quarantined"
                  ? "border-dashed border-status-quarantined-border bg-status-quarantined-bg/40"
                  : "border-border bg-bg")
              }
            >
              <p className="text-[10px] font-semibold uppercase tracking-wide text-text-muted">
                Memory content under review — quoted, not asserted
              </p>
              <p className="mt-1 font-mono text-sm text-text">{selected.content}</p>
            </div>
          </div>

          <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
            <StatTile
              label="Runs touched"
              value={runIds.size}
              bounded={bounded}
              note="Distinct run_ids with an injection_log row naming this memory."
            />
            <StatTile
              label="Traces resolved"
              value={matchedTraces.length}
              bounded={bounded}
              note={
                unresolvedTraceRuns > 0
                  ? `${unresolvedTraceRuns} touched run${unresolvedTraceRuns === 1 ? "" : "s"} had no trace_index row in this snapshot.`
                  : "Every touched run resolved to a trace_index row."
              }
            />
            <StatTile
              label="Outcomes on touched runs"
              value={matchedOutcomes.length}
              bounded={bounded}
              note="Co-occurrence, not attribution — these runs also carried other memories and the run's own reasoning."
            />
            <div className="rounded-lg border border-dashed border-border-strong bg-surface px-4 py-3">
              <p className="text-xs font-medium uppercase tracking-wide text-text-muted">
                Derived descendants
              </p>
              <p className="mt-1 text-2xl font-semibold text-text-faint">unknown</p>
              <p className="mt-1 text-[11px] leading-snug text-text-muted">
                memory_link has no route and no export table — the derived-descendant hop is not
                computable from any data this dashboard can reach.
              </p>
            </div>
          </div>

          <section className="rounded-lg border border-border bg-surface p-4">
            <h2 className="text-sm font-semibold text-text">Runs touched</h2>
            <p className="mt-0.5 text-xs text-text-muted">
              Every injection_log row naming this memory_id, cross-referenced against trace_index for
              outcome_status.
            </p>
            {directRuns.length === 0 ? (
              <div className="mt-3">
                <EmptyState
                  bordered={false}
                  title={bounded ? "No injections found within the snapshot cap" : "Never injected into a run"}
                  description={
                    bounded
                      ? "The export cap was reached before the stream ended, so absence here is not evidence of absence — this memory may have been injected into runs beyond the cap."
                      : "A real fact — this memory has no injection_log rows in the complete export snapshot."
                  }
                />
              </div>
            ) : (
              <ul className="mt-3 space-y-1.5 text-xs">
                {directRuns.map((r) => {
                  const trace = outcomeStatusByRun.get(r.run_id);
                  return (
                    <li key={`${r.run_id}-${r.slot}`} className="flex flex-wrap items-center gap-3 rounded border border-border px-2.5 py-1.5">
                      <span className="font-mono text-text" title={r.run_id}>
                        {truncateId(r.run_id, 6, 3)}
                      </span>
                      <span className="text-text-muted">{r.slot}</span>
                      <span className="tabular-nums text-text-muted">score {formatFloat(r.score)}</span>
                      <span className="tabular-nums text-text-muted">{r.tokens} tok</span>
                      {trace !== undefined && (
                        <span className="text-text-muted">{trace.outcome_status}</span>
                      )}
                      <span className="text-text-faint" title={formatDateTime(r.injected_at)}>
                        {formatRelativeTime(r.injected_at)}
                      </span>
                    </li>
                  );
                })}
              </ul>
            )}
          </section>

          <section className="rounded-lg border border-border bg-surface p-4">
            <h2 className="text-sm font-semibold text-text">Outcomes on touched runs</h2>
            <p className="mt-0.5 text-xs text-text-muted">
              outcome_event rows on the same run_ids — every downstream signal this memory{" "}
              <em>could</em> have influenced. Nothing here establishes that it did: a run carries other
              memories, a static prefix, and its own reasoning, and Tracebed attributes contribution
              only through the scorer&apos;s judge, not through co-occurrence.
            </p>
            {matchedOutcomes.length === 0 ? (
              <div className="mt-3">
                <EmptyState bordered={false} title="No outcomes recorded yet on touched runs" />
              </div>
            ) : (
              <ul className="mt-3 grid gap-1.5 text-xs sm:grid-cols-2">
                {matchedOutcomes.map((o) => (
                  <li key={o.event_id} className="flex items-center justify-between gap-2 rounded border border-border px-2.5 py-1.5">
                    <span className="text-text-muted">{o.adapter}</span>
                    <span className="tabular-nums text-text">r={formatFloat(o.r)}</span>
                    <span className="text-text-faint" title={formatDateTime(o.occurred_at)}>
                      {formatRelativeTime(o.occurred_at)}
                    </span>
                  </li>
                ))}
              </ul>
            )}
          </section>

          <section className="rounded-lg border border-dashed border-border-strong bg-surface p-4">
            <h2 className="text-sm font-semibold text-text">Derived descendants — not computable</h2>
            <p className="mt-2 max-w-2xl text-xs leading-relaxed text-text-muted">
              PLAN.md §8&apos;s Recall &amp; Rollback flags derived descendants through{" "}
              <code className="font-mono">memory_link</code>. That table is defined in PLAN.md §5 but has
              no API surface whatsoever: no route reads it, and it is not one of{" "}
              <code className="font-mono">GET /export/project</code>&apos;s five tables (memory_item,
              trace_index, outcome_event, injection_log, retrieval_event). Consolidation and
              supersession descendants are therefore <strong>unknown</strong>, and no stand-in chain is
              drawn here — an invented descendant list beside a real run list would be read as a real
              one, and this panel is exactly where an operator decides how far a poisoned memory
              spread.
            </p>
          </section>

          <section className="rounded-lg border border-status-quarantined-border/60 bg-status-quarantined-bg/20 p-4">
            <h2 className="text-sm font-semibold text-text">Now what</h2>
            <p className="mt-1 max-w-2xl text-sm text-text-muted">
              Quarantining this memory would re-open every run and outcome above for re-evaluation.
              {bounded
                ? " The figures it would act on are lower bounds, because the export snapshot hit its cap — the real blast radius is at least this large."
                : ""}{" "}
              That action has no route to call — see the banner above.
            </p>
            <button
              type="button"
              onClick={() => setConfirmOpen(true)}
              className="mt-3 rounded-md bg-danger px-3 py-1.5 text-sm font-medium text-danger-contrast hover:opacity-90"
            >
              Quarantine &amp; reopen blast radius
            </button>
            {acknowledged && (
              <p role="status" className="mt-2 text-xs text-text-faint">
                Acknowledged — nothing was sent. No <code className="font-mono">POST /admin/memory/{"{id}"}/quarantine</code>{" "}
                route exists to call.
              </p>
            )}
          </section>

          <ConfirmDialog
            open={confirmOpen}
            title="Quarantine this memory and reopen its blast radius"
            description="This would transition the memory to quarantined and flag every run and outcome below for re-evaluation. No route exists for this action — confirming will not change any server state."
            tone="danger"
            impact={[
              { label: "Runs touched", value: bounded ? `≥ ${runIds.size}` : runIds.size },
              {
                label: "Outcomes on touched runs",
                value: bounded ? `≥ ${matchedOutcomes.length}` : matchedOutcomes.length,
              },
              { label: "Derived descendants", value: "unknown — memory_link has no route" },
              ...(bounded
                ? [
                    {
                      label: "Figures complete?",
                      value: "No — export cap reached; these are lower bounds",
                    },
                  ]
                : []),
              { label: "Persisted to server?", value: "No — no quarantine route exists" },
            ]}
            confirmLabel="Acknowledge (not sent)"
            onConfirm={() => {
              setConfirmOpen(false);
              setAcknowledged(true);
            }}
            onCancel={() => setConfirmOpen(false)}
          />
        </>
      )}
    </div>
  );
}
