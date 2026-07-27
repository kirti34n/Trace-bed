import { useMemo, useState } from "react";
import { useExportRows, useMemoryItem, type QueryStatus } from "../api/hooks";
import { Table, type ColumnDef } from "../components/Table";
import { StatusBadge, TrustTierBadge } from "../components/StatusBadge";
import { EmptyState } from "../components/EmptyState";
import { ErrorState } from "../components/ErrorState";
import {
  formatDateTime,
  formatFloat,
  formatInt,
  formatTokens,
  truncateId,
} from "../lib/format";
import {
  RETRIEVABLE_STATUSES,
  type InjectionLogExportRow,
  type Slot,
  type TraceIndexExportRow,
} from "../api/types";

// "What was injected into which run, in which slot, at what score, costing how
// many tokens. Drill from an injection to the memory, and from the memory to
// its provenance traces. This is the view that makes memory auditable" (task
// brief). Every step of that drill uses a route that actually exists:
//   injection_log rows      -> GET /export/project (filtered client-side)
//   injection -> memory     -> GET /admin/memory/{id} (the only by-id read)
//   memory -> provenance    -> memory_item.provenance.trace_ids, resolved
//                              against trace_index rows from the same export
// No list/filter/paginate route exists for injection_log (contract gap).
//
// The one thing this view must not imply: that the memory panel describes the
// memory AS IT WAS when it was injected. `GET /admin/memory/{id}` returns
// current state, and there is no as-of read. A memory injected into 400 runs
// last month and quarantined this morning would otherwise render as an
// unremarkable row — which is exactly the case an operator opens this view to
// find. It is called out in the panel, prominently, whenever the memory's
// current status is one the hot path would no longer serve.

const EXPORT_ROW_CAP = 8000;

const SLOT_LABEL: Record<Slot, string> = {
  static_prefix: "Static prefix",
  fact: "Fact",
  exemplar: "Exemplar",
  pitfall: "Pitfall",
  candidate_note: "Candidate note",
  jit_lesson: "JIT lesson",
};

function StatTile({ label, value, sublabel }: { label: string; value: string; sublabel?: string }) {
  return (
    <div className="rounded-lg border border-border bg-surface px-4 py-3">
      <p className="text-xs font-medium uppercase tracking-wide text-text-muted">{label}</p>
      <p className="mt-1 text-2xl font-semibold tabular-nums text-text">{value}</p>
      {sublabel !== undefined && <p className="mt-0.5 text-xs text-text-faint">{sublabel}</p>}
    </div>
  );
}

function median(values: readonly number[]): number | null {
  if (values.length === 0) return null;
  const sorted = [...values].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  if (sorted.length % 2 === 1) return sorted[mid] ?? null;
  const lo = sorted[mid - 1];
  const hi = sorted[mid];
  return lo !== undefined && hi !== undefined ? (lo + hi) / 2 : null;
}

function MemoryDetailPanel({
  injection,
  traceRows,
  traceStatus,
  traceTruncated,
}: {
  injection: InjectionLogExportRow;
  traceRows: TraceIndexExportRow[];
  traceStatus: QueryStatus;
  traceTruncated: boolean;
}) {
  const memoryQuery = useMemoryItem(injection.memory_id);

  const header = (
    <div className="border-b border-border pb-3">
      <h2 className="text-sm font-semibold text-text">Selected injection</h2>
      <dl className="mt-1.5 grid grid-cols-2 gap-x-4 gap-y-1 text-xs">
        <div>
          <dt className="text-text-faint">Run</dt>
          <dd className="truncate font-mono text-text" title={injection.run_id}>
            {truncateId(injection.run_id)}
          </dd>
        </div>
        <div>
          <dt className="text-text-faint">Memory</dt>
          <dd className="truncate font-mono text-text" title={injection.memory_id}>
            {truncateId(injection.memory_id)}
          </dd>
        </div>
        <div>
          <dt className="text-text-faint">Slot</dt>
          <dd className="text-text">{SLOT_LABEL[injection.slot]}</dd>
        </div>
        <div>
          <dt className="text-text-faint">Injected at</dt>
          <dd className="text-text">{formatDateTime(injection.injected_at)}</dd>
        </div>
      </dl>
    </div>
  );

  let body: JSX.Element;
  if (memoryQuery.status === "loading" || memoryQuery.status === "idle") {
    body = (
      <div
        role="status"
        aria-label="Loading the injected memory"
        className="h-40 animate-pulse rounded-md border border-border bg-surface-raised"
      />
    );
  } else if (memoryQuery.status === "error") {
    body = (
      <ErrorState
        error={memoryQuery.error}
        onRetry={memoryQuery.reload}
        title="Could not load this memory"
      />
    );
  } else if (memoryQuery.data === undefined) {
    body = (
      <EmptyState
        title="The API returned no body for this memory"
        description="GET /admin/memory/{id} answered successfully but with an empty payload. Nothing about this memory's current state can be shown."
        bordered={false}
      />
    );
  } else {
    const memory = memoryQuery.data;
    const traceIds = memory.provenance.trace_ids ?? [];
    const matchedTraces = traceRows.filter((t) => traceIds.includes(t.run_id));
    const stillServable = RETRIEVABLE_STATUSES.has(memory.status);

    body = (
      <div className="space-y-4">
        {!stillServable && (
          <div
            role="alert"
            className="rounded-md border border-status-quarantined-border bg-status-quarantined-bg px-3 py-2 text-xs text-status-quarantined-fg"
          >
            <strong className="font-semibold">
              This memory was injected into the run above, and its status is now “
              {memory.status}”.
            </strong>{" "}
            The hot path will not serve it again — but the run it was injected into already consumed
            it. Runs that used it before the status change are not retroactively corrected anywhere.
          </div>
        )}
        <div className="flex flex-wrap items-center gap-2">
          <StatusBadge status={memory.status} />
          <TrustTierBadge tier={memory.trust_tier} />
          <span className="text-xs text-text-muted">
            {memory.mem_type} · {memory.kind} · {memory.lane} lane
          </span>
        </div>
        <p className="text-xs text-text-faint">
          Status, Q and confidence below are <strong className="font-semibold">current</strong>, not
          as-of the injection above. No as-of read exists in the API.
        </p>
        <p className="whitespace-pre-wrap text-sm text-text">{memory.content}</p>
        <dl className="grid grid-cols-2 gap-x-4 gap-y-1.5 text-xs sm:grid-cols-4">
          <div>
            <dt className="text-text-faint">Q value</dt>
            <dd className="tabular-nums text-text">
              {formatFloat(memory.q_value)}
              <span className="ml-1 text-text-faint">
                (n={formatInt(memory.scored_use_count)} scored)
              </span>
            </dd>
          </div>
          <div>
            <dt className="text-text-faint">Confidence</dt>
            <dd className="tabular-nums text-text">{formatFloat(memory.confidence)}</dd>
          </div>
          <div>
            <dt className="text-text-faint">Scored uses</dt>
            <dd className="tabular-nums text-text">{formatInt(memory.scored_use_count)}</dd>
          </div>
          <div>
            <dt className="text-text-faint">Strikes</dt>
            <dd className="tabular-nums text-text">{formatInt(memory.strike_count)}</dd>
          </div>
        </dl>
        {memory.scored_use_count === 0 && (
          <p className="text-xs text-text-muted">
            Q is still at its starting value — no unambiguous outcome has scored this memory yet, so
            it carries no evidence in either direction.
          </p>
        )}

        <div>
          <h3 className="text-xs font-semibold uppercase tracking-wide text-text-muted">
            Provenance — {memory.provenance.class}
          </h3>
          {traceIds.length === 0 ? (
            <p className="mt-1 text-xs text-text-faint">
              This memory's provenance carries no trace_ids (expected for provenance classes such as{" "}
              <code className="font-mono">operator</code> or{" "}
              <code className="font-mono">human_verdict</code>, which point at a verdict rather than
              a raw run).
            </p>
          ) : traceStatus === "error" ? (
            <p className="mt-1 text-xs text-status-tombstoned-fg">
              Could not load trace_index rows, so these {traceIds.length} provenance trace id(s)
              could not be resolved. Absence below is a load failure, not evidence the traces are
              missing.
            </p>
          ) : traceStatus === "loading" || traceStatus === "idle" ? (
            <p className="mt-1 text-xs text-text-faint">
              Resolving {traceIds.length} provenance trace(s)…
            </p>
          ) : (
            <>
              <ul className="mt-2 space-y-1.5">
                {matchedTraces.map((t) => (
                  <li
                    key={t.run_id}
                    className="rounded-md border border-border-strong px-2.5 py-1.5 text-xs"
                  >
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <span className="font-mono text-text" title={t.run_id}>
                        {truncateId(t.run_id)}
                      </span>
                      <span className="text-text-muted">{t.outcome_status}</span>
                    </div>
                    <div className="mt-0.5 text-text-faint">
                      {t.instrumentation_source} · arm {t.arm} · started{" "}
                      {t.started_at !== null ? formatDateTime(t.started_at) : "—"}
                    </div>
                  </li>
                ))}
              </ul>
              {matchedTraces.length < traceIds.length && (
                <p className="mt-2 text-xs text-text-muted">
                  {formatInt(traceIds.length - matchedTraces.length)} of{" "}
                  {formatInt(traceIds.length)} provenance trace id(s) were not found among the
                  exported trace_index rows
                  {traceTruncated
                    ? " — the trace export hit its row cap, so this is very likely truncation rather than missing provenance."
                    : ", so they either predate this project's retained trace history or were never indexed."}
                </p>
              )}
            </>
          )}
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-4 rounded-lg border border-border bg-surface p-4">
      {header}
      {body}
    </div>
  );
}

export default function Injections() {
  const injectionExport = useExportRows(["injection_log"], EXPORT_ROW_CAP);
  const traceExport = useExportRows(["trace_index"], EXPORT_ROW_CAP);
  const [selected, setSelected] = useState<InjectionLogExportRow | null>(null);

  const injectionRows = useMemo(
    () =>
      injectionExport.rows.flatMap((r): InjectionLogExportRow[] =>
        r.table === "injection_log" ? [r.row] : []
      ),
    [injectionExport.rows]
  );
  const traceRows = useMemo(
    () =>
      traceExport.rows.flatMap((r): TraceIndexExportRow[] =>
        r.table === "trace_index" ? [r.row] : []
      ),
    [traceExport.rows]
  );

  const totalTokens = injectionRows.reduce((sum, r) => sum + r.tokens, 0);
  const scores = injectionRows.map((r) => r.score);
  const medianScore = median(scores);
  const distinctRuns = new Set(injectionRows.map((r) => r.run_id)).size;
  const distinctMemories = new Set(injectionRows.map((r) => r.memory_id)).size;

  const columns: ColumnDef<InjectionLogExportRow>[] = [
    {
      key: "injected_at",
      header: "Injected (UTC)",
      width: "20ch",
      render: (row) => formatDateTime(row.injected_at),
      sortValue: (row) => row.injected_at,
    },
    {
      key: "run_id",
      header: "Run",
      width: "14ch",
      render: (row) => (
        <span className="font-mono text-xs" title={row.run_id}>
          {truncateId(row.run_id)}
        </span>
      ),
      sortValue: (row) => row.run_id,
    },
    {
      key: "memory_id",
      header: "Memory",
      width: "14ch",
      render: (row) => {
        const isSelected =
          selected !== null &&
          selected.run_id === row.run_id &&
          selected.memory_id === row.memory_id;
        return (
          <span className="inline-flex items-center gap-1.5">
            <span className="font-mono text-xs" title={row.memory_id}>
              {truncateId(row.memory_id)}
            </span>
            {/* Selection is stated in text, not by a background tint alone —
                the detail panel to the right is otherwise unattributable. */}
            {isSelected && (
              <span className="rounded-sm border border-accent px-1 text-[10px] font-semibold uppercase text-accent">
                shown
              </span>
            )}
          </span>
        );
      },
      sortValue: (row) => row.memory_id,
    },
    {
      key: "slot",
      header: "Slot",
      width: "13ch",
      render: (row) => SLOT_LABEL[row.slot],
      sortValue: (row) => row.slot,
    },
    {
      key: "score",
      header: "Score",
      numeric: true,
      width: "8ch",
      render: (row) => formatFloat(row.score, 3),
      sortValue: (row) => row.score,
    },
    {
      key: "tokens",
      header: "Tokens",
      numeric: true,
      width: "9ch",
      render: (row) => formatTokens(row.tokens),
      sortValue: (row) => row.tokens,
    },
  ];

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-lg font-semibold text-text">Injections</h1>
        <p className="mt-1 text-sm text-text-muted">
          Every memory injected into a run, in which slot, at what score, costing how many tokens.
          Select a row to drill into the memory and its provenance traces.
        </p>
      </div>

      {injectionExport.status === "error" ? (
        <ErrorState error={injectionExport.error} onRetry={injectionExport.reload} />
      ) : injectionExport.status === "loading" ? (
        <div role="status" aria-label="Loading injections" className="grid grid-cols-2 gap-3 sm:grid-cols-4">
          {Array.from({ length: 4 }, (_, i) => (
            <div key={i} className="h-[70px] animate-pulse rounded-lg border border-border bg-surface" />
          ))}
        </div>
      ) : injectionRows.length === 0 ? (
        <EmptyState
          title="No injections recorded yet"
          description="No memory has been injected into a run for this project yet — expected until at least one /v1/retrieve call resolves to outcome_code=injected. A young project abstaining on every call is the designed behaviour, not a fault."
        />
      ) : (
        <>
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
            <StatTile
              label="Injections"
              value={formatInt(injectionRows.length)}
              sublabel="all-time, exported"
            />
            <StatTile
              label="Distinct runs"
              value={formatInt(distinctRuns)}
              sublabel={`${formatInt(distinctMemories)} distinct memories`}
            />
            <StatTile
              label="Median score"
              value={medianScore !== null ? formatFloat(medianScore, 3) : "—"}
              sublabel={`n=${formatInt(scores.length)} — median, not mean; scores are not comparable across scoring epochs`}
            />
            <StatTile
              label="Tokens spent"
              value={formatTokens(totalTokens)}
              sublabel={`across ${formatInt(distinctRuns)} run(s)`}
            />
          </div>
          {injectionExport.truncated && (
            <p className="text-xs text-status-quarantined-fg">
              This list hit its {formatInt(EXPORT_ROW_CAP)}-row export cap before finishing — older
              injections may be missing, so every figure above is a lower bound. No paginated or
              filtered injection_log route exists (see Contract gaps).
            </p>
          )}

          <p className="text-xs text-text-muted">
            Score is the assembler's selection score recorded at injection time. It is not a
            probability and is not comparable across scoring epochs, so it ranks within a run rather
            than measuring quality between them.
          </p>

          <div className="grid gap-6 xl:grid-cols-[1fr,420px]">
            <Table
              caption="Memories injected into runs, one row per run and memory pair. Select a row to load that memory and its provenance."
              columns={columns}
              rows={injectionRows}
              getRowId={(row) => `${row.run_id}:${row.memory_id}`}
              onRowClick={setSelected}
              initialSort={{ key: "injected_at", direction: "desc" }}
              maxHeight="70vh"
            />
            <div aria-live="polite">
              {selected === null ? (
                <EmptyState
                  title="No injection selected"
                  description="Select a row — click it, or focus the table and press Enter — to view the injected memory and drill into its provenance traces."
                />
              ) : (
                <MemoryDetailPanel
                  key={`${selected.run_id}:${selected.memory_id}`}
                  injection={selected}
                  traceRows={traceRows}
                  traceStatus={traceExport.status}
                  traceTruncated={traceExport.truncated}
                />
              )}
            </div>
          </div>
        </>
      )}
    </div>
  );
}
