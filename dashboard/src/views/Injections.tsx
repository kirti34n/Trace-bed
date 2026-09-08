import { useEffect, useState } from "react";
import { useInjections, useMemoryItem } from "../api/hooks";
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
  type InjectionEntryOut,
  type Slot,
} from "../api/types";

// "What was injected into which run, in which slot, at what score, costing how
// many tokens. Drill from an injection to the memory, and from the memory to
// its provenance traces. This is the view that makes memory auditable" (task
// brief). Every step of that drill uses a route that actually exists:
//   injection_log rows      -> GET /admin/injections (paged server feed)
//   injection -> memory     -> GET /admin/memory/{id} (the only by-id read)
// The API has no trace-index drilldown route, so provenance trace ids are
// disclosed as identifiers rather than reconstructed from a project export.
//
// The one thing this view must not imply: that the memory panel describes the
// memory AS IT WAS when it was injected. `GET /admin/memory/{id}` returns
// current state, and there is no as-of read. A memory injected into 400 runs
// last month and quarantined this morning would otherwise render as an
// unremarkable row — which is exactly the case an operator opens this view to
// find. It is called out in the panel, prominently, whenever the memory's
// current status is one the hot path would no longer serve.

const PAGE_SIZE = 100;

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

function MemoryDetailPanel({ injection }: { injection: InjectionEntryOut }) {
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
          <h3 className="text-xs font-semibold uppercase tracking-wide text-text-muted">Provenance — {memory.provenance.class}</h3>
          <p className="mt-1 text-xs text-text-faint">This paginated feed has no trace-index join. The API reports {memory.provenance.trace_ids?.length ?? 0} provenance trace id(s); it does not provide an as-of trace drilldown.</p>
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
  const [offset, setOffset] = useState(0);
  const injectionPage = useInjections(PAGE_SIZE, offset);
  const [selected, setSelected] = useState<InjectionEntryOut | null>(null);
  const injectionRows = injectionPage.data?.items ?? [];
  useEffect(() => setSelected(null), [offset]);

  const totalTokens = injectionRows.reduce((sum, r) => sum + r.tokens, 0);
  const scores = injectionRows.map((r) => r.score);
  const medianScore = median(scores);
  const distinctRuns = new Set(injectionRows.map((r) => r.run_id)).size;
  const distinctMemories = new Set(injectionRows.map((r) => r.memory_id)).size;

  const columns: ColumnDef<InjectionEntryOut>[] = [
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

      {injectionPage.status === "error" ? (
        <ErrorState error={injectionPage.error} onRetry={injectionPage.reload} />
      ) : injectionPage.status === "loading" ? (
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
              sublabel={`page starting at ${formatInt(offset + 1)}`}
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
              getRowId={(row) => `${row.run_id}:${row.memory_id}:${row.slot}:${row.injected_at}`}
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
                  key={`${selected.run_id}:${selected.memory_id}:${selected.slot}:${selected.injected_at}`}
                  injection={selected}
                />
              )}
            </div>
          </div>
          <nav aria-label="Injection pages" className="flex items-center justify-end gap-3 text-sm">
            <button type="button" disabled={offset === 0} onClick={() => setOffset((current) => Math.max(0, current - PAGE_SIZE))} className="rounded-md border border-border-strong px-3 py-1.5 disabled:opacity-40">Newer</button>
            <span className="text-text-muted">{formatInt(offset + 1)}–{formatInt(offset + injectionRows.length)}</span>
            <button type="button" disabled={injectionPage.data === undefined || injectionPage.data.returned < injectionPage.data.limit} onClick={() => setOffset((current) => current + PAGE_SIZE)} className="rounded-md border border-border-strong px-3 py-1.5 disabled:opacity-40">Older</button>
          </nav>
        </>
      )}
    </div>
  );
}
