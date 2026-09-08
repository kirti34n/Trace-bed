import { useMemo } from "react";
import { useDemoManifest, useExportRows } from "../api/hooks";
import type { DemoValidationRun, TraceIndexExportRow } from "../api/types";
import { ErrorState } from "../components/ErrorState";
import { EmptyState } from "../components/EmptyState";
import { Table, type ColumnDef } from "../components/Table";
import { formatDateTime, truncateId } from "../lib/format";

interface JoinedRun extends DemoValidationRun {
  trace: TraceIndexExportRow | undefined;
}

const columns: ColumnDef<JoinedRun>[] = [
  {
    key: "label",
    header: "Validation",
    render: (row) => <span className="font-medium text-text">{row.label}</span>,
    sortValue: (row) => row.label,
  },
  {
    key: "declared",
    header: "Evidence status",
    render: (row) => <span className="capitalize text-status-validated-fg">{row.status}</span>,
    sortValue: (row) => row.status,
    width: "13ch",
  },
  {
    key: "facts",
    header: "Facts / results",
    render: (row) => <span className="text-text-muted">{row.facts}</span>,
    sortValue: (row) => row.facts,
    width: "34ch",
  },
  {
    key: "trace",
    header: "Exported trace",
    render: (row) => row.trace === undefined ? <span className="text-text-faint">Waiting for export</span> : <span className="capitalize">{row.trace.outcome_status}</span>,
    sortValue: (row) => row.trace?.outcome_status ?? null,
    width: "18ch",
  },
  {
    key: "completed",
    header: "Recorded at",
    render: (row) => row.trace?.ended_at === null || row.trace?.ended_at === undefined ? <span className="text-text-faint">—</span> : formatDateTime(row.trace.ended_at),
    sortValue: (row) => row.trace?.ended_at ?? null,
    width: "22ch",
  },
  {
    key: "run",
    header: "Run ID",
    render: (row) => <code className="font-mono text-xs text-text-muted" title={row.run_id}>{truncateId(row.run_id)}</code>,
    sortValue: (row) => row.run_id,
    width: "15ch",
  },
];

export default function ValidationRuns() {
  const manifest = useDemoManifest();
  const traceIndex = useExportRows(["trace_index"], 250);
  const rows = useMemo<JoinedRun[]>(() => {
    if (manifest.data === undefined) return [];
    const index = new Map(
      traceIndex.rows.flatMap((entry) => entry.table === "trace_index" ? [[entry.row.run_id, entry.row] as const] : [])
    );
    return manifest.data.runs.map((run) => ({ ...run, trace: index.get(run.run_id) }));
  }, [manifest.data, traceIndex.rows]);

  if (manifest.status === "error") {
    return <EmptyState title="Validation Runs is available only in the local demo" description="The production edge deliberately does not serve local-demo evidence metadata." />;
  }
  if (manifest.status === "loading") return <div role="status" aria-label="Loading local demo validation evidence" className="h-64 animate-pulse rounded-lg border border-border bg-surface" />;
  if (traceIndex.status === "error") return <ErrorState error={traceIndex.error} onRetry={traceIndex.reload} title="Could not load the authoritative trace export" />;

  return (
    <div className="space-y-6">
      <div>
        <div className="flex items-center gap-2"><h1 className="text-lg font-semibold text-text">Validation Runs</h1><span className="rounded-full border border-accent/40 bg-accent/10 px-2 py-0.5 text-xs font-medium text-accent">Local demo</span></div>
        <p className="mt-1 max-w-3xl text-sm text-text-muted">{manifest.data?.provenance}</p>
      </div>
      <section className="space-y-3">
        <p className="max-w-3xl text-xs text-text-muted">Evidence labels come from the checked-in local-demo manifest. The Exported trace column is joined by run ID from the authenticated project export; a missing row means it has not appeared in this capped export, not that the validation failed.</p>
        <Table columns={columns} rows={rows} getRowId={(row) => row.run_id} loading={traceIndex.status === "loading"} caption="Local demo validation evidence joined to exported trace records" initialSort={{ key: "label", direction: "asc" }} />
      </section>
    </div>
  );
}
