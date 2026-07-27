import { useMemo } from "react";
import { useKillswitchState } from "../api/hooks";
import { EmptyState } from "../components/EmptyState";
import { ErrorState } from "../components/ErrorState";
import { Table, type ColumnDef } from "../components/Table";
import { formatDateTime, formatEstimateWithCI, formatInt, truncateId } from "../lib/format";
import type { KillswitchCellOut } from "../api/types";

// PLAN.md §6's `killswitch.trigger`: stratified lift on runs where something
// was actually injected, versus the shadow-retrieved holdout arm; lower
// confidence bound below zero sustained 14 days; minimum cell N 200;
// Benjamini-Hochberg correction across cells. When that fires,
// `workers/killswitch.py` writes ONE `killswitch_state` row per triggering
// cell, carrying its own `evidence` record. This view reads those rows.
//
// It is READ-ONLY, and deliberately so. There is no override control, because
// there is no write route and adding one would be precisely the "admin bypass
// in code" PLAN.md §10 forbids: `evidence["source"]` is what distinguishes an
// automatic disable from an operator's reversal of one, and that authorship
// belongs to the worker that owns the decision, not to a browser.
//
// The evidence object is rendered from whatever the worker actually wrote. It
// is NOT re-derived, and no lift figure is reconstructed client-side from
// retrieval_event rows: a governing number has one author, and a dashboard
// that recomputed it would silently become a second one whose method could
// drift from the worker's (BH correction across cells is not something a
// per-cell view can even see).

/** Keys `workers/killswitch.py`'s `_evidence` is known to write. Anything else
 * in the object still renders — in the raw JSON block — but only these are
 * given a human label, because a label invented for an unknown key is a claim
 * about its meaning. */
const EVIDENCE_LABELS: Record<string, string> = {
  source: "Decision source",
  reason: "Trigger reason",
  metric: "Metric measured",
  window_days: "Sustained over (days)",
  min_cell_n: "Minimum cell N required",
  scoring_epoch_id: "Scoring epoch",
  principal_ref: "Acting principal",
};

function asNumber(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

/**
 * A lift figure without its interval and its N is the single most misleading
 * thing this console can display, so the estimate renders through
 * `formatEstimateWithCI` or it does not render at all. A partial evidence
 * record (a bound with no point estimate, an estimate with no N) is reported
 * as incomplete rather than rendered with the missing pieces silently dropped.
 */
function EvidenceEstimate({ evidence }: { evidence: Record<string, unknown> }) {
  const point = asNumber(evidence["lift"] ?? evidence["estimate"] ?? evidence["point"]);
  const low = asNumber(evidence["ci_low"] ?? evidence["lift_ci_low"]);
  const high = asNumber(evidence["ci_high"] ?? evidence["lift_ci_high"]);
  const n = asNumber(evidence["n"] ?? evidence["cell_n"] ?? evidence["min_arm_n"]);

  if (point === null && low === null && high === null && n === null) return null;
  if (point === null || low === null || high === null || n === null) {
    return (
      <p className="mt-1 text-xs text-status-quarantined-fg">
        Incomplete measurement record — this decision&rsquo;s evidence does not carry a point
        estimate, both interval bounds and an N together, so no lift figure is shown. The raw
        record is below.
      </p>
    );
  }
  return (
    <p className="mt-1 font-mono text-xs text-text">
      lift {formatEstimateWithCI(point, low, high, n)}
    </p>
  );
}

function EvidencePanel({ evidence }: { evidence: Record<string, unknown> | null }) {
  if (evidence === null) {
    return (
      <p className="text-xs text-status-quarantined-fg">
        No evidence recorded on this row. A disablement with no recorded reason cannot be reviewed;
        treat it as an unexplained change and check the audit sink.
      </p>
    );
  }
  const labelled = Object.entries(evidence).filter(([k]) => k in EVIDENCE_LABELS);
  return (
    <div className="space-y-2">
      <EvidenceEstimate evidence={evidence} />
      {labelled.length > 0 && (
        <dl className="grid grid-cols-[max-content_1fr] gap-x-3 gap-y-0.5 text-xs">
          {labelled.map(([k, v]) => (
            <div key={k} className="contents">
              <dt className="text-text-muted">{EVIDENCE_LABELS[k]}</dt>
              <dd className="font-mono text-text">{String(v)}</dd>
            </div>
          ))}
        </dl>
      )}
      <details>
        <summary className="cursor-pointer text-xs font-medium text-text-muted hover:text-text">
          Raw evidence record
        </summary>
        <pre className="mt-1 max-w-full overflow-x-auto rounded-md border border-border bg-bg p-2 font-mono text-[11px] leading-relaxed text-text-muted">
          {JSON.stringify(evidence, null, 2)}
        </pre>
      </details>
    </div>
  );
}

export default function KillSwitch() {
  const query = useKillswitchState();
  const cells = useMemo(() => query.data?.cells ?? [], [query.data]);
  const disabledCount = cells.filter((c) => c.disabled).length;

  const columns: ColumnDef<KillswitchCellOut>[] = [
    {
      key: "state",
      header: "State",
      width: "14ch",
      // Word first, colour second — an operator with any colour vision reads
      // "DISABLED" identically.
      render: (row) =>
        row.disabled ? (
          <span className="inline-flex items-center gap-1.5 rounded-full border border-status-tombstoned-border bg-status-tombstoned-bg px-2 py-0.5 text-xs font-semibold text-status-tombstoned-fg">
            <span aria-hidden="true">■</span> DISABLED
          </span>
        ) : (
          <span className="inline-flex items-center gap-1.5 rounded-full border border-border-strong px-2 py-0.5 text-xs font-medium text-text-muted">
            <span aria-hidden="true">□</span> Enabled
          </span>
        ),
      sortValue: (row) => (row.disabled ? 0 : 1),
    },
    {
      key: "scope",
      header: "Agent type",
      width: "26ch",
      render: (row) =>
        row.agent_type_id === null ? (
          // NOT an unknown agent type: migrations/0001 uses a NULL
          // agent_type_id as the project-wide sentinel, which is the WIDEST
          // possible disablement. Rendering it as "unknown" would report the
          // broadest scope as the narrowest.
          <span className="font-medium text-text">All agent types (project-wide)</span>
        ) : (
          <span className="font-mono text-xs text-text" title={row.agent_type_id}>
            {truncateId(row.agent_type_id)}
          </span>
        ),
      sortValue: (row) => row.agent_type_id ?? "",
    },
    {
      key: "mem_type",
      header: "Memory type",
      width: "14ch",
      render: (row) => row.mem_type,
      sortValue: (row) => row.mem_type,
    },
    {
      key: "changed_at",
      header: "Changed (UTC)",
      width: "24ch",
      render: (row) => <span title={row.changed_at}>{formatDateTime(row.changed_at)}</span>,
      sortValue: (row) => row.changed_at,
    },
    {
      key: "evidence",
      header: "Recorded evidence",
      render: (row) => <EvidencePanel evidence={row.evidence} />,
    },
  ];

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-lg font-semibold text-text">Kill switch</h1>
        <p className="mt-1 max-w-3xl text-sm text-text-muted">
          Every recorded <code className="font-mono text-xs">killswitch_state</code> decision for
          this project, newest first — live from{" "}
          <code className="font-mono text-xs">GET /admin/killswitch_state</code>.
        </p>
      </div>

      <div className="rounded-md border border-border bg-surface px-3 py-2 text-xs text-text-muted">
        <strong className="font-semibold text-text">Read-only, on purpose.</strong> No route writes
        this table, and none is offered: PLAN.md §10 says no admin bypass exists in code, and{" "}
        <code className="font-mono">evidence.source</code> is what separates an automatic disable
        from an operator reversing one. That authorship belongs to{" "}
        <code className="font-mono">workers/killswitch.py</code>. Lift figures shown here are the
        worker&rsquo;s own recorded numbers — nothing on this page recomputes them, because a
        per-cell view cannot see the Benjamini-Hochberg correction applied across cells.
      </div>

      {query.status === "error" ? (
        <ErrorState error={query.error} onRetry={query.reload} />
      ) : query.status === "success" && cells.length === 0 ? (
        <EmptyState
          title="No kill-switch decision has ever been recorded"
          description="killswitch_state is empty for this project. Read that precisely: it means nothing has been auto-disabled and no override has been logged. It does NOT mean every (agent type, memory type) cell has been measured and passed — a cell with too few runs to reach the minimum N is never evaluated, and therefore never leaves a row here."
        />
      ) : (
        <>
          {query.status === "success" && (
            <p className="text-sm text-text">
              <span className="font-semibold tabular-nums">{formatInt(disabledCount)}</span> of{" "}
              {formatInt(cells.length)} recorded cell(s) are currently disabled — memory of that
              type is not injected for that agent type until the state changes.
            </p>
          )}
          <Table
            caption="Recorded kill-switch decisions: scope, memory type, when it changed, and the evidence the worker recorded for it"
            columns={columns}
            rows={cells}
            getRowId={(row) =>
              `${row.agent_type_id ?? "project-wide"}:${row.mem_type}:${row.changed_at}`
            }
            loading={query.status === "loading"}
            initialSort={{ key: "changed_at", direction: "desc" }}
          />
        </>
      )}

      <section className="rounded-lg border border-border bg-surface p-4">
        <h2 className="text-sm font-semibold text-text">What is not on this page</h2>
        <ul className="mt-2 space-y-1.5 text-xs text-text-muted">
          <li>
            <strong className="font-medium text-text">A per-cell lift table for every cell.</strong>{" "}
            Only cells the worker acted on leave a row. A cell that was measured and passed, or that
            never reached the minimum N, is indistinguishable here from one that was never measured.
            Closing that would need a table the worker does not write.
          </li>
          <li>
            <strong className="font-medium text-text">Q trajectories.</strong>{" "}
            <code className="font-mono">memory_item</code> carries one current{" "}
            <code className="font-mono">q_value</code> and one{" "}
            <code className="font-mono">status_changed_at</code>; no per-update history is stored
            anywhere, so no view can plot how a Q got where it is.
          </li>
          <li>
            <strong className="font-medium text-text">
              Policy-violation rate memory-on vs memory-off.
            </strong>{" "}
            PLAN.md §8 improvement 2 measures it alongside task quality; if a deployment&rsquo;s
            worker records it, it appears in the raw evidence block above under whatever key the
            worker used.
          </li>
        </ul>
      </section>
    </div>
  );
}
