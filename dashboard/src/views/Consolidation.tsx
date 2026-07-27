import { useMemo } from "react";
import { get } from "../api/client";
import { useQuery } from "../api/hooks";
import { EmptyState } from "../components/EmptyState";
import { ErrorState } from "../components/ErrorState";
import { Table, type ColumnDef } from "../components/Table";
import { formatDateTime, formatFloat, formatInt, truncateId } from "../lib/format";

// Consolidation is the nightly-merge loop ACE (arXiv:2510.04618, ICLR 2026)
// names brevity bias and context collapse as the failure modes of: a
// consolidator that rewrites an item wholesale progressively strips detail
// until each individual rewrite looks reasonable in isolation and the memory
// says something shorter and less true than what it replaced.
//
// THIS PAGE CANNOT SHOW THAT YET, AND SAYS SO RATHER THAN IMPLYING OTHERWISE.
// `workers/consolidator.py`'s per-sweep DeltaRecord — the ADD/AMEND/REMOVE log
// with before/after element text that a human would actually audit for brevity
// bias — has no store anywhere in this codebase. GET /admin/consolidation/diffs
// therefore reads `derived_state`, the only table in the schema shaped like a
// versioned per-key delta, and reports `sweep_deltas_available: false` so this
// view can tell "this project ran no sweeps" apart from "nothing in this system
// records sweeps". Those two render identically as an empty list and only one
// of them is a fact about the project.
//
// The retention figure is likewise NOT the ACE metric. The server sends
// `value_retained_fraction` = 1 - |delta_pct|/100: how far one derived_state
// key's numeric value moved between two versions. It says nothing about
// whether any fact survived. It is labelled for what it is at every point of
// use, because a column headed "information retention" would be quoted as an
// ACE retention number the first time this page was screenshot.
//
// NO FIXTURE. An earlier build rendered hand-authored sweeps behind a banner
// when the route 404'd. The route exists now, and inventing a retention
// percentage on the one page whose job is catching silent data loss was never
// a defensible failure mode.
//
// Interfaces transcribed from src/tracebed/api/models_reports.py:
// ConsolidationDiffsOut / ConsolidationDiffOut.

// --------------------------------------------------------------------- //
// Wire contract for GET /admin/consolidation/diffs.
// --------------------------------------------------------------------- //

interface ConsolidationDiffOut {
  agent_type_id: string;
  key: string;
  version: number;
  value: Record<string, unknown>;
  /** Signed percentage move from the previous version (D-022's ±10% rate
   * clamp input). `null` for a first version — there is no previous value to
   * have moved from, which is not the same as "moved 0%". */
  delta_pct: number | null;
  /** True when D-022's rate-bounded-movement clamp bound this update: the
   * consolidator wanted to move further than one step allows. */
  clamped: boolean;
  /** `1 - |delta_pct|/100`, clamped to [0,1]. NOT the ACE information-retention
   * metric — see this file's header. `null` iff `delta_pct` is null. */
  value_retained_fraction: number | null;
  computed_at: string;
}

interface ConsolidationDiffsOut {
  items: ConsolidationDiffOut[];
  limit: number;
  offset: number;
  returned: number;
  /** False on every build where no writer for per-sweep ADD/AMEND/REMOVE
   * deltas exists. Lets this view distinguish "no sweeps ran" from "sweeps
   * are not recorded anywhere", which an empty `items` list cannot. */
  sweep_deltas_available: boolean;
}

// --------------------------------------------------------------------- //
// Sections
// --------------------------------------------------------------------- //

function SweepDeltasUnavailableNotice() {
  return (
    <div className="rounded-md border border-dashed border-border-strong bg-surface px-3 py-2.5 text-xs text-text-muted">
      <strong className="font-semibold text-text">
        Per-sweep add / remove / amend deltas are not recorded by this system.
      </strong>{" "}
      <code className="font-mono">workers/consolidator.py</code> builds a{" "}
      <code className="font-mono">DeltaRecord</code> for every element it adds, amends or
      removes, and nothing persists it &mdash; there is no table to read and no route that
      could return one. The before/after element text a human would audit for brevity bias
      (ACE, ICLR 2026) is therefore not available on this page, and the retention percentage
      that <code className="font-mono">harness/consolidation_regression.py</code> computes is
      not either: that harness measures how many distinct verifiable facts survive a sweep, and
      it writes its result to a test report, not to this project&rsquo;s database.
      <span className="mt-1.5 block text-text-faint">
        This notice is not a bug in this view and not an outage. It is the honest state of the
        system, and it is shown rather than hidden so an empty page is never mistaken for
        &ldquo;consolidation ran and lost nothing&rdquo;.
      </span>
    </div>
  );
}

function DerivedStateTable({ items }: { items: ConsolidationDiffOut[] }) {
  const columns: ColumnDef<ConsolidationDiffOut>[] = [
    {
      key: "key",
      header: "Derived key",
      render: (row) => <span className="font-mono text-xs text-text">{row.key}</span>,
      sortValue: (row) => row.key,
    },
    {
      key: "agent_type_id",
      header: "Agent type",
      width: "16ch",
      render: (row) => (
        <span className="font-mono text-xs text-text-muted" title={row.agent_type_id}>
          {truncateId(row.agent_type_id)}
        </span>
      ),
      sortValue: (row) => row.agent_type_id,
    },
    {
      key: "version",
      header: "Version",
      width: "10ch",
      numeric: true,
      render: (row) => formatInt(row.version),
      sortValue: (row) => row.version,
    },
    {
      key: "delta_pct",
      header: "Movement",
      width: "22ch",
      numeric: true,
      // Neutral tone deliberately: a value moving is neither good nor bad on
      // its own, and colouring the sign would make a routine recalibration
      // read as a regression.
      render: (row) =>
        row.delta_pct === null ? (
          <span className="text-text-faint">first version — no previous value</span>
        ) : (
          <span className="text-text">
            {row.delta_pct > 0 ? "+" : ""}
            {formatFloat(row.delta_pct, 2)}%
            {row.clamped && (
              <span className="text-status-quarantined-fg"> · clamped</span>
            )}
          </span>
        ),
      sortValue: (row) => row.delta_pct,
    },
    {
      key: "value_retained_fraction",
      header: "Value retained (1 − |Δ|)",
      width: "20ch",
      numeric: true,
      render: (row) =>
        row.value_retained_fraction === null ? (
          <span className="text-text-faint">not applicable</span>
        ) : (
          <span className="text-text">
            {formatFloat(row.value_retained_fraction * 100, 1)}%
          </span>
        ),
      sortValue: (row) => row.value_retained_fraction,
    },
    {
      key: "computed_at",
      header: "Computed (UTC)",
      width: "22ch",
      render: (row) => <span title={row.computed_at}>{formatDateTime(row.computed_at)}</span>,
      sortValue: (row) => row.computed_at,
    },
    {
      key: "value",
      header: "Value",
      render: (row) => (
        // Keyboard-reachable disclosure, never a hover-only title attribute.
        <details>
          <summary className="cursor-pointer text-xs text-text-muted hover:text-text">
            Stored value
          </summary>
          <pre className="mt-1 max-w-full overflow-x-auto rounded-md border border-border bg-bg p-2 font-mono text-[11px] text-text-muted">
            {JSON.stringify(row.value, null, 2)}
          </pre>
        </details>
      ),
    },
  ];

  return (
    <Table
      caption="Every derived_state version this page of results covers: which key moved, by how much, whether the rate clamp bound the move, and the stored value at that version"
      columns={columns}
      rows={items}
      // The primary key is (project, agent_type, key, version) — never an
      // array index, which breaks the instant the table is re-sorted or a
      // newer version lands at the top.
      getRowId={(row) => `${row.agent_type_id}::${row.key}::${row.version}`}
      initialSort={{ key: "computed_at", direction: "desc" }}
      density="compact"
      maxHeight="60vh"
    />
  );
}

// --------------------------------------------------------------------- //
// Page
// --------------------------------------------------------------------- //

export default function Consolidation() {
  const query = useQuery<ConsolidationDiffsOut>(
    (signal) => get<ConsolidationDiffsOut>("/admin/consolidation/diffs", { signal }),
    "/admin/consolidation/diffs"
  );
  const diffs = query.data;

  const clampedCount = useMemo(
    () => (diffs?.items ?? []).filter((i) => i.clamped).length,
    [diffs]
  );

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-lg font-semibold text-text">Consolidation</h1>
        <p className="mt-1 max-w-3xl text-sm text-text-muted">
          What the nightly merge loop changed. The structured deltas a human would audit for
          brevity bias are not stored by this system yet &mdash; what is below is the
          rate-clamped movement of every derived-state key, which is a different and much
          narrower thing.
        </p>
      </div>

      {query.status === "error" ? (
        <ErrorState error={query.error} onRetry={query.reload} />
      ) : query.status === "loading" || query.status === "idle" ? (
        <div
          role="status"
          aria-label="Loading consolidation diffs"
          className="h-64 animate-pulse rounded-lg border border-border bg-surface"
        />
      ) : diffs === undefined ? (
        <EmptyState
          title="The server returned no body"
          description="GET /admin/consolidation/diffs answered successfully with an empty body. Treat that as a server-side fault, not as evidence that consolidation is healthy."
        />
      ) : (
        <>
          {!diffs.sweep_deltas_available && <SweepDeltasUnavailableNotice />}

          <section>
            <h2 className="mb-3 text-sm font-semibold text-text">Derived-state versions</h2>
            {diffs.items.length === 0 ? (
              <EmptyState
                title="No derived_state version exists for this project"
                description="Nothing has written a derived_state row. On every build shipped today that is the expected result for every project — the table has no writer anywhere in this codebase yet — so this empty state is a fact about the system, not about your project's consolidator."
              />
            ) : (
              <>
                <p className="mb-2 text-xs text-text-faint">
                  Showing {formatInt(diffs.returned)} version(s) from offset{" "}
                  {formatInt(diffs.offset)}
                  {diffs.returned >= diffs.limit &&
                    ` — this is a full page of ${formatInt(diffs.limit)}, so older versions exist beyond it`}
                  .
                </p>
                {clampedCount > 0 && (
                  <p className="mb-2 rounded-md border border-status-quarantined-border bg-status-quarantined-bg px-3 py-2 text-xs text-status-quarantined-fg">
                    {formatInt(clampedCount)} version(s) on this page had their movement clamped
                    by D-022&rsquo;s rate bound &mdash; the consolidator wanted to move the
                    value further than one update is allowed to. A clamp binding several
                    consecutive updates to the same key is the signal D-022 exists to raise; the
                    version column above is how to check for a run of them.
                  </p>
                )}
                <DerivedStateTable items={diffs.items} />
              </>
            )}
          </section>

          <section className="rounded-lg border border-border bg-surface p-4">
            <h2 className="text-sm font-semibold text-text">What is not on this page</h2>
            <ul className="mt-2 space-y-1.5 text-xs text-text-muted">
              <li>
                <strong className="font-medium text-text">
                  Before / after text for anything a sweep rewrote.
                </strong>{" "}
                That lives in <code className="font-mono">workers/consolidator.py</code>&rsquo;s
                in-memory <code className="font-mono">DeltaRecord</code>, which no table
                persists. Without it there is no way to see a fact being quietly dropped from a
                memory, which is the exact failure ACE names.
              </li>
              <li>
                <strong className="font-medium text-text">
                  An information-retention percentage.
                </strong>{" "}
                <code className="font-mono">harness/consolidation_regression.py</code> computes
                one, against synthetic marker facts, in a test run &mdash; not against this
                project&rsquo;s data and not into any table this route can read. The &ldquo;value
                retained&rdquo; column above is a different quantity and must not be quoted as
                that number.
              </li>
            </ul>
          </section>
        </>
      )}
    </div>
  );
}
