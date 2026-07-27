import { useState } from "react";
import { Link } from "react-router-dom";
import { useReviewQueue } from "../api/hooks";
import { Table, type ColumnDef } from "../components/Table";
import { EmptyState } from "../components/EmptyState";
import { ErrorState } from "../components/ErrorState";
import { formatDateTime, formatInt, formatRelativeTime, truncateId } from "../lib/format";
import type { ReviewItemOut } from "../api/types";

// The human backstop. `review_queue` collects the decisions Tracebed refused
// to make on its own — PLAN.md §6's `retirement.min_distinct_principals` (K=3)
// routes a below-K retirement here rather than auto-retiring, and a candidate
// that re-flags on a scan re-pass lands here rather than being quietly
// quarantined a second time.
//
// This view is READ-ONLY, and that is a design constraint rather than an
// unfinished edge. Resolving an item means moving the memory it points at
// through the state machine (PLAN.md §5's transition table), and no route
// changes a memory's status, because PLAN.md §10 says no admin bypass exists
// in code. A "Resolve" button here would either lie or BE that bypass. What
// the view can do is make each item traceable: every row carrying a memory_id
// links into the vault detail for that memory, which is where the provenance
// the decision has to be made against actually lives.

const PAGE_LIMIT = 200;

/** Reasons `Repo.insert_review_item` is called with, glossed into what the
 * operator is actually being asked to decide. An unrecognised reason renders
 * verbatim with NO gloss: inventing an explanation for a string this
 * dashboard has never seen is worse than showing the string. */
const REASON_GLOSS: Record<string, string> = {
  retirement_below_k_principals:
    "Q fell below the retirement threshold, but the negative evidence came from fewer than the required distinct authenticated principals. Auto-retirement is refused for exactly this case: one principal producing four bad outcomes is one opinion, not a fleet signal.",
  scan_reflag:
    "The shared scan suite flagged this item on a re-pass it had previously passed. Either the item changed or the suite did, and both need a human to say which.",
  contradiction:
    "This item contradicts another of comparable provenance strength, so neither automatically supersedes the other.",
};

function ReasonCell({ reason }: { reason: string }) {
  const gloss = REASON_GLOSS[reason];
  return (
    <div className="min-w-0 max-w-xl">
      <p className="font-medium text-text">{reason}</p>
      {gloss !== undefined && <p className="mt-0.5 text-xs text-text-muted">{gloss}</p>}
    </div>
  );
}

export default function ReviewQueue() {
  const [includeResolved, setIncludeResolved] = useState(false);
  const query = useReviewQueue(includeResolved, PAGE_LIMIT);

  const items = query.data?.items ?? [];
  const returned = query.data?.returned ?? 0;
  const limit = query.data?.limit ?? PAGE_LIMIT;
  const atLimit = returned >= limit;
  const openCount = items.filter((i) => i.resolved_at === null).length;

  const columns: ColumnDef<ReviewItemOut>[] = [
    {
      key: "reason",
      header: "Why it is here",
      render: (row) => <ReasonCell reason={row.reason} />,
      sortValue: (row) => row.reason,
    },
    {
      key: "memory",
      header: "Memory",
      width: "22ch",
      render: (row) =>
        row.memory_id === null ? (
          // An item with no memory_id is a project-level finding, not a broken
          // row; saying so costs a line and saves an operator hunting for a
          // link that was never meant to be there.
          <span className="text-xs text-text-faint">No memory — project-level item</span>
        ) : (
          <Link
            to={`/memory-vault/${row.memory_id}`}
            title={row.memory_id}
            className="font-mono text-xs text-accent underline-offset-2 hover:underline"
          >
            {truncateId(row.memory_id)}
          </Link>
        ),
      sortValue: (row) => row.memory_id,
    },
    {
      key: "opened_at",
      header: "Opened (UTC)",
      width: "24ch",
      render: (row) => (
        <span title={row.opened_at}>
          {formatDateTime(row.opened_at)}
          <span className="ml-1.5 text-xs text-text-faint">
            {formatRelativeTime(row.opened_at)}
          </span>
        </span>
      ),
      sortValue: (row) => row.opened_at,
    },
    {
      key: "state",
      header: "State",
      width: "26ch",
      render: (row) =>
        row.resolved_at === null ? (
          <span className="inline-flex items-center gap-1.5 rounded-full border border-status-quarantined-border bg-status-quarantined-bg px-2 py-0.5 text-xs font-medium text-status-quarantined-fg">
            <span aria-hidden="true">●</span> Open
          </span>
        ) : (
          <span className="text-xs text-text-muted">
            Resolved {formatDateTime(row.resolved_at)}
            {row.resolution !== null && (
              <span className="block text-text-faint">{row.resolution}</span>
            )}
          </span>
        ),
      // Open first when ascending: the rows needing action are the rows the
      // operator opened this page for.
      sortValue: (row) => (row.resolved_at === null ? 0 : 1),
    },
  ];

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-lg font-semibold text-text">Review queue</h1>
        <p className="mt-1 max-w-3xl text-sm text-text-muted">
          Decisions Tracebed declined to make automatically. Live from{" "}
          <code className="font-mono text-xs">GET /admin/review_queue</code>.
        </p>
      </div>

      <div className="rounded-md border border-border bg-surface px-3 py-2 text-xs text-text-muted">
        <strong className="font-semibold text-text">This view is read-only.</strong> Resolving an
        item means moving the memory it points at through the state machine, and no route changes a
        memory&rsquo;s status — PLAN.md §10 forbids an admin bypass in code. Follow the memory link
        to inspect provenance; the transition itself happens through the tooling that owns it, not
        through this table.
      </div>

      <div className="flex flex-wrap items-center justify-between gap-3">
        <label className="inline-flex items-center gap-2 text-sm text-text">
          <input
            type="checkbox"
            checked={includeResolved}
            onChange={(e) => setIncludeResolved(e.target.checked)}
            className="h-3.5 w-3.5 accent-accent"
          />
          Include resolved items
        </label>
        {query.status === "success" && (
          <p className="text-xs text-text-muted">
            {formatInt(openCount)} open
            {includeResolved && ` · ${formatInt(items.length - openCount)} resolved`}
            {atLimit && ` · page limit ${formatInt(limit)} reached, so this is a lower bound`}
          </p>
        )}
      </div>

      {query.status === "error" ? (
        <ErrorState error={query.error} onRetry={query.reload} />
      ) : query.status === "success" && items.length === 0 ? (
        <EmptyState
          title={includeResolved ? "Nothing in the review queue" : "No open review items"}
          description={
            includeResolved
              ? "review_queue has no rows at all for this project. Nothing has ever been escalated to a human here."
              : "Nothing is waiting on a human decision right now. Items appear when a retirement is blocked below the distinct-principal threshold, or when a candidate re-flags on a scan re-pass."
          }
        />
      ) : (
        <Table
          caption="Review queue items, why each was escalated, the memory it concerns, and whether it is still open"
          columns={columns}
          rows={items}
          getRowId={(row) => row.item_id}
          loading={query.status === "loading"}
          initialSort={{ key: "state", direction: "asc" }}
          maxHeight="60vh"
        />
      )}
    </div>
  );
}
