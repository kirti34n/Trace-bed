import { useMemo, useState } from "react";
import { get } from "../api/client";
import { useMemoryItem, useQuery } from "../api/hooks";
import { EmptyState } from "../components/EmptyState";
import { ErrorState } from "../components/ErrorState";
import { StatusBadge, TrustTierBadge } from "../components/StatusBadge";
import { Table, type ColumnDef } from "../components/Table";
import { formatDateTime, formatFloat, formatInt, truncateId } from "../lib/format";
import type { MemType } from "../api/types";

// What went stale, why, and what is drifting towards revalidation. PLAN.md
// §5's `invalidation_event` table and `memory_item`'s strike/lifecycle columns
// are the only two places staleness is stored server-side; this view reads
// both and refuses to invent a third.
//
// THE ONE THING THIS VIEW MUST NOT SAY. There is no persisted causal link
// anywhere in the schema recording "event X staled memory Y" —
// `workers/invalidator.py` transitions the row but writes no back-reference to
// the event that triggered it. What the server can compute, and does, is which
// currently-stale memories an event's selector MATCHES, using the real
// `selector_matches` predicate. That is evidence, not causation: the same
// memory legitimately appears under every event whose selector matches its
// provenance, and a memory staled by an event that has since been paged out of
// the response still matches. An earlier build of this view called that column
// "blast radius" and said "staled by this event", which reads as a recorded
// fact. It is not one, and every label below says what it actually is.
//
// NO FIXTURE. An earlier build fell back to hand-authored numbers on a 404 or
// network failure. GET /admin/staleness/report now exists (api/reports.py), so
// there is nothing left to stand in for — and a page whose whole job is
// distinguishing "nothing went stale" from "the invalidator is not firing"
// must never answer that question with invented rows.
//
// Interfaces below are transcribed from src/tracebed/api/models_reports.py
// field for field: StalenessReportOut / InvalidationReportEntryOut /
// InvalidationMatchOut / RevalidationCandidateOut.

// --------------------------------------------------------------------- //
// Wire contract for GET /admin/staleness/report.
// --------------------------------------------------------------------- //

interface InvalidationMatchOut {
  memory_id: string;
  mem_type: MemType;
  strike_count: number;
  status_changed_at: string | null;
}

interface InvalidationReportEntryOut {
  event_id: string;
  /** Free text server-side (PLAN.md §5 has no closed enum for this column). */
  event_type: string;
  selector: Record<string, unknown> | null;
  fired_at: string;
  /** Currently-stale memories whose provenance this event's selector matches.
   * Evidence, NOT a recorded causal link — see this file's header. May be a
   * capped prefix of the real match set; `matched_memories_total` is the
   * exact count and is what this view renders as the count. */
  matched_memories: InvalidationMatchOut[];
  /** EXACT number of matches, even when `matched_memories` was capped. */
  matched_memories_total: number;
  /** True when `matched_memories` is an incomplete list — either the server's
   * stale-memory scan was bounded, or this one event matched more than a
   * single response carries. Either way the list reads "at least these". */
  matched_memories_truncated: boolean;
}

interface RevalidationCandidateOut {
  memory_id: string;
  mem_type: MemType;
  /** `last_retrieved_at`, or `created_at` when never retrieved — the idle
   * reference `workers/revalidation.py` measures against. NOT the same field
   * as `last_revalidated_at`. */
  reference_at: string;
  age_days: number;
  /** `lifecycle.revalidation_age_days` (R) this response was computed under —
   * travels with the rows so a threshold is never rendered from a client-side
   * guess at the deployment's configured value. */
  r_days: number;
  last_revalidated_at: string | null;
}

interface StalenessReportOut {
  invalidation_events: InvalidationReportEntryOut[];
  event_limit: number;
  event_offset: number;
  event_returned: number;
  approaching_revalidation: RevalidationCandidateOut[];
  approaching_limit: number;
  approaching_offset: number;
  approaching_returned: number;
  r_days: number;
}

// `cache_flush` invalidates Valkey cache keys (D-041 / stores/valkey/flush.py)
// and touches no `memory_item` row at all — zero matches on one is CORRECT and
// must read as correct, never as a caution. Every other event type is meant to
// reach at least one memory when it fires.
const EVENT_TYPES_THAT_NEVER_TOUCH_MEMORIES = new Set(["cache_flush"]);

// A display heuristic belonging to this page, not a threshold configured
// anywhere in PLAN.md §6 — disclosed as such at the point of use, because a
// number that looks like a system threshold teaches an operator to tune the
// system against a bound the system has never heard of.
const LARGE_MATCH_SET_PAGE_HEURISTIC = 10;

// --------------------------------------------------------------------- //
// Shared
// --------------------------------------------------------------------- //

function MemoryDrilldown({ memoryId }: { memoryId: string }) {
  const [open, setOpen] = useState(false);
  const query = useMemoryItem(open ? memoryId : null);
  return (
    <details
      className="mt-1"
      onToggle={(e) => setOpen((e.currentTarget as HTMLDetailsElement).open)}
    >
      <summary
        aria-label={`Look up current state of memory ${memoryId}`}
        className="cursor-pointer text-xs font-medium text-text-muted hover:text-text"
      >
        Look up {truncateId(memoryId)}
      </summary>
      {query.status === "loading" ? (
        <p className="mt-1 text-xs text-text-faint">Loading…</p>
      ) : query.status === "error" ? (
        <ErrorState error={query.error} onRetry={query.reload} />
      ) : query.data !== undefined ? (
        <div className="mt-1 flex flex-wrap items-center gap-2 rounded-md border border-border bg-bg p-2 text-xs">
          <StatusBadge status={query.data.status} />
          <TrustTierBadge tier={query.data.trust_tier} />
          <span className="text-text-muted">
            strikes={formatInt(query.data.strike_count)} of 2
          </span>
        </div>
      ) : null}
    </details>
  );
}

/** The two-strike rule rendered in words, so the raw integer means something:
 * 0 is healthy, 1 is one strike from retirement (validated -> stale), 2 IS
 * retirement (stale -> retired). Never colour alone. */
function StrikeCount({ count }: { count: number }) {
  return (
    <span className={count >= 2 ? "text-status-tombstoned-fg" : "text-text"}>
      {formatInt(count)} of 2
      {count === 1 && " — one more retires it"}
      {count >= 2 && " — retired"}
    </span>
  );
}

// --------------------------------------------------------------------- //
// Section 1: invalidation events
// --------------------------------------------------------------------- //

function EventsTable({ events }: { events: InvalidationReportEntryOut[] }) {
  const columns: ColumnDef<InvalidationReportEntryOut>[] = [
    {
      key: "event_type",
      header: "Event type",
      width: "20ch",
      render: (row) => row.event_type,
      sortValue: (row) => row.event_type,
    },
    {
      key: "fired_at",
      header: "Fired (UTC)",
      width: "22ch",
      render: (row) => <span title={row.fired_at}>{formatDateTime(row.fired_at)}</span>,
      sortValue: (row) => row.fired_at,
    },
    {
      key: "selector",
      header: "Selector",
      width: "16ch",
      render: (row) =>
        row.selector === null || Object.keys(row.selector).length === 0 ? (
          <span className="text-text-faint">none</span>
        ) : (
          // Keyboard-reachable disclosure, never a hover-only title attribute:
          // a payload only a mouse can read is a payload a keyboard operator
          // cannot audit.
          <details>
            <summary className="cursor-pointer text-xs text-text-muted hover:text-text">
              {formatInt(Object.keys(row.selector).length)} field(s)
            </summary>
            <pre className="mt-1 max-w-full overflow-x-auto rounded-md border border-border bg-bg p-2 font-mono text-[11px] text-text-muted">
              {JSON.stringify(row.selector, null, 2)}
            </pre>
          </details>
        ),
    },
    {
      key: "matches",
      header: "Stale memories matching this selector",
      render: (row) => {
        // The COUNT is the server's exact total, not the length of the
        // (possibly capped) list below it — an over-invalidating selector that
        // reached 4,000 memories must not read as "50 matches" because that is
        // how many rows fit in the response.
        const n = row.matched_memories_total;
        const shown = row.matched_memories.length;
        const touchesMemories = !EVENT_TYPES_THAT_NEVER_TOUCH_MEMORIES.has(row.event_type);
        if (n === 0) {
          return touchesMemories ? (
            <span className="text-status-quarantined-fg">
              0 matches &mdash; caution: an event of this type is expected to reach at least one
              memory
            </span>
          ) : (
            <span className="text-text-muted">
              0 matches &mdash; correct for {row.event_type}, which touches cache keys, never
              memory rows
            </span>
          );
        }
        return (
          <div>
            <span className="text-text">
              {formatInt(n)} currently-stale memor{n === 1 ? "y" : "ies"} match
            </span>
            {row.matched_memories_truncated && (
              <p className="mt-0.5 text-xs text-status-quarantined-fg">
                Listing {formatInt(shown)} of them. The rest are either past the server&rsquo;s
                per-event listing cap or outside the bounded set it scanned &mdash; read the
                list as &ldquo;at least these&rdquo;, and the count above as the floor rather
                than a certainty.
              </p>
            )}
            {n > LARGE_MATCH_SET_PAGE_HEURISTIC && (
              <p className="mt-0.5 text-xs text-text-faint">
                Flagged large by this page&rsquo;s own display heuristic (&gt;
                {formatInt(LARGE_MATCH_SET_PAGE_HEURISTIC)}) &mdash; not a configured system
                threshold anywhere in PLAN.md §6.
              </p>
            )}
            <ul className="mt-1 space-y-1">
              {row.matched_memories.map((m) => (
                <li key={m.memory_id} className="text-xs">
                  <span className="font-mono text-text" title={m.memory_id}>
                    {truncateId(m.memory_id)}
                  </span>{" "}
                  <span className="text-text-muted">
                    · {m.mem_type} · <StrikeCount count={m.strike_count} />
                    {m.status_changed_at !== null && (
                      <>
                        {" "}
                        · went stale <span title={m.status_changed_at}>
                          {formatDateTime(m.status_changed_at)}
                        </span>
                      </>
                    )}
                  </span>
                  <MemoryDrilldown memoryId={m.memory_id} />
                </li>
              ))}
            </ul>
          </div>
        );
      },
      sortValue: (row) => row.matched_memories_total,
    },
  ];

  return (
    <Table
      caption="Invalidation events: type, when fired, the provenance selector that scoped it, and which currently-stale memories that selector matches. Matching is evidence of dependency, not a recorded record of which event staled which memory."
      columns={columns}
      rows={events}
      getRowId={(row) => row.event_id}
      initialSort={{ key: "fired_at", direction: "desc" }}
    />
  );
}

// --------------------------------------------------------------------- //
// Section 2: memories approaching (or past) revalidation age
// --------------------------------------------------------------------- //

function ApproachingTable({ rows }: { rows: RevalidationCandidateOut[] }) {
  const columns: ColumnDef<RevalidationCandidateOut>[] = [
    {
      key: "memory_id",
      header: "Memory",
      width: "16ch",
      render: (row) => (
        <span className="font-mono text-xs text-text" title={row.memory_id}>
          {truncateId(row.memory_id)}
        </span>
      ),
      sortValue: (row) => row.memory_id,
    },
    {
      key: "mem_type",
      header: "Type",
      width: "12ch",
      render: (row) => row.mem_type,
      sortValue: (row) => row.mem_type,
    },
    {
      key: "age_days",
      header: "Idle age",
      width: "22ch",
      numeric: true,
      // The threshold travels with the row, so this cell never renders a bare
      // number against a bound the reader has to remember or guess.
      render: (row) => (
        <span className={row.age_days >= row.r_days ? "text-status-quarantined-fg" : "text-text"}>
          {formatFloat(row.age_days, 1)}d of R={formatInt(row.r_days)}d
          {row.age_days >= row.r_days && " — past R"}
        </span>
      ),
      sortValue: (row) => row.age_days,
    },
    {
      key: "reference_at",
      header: "Idle since (UTC)",
      width: "22ch",
      render: (row) => <span title={row.reference_at}>{formatDateTime(row.reference_at)}</span>,
      sortValue: (row) => row.reference_at,
    },
    {
      key: "last_revalidated_at",
      header: "Last revalidated",
      width: "22ch",
      render: (row) =>
        row.last_revalidated_at === null ? (
          <span className="text-text-faint">never</span>
        ) : (
          <span title={row.last_revalidated_at}>
            {formatDateTime(row.last_revalidated_at)}
          </span>
        ),
      sortValue: (row) => row.last_revalidated_at,
    },
    {
      key: "drilldown",
      header: "Current state",
      render: (row) => <MemoryDrilldown memoryId={row.memory_id} />,
    },
  ];

  return (
    <Table
      caption="Validated memories whose idle age has reached a fraction of the revalidation age R, including those already past R. Idle age is measured from last retrieval, or from creation for a memory never retrieved."
      columns={columns}
      rows={rows}
      getRowId={(row) => row.memory_id}
      initialSort={{ key: "age_days", direction: "desc" }}
      maxHeight="60vh"
    />
  );
}

// --------------------------------------------------------------------- //
// Page
// --------------------------------------------------------------------- //

export default function Staleness() {
  const query = useQuery<StalenessReportOut>(
    (signal) => get<StalenessReportOut>("/admin/staleness/report", { signal }),
    "/admin/staleness/report"
  );
  const report = query.data;

  // Over-invalidation risk: an event fired that is meant to reach memories and
  // matches none. Under-invalidation risk: a validated memory whose idle age
  // has already passed R and which workers/revalidation.py has not acted on.
  // Both are real failure modes and neither is visible anywhere else.
  const overInvalidationCount = useMemo(
    () =>
      (report?.invalidation_events ?? []).filter(
        (e) =>
          e.matched_memories_total === 0 &&
          !EVENT_TYPES_THAT_NEVER_TOUCH_MEMORIES.has(e.event_type)
      ).length,
    [report]
  );
  const pastRCount = useMemo(
    () =>
      (report?.approaching_revalidation ?? []).filter((m) => m.age_days >= m.r_days).length,
    [report]
  );

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-lg font-semibold text-text">Staleness</h1>
        <p className="mt-1 max-w-3xl text-sm text-text-muted">
          What invalidation events fired, which stale memories their selectors reach, and which
          validated memories are drifting past their revalidation age. Over-invalidation (an
          event that should reach memories and reaches none) and under-invalidation (a memory
          past R that was never revalidated) are both failures, and this is where either becomes
          visible.
        </p>
      </div>

      {query.status === "error" ? (
        <ErrorState error={query.error} onRetry={query.reload} />
      ) : query.status === "loading" || query.status === "idle" ? (
        <div
          role="status"
          aria-label="Loading staleness report"
          className="h-64 animate-pulse rounded-lg border border-border bg-surface"
        />
      ) : report === undefined ? (
        <EmptyState
          title="The server returned no report body"
          description="GET /admin/staleness/report answered successfully with an empty body. Nothing can be inferred about this project's invalidation health from that — treat it as a server-side fault, not as a clean bill."
        />
      ) : (
        <>
          <section className="rounded-lg border border-border bg-surface p-4">
            <h2 className="text-sm font-semibold text-text">How to read this page</h2>
            <p className="mt-2 text-xs text-text-muted">
              No table in this system records which event staled which memory. What the server
              computes is which currently-stale memories an event&rsquo;s provenance selector{" "}
              <em>matches</em>, using the same predicate{" "}
              <code className="font-mono">workers/invalidator.py</code> judges dependents with.
              A memory legitimately appears under every event whose selector matches it, and a
              memory staled by an event outside this page&rsquo;s window matches nothing here.
              Read a match as &ldquo;this memory depends on the thing that changed&rdquo;, never
              as &ldquo;this event staled it&rdquo;.
            </p>
            <p className="mt-2 text-xs text-text-muted">
              Revalidation age R for this response is{" "}
              <span className="font-mono text-text">{formatInt(report.r_days)} days</span>,
              reported by the server rather than assumed by this page.
            </p>
            {(overInvalidationCount > 0 || pastRCount > 0) && (
              <div className="mt-3 space-y-1 border-t border-border pt-2 text-xs">
                {overInvalidationCount > 0 && (
                  <p className="text-status-quarantined-fg">
                    {formatInt(overInvalidationCount)} event(s) of a type that is meant to reach
                    memories match no currently-stale memory. Either their selectors match
                    nothing in this vault, or the memories they reached have since moved on from{" "}
                    <code className="font-mono">stale</code> &mdash; worth checking before
                    assuming invalidation is working.
                  </p>
                )}
                {pastRCount > 0 && (
                  <p className="text-status-quarantined-fg">
                    {formatInt(pastRCount)} validated memory(ies) are already past R=
                    {formatInt(report.r_days)} days idle and have not been revalidated &mdash;
                    possible under-invalidation (the revalidation worker did not fire when it
                    should have).
                  </p>
                )}
              </div>
            )}
          </section>

          <section>
            <h2 className="mb-3 text-sm font-semibold text-text">Invalidation events</h2>
            {report.invalidation_events.length === 0 ? (
              <EmptyState
                title="No invalidation event recorded for this project"
                description="No invalidation_event row exists in this page of results. Expected for a young project, or for one with no invalidation webhook or poller configured — but note that this is also what a silently unwired invalidation source looks like, so an empty table here is not by itself evidence that nothing has changed."
              />
            ) : (
              <>
                <p className="mb-2 text-xs text-text-faint">
                  Showing {formatInt(report.event_returned)} event(s) from offset{" "}
                  {formatInt(report.event_offset)}
                  {report.event_returned >= report.event_limit &&
                    ` — this is a full page of ${formatInt(report.event_limit)}, so older events exist beyond it`}
                  .
                </p>
                <EventsTable events={report.invalidation_events} />
              </>
            )}
          </section>

          <section>
            <h2 className="mb-3 text-sm font-semibold text-text">
              Approaching (or past) revalidation age
            </h2>
            {report.approaching_revalidation.length === 0 ? (
              <EmptyState
                title="No validated memory is near its revalidation age"
                description={`Every validated memory in this project has been retrieved (or created) recently enough to sit well under R=${formatInt(report.r_days)} days idle. This is the healthy case, not an empty result.`}
              />
            ) : (
              <>
                <p className="mb-2 text-xs text-text-faint">
                  Showing {formatInt(report.approaching_returned)} memory(ies) from offset{" "}
                  {formatInt(report.approaching_offset)}
                  {report.approaching_returned >= report.approaching_limit &&
                    ` — this is a full page of ${formatInt(report.approaching_limit)}, so more exist beyond it`}
                  .
                </p>
                <ApproachingTable rows={report.approaching_revalidation} />
              </>
            )}
          </section>

          <section className="rounded-lg border border-border bg-surface p-4">
            <h2 className="text-sm font-semibold text-text">What is not on this page</h2>
            <ul className="mt-2 space-y-1.5 text-xs text-text-muted">
              <li>
                <strong className="font-medium text-text">
                  Which event actually staled a given memory.
                </strong>{" "}
                <code className="font-mono">workers/invalidator.py</code> transitions the row
                and writes no back-reference to the triggering event. Closing that would need a
                column the schema does not have.
              </li>
              <li>
                <strong className="font-medium text-text">
                  Memories already retired by the second strike.
                </strong>{" "}
                The matched-memory sets above are drawn from memories currently in{" "}
                <code className="font-mono">stale</code>. A memory that took its second strike
                has already left that status, so an event that retired something shows fewer
                matches, not more.
              </li>
            </ul>
          </section>
        </>
      )}
    </div>
  );
}
