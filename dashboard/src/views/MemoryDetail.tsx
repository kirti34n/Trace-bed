import { useMemo, type ReactNode } from "react";
import { Link, useParams } from "react-router-dom";
import { useExportRows, useMemoryItem } from "../api/hooks";
import { StatusBadge, TrustTierBadge } from "../components/StatusBadge";
import { EmptyState } from "../components/EmptyState";
import { ErrorState } from "../components/ErrorState";
import type {
  ExportRow,
  InjectionLogExportRow,
  MemoryItemExportRow,
  MemoryItemOut,
  OutcomeEventExportRow,
  Status,
  TraceIndexExportRow,
} from "../api/types";
import { formatDateTime, formatFloat, formatRelativeTime, truncateId } from "../lib/format";

// Two REAL data sources, and nothing else:
//   - `useMemoryItem(id)` — GET /admin/memory/{id}, the one real by-id route.
//   - `useExportRows([...])` — GET /export/project, cross-referenced by
//     memory_id / run_id to recover provenance source traces, shadow-
//     confirmation independence, and injection/outcome history.
//
// Status-transition history, Q-over-time, and memory_link relations have NO
// backing route (contract gaps, listed inline at each site). They are rendered
// as an explicit absence — never as a plausible-looking reconstruction. An
// invented Q trajectory drawn as a line, or a transition timeline carrying
// synthesised timestamps that `formatDateTime` renders identically to the one
// real one, is indistinguishable from evidence at a glance; in a console whose
// job is deciding whether to trust what the vault learned, that is worse than
// showing nothing.

const MAX_ENRICHMENT_ROWS = 4000;

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
function traceIndexRowsOf(all: ExportRow[]): TraceIndexExportRow[] {
  const out: TraceIndexExportRow[] = [];
  for (const entry of all) {
    if (entry.table === "trace_index") out.push(entry.row);
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
function outcomeEventRowsOf(all: ExportRow[]): OutcomeEventExportRow[] {
  const out: OutcomeEventExportRow[] = [];
  for (const entry of all) {
    if (entry.table === "outcome_event") out.push(entry.row);
  }
  return out;
}

interface ConfirmationRow {
  run_id: string;
  principal_id: string;
  input_signature_hash: string;
}

/** Greedy approximation of state_machine.py's `independent_confirmations`:
 * the real predicate treats two signatures as one cluster at Hamming distance
 * <= 8 on the trailing 8 simhash bytes (domain/signatures.py's `same_cluster`),
 * which cannot be reproduced client-side without porting that bit-level
 * function. Treating two hashes as same-cluster only when byte-identical is
 * conservative — it can only UNDER-count independence, never claim a
 * confirmation the server would reject. */
function conservativeIndependentCount(confirmations: ConfirmationRow[]): number {
  const usedPrincipals = new Set<string>();
  const usedHashes = new Set<string>();
  let count = 0;
  for (const c of confirmations) {
    if (usedPrincipals.has(c.principal_id) || usedHashes.has(c.input_signature_hash)) continue;
    usedPrincipals.add(c.principal_id);
    usedHashes.add(c.input_signature_hash);
    count += 1;
  }
  return count;
}

/** The edges PLAN.md §5's transition table allows INTO each status. This is a
 * statement about the state machine, not about this row: it tells an operator
 * which paths could have produced the status they are looking at, without
 * inventing which one did or when. */
const INCOMING_EDGES: Record<Status, string[]> = {
  quarantined: [
    "insert — Tier B (distiller or proposal), scan passed, provenance complete",
    "candidate → quarantined — contradiction with weaker provenance, or scan re-flag",
  ],
  candidate: [
    "insert — Tier A parser output, scan passed, provenance complete",
    "quarantined → candidate — shadow-confirmed (≥2 independent runs; 1 for failure lessons) or verified-human-verdict provenance",
  ],
  validated: [
    "candidate → validated — promotion predicate met (outcomes, ≥2 distinct principals, scan re-pass, no open contradiction)",
    "stale → validated — re-verification pass",
    "archived → validated — operator restore (recoverable, logged)",
  ],
  superseded: ["validated → superseded — contradicted by equal or stronger provenance (link kept)"],
  stale: [
    "validated → stale — invalidation event, TTL-class expiry, or revalidation failure (strike 1)",
  ],
  retired: [
    "validated → retired — Q below threshold after ≥4 scored uses from ≥K distinct principals",
    "stale → retired — second strike",
  ],
  archived: [
    "quarantined → archived — quarantine TTL (30d) expired",
    "candidate → archived — candidate TTL (45d) unpromoted",
    "validated → archived — decay floor (0.15) reached",
  ],
  pinned: ["insert — operator-created preference (provenance class `operator`)"],
  tombstoned: [
    "any non-terminal → tombstoned — subject erasure (crypto-shred) or review-queue-approved delete",
  ],
};

function EnrichmentNotice({ truncated }: { truncated: boolean }) {
  return (
    <p className="text-xs text-text-faint">
      Cross-referenced from <code className="font-mono">GET /export/project</code> by id — a capped
      snapshot, not a dedicated route for this join.
      {truncated && (
        <>
          {" "}
          <strong className="text-status-quarantined-fg">
            The cap was reached, so anything below is a lower bound.
          </strong>
        </>
      )}
    </p>
  );
}

function GapNotice({ children }: { children: ReactNode }) {
  return (
    <div className="rounded-md border border-dashed border-border-strong bg-bg px-3 py-2.5 text-xs leading-relaxed text-text-muted">
      {children}
    </div>
  );
}

function SectionCard({ title, children, note }: { title: string; children: ReactNode; note?: string }) {
  return (
    <section className="rounded-lg border border-border bg-surface p-4">
      <h2 className="text-sm font-semibold text-text">{title}</h2>
      {note !== undefined && <p className="mt-0.5 text-xs text-text-muted">{note}</p>}
      <div className="mt-3">{children}</div>
    </section>
  );
}

function ProvenanceBlock({ provenance }: { provenance: MemoryItemOut["provenance"] }) {
  return (
    <dl className="grid grid-cols-[max-content_1fr] gap-x-4 gap-y-1.5 text-sm">
      <dt className="text-text-muted">Class</dt>
      <dd className="text-text">{provenance.class}</dd>
      {provenance.verdict_id !== undefined && (
        <>
          <dt className="text-text-muted">Verdict id</dt>
          <dd className="font-mono text-xs text-text" title={provenance.verdict_id}>
            {truncateId(provenance.verdict_id)}
          </dd>
        </>
      )}
      {provenance.run_id !== undefined && (
        <>
          <dt className="text-text-muted">Proposal run</dt>
          <dd className="font-mono text-xs text-text" title={provenance.run_id}>
            {truncateId(provenance.run_id)}
          </dd>
        </>
      )}
      {provenance.principal !== undefined && (
        <>
          <dt className="text-text-muted">Operator principal</dt>
          <dd className="font-mono text-xs text-text" title={provenance.principal}>
            {truncateId(provenance.principal)}
          </dd>
        </>
      )}
      {provenance.tool_refs !== undefined && provenance.tool_refs.length > 0 && (
        <>
          <dt className="text-text-muted">Tool refs</dt>
          <dd className="text-text">{provenance.tool_refs.join(", ")}</dd>
        </>
      )}
    </dl>
  );
}

export default function MemoryDetail() {
  const { id } = useParams<{ id: string }>();
  const memoryId = id ?? null;
  const item = useMemoryItem(memoryId);
  const enrichment = useExportRows(
    ["memory_item", "trace_index", "injection_log", "outcome_event"],
    MAX_ENRICHMENT_ROWS
  );

  const exportMemoryRow = useMemo((): MemoryItemExportRow | undefined => {
    if (memoryId === null) return undefined;
    return memoryItemRows(enrichment.rows).find((r) => r.id === memoryId);
  }, [enrichment.rows, memoryId]);

  const traceIndexRows = useMemo(() => traceIndexRowsOf(enrichment.rows), [enrichment.rows]);
  const injectionRows = useMemo((): InjectionLogExportRow[] => {
    if (memoryId === null) return [];
    return injectionLogRowsOf(enrichment.rows).filter((r) => r.memory_id === memoryId);
  }, [enrichment.rows, memoryId]);
  const outcomeRows = useMemo((): OutcomeEventExportRow[] => {
    const touchedRunIds = new Set(injectionRows.map((r) => r.run_id));
    if (touchedRunIds.size === 0) return [];
    return outcomeEventRowsOf(enrichment.rows).filter((r) => touchedRunIds.has(r.run_id));
  }, [enrichment.rows, injectionRows]);

  const provenanceTraceIds = useMemo(
    () => item.data?.provenance.trace_ids ?? [],
    [item.data]
  );
  const sourceTraces = useMemo((): TraceIndexExportRow[] => {
    const traceIds = new Set(provenanceTraceIds);
    if (traceIds.size === 0) return [];
    return traceIndexRows.filter((r) => traceIds.has(r.run_id));
  }, [traceIndexRows, provenanceTraceIds]);

  // A shadow_confirm_runs entry whose trace_index row fell outside the export
  // cap yields NO ConfirmationRow, which silently lowers the independence
  // count. The count is therefore always reported alongside how many confirming
  // runs could not be resolved — an operator must never read "1 of the 2
  // required confirmations" when the truth is "we could only see 1 of 4".
  const confirmationScan = useMemo((): {
    resolved: ConfirmationRow[];
    declared: number;
    unresolved: number;
  } => {
    const runIds = exportMemoryRow?.shadow_confirm_runs ?? [];
    const byRunId = new Map(traceIndexRows.map((r) => [r.run_id, r] as const));
    const resolved: ConfirmationRow[] = [];
    for (const runId of runIds) {
      const trace = byRunId.get(runId);
      if (trace === undefined) continue;
      resolved.push({
        run_id: runId,
        principal_id: trace.submitter_principal,
        input_signature_hash: trace.input_signature_hash,
      });
    }
    return { resolved, declared: runIds.length, unresolved: runIds.length - resolved.length };
  }, [exportMemoryRow, traceIndexRows]);

  if (memoryId === null) {
    return (
      <EmptyState
        title="No memory selected"
        description="Open this page from a row in Memory Vault, or navigate to /memory-vault/:id directly."
      />
    );
  }

  if (item.status === "loading" || item.status === "idle") {
    return (
      <div className="space-y-4">
        <p className="sr-only" role="status">
          Loading memory {memoryId}
        </p>
        <div className="h-6 w-1/2 animate-pulse rounded bg-border" />
        <div className="h-32 animate-pulse rounded-lg bg-border" />
        <div className="h-48 animate-pulse rounded-lg bg-border" />
      </div>
    );
  }

  if (item.status === "error" || item.data === undefined) {
    return <ErrorState error={item.error} onRetry={item.reload} title="Couldn't load this memory" />;
  }

  const row = item.data;
  const confirmations = confirmationScan.resolved;
  const independentCount = conservativeIndependentCount(confirmations);
  const isQuarantined = row.status === "quarantined";
  const isQuarantinedTierB = isQuarantined && row.trust_tier === "B";
  const enrichmentLoading = enrichment.status === "loading";
  const enrichmentFailed = enrichment.status === "error";

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between gap-4">
        <div className="min-w-0 space-y-2">
          <div className="flex flex-wrap items-center gap-2">
            <StatusBadge status={row.status} />
            <TrustTierBadge tier={row.trust_tier} />
            <span className="text-xs text-text-faint">
              {row.mem_type} · {row.lane} · {row.scope_type}
            </span>
          </div>
          {/* Quarantined content is framed as quarantined content: the border,
              the label and the icon all sit around the text itself, so the
              sentence cannot be read out of its governance context. */}
          {isQuarantined ? (
            <div className="max-w-2xl rounded-md border-2 border-dashed border-status-quarantined-border bg-status-quarantined-bg/40 p-3">
              <p className="flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wide text-status-quarantined-fg">
                <svg viewBox="0 0 20 20" fill="currentColor" aria-hidden="true" className="h-3.5 w-3.5 shrink-0">
                  <path
                    fillRule="evenodd"
                    d="M8.257 3.099c.765-1.36 2.72-1.36 3.486 0l6.28 11.18c.75 1.334-.213 2.98-1.742 2.98H3.72c-1.53 0-2.492-1.646-1.743-2.98l6.28-11.18ZM11 13a1 1 0 1 1-2 0 1 1 0 0 1 2 0Zm-1-8a1 1 0 0 0-1 1v3a1 1 0 1 0 2 0V6a1 1 0 0 0-1-1Z"
                    clipRule="evenodd"
                  />
                </svg>
                Quarantined — unverified, not retrievable, do not treat as fact
              </p>
              <p className="mt-2 text-base text-text">{row.content}</p>
              <p className="mt-2 text-xs text-status-quarantined-fg">
                {isQuarantinedTierB
                  ? "Content-derived (Tier B) and not yet corroborated by independent runs."
                  : "Held out of retrieval pending the quarantined → candidate guard."}
              </p>
            </div>
          ) : (
            <p className="max-w-2xl text-base text-text">{row.content}</p>
          )}
        </div>
        <Link
          to="/memory-vault"
          className="shrink-0 rounded-md border border-border-strong px-3 py-1.5 text-sm font-medium text-text-muted hover:bg-surface-raised hover:text-text"
        >
          Back to vault
        </Link>
      </div>

      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <ScoredTile
          label="Q value"
          value={row.q_value}
          n={row.scored_use_count}
          unscoredNote="Seed value (scoring.q_start) — no unambiguous outcome has moved it yet."
        />
        <ScoredTile
          label="Confidence"
          value={row.confidence}
          n={row.scored_use_count}
          unscoredNote="No scored observations behind this figure yet."
        />
        <PlainTile label="Scored uses" value={String(row.scored_use_count)} note="The N behind Q and confidence." />
        <PlainTile label="Strikes" value={String(row.strike_count)} note="Two strikes retire a stale memory." />
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <SectionCard title="Provenance">
          <ProvenanceBlock provenance={row.provenance} />
          <div className="mt-3 space-y-1 text-sm">
            <p className="text-text-muted">Scan verdict id</p>
            <p className="font-mono text-xs text-text" title={row.scan_verdict_id}>
              {truncateId(row.scan_verdict_id)}
            </p>
            <p className="text-xs text-text-faint">
              No route returns the full scan verdict (reasons, suite_version, issued_at) — only this
              id, stamped on the row at insert, is visible (contract gap).
            </p>
          </div>
        </SectionCard>

        <SectionCard
          title="Source traces"
          note="Provenance trace_ids cross-referenced against trace_index export rows."
        >
          {enrichmentLoading ? (
            <p className="text-sm text-text-faint" role="status">
              Loading export snapshot…
            </p>
          ) : enrichmentFailed ? (
            <ErrorState
              error={enrichment.error}
              onRetry={enrichment.reload}
              title="Couldn't load the export snapshot"
            />
          ) : provenanceTraceIds.length === 0 ? (
            <EmptyState
              bordered={false}
              title="This row's provenance carries no trace_ids"
              description="A real fact from GET /admin/memory/{id}, not a lookup that failed."
            />
          ) : (
            <>
              <p className="mb-2 text-xs text-text-muted">
                Resolved{" "}
                <span className="font-semibold tabular-nums text-text">{sourceTraces.length}</span>{" "}
                of <span className="font-semibold tabular-nums text-text">{provenanceTraceIds.length}</span>{" "}
                declared source traces in this snapshot.
              </p>
              {sourceTraces.length === 0 ? (
                <EmptyState
                  bordered={false}
                  title="None of the declared source traces are in this snapshot"
                  description="Their trace_index rows fell outside the export cap — this is a visibility limit, not evidence that they are missing."
                />
              ) : (
                <ul className="space-y-2 text-sm">
                  {sourceTraces.map((t) => (
                    <li key={t.run_id} className="rounded-md border border-border px-3 py-2">
                      <div className="flex items-center justify-between gap-2">
                        <span className="font-mono text-xs text-text" title={t.run_id}>
                          {truncateId(t.run_id)}
                        </span>
                        <span className="text-xs text-text-muted">{t.outcome_status}</span>
                      </div>
                      <p className="mt-1 text-xs text-text-faint">
                        {t.started_at !== null ? formatDateTime(t.started_at) : "—"} · agent_type{" "}
                        {truncateId(t.agent_type_id, 6, 3)}
                      </p>
                    </li>
                  ))}
                </ul>
              )}
            </>
          )}
          <div className="mt-2">
            <EnrichmentNotice truncated={enrichment.truncated} />
          </div>
        </SectionCard>

        <SectionCard
          title="Shadow-confirmation state"
          note="quarantined → candidate requires ≥2 independent confirmations: distinct principals AND distinct input-signature clusters."
        >
          {enrichmentLoading ? (
            <p className="text-sm text-text-faint" role="status">
              Loading export snapshot…
            </p>
          ) : enrichmentFailed ? (
            <ErrorState
              error={enrichment.error}
              onRetry={enrichment.reload}
              title="Couldn't load the export snapshot"
            />
          ) : exportMemoryRow === undefined ? (
            <GapNotice>
              This row is not in the export snapshot (the cap was reached before it streamed), so its{" "}
              <code className="font-mono">shadow_confirm_runs</code> array cannot be read.{" "}
              <strong>No confirmation count is shown rather than a zero</strong> — the two are not the
              same claim. <code className="font-mono">GET /admin/memory/{"{id}"}</code> does not return
              this column.
            </GapNotice>
          ) : confirmationScan.declared === 0 ? (
            <EmptyState
              bordered={false}
              title="No shadow-confirming runs recorded"
              description="shadow_confirm_runs is empty on this row — a real fact from the export snapshot."
            />
          ) : (
            <>
              <p className="mb-2 text-sm text-text">
                Conservative independent-confirmation count:{" "}
                <span className="font-semibold tabular-nums">{independentCount}</span>{" "}
                <span className="text-text-muted">
                  (needs ≥2, or ≥1 for failure lessons; computed over {confirmations.length} of{" "}
                  {confirmationScan.declared} declared confirming runs)
                </span>
              </p>
              {confirmationScan.unresolved > 0 && (
                <p className="mb-2 rounded border border-status-quarantined-border/60 bg-status-quarantined-bg/40 px-2.5 py-1.5 text-xs text-status-quarantined-fg">
                  {confirmationScan.unresolved} confirming run
                  {confirmationScan.unresolved === 1 ? "" : "s"} could not be resolved to a trace_index
                  row in this snapshot. The count above is a floor and must not be read as "not yet
                  corroborated".
                </p>
              )}
              <ul className="space-y-1.5 text-xs">
                {confirmations.map((c) => (
                  <li
                    key={c.run_id}
                    className="flex items-center justify-between gap-2 rounded border border-border px-2.5 py-1.5"
                  >
                    <span className="font-mono text-text" title={c.run_id}>
                      run {truncateId(c.run_id, 6, 3)}
                    </span>
                    <span className="font-mono text-text-muted" title={c.principal_id}>
                      principal {truncateId(c.principal_id, 6, 3)}
                    </span>
                    <span className="font-mono text-text-muted" title={c.input_signature_hash}>
                      cluster {truncateId(c.input_signature_hash, 6, 3)}
                    </span>
                  </li>
                ))}
              </ul>
              <p className="mt-2 text-xs text-text-faint">
                Cluster equality shown here is exact-hash matching (a conservative stand-in for the
                server&apos;s Hamming-distance same_cluster predicate) — it can only undercount
                independence, never overstate it.
              </p>
            </>
          )}
        </SectionCard>

        <SectionCard title="Injection history" note="Real injection_log rows for this memory_id.">
          {enrichmentLoading ? (
            <p className="text-sm text-text-faint" role="status">
              Loading export snapshot…
            </p>
          ) : enrichmentFailed ? (
            <ErrorState
              error={enrichment.error}
              onRetry={enrichment.reload}
              title="Couldn't load the export snapshot"
            />
          ) : injectionRows.length === 0 ? (
            <EmptyState
              bordered={false}
              title={
                enrichment.truncated
                  ? "No injections found within the snapshot cap"
                  : "Never injected into a run"
              }
              description={
                enrichment.truncated
                  ? "The export cap was reached, so absence here is not proof of absence in the vault."
                  : "This is a real fact from the complete export snapshot, not a missing route."
              }
            />
          ) : (
            <ul className="space-y-1.5 text-xs">
              {injectionRows.map((inj) => (
                <li
                  key={`${inj.run_id}-${inj.memory_id}`}
                  className="flex items-center justify-between gap-2 rounded border border-border px-2.5 py-1.5"
                >
                  <span className="font-mono text-text" title={inj.run_id}>
                    run {truncateId(inj.run_id, 6, 3)}
                  </span>
                  <span className="text-text-muted">{inj.slot}</span>
                  <span className="tabular-nums text-text-muted">score {formatFloat(inj.score)}</span>
                  <span className="tabular-nums text-text-muted">{inj.tokens} tok</span>
                  <span className="text-text-faint" title={formatDateTime(inj.injected_at)}>
                    {formatRelativeTime(inj.injected_at)}
                  </span>
                </li>
              ))}
            </ul>
          )}
          <div className="mt-2">
            <EnrichmentNotice truncated={enrichment.truncated} />
          </div>
        </SectionCard>
      </div>

      <SectionCard
        title="Downstream outcomes on runs where this memory was injected"
        note="Real outcome_event rows joined by run_id. Co-occurrence, not attribution: these outcomes happened on runs this memory was in, which is not the same as this memory causing them."
      >
        {enrichmentLoading ? (
          <p className="text-sm text-text-faint" role="status">
            Loading export snapshot…
          </p>
        ) : enrichmentFailed ? (
          <ErrorState
            error={enrichment.error}
            onRetry={enrichment.reload}
            title="Couldn't load the export snapshot"
          />
        ) : outcomeRows.length === 0 ? (
          <EmptyState
            bordered={false}
            title="No outcome events on the runs this memory touched"
            description="Expected for a young project: outcome events arrive through FeedbackPort adapters and may lag their run by days."
          />
        ) : (
          <ul className="grid gap-1.5 text-xs sm:grid-cols-2">
            {outcomeRows.map((o) => (
              <li
                key={o.event_id}
                className="flex items-center justify-between gap-2 rounded border border-border px-2.5 py-1.5"
              >
                <span className="text-text-muted">{o.adapter}</span>
                <span className="tabular-nums text-text">r={formatFloat(o.r)}</span>
                <span className="text-text-faint" title={formatDateTime(o.occurred_at)}>
                  {formatRelativeTime(o.occurred_at)}
                </span>
              </li>
            ))}
          </ul>
        )}
      </SectionCard>

      <SectionCard
        title="Status"
        note="The current status and when it last changed are the only status facts any route exposes."
      >
        <div className="flex flex-wrap items-center gap-3">
          <StatusBadge status={row.status} />
          <span className="text-sm text-text">
            {row.status_changed_at !== null ? (
              <>
                since{" "}
                <span title={formatDateTime(row.status_changed_at)}>
                  {formatRelativeTime(row.status_changed_at)}
                </span>
              </>
            ) : (
              "status_changed_at is null on this row"
            )}
          </span>
          <span className="text-sm text-text-muted">
            created <span title={formatDateTime(row.created_at)}>{formatRelativeTime(row.created_at)}</span>
          </span>
        </div>

        <div className="mt-4 space-y-2">
          <p className="text-xs font-semibold uppercase tracking-wide text-text-muted">
            Transitions the state machine allows into “{row.status}”
          </p>
          <ul className="space-y-1 text-xs text-text-muted">
            {INCOMING_EDGES[row.status].map((edge) => (
              <li key={edge} className="rounded border border-border px-2.5 py-1.5">
                {edge}
              </li>
            ))}
          </ul>
          <p className="text-xs text-text-faint">
            These are the legal edges from PLAN.md §5&apos;s transition table — which one this row
            actually took, and when, is not recoverable: no status-history route or table exists
            (contract gap).
          </p>
        </div>
      </SectionCard>

      <div className="grid gap-4 lg:grid-cols-2">
        <SectionCard title="Q trajectory">
          <GapNotice>
            No route or table records historical Q values — only the current one. A trend line drawn
            from the current value backwards would be invented, and a line chart reads as measurement,
            so none is drawn. Current Q is{" "}
            <span className="font-semibold tabular-nums text-text">{formatFloat(row.q_value, 3)}</span>{" "}
            over{" "}
            <span className="font-semibold tabular-nums text-text">{row.scored_use_count}</span> scored
            use{row.scored_use_count === 1 ? "" : "s"}
            {row.scored_use_count === 0
              ? " — i.e. it is still the scoring.q_start seed and carries no evidence at all."
              : "."}
          </GapNotice>
        </SectionCard>

        <SectionCard title="Related and derived memories">
          <GapNotice>
            <code className="font-mono">memory_link</code> (PLAN.md §5) has no API surface at all — it
            is not in <code className="font-mono">GET /export/project</code>&apos;s five tables and no
            route reads it. Supersession, derivation and contradiction links therefore cannot be shown,
            and nothing is displayed in their place: an illustrative relation next to real provenance
            would be indistinguishable from one.
          </GapNotice>
        </SectionCard>
      </div>
    </div>
  );
}

function ScoredTile({
  label,
  value,
  n,
  unscoredNote,
}: {
  label: string;
  value: number;
  n: number;
  unscoredNote: string;
}) {
  const unscored = n === 0;
  return (
    <div
      className={
        "rounded-lg border px-4 py-3 " +
        (unscored ? "border-dashed border-border-strong bg-surface" : "border-border bg-surface")
      }
    >
      <p className="text-xs font-medium uppercase tracking-wide text-text-muted">{label}</p>
      <p
        className={
          "mt-1 text-2xl font-semibold tabular-nums " + (unscored ? "text-text-faint" : "text-text")
        }
      >
        {formatFloat(value)}
        <span className="ml-1.5 text-xs font-medium">{unscored ? "unscored" : `n=${n}`}</span>
      </p>
      {unscored && <p className="mt-1 text-[11px] leading-snug text-text-muted">{unscoredNote}</p>}
    </div>
  );
}

function PlainTile({ label, value, note }: { label: string; value: string; note?: string }) {
  return (
    <div className="rounded-lg border border-border bg-surface px-4 py-3">
      <p className="text-xs font-medium uppercase tracking-wide text-text-muted">{label}</p>
      <p className="mt-1 text-2xl font-semibold tabular-nums text-text">{value}</p>
      {note !== undefined && <p className="mt-1 text-[11px] leading-snug text-text-muted">{note}</p>}
    </div>
  );
}
