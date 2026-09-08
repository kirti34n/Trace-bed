// Data-fetching hooks (task brief: "keep it dependency-light" — no
// react-query, no SWR; every view state a component needs — loading, error,
// empty, data — comes back from one of these two small generics plus the
// handful of named hooks built on top of them.
import { useCallback, useEffect, useRef, useState } from "react";
import {
  get,
  postJson,
  streamNdjson,
  ApiError,
} from "./client";
import type {
  AcceptedOut,
  ConfigOut,
  DemoManifestOut,
  ExportRow,
  ExportTable,
  FeedbackIn,
  InvalidationIn,
  InvalidationListOut,
  InjectionsOut,
  KillswitchStateOut,
  ConsolidationDiffsOut,
  LiftReportOut,
  MemoryItemOut,
  MemoryListOut,
  ProposeIn,
  RetrieveIn,
  RetrieveResult,
  ReviewQueueOut,
  ScopeOut,
  SpendOut,
  StalenessReportOut,
  Status,
  TraceIn,
} from "./types";

// --------------------------------------------------------------------- //
// useQuery — read-side. `status` is the one field every view branches on:
// EmptyState for "success" + empty data, ErrorState for "error", a skeleton
// for "loading" — no view is left to invent a fifth state.
// --------------------------------------------------------------------- //

export type QueryStatus = "idle" | "loading" | "success" | "error";

export interface QueryState<T> {
  status: QueryStatus;
  data: T | undefined;
  error: ApiError | undefined;
  reload: () => void;
}

/**
 * `key` identifies the REQUEST, not the hook. The effect deliberately depends
 * on `key` rather than on `fetcher`: a fetcher written inline in a component
 * is a new function object every render, so depending on it would refetch on
 * every keystroke. But without `key`, a hook whose parameters changed (e.g.
 * `useSpend(7)` -> `useSpend(30)`) would keep showing the FIRST window's rows
 * under the second window's label, which is a governance figure paired with
 * the wrong denominator. Named hooks below pass their parameters as `key`.
 */
export function useQuery<T>(
  fetcher: ((signal: AbortSignal) => Promise<T>) | null,
  key = ""
): QueryState<T> {
  const [status, setStatus] = useState<QueryStatus>(fetcher ? "loading" : "idle");
  const [data, setData] = useState<T | undefined>(undefined);
  const [error, setError] = useState<ApiError | undefined>(undefined);
  const [generation, setGeneration] = useState(0);
  const fetcherRef = useRef(fetcher);
  fetcherRef.current = fetcher;

  useEffect(() => {
    const activeFetcher = fetcherRef.current;
    if (activeFetcher === null) {
      setStatus("idle");
      return;
    }
    const controller = new AbortController();
    setStatus("loading");
    // A request-key change (cursor, scope, or server-side filter) must not
    // leave prior-page data rendered while the new page is in flight.
    setData(undefined);
    setError(undefined);
    activeFetcher(controller.signal)
      .then((result) => {
        setData(result);
        setStatus("success");
      })
      .catch((err: unknown) => {
        if (err instanceof ApiError && err.kind === "cancelled") return;
        setError(
          err instanceof ApiError ? err : new ApiError("network", "unknown error")
        );
        setStatus("error");
      });
    return () => controller.abort();
  }, [generation, key]);

  const reload = useCallback(() => setGeneration((g) => g + 1), []);

  return { status, data, error, reload };
}

// --------------------------------------------------------------------- //
// useMutation — write-side (the accepted data routes). Distinct from useQuery because a mutation never
// auto-fires and never auto-retries — it runs exactly when a component
// calls `mutate`.
// --------------------------------------------------------------------- //

export type MutationStatus = "idle" | "pending" | "success" | "error";

export interface MutationState<TInput, TOutput> {
  status: MutationStatus;
  data: TOutput | undefined;
  error: ApiError | undefined;
  mutate: (input: TInput) => Promise<TOutput>;
  reset: () => void;
}

export function useMutation<TInput, TOutput>(
  fn: (input: TInput, signal: AbortSignal) => Promise<TOutput>
): MutationState<TInput, TOutput> {
  const [status, setStatus] = useState<MutationStatus>("idle");
  const [data, setData] = useState<TOutput | undefined>(undefined);
  const [error, setError] = useState<ApiError | undefined>(undefined);
  const controllerRef = useRef<AbortController | null>(null);

  useEffect(() => () => controllerRef.current?.abort(), []);

  const mutate = useCallback(
    async (input: TInput): Promise<TOutput> => {
      controllerRef.current?.abort();
      const controller = new AbortController();
      controllerRef.current = controller;
      setStatus("pending");
      setError(undefined);
      try {
        const result = await fn(input, controller.signal);
        setData(result);
        setStatus("success");
        return result;
      } catch (err) {
        const apiErr = err instanceof ApiError ? err : new ApiError("network", "unknown error");
        setError(apiErr);
        setStatus("error");
        throw apiErr;
      }
    },
    [fn]
  );

  const reset = useCallback(() => {
    setStatus("idle");
    setData(undefined);
    setError(undefined);
  }, []);

  return { status, data, error, mutate, reset };
}

// --------------------------------------------------------------------- //
// Named hooks. Every one of these maps 1:1 to a route that actually exists
// (routes_v1.py / admin.py) — see README's "Contract gaps" for the views
// that have NO hook here because no route feeds them.
// --------------------------------------------------------------------- //

/** `GET /admin/memory/{memory_id}` — the ONLY memory read route (no list/search
 * endpoint exists). `id === null` means "nothing selected yet", not an error. */
export function useMemoryItem(id: string | null): QueryState<MemoryItemOut> {
  return useQuery<MemoryItemOut>(
    id === null
      ? null
      : (signal) => get<MemoryItemOut>(`/admin/memory/${id}`, { signal }),
    id ?? ""
  );
}

export interface ExportState {
  status: QueryStatus;
  rows: ExportRow[];
  /** True once `maxRows` was hit and streaming was stopped early — a view
   * MUST show this rather than silently presenting a partial vault as
   * complete (task brief: "empty must look deliberate, not broken" applies
   * equally to "truncated must look deliberate, not broken"). */
  truncated: boolean;
  error: ApiError | undefined;
  reload: () => void;
}

/**
 * `GET /export/project` (contract §9.3), filtered client-side to the
 * requested table(s) and capped at `maxRows` — this route has no query
 * params, no pagination and dumps every partitioned table for the whole
 * project in one NDJSON stream, so a view built on it MUST bound how much it
 * pulls into memory and MUST show `truncated` when it does. This is a
 * contract gap (no list/filter/paginate endpoint exists per table) worked
 * around at the one client boundary, not invented as a fake server capability.
 */
export function useExportRows(
  tables: readonly ExportTable[],
  maxRows = 5000
): ExportState {
  const [status, setStatus] = useState<QueryStatus>("loading");
  const [rows, setRows] = useState<ExportRow[]>([]);
  const [truncated, setTruncated] = useState(false);
  const [error, setError] = useState<ApiError | undefined>(undefined);
  const [generation, setGeneration] = useState(0);
  const tablesKey = tables.join(",");

  useEffect(() => {
    const controller = new AbortController();
    let active = true;
    setStatus("loading");
    setRows([]);
    setTruncated(false);
    setError(undefined);
    const wanted = new Set(tablesKey.length > 0 ? tablesKey.split(",") : []);

    (async () => {
      const collected: ExportRow[] = [];
      let reachedRowCap = false;
      for await (const envelope of streamNdjson<ExportRow>("/export/project", {
        signal: controller.signal,
      })) {
        if (wanted.size > 0 && !wanted.has(envelope.table)) continue;
        collected.push(envelope);
        if (collected.length >= maxRows) {
          reachedRowCap = true;
          // Closing both layers is intentional: the generator cancels its
          // reader as it unwinds, and the controller aborts the fetch body.
          controller.abort();
          break;
        }
      }
      if (!active) return;
      setRows(collected);
      setTruncated(reachedRowCap);
      setStatus("success");
    })().catch((err: unknown) => {
      if (!active || (err instanceof ApiError && err.kind === "cancelled")) return;
      // A rejected bound/completeness check must discard locally collected
      // rows: no partial export is ever a successful dashboard state.
      setRows([]);
      setTruncated(false);
      setError(err instanceof ApiError ? err : new ApiError("network", "unknown error"));
      setStatus("error");
    });

    return () => {
      active = false;
      controller.abort();
    };
  }, [tablesKey, maxRows, generation]);

  const reload = useCallback(() => setGeneration((g) => g + 1), []);
  return { status, rows, truncated, error, reload };
}

/** `POST /v1/retrieve` — sync, budgeted; useful for an operator "test this
 * agent_type's retrieval" console (Settings/Forensics), not a page load. */
export function useRetrieve(): MutationState<RetrieveIn, RetrieveResult> {
  return useMutation((body, signal) => postJson<RetrieveResult>("/v1/retrieve", body, { signal }));
}

/** `POST /v1/trace` — fire-and-forget (202). */
export function useTrace(): MutationState<TraceIn, AcceptedOut> {
  return useMutation((body, signal) => postJson<AcceptedOut>("/v1/trace", body, { signal }));
}

/** `POST /v1/feedback` — fire-and-forget (202). */
export function useFeedback(): MutationState<FeedbackIn, AcceptedOut> {
  return useMutation((body, signal) => postJson<AcceptedOut>("/v1/feedback", body, { signal }));
}

/** `POST /v1/propose_memory` — fire-and-forget (202), agent_control mode. */
export function useProposeMemory(): MutationState<ProposeIn, AcceptedOut> {
  return useMutation((body, signal) => postJson<AcceptedOut>("/v1/propose_memory", body, { signal }));
}

/** `POST /v1/invalidation` — synchronous write of one invalidation_event row. */
export function useInvalidation(): MutationState<InvalidationIn, AcceptedOut> {
  return useMutation((body, signal) => postJson<AcceptedOut>("/v1/invalidation", body, { signal }));
}

// --------------------------------------------------------------------- //
// Control-plane reads (D-093). Each maps 1:1 to a route in api/admin.py and
// replaces a view that previously rendered a hand-authored fixture. All of
// them are GETs with no body, so the invariant-4 guard in client.ts has
// nothing to inspect — the guarantee here is structural instead: none of
// these functions has a parameter that could carry a project id.
// --------------------------------------------------------------------- //

/** `GET /admin/whoami` — the scope the server derived for this credential.
 * The dashboard cannot ask for a project; this is how it learns which one it
 * is looking at. */
export function useScope(): QueryState<ScopeOut> {
  return useQuery<ScopeOut>(
    (signal) => get<ScopeOut>("/admin/whoami", { signal }),
    "/admin/whoami"
  );
}

/** Optional public marker emitted only by the separately configured local
 * demo edge. A production 404 is intentionally rendered as no badge. */
export function useDemoManifest(): QueryState<DemoManifestOut> {
  return useQuery<DemoManifestOut>(
    (signal) => get<DemoManifestOut>("/auth/demo-manifest", { signal }),
    "/auth/demo-manifest"
  );
}

/** `GET /admin/memory` — a bounded, status-filtered page of memory_item rows.
 * Pass `statuses` to narrow; omit it to get every status including the ones
 * the hot path can never serve. */
export function useMemoryList(
  statuses: readonly Status[] | null,
  cursor: string | null,
  limit = 100
): QueryState<MemoryListOut> {
  const query = new URLSearchParams();
  if (statuses !== null) for (const s of statuses) query.append("status", s);
  query.set("limit", String(limit));
  if (cursor !== null) query.set("cursor", cursor);
  const path = `/admin/memory?${query.toString()}`;
  return useQuery<MemoryListOut>((signal) => get<MemoryListOut>(path, { signal }), path);
}

/** `GET /admin/injections` — newest-first page, never an exported project
 * dump. `offset` is explicit so the caller cannot mistake one page for the
 * complete feed. */
export function useInjections(limit = 100, offset = 0): QueryState<InjectionsOut> {
  const path = `/admin/injections?limit=${limit}&offset=${offset}`;
  return useQuery<InjectionsOut>((signal) => get<InjectionsOut>(path, { signal }), path);
}

/** `GET /admin/review_queue` — open items by default. Read-only: resolving an
 * item is a state-machine transition on the memory it points at, and no route
 * exists that would let this dashboard shortcut the machine. */
export function useReviewQueue(includeResolved = false, limit = 200): QueryState<ReviewQueueOut> {
  const path = `/admin/review_queue?include_resolved=${includeResolved ? "true" : "false"}&limit=${limit}`;
  return useQuery<ReviewQueueOut>((signal) => get<ReviewQueueOut>(path, { signal }), path);
}

/** `GET /admin/killswitch_state` — every recorded kill-switch decision.
 * An EMPTY list means no decision has ever been recorded, NOT that everything
 * is enabled; consumers must render that distinction. */
export function useKillswitchState(): QueryState<KillswitchStateOut> {
  return useQuery<KillswitchStateOut>(
    (signal) => get<KillswitchStateOut>("/admin/killswitch_state", { signal }),
    "/admin/killswitch_state"
  );
}

/** `GET /admin/invalidations` — invalidation_event rows, newest first. */
export function useInvalidations(limit = 200): QueryState<InvalidationListOut> {
  const path = `/admin/invalidations?limit=${limit}`;
  return useQuery<InvalidationListOut>((signal) => get<InvalidationListOut>(path, { signal }), path);
}

/** `GET /admin/spend` — this project's spend_ledger cells for a window that
 * travels back with the rows, so a total can never be shown without it. */
export function useSpend(days = 30): QueryState<SpendOut> {
  const path = `/admin/spend?days=${days}`;
  return useQuery<SpendOut>((signal) => get<SpendOut>(path, { signal }), path);
}

/** `GET /admin/config` — the two STORED override layers, not the resolved
 * config (process defaults live in the server's environment). */
export function useProjectConfig(): QueryState<ConfigOut> {
  return useQuery<ConfigOut>(
    (signal) => get<ConfigOut>("/admin/config", { signal }),
    "/admin/config"
  );
}

export function useLiftReport(): QueryState<LiftReportOut> {
  return useQuery<LiftReportOut>(
    (signal) => get<LiftReportOut>("/admin/lift/report", { signal }),
    "/admin/lift/report"
  );
}

export function useStalenessReport(): QueryState<StalenessReportOut> {
  return useQuery<StalenessReportOut>(
    (signal) => get<StalenessReportOut>("/admin/staleness/report", { signal }),
    "/admin/staleness/report"
  );
}

export function useConsolidationDiffs(limit = 200, offset = 0): QueryState<ConsolidationDiffsOut> {
  const path = `/admin/consolidation/diffs?limit=${limit}&offset=${offset}`;
  return useQuery<ConsolidationDiffsOut>((signal) => get<ConsolidationDiffsOut>(path, { signal }), path);
}
