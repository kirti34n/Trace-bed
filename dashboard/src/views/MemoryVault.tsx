import { useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useExportRows } from "../api/hooks";
import type { ColumnDef } from "../components/Table";
import { Table } from "../components/Table";
import { StatusBadge, TrustTierBadge } from "../components/StatusBadge";
import { EmptyState } from "../components/EmptyState";
import { ErrorState } from "../components/ErrorState";
import {
  LANES,
  MEM_TYPES,
  RETRIEVABLE_STATUSES,
  SCOPE_TYPES,
  STATUSES,
  TRUST_TIERS,
} from "../api/types";
import type {
  ExportRow,
  Lane,
  MemType,
  MemoryItemExportRow,
  ScopeType,
  Status,
  TrustTier,
} from "../api/types";
import { formatDateTime, formatFloat, formatRelativeTime, truncateId } from "../lib/format";

// contract_gap: Repo.list_memories (PHASE0-CONTRACT.md §5.1) is never exposed
// over HTTP — GET /admin/memory/{id} is by-id only, and no route filters or
// paginates memory_item. This view is built against the closest REAL data
// available: GET /export/project's memory_item rows via useExportRows. That
// makes it an honest project *snapshot* (capped at MAX_ROWS, flagged
// `truncated`), not a live paginated/filtered feed — every filter below runs
// client-side over whatever rows the cap let through, never the full vault.
// A real Repo.list_memories-backed route would let filters run server-side
// and remove the cap entirely; until then this is the documented workaround,
// not a fabricated endpoint (task brief rule 2).
const MAX_ROWS = 4000;

type AgeOption = "any" | "24h" | "7d" | "30d" | "90d";
const AGE_OPTIONS: { value: AgeOption; label: string }[] = [
  { value: "any", label: "Any time" },
  { value: "24h", label: "Last 24h" },
  { value: "7d", label: "Last 7 days" },
  { value: "30d", label: "Last 30 days" },
  { value: "90d", label: "Last 90 days" },
];

/** Narrows the select's `string` value without a cast, so adding an option to
 * AGE_OPTIONS without adding it to AgeOption fails loudly instead of silently
 * becoming a filter that matches nothing. */
function parseAgeOption(raw: string): AgeOption {
  const match = AGE_OPTIONS.find((o) => o.value === raw);
  return match?.value ?? "any";
}

function ageCutoffMs(age: AgeOption): number | null {
  const hour = 3_600_000;
  switch (age) {
    case "24h":
      return Date.now() - 24 * hour;
    case "7d":
      return Date.now() - 7 * 24 * hour;
    case "30d":
      return Date.now() - 30 * 24 * hour;
    case "90d":
      return Date.now() - 90 * 24 * hour;
    default:
      return null;
  }
}

/** An emptied or half-typed number input yields "" / "-" — `Number()` turns
 * those into 0/NaN, and a NaN bound silently filters every row away with no
 * visible cause. */
function clampUnit(raw: string, fallback: number): number {
  const parsed = Number(raw);
  if (raw.trim() === "" || Number.isNaN(parsed)) return fallback;
  return Math.min(1, Math.max(0, parsed));
}

function memoryItemRows(all: ExportRow[]): MemoryItemExportRow[] {
  const out: MemoryItemExportRow[] = [];
  for (const entry of all) {
    if (entry.table === "memory_item") out.push(entry.row);
  }
  return out;
}

function toggled<T>(set: Set<T>, value: T): Set<T> {
  const next = new Set(set);
  if (next.has(value)) next.delete(value);
  else next.add(value);
  return next;
}

/** PLAN.md §5: "Retrievable statuses: validated, candidate (Tier A only,
 * labeled lower-trust, cap 1/run), pinned (prefix only)." A Tier B row that
 * has left quarantine into `candidate` is NOT servable — counting it as
 * retrievable would tell an operator that unpromoted content-derived material
 * is already reaching prompts, which is the opposite of true. */
function isRetrievableNow(row: MemoryItemExportRow): boolean {
  if (!RETRIEVABLE_STATUSES.has(row.status)) return false;
  return !(row.status === "candidate" && row.trust_tier === "B");
}

/** Q starts at `scoring.q_start` (0.5) and only moves on an unambiguous
 * outcome (invariant 8). With zero scored uses the number on the row is the
 * seed, not a measurement — rendering it as a bare "0.50" next to a Q earned
 * over 40 outcomes is the point-estimate-without-its-N failure this console
 * exists to prevent, so N travels with the value everywhere. */
function ScoredValue({
  value,
  n,
  unscoredHint,
}: {
  value: number;
  n: number;
  unscoredHint: string;
}) {
  if (n === 0) {
    return (
      <span className="text-text-faint" title={unscoredHint}>
        {formatFloat(value)}
        <span className="ml-1 text-[10px] uppercase tracking-wide">unscored</span>
      </span>
    );
  }
  return (
    <span title={`${formatFloat(value, 3)} over n=${n} scored use${n === 1 ? "" : "s"}`}>
      {formatFloat(value)}
      <span className="ml-1 text-[10px] text-text-faint">n={n}</span>
    </span>
  );
}

/** Every headline count here is computed over a capped export snapshot, so
 * when the cap bound it is a LOWER BOUND, not a total — it renders as "≥ N".
 * Before the stream resolves it renders "—", never "0": a placeholder zero on
 * a "Quarantined Tier B" tile reads as "you have none", which is a claim this
 * view has not yet earned the right to make. */
function CountTile({
  label,
  value,
  loaded,
  truncated,
  tone = "neutral",
  hint,
}: {
  label: string;
  value: number;
  loaded: boolean;
  truncated: boolean;
  tone?: "neutral" | "quarantined";
  hint?: string;
}) {
  const quarantined = tone === "quarantined";
  return (
    <div
      className={
        "rounded-lg border px-4 py-3 " +
        (quarantined
          ? "border-status-quarantined-border/60 bg-status-quarantined-bg/40"
          : "border-border bg-surface")
      }
    >
      <p
        className={
          "text-xs font-medium uppercase tracking-wide " +
          (quarantined ? "text-status-quarantined-fg" : "text-text-muted")
        }
        title={hint}
      >
        {label}
      </p>
      <p
        className={
          "mt-1 text-2xl font-semibold tabular-nums " +
          (quarantined ? "text-status-quarantined-fg" : "text-text")
        }
      >
        {loaded ? `${truncated ? "≥ " : ""}${value.toLocaleString()}` : "—"}
      </p>
      {loaded && truncated && (
        <p className="mt-0.5 text-[10px] uppercase tracking-wide text-text-faint">
          lower bound — snapshot capped
        </p>
      )}
      {hint !== undefined && <p className="mt-1 text-[11px] leading-snug text-text-muted">{hint}</p>}
    </div>
  );
}

function CheckGlyph() {
  return (
    <svg viewBox="0 0 20 20" fill="currentColor" aria-hidden="true" className="h-3 w-3 shrink-0">
      <path
        fillRule="evenodd"
        d="M16.7 5.3a1 1 0 0 1 0 1.4l-7.5 7.5a1 1 0 0 1-1.42 0l-3.5-3.5a1 1 0 0 1 1.42-1.4l2.79 2.78 6.79-6.78a1 1 0 0 1 1.42 0Z"
        clipRule="evenodd"
      />
    </svg>
  );
}

function WarningGlyph() {
  return (
    <svg viewBox="0 0 20 20" fill="currentColor" aria-hidden="true" className="h-3 w-3 shrink-0">
      <path
        fillRule="evenodd"
        d="M8.257 3.099c.765-1.36 2.72-1.36 3.486 0l6.28 11.18c.75 1.334-.213 2.98-1.742 2.98H3.72c-1.53 0-2.492-1.646-1.743-2.98l6.28-11.18ZM11 13a1 1 0 1 1-2 0 1 1 0 0 1 2 0Zm-1-8a1 1 0 0 0-1 1v3a1 1 0 1 0 2 0V6a1 1 0 0 0-1-1Z"
        clipRule="evenodd"
      />
    </svg>
  );
}

interface ChipGroupProps<T extends string> {
  legend: string;
  options: readonly T[];
  selected: Set<T>;
  onToggle: (value: T) => void;
}

function ChipGroup<T extends string>({ legend, options, selected, onToggle }: ChipGroupProps<T>) {
  return (
    <fieldset className="space-y-1.5">
      <legend className="text-xs font-semibold uppercase tracking-wide text-text-muted">{legend}</legend>
      <div className="flex flex-wrap gap-1.5">
        {options.map((opt) => {
          const active = selected.has(opt);
          return (
            <button
              key={opt}
              type="button"
              aria-pressed={active}
              onClick={() => onToggle(opt)}
              className={
                // Selection is encoded twice — a check glyph and a heavier
                // border — never by colour alone (task brief: accessibility).
                "inline-flex items-center gap-1 rounded-full border px-2.5 py-1 text-xs font-medium transition-colors " +
                (active
                  ? "border-2 border-accent bg-accent/10 text-accent"
                  : "border border-dashed border-border-strong text-text-muted hover:bg-surface-raised hover:text-text")
              }
            >
              {active ? <CheckGlyph /> : null}
              {opt}
            </button>
          );
        })}
      </div>
    </fieldset>
  );
}

export default function MemoryVault() {
  const navigate = useNavigate();
  const { status, rows, truncated, error, reload } = useExportRows(["memory_item"], MAX_ROWS);
  const allMemories = useMemo(() => memoryItemRows(rows), [rows]);

  const [statuses, setStatuses] = useState<Set<Status>>(new Set(STATUSES));
  const [tiers, setTiers] = useState<Set<TrustTier>>(new Set(TRUST_TIERS));
  const [memTypes, setMemTypes] = useState<Set<MemType>>(new Set(MEM_TYPES));
  const [lanes, setLanes] = useState<Set<Lane>>(new Set(LANES));
  const [scopeTypes, setScopeTypes] = useState<Set<ScopeType>>(new Set(SCOPE_TYPES));
  const [minQ, setMinQ] = useState(0);
  const [maxQ, setMaxQ] = useState(1);
  const [age, setAge] = useState<AgeOption>("any");
  const [search, setSearch] = useState("");

  const filtered = useMemo(() => {
    const cutoff = ageCutoffMs(age);
    const term = search.trim().toLowerCase();
    return allMemories.filter((m) => {
      if (!statuses.has(m.status)) return false;
      if (!tiers.has(m.trust_tier)) return false;
      if (!memTypes.has(m.mem_type)) return false;
      if (!lanes.has(m.lane)) return false;
      if (!scopeTypes.has(m.scope_type)) return false;
      if (m.q_value < minQ || m.q_value > maxQ) return false;
      if (cutoff !== null && new Date(m.created_at).getTime() < cutoff) return false;
      if (term.length > 0 && !m.content.toLowerCase().includes(term)) return false;
      return true;
    });
  }, [allMemories, statuses, tiers, memTypes, lanes, scopeTypes, minQ, maxQ, age, search]);

  const quarantinedTierBCount = useMemo(
    () => filtered.filter((m) => m.status === "quarantined" && m.trust_tier === "B").length,
    [filtered]
  );
  const retrievableCount = useMemo(() => filtered.filter(isRetrievableNow).length, [filtered]);
  const loaded = status === "success";

  function resetFilters() {
    setStatuses(new Set(STATUSES));
    setTiers(new Set(TRUST_TIERS));
    setMemTypes(new Set(MEM_TYPES));
    setLanes(new Set(LANES));
    setScopeTypes(new Set(SCOPE_TYPES));
    setMinQ(0);
    setMaxQ(1);
    setAge("any");
    setSearch("");
  }

  const columns: ColumnDef<MemoryItemExportRow>[] = [
    {
      key: "content",
      header: "Content",
      render: (row) => (
        <div className="flex max-w-md flex-col gap-1 py-0.5">
          <span
            className={
              "line-clamp-2 " + (row.status === "quarantined" ? "font-mono text-text-muted" : "text-text")
            }
          >
            {row.content}
          </span>
          {/* Every quarantined row gets this, not only Tier B ones: a Tier A
              memory pushed back into quarantine by a scan re-flag is just as
              unservable, and a warning that appears on some quarantined rows
              but not others teaches operators the absence means "safe". */}
          {row.status === "quarantined" && (
            <span className="inline-flex w-fit items-center gap-1 rounded border border-status-quarantined-border bg-status-quarantined-bg px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-status-quarantined-fg">
              <WarningGlyph />
              {row.trust_tier === "B"
                ? "Unconfirmed content-derived — do not treat as fact"
                : "Quarantined — do not treat as fact"}
            </span>
          )}
        </div>
      ),
      sortValue: (row) => row.content,
    },
    {
      key: "mem_type",
      header: "Type",
      width: "10ch",
      render: (row) => <span className="text-text-muted">{row.mem_type}</span>,
      sortValue: (row) => row.mem_type,
    },
    {
      key: "scope",
      header: "Scope",
      width: "16ch",
      render: (row) => (
        <span className="text-text-muted" title={row.scope_id ?? undefined}>
          {row.scope_type}
          {row.scope_id !== null ? ` · ${truncateId(row.scope_id, 6, 3)}` : ""}
        </span>
      ),
      sortValue: (row) => row.scope_type,
    },
    {
      key: "lane",
      header: "Lane",
      width: "10ch",
      render: (row) => <span className="text-text-muted">{row.lane}</span>,
      sortValue: (row) => row.lane,
    },
    {
      key: "trust_tier",
      header: "Tier",
      width: "9ch",
      render: (row) => <TrustTierBadge tier={row.trust_tier} />,
      sortValue: (row) => row.trust_tier,
    },
    {
      key: "status",
      header: "Status",
      width: "14ch",
      render: (row) => <StatusBadge status={row.status} />,
      sortValue: (row) => row.status,
    },
    {
      key: "q_value",
      header: "Q (n)",
      numeric: true,
      width: "13ch",
      render: (row) => (
        <ScoredValue
          value={row.q_value}
          n={row.scored_use_count}
          unscoredHint="No scored outcomes yet — this is the scoring.q_start seed (0.50), not a measured value."
        />
      ),
      // Unscored rows sort last in both directions: an unearned 0.50 must
      // never rank alongside a 0.50 measured over dozens of outcomes.
      sortValue: (row) => (row.scored_use_count === 0 ? null : row.q_value),
    },
    {
      key: "confidence",
      header: "Conf. (n)",
      numeric: true,
      width: "13ch",
      render: (row) => (
        <ScoredValue
          value={row.confidence}
          n={row.scored_use_count}
          unscoredHint="No scored outcomes yet — confidence has no observations behind it."
        />
      ),
      sortValue: (row) => (row.scored_use_count === 0 ? null : row.confidence),
    },
    {
      key: "strike_count",
      header: "Strikes",
      numeric: true,
      width: "8ch",
      render: (row) => row.strike_count,
      sortValue: (row) => row.strike_count,
    },
    {
      key: "pinned",
      header: "Pinned",
      width: "8ch",
      align: "center",
      render: (row) => (row.pinned ? "Yes" : "—"),
      sortValue: (row) => (row.pinned ? 1 : 0),
    },
    {
      key: "created_at",
      header: "Age",
      width: "12ch",
      render: (row) => <span title={formatDateTime(row.created_at)}>{formatRelativeTime(row.created_at)}</span>,
      sortValue: (row) => row.created_at,
    },
  ];

  if (status === "error") {
    return <ErrorState error={error} onRetry={reload} title="Couldn't load the vault snapshot" />;
  }

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-lg font-semibold text-text">Memory Vault</h1>
        <p className="mt-1 text-sm text-text-muted">
          Browse and filter every memory this project has learned. Quarantined rows are set in
          monospace and carry an explicit unconfirmed marker — never mistake a content-derived
          distillation awaiting corroboration for a validated fact. Q and confidence always travel
          with the number of scored uses behind them; a row with none shows “unscored”, because its
          0.50 is the seed, not a measurement.
        </p>
      </div>

      <div className="rounded-md border border-status-candidate-border/60 bg-status-candidate-bg/40 px-3 py-2 text-xs text-status-candidate-fg">
        No filtered/paginated memory list endpoint exists (PHASE0-CONTRACT.md §5.1's{" "}
        <code className="font-mono">Repo.list_memories</code> is never exposed over HTTP). This table is
        a snapshot of <code className="font-mono">GET /export/project</code>&apos;s{" "}
        <code className="font-mono">memory_item</code> rows, capped at {MAX_ROWS.toLocaleString()} and
        filtered client-side — not a live server-side filter.
        {truncated && (
          <>
            {" "}
            <strong>The cap was reached:</strong> older or lower-priority rows beyond the cap are not
            represented below.
          </>
        )}
      </div>

      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <CountTile label="In snapshot" value={allMemories.length} loaded={loaded} truncated={truncated} />
        <CountTile label="Matching filters" value={filtered.length} loaded={loaded} truncated={truncated} />
        <CountTile
          label="Quarantined Tier B"
          value={quarantinedTierBCount}
          loaded={loaded}
          truncated={truncated}
          tone="quarantined"
        />
        <CountTile
          label="Retrievable now"
          value={retrievableCount}
          loaded={loaded}
          truncated={truncated}
          hint="validated, pinned, and Tier A candidates only — a Tier B candidate has left quarantine but is still not servable (PLAN.md §5)."
        />
      </div>

      <div className="space-y-4 rounded-lg border border-border bg-surface p-4">
        <div className="flex items-center justify-between gap-2">
          <label className="flex-1 space-y-1">
            <span className="text-xs font-semibold uppercase tracking-wide text-text-muted">
              Search content
            </span>
            <input
              type="search"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Filter by substring…"
              className="w-full max-w-sm rounded-md border border-border-strong bg-bg px-3 py-1.5 text-sm text-text placeholder:text-text-faint"
            />
          </label>
          <button
            type="button"
            onClick={resetFilters}
            className="rounded-md border border-border-strong px-3 py-1.5 text-sm font-medium text-text-muted transition-colors hover:bg-surface-raised hover:text-text"
          >
            Reset filters
          </button>
        </div>

        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          <ChipGroup legend="Status" options={STATUSES} selected={statuses} onToggle={(v) => setStatuses((s) => toggled(s, v))} />
          <ChipGroup legend="Trust tier" options={TRUST_TIERS} selected={tiers} onToggle={(v) => setTiers((s) => toggled(s, v))} />
          <ChipGroup legend="Memory type" options={MEM_TYPES} selected={memTypes} onToggle={(v) => setMemTypes((s) => toggled(s, v))} />
          <ChipGroup legend="Lane" options={LANES} selected={lanes} onToggle={(v) => setLanes((s) => toggled(s, v))} />
          <ChipGroup legend="Scope" options={SCOPE_TYPES} selected={scopeTypes} onToggle={(v) => setScopeTypes((s) => toggled(s, v))} />
          <fieldset className="space-y-1.5">
            <legend className="text-xs font-semibold uppercase tracking-wide text-text-muted">Created</legend>
            <select
              value={age}
              onChange={(e) => setAge(parseAgeOption(e.target.value))}
              className="w-full rounded-md border border-border-strong bg-bg px-2.5 py-1.5 text-sm text-text"
            >
              {AGE_OPTIONS.map((opt) => (
                <option key={opt.value} value={opt.value}>
                  {opt.label}
                </option>
              ))}
            </select>
          </fieldset>
          <fieldset className="space-y-1.5 sm:col-span-2">
            <legend className="text-xs font-semibold uppercase tracking-wide text-text-muted">Q value range</legend>
            <div className="flex items-center gap-2">
              <label className="flex items-center gap-1.5 text-sm text-text-muted">
                Min
                <input
                  type="number"
                  min={0}
                  max={1}
                  step={0.05}
                  value={minQ}
                  onChange={(e) => setMinQ(clampUnit(e.target.value, 0))}
                  className="w-20 rounded-md border border-border-strong bg-bg px-2 py-1 text-sm tabular-nums text-text"
                />
              </label>
              <label className="flex items-center gap-1.5 text-sm text-text-muted">
                Max
                <input
                  type="number"
                  min={0}
                  max={1}
                  step={0.05}
                  value={maxQ}
                  onChange={(e) => setMaxQ(clampUnit(e.target.value, 1))}
                  className="w-20 rounded-md border border-border-strong bg-bg px-2 py-1 text-sm tabular-nums text-text"
                />
              </label>
            </div>
            {minQ > maxQ && (
              <p role="status" className="text-xs text-status-quarantined-fg">
                Min is above max — no row can satisfy this range.
              </p>
            )}
            <p className="text-[11px] leading-snug text-text-muted">
              Filters on the stored Q, including rows with zero scored uses whose Q is still the
              0.50 seed.
            </p>
          </fieldset>
        </div>
      </div>

      {status === "success" && allMemories.length === 0 ? (
        <EmptyState
          title="No memories in this vault yet"
          description="This is expected for a young project — Tier A candidates and Tier B quarantined content appear here once traces have been distilled."
        />
      ) : status === "success" && filtered.length === 0 ? (
        <EmptyState
          title="No memories match these filters"
          description="Loosen a filter above — the snapshot has rows, none of them fit the current combination."
          action={{ label: "Reset filters", onClick: resetFilters }}
        />
      ) : (
        <Table
          caption="Memory vault rows filtered by status, tier, type, lane, scope, Q value and age"
          columns={columns}
          rows={filtered}
          getRowId={(row) => row.id}
          loading={status === "loading"}
          initialSort={{ key: "created_at", direction: "desc" }}
          onRowClick={(row) => navigate(`/memory-vault/${row.id}`)}
          maxHeight="65vh"
        />
      )}
    </div>
  );
}
