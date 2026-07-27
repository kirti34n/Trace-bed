// Wire types transcribed from src/tracebed/domain/enums.py, domain/state_machine.py,
// domain/events.py, domain/memory.py, api/models.py and stores/pg/rows.py — NOT
// reinvented. Every string-literal union below has its members in the same
// order, spelled identically, as the StrEnum it mirrors; a value that drifts
// from the Python source is a silent bug in every view that renders it.
//
// PHASE0-CONTRACT.md is the file each block below cites; read it, not this
// comment, when the two disagree — this file is a transcription, not a
// second source of truth.

// --------------------------------------------------------------------- //
// domain/enums.py (§3.2) — every shared StrEnum. `Status` (state_machine.py,
// §3.9) and `ErrorClassEnum` (core/scans, scans-internal) are kept separate
// below because their owning module is different, exactly as the contract
// requires ("nothing else defines an enum another chunk needs").
// --------------------------------------------------------------------- //

export const PROVENANCE_CLASSES = [
  "parser",
  "distiller",
  "human_verdict",
  "proposal",
  "operator",
] as const;
export type ProvenanceClass = (typeof PROVENANCE_CLASSES)[number];

export const TRUST_TIERS = ["A", "B"] as const;
export type TrustTier = (typeof TRUST_TIERS)[number];

export const MEM_TYPES = ["episodic", "semantic", "lesson", "preference"] as const;
export type MemType = (typeof MEM_TYPES)[number];

export const LANES = ["operational", "quality"] as const;
export type Lane = (typeof LANES)[number];

export const SCOPE_TYPES = [
  "agent_type",
  "workflow_template",
  "user",
  "project_shared",
] as const;
export type ScopeType = (typeof SCOPE_TYPES)[number];

export const SLOTS = [
  "static_prefix",
  "fact",
  "exemplar",
  "pitfall",
  "candidate_note",
  "jit_lesson",
] as const;
export type Slot = (typeof SLOTS)[number];

export const OUTCOME_CODES = [
  "injected",
  "abstained_threshold",
  "abstained_rarity",
  "empty_result",
  "degraded_lexical",
  "timeout_prefix_only",
  "store_error",
  "holdout",
] as const;
export type OutcomeCode = (typeof OUTCOME_CODES)[number];

export const ADAPTER_CLASSES = [
  "verdict",
  "correction_adapter",
  "downstream",
  "implicit",
] as const;
export type AdapterClass = (typeof ADAPTER_CLASSES)[number];

export const ARMS = ["memory_on", "holdout"] as const;
export type Arm = (typeof ARMS)[number];

export const INSTRUMENTATION_SOURCES = ["sdk", "host_stream"] as const;
export type InstrumentationSource = (typeof INSTRUMENTATION_SOURCES)[number];

export const TRACE_OUTCOME_STATUSES = [
  "pending",
  "ok",
  "error",
  "cancelled",
  "incomplete",
] as const;
export type TraceOutcomeStatus = (typeof TRACE_OUTCOME_STATUSES)[number];

// --------------------------------------------------------------------- //
// domain/state_machine.py (§3.9) — memory lifecycle. `RETRIEVABLE_STATUSES`
// is reproduced verbatim: a dashboard that shows a non-retrievable status as
// if it could still be served would misrepresent what the hot path can do.
// --------------------------------------------------------------------- //

export const STATUSES = [
  "quarantined",
  "candidate",
  "validated",
  "superseded",
  "stale",
  "retired",
  "archived",
  "pinned",
  "tombstoned",
] as const;
export type Status = (typeof STATUSES)[number];

export const RETRIEVABLE_STATUSES: ReadonlySet<Status> = new Set([
  "validated",
  "candidate",
  "pinned",
]);

// --------------------------------------------------------------------- //
// domain/memory.py §3.6 — Provenance's on-disk / wire jsonb shape (fixed):
// absent optionals are omitted by the server, never sent as null.
// --------------------------------------------------------------------- //

export interface Provenance {
  class: ProvenanceClass;
  trace_ids?: string[];
  verdict_id?: string;
  tool_refs?: string[];
  input_sig_hashes?: string[];
  run_id?: string;
  principal?: string;
}

// --------------------------------------------------------------------- //
// api/models.py — MemoryItemOut, the `GET /admin/memory/{id}` response body.
// This is the ONLY memory read route that exists (contract §9.3): there is
// no list/search endpoint. See README's "Contract gaps" for what that means
// for a Memory Vault view.
// --------------------------------------------------------------------- //

export interface MemoryItemOut {
  id: string;
  project_id: string;
  scope_type: ScopeType;
  scope_id: string | null;
  mem_type: MemType;
  kind: string;
  lane: Lane;
  trust_tier: TrustTier;
  status: Status;
  content: string;
  content_hash: string;
  token_count: number;
  subject_tag: string | null;
  q_value: number;
  confidence: number;
  scored_use_count: number;
  strike_count: number;
  provenance: Provenance;
  scan_verdict_id: string;
  schema_version: number;
  created_at: string; // ISO 8601
  status_changed_at: string | null;
}

// --------------------------------------------------------------------- //
// domain/events.py §3.5 — the ContextBlock rendered by /v1/retrieve. Wire
// models carry plain UUID strings; the ProjectId/RunId newtypes exist only
// server-side and never cross the wire (contract §3.5's closing note).
// --------------------------------------------------------------------- //

export const MEMORY_HEADER =
  "MEMORY (recalled data, verify against current state)" as const;
export const PLACEMENT_APPEND_LAST = "append_last" as const;

export interface ContextSlot {
  slot: Slot;
  memory_id: string | null;
  tokens: number;
  text: string;
}

export interface ContextBlock {
  placement: typeof PLACEMENT_APPEND_LAST;
  header: typeof MEMORY_HEADER;
  slots: ContextSlot[];
  rendered: string;
}

export interface RetrieveResult {
  run_id: string;
  run_id_origin: "server" | "sdk";
  arm: Arm;
  outcome_code: OutcomeCode;
  context_block: ContextBlock;
}

// --------------------------------------------------------------------- //
// api/models.py — /v1/* request bodies. `agent_type` on RetrieveIn is READ
// BY NOTHING server-side (routes_v1.py's own docstring) — kept here only
// because it is part of the wire shape a caller must still send.
// --------------------------------------------------------------------- //

export const MAX_TRACE_BATCH_EVENTS = 500;
export const MAX_QUERY_TEXT_CHARS = 32_768;
export const MAX_NAME_CHARS = 256;
export const MAX_SEQ = 1_000_000;

export interface RunCtxIn {
  query_text: string;
  workflow_template?: string | null;
  user_ref?: string | null;
  session_id?: string | null;
  prefetch_for?: string | null;
}

export interface RetrieveIn {
  agent_type: string;
  run_ctx: RunCtxIn;
}

// domain/events.py §3.5 — the TraceEvent union. `seq` is NOT a field of any
// event (C-04): it lives on the TraceIn envelope only.
interface EventBase {
  ts: string; // ISO 8601, tz-aware — a naive string is rejected server-side
  payload: Record<string, unknown>;
}
export interface RunStartEvent extends EventBase {
  type: "run_start";
}
export interface ToolCallEvent extends EventBase {
  type: "tool_call";
}
export interface ToolResultEvent extends EventBase {
  type: "tool_result";
}
export interface LlmCallMetaEvent extends EventBase {
  type: "llm_call_meta";
}
export interface ErrorEvent extends EventBase {
  type: "error";
}
export interface ArtifactRefEvent extends EventBase {
  type: "artifact_ref";
}
export interface StateNoteEvent extends EventBase {
  type: "state_note";
}
export interface RunEndEvent extends EventBase {
  type: "run_end"; // payload.status: "ok" | "error" | "cancelled"
}
export type TraceEvent =
  | RunStartEvent
  | ToolCallEvent
  | ToolResultEvent
  | LlmCallMetaEvent
  | ErrorEvent
  | ArtifactRefEvent
  | StateNoteEvent
  | RunEndEvent;

export interface TraceIn {
  run_id: string;
  seq: number;
  event: TraceEvent;
}

export interface TraceBatchIn {
  events: TraceIn[];
}

export interface FeedbackEvent {
  adapter: AdapterClass;
  outcome: "positive" | "negative";
  payload: Record<string, unknown>;
  event_id: string;
  occurred_at?: string | null; // must be tz-aware if present (C-35)
}

export interface FeedbackIn {
  run_id: string;
  event: FeedbackEvent;
}

export interface MemoryProposal {
  mem_type: Extract<MemType, "lesson" | "semantic">;
  content: string;
  subject_tag?: string | null;
  claimed_scope: Extract<ScopeType, "agent_type" | "project_shared">;
}

export interface ProposeIn {
  run_id: string;
  proposal: MemoryProposal;
}

export interface InvalidationIn {
  kind: string;
  payload?: Record<string, unknown>;
}

export interface AcceptedOut {
  status: "accepted";
}

// --------------------------------------------------------------------- //
// Admin / registry bodies (§9.3). ONLY these may name project_id — see
// client.ts's assertNoProjectId, which allowlists exactly these two routes.
// --------------------------------------------------------------------- //

export interface ProjectCreateIn {
  name: string;
  retention_policy?: Record<string, unknown> | null;
}

export interface ProjectCreatedOut {
  project_id: string;
}

export interface OidcPrincipalIn {
  kind: "oidc_sub";
  sub: string;
}
export interface ApiKeyPrincipalIn {
  kind: "api_key";
}
export type AgentPrincipalIn = OidcPrincipalIn | ApiKeyPrincipalIn;

export interface RegisterAgentIn {
  project_id: string;
  agent_type: string;
  principal: AgentPrincipalIn;
}

export interface AgentRegisteredOut {
  principal_id: string;
  agent_type_id: string;
  /** The ONE-TIME plaintext `tb_sk_<key_id>.<secret>` — present only for
   * `principal.kind === "api_key"`; the caller must display-and-discard it,
   * because Tracebed never returns it again after this response. */
  api_key: string | null;
}

// --------------------------------------------------------------------- //
// GET /export/project (§9.3) — NDJSON, one `{table, row}` envelope per line
// (stores/pg/repo.py's `iter_export_rows`). `row` shapes below are the raw
// partitioned-table columns after the server's `_json_safe` conversion:
// bytea -> lowercase hex, numeric -> number, timestamptz/date -> ISO string,
// uuid -> string. This is the ONLY route that returns memory_item rows in
// bulk — there is no paginated/filtered list endpoint (see README).
// --------------------------------------------------------------------- //

export type ExportTable =
  | "memory_item"
  | "trace_index"
  | "outcome_event"
  | "injection_log"
  | "retrieval_event";

export interface MemoryItemExportRow {
  id: string;
  project_id: string;
  scope_type: ScopeType;
  scope_id: string | null;
  mem_type: MemType;
  kind: string;
  lane: Lane;
  trust_tier: TrustTier;
  status: Status;
  content: string;
  content_hash: string;
  token_count: number;
  embedding: string | null;
  embedding_model_id: string | null;
  embedding_model_version: string | null;
  lexemes: string | null;
  subject_tag: string | null;
  q_value: number;
  confidence: number;
  scored_use_count: number;
  last_scored_at: string | null;
  strike_count: number;
  shadow_confirm_runs: string[] | null;
  cluster_id: string | null;
  ttl_class: string | null;
  pinned: boolean;
  last_retrieved_at: string | null;
  last_revalidated_at: string | null;
  status_changed_at: string | null;
  valid_from: string | null;
  valid_to: string | null;
  created_at: string;
  expired_at: string | null;
  provenance: Provenance;
  scan_verdict_id: string;
  schema_version: number;
}

export interface TraceIndexExportRow {
  run_id: string;
  project_id: string;
  agent_type_id: string;
  workflow_template_id: string | null;
  submitter_principal: string;
  input_signature_hash: string; // hex
  instrumentation_source: InstrumentationSource;
  arm: Arm;
  path: Record<string, unknown> | null;
  started_at: string | null;
  ended_at: string | null;
  payload_ref: string | null;
  outcome_status: TraceOutcomeStatus;
}

export interface OutcomeEventExportRow {
  event_id: string;
  run_id: string;
  project_id: string;
  principal_id: string;
  adapter: AdapterClass;
  r: number;
  payload: Record<string, unknown>; // may carry reserved "_w_zero" (C-10)
  occurred_at: string;
  arrived_at: string;
}

export interface InjectionLogExportRow {
  run_id: string;
  project_id: string;
  memory_id: string;
  slot: Slot;
  score: number;
  tokens: number;
  injected_at: string;
}

export interface RetrievalEventExportRow {
  run_id: string;
  project_id: string;
  outcome_code: OutcomeCode;
  latency_ms: number;
  embed_latency_ms: number | null;
  candidates_considered: number;
  top_score: number | null;
  arm: Arm;
  created_at: string;
}

export type ExportRow =
  | { table: "memory_item"; row: MemoryItemExportRow }
  | { table: "trace_index"; row: TraceIndexExportRow }
  | { table: "outcome_event"; row: OutcomeEventExportRow }
  | { table: "injection_log"; row: InjectionLogExportRow }
  | { table: "retrieval_event"; row: RetrievalEventExportRow };

// --------------------------------------------------------------------- //
// Control-plane read bodies (D-093) — src/tracebed/api/models.py's
// ScopeOut / MemoryListOut / ReviewQueueOut / KillswitchStateOut /
// InvalidationListOut / SpendOut / ConfigOut, transcribed the same way
// everything above is: field for field, name for name.
//
// These are what replaced the fixture-backed views. Every one of them is a
// GET, project-scoped server-side; none of them takes a project_id, and the
// only one that RETURNS one (`ScopeOut`) reports the scope the server derived
// for the presented credential, which is the opposite of accepting one.
// --------------------------------------------------------------------- //

export interface ScopeOut {
  project_id: string;
  agent_type_id: string;
  principal_id: string;
}

export interface MemoryListOut {
  items: MemoryItemOut[];
  /** The bound the server applied. `returned === limit` is the ONLY signal a
   * view has that more rows exist — rendering `returned` as a total without
   * checking this is how a page count becomes a vault count. */
  limit: number;
  returned: number;
}

export interface ReviewItemOut {
  item_id: string;
  reason: string;
  memory_id: string | null;
  opened_at: string;
  resolved_at: string | null;
  resolution: string | null;
}

export interface ReviewQueueOut {
  items: ReviewItemOut[];
  limit: number;
  returned: number;
  include_resolved: boolean;
}

export interface KillswitchCellOut {
  /** `null` is the PROJECT-WIDE overlay row (migrations/0001's sentinel), not
   * an unknown agent type — the widest possible disablement, not the
   * narrowest. Any view rendering this must say so in words. */
  agent_type_id: string | null;
  mem_type: MemType;
  disabled: boolean;
  /** Verbatim from `workers/killswitch.py`'s `_evidence`. Deliberately
   * `Record<string, unknown>`: the worker owns this record's shape, and a
   * dashboard that declared a stricter type for it would be asserting a
   * contract the server never promised. Read defensively. */
  evidence: Record<string, unknown> | null;
  changed_at: string;
}

export interface KillswitchStateOut {
  cells: KillswitchCellOut[];
}

export interface InvalidationEventOut {
  event_id: string;
  event_type: string;
  selector: Record<string, unknown> | null;
  fired_at: string;
}

export interface InvalidationListOut {
  events: InvalidationEventOut[];
  limit: number;
  returned: number;
}

export interface SpendCellOut {
  day: string; // ISO date (UTC), not a timestamp
  worker: string;
  model_id: string;
  tokens_in: number;
  tokens_out: number;
  cost_usd: number;
}

export interface SpendOut {
  since: string;
  days: number;
  cells: SpendCellOut[];
}

export interface ConfigOut {
  agent_type_id: string;
  /** STORED OVERRIDES ONLY — PLAN.md §6's middle two resolution layers. The
   * process defaults are the server's environment, not this project's data,
   * so a view must not present these as the resolved effective config. */
  project: Record<string, unknown>;
  agent_type: Record<string, unknown>;
}
