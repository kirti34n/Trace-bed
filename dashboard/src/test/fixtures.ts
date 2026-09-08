import type { InjectionEntryOut, MemoryItemOut, SessionStatusOut } from "../api/types";

export const authenticatedSession: SessionStatusOut = { authenticated: true, csrf_token: "test-csrf" };
export const anonymousSession: SessionStatusOut = { authenticated: false, csrf_token: null };

export const memoryFixture: MemoryItemOut = {
  id: "memory-1", project_id: "project-1", scope_type: "project_shared", scope_id: null,
  mem_type: "semantic", kind: "fact", lane: "quality", trust_tier: "A", status: "validated",
  content: "A safely rendered memory", content_hash: "hash", token_count: 4, subject_tag: null,
  q_value: 0.5, confidence: 0.7, scored_use_count: 2, strike_count: 0,
  provenance: { class: "parser" }, scan_verdict_id: "scan-1", schema_version: 1,
  created_at: "2026-01-01T00:00:00Z", status_changed_at: null,
};

export const injectionFixture: InjectionEntryOut = {
  run_id: "run-1", memory_id: "memory-1", slot: "fact", score: 0.7, tokens: 12,
  injected_at: "2026-01-01T00:00:00Z",
};
