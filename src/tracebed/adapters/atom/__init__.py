"""Atom integration seam: documented interface stubs ONLY (PLAN.md §3 `adapters/`, §4 repo
layout: "atom/ — documented interface stubs ONLY — the human writes the integration"; PLAN.md
§7 Phase 4: "operator docs, per-archetype configs, adapter-port authoring guide (the Atom seam
documentation)").

Nothing in this package is wired to anything. Every class in `stubs.py` raises
`NotImplementedError` unconditionally — that is the point, not an oversight: this chunk's task
is explicit that "the human writes that themselves" is a decision already made in PLAN.md, not
one this package is free to relitigate by sneaking in a working implementation. Read
`README.md` first, then `../../../../docs/ADAPTER-GUIDE.md` for what each stub's target port
requires a real implementation to guarantee.

Import-safe by construction: every stub class only references `adapters.ports` Protocols,
`domain` types, and stdlib — nothing here reaches into `workers/`, `hotpath/`, or any concrete
store, so `import tracebed.adapters.atom` never has a side effect and never requires a
database, Keycloak, GATE, or any other live Atom component to succeed.
"""

from __future__ import annotations

from tracebed.adapters.atom.stubs import (
    AtomAgentArmorFeedbackAdapter,
    AtomBuilderInvalidationSource,
    AtomGateEmbeddingProvider,
    AtomGateLLMProvider,
    AtomKeycloakPrincipalPort,
    AtomMinioAuditSink,
    AtomPolicyExecutorVerdictAdapter,
    AtomWorkflowFeedbackAdapter,
)

__all__ = [
    "AtomAgentArmorFeedbackAdapter",
    "AtomBuilderInvalidationSource",
    "AtomGateEmbeddingProvider",
    "AtomGateLLMProvider",
    "AtomKeycloakPrincipalPort",
    "AtomMinioAuditSink",
    "AtomPolicyExecutorVerdictAdapter",
    "AtomWorkflowFeedbackAdapter",
]
