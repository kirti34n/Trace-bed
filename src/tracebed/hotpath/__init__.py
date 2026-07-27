"""The hot read plane (PLAN.md §3, §7 Phase 1).

Everything under `hotpath/` is reachable from the synchronous retrieval path
and is therefore subject to `scripts/purity_check.py` (invariant 1): no
generative LLM client, no `tracebed.workers`, no `tracebed.ingest`, no
`tracebed.crypto` may be reachable from here, directly or transitively.
Permitted imports: `tracebed.domain`, `tracebed.stores`,
`tracebed.adapters.embedding`, `tracebed.adapters.ports`, `tracebed.core`.
"""

from __future__ import annotations
