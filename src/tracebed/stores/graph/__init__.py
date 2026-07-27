"""`GraphStorePort` — the `memory_link` traversal surface for a native-graph alternative
(PLAN.md §7 Phase 4: "Apache AGE hook behind an interface ... for memory_link traversal (the
forensics descendant walk is the obvious consumer)").

Mirrors what `workers.forensics` already does over `memory_link` rather than inventing a
generic graph-query surface: `ForensicsRepoPort.list_direct_derived_descendants`'s one-hop
shape, and the transitive closure `Forensics._transitive_descendants` computes over it with a
bounded BFS of repeated one-hop calls (`workers/forensics.py`, out of this chunk's file
list — read, not imported: this port does not depend on `workers/`, only mirrors its shape).
That BFS is exactly the case PLAN.md §7 names as "the obvious consumer" of a native graph
traversal: a real Apache AGE backend can answer the *whole* multi-hop closure in ONE query
instead of one round trip per generation, which is what `transitive_derived_descendants`
below exposes that `ForensicsRepoPort` does not.

`upsert_link`/`delete_by_project` complete the write/lifecycle side the same way
`stores.vector.base.VectorStorePort` completes its own read-only extraction with upsert and
delete-by-project — a graph store needs to be kept in sync with `memory_link` writes and
cleaned up on project deletion/GC exactly like a vector index does.

This port is declared here (`stores/graph/__init__.py`), not in a separate `base.py`, matching
`stores.tracestore`'s own convention: the one port this package exists for lives in the
package's `__init__.py`; drivers (`age.py`) live alongside it.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Protocol, runtime_checkable

from tracebed.domain.ids import MemoryId, ProjectId

__all__ = ["GraphStorePort"]


@runtime_checkable
class GraphStorePort(Protocol):
    """Host-implements port (PLAN.md §3 ports-table shape). No shipped default — Postgres
    `memory_link` queries (`workers.forensics`'s own BFS) remain the default traversal
    mechanism; this port is the off-by-default alternative. Every implementation must scope
    every read/write to `project_id` server-side (PLAN.md §2 invariant 4) — same "no RLS
    backstop" reasoning as `VectorStorePort`."""

    def direct_derived_descendants(
        self, project_id: ProjectId, memory_id: MemoryId
    ) -> Sequence[MemoryId]:
        """Every memory ONE HOP `derived_from`-linked FROM `memory_id` — same contract as
        `workers.forensics.ForensicsRepoPort.list_direct_derived_descendants`."""
        ...

    def transitive_derived_descendants(
        self,
        project_id: ProjectId,
        memory_id: MemoryId,
        *,
        max_generations: int,
        max_descendants: int,
    ) -> tuple[Sequence[MemoryId], bool]:
        """The full multi-hop closure, bounded the same way
        `workers.forensics.Forensics._transitive_descendants` bounds its own BFS (both caps
        can only make the returned set SMALLER than the true one, never larger). Returns
        `(descendants, truncated)` — `truncated` is never inferred from length (a walk that
        exhausts the graph at exactly `max_descendants` is complete; one bounded by
        generations with edges left unexplored is not), matching
        `workers.forensics.BlastRadiusReport.descendants_truncated`'s own contract exactly.
        """
        ...

    def upsert_link(
        self, project_id: ProjectId, src_id: MemoryId, dst_id: MemoryId, relation: str
    ) -> None:
        """Write (or overwrite) one `memory_link` edge, scoped to `project_id`."""
        ...

    def delete_by_project(self, project_id: ProjectId) -> None:
        """Erase every node/edge belonging to `project_id`. Idempotent."""
        ...
