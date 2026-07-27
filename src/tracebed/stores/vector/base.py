"""`VectorStorePort` — the vector-index surface `hotpath.retriever` actually needs
(PLAN.md §7 Phase 4: "Qdrant driver ... behind interfaces, compile-tested, off by default").

Extracted from the EXISTING pgvector usage, not invented aspirationally: for the vector arm
`hotpath.retriever` calls exactly ONE thing on `stores.pg.search.SearchStore` —
`vector_arm(project_id, embedding, top_n, hnsw_iterative_scan=..., hnsw_max_scan_tuples=...)`
— plus, at the write/lifecycle edges nothing in `hotpath/` touches, an upsert of one memory's
embedding and a delete-by-project for GC/project-deletion. That is the whole surface this port
declares: three methods, matching `pgvector.py`'s three faithful wrappers.

CONTRACT GAP (wiring): `hotpath.retriever.Retriever` holds a concrete `SearchStore`, not this
port — swapping a driver in for real needs a constructor change in `hotpath/retriever.py`,
outside this chunk's file list. This port is the compile-tested interface PLAN.md §7 asks for;
it is not yet the type the hot path depends on.

Deliberately NOT included: `lexical_arm` (BM25 via `pg_textsearch` has no Qdrant/AGE analogue),
`document_frequency`/`corpus_size` (the rarity gate's IDF source is Postgres-native), and
`fetch_candidates` (content/score columns live in `memory_item` regardless of which store
indexes the embedding). Widening this port to cover those would be exactly the "aspirational
interface" PLAN.md §7 warns against — a vector store answers ANN queries; it is not where BM25
or content live.

`ArmHit` (`stores.pg.search`) is reused verbatim as the result type. Introducing a parallel
"VectorHit" shape here would be its own drift risk — the one this port exists to avoid.

Every implementation MUST embed `project_id` in every write and scope every read to it
server-side (PLAN.md §2 invariant 4) — for pgvector, Postgres RLS is the backstop; for a second
vector store (Qdrant) there is no RLS backstop at all, so the scoping must be structural in the
driver itself (`qdrant.py`'s module docstring). This protocol's signature is what makes that
checkable: `project_id` is the first positional parameter of every method, never optional, never
inferred from anything the driver constructs on its own.

Invariant 7 travels with the port, not with one driver's SQL: `ann_search` returns only rows
`stores.pg.search.assert_dynamically_retrievable` accepts, and every implementation is required
to enforce that in its own query AND to re-assert it on every hit it returns. `pgvector.py` gets
both from `SearchStore`; `qdrant.py` restates the filter and calls the exported assertion (see
D-070, the `assert_dynamically_retrievable` entry, which names an alternative vector driver
as precisely the thing that would otherwise route around the control).
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Protocol, runtime_checkable

from tracebed.domain.enums import TrustTier
from tracebed.domain.ids import MemoryId, ProjectId
from tracebed.domain.state_machine import Status
from tracebed.stores.pg.search import ArmHit

__all__ = ["VectorStorePort"]


@runtime_checkable
class VectorStorePort(Protocol):
    """Host-implements port (PLAN.md §3 ports-table shape), shipped default `PgVectorStore`."""

    def ann_search(
        self,
        project_id: ProjectId,
        embedding: Sequence[float],
        top_n: int,
        *,
        hnsw_iterative_scan: bool,
        hnsw_max_scan_tuples: int,
        statement_timeout_ms: int | None = None,
    ) -> list[ArmHit]:
        """Same contract as `SearchStore.vector_arm`: retrievability-predicate-filtered
        (`RETRIEVABLE_STATUSES` minus `pinned`, `candidate` restricted to Tier A), ordered by
        descending similarity, capped at `top_n`. A non-positive `top_n` or an empty
        `embedding` returns `[]` without issuing a query — "asked for nothing" is the correct,
        cheaper answer.

        `hnsw_iterative_scan`/`hnsw_max_scan_tuples` are pgvector's own tuning knobs
        (PLAN.md §6 `retrieval.hnsw_*`), carried on the port rather than defaulted here so a
        caller passing `EffectiveConfig` values through never has this driver invent its own
        constant (hard rule 4). A driver with no equivalent knob (Qdrant's own ANN tuning is
        `hnsw_ef`, a different parameter entirely) accepts and documents them as unused rather
        than dropping them from its signature — the port stays one shape for every driver.

        `statement_timeout_ms` (D-139) is the SERVER-side half of invariant 2's bound: how long
        the store may keep EXECUTING this query, as opposed to how long the caller waits for it.
        The caller derives it from `retrieval.total_budget_ms` minus what the call has already
        spent, so it is never a constant and never wider than the budget. It is on the port for
        the same reason the HNSW knobs are — the hot path passes it through and no driver may
        invent its own — and a driver with no server-side equivalent accepts and documents it as
        unused by the same rule. `None` means "no server-side bound", which is what every
        non-hot-path caller passes.
        """
        ...

    def upsert(
        self,
        project_id: ProjectId,
        memory_id: MemoryId,
        embedding: Sequence[float],
        *,
        trust_tier: TrustTier,
        status: Status,
    ) -> None:
        """Write (or overwrite) one memory's vector, scoped to `project_id`.

        `trust_tier`/`status` are carried because a store whose vectors live outside
        `memory_item` (Qdrant) has nowhere else to keep the columns `ann_search`'s result
        (`ArmHit`) must report back — pgvector's own implementation already has them in the
        row and passes them through for the same reason `ArmHit` needs them: invariant 7's
        retrievability check runs on every hit a dynamic arm returns, regardless of which
        store produced it.
        """
        ...

    def delete_by_project(self, project_id: ProjectId) -> None:
        """Erase every vector belonging to `project_id` — the vector-store half of project
        deletion/GC. Idempotent: deleting an already-empty/absent project is a no-op, never an
        error (mirrors `stores.pg.partitions.drop_project`'s own tolerance of a partially
        provisioned project)."""
        ...
