"""`PgVectorStore` — the shipped default `VectorStorePort` driver (PLAN.md §7 Phase 4).

A thin adapter over what `stores.pg` already does, never a parallel implementation:

  * `ann_search` is a straight passthrough to `stores.pg.search.SearchStore.vector_arm` — same
    parameters, same return type (`ArmHit`), same retrievability guarantees. There is no
    branch here that could disagree with `SearchStore` about which rows are retrievable.
  * destructive erasure is intentionally *not* delegated here.  `memory_item`
    is primary data, not an independent vector index; E3's separately
    credentialed PostgreSQL routine owns its deletion and project partition
    DDL.  This hot-path adapter cannot erase a project.

`pgvector.py` sits OUTSIDE `stores/pg/`, so `scripts/raw_sql_lint.py` fails it on sight if it
executes SQL directly — every read/delete here is a call into the one place SQL is allowed to
live, never a `cur.execute(...)` of its own.

CONTRACT GAP (`upsert`): no chunk across Phases 0-3 shipped a `Repo`/`SearchStore` method that
writes `memory_item.embedding` — `Repo.insert_memory_item` (`stores/pg/repo.py`, frozen/outside
this chunk's file list) takes no embedding parameter, and a repo-wide grep turns up zero
`UPDATE memory_item SET embedding` anywhere in `src/tracebed`. Inventing that SQL here would be
exactly the "parallel implementation that can drift" PLAN.md §7 warns against, and this module
cannot execute SQL at all regardless (`raw_sql_lint`). `PgVectorStore.upsert` therefore raises
`VectorStoreWriteUnavailable`, naming the missing primitive precisely, rather than a silent
no-op or a placeholder success (hard rule 8) — reported here for whichever future chunk adds an
embedding-write path to `Repo`.
"""

from __future__ import annotations

from collections.abc import Sequence

from psycopg_pool import ConnectionPool

from tracebed.domain.enums import TrustTier
from tracebed.domain.errors import TracebedError
from tracebed.domain.ids import MemoryId, ProjectId
from tracebed.domain.state_machine import Status
from tracebed.stores.pg.pool import RemainingBudget
from tracebed.stores.pg.search import ArmHit, SearchStore

__all__ = ["PgVectorStore", "VectorStoreWriteUnavailable"]


class VectorStoreWriteUnavailable(TracebedError):
    """Raised by a `VectorStorePort` write this driver cannot perform without inventing SQL
    outside `stores/pg/` (see module docstring's CONTRACT GAP)."""


class PgVectorStore:
    """`VectorStorePort` over the `halfvec` column already on `memory_item`. Satisfies the
    port structurally; construct with the same `SearchStore`/`ConnectionPool` the rest of the
    read/admin paths already use — this driver introduces no connection of its own.

    Reads (`ann_search`) go through `SearchStore`, which opens its own scoped
    transaction.  Project deletion is unavailable through this adapter; use
    the E3 executor's dedicated destructive-store port instead.
    """

    def __init__(self, search: SearchStore, pool: ConnectionPool) -> None:
        self._search = search
        self._pool = pool

    def ann_search(
        self,
        project_id: ProjectId,
        embedding: Sequence[float],
        top_n: int,
        *,
        hnsw_iterative_scan: bool,
        hnsw_max_scan_tuples: int,
        statement_timeout_ms: int | None = None,
        deadline: RemainingBudget | None = None,
    ) -> list[ArmHit]:
        return self._search.vector_arm(
            project_id,
            embedding,
            top_n,
            hnsw_iterative_scan=hnsw_iterative_scan,
            hnsw_max_scan_tuples=hnsw_max_scan_tuples,
            statement_timeout_ms=statement_timeout_ms,
            deadline=deadline,
        )

    def upsert(
        self,
        project_id: ProjectId,
        memory_id: MemoryId,
        embedding: Sequence[float],
        *,
        trust_tier: TrustTier,
        status: Status,
    ) -> None:
        # Plain concatenation, not an f-string, for the clause naming the missing SQL shape:
        # ruff's S608 (possible SQL-injection-via-string-construction) pattern-matches an
        # f-string containing SQL keywords regardless of context, and this message quotes
        # one to name a gap, never to build a query -- see the module docstring's CONTRACT
        # GAP; this is prose about SQL that does not exist, not SQL being assembled.
        no_write_path = (
            "no memory_item embedding-column write statement exists anywhere in stores/pg/"
        )
        raise VectorStoreWriteUnavailable(
            f"pgvector driver has no embedding-write primitive to delegate to for memory "
            f"{memory_id} in project {project_id}: stores.pg.repo.Repo.insert_memory_item "
            f"takes no embedding parameter, and {no_write_path} (see "
            "stores/vector/pgvector.py module docstring) -- a future chunk must add one to "
            "stores/pg/ before this driver can serve writes"
        )
