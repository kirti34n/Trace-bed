"""Alternative vector-store drivers behind `VectorStorePort` (PLAN.md §7 Phase 4).

`pgvector.py` is the shipped default (D-036-consistent: it wraps `stores.pg.search` and
`stores.pg.partitions`, never a parallel SQL surface). `qdrant.py` is OFF BY DEFAULT and
lazy-imports its optional client — see `qdrant.DEFAULT_ENABLED` and the module docstring
there for why, and for the CONTRACT GAP on where that default belongs (`domain.config`,
outside this chunk's file list).
"""

from __future__ import annotations

from tracebed.stores.vector.base import VectorStorePort
from tracebed.stores.vector.pgvector import PgVectorStore, VectorStoreWriteUnavailable
from tracebed.stores.vector.qdrant import (
    DEFAULT_ENABLED as QDRANT_DEFAULT_ENABLED,
)
from tracebed.stores.vector.qdrant import (
    QdrantPayloadInvalid,
    QdrantScopeViolation,
    QdrantUnavailable,
    QdrantVectorStore,
)

__all__ = [
    "QDRANT_DEFAULT_ENABLED",
    "PgVectorStore",
    "QdrantPayloadInvalid",
    "QdrantScopeViolation",
    "QdrantUnavailable",
    "QdrantVectorStore",
    "VectorStorePort",
    "VectorStoreWriteUnavailable",
]
