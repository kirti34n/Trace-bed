"""`QdrantVectorStore` — an alternative `VectorStorePort` driver (PLAN.md §7 Phase 4).

OFF BY DEFAULT (`DEFAULT_ENABLED` below). `qdrant-client` is deliberately NOT a
`pyproject.toml` dependency — adding it would need its own `scripts/license_policy.toml`
entry, the way psycopg's LGPL did (D-036 keeps the dependency list closed) — so it is an
optional import behind a documented extra, checked at construction, never at first query
(mirrors `adapters.embedding.onnx_local.OnnxLocalEmbeddingClient`'s established pattern:
a missing optional dependency must fail deployment wiring, not the hot path's first
retrieval).

CONTRACT GAP (`DEFAULT_ENABLED`'s home): PLAN.md §6's config surface (`domain/config.py`) has
no field selecting a vector-store driver — `TraceStoreConfig.driver`/`EmbeddingConfig.driver`
are the established pattern this port's driver selection should eventually follow, but
`domain/config.py` is outside this chunk's file list. `DEFAULT_ENABLED` here is the interim,
self-contained "off by default" fact this chunk owns and its tests assert directly; wiring it
into `EffectiveConfig`/`StorageConfig` is reported for whichever future chunk owns that file.

CONTRACT GAP (client surface): `QdrantClientPort` is modelled on `qdrant_client.QdrantClient`'s
`search`/`upsert`/`delete` signatures. `qdrant-client` is not installed in this environment, so
that shape is asserted against a fake, never against the real package — any deployment enabling
this driver must run the port's contract tests against the pinned client version first.

THE WALL STILL APPLIES (PLAN.md §7): "a second vector store is a second place project
isolation can break, and it has no RLS backstop -- so the scoping must be structural in the
driver." Concretely, in this module:

  1. Every point's payload carries `project_id` (`_point_struct`), and every upsert stamps it
     from the SAME `project_id` parameter the caller supplied -- there is no parameter through
     which a point could be written without one. The point's own ID is derived from
     (`project_id`, `memory_id`) together (`_point_id`), because a Qdrant point id is unique
     per COLLECTION and not per filter: two projects reusing one `memory_id` would otherwise
     overwrite each other's vector on upsert, which no read-side filter can undo.
  2. Every search/delete attaches a `must`-filter on `project_id` (`_project_condition`) built
     from that call's own `project_id` argument -- there is no method on this class, and no
     keyword argument on any method, that can issue a search or delete without that filter.
  3. Every result is re-checked on the way OUT (`_result_to_arm_hit`): if a point whose payload
     `project_id` disagrees with the query's `project_id` is ever returned (a driver bug, a
     stale index, an operator who queried the wrong collection), `QdrantScopeViolation` is
     raised rather than the mismatched hit being silently handed to the caller -- the same
     fail-closed discipline `stores.pg.search.assert_dynamically_retrievable` applies to
     pgvector's own rows.

INVARIANT 7 APPLIES ON THIS PATH TOO, and it is the reason D-070 (the
`assert_dynamically_retrievable` entry in DECISIONS.md) names "PLAN.md §9's Qdrant driver" as
the exact thing that would otherwise route around the retrievability control: an alternative
retrieval driver reaches fusion, the assembler and the renderer without ever touching
`stores/pg/search.py`'s SQL predicate. So both halves of that control are restated here in the
only two places they can be:

  * server-side, `_retrievable_condition()` — the filter conjunct that admits exactly
    `validated`, plus `candidate` only at Tier A (`pinned` is static-prefix-only and never a
    dynamic-arm hit; see `stores/pg/search.py`'s module docstring). Its equivalence to
    `assert_dynamically_retrievable` is proven exhaustively over every (status, tier) pair in
    `tests/phase4/test_vector_drivers.py`, so a future change to the rule in `stores/pg/`
    fails this driver's tests instead of silently widening it.
  * on the way out, `assert_dynamically_retrievable` itself — imported, not restated, from the
    one module that owns the rule.

The payload a point carries is a SNAPSHOT of `memory_item.status`/`trust_tier` as of its last
`upsert`, not a join against the live row (a separate store has no such join). A memory
quarantined after its last upsert therefore stays filter-visible here until the write path
re-upserts it — an inherent property of any out-of-database index, stated rather than hidden.
`hotpath.assembly`'s third `assert_dynamically_retrievable` call (D-070) is
the check that still holds on freshly-fetched `memory_item` rows regardless.
"""

from __future__ import annotations

import math
from collections.abc import Mapping, Sequence
from typing import Any, Final, Protocol, runtime_checkable
from uuid import NAMESPACE_URL, UUID, uuid5

from tracebed.domain.enums import TrustTier
from tracebed.domain.errors import TracebedError
from tracebed.domain.ids import MemoryId, ProjectId
from tracebed.domain.state_machine import Status
from tracebed.stores.pg.search import ArmHit, assert_dynamically_retrievable

__all__ = [
    "DEFAULT_ENABLED",
    "QdrantClientPort",
    "QdrantPayloadInvalid",
    "QdrantScopeViolation",
    "QdrantUnavailable",
    "QdrantVectorStore",
]

# See module docstring's CONTRACT GAP: the real home for this fact is a `domain.config`
# driver-selection field this chunk's file list does not include.
DEFAULT_ENABLED: Final[bool] = False

# Mirrors `stores.pg.search._MAX_ARM_TOP_N`'s own bound and rationale: a defensive ceiling on
# a caller-supplied `top_n`, not a retrieval-quality tunable (`EffectiveConfig` owns that).
_MAX_TOP_N: Final[int] = 1_000

_PROJECT_ID_KEY: Final[str] = "project_id"
_MEMORY_ID_KEY: Final[str] = "memory_id"
_TRUST_TIER_KEY: Final[str] = "trust_tier"
_STATUS_KEY: Final[str] = "status"

DEFAULT_COLLECTION: Final[str] = "tracebed_memory_item"


class QdrantUnavailable(TracebedError):
    """`qdrant-client` is not importable in this environment.

    Raised at `QdrantVectorStore.__init__`, never at first `ann_search()`/`upsert()` call --
    a missing optional dependency must fail deployment wiring, not the hot path's first
    retrieval (same discipline as `OnnxRuntimeUnavailable`).
    """


class QdrantScopeViolation(TracebedError):
    """A point or search result crossed `project_id` at the one boundary this driver is the
    last line of defence for (module docstring, point 3). Raised rather than silently
    filtered: a caller that received a truncated-but-unlabelled result would trust it, which
    is worse than a loud failure."""


class QdrantPayloadInvalid(TracebedError):
    """A search result's payload is missing a field this driver must read, or carries a value
    outside the domain enum it maps to.

    A `TracebedError` rather than the bare `KeyError`/`ValueError` the parse would otherwise
    raise, because `hotpath.pipeline`'s degradation ladder (PLAN.md §2 invariant 2) is written
    in terms of typed store failures: an untyped exception escaping a retrieval arm fails the
    RUN, which is the one outcome the ladder exists to prevent.
    """


@runtime_checkable
class QdrantClientPort(Protocol):
    """The exact slice of `qdrant_client.QdrantClient` this driver calls -- narrow on purpose
    so a test fake needs to implement three methods, not the real client's full surface.
    Deliberately typed in plain `dict`/`Any` terms rather than `qdrant_client.models` types:
    Qdrant's REST/gRPC API accepts plain mappings for filters and point structs, and typing
    against the real models module would make this Protocol itself require the optional
    dependency to even import."""

    def search(
        self,
        collection_name: str,
        query_vector: Sequence[float],
        query_filter: Mapping[str, Any],
        limit: int,
    ) -> Sequence[Any]: ...

    def upsert(self, collection_name: str, points: Sequence[Mapping[str, Any]]) -> Any: ...

    def delete(self, collection_name: str, points_selector: Mapping[str, Any]) -> Any: ...


def _project_condition(project_id: ProjectId) -> dict[str, Any]:
    """The ONE project-scope condition every search/delete call carries -- built from
    `project_id` and nothing else. No caller of this module's public methods can supply a
    filter directly (no method takes one), so no query can reach Qdrant without it."""
    return {"key": _PROJECT_ID_KEY, "match": {"value": str(project_id.value)}}


def _retrievable_condition() -> dict[str, Any]:
    """Invariant 7's server-side half for this driver: `status = validated` OR
    (`status = candidate` AND `trust_tier = A`).

    The same set `stores.pg.search`'s SQL predicate admits, expressed as a nested Qdrant
    filter rather than restated as prose -- and proven equal to `assert_dynamically_retrievable`
    over every (status, tier) pair by this chunk's tests, so the two cannot drift apart in
    silence (module docstring).
    """
    return {
        "should": [
            {"key": _STATUS_KEY, "match": {"value": Status.VALIDATED.value}},
            {
                "must": [
                    {"key": _STATUS_KEY, "match": {"value": Status.CANDIDATE.value}},
                    {"key": _TRUST_TIER_KEY, "match": {"value": TrustTier.A.value}},
                ]
            },
        ]
    }


def _search_filter(project_id: ProjectId) -> dict[str, Any]:
    """Project scope AND retrievability -- the filter every READ carries."""
    return {"must": [_project_condition(project_id), _retrievable_condition()]}


def _erasure_filter(project_id: ProjectId) -> dict[str, Any]:
    """Project scope ONLY -- the filter every DELETE carries.

    Deliberately NOT `_search_filter`: erasure must remove every point of the project,
    including the quarantined/retired/tombstoned ones a read must never surface. A delete
    narrowed by the retrievability condition would leave exactly the vectors an erasure exists
    to destroy (`stores.pg.partitions.drop_project`, the pgvector driver's own delete path,
    drops the whole partition for the same reason).
    """
    return {"must": [_project_condition(project_id)]}


def _point_id(project_id: ProjectId, memory_id: MemoryId) -> str:
    """The point's id in the collection, derived from BOTH ids.

    A Qdrant point id is unique per collection, and `delete`/`upsert` by id ignore payload
    filters entirely -- so a bare `memory_id` as the point id makes one project able to
    overwrite another's vector (last writer wins, payload and all) in a store with no RLS to
    stop it. `uuid5` is deterministic, so re-upserting the SAME memory still overwrites its own
    point rather than accumulating duplicates, and the result is a UUID, which is one of the
    two id types Qdrant accepts.
    """
    return str(uuid5(NAMESPACE_URL, f"tracebed://{project_id.value}/{memory_id.value}"))


def _point_struct(
    project_id: ProjectId,
    memory_id: MemoryId,
    embedding: Sequence[float],
    *,
    trust_tier: TrustTier,
    status: Status,
) -> dict[str, Any]:
    """The ONE point shape `upsert` writes -- `project_id` stamped into the payload from the
    same parameter the caller supplied, never read back from anywhere the caller could have
    influenced independently of it."""
    return {
        "id": _point_id(project_id, memory_id),
        "vector": list(embedding),
        "payload": {
            _PROJECT_ID_KEY: str(project_id.value),
            _MEMORY_ID_KEY: str(memory_id.value),
            _TRUST_TIER_KEY: trust_tier.value,
            _STATUS_KEY: status.value,
        },
    }


def _bounded_top_n(top_n: int) -> int:
    return min(top_n, _MAX_TOP_N)


def _checked_vector(embedding: Sequence[float]) -> list[float]:
    """Same rejection `stores.pg.search._embedding_literal` applies before a vector reaches
    pgvector: a NaN/infinite component makes every distance it participates in meaningless, and
    an ANN index that accepts one returns a ranking no downstream calibration can interpret.
    Enforced here so the two drivers cannot disagree about what a usable vector is."""
    for component in embedding:
        if math.isnan(component) or math.isinf(component):
            raise ValueError("embedding must not contain NaN or infinite components")
    return [float(v) for v in embedding]


def _payload_of(result: Any) -> Mapping[str, Any]:
    try:
        payload = result.payload if hasattr(result, "payload") else result["payload"]
    except (KeyError, TypeError) as exc:
        raise QdrantPayloadInvalid(
            "qdrant search result carries no payload; refusing to trust an unscoped result"
        ) from exc
    if not isinstance(payload, Mapping):
        raise QdrantScopeViolation(
            f"qdrant search result carries a non-mapping payload ({type(payload).__name__}); "
            "refusing to trust an unscoped result"
        )
    return payload


def _score_of(result: Any) -> float:
    try:
        raw = result.score if hasattr(result, "score") else result["score"]
        return float(raw)
    except (KeyError, TypeError, ValueError) as exc:
        raise QdrantPayloadInvalid("qdrant search result carries no usable score") from exc


def _required(payload: Mapping[str, Any], key: str) -> str:
    value = payload.get(key)
    if value is None:
        raise QdrantPayloadInvalid(f"qdrant point payload is missing {key!r}")
    return str(value)


def _result_to_arm_hit(project_id: ProjectId, result: Any) -> ArmHit:
    """Parses one search result, refusing any whose payload disagrees with the project this
    search was scoped to (module docstring, point 3) or whose status/tier the retrievability
    filter should have excluded (invariant 7, module docstring)."""
    payload = _payload_of(result)
    result_project_id = str(payload.get(_PROJECT_ID_KEY))
    if result_project_id != str(project_id.value):
        raise QdrantScopeViolation(
            f"qdrant returned a point tagged project_id={result_project_id!r} for a search "
            f"scoped to project_id={project_id.value!r} -- refusing to hand it to the caller"
        )
    try:
        hit = ArmHit(
            memory_id=MemoryId(UUID(_required(payload, _MEMORY_ID_KEY))),
            raw_score=_score_of(result),
            trust_tier=TrustTier(_required(payload, _TRUST_TIER_KEY)),
            status=Status(_required(payload, _STATUS_KEY)),
        )
    except ValueError as exc:
        raise QdrantPayloadInvalid(
            f"qdrant point payload is not parseable into an ArmHit: {exc}"
        ) from exc
    assert_dynamically_retrievable(hit.memory_id, hit.status, hit.trust_tier)
    return hit


class QdrantVectorStore:
    """`VectorStorePort` over a Qdrant collection. Every point in `collection` carries
    `project_id` in its payload (module docstring, point 1); every read/delete this class
    issues carries the matching filter (point 2); every result is re-checked on the way out
    (point 3).

    Stateless per call: nothing about a call (its project, its filter, its results) is stored
    on the instance, which is what makes one store safely shareable across the retriever's
    threads -- see this chunk's threaded contention tests.
    """

    def __init__(
        self,
        *,
        url: str | None = None,
        api_key: str | None = None,
        collection: str = DEFAULT_COLLECTION,
        client: QdrantClientPort | None = None,
    ) -> None:
        if client is not None:
            # The test/injection seam: bypasses the optional import entirely, which is what
            # lets this driver's scoping logic be unit-tested with a fake client and no
            # server (PLAN.md §7) -- the real deployment path below is the only one that
            # needs `qdrant-client` installed at all.
            self._client: QdrantClientPort = client
        else:
            # Checked before the import attempt: a missing required config value is a
            # different, more specific failure than a missing optional dependency, and a
            # caller should learn about it even in an environment where `qdrant-client`
            # happens not to be installed at all.
            if url is None:
                raise ValueError(
                    "QdrantVectorStore requires `url` when constructing a real QdrantClient "
                    "(pass `client=` directly to bypass construction, e.g. in tests)"
                )
            try:
                from qdrant_client import QdrantClient  # type: ignore[import-not-found]
            except ImportError as exc:
                raise QdrantUnavailable(
                    "qdrant-client is not installed; install the `tracebed[qdrant]` extra to "
                    "use the Qdrant vector-store driver (see stores/vector/qdrant.py)"
                ) from exc
            self._client = QdrantClient(url=url, api_key=api_key)
        self._collection = collection

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
        # Qdrant's own ANN tuning is `hnsw_ef` / exact-search flags, not pgvector's iterative-
        # scan GUCs -- accepted (per VectorStorePort's contract) and deliberately unused here
        # rather than dropped from the signature, so every driver presents one port shape.
        #
        # CONTRACT GAP (D-139), reported rather than half-implemented: `statement_timeout_ms` is
        # accepted and UNUSED here too, so on this driver the hot path's server-side bound does
        # not exist and a stalled Qdrant is bounded only by the retriever's client-side wait --
        # i.e. exactly the pre-D-139 state, which leaves the arm's worker slot occupied for the
        # life of the stall. Qdrant's HTTP API does carry a per-request timeout, but
        # `_QdrantClientPort.search` above does not expose one, and widening that Protocol on the
        # strength of an API this environment cannot exercise (no Qdrant here) would be a claim
        # rather than a mechanism. The pgvector driver is the shipped default; this is a gap in
        # the alternative driver, named where a reader of it will meet it.
        del hnsw_iterative_scan, hnsw_max_scan_tuples, statement_timeout_ms
        if top_n <= 0 or not embedding:
            return []
        results = self._client.search(
            collection_name=self._collection,
            query_vector=_checked_vector(embedding),
            query_filter=_search_filter(project_id),
            limit=_bounded_top_n(top_n),
        )
        return [_result_to_arm_hit(project_id, r) for r in results]

    def upsert(
        self,
        project_id: ProjectId,
        memory_id: MemoryId,
        embedding: Sequence[float],
        *,
        trust_tier: TrustTier,
        status: Status,
    ) -> None:
        if not embedding:
            raise ValueError("embedding must not be empty")
        point = _point_struct(
            project_id,
            memory_id,
            _checked_vector(embedding),
            trust_tier=trust_tier,
            status=status,
        )
        self._client.upsert(collection_name=self._collection, points=[point])

    def delete_by_project(self, project_id: ProjectId) -> None:
        # `{"filter": ...}` (Qdrant's `FilterSelector` shape), not a bare filter: the delete
        # endpoint's selector is a union of "these ids" and "everything matching this filter",
        # and the bare filter is neither arm of it.
        self._client.delete(
            collection_name=self._collection,
            points_selector={"filter": _erasure_filter(project_id)},
        )
