"""`VectorStorePort` contract tests (PLAN.md §7 Phase 4).

`PgVectorStore` (the shipped default) is exercised offline against a fake `SearchStore`-shaped
object and a mocked `drop_project` for the delegation/wiring proofs, plus one
`@pytest.mark.integration` test against a real Postgres 18 (skips cleanly when unavailable,
per this repository's environment constraint) proving `ann_search`/`delete_by_project` work
end to end through the real `SearchStore`/`drop_project` this driver wraps. The embedding
column is seeded directly via `psycopg` in that test's setup only (never through `Repo`,
which has no write path for it — the exact CONTRACT GAP `PgVectorStore.upsert` reports).

`QdrantVectorStore` (off by default, lazy-imported) is compile-tested via import, and its
scoping logic is unit-tested against a fake client satisfying `QdrantClientPort` -- no server
needed. `qdrant-client` is genuinely not installed in this environment, so
`test_qdrant_unavailable_without_package_or_client` exercises the real "not installed" path,
not a simulated one.

Two families of test here are deliberately NOT "call it and assert it did not crash":

  * the filter assertions compare against LITERAL expected structures, never against the
    module's own builder — a test asserting `sent == _search_filter(p)` passes happily when
    `_search_filter` is mutated to return `{}`, which is the one mutation that matters;
  * `test_qdrant_search_filter_admits_exactly_what_invariant_7_permits` walks every
    (status, tier) pair through both the emitted filter and
    `stores.pg.search.assert_dynamically_retrievable`, so this driver's server-side
    retrievability rule cannot drift from the SQL one without a red test.
"""

from __future__ import annotations

import inspect
import threading
import uuid
from collections.abc import Mapping, Sequence
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from tracebed.domain.enums import TrustTier
from tracebed.domain.errors import TracebedError
from tracebed.domain.ids import MemoryId, ProjectId
from tracebed.domain.state_machine import Status
from tracebed.stores.pg.search import ArmHit, SearchStore, assert_dynamically_retrievable
from tracebed.stores.vector.base import VectorStorePort
from tracebed.stores.vector.pgvector import PgVectorStore, VectorStoreWriteUnavailable
from tracebed.stores.vector.qdrant import (
    DEFAULT_ENABLED,
    QdrantPayloadInvalid,
    QdrantScopeViolation,
    QdrantUnavailable,
    QdrantVectorStore,
    _erasure_filter,
    _point_id,
    _search_filter,
)

pytestmark = pytest.mark.phase4

PROJECT_A = ProjectId(uuid.UUID(int=1))
PROJECT_B = ProjectId(uuid.UUID(int=2))
MEM_1 = MemoryId(uuid.UUID(int=10))
MEM_2 = MemoryId(uuid.UUID(int=11))


def _hit(memory_id: MemoryId, score: float) -> ArmHit:
    return ArmHit(memory_id=memory_id, raw_score=score, trust_tier=TrustTier.A, status=Status.VALIDATED)


def _expected_search_filter(project_id: ProjectId) -> dict[str, Any]:
    """The filter every read MUST carry, written out by hand rather than by calling the
    module's own builder -- an assertion that calls the code under test to produce its own
    expectation cannot fail when that code stops scoping."""
    return {
        "must": [
            {"key": "project_id", "match": {"value": str(project_id.value)}},
            {
                "should": [
                    {"key": "status", "match": {"value": "validated"}},
                    {
                        "must": [
                            {"key": "status", "match": {"value": "candidate"}},
                            {"key": "trust_tier", "match": {"value": "A"}},
                        ]
                    },
                ]
            },
        ]
    }


# --------------------------------------------------------------------------------------- #
# Structural port compliance
# --------------------------------------------------------------------------------------- #


def test_pgvector_store_satisfies_vector_store_port() -> None:
    assert isinstance(PgVectorStore(search=MagicMock(), pool=MagicMock()), VectorStorePort)


def test_qdrant_store_satisfies_vector_store_port() -> None:
    store = QdrantVectorStore(client=_FakeQdrantClient())
    assert isinstance(store, VectorStorePort)


def test_every_driver_ann_search_signature_matches_search_store_vector_arm() -> None:
    """`isinstance(..., VectorStorePort)` is a `runtime_checkable` Protocol check: it verifies
    method NAMES exist and nothing else. This is the assertion that actually catches drift --
    if `SearchStore.vector_arm` grows a parameter, `PgVectorStore.ann_search` (a passthrough)
    and the port itself must grow it too, or the passthrough breaks at the first real call."""
    reference = inspect.signature(SearchStore.vector_arm)
    for method in (
        PgVectorStore.ann_search,
        QdrantVectorStore.ann_search,
        VectorStorePort.ann_search,
    ):
        assert inspect.signature(method) == reference, method.__qualname__


# --------------------------------------------------------------------------------------- #
# PgVectorStore: faithful delegation to stores.pg.search / stores.pg.partitions
# --------------------------------------------------------------------------------------- #


class _FakeSearchStore:
    """Records the exact call `PgVectorStore.ann_search` makes -- proves it is a passthrough,
    not a parallel implementation."""

    def __init__(self, hits: list[ArmHit]) -> None:
        self._hits = hits
        self.calls: list[tuple[ProjectId, Sequence[float], int, bool, int]] = []
        self.statement_timeouts: list[int | None] = []

    def vector_arm(
        self,
        project_id: ProjectId,
        embedding: Sequence[float],
        top_n: int,
        *,
        hnsw_iterative_scan: bool,
        hnsw_max_scan_tuples: int,
        statement_timeout_ms: int | None = None,
    ) -> list[ArmHit]:
        self.calls.append((project_id, embedding, top_n, hnsw_iterative_scan, hnsw_max_scan_tuples))
        self.statement_timeouts.append(statement_timeout_ms)
        return self._hits


def test_pgvector_ann_search_delegates_faithfully_to_search_store() -> None:
    hits = [_hit(MEM_1, 0.9)]
    fake_search = _FakeSearchStore(hits)
    store = PgVectorStore(search=fake_search, pool=MagicMock())  # type: ignore[arg-type]

    result = store.ann_search(
        PROJECT_A, [0.1, 0.2, 0.3], 5, hnsw_iterative_scan=True, hnsw_max_scan_tuples=20_000
    )

    assert result == hits
    assert fake_search.calls == [(PROJECT_A, [0.1, 0.2, 0.3], 5, True, 20_000)]
    assert fake_search.statement_timeouts == [None]


def test_pgvector_ann_search_forwards_the_server_side_bound_rather_than_dropping_it() -> None:
    """D-139. The bound is the one thing on this port that can be silently accepted and
    discarded and leave no trace: the query still runs, still returns, and only the recovery
    behaviour under a stalled store differs. Qdrant documents exactly that drop as a contract
    gap; pgvector must not have it, since pgvector is the shipped driver and `SearchStore` is
    where the `set_config` is actually issued.
    """
    fake_search = _FakeSearchStore([])
    store = PgVectorStore(search=fake_search, pool=MagicMock())  # type: ignore[arg-type]

    store.ann_search(
        PROJECT_A,
        [0.1],
        3,
        hnsw_iterative_scan=False,
        hnsw_max_scan_tuples=1,
        statement_timeout_ms=173,
    )

    assert fake_search.statement_timeouts == [173]


def test_pgvector_ann_search_passes_the_project_it_was_given_not_another() -> None:
    """A second project through the same instance must not be answered from the first's
    arguments -- the store holds no per-call state (it is shared across the retriever's
    threads)."""
    fake_search = _FakeSearchStore([])
    store = PgVectorStore(search=fake_search, pool=MagicMock())  # type: ignore[arg-type]

    store.ann_search(PROJECT_A, [0.1], 3, hnsw_iterative_scan=False, hnsw_max_scan_tuples=1)
    store.ann_search(PROJECT_B, [0.2], 4, hnsw_iterative_scan=True, hnsw_max_scan_tuples=2)

    assert [call[0] for call in fake_search.calls] == [PROJECT_A, PROJECT_B]
    assert [call[2] for call in fake_search.calls] == [3, 4]


def test_pgvector_upsert_reports_the_missing_write_primitive_rather_than_a_placeholder() -> None:
    store = PgVectorStore(search=MagicMock(), pool=MagicMock())
    with pytest.raises(VectorStoreWriteUnavailable, match="embedding-write primitive"):
        store.upsert(PROJECT_A, MEM_1, [0.1, 0.2], trust_tier=TrustTier.A, status=Status.VALIDATED)


def test_pgvector_delete_by_project_delegates_to_drop_project() -> None:
    fake_pool = MagicMock()
    fake_conn = MagicMock()
    fake_pool.connection.return_value.__enter__.return_value = fake_conn
    store = PgVectorStore(search=MagicMock(), pool=fake_pool)

    with patch("tracebed.stores.vector.pgvector.drop_project") as mock_drop:
        store.delete_by_project(PROJECT_A)

    mock_drop.assert_called_once_with(fake_conn, PROJECT_A)


# --------------------------------------------------------------------------------------- #
# QdrantVectorStore: off by default, lazy import, structural project scoping
# --------------------------------------------------------------------------------------- #


def test_qdrant_disabled_by_default() -> None:
    assert DEFAULT_ENABLED is False


def test_qdrant_unavailable_without_package_or_client() -> None:
    # qdrant-client is genuinely not installed in this environment (PLAN.md §7: "do NOT add
    # a qdrant dependency to pyproject") -- this exercises the real ImportError path.
    with pytest.raises(QdrantUnavailable, match="qdrant-client is not installed"):
        QdrantVectorStore(url="http://localhost:6333")


def test_qdrant_requires_url_for_a_real_client() -> None:
    with pytest.raises(ValueError, match="requires `url`"):
        QdrantVectorStore()


class _FakeQdrantClient:
    """Satisfies `QdrantClientPort`; records every call verbatim so tests can assert exactly
    what was sent over the wire -- no server needed."""

    def __init__(self, search_results: list[Any] | None = None) -> None:
        self._search_results = search_results if search_results is not None else []
        self.search_calls: list[dict[str, Any]] = []
        self.upsert_calls: list[dict[str, Any]] = []
        self.delete_calls: list[dict[str, Any]] = []

    def search(
        self,
        collection_name: str,
        query_vector: Sequence[float],
        query_filter: Mapping[str, Any],
        limit: int,
    ) -> Sequence[Any]:
        self.search_calls.append(
            {
                "collection_name": collection_name,
                "query_vector": query_vector,
                "query_filter": query_filter,
                "limit": limit,
            }
        )
        return self._search_results

    def upsert(self, collection_name: str, points: Sequence[Mapping[str, Any]]) -> Any:
        self.upsert_calls.append({"collection_name": collection_name, "points": points})
        return None

    def delete(self, collection_name: str, points_selector: Mapping[str, Any]) -> Any:
        self.delete_calls.append(
            {"collection_name": collection_name, "points_selector": points_selector}
        )
        return None


def _payload_result(
    project_id: ProjectId,
    memory_id: MemoryId,
    score: float,
    *,
    status: Status = Status.VALIDATED,
    trust_tier: TrustTier = TrustTier.A,
) -> dict[str, Any]:
    return {
        "score": score,
        "payload": {
            "project_id": str(project_id.value),
            "memory_id": str(memory_id.value),
            "trust_tier": trust_tier.value,
            "status": status.value,
        },
    }


# -- filters ----------------------------------------------------------------------------- #


def test_qdrant_search_filter_is_exactly_the_expected_structure() -> None:
    assert _search_filter(PROJECT_A) == _expected_search_filter(PROJECT_A)
    assert _search_filter(PROJECT_B) != _search_filter(PROJECT_A)


def _condition_matches(condition: Mapping[str, Any], payload: Mapping[str, Any]) -> bool:
    """Qdrant's own semantics for the two condition shapes this driver emits (a keyed `match`,
    or a nested filter), re-implemented in ten lines so the equivalence test below can be run
    without a server. Any shape the driver starts emitting that is not one of these two makes
    this raise rather than silently return `False`."""
    if "key" in condition:
        return payload.get(condition["key"]) == condition["match"]["value"]
    if "must" in condition or "should" in condition:
        return _filter_matches(condition, payload)
    raise AssertionError(f"unrecognised qdrant condition shape: {condition!r}")


def _filter_matches(flt: Mapping[str, Any], payload: Mapping[str, Any]) -> bool:
    if not all(_condition_matches(c, payload) for c in flt.get("must", ())):
        return False
    should = flt.get("should")
    return should is None or any(_condition_matches(c, payload) for c in should)


def test_qdrant_search_filter_admits_exactly_what_invariant_7_permits() -> None:
    """The server-side half of invariant 7 on the no-RLS path, proven equal to the rule
    `stores.pg.search` owns over EVERY (status, tier) pair -- not asserted for one happy
    status. If the SQL rule changes, this goes red instead of the Qdrant driver quietly
    admitting a wider set (DECISIONS.md names an alternative vector driver as exactly the
    thing that routes around the control)."""
    checked = 0
    for status in Status:
        for tier in TrustTier:
            payload = {
                "project_id": str(PROJECT_A.value),
                "status": status.value,
                "trust_tier": tier.value,
            }
            admitted_by_filter = _filter_matches(_search_filter(PROJECT_A), payload)
            try:
                assert_dynamically_retrievable(MEM_1, status, tier)
            except TracebedError:
                permitted = False
            else:
                permitted = True
            assert admitted_by_filter is permitted, (status, tier)
            checked += 1
    assert checked == len(Status) * len(TrustTier)


def test_qdrant_search_filter_rejects_another_projects_payload() -> None:
    payload = {
        "project_id": str(PROJECT_B.value),
        "status": Status.VALIDATED.value,
        "trust_tier": TrustTier.A.value,
    }
    assert _filter_matches(_search_filter(PROJECT_A), payload) is False


def test_qdrant_erasure_filter_is_project_scoped_but_never_retrievability_scoped() -> None:
    """An erasure narrowed by retrievability would leave behind exactly the quarantined and
    tombstoned vectors it exists to destroy."""
    assert _erasure_filter(PROJECT_A) == {
        "must": [{"key": "project_id", "match": {"value": str(PROJECT_A.value)}}]
    }
    for status in Status:
        payload = {
            "project_id": str(PROJECT_A.value),
            "status": status.value,
            "trust_tier": TrustTier.B.value,
        }
        assert _filter_matches(_erasure_filter(PROJECT_A), payload) is True, status
        other = {**payload, "project_id": str(PROJECT_B.value)}
        assert _filter_matches(_erasure_filter(PROJECT_A), other) is False, status


# -- reads ------------------------------------------------------------------------------- #


def test_qdrant_ann_search_always_attaches_the_project_filter() -> None:
    fake = _FakeQdrantClient(search_results=[_payload_result(PROJECT_A, MEM_1, 0.75)])
    store = QdrantVectorStore(client=fake)

    hits = store.ann_search(
        PROJECT_A, [0.1, 0.2], 10, hnsw_iterative_scan=True, hnsw_max_scan_tuples=20_000
    )

    assert len(fake.search_calls) == 1
    assert fake.search_calls[0]["query_filter"] == _expected_search_filter(PROJECT_A)
    assert fake.search_calls[0]["limit"] == 10
    assert hits == [_hit(MEM_1, 0.75)]


def test_qdrant_ann_search_bounds_a_pathological_top_n() -> None:
    fake = _FakeQdrantClient()
    store = QdrantVectorStore(client=fake)

    store.ann_search(
        PROJECT_A, [0.1], 10_000_000, hnsw_iterative_scan=False, hnsw_max_scan_tuples=1
    )

    assert fake.search_calls[0]["limit"] == 1_000


def test_qdrant_cross_project_result_is_structurally_impossible_to_accept() -> None:
    """Even if a fake/buggy client ignored the filter and returned another project's point,
    `QdrantVectorStore` refuses to hand it back -- the query-time filter is the primary
    control, this is the fail-closed backstop (PLAN.md §7: 'no RLS backstop')."""
    fake = _FakeQdrantClient(search_results=[_payload_result(PROJECT_B, MEM_2, 0.9)])
    store = QdrantVectorStore(client=fake)

    with pytest.raises(QdrantScopeViolation):
        store.ann_search(
            PROJECT_A, [0.1, 0.2], 10, hnsw_iterative_scan=True, hnsw_max_scan_tuples=20_000
        )


@pytest.mark.parametrize(
    ("status", "trust_tier"),
    [
        (Status.QUARANTINED, TrustTier.A),
        (Status.RETIRED, TrustTier.A),
        (Status.TOMBSTONED, TrustTier.A),
        (Status.STALE, TrustTier.A),
        (Status.PINNED, TrustTier.A),
        (Status.CANDIDATE, TrustTier.B),
    ],
)
def test_qdrant_refuses_a_non_retrievable_hit_the_filter_should_have_excluded(
    status: Status, trust_tier: TrustTier
) -> None:
    """Invariant 7's way-OUT half on the no-RLS path: a stale payload, a widened filter or a
    buggy server cannot put a quarantined memory into fusion through this driver."""
    fake = _FakeQdrantClient(
        search_results=[
            _payload_result(PROJECT_A, MEM_1, 0.9, status=status, trust_tier=trust_tier)
        ]
    )
    store = QdrantVectorStore(client=fake)

    with pytest.raises(TracebedError, match="retrievability predicate breached"):
        store.ann_search(PROJECT_A, [0.1], 10, hnsw_iterative_scan=True, hnsw_max_scan_tuples=1)


def test_qdrant_accepts_a_tier_a_candidate_hit() -> None:
    """The other side of the same rule -- the filter is not simply "validated only"."""
    fake = _FakeQdrantClient(
        search_results=[
            _payload_result(
                PROJECT_A, MEM_1, 0.4, status=Status.CANDIDATE, trust_tier=TrustTier.A
            )
        ]
    )
    store = QdrantVectorStore(client=fake)

    hits = store.ann_search(PROJECT_A, [0.1], 10, hnsw_iterative_scan=True, hnsw_max_scan_tuples=1)

    assert [(h.memory_id, h.status) for h in hits] == [(MEM_1, Status.CANDIDATE)]


@pytest.mark.parametrize(
    ("result", "expected_message"),
    [
        ({"score": 0.5}, "carries no payload"),
        (
            {"score": 0.5, "payload": {"project_id": str(PROJECT_A.value)}},
            "missing 'memory_id'",
        ),
        (
            {
                "score": 0.5,
                "payload": {
                    "project_id": str(PROJECT_A.value),
                    "memory_id": str(MEM_1.value),
                    "status": "validated",
                },
            },
            "missing 'trust_tier'",
        ),
        (
            {
                "score": 0.5,
                "payload": {
                    "project_id": str(PROJECT_A.value),
                    "memory_id": str(MEM_1.value),
                    "trust_tier": "Z",
                    "status": "validated",
                },
            },
            "not parseable",
        ),
        (
            {
                "score": 0.5,
                "payload": {
                    "project_id": str(PROJECT_A.value),
                    "memory_id": "not-a-uuid",
                    "trust_tier": "A",
                    "status": "validated",
                },
            },
            "not parseable",
        ),
    ],
)
def test_qdrant_malformed_payload_raises_a_typed_store_error(
    result: dict[str, Any], expected_message: str
) -> None:
    """A bare `KeyError`/`ValueError` escaping a retrieval arm fails the RUN; the degradation
    ladder (invariant 2) is written in terms of typed store failures.

    The message is pinned, not just the type: a MISSING field and an UNPARSEABLE one are
    different operator problems (a write path that never wrote the column vs. a schema skew),
    and collapsing both into "not parseable: 'None' is not a valid UUID" sends whoever reads
    the log looking for the wrong bug."""
    store = QdrantVectorStore(client=_FakeQdrantClient(search_results=[result]))
    with pytest.raises(QdrantPayloadInvalid, match=expected_message):
        store.ann_search(PROJECT_A, [0.1], 10, hnsw_iterative_scan=True, hnsw_max_scan_tuples=1)


def test_qdrant_non_mapping_payload_is_refused() -> None:
    store = QdrantVectorStore(client=_FakeQdrantClient(search_results=[{"score": 1.0, "payload": []}]))
    with pytest.raises(QdrantScopeViolation):
        store.ann_search(PROJECT_A, [0.1], 10, hnsw_iterative_scan=True, hnsw_max_scan_tuples=1)


def test_qdrant_ann_search_returns_empty_for_non_positive_top_n_or_empty_embedding() -> None:
    fake = _FakeQdrantClient(search_results=[_payload_result(PROJECT_A, MEM_1, 0.5)])
    store = QdrantVectorStore(client=fake)

    assert store.ann_search(PROJECT_A, [0.1], 0, hnsw_iterative_scan=True, hnsw_max_scan_tuples=1) == []
    assert store.ann_search(PROJECT_A, [], 10, hnsw_iterative_scan=True, hnsw_max_scan_tuples=1) == []
    assert fake.search_calls == []  # neither call reached the client


@pytest.mark.parametrize("bad", [float("nan"), float("inf"), float("-inf")])
def test_qdrant_rejects_a_non_finite_vector_component_on_both_paths(bad: float) -> None:
    """Parity with `stores.pg.search._embedding_literal`: pgvector refuses these outright, and
    two drivers behind one port must not disagree about what a usable vector is."""
    fake = _FakeQdrantClient()
    store = QdrantVectorStore(client=fake)

    with pytest.raises(ValueError, match="NaN or infinite"):
        store.ann_search(PROJECT_A, [0.1, bad], 5, hnsw_iterative_scan=True, hnsw_max_scan_tuples=1)
    with pytest.raises(ValueError, match="NaN or infinite"):
        store.upsert(PROJECT_A, MEM_1, [0.1, bad], trust_tier=TrustTier.A, status=Status.VALIDATED)

    assert fake.search_calls == []
    assert fake.upsert_calls == []


# -- writes / deletes -------------------------------------------------------------------- #


def test_qdrant_upsert_stamps_project_id_into_every_point() -> None:
    fake = _FakeQdrantClient()
    store = QdrantVectorStore(client=fake)

    store.upsert(PROJECT_A, MEM_1, [0.1, 0.2], trust_tier=TrustTier.A, status=Status.VALIDATED)

    assert len(fake.upsert_calls) == 1
    point = fake.upsert_calls[0]["points"][0]
    assert point["payload"]["project_id"] == str(PROJECT_A.value)
    assert point["payload"]["memory_id"] == str(MEM_1.value)
    assert point["vector"] == [0.1, 0.2]


def test_qdrant_point_ids_cannot_collide_across_projects() -> None:
    """A Qdrant point id is unique per COLLECTION and upsert-by-id ignores payload filters --
    so the same `memory_id` written by two projects must not resolve to one point, or the
    second write destroys the first project's vector with no read-side filter able to notice.
    The id must still be STABLE for one (project, memory) pair, or every re-embed duplicates
    the point instead of replacing it."""
    assert _point_id(PROJECT_A, MEM_1) != _point_id(PROJECT_B, MEM_1)
    assert _point_id(PROJECT_A, MEM_1) != _point_id(PROJECT_A, MEM_2)
    assert _point_id(PROJECT_A, MEM_1) == _point_id(PROJECT_A, MEM_1)
    assert uuid.UUID(_point_id(PROJECT_A, MEM_1))  # a Qdrant-acceptable id type

    fake = _FakeQdrantClient()
    store = QdrantVectorStore(client=fake)
    store.upsert(PROJECT_A, MEM_1, [0.1], trust_tier=TrustTier.A, status=Status.VALIDATED)
    store.upsert(PROJECT_B, MEM_1, [0.2], trust_tier=TrustTier.A, status=Status.VALIDATED)
    written_ids = [call["points"][0]["id"] for call in fake.upsert_calls]
    assert written_ids[0] != written_ids[1]


def test_qdrant_delete_by_project_sends_a_filter_selector_scoped_to_the_project() -> None:
    fake = _FakeQdrantClient()
    store = QdrantVectorStore(client=fake)

    store.delete_by_project(PROJECT_A)

    assert fake.delete_calls[0]["points_selector"] == {
        "filter": {"must": [{"key": "project_id", "match": {"value": str(PROJECT_A.value)}}]}
    }


def test_qdrant_upsert_rejects_empty_embedding() -> None:
    store = QdrantVectorStore(client=_FakeQdrantClient())
    with pytest.raises(ValueError, match="embedding must not be empty"):
        store.upsert(PROJECT_A, MEM_1, [], trust_tier=TrustTier.A, status=Status.VALIDATED)


# --------------------------------------------------------------------------------------- #
# Contention — real threads, real repetition (fixture-only, no host dependency)
# --------------------------------------------------------------------------------------- #


def _echoed_memory_id(project_value: str) -> MemoryId:
    """The one memory the echoing fakes below hold for a project -- derived FROM the project so
    a hit identifies whose it is.

    This function is why the contention tests can fail at all. A fake that answered every
    project with the same memory id makes a stale-scope race INVISIBLE: the driver would filter
    on thread B's project and re-check the result against thread B's project, agree with
    itself, and hand thread A a perfectly self-consistent answer about the wrong tenant.
    `ArmHit` carries no `project_id`, so the returned id is the only thing a caller can hold
    the answer to.
    """
    return MemoryId(uuid.UUID(int=uuid.UUID(project_value).int + 500_000))


class _EchoingQdrantClient:
    """Answers every search with a point belonging to whatever project the FILTER named.

    This is the fake that makes the concurrency test able to fail: a driver that built its
    filter from anything other than THIS call's own `project_id` (a value cached on the
    instance, a field written by another thread between two statements) answers from the wrong
    project. A fake that echoed the caller's argument instead would make every interleaving
    look correct."""

    def search(
        self,
        collection_name: str,
        query_vector: Sequence[float],
        query_filter: Mapping[str, Any],
        limit: int,
    ) -> Sequence[Any]:
        project_value = query_filter["must"][0]["match"]["value"]
        return [
            {
                "score": 0.5,
                "payload": {
                    "project_id": project_value,
                    "memory_id": str(_echoed_memory_id(project_value).value),
                    "trust_tier": TrustTier.A.value,
                    "status": Status.VALIDATED.value,
                },
            }
        ]

    def upsert(self, collection_name: str, points: Sequence[Mapping[str, Any]]) -> Any:
        return None

    def delete(self, collection_name: str, points_selector: Mapping[str, Any]) -> Any:
        return None


_THREADS = 8
_ITERATIONS = 250


def test_qdrant_concurrent_searches_never_cross_projects() -> None:
    """One shared store, eight threads, 250 searches each, every thread on its own project,
    released together from a barrier so the interleavings are real rather than staged."""
    store = QdrantVectorStore(client=_EchoingQdrantClient())
    barrier = threading.Barrier(_THREADS)
    failures: list[Exception] = []
    seen: list[tuple[int, str]] = []
    lock = threading.Lock()

    def worker(index: int) -> None:
        project_id = ProjectId(uuid.UUID(int=1000 + index))
        mine = _echoed_memory_id(str(project_id.value))
        try:
            barrier.wait(timeout=10)
            for _ in range(_ITERATIONS):
                hits = store.ann_search(
                    project_id, [0.1, 0.2], 5, hnsw_iterative_scan=True, hnsw_max_scan_tuples=1
                )
                # Whose answer this is, not merely that one arrived: a driver holding a project
                # on the instance hands back a self-consistent answer about another tenant, and
                # `len(hits) == 1` is true for that too.
                assert [hit.memory_id for hit in hits] == [mine]
            with lock:
                seen.append((index, str(project_id.value)))
        except Exception as exc:
            # Reported through `failures` rather than raised: an exception in a worker thread
            # is invisible to pytest, so a scope violation here would otherwise PASS.
            with lock:
                failures.append(exc)

    threads = [threading.Thread(target=worker, args=(i,), name=f"qdrant-{i}") for i in range(_THREADS)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)

    assert not any(thread.is_alive() for thread in threads)
    assert failures == []
    assert len(seen) == _THREADS


def test_qdrant_concurrent_upserts_keep_their_own_project_stamp() -> None:
    """Writes are the other half: a batch that mixed scopes, or a point struct assembled from
    instance state, shows up here as a payload/point-id pair belonging to the wrong project."""
    recorded: list[Mapping[str, Any]] = []
    lock = threading.Lock()

    class _RecordingClient(_EchoingQdrantClient):
        def upsert(self, collection_name: str, points: Sequence[Mapping[str, Any]]) -> Any:
            with lock:
                recorded.extend(points)
            return None

    store = QdrantVectorStore(client=_RecordingClient())
    barrier = threading.Barrier(_THREADS)

    def worker(index: int) -> None:
        project_id = ProjectId(uuid.UUID(int=2000 + index))
        memory_id = MemoryId(uuid.UUID(int=3000 + index))
        barrier.wait(timeout=10)
        for _ in range(_ITERATIONS):
            store.upsert(
                project_id, memory_id, [0.1], trust_tier=TrustTier.A, status=Status.VALIDATED
            )

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(_THREADS)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)

    assert len(recorded) == _THREADS * _ITERATIONS
    for point in recorded:
        project_value = point["payload"]["project_id"]
        memory_value = point["payload"]["memory_id"]
        index = uuid.UUID(project_value).int - 2000
        assert 0 <= index < _THREADS
        assert uuid.UUID(memory_value).int == 3000 + index
        assert point["id"] == _point_id(
            ProjectId(uuid.UUID(project_value)), MemoryId(uuid.UUID(memory_value))
        )
    assert len({point["id"] for point in recorded}) == _THREADS


# --------------------------------------------------------------------------------------- #
# Integration — a real Postgres 18 with pgvector (absent here; skips cleanly).
# --------------------------------------------------------------------------------------- #


@pytest.mark.integration
def test_pgvector_ann_search_and_delete_by_project_against_a_real_database(pg: str) -> None:
    """`PgVectorStore` end to end through the real `SearchStore` and `drop_project` it wraps —
    proves the delegation proven offline above is not merely a shape match. Skips (does not
    error) exactly like `tests/phase1/test_search_sql.py`'s own integration test whenever the
    reachable Postgres lacks `pgvector`/`pg_textsearch`, per this repository's environment
    constraint (no Docker/Postgres on this build machine)."""
    import psycopg

    from tracebed.core.scans import ScanContext, scan
    from tracebed.domain.clock import FakeClock
    from tracebed.domain.enums import Lane, MemType, ProvenanceClass, ScopeType
    from tracebed.domain.ids import mint_run_id
    from tracebed.domain.memory import NewMemoryItem, Provenance
    from tracebed.stores.pg.migrate import apply_migrations
    from tracebed.stores.pg.partitions import create_project_partitions
    from tracebed.stores.pg.pool import create_pool
    from tracebed.stores.pg.repo import Repo

    try:
        apply_migrations(pg)
    except Exception as exc:
        pytest.skip(f"could not bring the schema current: {exc.__class__.__name__}")

    pool = create_pool(pg)
    try:
        project_id = ProjectId(uuid.uuid4())
        try:
            with pool.connection() as conn:
                create_project_partitions(conn, project_id)
        except psycopg.errors.UndefinedObject as exc:
            pytest.skip(f"pgvector/pg_textsearch access method unavailable: {exc}")
        except Exception as exc:  # pragma: no cover - environment-dependent
            pytest.skip(f"could not provision a test project: {exc.__class__.__name__}")

        repo = Repo(pool, FakeClock())
        run_id = mint_run_id()
        item = NewMemoryItem(
            scope_type=ScopeType.PROJECT_SHARED,
            scope_id=None,
            mem_type=MemType.LESSON,
            kind="k",
            lane=Lane.OPERATIONAL,
            trust_tier=TrustTier.A,
            # Tier-A `candidate`, not `validated`: `Repo.insert_memory_item` refuses any
            # status that is not a legal CREATION status (invariant 7's creation half), and
            # the retrievability predicate treats a Tier-A candidate as retrievable, which is
            # all this driver test needs.
            status=Status.CANDIDATE,
            content="retry the flaky tool with jittered backoff",
            token_count=6,
            provenance=Provenance(cls=ProvenanceClass.PARSER, trace_ids=(run_id,)),
        )
        verdict = scan(
            item.content,
            context=ScanContext(
                project_id=project_id,
                mem_type=item.mem_type,
                trust_tier=item.trust_tier,
                provenance_class=item.provenance.cls,
                lane=Lane.OPERATIONAL,
            ),
        ).verdict()
        memory_id = repo.insert_memory_item(project_id, item, verdict)

        from tracebed.stores.pg.pool import scoped

        # Seeds `memory_item.embedding` directly -- Repo has no write path for it at all (the
        # CONTRACT GAP `PgVectorStore.upsert` reports); this is test-setup-only, never a
        # production write path, and tests/ is outside raw_sql_lint's scanned root. Uses
        # `scoped()` (the one existing RLS-GUC-setting gateway) rather than a bare connection.
        embedding = [0.1] * 768
        literal = "[" + ",".join(repr(v) for v in embedding) + "]"
        try:
            with scoped(pool, project_id) as conn:
                conn.execute(
                    "UPDATE memory_item SET embedding = %(embedding)s::halfvec "
                    "WHERE project_id = %(project_id)s AND id = %(id)s",
                    {"embedding": literal, "project_id": project_id, "id": memory_id},
                )
        except psycopg.errors.UndefinedObject as exc:
            pytest.skip(f"halfvec type unavailable: {exc}")

        from tracebed.stores.pg.search import SearchStore as RealSearchStore

        search = RealSearchStore(pool)
        store = PgVectorStore(search=search, pool=pool)

        hits = store.ann_search(
            project_id, embedding, 10, hnsw_iterative_scan=True, hnsw_max_scan_tuples=20_000
        )
        assert {hit.memory_id for hit in hits} == {memory_id}

        from tracebed.stores.pg.partitions import partition_name

        store.delete_by_project(project_id)
        with pool.connection() as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT to_regclass(%s) IS NOT NULL",
                (partition_name("memory_item", project_id),),
            )
            row = cur.fetchone()
            assert row is not None
            assert row[0] is False, "memory_item partition should be gone after delete_by_project"
    finally:
        pool.close()
