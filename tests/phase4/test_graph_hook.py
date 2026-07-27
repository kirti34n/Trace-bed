"""`GraphStorePort` / Apache AGE hook tests (PLAN.md §7 Phase 4).

`AgeGraphStore` is compile-tested via import and unit-tested against a fake
`CypherExecutorPort` -- no Postgres, no AGE extension, no `age` package needed for the
scoping-logic assertions. The two "not wired" failure paths (`age` genuinely absent; `age`
present but no default executor) ARE exercised for real -- `age` is genuinely not installed
in this environment (PLAN.md §7: "no new hard dependency").

Because no executor exists in this repository, the Cypher TEXT is the only artifact these
tests can hold to account -- so they hold it structurally rather than by eyeball: every node
pattern in every query this module can emit is parsed out and checked for the project scope,
and every `MERGE` pattern is checked for the node identity a merge needs to bind ONE node
(`MERGE (n {project_id: $p})` matches any node already in the project, which is a wrong-edge
bug no amount of scoping catches).
"""

from __future__ import annotations

import re
import sys
import threading
import uuid
from collections.abc import Mapping, Sequence
from typing import Any
from unittest.mock import MagicMock

import pytest

from tracebed.domain.ids import MemoryId, ProjectId
from tracebed.stores.graph import GraphStorePort
from tracebed.stores.graph.age import (
    DEFAULT_ENABLED,
    AgeGraphStore,
    AgeRowInvalid,
    AgeScopeViolation,
    AgeUnavailable,
)

pytestmark = pytest.mark.phase4

PROJECT_A = ProjectId(uuid.UUID(int=1))
PROJECT_B = ProjectId(uuid.UUID(int=2))
MEM_ROOT = MemoryId(uuid.UUID(int=100))
MEM_A = MemoryId(uuid.UUID(int=101))
MEM_B = MemoryId(uuid.UUID(int=102))
MEM_C = MemoryId(uuid.UUID(int=103))

# `(var {prop: $bind, ...})` — the only node-pattern shape this module emits.
_NODE_PATTERN = re.compile(r"\(\s*(\w+)\s*\{([^}]*)\}\s*\)")
_MERGE_NODE_PATTERN = re.compile(r"MERGE\s+\(\s*\w+\s*\{([^}]*)\}\s*\)")


class _FakeExecutor:
    """Satisfies `CypherExecutorPort`. `edges` models a `derived_from` adjacency list;
    `direct_derived_descendants`'s query is recognised by its own `RETURN` clause and answered
    from it, everything else (`upsert_link`/`delete_by_project`) just records the call."""

    def __init__(
        self, edges: dict[MemoryId, list[MemoryId]] | None = None, *, leak_wrong_project: bool = False
    ) -> None:
        self._edges = edges if edges is not None else {}
        self._leak = leak_wrong_project
        self.calls: list[tuple[ProjectId, str, str, dict[str, Any]]] = []

    def run_cypher(
        self, project_id: ProjectId, graph_name: str, cypher: str, params: Mapping[str, Any]
    ) -> Sequence[Mapping[str, Any]]:
        self.calls.append((project_id, graph_name, cypher, dict(params)))
        if "RETURN src.memory_id" not in cypher:
            return []
        parent = MemoryId(uuid.UUID(str(params["memory_id"])))
        row_project_id = str(uuid.uuid4()) if self._leak else str(project_id.value)
        return [
            {"memory_id": str(child.value), "project_id": row_project_id}
            for child in self._edges.get(parent, [])
        ]


def _every_query_the_module_can_emit() -> list[str]:
    """One call to each public method, returning the Cypher each produced. Any method added
    later without a scope is caught by the two structural tests that consume this."""
    executor = _FakeExecutor({MEM_ROOT: [MEM_A], MEM_A: [MEM_B]})
    store = AgeGraphStore(executor=executor)
    store.direct_derived_descendants(PROJECT_A, MEM_ROOT)
    store.transitive_derived_descendants(
        PROJECT_A, MEM_ROOT, max_generations=8, max_descendants=8
    )
    store.upsert_link(PROJECT_A, MEM_ROOT, MEM_A, "derived_from")
    store.delete_by_project(PROJECT_A)
    return [call[2] for call in executor.calls]


# --------------------------------------------------------------------------------------- #
# Structural port compliance / off-by-default / lazy import
# --------------------------------------------------------------------------------------- #


def test_age_graph_store_satisfies_graph_store_port() -> None:
    store = AgeGraphStore(executor=_FakeExecutor())
    assert isinstance(store, GraphStorePort)


def test_age_disabled_by_default() -> None:
    assert DEFAULT_ENABLED is False


def test_age_unavailable_when_package_genuinely_absent_and_no_executor() -> None:
    # `age` (apache-age-python) is genuinely not installed here (PLAN.md §7: "no new hard
    # dependency") -- this exercises the real ImportError path, not a simulated one.
    assert "age" not in sys.modules
    with pytest.raises(AgeUnavailable, match="not installed"):
        AgeGraphStore()


def test_age_unavailable_even_when_package_present_without_a_default_executor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Simulates the package being importable to prove the OTHER half of the contract gap:
    # even then, this chunk ships no default wiring (stores/pg/ is outside its file list).
    monkeypatch.setitem(sys.modules, "age", MagicMock())
    with pytest.raises(AgeUnavailable, match="no default CypherExecutorPort"):
        AgeGraphStore()


def test_age_graph_store_with_explicit_executor_never_needs_the_package() -> None:
    assert "age" not in sys.modules
    AgeGraphStore(executor=_FakeExecutor())  # must not raise


# --------------------------------------------------------------------------------------- #
# Structural project scoping
# --------------------------------------------------------------------------------------- #


def test_no_node_pattern_in_any_emitted_query_is_unscoped() -> None:
    """Parses every node pattern out of every query this module can build. A pattern without
    the project property is a cross-project read/write in a store with no RLS behind it."""
    queries = _every_query_the_module_can_emit()
    assert queries
    for cypher in queries:
        patterns = _NODE_PATTERN.findall(cypher)
        assert patterns, f"no parseable node pattern in {cypher!r}"
        for var, props in patterns:
            assert "project_id: $project_id" in props, f"{var} unscoped in {cypher!r}"


def test_every_merge_pattern_identifies_one_node_by_memory_id() -> None:
    """`MERGE (n {project_id: $p})` MATCHES ANY node already in the project and binds to it --
    so a merge scoped only by project attaches the new edge to whichever node happens to exist,
    not to the memory the caller named. Every MERGE pattern must therefore carry the node's own
    identity as well."""
    merge_patterns = [
        props
        for cypher in _every_query_the_module_can_emit()
        for props in _MERGE_NODE_PATTERN.findall(cypher)
    ]
    assert merge_patterns, "upsert_link emits no MERGE node pattern at all"
    for props in merge_patterns:
        assert "project_id: $project_id" in props
        assert re.search(r"memory_id: \$\w+", props), props


def test_direct_derived_descendants_scopes_every_query_to_project_id() -> None:
    executor = _FakeExecutor({MEM_ROOT: [MEM_A]})
    store = AgeGraphStore(executor=executor)

    result = store.direct_derived_descendants(PROJECT_A, MEM_ROOT)

    assert result == [MEM_A]
    assert len(executor.calls) == 1
    called_project_id, _graph_name, cypher, params = executor.calls[0]
    assert called_project_id == PROJECT_A
    assert params["project_id"] == str(PROJECT_A.value)
    assert params["memory_id"] == str(MEM_ROOT.value)
    assert params["relation"] == "derived_from"
    # The scope is a property MATCH on BOTH node patterns, and the memory being asked about
    # identifies the `dst` pattern itself rather than living in a droppable WHERE conjunct.
    assert cypher.count("project_id: $project_id") == 2
    assert "(dst {project_id: $project_id, memory_id: $memory_id})" in cypher
    # Direction: `memory_link(src_id -> dst_id, relation='derived_from')` means SRC is derived
    # FROM DST, so descendants of a memory are the SOURCES of edges pointing at it -- the same
    # direction `ForensicsRepoPort.list_direct_derived_descendants` documents.
    assert "RETURN src.memory_id AS memory_id" in cypher


def test_direct_derived_descendants_raises_on_a_cross_project_row() -> None:
    """Even if the (fake/buggy) executor ignored scoping and returned another project's row,
    `AgeGraphStore` refuses to hand it back -- the fail-closed backstop (PLAN.md §7: 'no RLS
    backstop')."""
    executor = _FakeExecutor({MEM_ROOT: [MEM_A]}, leak_wrong_project=True)
    store = AgeGraphStore(executor=executor)

    with pytest.raises(AgeScopeViolation):
        store.direct_derived_descendants(PROJECT_A, MEM_ROOT)


class _MalformedRowExecutor:
    def __init__(self, row: Mapping[str, Any]) -> None:
        self._row = row

    def run_cypher(
        self, project_id: ProjectId, graph_name: str, cypher: str, params: Mapping[str, Any]
    ) -> Sequence[Mapping[str, Any]]:
        return [{"project_id": str(project_id.value), **self._row}]


@pytest.mark.parametrize(
    ("row", "expected_message"),
    [
        ({}, "no 'memory_id' column"),
        ({"memory_id": None}, "no 'memory_id' column"),
        ({"memory_id": "not-a-uuid"}, "not a memory id"),
    ],
)
def test_a_malformed_row_raises_a_typed_store_error(
    row: Mapping[str, Any], expected_message: str
) -> None:
    """A bare `KeyError`/`ValueError` from a lineage read would surface as an unrelated crash
    in the middle of a `workers.forensics` containment pass.

    The message is pinned as well as the type: "the executor returned no such column" and "the
    executor returned a value that is not an id" are different faults (a wrong RETURN clause vs.
    a graph holding junk), and one message for both misdirects whoever debugs it."""
    store = AgeGraphStore(executor=_MalformedRowExecutor(row))
    with pytest.raises(AgeRowInvalid, match=expected_message):
        store.direct_derived_descendants(PROJECT_A, MEM_ROOT)


def test_upsert_link_binds_both_endpoints_and_scopes_to_project_id() -> None:
    executor = _FakeExecutor()
    store = AgeGraphStore(executor=executor)

    store.upsert_link(PROJECT_A, MEM_ROOT, MEM_A, "derived_from")

    called_project_id, _graph_name, cypher, params = executor.calls[0]
    assert called_project_id == PROJECT_A
    assert params["project_id"] == str(PROJECT_A.value)
    assert params["src_id"] == str(MEM_ROOT.value)
    assert params["dst_id"] == str(MEM_A.value)
    assert params["relation"] == "derived_from"
    assert cypher.count("project_id: $project_id") == 2
    assert "MERGE (src {project_id: $project_id, memory_id: $src_id})" in cypher
    assert "MERGE (dst {project_id: $project_id, memory_id: $dst_id})" in cypher
    assert "MERGE (src)-[r:LINK {relation: $relation}]->(dst)" in cypher


def test_delete_by_project_scopes_to_project_id_and_nothing_narrower() -> None:
    executor = _FakeExecutor()
    store = AgeGraphStore(executor=executor)

    store.delete_by_project(PROJECT_A)

    called_project_id, _graph_name, cypher, params = executor.calls[0]
    assert called_project_id == PROJECT_A
    assert params == {"project_id": str(PROJECT_A.value)}
    assert "project_id: $project_id" in cypher
    assert "DETACH DELETE" in cypher
    # An erasure narrowed by anything else leaves behind exactly what it exists to destroy.
    assert "WHERE" not in cypher
    assert _NODE_PATTERN.findall(cypher) == [("n", "project_id: $project_id")]


def test_two_projects_produce_independent_calls_with_distinct_scoping() -> None:
    executor = _FakeExecutor({MEM_ROOT: [MEM_A]})
    store = AgeGraphStore(executor=executor)

    store.direct_derived_descendants(PROJECT_A, MEM_ROOT)
    store.direct_derived_descendants(PROJECT_B, MEM_ROOT)

    project_ids_seen = {call[3]["project_id"] for call in executor.calls}
    assert project_ids_seen == {str(PROJECT_A.value), str(PROJECT_B.value)}


# --------------------------------------------------------------------------------------- #
# Transitive descendant walk (the forensics-descendant-walk consumer PLAN.md §7 names)
# --------------------------------------------------------------------------------------- #


def test_transitive_derived_descendants_finds_the_third_generation() -> None:
    """root -> a -> b -> c: `c` is only reachable through TWO intermediate hops, exactly the
    case a naive one-hop implementation misses (mirrors `workers.forensics`'s own gate
    assertion, re-derived independently here per this module's CONTRACT GAP)."""
    executor = _FakeExecutor({MEM_ROOT: [MEM_A], MEM_A: [MEM_B], MEM_B: [MEM_C]})
    store = AgeGraphStore(executor=executor)

    descendants, truncated = store.transitive_derived_descendants(
        PROJECT_A, MEM_ROOT, max_generations=256, max_descendants=10_000
    )

    assert list(descendants) == [MEM_A, MEM_B, MEM_C]
    assert truncated is False


def test_transitive_derived_descendants_reports_truncation_on_generation_bound() -> None:
    executor = _FakeExecutor({MEM_ROOT: [MEM_A], MEM_A: [MEM_B], MEM_B: [MEM_C]})
    store = AgeGraphStore(executor=executor)

    descendants, truncated = store.transitive_derived_descendants(
        PROJECT_A, MEM_ROOT, max_generations=1, max_descendants=10_000
    )

    assert list(descendants) == [MEM_A]
    assert truncated is True


def test_transitive_derived_descendants_reports_truncation_on_descendant_count_bound() -> None:
    executor = _FakeExecutor({MEM_ROOT: [MEM_A, MEM_B]})
    store = AgeGraphStore(executor=executor)

    descendants, truncated = store.transitive_derived_descendants(
        PROJECT_A, MEM_ROOT, max_generations=256, max_descendants=1
    )

    assert list(descendants) == [MEM_A]
    assert truncated is True


def test_transitive_derived_descendants_completing_exactly_at_the_bound_is_not_truncated() -> None:
    executor = _FakeExecutor({MEM_ROOT: [MEM_A]})
    store = AgeGraphStore(executor=executor)

    descendants, truncated = store.transitive_derived_descendants(
        PROJECT_A, MEM_ROOT, max_generations=256, max_descendants=1
    )

    assert list(descendants) == [MEM_A]
    assert truncated is False


def test_transitive_derived_descendants_generation_bound_matches_the_forensics_walk() -> None:
    """`max_generations=2` over root -> a -> b -> c must return TWO generations and report
    truncation -- an off-by-one either way (an extra generation, or a `truncated` that fires
    on a walk that had nothing left to explore) is invisible in a one-generation test."""
    executor = _FakeExecutor({MEM_ROOT: [MEM_A], MEM_A: [MEM_B], MEM_B: [MEM_C]})
    store = AgeGraphStore(executor=executor)

    descendants, truncated = store.transitive_derived_descendants(
        PROJECT_A, MEM_ROOT, max_generations=2, max_descendants=10_000
    )

    assert list(descendants) == [MEM_A, MEM_B]
    assert truncated is True


def test_a_generation_bound_reached_with_an_unqueried_frontier_reports_truncated() -> None:
    """root -> a -> b, `max_generations=2`: `b` is found, but `b`'s OWN edges are never
    queried, so the walk cannot know the graph is exhausted. Reporting `truncated=True` here is
    the conservative direction and is exactly what `workers.forensics` does -- an
    over-reported blast radius is re-checkable, an under-reported one is trusted.

    The parallel case for the DESCENDANT bound is genuinely different and tested separately
    (`..._completing_exactly_at_the_bound_is_not_truncated`): there the frontier IS exhausted,
    so the walk knows it is complete.
    """
    executor = _FakeExecutor({MEM_ROOT: [MEM_A], MEM_A: [MEM_B]})
    store = AgeGraphStore(executor=executor)

    descendants, truncated = store.transitive_derived_descendants(
        PROJECT_A, MEM_ROOT, max_generations=2, max_descendants=10_000
    )

    assert list(descendants) == [MEM_A, MEM_B]
    assert truncated is True


@pytest.mark.parametrize(
    "edges",
    [
        {MEM_ROOT: [MEM_A], MEM_A: [MEM_B], MEM_B: [MEM_C]},
        {MEM_ROOT: [MEM_A, MEM_B], MEM_A: [MEM_C]},
        {MEM_ROOT: [MEM_A], MEM_A: [MEM_ROOT]},
        {MEM_ROOT: [MEM_A, MEM_B, MEM_C], MEM_B: [MEM_A]},
        {},
    ],
)
@pytest.mark.parametrize(("max_generations", "max_descendants"), [(1, 10), (2, 10), (256, 1), (256, 2), (256, 10_000)])
def test_the_walk_is_bit_for_bit_the_forensics_walk(
    edges: dict[MemoryId, list[MemoryId]],
    max_generations: int,
    max_descendants: int,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`age.py`'s docstring claims this BFS is `workers.forensics.Forensics
    ._transitive_descendants` re-derived (it may not import `workers/` from `stores/`). This
    runs BOTH over the same graph at the same bounds and demands identical output, including
    the `truncated` flag -- so "mirrors forensics" is a checked fact rather than a comment that
    rots the first time either walk is edited."""
    from tracebed.domain.clock import FakeClock
    from tracebed.workers import forensics as forensics_module

    monkeypatch.setattr(forensics_module, "MAX_GENERATIONS_CONSIDERED", max_generations)
    monkeypatch.setattr(forensics_module, "MAX_DESCENDANTS_CONSIDERED", max_descendants)

    class _Repo:
        def list_direct_derived_descendants(
            self, project_id: ProjectId, memory_id: MemoryId
        ) -> Sequence[MemoryId]:
            return edges.get(memory_id, [])

    reference = forensics_module.Forensics(
        repo=_Repo(),  # type: ignore[arg-type]
        clock=FakeClock(),
    )
    expected_ids, expected_truncated = reference._transitive_descendants(PROJECT_A, MEM_ROOT)

    store = AgeGraphStore(executor=_FakeExecutor(edges))
    got_ids, got_truncated = store.transitive_derived_descendants(
        PROJECT_A, MEM_ROOT, max_generations=max_generations, max_descendants=max_descendants
    )

    assert tuple(got_ids) == expected_ids
    assert got_truncated is expected_truncated


def test_transitive_derived_descendants_handles_a_cycle_without_looping() -> None:
    executor = _FakeExecutor({MEM_ROOT: [MEM_A], MEM_A: [MEM_ROOT]})
    store = AgeGraphStore(executor=executor)

    descendants, truncated = store.transitive_derived_descendants(
        PROJECT_A, MEM_ROOT, max_generations=256, max_descendants=10_000
    )

    assert list(descendants) == [MEM_A]
    assert truncated is False


def test_transitive_walk_scopes_every_hop_to_the_same_project() -> None:
    executor = _FakeExecutor({MEM_ROOT: [MEM_A], MEM_A: [MEM_B]})
    store = AgeGraphStore(executor=executor)

    store.transitive_derived_descendants(
        PROJECT_B, MEM_ROOT, max_generations=256, max_descendants=10_000
    )

    assert len(executor.calls) == 3  # root, a, b
    assert {call[0] for call in executor.calls} == {PROJECT_B}
    assert {call[3]["project_id"] for call in executor.calls} == {str(PROJECT_B.value)}


# --------------------------------------------------------------------------------------- #
# Contention — real threads, real repetition (fixture-only, no host dependency)
# --------------------------------------------------------------------------------------- #


def _echoed_memory_id(project_value: str) -> MemoryId:
    """The one descendant the echoing executor holds for a project -- derived FROM the project,
    so a returned row identifies whose it is.

    Without that derivation the contention test cannot fail: a driver that bound a stale
    project would query the wrong tenant AND re-check the row against that same stale project,
    agree with itself, and return an answer indistinguishable from the right one."""
    return MemoryId(uuid.UUID(int=uuid.UUID(project_value).int + 500_000))


class _EchoingExecutor:
    """Answers from the PARAMS the driver bound, not from the `project_id` argument it was
    handed -- so a driver that bound a project from anywhere other than this call's own
    argument (a cached value, a field another thread just wrote) answers from the wrong tenant.
    An executor echoing the argument instead would make any interleaving look correct."""

    def run_cypher(
        self, project_id: ProjectId, graph_name: str, cypher: str, params: Mapping[str, Any]
    ) -> Sequence[Mapping[str, Any]]:
        if "RETURN src.memory_id" not in cypher:
            return []
        project_value = str(params["project_id"])
        return [
            {
                "memory_id": str(_echoed_memory_id(project_value).value),
                "project_id": project_value,
            }
        ]


def test_concurrent_traversals_never_cross_projects() -> None:
    store = AgeGraphStore(executor=_EchoingExecutor())
    threads_count = 8
    iterations = 250
    barrier = threading.Barrier(threads_count)
    failures: list[Exception] = []
    lock = threading.Lock()

    def worker(index: int) -> None:
        project_id = ProjectId(uuid.UUID(int=4000 + index))
        mine = _echoed_memory_id(str(project_id.value))
        try:
            barrier.wait(timeout=10)
            for _ in range(iterations):
                found = store.direct_derived_descendants(project_id, MEM_ROOT)
                # Whose lineage this is, not merely that a row came back.
                assert list(found) == [mine]
        except Exception as exc:
            # An exception raised in a worker thread is invisible to pytest; collected so a
            # scope violation fails the test instead of passing silently.
            with lock:
                failures.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(threads_count)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)

    assert not any(thread.is_alive() for thread in threads)
    assert failures == []
