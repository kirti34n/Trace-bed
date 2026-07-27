"""`AgeGraphStore` — an Apache AGE `GraphStorePort` hook (PLAN.md §7 Phase 4).

OFF BY DEFAULT (`DEFAULT_ENABLED` below; same CONTRACT GAP on its home as
`stores.vector.qdrant.DEFAULT_ENABLED` — `domain/config.py` is outside this chunk's file list).

CONTRACT GAP (query execution — the load-bearing one): `stores/graph/age.py` sits outside
`stores/pg/`, so it may not execute SQL or call anything named `.execute(...)` at all —
`scripts/raw_sql_lint.py`'s AST walk flags any `execute`/`executemany`/`execute_batch`/
`executescript`/`copy`-named call anywhere outside `stores/pg/`, regardless of what object it
is called on. The SQL wrapper AGE's Cypher queries need —
`SELECT * FROM cypher(%(graph)s, $$ ... $$) AS (result agtype)`, run against a pooled psycopg
connection with the RLS GUC set exactly like every other partitioned read
(`stores.pg.pool.scoped`) — is precisely the kind of literal the raw-SQL containment rule
exists to keep out of every package but one.

`AgeGraphStore` therefore depends on an injected `CypherExecutorPort` — the "run this Cypher,
get rows back" primitive — rather than a psycopg connection or the AGE extension directly.
Wiring a real executor against `stores.pg.pool.scoped()` is a CONTRACT GAP for whoever owns
`stores/pg/` next: that file is outside this chunk's file list, and nothing shipped in Phases
0-3 implements this port. This chunk does not fabricate that wiring — a hook that pretends to
run a query it cannot is exactly the placeholder hard rule 8 forbids.

Constructing `AgeGraphStore` WITHOUT an explicit executor attempts a lazy import of the
optional `age` package (`apache-age-python`) purely to give the off-by-default path an
actionable, specific "not installed" message — it is NOT a `pyproject.toml` dependency (D-036:
it would need its own `scripts/license_policy.toml` entry, the way psycopg's LGPL and
`onnxruntime`'s optional extra did). Even with the package importable, this chunk still ships
no default executor (see above), so construction without one still fails — loudly, naming the
real gap, never silently succeeding into a client that cannot answer a query.

THE WALL STILL APPLIES (PLAN.md §7): every query this module builds embeds `project_id` as a
node PROPERTY match on every node pattern in the Cypher text (`_scoped_node`), never only in a
`WHERE` clause a future edit could drop — there is no method here, and no parameter on any
method, that can build a query omitting it. Every row `CypherExecutorPort.run_cypher` returns
is re-checked on the way out (`_row_memory_id`): a row tagged with a different `project_id`
raises `AgeScopeViolation` rather than being silently trusted — the same fail-closed
discipline `stores.pg.search.assert_dynamically_retrievable` and `stores.vector.qdrant`'s own
result check apply.

NOT the vector driver's invariant-7 problem: `memory_link` edges carry no `status`/`trust_tier`
and are never a retrieval source — `GraphStorePort` answers lineage questions for
`workers.forensics`, whose whole purpose is to walk memories that are being CONTAINED (i.e.
deliberately not retrievable). A retrievability filter here would hide exactly the rows a blast
radius must name.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any, Final, Protocol, runtime_checkable
from uuid import UUID

from tracebed.domain.errors import TracebedError
from tracebed.domain.ids import MemoryId, ProjectId

__all__ = [
    "DEFAULT_ENABLED",
    "AgeGraphStore",
    "AgeRowInvalid",
    "AgeScopeViolation",
    "AgeUnavailable",
    "CypherExecutorPort",
]

# See module docstring's CONTRACT GAP: the real home for this fact is a `domain.config`
# driver-selection field this chunk's file list does not include.
DEFAULT_ENABLED: Final[bool] = False

DEFAULT_GRAPH_NAME: Final[str] = "tracebed_memory_link"

# One edge LABEL for every `memory_link` row, mirroring the SQL table's own shape (PLAN.md §5:
# `memory_link(project_id, src_id, dst_id, relation)`, one table, a `relation` text column --
# not one Postgres table per relation). A per-relation Cypher edge type would be a second,
# divergent modelling choice this hook does not need to make.
_LINK_EDGE_LABEL: Final[str] = "LINK"
_DERIVED_FROM_RELATION: Final[str] = "derived_from"

_RELATION_PROP_KEY: Final[str] = "relation"
_PROJECT_ID_KEY: Final[str] = "project_id"
_MEMORY_ID_KEY: Final[str] = "memory_id"


class AgeUnavailable(TracebedError):
    """Raised at `AgeGraphStore.__init__` when no executor is supplied: either the `age`
    package is missing (install the `tracebed[age]` extra) or, if present, this chunk ships
    no default wiring for it (see module docstring's CONTRACT GAP)."""


class AgeScopeViolation(TracebedError):
    """A row `CypherExecutorPort.run_cypher` returned was tagged with a `project_id` other
    than the one the query was scoped to — the fail-closed backstop PLAN.md §7 requires for a
    second store with no RLS of its own."""


class AgeRowInvalid(TracebedError):
    """A row the executor returned is missing a column this driver must read, or carries a
    value that is not a memory id."""


@runtime_checkable
class CypherExecutorPort(Protocol):
    """What `AgeGraphStore` needs to actually run a query — see module docstring's CONTRACT
    GAP for why this is not a psycopg connection."""

    def run_cypher(
        self, project_id: ProjectId, graph_name: str, cypher: str, params: Mapping[str, Any]
    ) -> Sequence[Mapping[str, Any]]:
        """Runs one parameterised Cypher query against `graph_name`, returns one dict per
        result row. `cypher` is already `project_id`-scoped by the caller (every query this
        module builds carries a `project_id` property match on every node pattern — see
        `_scoped_node`); this port does not add its own scoping, it only executes what it is
        given. `params` always contains `project_id`, so a real executor can additionally set
        the RLS GUC (`stores.pg.pool.scoped`) for the connection it runs on."""
        ...


def _scoped_node(node_var: str, *, memory_id_param: str | None = None) -> str:
    """The ONE node-pattern fragment every query in this module uses.

    `project_id` is a property match ON THE PATTERN, never a separate `WHERE` clause a later
    edit could detach from the pattern it was meant to guard; the value itself travels as the
    `$project_id` BIND parameter `_params` fills from the caller's own `ProjectId` (a Cypher
    string that interpolated the id would be an injection surface and would defeat AGE's plan
    cache). There is no parameter on any public method of this module through which the scope
    could be omitted or pointed at another project.

    `memory_id_param` names the bind parameter identifying ONE node. It is not optional
    decoration on a `MERGE`: `MERGE (n {project_id: $p})` matches ANY node already in the
    project and binds to it, so a merge that identifies its node only by project would attach
    new edges to whichever node happened to exist first. Every `MERGE` pattern here therefore
    identifies its node by `memory_id` as well.
    """
    props = f"{_PROJECT_ID_KEY}: $project_id"
    if memory_id_param is not None:
        props += f", {_MEMORY_ID_KEY}: ${memory_id_param}"
    return f"({node_var} {{{props}}})"


def _params(project_id: ProjectId, **extra: Any) -> dict[str, Any]:
    return {"project_id": str(project_id.value), **extra}


def _row_memory_id(row: Mapping[str, Any], key: str, project_id: ProjectId) -> MemoryId:
    row_project_id = str(row.get(_PROJECT_ID_KEY))
    if row_project_id != str(project_id.value):
        raise AgeScopeViolation(
            f"executor returned a row tagged project_id={row_project_id!r} for a query "
            f"scoped to project_id={project_id.value!r} -- refusing to hand it to the caller"
        )
    raw = row.get(key)
    if raw is None:
        raise AgeRowInvalid(f"executor returned a row with no {key!r} column")
    try:
        return MemoryId(UUID(str(raw)))
    except ValueError as exc:
        # A typed failure, not a bare `ValueError`: `workers.forensics` treats a store fault as
        # a store fault, and an untyped exception from a lineage read would surface as an
        # unrelated crash in the middle of a containment pass.
        raise AgeRowInvalid(f"executor returned {key}={raw!r}, which is not a memory id") from exc


class AgeGraphStore:
    """`GraphStorePort` over Apache AGE. `graph_name` is the one AGE graph housing
    `memory_link` — shared across every project exactly like `memory_item` is one table
    shared across every project (LIST-partitioning scopes by ROW, not by schema/graph);
    `project_id` is a property on every node, never a separate graph per project.

    Stateless per call: no method stores a project, a query or a result on the instance, so one
    store is safely shareable across threads (this chunk's threaded contention tests prove a
    concurrent mix of projects never crosses over)."""

    def __init__(
        self,
        executor: CypherExecutorPort | None = None,
        *,
        graph_name: str = DEFAULT_GRAPH_NAME,
    ) -> None:
        if executor is None:
            # Test/injection seam is the OTHER branch (an explicit executor skips this
            # entirely) -- this branch only matters for the off-by-default real-deployment
            # path, which is the only one that needs the optional dependency at all.
            try:
                import age  # type: ignore[import-not-found]  # noqa: F401
            except ImportError as exc:
                raise AgeUnavailable(
                    "the `age` package (apache-age-python) is not installed; install the "
                    "`tracebed[age]` extra, or construct AgeGraphStore with an explicit "
                    "CypherExecutorPort (see stores/graph/age.py)"
                ) from exc
            raise AgeUnavailable(
                "`age` is installed, but this chunk ships no default CypherExecutorPort -- "
                "wiring one against stores.pg.pool.scoped() is a contract gap outside this "
                "chunk's file list (see stores/graph/age.py module docstring); construct "
                "AgeGraphStore with an explicit executor"
            )
        self._executor = executor
        self._graph_name = graph_name

    def direct_derived_descendants(
        self, project_id: ProjectId, memory_id: MemoryId
    ) -> Sequence[MemoryId]:
        # `dst` is identified by `memory_id` in the PATTERN for the same reason the scope is:
        # a `WHERE` conjunct is one edit away from being dropped, and dropping this one would
        # return every `derived_from` source in the project rather than this memory's.
        cypher = (
            f"MATCH {_scoped_node('src')}"
            f"-[r:{_LINK_EDGE_LABEL}]->{_scoped_node('dst', memory_id_param='memory_id')} "
            f"WHERE r.{_RELATION_PROP_KEY} = $relation "
            "RETURN src.memory_id AS memory_id, src.project_id AS project_id"
        )
        rows = self._executor.run_cypher(
            project_id,
            self._graph_name,
            cypher,
            _params(
                project_id, memory_id=str(memory_id.value), relation=_DERIVED_FROM_RELATION
            ),
        )
        return [_row_memory_id(r, _MEMORY_ID_KEY, project_id) for r in rows]

    def transitive_derived_descendants(
        self,
        project_id: ProjectId,
        memory_id: MemoryId,
        *,
        max_generations: int,
        max_descendants: int,
    ) -> tuple[Sequence[MemoryId], bool]:
        """Bounded BFS over `direct_derived_descendants`, one generation at a time — the same
        shape and bounds as `workers.forensics.Forensics._transitive_descendants` (re-derived
        here, not imported: `workers/` is outside this chunk's file list, and a `stores/`
        module importing `workers/` would itself be a layering violation nothing in this
        codebase permits). A single-round-trip Cypher path query is the real payoff a live AGE
        backend would offer over this — this bounded walk is what the hook can promise with
        only `direct_derived_descendants` as its primitive, exactly like the BFS it mirrors.
        """
        visited = {memory_id}
        frontier = [memory_id]
        order: list[MemoryId] = []
        generations = 0
        truncated = False

        while frontier:
            if generations >= max_generations:
                truncated = True
                break
            generations += 1
            next_frontier: list[MemoryId] = []
            for parent in frontier:
                for child in self.direct_derived_descendants(project_id, parent):
                    if child in visited:
                        continue
                    if len(order) >= max_descendants:
                        truncated = True
                        break
                    visited.add(child)
                    order.append(child)
                    next_frontier.append(child)
                if truncated:
                    break
            if truncated:
                break
            frontier = next_frontier

        return tuple(order), truncated

    def upsert_link(
        self, project_id: ProjectId, src_id: MemoryId, dst_id: MemoryId, relation: str
    ) -> None:
        cypher = (
            f"MERGE {_scoped_node('src', memory_id_param='src_id')} "
            f"MERGE {_scoped_node('dst', memory_id_param='dst_id')} "
            f"MERGE (src)-[r:{_LINK_EDGE_LABEL} {{{_RELATION_PROP_KEY}: $relation}}]->(dst)"
        )
        self._executor.run_cypher(
            project_id,
            self._graph_name,
            cypher,
            _params(
                project_id,
                src_id=str(src_id.value),
                dst_id=str(dst_id.value),
                relation=relation,
            ),
        )

    def delete_by_project(self, project_id: ProjectId) -> None:
        # Scoped by project ONLY -- an erasure that also filtered on anything else would leave
        # exactly the nodes it exists to destroy (same reasoning as the vector driver's
        # erasure filter and `stores.pg.partitions.drop_project`'s whole-partition drop).
        cypher = f"MATCH {_scoped_node('n')} DETACH DELETE n"
        self._executor.run_cypher(project_id, self._graph_name, cypher, _params(project_id))
