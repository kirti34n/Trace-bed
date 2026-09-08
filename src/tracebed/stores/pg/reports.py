"""The D-093 aggregate read queries `api/reports.py` needs (PLAN.md §5, §6, §7 Phase 3/4).

SQL lives here and ONLY here for these four routes -- `scripts/raw_sql_lint.py` fails CI on a
SQL literal or a `.execute(...)` call anywhere outside `stores/pg/`, and this file is the one
this chunk's file list grants for it (`src/tracebed/api/reports.py` composes these results into
response bodies; it must never itself hold a query string).

`ReportsRepo` is deliberately its OWN class rather than new methods bolted onto
`stores.pg.repo.Repo`: `repo.py` is outside this chunk's file list (hard rule), and every query
below is a READ over tables `Repo` already writes -- `trace_index`, `injection_log`,
`retrieval_event`, `outcome_event`, `invalidation_event`, `memory_item`, `derived_state`. Every
public method takes `ProjectId` first and opens its connection exclusively through
`stores.pg.pool.scoped()` (invariant 4) -- the same structural guarantee `Repo` makes, made here
independently because this class does not subclass or wrap `Repo`.

CONTRACT GAPS THIS FILE DOES NOT PAPER OVER (read before trusting a wide response):

1. **Q-value trajectory has no history table.** `memory_item` stores
   `q_value`/`confidence`/`last_scored_at` as CURRENT values only. It does persist the exact
   scorer-selected `epoch_id`, so `q_trajectory()` reads that stored foreign key rather than
   inferring an epoch from wall-clock time. It still returns exactly one point per scored memory:
   a population ordered by when each was last scored is a real (if coarse) trend, not a
   per-memory multi-point trajectory.
2. **Consolidation sweeps are not durable anywhere.** `workers.consolidator`/`workers.deltas`
   both document, verbatim, that `DeltaRecord` (one ADD/AMEND/REMOVE per sweep) has no store --
   "no separate snapshot table this chunk owns". `derived_state` (migrations/0001) is the only
   table in the whole schema shaped like a versioned per-key delta (`version`, `value`,
   `delta_pct`, `computed_at`), but nothing in this codebase writes to it either (verified by
   reading `stores/pg/repo.py` in full: no `insert_derived_state`/`list_derived_state` method
   exists). `consolidation_diffs()` queries it anyway, honestly, rather than fabricating rows a
   nightly-merge loop never wrote -- on every build shipped today it returns an empty page, for
   the same reason `admin.get_killswitch_state`'s docstring gives: "empty... is NOT the same as
   everything being fine; it is what an unwired writer looks like, and the dashboard says so."
   When a future `workers.consolidator` writer lands, this query's shape (ordered by
   `computed_at DESC`, `information_retention = 1 - abs(delta_pct)/100`) is ready for it without
   further schema work.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Final
from uuid import UUID

from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool

from tracebed.domain.clock import Clock
from tracebed.domain.enums import Arm, MemType, OutcomeCode
from tracebed.domain.ids import AgentTypeId, MemoryId, ProjectId, RunId
from tracebed.domain.memory import Provenance
from tracebed.stores.pg.pool import scoped

__all__ = [
    "MAX_LIFT_OBSERVATIONS",
    "MAX_REPORT_LIMIT",
    "MAX_REPORT_OFFSET",
    "MAX_STALE_FOR_MATCHING",
    "ConsolidationDiffRow",
    "InjectionFeedRow",
    "InvalidationReportRow",
    "LiftRunObservationRow",
    "QTrajectoryPointRow",
    "ReportsRepo",
    "RevalidationCandidateRow",
    "StaleMemoryRow",
]

# Same ceiling as `stores.pg.repo.MAX_ROW_LIMIT` -- kept as its own constant rather than an
# import (this file must not depend on `repo.py`, which is outside this chunk's file list; the
# two are independent literals, not a shared one that could silently drift, which is why the
# value is repeated in this module's own docstring-worthy comment rather than assumed identical
# by name alone).
MAX_REPORT_LIMIT: Final[int] = 1_000
# Offset pagination is retained for historical report shapes, but an unbounded
# offset makes PostgreSQL walk and discard an attacker-selected prefix.  A
# finite ceiling keeps the legacy routes bounded until they move to keysets.
MAX_REPORT_OFFSET: Final[int] = 10_000

# Cap on the lift-observation join: a report computes ONE pooled stratified estimate over its
# whole window, not a day-bucketed sustained check (that is `workers.killswitch`'s job, over its
# own store, not this route's) -- but the join still must not become an unbounded server-side
# allocation on a 100k-run project.
#
# EXPORTED, not private, because a truncated join produces a lift estimate whose N is a LOWER
# BOUND on the project's real N, and `api.reports` has to be able to detect that and say so on
# the wire. A governance figure silently computed from the oldest 50,000 of 300,000 runs, whose
# reported N reads as if it were the whole window, is exactly the misleading-figure class this
# product refuses; the cap stays, the silence does not.
MAX_LIFT_OBSERVATIONS: Final[int] = 50_000

# Internal cap on how many `stale` memories are fetched to resolve which ones an
# `invalidation_event`'s selector matches (`api.reports._matched_memory_ids`). Independent of
# the event page's own `limit`/`offset` -- an operator paging through 100k events must not
# also pull every stale memory in the project on every page, but the match set itself has to be
# bounded somewhere too.
MAX_STALE_FOR_MATCHING: Final[int] = 5_000

# E2 report disclosure predicates.  Runtime reports have no direct ACL on
# erasure ledgers/fences/sets; the profiled boolean functions retain the same
# durable predicate while binding every call to the RLS project GUC.  Each
# helper receives only a fixed SQL alias selected in this module.
_ERASURE_PROJECT_TEMPLATE: Final[str] = """
AND public.tracebed_runtime_project_readable(@TABLE@project_id)
""".strip()

_ERASURE_RUN_TEMPLATE: Final[str] = """
AND public.tracebed_runtime_run_visible(@TABLE@project_id, @TABLE@run_id)
""".strip()

_ERASURE_MEMORY_TEMPLATE: Final[str] = """
AND public.tracebed_runtime_memory_visible(@TABLE@project_id, @TABLE@id)
""".strip()

_ERASURE_INVALIDATION_TEMPLATE: Final[str] = """
AND public.tracebed_runtime_subjects_visible(
    @TABLE@project_id, @TABLE@subject_digests
)
""".strip()


def _erasure_project_readable(table_alias: str) -> str:
    return _ERASURE_PROJECT_TEMPLATE.replace("@TABLE@", table_alias)


def _erasure_run_visible(table_alias: str) -> str:
    return _ERASURE_RUN_TEMPLATE.replace("@TABLE@", table_alias)


def _erasure_memory_visible(table_alias: str) -> str:
    return _ERASURE_MEMORY_TEMPLATE.replace("@TABLE@", table_alias)


def _erasure_invalidation_visible(table_alias: str) -> str:
    return _ERASURE_INVALIDATION_TEMPLATE.replace("@TABLE@", table_alias)


def _bounded(limit: int, offset: int) -> tuple[int, int]:
    """Clamp caller-supplied paging into finite report bounds.

    Callers here are always FastAPI `Query(ge=..., le=...)` parameters (already bounded at the
    wire, `api/reports.py`), so this is defence in depth, not the primary control -- the same
    layering `stores.pg.repo._bounded_limit` documents for `MAX_ROW_LIMIT`.
    """
    lim = max(1, min(limit, MAX_REPORT_LIMIT))
    off = max(0, min(offset, MAX_REPORT_OFFSET))
    return lim, off


@dataclass(frozen=True, slots=True)
class LiftRunObservationRow:
    """One run's contribution to `api.reports`'s stratified lift computation.

    One ROW per `(run, mem_type)` pair a run's `injection_log` rows resolve to -- a run that
    injected both a `lesson` and a `fact` memory contributes its outcome to BOTH strata's
    treatment group, because D-027's stratification question ("did memory help THIS agent-type
    x mem-type cell") is asked once per mem_type actually exercised, not once per run.
    `mem_type is None` (a `LEFT JOIN` miss) means this run injected (or would have injected)
    nothing at all -- exactly `workers.lift`'s "neither treatment nor shadow control" case.
    """

    run_id: RunId
    agent_type_id: AgentTypeId
    arm: Arm
    outcome_code: OutcomeCode
    mem_type: MemType | None
    outcome_r: float
    """`AVG(outcome_event.r)` across every outcome_event this run recorded. `outcome_event` has
    no natural single-row-per-run guarantee (multiple adapters may each post one) and this
    module owns no adapter-weighting logic (`scoring.adapter_weights` is `workers.scorer`'s
    field, not this report's) -- an unweighted mean is the least-invented aggregate available
    from data this route is allowed to read."""


@dataclass(frozen=True, slots=True)
class QTrajectoryPointRow:
    """One point of the Q-value trajectory with its stored scorer epoch."""

    memory_id: MemoryId
    agent_type_id: AgentTypeId
    mem_type: MemType
    q_value: float
    confidence: float
    scored_use_count: int
    observed_at: datetime
    scoring_epoch_id: int | None


@dataclass(frozen=True, slots=True)
class InvalidationReportRow:
    """One `invalidation_event` row -- same shape as `stores.pg.rows.InvalidationEventRow`,
    redefined here rather than imported: that dataclass lives in `stores/pg/rows.py`, which is
    outside this chunk's file list."""

    event_id: UUID
    event_type: str
    selector: Mapping[str, object] | None
    fired_at: datetime


@dataclass(frozen=True, slots=True)
class StaleMemoryRow:
    """One `status='stale'` `memory_item` row, projected for staleness reporting."""

    memory_id: MemoryId
    mem_type: MemType
    strike_count: int
    status_changed_at: datetime | None
    last_revalidated_at: datetime | None
    provenance: Provenance


@dataclass(frozen=True, slots=True)
class RevalidationCandidateRow:
    """One `status='validated'` memory whose idle reference is at or past the caller's
    threshold -- i.e. at or past some fraction of `lifecycle.revalidation_age_days` (R).

    This set DELIBERATELY INCLUDES rows already past R, and the field name "candidate" must
    not be read as "not yet due". A `validated` row whose idle age has passed R is the
    under-invalidation signal -- `workers.revalidation` should have acted on it and, as far as
    this row shows, has not -- and dropping it here would hide the one failure the staleness
    report exists to surface. `age_days` and the caller's `r_days` together are what separate
    "approaching" from "overdue"; neither this row nor the wire model asserts which it is.
    """

    memory_id: MemoryId
    mem_type: MemType
    reference_at: datetime
    """`last_retrieved_at`, or `created_at` if the memory was never retrieved -- the exact idle
    reference `workers.revalidation.is_due_for_revalidation` uses."""
    age_days: float
    last_revalidated_at: datetime | None


@dataclass(frozen=True, slots=True)
class ConsolidationDiffRow:
    """One `derived_state` version row (module docstring, gap 2)."""

    agent_type_id: AgentTypeId
    key: str
    version: int
    value: Mapping[str, object]
    delta_pct: float | None
    clamped: bool
    computed_at: datetime


@dataclass(frozen=True, slots=True)
class InjectionFeedRow:
    """One `injection_log` row, joinable to a memory id (task requirement)."""

    run_id: RunId
    memory_id: MemoryId
    slot: str
    score: float
    tokens: int
    injected_at: datetime


class ReportsRepo:
    """The D-093 report queries. `ReportsRepo(pool, clock)` -- constructed once per process in
    `api.main.run()`, exactly like `stores.pg.repo.Repo`, and attached to `app.state` there
    (see that module's own note on why `AppDeps` itself is not extended here: it is outside
    this chunk's file list).
    """

    def __init__(self, pool: ConnectionPool, clock: Clock) -> None:
        self._pool = pool
        self._clock = clock

    # ------------------------------------------------------------------ lift ---------------

    def lift_observations(
        self, project_id: ProjectId, *, since: datetime, limit: int = MAX_LIFT_OBSERVATIONS
    ) -> list[LiftRunObservationRow]:
        """Every `(run, mem_type)` observation `trace_index.started_at >= since` produced,
        for `api.reports` to fold through `workers.lift.compute_stratified_lift`.

        Every one of the four joined tables is filtered on `project_id` explicitly (not left to
        the RLS GUC alone) -- the same belt-and-braces discipline `stores.pg.repo`'s own
        queries use throughout, because the GUC is the backstop, not the primary control
        (`stores.pg.pool.scoped`'s own docstring).

        The ORDER BY is a TOTAL order (`started_at`, then the `trace_index` primary key's
        `run_id`, then the fanned-out `mem_type`), not just `started_at`. `trace_index
        .started_at` is nullable and carries no uniqueness of any kind, and the `run_mem_types`
        LEFT JOIN multiplies each run by the mem_types it injected -- so a partial order plus
        `LIMIT` lets Postgres return a different 50,000 rows for the same query on the same
        data, which makes the SAME lift figure move between two consecutive page loads with no
        write in between. It also let the cut fall in the middle of one run's mem_type fan-out,
        putting that run in one cell's treatment arm and not another's for no reason a reader
        could ever discover.
        """
        lim = max(1, min(limit, MAX_LIFT_OBSERVATIONS))
        with (
            scoped(self._pool, project_id) as conn,
            conn.cursor(row_factory=dict_row) as cur,
        ):
            cur.execute(
                (
                    """
                WITH run_outcomes AS (
                    SELECT run_id, AVG(r)::double precision AS outcome_r
                    FROM outcome_event
                    WHERE project_id = %(project_id)s
                    @OUTCOME_FENCE@
                    GROUP BY run_id
                ),
                run_mem_types AS (
                    SELECT DISTINCT ij.run_id, mi.mem_type
                    FROM injection_log ij
                    JOIN memory_item mi
                        ON mi.project_id = ij.project_id AND mi.id = ij.memory_id
                    WHERE ij.project_id = %(project_id)s
                    @INJECTION_FENCE@
                    @MEMORY_FENCE@
                )
                SELECT
                    ti.run_id AS run_id,
                    ti.agent_type_id AS agent_type_id,
                    -- `re.arm`, not `ti.arm`: the arm the SERVER assigned for this run
                    -- (`hotpath.pipeline` -> `retrieval_event`), which is the value the
                    -- experiment is stratified on. `trace_index.arm` is now derived from this
                    -- same column by the ingest upsert, so the two agree -- reading the
                    -- first-hand source removes the derivation from the governing number's
                    -- dependency chain entirely (PLAN.md §10).
                    re.arm AS arm,
                    re.outcome_code AS outcome_code,
                    rmt.mem_type AS mem_type,
                    ro.outcome_r AS outcome_r
                FROM trace_index ti
                JOIN retrieval_event re
                    ON re.project_id = ti.project_id AND re.run_id = ti.run_id
                JOIN run_outcomes ro
                    ON ro.run_id = ti.run_id
                LEFT JOIN run_mem_types rmt
                    ON rmt.run_id = ti.run_id
                WHERE ti.project_id = %(project_id)s
                  AND re.project_id = %(project_id)s
                  AND ti.started_at >= %(since)s
                  @TRACE_FENCE@
                ORDER BY ti.started_at ASC, ti.run_id ASC, rmt.mem_type ASC NULLS LAST
                LIMIT %(limit)s
                    """.replace("@OUTCOME_FENCE@", _erasure_run_visible("outcome_event."))
                    .replace("@INJECTION_FENCE@", _erasure_run_visible("ij."))
                    .replace("@MEMORY_FENCE@", _erasure_memory_visible("mi."))
                    .replace("@TRACE_FENCE@", _erasure_run_visible("ti."))
                ),
                {"project_id": project_id, "since": since, "limit": lim},
            )
            rows = cur.fetchall()
        observations: list[LiftRunObservationRow] = []
        for row in rows:
            observations.append(
                LiftRunObservationRow(
                    run_id=RunId(row["run_id"]),
                    agent_type_id=AgentTypeId(row["agent_type_id"]),
                    arm=Arm(row["arm"]),
                    outcome_code=OutcomeCode(row["outcome_code"]),
                    mem_type=MemType(row["mem_type"]) if row["mem_type"] is not None else None,
                    outcome_r=float(row["outcome_r"]),
                )
            )
        return observations

    # ------------------------------------------------------------------ Q trajectory -------

    def q_trajectory(
        self, project_id: ProjectId, *, limit: int = 100, offset: int = 0
    ) -> list[QTrajectoryPointRow]:
        """One point per scored `memory_item` row, oldest-scored first (module docstring, gap
        1). Scoped to `scope_type='agent_type'` rows only: `scope_id` is the (agent_type,
        mem_type)-keyed grid's `agent_type_id` exactly when the scope is one -- a
        `workflow_template`/`user`/`project_shared` memory has no agent type to stratify by at
        all, and including it under a fabricated key would misreport which agent it belongs to.

        `scope_id IS NOT NULL` is a separate predicate, not redundant with the `scope_type`
        one: `migrations/0002_partitioned.sql` declares `scope_id uuid` NULLABLE with no CHECK
        binding it to `scope_type`, so `scope_type='agent_type'` with a NULL `scope_id` is a
        representable row. Without this filter that row reaches `AgentTypeId(None)` and turns
        one malformed memory into an opaque 500 for the entire report -- a dashboard losing
        every cell over one bad row, with nothing on screen to say which row or why.
        """
        lim, off = _bounded(limit, offset)
        with (
            scoped(self._pool, project_id) as conn,
            conn.cursor(row_factory=dict_row) as cur,
        ):
            cur.execute(
                (
                    """
                SELECT
                    mi.id AS memory_id,
                    mi.scope_id AS agent_type_id,
                    mi.mem_type AS mem_type,
                    mi.q_value AS q_value,
                    mi.confidence AS confidence,
                    mi.scored_use_count AS scored_use_count,
                    mi.last_scored_at AS observed_at,
                    mi.epoch_id AS scoring_epoch_id
                FROM memory_item mi
                WHERE mi.project_id = %(project_id)s
                  AND mi.scope_type = 'agent_type'
                  AND mi.scope_id IS NOT NULL
                  AND mi.last_scored_at IS NOT NULL
                  @MEMORY_FENCE@
                ORDER BY mi.last_scored_at ASC, mi.id ASC
                LIMIT %(limit)s OFFSET %(offset)s
                    """.replace("@MEMORY_FENCE@", _erasure_memory_visible("mi."))
                ),
                {"project_id": project_id, "limit": lim, "offset": off},
            )
            rows = cur.fetchall()
        return [
            QTrajectoryPointRow(
                memory_id=MemoryId(row["memory_id"]),
                agent_type_id=AgentTypeId(row["agent_type_id"]),
                mem_type=MemType(row["mem_type"]),
                q_value=float(row["q_value"]),
                confidence=float(row["confidence"]),
                scored_use_count=int(row["scored_use_count"]),
                observed_at=row["observed_at"],
                scoring_epoch_id=(
                    int(row["scoring_epoch_id"]) if row["scoring_epoch_id"] is not None else None
                ),
            )
            for row in rows
        ]

    # ------------------------------------------------------------------ staleness ----------

    def invalidation_events(
        self, project_id: ProjectId, *, limit: int = 100, offset: int = 0
    ) -> list[InvalidationReportRow]:
        """`invalidation_event` rows, newest first, paginated."""
        lim, off = _bounded(limit, offset)
        with (
            scoped(self._pool, project_id) as conn,
            conn.cursor(row_factory=dict_row) as cur,
        ):
            cur.execute(
                (
                    """
                SELECT event_id, event_type, selector, fired_at
                FROM invalidation_event
                WHERE project_id = %(project_id)s
                @INVALIDATION_FENCE@
                ORDER BY fired_at DESC, event_id DESC
                LIMIT %(limit)s OFFSET %(offset)s
                    """.replace(
                        "@INVALIDATION_FENCE@", _erasure_invalidation_visible("invalidation_event.")
                    )
                ),
                {"project_id": project_id, "limit": lim, "offset": off},
            )
            rows = cur.fetchall()
        return [
            InvalidationReportRow(
                event_id=row["event_id"],
                event_type=row["event_type"],
                selector=row["selector"],
                fired_at=row["fired_at"],
            )
            for row in rows
        ]

    def stale_memories(
        self, project_id: ProjectId, *, limit: int = MAX_STALE_FOR_MATCHING
    ) -> list[StaleMemoryRow]:
        """Every `status='stale'` memory's provenance + strike count, bounded by `limit`
        (module docstring: this feeds `api.reports`'s selector-match correlation against the
        current page of `invalidation_event`s, not a paginated listing in its own right).
        """
        lim = max(1, min(limit, MAX_STALE_FOR_MATCHING))
        with (
            scoped(self._pool, project_id) as conn,
            conn.cursor(row_factory=dict_row) as cur,
        ):
            cur.execute(
                (
                    """
                SELECT id AS memory_id, mem_type, strike_count, status_changed_at,
                       last_revalidated_at, provenance
                FROM memory_item
                WHERE project_id = %(project_id)s AND status = 'stale'
                @MEMORY_FENCE@
                ORDER BY status_changed_at DESC NULLS LAST, id ASC
                LIMIT %(limit)s
                    """.replace("@MEMORY_FENCE@", _erasure_memory_visible("memory_item."))
                ),
                {"project_id": project_id, "limit": lim},
            )
            rows = cur.fetchall()
        return [
            StaleMemoryRow(
                memory_id=MemoryId(row["memory_id"]),
                mem_type=MemType(row["mem_type"]),
                strike_count=int(row["strike_count"]),
                status_changed_at=row["status_changed_at"],
                last_revalidated_at=row["last_revalidated_at"],
                provenance=Provenance.from_json(row["provenance"]),
            )
            for row in rows
        ]

    def revalidation_candidates(
        self,
        project_id: ProjectId,
        *,
        threshold_at: datetime,
        now: datetime,
        limit: int = 100,
        offset: int = 0,
    ) -> list[RevalidationCandidateRow]:
        """`status='validated'` rows whose idle reference is at or before `threshold_at` --
        a fraction of R computed by the caller (`api.reports`) so this query only ever needs
        one comparison value, never a formula duplicated in SQL. Rows already PAST R are
        included, not filtered out; see `RevalidationCandidateRow` for why.
        """
        lim, off = _bounded(limit, offset)
        with (
            scoped(self._pool, project_id) as conn,
            conn.cursor(row_factory=dict_row) as cur,
        ):
            cur.execute(
                (
                    """
                SELECT id AS memory_id, mem_type,
                       COALESCE(last_retrieved_at, created_at) AS reference_at,
                       last_revalidated_at
                FROM memory_item
                WHERE project_id = %(project_id)s
                  AND status = 'validated'
                  AND COALESCE(last_retrieved_at, created_at) <= %(threshold_at)s
                  @MEMORY_FENCE@
                ORDER BY COALESCE(last_retrieved_at, created_at) ASC, id ASC
                LIMIT %(limit)s OFFSET %(offset)s
                    """.replace("@MEMORY_FENCE@", _erasure_memory_visible("memory_item."))
                ),
                {
                    "project_id": project_id,
                    "threshold_at": threshold_at,
                    "limit": lim,
                    "offset": off,
                },
            )
            rows = cur.fetchall()
        results: list[RevalidationCandidateRow] = []
        for row in rows:
            reference_at: datetime = row["reference_at"]
            age_days = (now - reference_at).total_seconds() / 86_400.0
            results.append(
                RevalidationCandidateRow(
                    memory_id=MemoryId(row["memory_id"]),
                    mem_type=MemType(row["mem_type"]),
                    reference_at=reference_at,
                    age_days=age_days,
                    last_revalidated_at=row["last_revalidated_at"],
                )
            )
        return results

    # ------------------------------------------------------------------ consolidation ------

    def consolidation_diffs(
        self, project_id: ProjectId, *, limit: int = 100, offset: int = 0
    ) -> list[ConsolidationDiffRow]:
        """`derived_state` versions, newest first (module docstring, gap 2: real query, no
        writer exists yet on this build, so this returns an empty page today)."""
        lim, off = _bounded(limit, offset)
        with (
            scoped(self._pool, project_id) as conn,
            conn.cursor(row_factory=dict_row) as cur,
        ):
            cur.execute(
                (
                    """
                SELECT agent_type_id, key, version, value, delta_pct, clamped, computed_at
                FROM derived_state
                WHERE project_id = %(project_id)s
                @DERIVED_FENCE@
                ORDER BY computed_at DESC, agent_type_id ASC, key ASC, version DESC
                LIMIT %(limit)s OFFSET %(offset)s
                    """.replace("@DERIVED_FENCE@", _erasure_project_readable("derived_state."))
                ),
                {"project_id": project_id, "limit": lim, "offset": off},
            )
            rows = cur.fetchall()
        return [
            ConsolidationDiffRow(
                agent_type_id=AgentTypeId(row["agent_type_id"]),
                key=row["key"],
                version=int(row["version"]),
                value=row["value"],
                delta_pct=(float(row["delta_pct"]) if row["delta_pct"] is not None else None),
                clamped=bool(row["clamped"]),
                computed_at=row["computed_at"],
            )
            for row in rows
        ]

    # ------------------------------------------------------------------ injections ---------

    def injection_feed(
        self, project_id: ProjectId, *, limit: int = 100, offset: int = 0
    ) -> list[InjectionFeedRow]:
        """`injection_log` rows, newest first, paginated -- every row already carries
        `memory_id`, so it is joinable to `GET /admin/memory/{memory_id}` by construction."""
        lim, off = _bounded(limit, offset)
        with (
            scoped(self._pool, project_id) as conn,
            conn.cursor(row_factory=dict_row) as cur,
        ):
            cur.execute(
                (
                    """
                SELECT run_id, memory_id, slot, score, tokens, injected_at
                FROM injection_log
                WHERE project_id = %(project_id)s
                @INJECTION_FENCE@
                AND EXISTS (
                    SELECT 1 FROM memory_item AS memory_item
                    WHERE memory_item.project_id = injection_log.project_id
                      AND memory_item.id = injection_log.memory_id
                      @MEMORY_FENCE@
                )
                ORDER BY injected_at DESC, run_id ASC, memory_id ASC
                LIMIT %(limit)s OFFSET %(offset)s
                    """.replace(
                        "@INJECTION_FENCE@", _erasure_run_visible("injection_log.")
                    ).replace("@MEMORY_FENCE@", _erasure_memory_visible("memory_item."))
                ),
                {"project_id": project_id, "limit": lim, "offset": off},
            )
            rows = cur.fetchall()
        return [
            InjectionFeedRow(
                run_id=RunId(row["run_id"]),
                memory_id=MemoryId(row["memory_id"]),
                slot=row["slot"],
                score=float(row["score"]),
                tokens=int(row["tokens"]),
                injected_at=row["injected_at"],
            )
            for row in rows
        ]
