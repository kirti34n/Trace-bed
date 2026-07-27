"""`/admin/lift/report`, `/admin/staleness/report`, `/admin/consolidation/diffs`,
`/admin/injections` (D-093 gap: dashboard aggregate reads with no route until this chunk).

Same auth plane as every other read route in `api/admin.py`: `ScopeDep` (`api.deps.get_scope`),
so a caller with no credential never reaches a query (401 before any read) and a caller naming
another project in a query parameter is silently ignored -- `scope.project_id`, server-derived
from the authenticated principal, is the only project id any handler here ever passes to
`ReportsRepo` (invariant 4). None of these four routes takes a `project_id` field anywhere.

WIRING NOTE (read before assuming a missing `AppDeps` field is a bug): `stores.pg.reports
.ReportsRepo` is NOT one of `AppDeps`'s typed fields. `api/deps.py` -- where `AppDeps` is
declared -- is outside this chunk's file list, and bolting a new required field onto a frozen,
`slots=True` dataclass declared in a file this chunk may not touch is not available. Instead,
`api.main.run()` attaches one `ReportsRepo` instance directly to `app.state.reports_store`
(mirroring how `app.state.admin_key_hash` already lives beside `app.state.deps`, not inside it) --
`_reports_store()` below is the one place this module reads it back, and fails closed exactly
like `api.admin._control_plane` does when a deployment wired none: `ConfigError` (a
`TracebedError`), which `api.main`'s already-registered fallback handler turns into an opaque
500, never an empty report a dashboard could mistake for "this project has nothing to show".
Offline tests attach a fake the same way, after `create_app` returns (see
`tests/phase4/test_report_routes.py`) -- `create_app`'s own contract ("pure wiring... zero
services") is unchanged; nothing here makes `create_app` open a connection.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import timedelta
from typing import Annotated, Protocol, runtime_checkable

from fastapi import APIRouter, Query, Request

from tracebed.api.deps import AppDepsDep, ScopeDep
from tracebed.api.models_reports import (
    ConsolidationDiffOut,
    ConsolidationDiffsOut,
    InjectionEntryOut,
    InjectionsOut,
    InvalidationMatchOut,
    InvalidationReportEntryOut,
    LiftCellOut,
    LiftMethodologyOut,
    LiftReportOut,
    LiftWindowOut,
    QTrajectoryOut,
    QTrajectoryPointOut,
    RevalidationCandidateOut,
    StalenessReportOut,
)
from tracebed.domain.config import KillswitchConfig, LifecycleConfig
from tracebed.domain.errors import ConfigError
from tracebed.domain.ids import ProjectId, RunId
from tracebed.stores.pg.reports import (
    MAX_LIFT_OBSERVATIONS,
    MAX_REPORT_LIMIT,
    MAX_STALE_FOR_MATCHING,
    ConsolidationDiffRow,
    InjectionFeedRow,
    InvalidationReportRow,
    LiftRunObservationRow,
    QTrajectoryPointRow,
    RevalidationCandidateRow,
    StaleMemoryRow,
)
from tracebed.workers.invalidator import (
    InvalidationSelector,
    parse_invalidation_payload,
    selector_matches,
)
from tracebed.workers.lift import (
    DEFAULT_BH_ALPHA,
    DEFAULT_CONFIDENCE,
    AdverseDirection,
    LiftObservation,
    compute_stratified_lift,
    directional_p_value,
    stratify,
)
from tracebed.workers.statistics import bh_adjusted_p_values

__all__ = ["router"]

router = APIRouter()

# D-118 / D-126: this module used to define its own Benjamini-Hochberg step-up implementation
# (`_bh_adjusted_p_values`) alongside `workers.killswitch.benjamini_hochberg` -- the exact "two
# authors of one governing number" defect D-118 and D-093 both name, and the two did not in fact
# agree (see `workers.statistics`'s module docstring for the worked disagreements). The one
# implementation now lives in `workers.statistics`, imported above. This name is kept, bound to the
# SAME function object rather than to a wrapper, purely so `_bh_adjusted_p_values` stays importable
# under its old private name for existing callers (`tests/phase4/test_report_routes.py
# ::TestBhAdjustedPValues`, outside this chunk's file list) --
# `tests/phase3/test_bh_single_authority.py` asserts this `is` `workers.statistics
# .bh_adjusted_p_values`, so reintroducing a second definition here fails that test rather than
# silently shipping a second author again.
_bh_adjusted_p_values = bh_adjusted_p_values

# Same ceiling as `api.admin._MAX_LIST_LIMIT` / `stores.pg.reports.MAX_REPORT_LIMIT` -- repeated
# locally (not imported from `api.admin`, a sibling route module this chunk does not own) for
# the wire-level 422 bound on every `Query(..., le=...)` below.
_MAX_LIST_LIMIT = MAX_REPORT_LIMIT
_MAX_WINDOW_DAYS = 365

# Per-event cap on how many matched memories cross the wire.
#
# WHY A SECOND CAP EXISTS. `MAX_STALE_FOR_MATCHING` bounds how many memories are SCANNED;
# nothing bounded how many are RETURNED. An over-matching selector (D-041's named
# over-invalidation failure mode: one selector demoting every validated memory in a project) on
# every event of a full 1,000-event page produces up to five million wire objects from a single
# GET -- the response body, not the computation, becomes the denial of service. The cap is
# small on purpose: nobody audits an over-invalidation by reading its ten-thousandth match,
# they audit it by seeing the count, and `matched_memories_truncated` already exists to carry
# "there are more than these".
_MAX_MATCHES_PER_EVENT = 50

# "Approaching" `lifecycle.revalidation_age_days` (R) has no PLAN.md §6 field of its own --
# R itself is a config value, but the fraction-of-R that counts as "getting close" is a
# report-only heuristic this route needs and the config surface does not define (the same
# shape of gap `workers.contribution_judge.MAX_MEMORY_CHARS` documents for its own prompt
# bound: a real threshold with nowhere in `domain/config.py` to live, so it is a named,
# documented module constant here instead of an invented `Field`).
_APPROACHING_FRACTION = 0.8


@runtime_checkable
class ReportsPort(Protocol):
    """The exact `ReportsRepo` surface these routes call -- declared here, not imported from
    `stores.pg.reports`, so a fake in `tests/phase4/test_report_routes.py` only has to satisfy
    this shape structurally (the same `Protocol`-plus-fake pattern `api.deps.ControlPlaneReadPort`
    already uses for the sibling D-093 routes)."""

    def lift_observations(
        self, project_id: ProjectId, *, since: object, limit: int = ...
    ) -> list[LiftRunObservationRow]: ...

    def q_trajectory(
        self, project_id: ProjectId, *, limit: int = ..., offset: int = ...
    ) -> list[QTrajectoryPointRow]: ...

    def invalidation_events(
        self, project_id: ProjectId, *, limit: int = ..., offset: int = ...
    ) -> list[InvalidationReportRow]: ...

    def stale_memories(
        self, project_id: ProjectId, *, limit: int = ...
    ) -> list[StaleMemoryRow]: ...

    def revalidation_candidates(
        self, project_id: ProjectId, *, threshold_at: object, now: object, limit: int = ..., offset: int = ...
    ) -> list[RevalidationCandidateRow]: ...

    def consolidation_diffs(
        self, project_id: ProjectId, *, limit: int = ..., offset: int = ...
    ) -> list[ConsolidationDiffRow]: ...

    def injection_feed(
        self, project_id: ProjectId, *, limit: int = ..., offset: int = ...
    ) -> list[InjectionFeedRow]: ...


def _reports_store(request: Request) -> ReportsPort:
    """Fail closed when the deployment wired no reports reader (module docstring) -- the exact
    shape of `api.admin._control_plane`, independently reimplemented here because that function
    is private to its own module and `api/admin.py` is not this chunk's to import internals from.
    """
    store = getattr(request.app.state, "reports_store", None)
    if store is None:
        raise ConfigError("no reports reader is configured on this deployment")
    return store  # type: ignore[no-any-return]


@router.get("/admin/lift/report", response_model=LiftReportOut)
def get_lift_report(
    scope: ScopeDep,
    deps: AppDepsDep,
    request: Request,
    days: Annotated[int, Query(ge=1, le=_MAX_WINDOW_DAYS)] = 14,
    q_limit: Annotated[int, Query(ge=1, le=_MAX_LIST_LIMIT)] = 100,
    q_offset: Annotated[int, Query(ge=0)] = 0,
) -> LiftReportOut:
    """Stratified task-quality lift per `(agent_type_id, mem_type)` cell over the trailing
    `days`-day window, plus the Q-value trajectory (`stores.pg.reports` module docstring, gap
    1). ONE pooled estimate per cell over the whole window -- the day-bucketed "sustained 14
    days" trigger is `workers.killswitch`'s job over its own store, not this report's; a
    dashboard summary and an automated kill-switch decision are different questions even when
    they share `workers.lift`'s math.
    """
    store = _reports_store(request)
    since = deps.clock.now() - timedelta(days=days)

    rows = store.lift_observations(scope.project_id, since=since)
    # A join that came back exactly at the cap was (or may have been) cut short, so every N
    # below is a LOWER BOUND on this window's real N, not the window's N. That distinction is
    # the difference between "this cell has 6,000 runs behind it" and "this cell has at least
    # 6,000 of an unknown number", and it travels on the wire rather than being swallowed here:
    # a governance figure whose denominator is silently partial is the misleading-figure defect
    # class this whole report is built to avoid.
    observations_truncated = len(rows) >= MAX_LIFT_OBSERVATIONS
    observations: list[LiftObservation] = []
    for row in rows:
        try:
            observations.append(
                LiftObservation(
                    run_id=row.run_id,
                    agent_type_id=row.agent_type_id,
                    arm=row.arm,
                    outcome_code=row.outcome_code,
                    mem_type=row.mem_type,
                    outcome_r=row.outcome_r,
                )
            )
        except ValueError:
            # A row that fails `LiftObservation`'s own placement/range invariants is a
            # data-integrity signal about the write path that produced it (module docstring's
            # exact concern in `workers.lift`), not a defect in this report -- skipped rather
            # than 500ing a dashboard summary over one malformed row.
            continue

    lift_report = compute_stratified_lift(observations, confidence=DEFAULT_CONFIDENCE)
    treatment, control = stratify(observations)
    killswitch_defaults = KillswitchConfig()
    min_cell_n = killswitch_defaults.min_cell_n

    keys = sorted(set(treatment) | set(control), key=lambda k: (str(k[0]), k[1].value))
    directional_ps: list[float] = []
    cells: list[LiftCellOut] = []
    for key in keys:
        agent_type_id, mem_type = key
        n_treatment = len(treatment.get(key, ()))
        n_control = len(control.get(key, ()))
        estimate = lift_report.estimates.get(key)
        point_estimate: float | None
        lower_bound: float | None
        upper_bound: float | None
        confidence: float | None
        p_value: float | None
        if estimate is not None:
            directional_p = directional_p_value(estimate, AdverseDirection.LOWER)
            point_estimate = estimate.point_estimate
            lower_bound = estimate.lower_bound
            upper_bound = estimate.upper_bound
            confidence = estimate.confidence
            p_value = estimate.p_value
            insufficient = n_treatment < min_cell_n or n_control < min_cell_n
        else:
            # Fewer than 2 observations in an arm: `workers.killswitch.evaluate_grid`'s own
            # convention for "no snapshot" is p=1.0 (maximally non-significant, never
            # spuriously rejected) -- applied here for the same reason.
            directional_p = 1.0
            point_estimate = lower_bound = upper_bound = confidence = p_value = None
            insufficient = True
        directional_ps.append(directional_p)
        cells.append(
            LiftCellOut(
                agent_type_id=str(agent_type_id),
                mem_type=mem_type.value,
                n_treatment=n_treatment,
                n_control=n_control,
                min_cell_n=min_cell_n,
                insufficient=insufficient,
                point_estimate=point_estimate,
                lower_bound=lower_bound,
                upper_bound=upper_bound,
                confidence=confidence,
                p_value=p_value,
                bh_adjusted_p=None,  # filled in below, once every cell's directional p is known
            )
        )

    # Every observed cell is a hypothesis in the correction, including the ones with too little
    # data to estimate (they enter at p=1.0, `workers.killswitch.evaluate_grid`'s own convention
    # for "no snapshot") -- that only ever makes the adjustment MORE conservative, never less.
    # But an adjusted p is only meaningful next to the estimate it adjusts, and an insufficient
    # cell's estimate is refused, so its adjusted p is withheld too: showing "p=0.03" beside
    # "insufficient data" invites exactly the reading the refusal exists to prevent.
    bh_adjusted = bh_adjusted_p_values(directional_ps)
    cells = [
        cell.model_copy(update={"bh_adjusted_p": None if cell.insufficient else bh})
        for cell, bh in zip(cells, bh_adjusted, strict=True)
    ]

    q_rows = store.q_trajectory(scope.project_id, limit=q_limit, offset=q_offset)
    q_points = [
        QTrajectoryPointOut(
            agent_type_id=str(r.agent_type_id),
            mem_type=r.mem_type.value,
            memory_id=str(r.memory_id),
            q_value=r.q_value,
            confidence=r.confidence,
            scored_use_count=r.scored_use_count,
            observed_at=r.observed_at.isoformat(),
            scoring_epoch_id=r.scoring_epoch_id,
        )
        for r in q_rows
    ]

    return LiftReportOut(
        window=LiftWindowOut(
            since=since.isoformat(),
            days=days,
            observations_considered=len(rows),
            observations_truncated=observations_truncated,
            observations_cap=MAX_LIFT_OBSERVATIONS,
        ),
        methodology=LiftMethodologyOut(
            min_cell_n=min_cell_n,
            killswitch_window_days=killswitch_defaults.window_days,
            correction=killswitch_defaults.correction,
            confidence=DEFAULT_CONFIDENCE,
            bh_alpha=DEFAULT_BH_ALPHA,
            bh_hypotheses=len(cells),
            source="process_default",
        ),
        cells=cells,
        q_trajectory=QTrajectoryOut(
            items=q_points, limit=q_limit, offset=q_offset, returned=len(q_points)
        ),
    )


@dataclass(frozen=True, slots=True)
class _StaleProvenanceIndex:
    """Inverted index over the bounded stale-memory set, keyed by the three provenance entries
    `workers.invalidator.selector_matches` reads.

    WHY THIS EXISTS. The obvious implementation is one `selector_matches` call per (event,
    memory) pair. At this route's own wire bounds -- `event_limit` up to
    `MAX_REPORT_LIMIT` (1,000) events, `MAX_STALE_FOR_MATCHING` (5,000) stale memories --
    that is five million calls, each allocating six short-lived sets, on a single synchronous
    GET. One authenticated operator holding the page-size slider down is then a denial of
    service against every other tenant sharing the process. Nothing about that cost is
    visible in the per-call code, which is why it survived review.

    This index does NOT reimplement the predicate. It narrows the field to the memories that
    share at least one provenance entry with the selector -- a necessary condition for
    `selector_matches`, by that function's own definition -- and every surviving candidate is
    then confirmed by calling the real `selector_matches`. The authority for "does this
    memory depend on the changed thing" stays exactly where `workers.invalidator` put it, so
    a future change to the predicate cannot silently disagree with this route; it can only
    make this route return fewer rows than the index offered, never different ones.
    """

    by_tool_ref: Mapping[str, tuple[int, ...]]
    by_trace_id: Mapping[RunId, tuple[int, ...]]
    by_input_sig_hash: Mapping[bytes, tuple[int, ...]]

    @classmethod
    def build(cls, stale_rows: Sequence[StaleMemoryRow]) -> _StaleProvenanceIndex:
        tools: dict[str, list[int]] = {}
        traces: dict[RunId, list[int]] = {}
        hashes: dict[bytes, list[int]] = {}
        for position, row in enumerate(stale_rows):
            provenance = row.provenance
            for tool_ref in provenance.tool_refs:
                tools.setdefault(tool_ref, []).append(position)
            for trace_id in provenance.trace_ids:
                traces.setdefault(trace_id, []).append(position)
            for sig_hash in provenance.input_sig_hashes:
                hashes.setdefault(sig_hash, []).append(position)
        return cls(
            by_tool_ref={k: tuple(v) for k, v in tools.items()},
            by_trace_id={k: tuple(v) for k, v in traces.items()},
            by_input_sig_hash={k: tuple(v) for k, v in hashes.items()},
        )

    def candidates(self, selector: InvalidationSelector) -> list[int]:
        """Positions of every memory sharing at least one provenance entry with `selector`,
        in the store's own ordering -- so the response's row order is the query's row order,
        not an artefact of dict iteration."""
        positions: set[int] = set()
        for tool_ref in selector.tool_refs:
            positions.update(self.by_tool_ref.get(tool_ref, ()))
        for trace_id in selector.trace_ids:
            positions.update(self.by_trace_id.get(trace_id, ()))
        for sig_hash in selector.input_sig_hashes:
            positions.update(self.by_input_sig_hash.get(sig_hash, ()))
        return sorted(positions)


def _matched_memories(
    event: InvalidationReportRow,
    stale_rows: Sequence[StaleMemoryRow],
    index: _StaleProvenanceIndex,
) -> tuple[list[InvalidationMatchOut], int, bool]:
    """Which currently-`stale` memories this event's selector matches, via the SAME
    `workers.invalidator.selector_matches` predicate the real invalidator judges dependents
    with -- never a re-derived `LIKE` or ad hoc jsonb comparison (this module's own docstring:
    evidence, not a fabricated causal link). `index` only narrows which rows that predicate is
    asked about; see `_StaleProvenanceIndex`.

    Returns `(rows_to_send, total_matched_in_the_scanned_set, capped)`. The COUNT is returned
    separately from the rows because the count is the number an operator reads to spot
    over-invalidation, and it must stay exact even when the row list is capped -- a truncated
    list whose length is presented as the count understates the exact failure it exists to
    reveal.
    """
    try:
        parsed = parse_invalidation_payload(
            {"event_type": event.event_type, "selector": dict(event.selector or {})}
        )
    except ValueError:
        # A selector this codebase itself never wrote (or one from a build predating a
        # selector-shape change) -- reported as "matches nothing" rather than failing the
        # whole report over one event's malformed payload.
        return [], 0, False
    selector: InvalidationSelector = parsed.selector
    if selector.is_empty():
        return [], 0, False
    matches: list[InvalidationMatchOut] = []
    total = 0
    for position in index.candidates(selector):
        row = stale_rows[position]
        if not selector_matches(row.provenance, selector):
            continue
        total += 1
        if len(matches) >= _MAX_MATCHES_PER_EVENT:
            continue
        matches.append(
            InvalidationMatchOut(
                memory_id=str(row.memory_id),
                mem_type=row.mem_type.value,
                strike_count=row.strike_count,
                status_changed_at=(
                    row.status_changed_at.isoformat()
                    if row.status_changed_at is not None
                    else None
                ),
            )
        )
    return matches, total, total > len(matches)


@router.get("/admin/staleness/report", response_model=StalenessReportOut)
def get_staleness_report(
    scope: ScopeDep,
    deps: AppDepsDep,
    request: Request,
    event_limit: Annotated[int, Query(ge=1, le=_MAX_LIST_LIMIT)] = 100,
    event_offset: Annotated[int, Query(ge=0)] = 0,
    r_days: Annotated[int, Query(ge=1, le=3650)] = LifecycleConfig().revalidation_age_days,
    approaching_limit: Annotated[int, Query(ge=1, le=_MAX_LIST_LIMIT)] = 100,
    approaching_offset: Annotated[int, Query(ge=0)] = 0,
) -> StalenessReportOut:
    """`invalidation_event` rows (paginated) with the currently-`stale` memories each one's
    selector matches, plus `validated` memories approaching `lifecycle.revalidation_age_days`
    (R) -- `_APPROACHING_FRACTION` of R, never yet due (a row already due is
    `workers.revalidation`'s job to act on, not this report's to list twice).
    """
    store = _reports_store(request)
    now = deps.clock.now()

    events = store.invalidation_events(scope.project_id, limit=event_limit, offset=event_offset)
    stale_rows = store.stale_memories(scope.project_id)
    truncated = len(stale_rows) >= MAX_STALE_FOR_MATCHING
    # Built ONCE per request, not per event -- see `_StaleProvenanceIndex` for what the
    # per-event alternative costs at this route's own wire bounds.
    stale_index = _StaleProvenanceIndex.build(stale_rows)

    event_entries: list[InvalidationReportEntryOut] = []
    for e in events:
        matches, matched_total, capped = _matched_memories(e, stale_rows, stale_index)
        event_entries.append(
            InvalidationReportEntryOut(
                event_id=str(e.event_id),
                event_type=e.event_type,
                selector=dict(e.selector) if e.selector is not None else None,
                fired_at=e.fired_at.isoformat(),
                matched_memories=matches,
                matched_memories_total=matched_total,
                # Two independent reasons the list may be incomplete, deliberately OR-ed into
                # one flag a dashboard cannot forget to check: the scan itself was bounded
                # (`truncated`), or this event alone matched more than one response should
                # carry (`capped`). Either way "read this as at least these, never a total".
                matched_memories_truncated=truncated or capped,
            )
        )

    threshold_at = now - timedelta(days=r_days * _APPROACHING_FRACTION)
    candidates = store.revalidation_candidates(
        scope.project_id,
        threshold_at=threshold_at,
        now=now,
        limit=approaching_limit,
        offset=approaching_offset,
    )
    candidate_out = [
        RevalidationCandidateOut(
            memory_id=str(c.memory_id),
            mem_type=c.mem_type.value,
            reference_at=c.reference_at.isoformat(),
            age_days=round(c.age_days, 2),
            r_days=r_days,
            last_revalidated_at=(
                c.last_revalidated_at.isoformat() if c.last_revalidated_at is not None else None
            ),
        )
        for c in candidates
    ]

    return StalenessReportOut(
        invalidation_events=event_entries,
        event_limit=event_limit,
        event_offset=event_offset,
        event_returned=len(event_entries),
        approaching_revalidation=candidate_out,
        approaching_limit=approaching_limit,
        approaching_offset=approaching_offset,
        approaching_returned=len(candidate_out),
        r_days=r_days,
    )


@router.get("/admin/consolidation/diffs", response_model=ConsolidationDiffsOut)
def get_consolidation_diffs(
    scope: ScopeDep,
    request: Request,
    limit: Annotated[int, Query(ge=1, le=_MAX_LIST_LIMIT)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> ConsolidationDiffsOut:
    """`derived_state` versions (`stores.pg.reports` module docstring, gap 2). Honestly empty
    on every build shipped today -- no writer for this table exists yet anywhere in this
    codebase; see that docstring before assuming a non-empty response is a bug in this route
    rather than a genuinely unwired writer."""
    store = _reports_store(request)
    rows = store.consolidation_diffs(scope.project_id, limit=limit, offset=offset)
    items = [
        ConsolidationDiffOut(
            agent_type_id=str(r.agent_type_id),
            key=r.key,
            version=r.version,
            value=dict(r.value),
            delta_pct=r.delta_pct,
            clamped=r.clamped,
            value_retained_fraction=(
                max(0.0, min(1.0, 1.0 - abs(r.delta_pct) / 100.0))
                if r.delta_pct is not None
                else None
            ),
            computed_at=r.computed_at.isoformat(),
        )
        for r in rows
    ]
    return ConsolidationDiffsOut(items=items, limit=limit, offset=offset, returned=len(items))


@router.get("/admin/injections", response_model=InjectionsOut)
def get_injections(
    scope: ScopeDep,
    request: Request,
    limit: Annotated[int, Query(ge=1, le=_MAX_LIST_LIMIT)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> InjectionsOut:
    """The `injection_log` feed, newest first, paginated -- every entry already carries
    `memory_id` (joinable to `GET /admin/memory/{memory_id}` by construction)."""
    store = _reports_store(request)
    rows = store.injection_feed(scope.project_id, limit=limit, offset=offset)
    items = [
        InjectionEntryOut(
            run_id=str(r.run_id),
            memory_id=str(r.memory_id),
            slot=r.slot,
            score=r.score,
            tokens=r.tokens,
            injected_at=r.injected_at.isoformat(),
        )
        for r in rows
    ]
    return InjectionsOut(items=items, limit=limit, offset=offset, returned=len(items))
