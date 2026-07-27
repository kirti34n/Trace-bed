"""Wire response models for `api/reports.py` (D-093's four aggregate read routes).

Same conventions as `api/models.py`: every model forbids extra keys, and every timestamp/UUID
crossing the wire is a plain `str` (a frozen dataclass holding domain newtypes is never hand-
`model_validate`-d) -- `api/models.py`'s own `MemoryItemOut` docstring gives the reason.

`extra="forbid"` on a RESPONSE model has no bearing on invariant 4 (that is these routes never
accepting a `project_id` field in a QUERY parameter or body in the first place) but is kept for
the same reason `api/models.py` keeps it everywhere: one convention for the whole wire surface,
not "forbid on inputs, whatever on outputs".
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict

__all__ = [
    "ConsolidationDiffOut",
    "ConsolidationDiffsOut",
    "InjectionEntryOut",
    "InjectionsOut",
    "InvalidationMatchOut",
    "InvalidationReportEntryOut",
    "LiftCellOut",
    "LiftMethodologyOut",
    "LiftReportOut",
    "LiftWindowOut",
    "QTrajectoryOut",
    "QTrajectoryPointOut",
    "RevalidationCandidateOut",
    "StalenessReportOut",
]


# --------------------------------------------------------------------------- #
# GET /admin/lift/report
# --------------------------------------------------------------------------- #


class LiftWindowOut(BaseModel):
    model_config = ConfigDict(extra="forbid")

    since: str
    days: int
    observations_considered: int
    """How many `(run, mem_type)` rows the estimate was actually folded from."""
    observations_truncated: bool
    """`true` when the observation join came back at its cap, so every `n_treatment` /
    `n_control` below is a LOWER BOUND on this window's real N, not the window's N. A reader
    who cannot tell those apart cannot tell "this cell has 6,000 runs behind it" from "this
    cell has at least 6,000 of an unknown number", and the second is not evidence."""
    observations_cap: int
    """The cap `observations_truncated` was measured against
    (`stores.pg.reports.MAX_LIFT_OBSERVATIONS`)."""


class LiftMethodologyOut(BaseModel):
    """The constants this report's numbers were computed under, so a reader never has to
    guess them and a dashboard never has to hard-code PLAN.md's documented defaults and hope
    they match the deployment.

    `source` is the honest part. `"process_default"` means these came from
    `domain.config.KillswitchConfig()`'s field defaults and `workers.lift`'s module
    constants -- NOT from this project's resolved `EffectiveConfig`. `ConfigResolver` needs a
    `TracebedSettings` and a `ConfigStorePort` (including `get_killswitch_overlay`, which
    `api.deps.ControlPlaneReadPort` does not declare), and `AppDeps` carries neither, so this
    route cannot resolve a project's `killswitch.min_cell_n` override today. A project that
    HAS overridden it will see its cells judged against 200 here while the kill switch judges
    them against the override -- which is exactly why the field says where the number came
    from instead of presenting it as this deployment's configured value.
    """

    model_config = ConfigDict(extra="forbid")

    min_cell_n: int
    killswitch_window_days: int
    """`killswitch.window_days` -- the SUSTAINED-trigger window, not this report's `days`."""
    correction: str
    confidence: float
    bh_alpha: float
    bh_hypotheses: int
    """How many cells entered the Benjamini-Hochberg correction as hypotheses. Larger than the
    number of cells carrying a `bh_adjusted_p`: an insufficient cell still counts against the
    family (at p=1.0), it just does not get an adjusted value back."""
    source: str


class LiftCellOut(BaseModel):
    """One `(agent_type_id, mem_type)` stratified lift cell.

    `insufficient` is `true` whenever either arm's N is below `min_cell_n` -- including the
    degenerate case (fewer than 2 observations in an arm) where no confidence interval could be
    computed at all, in which case `point_estimate`/`lower_bound`/`upper_bound`/`p_value`/
    `bh_adjusted_p` are all `None`. This is the KillSwitch.tsx standard applied here: delta + CI
    + N, or an explicit refusal -- never a bare bound, and never a cell silently dropped instead
    of marked.
    """

    model_config = ConfigDict(extra="forbid")

    agent_type_id: str
    mem_type: str
    n_treatment: int
    n_control: int
    min_cell_n: int
    insufficient: bool
    point_estimate: float | None
    lower_bound: float | None
    upper_bound: float | None
    confidence: float | None
    p_value: float | None
    """Two-sided Wald p-value (`workers.lift.LiftEstimate.p_value`) -- `None` iff `insufficient`
    and fewer than 2 observations existed in an arm to compute one at all."""
    bh_adjusted_p: float | None
    """Benjamini-Hochberg-adjusted p-value (the directional, LOWER-adverse statistic
    `workers.killswitch` feeds its correction, adjusted across every cell in this response) --
    the standard "q-value" reading: reject at level alpha iff `bh_adjusted_p <= alpha`.

    `None` whenever `insufficient` is `true`, including cells that DID produce a computable
    estimate. The cell still entered the correction as a hypothesis (see
    `LiftMethodologyOut.bh_hypotheses`); it gets no adjusted value back because an adjusted p
    is only readable next to the estimate it adjusts, and this cell's estimate is refused. A
    significant-looking p printed beside the words "insufficient data" invites precisely the
    reading the refusal exists to prevent."""


class QTrajectoryPointOut(BaseModel):
    model_config = ConfigDict(extra="forbid")

    agent_type_id: str
    mem_type: str
    memory_id: str
    q_value: float
    confidence: float
    scored_use_count: int
    observed_at: str
    scoring_epoch_id: int | None
    """`None` when no `scoring_epoch` row's `started_at` precedes `observed_at` -- e.g. no
    epoch has ever been recorded on this deployment. Otherwise INFERRED by nearest-preceding
    `started_at`, never read off a stored foreign key (`stores.pg.reports` module docstring,
    gap 1: `memory_item` has no such column). The dashboard groups points by this field
    per-point, which is exactly why a report-level epoch list would not be sufficient."""


class QTrajectoryOut(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[QTrajectoryPointOut]
    limit: int
    offset: int
    returned: int


class LiftReportOut(BaseModel):
    model_config = ConfigDict(extra="forbid")

    window: LiftWindowOut
    methodology: LiftMethodologyOut
    cells: list[LiftCellOut]
    q_trajectory: QTrajectoryOut


# --------------------------------------------------------------------------- #
# GET /admin/staleness/report
# --------------------------------------------------------------------------- #


class InvalidationMatchOut(BaseModel):
    """One memory an `invalidation_event`'s selector matches (`workers.invalidator
    .selector_matches`, applied here read-only) AND that is currently `status='stale'`.

    This is selector-match EVIDENCE, not a persisted causal link -- no table anywhere records
    "event X staled memory Y" (`workers.invalidator` transitions the row but writes no back-
    reference to the event that triggered it). A memory can appear under more than one
    qualifying event when more than one event's selector matches its provenance; that is
    reported as-is rather than resolved to a single "the" cause the data cannot support.
    """

    model_config = ConfigDict(extra="forbid")

    memory_id: str
    mem_type: str
    strike_count: int
    status_changed_at: str | None


class InvalidationReportEntryOut(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_id: str
    event_type: str
    selector: dict[str, Any] | None
    fired_at: str
    matched_memories: list[InvalidationMatchOut]
    matched_memories_total: int
    """How many memories in the scanned set matched, EXACT even when `matched_memories` was
    capped. The count is what an operator reads to spot over-invalidation ("this selector
    reached 4,000 memories"); presenting `len(matched_memories)` as that count would
    understate the exact failure the number exists to reveal."""
    matched_memories_truncated: bool
    """`true` when `matched_memories` is incomplete, for either of two independent reasons:
    this project has more `stale` memories than the bounded set the server scanned
    (`stores.pg.reports.MAX_STALE_FOR_MATCHING`), or this one event matched more than a single
    response should carry (`api.reports._MAX_MATCHES_PER_EVENT`). One flag rather than two so a
    dashboard cannot check the wrong one; `matched_memories_total` is the exact number either
    way."""


class RevalidationCandidateOut(BaseModel):
    """One `validated` memory at or past a fraction of `lifecycle.revalidation_age_days` (R).

    "Candidate" does NOT mean "not yet due". Rows with `age_days >= r_days` are included on
    purpose: a `validated` memory past R that `workers.revalidation` has not acted on is the
    under-invalidation signal, and dropping it would hide the failure this report exists to
    surface. `age_days` and `r_days` travel together so a reader can always tell approaching
    from overdue without the server having asserted which.
    """

    model_config = ConfigDict(extra="forbid")

    memory_id: str
    mem_type: str
    reference_at: str
    """`last_retrieved_at`, or `created_at` when the memory has never been retrieved -- the
    exact idle reference `workers.revalidation.is_due_for_revalidation` uses. NOT the same
    field as `last_revalidated_at`."""
    age_days: float
    r_days: int
    last_revalidated_at: str | None


class StalenessReportOut(BaseModel):
    model_config = ConfigDict(extra="forbid")

    invalidation_events: list[InvalidationReportEntryOut]
    event_limit: int
    event_offset: int
    event_returned: int
    approaching_revalidation: list[RevalidationCandidateOut]
    approaching_limit: int
    approaching_offset: int
    approaching_returned: int
    r_days: int


# --------------------------------------------------------------------------- #
# GET /admin/consolidation/diffs
# --------------------------------------------------------------------------- #


class ConsolidationDiffOut(BaseModel):
    """One `derived_state` version row.

    NOT a consolidation SWEEP. `workers.consolidator`'s `DeltaRecord` (one ADD/AMEND/REMOVE
    per sweep, with before/after element text) has no store anywhere in this codebase;
    `derived_state` is the only table in the schema shaped like a versioned per-key delta, so
    it is what this route reads. A reader must not take these rows for the nightly merge
    loop's own diff log -- see `ConsolidationDiffsOut`.
    """

    model_config = ConfigDict(extra="forbid")

    agent_type_id: str
    key: str
    version: int
    value: dict[str, Any]
    delta_pct: float | None
    clamped: bool
    value_retained_fraction: float | None
    """`1 - abs(delta_pct) / 100`, clamped into `[0, 1]` -- `None` iff `delta_pct` is `None`
    (never fabricated from a missing input).

    DELIBERATELY NOT NAMED `information_retention`. That name belongs to
    `harness/consolidation_regression.py`'s `SweepResult`, which measures how many distinct
    verifiable FACTS survived a consolidation sweep -- the ACE (arXiv:2510.04618) brevity-bias
    metric. This is a different quantity entirely: how far one `derived_state` key's numeric
    value moved between two versions, which says nothing about whether any fact was lost. A
    field named for a metric it is not is a fabricated figure no matter how it is computed,
    and it would have been quoted as an ACE retention number the first time someone screenshot
    the page. Renamed at the wire, not just documented, because the name is what travels."""
    computed_at: str


class ConsolidationDiffsOut(BaseModel):
    """See `stores.pg.reports` module docstring, gap 2: real query against the one table
    shaped like a versioned per-key delta (`derived_state`), against which nothing in this
    codebase writes yet -- `items` is an honestly empty list on every build shipped today, not
    a fabricated one."""

    model_config = ConfigDict(extra="forbid")

    items: list[ConsolidationDiffOut]
    limit: int
    offset: int
    returned: int
    sweep_deltas_available: bool = False
    """Always `false` on this build, and constant rather than computed on purpose: no writer
    for `workers.consolidator`'s per-sweep ADD/AMEND/REMOVE `DeltaRecord`s exists anywhere in
    this codebase, so no response this route can produce today carries them. A dashboard needs
    to distinguish "this project ran no sweeps" from "nothing in this system records sweeps"
    -- the two render identically as an empty list, and only one of them is a fact about the
    project. It flips to `true` in the same change that lands the writer."""


# --------------------------------------------------------------------------- #
# GET /admin/injections
# --------------------------------------------------------------------------- #


class InjectionEntryOut(BaseModel):
    model_config = ConfigDict(extra="forbid")

    run_id: str
    memory_id: str
    slot: str
    score: float
    tokens: int
    injected_at: str


class InjectionsOut(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[InjectionEntryOut]
    limit: int
    offset: int
    returned: int
