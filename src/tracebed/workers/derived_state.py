"""derived_state writer: rate-bounded movement, clamp-binding alert, and a
slow/fast divergence alarm (PLAN.md section 5 `derived_state`, section 6
`derived.*`, D-014, D-022).

`derived_state` lives OUTSIDE the memory state machine (SM-05 / D-014): it is
a plain, versioned, per-`(project, agent_type, key)` numeric baseline, never
routed through `domain.state_machine.apply()` -- there is no governed status
here, only a rate limiter and two watchdogs over the baseline's own history.
`DerivedStateWriter.update()` is the single write path; nothing else in this
module mutates a baseline.

THREAT MODEL, AND WHAT EACH DEFENCE ACTUALLY BOUNDS
---------------------------------------------------
The attacker supplies the readings (they are derived from runs) and wants to
walk the baseline somewhere useful without either watchdog firing -- D-022's
"textbook boiling-frog baseline poisoning", whose payoff is that a
successfully walked baseline reads as *positive* lift to the kill switch.

* The rate bound (`derived.baseline_max_delta_pct`, 10) bounds one update's
  movement against the previous stored value. It bounds movement PER UPDATE
  and PLAN.md section 6 says so in those words; it therefore bounds nothing
  per unit time. A writer invoked N times inside one period permits
  `(1 + p)**N` movement in that period. No field in `DerivedConfig` bounds
  update frequency -- reported as a contract_gap, not invented here.
* The clamp-binding alert (`derived.clamp_alert_consecutive`, 3) catches the
  impatient attacker: anyone whose requests keep exceeding the rate bound.
  It says nothing about an attacker who stays under it.
* The divergence alarm (`derived.divergence_alarm_pct`, 25) is the only
  defence against the patient attacker, and it is only as good as its slow
  reference. See `workers/baselines.py`'s module docstring: a 30-day *mean*
  reference drifts along behind the attack and provably never fires below
  ~1.6 %/day, so the slow reference is the earliest still-retained reading
  instead, making the undetectable steady-state drift exactly the configured
  25 % per 30 days. Below that rate nothing here fires -- that floor is
  intrinsic to comparing against a 30-day-old reference, and it is pinned by
  a test rather than left implied.
* The alarm compares the slow reference against the fast (24h) reference AND
  against the value just written, reporting the larger. Averaging is what
  lets a run of clamp-legal updates inside one window park the stored
  baseline above every reference computed over it, and `derived_state`'s
  consumers read the latest row's `value`, not a mean.
* A key with a single instant of history has nothing to compare against.
  That is reported as `DerivedStateUpdateResult.divergence_evaluated=False`
  rather than as a silent all-clear, because a blind watchdog must not look
  like a healthy one.

STORAGE SEAM (contract_gap, read this before wiring a real deployment):
`DerivedStateStorePort` is declared locally rather than imported from
`stores.pg.repo.Repo`. This chunk's file list is exactly
`workers/derived_state.py` + `workers/baselines.py` + their two test modules
(hard rule 6) -- `Repo`, `stores/pg/rows.py`, and `stores/pg/ddl.py` are all
outside it. `stores/pg/ddl.py::PARTITIONED_TABLES` already lists
`derived_state` and PLAN.md section 5's DDL sketch already defines its
columns, but no method anywhere in `Repo` reads or writes that table today --
verified by reading `stores/pg/repo.py` in full. A real Postgres-backed
implementation of `DerivedStateStorePort` is therefore a contract_gap for
whoever next touches `stores/pg/repo.py`.

DURABILITY: this writer seeds its reading history and its consecutive-clamp
streak from the store the first time it touches a key, so a restart does not
hand an attacker a fresh unwatched window. The store retains only
`derived.keep_versions` (20) rows, so the seeded history reaches back 20
updates, not necessarily 30 days; a deployment that needs the full slow
window across restarts needs either a durable reading log or a larger
retention, and that decision belongs to whoever owns the `derived_state`
table's real shape.
"""

from __future__ import annotations

import math
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Protocol, runtime_checkable

from tracebed.domain.clock import Clock
from tracebed.domain.config import DerivedConfig
from tracebed.domain.errors import ConfigError
from tracebed.domain.ids import AgentTypeId, ProjectId
from tracebed.workers.baselines import (
    SLOW_WINDOW,
    Reading,
    compute_references,
    divergence_pct,
)

__all__ = [
    "ClampAlert",
    "DerivedStateStorePort",
    "DerivedStateUpdateResult",
    "DerivedStateVersion",
    "DerivedStateWriter",
    "DivergenceAlarm",
]

_KeyTriple = tuple[ProjectId, AgentTypeId, str]


@dataclass(frozen=True, slots=True)
class DerivedStateVersion:
    """One persisted row, mirroring PLAN.md section 5's `derived_state`
    columns: `project_id, agent_type_id, key, version, value, computed_at,
    delta_pct, clamped`. `value` stays a plain `float` here rather than the
    table's `jsonb` -- every caller this chunk serves hands in a numeric
    baseline reading; a caller needing a structured jsonb value is out of
    this chunk's scope and would be a contract_gap for the store adapter,
    not this dataclass.
    """

    project_id: ProjectId
    agent_type_id: AgentTypeId
    key: str
    version: int
    value: float
    computed_at: datetime
    delta_pct: float
    clamped: bool


@runtime_checkable
class DerivedStateStorePort(Protocol):
    """What `DerivedStateWriter` needs from a store (see the module
    docstring's storage-seam note). `Repo` does not satisfy this today; an
    in-memory fake in each test module satisfies it structurally."""

    def recent_versions(
        self, project_id: ProjectId, agent_type_id: AgentTypeId, key: str
    ) -> Sequence[DerivedStateVersion]:
        """Every retained version for this key, oldest first (empty when the
        key has never been written).

        This is the writer's only read: the last element is the value the
        rate bound clamps against, and the whole sequence seeds the reference
        history and the clamp streak after a restart. One method rather than
        a separate `latest_version` on purpose -- two reads of the same row
        set can disagree, and the disagreement would silently be a missing
        rate bound.
        """
        ...

    def append_version(self, version: DerivedStateVersion) -> None:
        """Appends one immutable version row. Never mutates an existing one --
        `derived_state`'s primary key is `(project_id, agent_type_id, key,
        version)`, and a versioned table exists precisely so nothing is
        overwritten in place."""
        ...

    def prune_versions(
        self, project_id: ProjectId, agent_type_id: AgentTypeId, key: str, *, keep: int
    ) -> None:
        """Deletes every version for this key except the most recent `keep`."""
        ...


@dataclass(frozen=True, slots=True)
class ClampAlert:
    """The clamp-binding alert (PLAN.md section 6, `derived.clamp_alert_consecutive`):
    the rate bound has clamped `consecutive_clamps` updates in a row for this
    key. Returned from `update()`, never raised -- a worker consuming this
    result decides what "raise an alert" means operationally (a log line, a
    `review_queue` row, a page); this module only detects the condition.
    """

    project_id: ProjectId
    agent_type_id: AgentTypeId
    key: str
    consecutive_clamps: int


@dataclass(frozen=True, slots=True)
class DivergenceAlarm:
    """The slow/fast divergence alarm (PLAN.md section 6,
    `derived.divergence_alarm_pct`): this key's baseline has moved more than
    the configured percentage away from where it stood `slow_age` ago.
    Returned from `update()`, never raised -- same rationale as `ClampAlert`.

    `divergence_pct` is the larger of two comparisons against the same slow
    reference: the fast (24h) reference, and the value just written. The
    second exists because `derived_state`'s consumers read the latest row's
    `value`, not a 24-hour mean -- averaging is what lets a burst of updates
    park the stored baseline far above every reference computed over it. With
    at most one update per fast window the two comparisons are identical.
    """

    project_id: ProjectId
    agent_type_id: AgentTypeId
    key: str
    slow_reference: float
    fast_reference: float
    current_value: float
    slow_age: timedelta
    divergence_pct: float


@dataclass(frozen=True, slots=True)
class DerivedStateUpdateResult:
    """Everything one `DerivedStateWriter.update()` call produced."""

    version: DerivedStateVersion | None
    """The persisted row, or `None` when the reading was dropped as
    guardrail-flagged (D-022) and nothing was written."""

    clamp_alert: ClampAlert | None
    divergence_alarm: DivergenceAlarm | None

    divergence_evaluated: bool
    """`False` when the divergence alarm could not be computed at all: the
    key's whole retained history is one instant, so there is no earlier
    reference to compare against. Distinct from `divergence_alarm is None`,
    which means the alarm ran and found nothing; a caller that treats the two
    the same is reading "the watchdog is blind" as "the watchdog is
    happy"."""

    guardrail_skipped: bool
    """`True` when the reading was dropped for being guardrail-flagged."""


def _clamped_move(previous: float, proposed: float, max_delta_pct: float) -> tuple[float, float, bool]:
    """`(applied_value, delta_pct, clamped)` for a move from `previous`.

    `previous == 0.0` has no percentage base, so the move passes through: ten
    percent of a zero magnitude is zero, and clamping to it would pin the
    baseline at zero forever.
    """
    if previous == 0.0:
        return proposed, 0.0, False
    requested_pct = (proposed - previous) / abs(previous) * 100.0
    if abs(requested_pct) <= max_delta_pct:
        return proposed, requested_pct, False
    delta_pct = math.copysign(max_delta_pct, requested_pct)
    return previous + (delta_pct / 100.0) * abs(previous), delta_pct, True


class DerivedStateWriter:
    """The rate-bounded, alerted, alarmed writer for one deployment's
    `derived_state` rows.

    One instance is safe to reuse across many `(project_id, agent_type_id,
    key)` triples -- all per-key bookkeeping is keyed internally, so a single
    long-lived worker process can drive every key in a project through the
    same writer. The per-key maps are never evicted, so a process touching an
    unbounded number of distinct keys over its lifetime grows with the number
    of distinct keys (each key's own history is bounded by `SLOW_WINDOW`); an
    eviction policy would need a retention field `DerivedConfig` does not
    have, so it is reported as a contract_gap rather than invented.
    """

    def __init__(self, store: DerivedStateStorePort, clock: Clock, cfg: DerivedConfig) -> None:
        # `derived` is an OVERRIDABLE_SECTION (domain/config.py), every field
        # is unconstrained, and each degenerate value silently disables a
        # control rather than failing: `keep_versions <= 0` prunes away the
        # row this writer just wrote, so the next update finds no previous
        # value and is never rate-bounded at all -- a project_config override
        # that removes the clamp while every dashboard still shows a clamp
        # configured. Refusing here is D-071's move (name the broken config
        # row where it is consumed) applied to the fields `DerivedConfig`
        # should itself constrain; that it cannot is a contract_gap.
        if not math.isfinite(cfg.baseline_max_delta_pct) or cfg.baseline_max_delta_pct <= 0:
            raise ConfigError(
                f"derived.baseline_max_delta_pct must be a positive percentage, got {cfg.baseline_max_delta_pct!r}"
            )
        if cfg.clamp_alert_consecutive < 1:
            raise ConfigError(
                f"derived.clamp_alert_consecutive must be at least 1, got {cfg.clamp_alert_consecutive!r}"
            )
        if not math.isfinite(cfg.divergence_alarm_pct) or cfg.divergence_alarm_pct < 0:
            raise ConfigError(
                f"derived.divergence_alarm_pct must be a non-negative percentage, got {cfg.divergence_alarm_pct!r}"
            )
        if cfg.keep_versions < 1:
            raise ConfigError(f"derived.keep_versions must be at least 1, got {cfg.keep_versions!r}")

        self._store = store
        self._clock = clock
        self._cfg = cfg
        self._readings: dict[_KeyTriple, list[Reading]] = {}
        self._consecutive_clamps: dict[_KeyTriple, int] = {}
        self._clamp_alert_active: dict[_KeyTriple, bool] = {}
        self._seeded: set[_KeyTriple] = set()

    def update(
        self,
        project_id: ProjectId,
        agent_type_id: AgentTypeId,
        key: str,
        raw_value: float,
        *,
        guardrail_flagged: bool = False,
    ) -> DerivedStateUpdateResult:
        """Write one new reading for `key`, applying all three defences.

        `guardrail_flagged` is D-022's "guardrail-flagged runs are excluded
        from baseline contribution", read literally: the reading contributes
        NOTHING. No version row is written, the reference history does not
        see it, and the clamp streak does not move. An earlier draft of this
        module applied such a reading to the baseline and only hid it from
        the divergence windows, which is the exact inverse of the decision --
        a flagged, i.e. suspect, run would have moved the stored baseline
        while being invisible to the one watchdog that could have noticed.
        No caller in this codebase sets it yet; the flagging mechanism itself
        is out of this chunk's file list and is reported as a contract_gap.
        """
        if not math.isfinite(raw_value):
            raise ValueError(f"DerivedStateWriter.update requires a finite raw_value, got {raw_value!r}")
        if not key:
            raise ValueError("DerivedStateWriter.update requires a non-empty key")

        now = self._clock.now()
        if now.tzinfo is None or now.utcoffset() is None:
            raise ValueError("DerivedStateWriter.update requires Clock.now() to be timezone-aware")

        triple: _KeyTriple = (project_id, agent_type_id, key)

        if guardrail_flagged:
            return DerivedStateUpdateResult(
                version=None,
                clamp_alert=None,
                divergence_alarm=None,
                divergence_evaluated=False,
                guardrail_skipped=True,
            )

        history = self._seed(triple, now)
        # Highest version rather than last element: the Protocol asks for
        # oldest-first, but the row the rate bound clamps against is too
        # important to depend on an adapter honouring a docstring.
        previous = max(history, key=lambda row: row.version) if history else None

        if previous is not None and now < previous.computed_at:
            # Every window here is "how long ago", so a clock that moves
            # backwards silently re-dates readings into periods they did not
            # happen in -- and the far-end reference is chosen by age.
            raise ValueError(
                f"DerivedStateWriter.update requires a non-decreasing clock: "
                f"now={now.isoformat()} precedes the stored computed_at={previous.computed_at.isoformat()}"
            )

        if previous is None:
            applied_value, delta_pct, clamped = raw_value, 0.0, False
            version_no = 1
        else:
            applied_value, delta_pct, clamped = _clamped_move(
                previous.value, raw_value, self._cfg.baseline_max_delta_pct
            )
            version_no = previous.version + 1

        version = DerivedStateVersion(
            project_id=project_id,
            agent_type_id=agent_type_id,
            key=key,
            version=version_no,
            value=applied_value,
            computed_at=now,
            delta_pct=delta_pct,
            clamped=clamped,
        )
        self._store.append_version(version)
        self._store.prune_versions(project_id, agent_type_id, key, keep=self._cfg.keep_versions)

        clamp_alert = self._track_clamp_streak(triple, clamped)
        alarm, evaluated = self._track_divergence(triple, now, applied_value)

        return DerivedStateUpdateResult(
            version=version,
            clamp_alert=clamp_alert,
            divergence_alarm=alarm,
            divergence_evaluated=evaluated,
            guardrail_skipped=False,
        )

    def _seed(self, triple: _KeyTriple, now: datetime) -> Sequence[DerivedStateVersion]:
        """Read this key's retained rows, and on the first touch of a key in
        this process rebuild the reference history and the clamp streak from
        them.

        Without this, restarting the worker resets both watchdogs: the slow
        reference becomes the first reading written AFTER the restart -- i.e.
        wherever the baseline had already been walked to, so every unit of
        accumulated drift is forgiven -- and the clamp streak restarts at
        zero, so the alert needs `clamp_alert_consecutive` fresh clamps
        again. Both are attacker-triggerable by anything that recycles the
        process, and a deploy does it for free.
        """
        project_id, agent_type_id, key = triple
        rows = self._store.recent_versions(project_id, agent_type_id, key)
        if triple in self._seeded:
            return rows
        self._seeded.add(triple)

        cutoff = now - SLOW_WINDOW
        self._readings[triple] = [
            Reading(row.computed_at, row.value)
            for row in rows
            if cutoff < row.computed_at <= now
        ]
        streak = 0
        for row in sorted(rows, key=lambda r: r.version, reverse=True):
            if not row.clamped:
                break
            streak += 1
        self._consecutive_clamps[triple] = streak
        self._clamp_alert_active[triple] = streak >= self._cfg.clamp_alert_consecutive
        return rows

    def _track_clamp_streak(self, triple: _KeyTriple, clamped: bool) -> ClampAlert | None:
        """Defence 2: alert exactly once per streak that reaches
        `derived.clamp_alert_consecutive`, never again until the streak
        breaks (a non-clamped update) and rebuilds -- a clamp that keeps
        binding is one ongoing incident, not a new one every update.
        """
        if not clamped:
            self._consecutive_clamps[triple] = 0
            self._clamp_alert_active[triple] = False
            return None

        streak = self._consecutive_clamps.get(triple, 0) + 1
        self._consecutive_clamps[triple] = streak

        if streak >= self._cfg.clamp_alert_consecutive and not self._clamp_alert_active.get(triple, False):
            self._clamp_alert_active[triple] = True
            project_id, agent_type_id, key = triple
            return ClampAlert(
                project_id=project_id,
                agent_type_id=agent_type_id,
                key=key,
                consecutive_clamps=streak,
            )
        return None

    def _track_divergence(
        self, triple: _KeyTriple, now: datetime, applied_value: float
    ) -> tuple[DivergenceAlarm | None, bool]:
        """Defence 3: record this reading, then compare the resulting
        references. Returns `(alarm, evaluated)`; `evaluated` is `False` when
        there is no slow reference to compare against yet.
        """
        readings = self._readings.setdefault(triple, [])
        readings.append(Reading(now, applied_value))
        cutoff = now - SLOW_WINDOW
        trimmed = [r for r in readings if cutoff < r.at <= now]
        self._readings[triple] = trimmed

        refs = compute_references(trimmed, now=now)
        if refs.slow is None or refs.fast is None or refs.slow_age is None:
            return None, False

        pct = max(divergence_pct(refs.slow, refs.fast), divergence_pct(refs.slow, applied_value))
        if pct <= self._cfg.divergence_alarm_pct:
            return None, True

        project_id, agent_type_id, key = triple
        return (
            DivergenceAlarm(
                project_id=project_id,
                agent_type_id=agent_type_id,
                key=key,
                slow_reference=refs.slow,
                fast_reference=refs.fast,
                current_value=applied_value,
                slow_age=refs.slow_age,
                divergence_pct=pct,
            ),
            True,
        )
