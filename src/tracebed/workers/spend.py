"""SpendMeter (PHASE-0 Task 16 / PHASE0-CONTRACT.md §5.4).

Records LLM spend into `spend_ledger`, rolled up by (project, UTC day, worker,
model). Phase 0 is records-only: `check_cap` reports whether today's spend has
crossed `SpendConfig.daily_llm_cap_usd`, it does not refuse anything -- Phase 3
is what pauses workers on `CapStatus.exceeded` (PLAN.md §7 Phase 3: "spend
enforcement"; `domain.errors.CapExceeded` is declared for that phase and is
never raised here).

UTC day bucketing (task description, restated because it is easy to get
wrong): the day bucket is computed from `clock.now().date()` after normalising
to UTC, never from a naive `date.today()` or from the wall clock's local
timezone. A ledger keyed on local midnight would roll over at a different
wall-clock instant in every deployment timezone, so "spend for 2026-07-25"
would mean a different 24-hour window in each one -- the ledger would not
reconcile against itself across deployments, let alone against the org-level
rollup this module documents below. `Clock.now()` is contracted to return a
timezone-aware UTC instant (`domain/clock.py`), but `_utc_day` ENFORCES that
rather than assuming it: a naive instant silently means "machine local time" to
`datetime.astimezone`, which is the exact mis-bucketing this module exists to
prevent, only harder to see because it depends on the host's TZ.

DELIBERATE ASYMMETRY (PLAN.md §10, task description): org-level rollup of
spend/token/latency is billing metadata and is the ONE explicit exemption from
the cross-project aggregation ban -- PLAN.md §10 says so verbatim ("Spend/
token/latency metering may roll up to org -- billing metadata, explicitly
exempt") and PHASE0-CONTRACT.md's DO-NOT list repeats it for this chunk
(D-037). Nothing in this module reads or aggregates spend across MULTIPLE
projects, memory content, or memory-derived statistics -- every method here
takes one `project_id` and every ledger read (`Repo.spend_by_day`) is scoped
to it via the RLS GUC like any other partitioned-table read. An org-rollup
worker, if one is ever built, belongs elsewhere and must be its own
explicitly-reviewed exemption, not something bolted onto this class -- this
paragraph exists so nobody "fixes" that isolation by widening `SpendMeter`
itself into a cross-project aggregator.
"""

from __future__ import annotations

import math
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, date, datetime

from tracebed.domain.clock import Clock
from tracebed.domain.config import SpendConfig
from tracebed.domain.ids import ProjectId
from tracebed.stores.pg.repo import Repo
from tracebed.stores.pg.rows import SpendRow

__all__ = ["CapStatus", "SpendMeter"]


def _utc_day(instant: datetime) -> date:
    """The explicit UTC calendar day for a `Clock` instant -- see module docstring.

    Rejects a naive instant instead of normalising it. `datetime.astimezone(UTC)` treats a
    naive datetime as the HOST's local time, so a Clock that returned naive instants would key
    the ledger to a day that varies with the deployment's TZ and would do it silently -- the
    failure would surface months later as a spend report that does not reconcile, not as an
    error. `FakeClock` raises on naive instants for the same reason; this is the same guard on
    the consuming side, because `Clock` is a structural Protocol and any object with `now()`
    satisfies it.
    """
    if instant.tzinfo is None or instant.utcoffset() is None:
        raise ValueError(
            "SpendMeter requires a timezone-aware instant from Clock.now(); a naive datetime "
            "would be bucketed against host-local time, not UTC"
        )
    return instant.astimezone(UTC).date()


def _cap_status(rows: Sequence[SpendRow], cap_usd: float) -> CapStatus:
    """Pure sum-and-compare, split out from `SpendMeter.check_cap` so the arithmetic (and its
    boundary, `spent == cap` is NOT exceeded -- only strictly over is) is testable without a
    repository or a database, per the task description's offline-testing instruction."""
    spent = sum((row.cost_usd for row in rows), 0.0)
    return CapStatus(spent_today_usd=spent, cap_usd=cap_usd, exceeded=spent > cap_usd)


@dataclass(frozen=True, slots=True)
class CapStatus:
    """Contract §5.4. `exceeded` is `spent_today_usd > cap_usd` -- spending exactly the cap is
    not yet exceeding it."""

    spent_today_usd: float
    cap_usd: float
    exceeded: bool


class SpendMeter:
    """Contract §5.4. Phase 0 records only; nothing here enforces the cap (see module
    docstring)."""

    def __init__(self, repo: Repo, clock: Clock, cfg: SpendConfig) -> None:
        self._repo = repo
        self._clock = clock
        self._cfg = cfg

    def add(
        self,
        project_id: ProjectId,
        worker: str,
        model_id: str,
        tokens_in: int,
        tokens_out: int,
        cost_usd: float,
    ) -> None:
        """Accumulates into today's (UTC) `spend_ledger` cell for `(project_id, worker,
        model_id)`. `Repo.spend_add` is itself additive (`ON CONFLICT ... DO UPDATE SET
        tokens_in = spend_ledger.tokens_in + EXCLUDED.tokens_in, ...`), so repeated calls within
        the same UTC day accumulate rather than overwrite.

        Only real, non-negative deltas are accepted. The ledger is the sole input to `check_cap`,
        which is the Phase 3 signal for pausing workers, and `spend_ledger` constrains neither
        sign nor NaN (migrations/0002: plain `bigint`/`numeric(14,6)`, no CHECK). Two ways a
        single bad delta silently disables the cap for the rest of the UTC day:

        - a NEGATIVE delta (a provider reporting -1 for "usage unknown", a caller improvising a
          refund) subtracts from the running total, putting the project back under its cap
          without anyone spending less;
        - a NaN cost is worse and quieter: `numeric` stores NaN, `sum()` propagates it, and
          `nan > cap_usd` is False -- so `exceeded` returns False forever after, no matter how
          much is spent. Fail-open on the one number the cap is computed from.

        A credit is a deliberate ledger correction and needs its own reviewed path, not an
        arithmetic side effect of the metering call. (`inf` is deliberately NOT rejected: it
        propagates to `exceeded=True`, which fails safe.)
        """
        if tokens_in < 0 or tokens_out < 0 or cost_usd < 0 or math.isnan(cost_usd):
            raise ValueError(
                "SpendMeter.add accepts non-negative, non-NaN deltas only; either would make "
                f"check_cap under-report the daily total (tokens_in={tokens_in}, "
                f"tokens_out={tokens_out}, cost_usd={cost_usd})"
            )
        day = _utc_day(self._clock.now())
        self._repo.spend_add(project_id, day, worker, model_id, tokens_in, tokens_out, cost_usd)

    def check_cap(self, project_id: ProjectId) -> CapStatus:
        """Sums every worker/model cell recorded for the current UTC day against
        `SpendConfig.daily_llm_cap_usd`. Records only -- Phase 3 is what acts on
        `CapStatus.exceeded`."""
        day = _utc_day(self._clock.now())
        rows = self._repo.spend_by_day(project_id, day)
        return _cap_status(rows, self._cfg.daily_llm_cap_usd)
