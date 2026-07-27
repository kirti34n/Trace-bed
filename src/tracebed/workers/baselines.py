"""Reference-window arithmetic for the derived-state divergence alarm.

PLAN.md section 5 ("derived_state ... clamp-binding alert + slow/fast
divergence alarm") and section 6 (`derived.divergence_alarm_pct`, 25, "slow
30d ref vs fast 24h ref") describe the alarm in prose only.
`domain.config.DerivedConfig` carries no window-length field -- only
`baseline_max_delta_pct`, `clamp_alert_consecutive`, `divergence_alarm_pct`
and `keep_versions` -- so `SLOW_WINDOW` and `FAST_WINDOW` are `Final`
constants of this specific control rather than invented config fields (the
same treatment `domain/signatures.py` gives `SAME_CLUSTER_MAX_HAMMING`).
Reported as a contract_gap for whoever owns `DerivedConfig`.

WHAT "THE SLOW REFERENCE" IS, AND WHY IT IS NOT A 30-DAY MEAN
-------------------------------------------------------------
The obvious reading -- slow reference = arithmetic mean of every reading in
the last 30 days -- was implemented first and is WRONG for the one attack
D-022 exists to stop, because that mean is itself computed over the attacked
series: it drifts along behind the fast reference and the two never separate.
Measured against this module's own arithmetic, sustained geometric drift with
one reading per day:

    drift rate      30d-mean reference        far-end reference (this module)
    9.0 %/day       alarms on day 6           alarms on day 3
    2.0 %/day       alarms on day 24          alarms on day 12
    1.0 %/day       NEVER alarms              alarms on day 23
    0.75%/day       NEVER alarms              never alarms

A trailing mean over a 30-day window lags a geometric series by roughly half
the window, so it only measures the drift RATE, and its effective floor is
about 1.6 %/day -- i.e. a baseline may be walked ~60 % per 30 days forever
without the 25 %-per-30-days alarm ever firing. That floor is emergent; no
one chose it. The far-end reference measures the CUMULATIVE displacement the
config actually names: the alarm fires when the baseline has moved more than
`divergence_alarm_pct` away from where it stood one `SLOW_WINDOW` ago, so the
undetectable steady-state drift is exactly 25 % per 30 days (~0.74 %/day) and
not twice that. The residual floor is intrinsic -- no comparison against a
30-day-old reference can catch an attacker moving slower than the threshold
divided by the window -- and is pinned by a test rather than left implied.

WHY THE SLOW REFERENCE IS ONE READING AND NOT AN AGGREGATE
----------------------------------------------------------
Any aggregate over the slow window is computed over samples the attacker
supplied, and its sensitivity then depends on how many of them there are --
i.e. on update frequency, which is a scheduling detail and must never be a
security parameter. 100 readings inside one day outvote the preceding 29 days
of history in a per-sample mean; weighting each 24-hour period equally fixes
that but still lets the far end of the window be reshaped by whatever landed
in its last period. The earliest retained reading has neither problem: it is
one fixed number that no later write can move, and it is exactly "where the
baseline stood a slow window ago". It also removes the warm-up hole, which
measurement showed was the dominant one: with an aggregate reference nothing
older than one fast window exists for the first 24 hours (or for the first 24
hours after a restart), so the divergence alarm could not answer at all and
an attacker running the rate bound 12 times a day walked the baseline 2.85x
inside that window. Anchored on the earliest reading, the same attacker is
held to 1.25x from its second update onward.

The cost is that the reference is a single sample rather than an average, so
its own noise (bounded by `derived.baseline_max_delta_pct` per update, since
every reading here is a rate-bounded applied value) enters the comparison.
That is the deliberate trade: a noisier reference that cannot be dragged,
over a smooth one that can.

Pure functions only -- no I/O, no clock import (the caller supplies `now`
from whatever `Clock` it holds) -- so `workers.derived_state` and its tests
drive an in-memory series through a `FakeClock` with zero database.
"""

from __future__ import annotations

import math
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Final

__all__ = [
    "FAST_WINDOW",
    "SLOW_WINDOW",
    "Reading",
    "SlowFastReference",
    "compute_references",
    "divergence_pct",
    "earliest_in_window",
    "window_average",
]

SLOW_WINDOW: Final[timedelta] = timedelta(days=30)
FAST_WINDOW: Final[timedelta] = timedelta(hours=24)


@dataclass(frozen=True, slots=True)
class Reading:
    """One sample contributing to the reference windows: an applied
    `derived_state` value at a point in time.

    `at` must be timezone-aware, mirroring `Clock.now()`'s own contract
    (`domain/clock.py`) -- a naive instant would make window membership
    depend on host-local time. `value` must be finite for the same reason
    `hotpath.abstention.CandidateSignals` refuses non-finite raw signals
    (D-048): every comparison below is numeric, and NaN compares `False`
    against everything, so one NaN reading would silently disable the alarm
    for the whole window rather than raise.
    """

    at: datetime
    value: float

    def __post_init__(self) -> None:
        if self.at.tzinfo is None or self.at.utcoffset() is None:
            raise ValueError("Reading.at must be a timezone-aware instant")
        if not math.isfinite(self.value):
            raise ValueError(f"Reading.value must be finite, got {self.value!r}")


def _require_aware(now: datetime, caller: str) -> None:
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError(f"{caller} requires a timezone-aware `now`")


def window_average(readings: Sequence[Reading], *, now: datetime, window: timedelta) -> float | None:
    """Mean of every reading in the half-open window `(now - window, now]`.

    Half-open, not closed at both ends: with one reading per day and a
    24-hour window, `now - window <= at` admits both today's and yesterday's
    reading, so a "24 hour" window would average two days and a "30 day"
    window thirty-one. The boundary reading belongs to the previous period,
    which is exactly where `period_averages` puts it.

    `None` when the window is empty -- there is no honest numeric average of
    zero samples, and the caller must decide what "no data yet" means rather
    than have this function fabricate a zero.
    """
    _require_aware(now, "window_average")
    if window <= timedelta(0):
        raise ValueError(f"window_average requires a positive window, got {window!r}")
    cutoff = now - window
    in_window = [r.value for r in readings if cutoff < r.at <= now]
    if not in_window:
        return None
    return sum(in_window) / len(in_window)


def earliest_in_window(readings: Sequence[Reading], *, now: datetime, window: timedelta) -> Reading | None:
    """The oldest reading in `(now - window, now]`, or `None` when the window
    is empty. Ties (identical instants) break on the lower value, so the
    result never depends on the order the caller happened to append in."""
    _require_aware(now, "earliest_in_window")
    if window <= timedelta(0):
        raise ValueError(f"earliest_in_window requires a positive window, got {window!r}")
    cutoff = now - window
    in_window = [r for r in readings if cutoff < r.at <= now]
    if not in_window:
        return None
    return min(in_window, key=lambda r: (r.at, r.value))


@dataclass(frozen=True, slots=True)
class SlowFastReference:
    """The two references the divergence alarm compares.

    `fast` is the mean of the readings inside the last `FAST_WINDOW`.
    `slow` is where the baseline stood at the far end of the retained
    history: the value of the earliest reading still inside `SLOW_WINDOW`
    (see the module docstring for why it is that and not an aggregate).

    `slow` is `None` while the history holds a single reading -- a first
    value cannot have drifted from anything. That state is NOT "no
    divergence": it is "this watchdog cannot answer yet", and
    `DerivedStateWriter` reports it as `divergence_evaluated=False` rather
    than as a silent all-clear, because a blind watchdog must not look like a
    healthy one.
    """

    slow: float | None
    fast: float | None
    slow_age: timedelta | None
    """How far back `slow` reaches, `None` when `slow` is. The alarm's real
    sensitivity is `divergence_alarm_pct` per `slow_age`, so a caller
    recording an alarm can say how much history it actually stood on -- and a
    caller seeing a short `slow_age` knows the reference is young."""


def compute_references(readings: Sequence[Reading], *, now: datetime) -> SlowFastReference:
    """The slow/fast pair PLAN.md section 5 names, over one reading series."""
    fast = window_average(readings, now=now, window=FAST_WINDOW)
    anchor = earliest_in_window(readings, now=now, window=SLOW_WINDOW)
    if anchor is None or anchor.at == now:
        # A single instant of history compares only with itself, which is a
        # guaranteed zero divergence -- the shape that let a fresh key look
        # healthy while it was being walked.
        return SlowFastReference(slow=None, fast=fast, slow_age=None)
    return SlowFastReference(slow=anchor.value, fast=fast, slow_age=now - anchor.at)


def divergence_pct(slow: float, fast: float) -> float:
    """How far `fast` has moved from `slow`, as a percentage of `slow`'s own
    magnitude -- what `derived.divergence_alarm_pct` (D-022) is compared
    against.

    `slow == 0` has no percentage base. Returns `0.0` when `fast` is also
    `0.0` (no movement at all) and `math.inf` otherwise: alarming on any
    movement away from a zero reference is the fail-loud choice, where
    silently reporting no divergence because the denominator collapsed is the
    fail-open arithmetic D-048 refused one layer over in
    `hotpath/abstention.py`.
    """
    if not math.isfinite(slow) or not math.isfinite(fast):
        raise ValueError(f"divergence_pct requires finite inputs, got slow={slow!r} fast={fast!r}")
    if slow == 0.0:
        return 0.0 if fast == 0.0 else math.inf
    return abs(fast - slow) / abs(slow) * 100.0
