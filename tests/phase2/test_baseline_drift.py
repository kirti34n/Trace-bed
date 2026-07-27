"""The Phase 2 gate's baseline-walk drill (PLAN.md section 7, D-022) and the
reference-window arithmetic under it (`workers.baselines`).

The gate sentence is "monotone drift attack trips the clamp alert and
divergence alarm", and PLAN.md section 6 states the reason the alarm exists
at all: "the rate bound alone cannot catch a patient attacker who stays under
10% forever; divergence can". That second sentence is the load-bearing one,
and it is a claim about the arithmetic, not a description of it -- whether it
is true depends entirely on what "the slow reference" is. With a 30-day MEAN
as the slow reference it is false: the mean is computed over the attacked
series, drifts along behind the fast reference, and a 1 %/day walk runs
forever without alarming (measured; see `workers/baselines.py`'s docstring
table). With the far-end reference this module's implementation uses, the
same walk alarms on day 23.

So the drills below come in three kinds:
  * the impatient attacker (over the clamp), which the clamp alert catches;
  * the patient attacker (under the clamp, forever), which only divergence
    can catch -- including the 1 %/day case that is the whole point;
  * the honest data and the detection floor, so the alarm's real limits are
    pinned by a test rather than assumed.
"""

from __future__ import annotations

import math
from datetime import UTC, datetime, timedelta

import pytest

from tests.phase2.test_derived_state import FakeDerivedStateStore
from tracebed.domain.clock import FakeClock
from tracebed.domain.config import DerivedConfig
from tracebed.domain.ids import AgentTypeId, ProjectId
from tracebed.workers.baselines import (
    FAST_WINDOW,
    SLOW_WINDOW,
    Reading,
    compute_references,
    divergence_pct,
    earliest_in_window,
    window_average,
)
from tracebed.workers.derived_state import DerivedStateWriter

pytestmark = pytest.mark.phase2

_PROJECT = ProjectId.parse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
_AGENT_TYPE = AgentTypeId.parse("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")
_KEY = "success_rate"
_START = datetime(2026, 1, 1, tzinfo=UTC)


# --------------------------------------------------------------------------- #
# workers.baselines -- pure reference-window arithmetic.
# --------------------------------------------------------------------------- #


def test_slow_and_fast_windows_are_thirty_days_and_twenty_four_hours() -> None:
    assert timedelta(days=30) == SLOW_WINDOW
    assert timedelta(hours=24) == FAST_WINDOW


def test_window_average_is_none_when_the_window_is_empty() -> None:
    assert window_average([], now=_START, window=SLOW_WINDOW) is None
    readings = [Reading(_START - timedelta(days=40), 100.0)]
    assert window_average(readings, now=_START, window=SLOW_WINDOW) is None


def test_window_average_is_half_open_at_the_old_end() -> None:
    """A reading exactly `window` old belongs to the previous period. Closed
    at both ends, one reading per day would put 31 readings in a "30 day"
    window and two days in a "24 hour" one."""
    at_boundary = [Reading(_START - FAST_WINDOW, 500.0), Reading(_START, 100.0)]
    assert window_average(at_boundary, now=_START, window=FAST_WINDOW) == pytest.approx(100.0)

    just_inside = [Reading(_START - FAST_WINDOW + timedelta(seconds=1), 500.0), Reading(_START, 100.0)]
    assert window_average(just_inside, now=_START, window=FAST_WINDOW) == pytest.approx(300.0)


def test_window_average_excludes_readings_outside_the_window() -> None:
    readings = [
        Reading(_START - timedelta(days=31), 1_000.0),  # outside a 30d window
        Reading(_START - timedelta(days=10), 100.0),
        Reading(_START, 200.0),
    ]
    assert window_average(readings, now=_START, window=SLOW_WINDOW) == pytest.approx(150.0)


def test_window_average_refuses_a_non_positive_window() -> None:
    with pytest.raises(ValueError):
        window_average([Reading(_START, 1.0)], now=_START, window=timedelta(0))


def test_earliest_in_window_ignores_readings_that_have_aged_out() -> None:
    readings = [
        Reading(_START - timedelta(days=31), 1.0),
        Reading(_START - SLOW_WINDOW, 1.5),  # exactly `window` old: already outside
        Reading(_START - timedelta(days=29), 2.0),
        Reading(_START, 3.0),
    ]
    anchor = earliest_in_window(readings, now=_START, window=SLOW_WINDOW)
    assert anchor is not None
    assert anchor.value == 2.0
    assert anchor.at == _START - timedelta(days=29)


def test_earliest_in_window_is_none_on_an_empty_window() -> None:
    assert earliest_in_window([], now=_START, window=SLOW_WINDOW) is None
    stale = [Reading(_START - timedelta(days=40), 1.0)]
    assert earliest_in_window(stale, now=_START, window=SLOW_WINDOW) is None


def test_no_number_of_recent_writes_can_move_the_slow_reference() -> None:
    """The burst defence. Whoever schedules the writer must not be able to
    choose the detector's sensitivity: under a per-sample mean, 100 readings
    inside one day outvote 29 days of history and drag the reference onto the
    attacked value."""
    history = [Reading(_START - timedelta(days=d), 100.0) for d in range(1, 30)]
    burst = [Reading(_START - timedelta(minutes=i), 1_000.0) for i in range(100)]
    readings = [*history, *burst]

    naive_mean = sum(r.value for r in readings) / len(readings)
    quiet = compute_references(history, now=_START)
    flooded = compute_references(readings, now=_START)

    assert naive_mean > 700.0  # the burst dominates a per-sample mean
    assert flooded.slow == quiet.slow == pytest.approx(100.0)
    assert flooded.fast is not None
    assert divergence_pct(flooded.slow or 0.0, flooded.fast) > 25.0


def test_compute_references_reads_the_far_end_of_the_slow_window() -> None:
    """The slow reference is where the baseline stood a slow window ago, not
    a 30-day mean of the attacked series."""
    readings = [
        Reading(_START - timedelta(days=20), 100.0),
        Reading(_START - timedelta(days=10), 400.0),
        Reading(_START, 900.0),
    ]
    refs = compute_references(readings, now=_START)
    assert refs.slow == pytest.approx(100.0)
    assert refs.fast == pytest.approx(900.0)
    assert refs.slow_age == timedelta(days=20)


def test_compute_references_has_no_slow_reference_from_a_single_instant() -> None:
    """One reading compares only against itself -- a guaranteed zero
    divergence, which is what made a fresh key look healthy while it was
    being walked. Beyond that single case the reference exists immediately;
    the alarm is strict about a young baseline rather than blind to it."""
    single = compute_references([Reading(_START, 100.0)], now=_START)
    assert single.slow is None
    assert single.slow_age is None
    assert single.fast == pytest.approx(100.0)

    minutes_old = compute_references(
        [Reading(_START - timedelta(minutes=5), 100.0), Reading(_START, 400.0)], now=_START
    )
    assert minutes_old.slow == pytest.approx(100.0)
    assert minutes_old.slow_age == timedelta(minutes=5)


def test_divergence_pct_zero_over_zero_is_zero_not_nan() -> None:
    assert divergence_pct(0.0, 0.0) == 0.0


def test_divergence_pct_nonzero_over_zero_is_infinite() -> None:
    assert math.isinf(divergence_pct(0.0, 5.0))


def test_divergence_pct_ordinary_case() -> None:
    assert divergence_pct(slow=100.0, fast=130.0) == pytest.approx(30.0)


def test_divergence_pct_is_symmetric_in_direction() -> None:
    """A baseline walked DOWN is poisoned exactly as thoroughly as one walked
    up; the alarm is on |movement|."""
    assert divergence_pct(slow=100.0, fast=70.0) == pytest.approx(30.0)


def test_divergence_pct_refuses_non_finite_inputs() -> None:
    with pytest.raises(ValueError):
        divergence_pct(float("nan"), 1.0)


def test_reading_rejects_naive_datetime() -> None:
    with pytest.raises(ValueError):
        Reading(datetime(2026, 1, 1), 1.0)  # a naive instant is exactly the point of the test


def test_reading_rejects_non_finite_value() -> None:
    with pytest.raises(ValueError):
        Reading(_START, float("nan"))


# --------------------------------------------------------------------------- #
# The Phase 2 gate's baseline-walk drill.
# --------------------------------------------------------------------------- #


def _writer(cfg: DerivedConfig | None = None) -> tuple[DerivedStateWriter, FakeClock]:
    clock = FakeClock(_START)
    writer = DerivedStateWriter(FakeDerivedStateStore(), clock, cfg or DerivedConfig())
    return writer, clock


def _walk(
    writer: DerivedStateWriter,
    clock: FakeClock,
    *,
    per_day: float,
    days: int,
    updates_per_day: int = 1,
) -> tuple[bool, bool, int | None, float]:
    """Drive a constant geometric walk. Returns
    `(any_clamped, clamp_alert_fired, first alarming day, final value)`."""
    step = timedelta(days=1) / updates_per_day
    per_step = per_day ** (1.0 / updates_per_day)
    value = 100.0
    writer.update(_PROJECT, _AGENT_TYPE, _KEY, value)
    any_clamped = False
    clamp_alert_fired = False
    alarm_day: int | None = None
    applied = value
    for tick in range(days * updates_per_day):
        clock.advance(step)
        value *= per_step
        result = writer.update(_PROJECT, _AGENT_TYPE, _KEY, value)
        assert result.version is not None
        applied = result.version.value
        any_clamped = any_clamped or result.version.clamped
        clamp_alert_fired = clamp_alert_fired or result.clamp_alert is not None
        if alarm_day is None and result.divergence_alarm is not None:
            alarm_day = 1 + tick // updates_per_day
    return any_clamped, clamp_alert_fired, alarm_day, applied


def test_patient_attacker_under_the_clamp_is_caught_by_divergence() -> None:
    """PLAN.md section 7's literal drill: 9 %/day, strictly under the 10 %
    clamp on every single update by construction, for 60 simulated days. The
    rate bound provably never binds; the divergence alarm is the only thing
    that can catch it, and it does."""
    writer, clock = _writer(DerivedConfig(baseline_max_delta_pct=10.0, divergence_alarm_pct=25.0))

    any_clamped, _alert, alarm_day, _final = _walk(writer, clock, per_day=1.09, days=60)

    assert any_clamped is False, "9%/day is strictly under the 10% clamp, every update"
    assert alarm_day is not None
    assert alarm_day <= 5


def test_a_one_percent_per_day_walk_is_caught_and_a_thirty_day_mean_would_never_catch_it() -> None:
    """THE failure mode this whole control exists for. 1 %/day never clamps
    and compounds to 1.8x in 60 days -- and against a 30-day MEAN reference
    it never alarms at all, because the mean is computed over the attacked
    series and drifts along with it. Against the far-end reference it alarms
    on day 23, which is the difference between a control and a decoration.

    The second half of the assertion is the mutation guard: it recomputes
    what the rejected design would have reported at the moment this one fires
    and asserts it is still under the threshold, so a revert to a 30-day mean
    turns this test red rather than merely slower.
    """
    cfg = DerivedConfig(baseline_max_delta_pct=10.0, divergence_alarm_pct=25.0)
    writer, clock = _writer(cfg)

    readings: list[Reading] = []
    value = 100.0
    writer.update(_PROJECT, _AGENT_TYPE, _KEY, value)
    readings.append(Reading(clock.now(), value))
    alarm_day: int | None = None
    mean_pct_at_alarm: float | None = None

    for day in range(1, 61):
        clock.advance(days=1)
        value *= 1.01
        result = writer.update(_PROJECT, _AGENT_TYPE, _KEY, value)
        assert result.version is not None
        assert result.version.clamped is False
        readings.append(Reading(clock.now(), result.version.value))
        if alarm_day is None and result.divergence_alarm is not None:
            alarm_day = day
            in_window = [r for r in readings if clock.now() - SLOW_WINDOW < r.at]
            thirty_day_mean = sum(r.value for r in in_window) / len(in_window)
            mean_pct_at_alarm = divergence_pct(thirty_day_mean, result.version.value)

    assert alarm_day is not None, "a 1%/day baseline walk must not run unnoticed"
    assert alarm_day <= 30
    assert mean_pct_at_alarm is not None
    assert mean_pct_at_alarm < cfg.divergence_alarm_pct, (
        "the rejected 30-day-mean reference is still reporting no divergence here"
    )


def test_monotone_drift_attack_trips_clamp_alert_and_divergence_alarm() -> None:
    """The Phase 2 gate's literal outcome, in one scenario: a +20 %/day
    request exceeds the 10 % rate bound on every update (so the clamp alert
    fires within 3 updates) and the clamped-but-still-monotone +10 %/day
    result diverges far enough from the far-end reference to alarm too."""
    cfg = DerivedConfig(baseline_max_delta_pct=10.0, clamp_alert_consecutive=3, divergence_alarm_pct=25.0)
    writer, clock = _writer(cfg)

    any_clamped, clamp_alert_fired, alarm_day, _final = _walk(writer, clock, per_day=1.20, days=60)

    assert any_clamped is True
    assert clamp_alert_fired is True
    assert alarm_day is not None


def test_a_downward_walk_alarms_too() -> None:
    """Halving a latency baseline is as useful to an attacker as doubling
    it -- a walked-down baseline makes a degraded fleet read as healthy."""
    writer, clock = _writer(DerivedConfig(baseline_max_delta_pct=10.0, divergence_alarm_pct=25.0))

    _clamped, _alert, alarm_day, final = _walk(writer, clock, per_day=1 / 1.09, days=60)

    assert alarm_day is not None
    assert final < 100.0


def test_the_alarm_threshold_comes_from_config_not_a_literal() -> None:
    """Every other drill here uses the shipped default (25), so a threshold
    hardcoded in the writer would survive all of them. The same walk must
    alarm under a tight threshold and stay quiet under a loose one."""
    tight, tight_clock = _writer(DerivedConfig(divergence_alarm_pct=5.0))
    loose, loose_clock = _writer(DerivedConfig(divergence_alarm_pct=400.0))

    _c1, _a1, tight_day, _f1 = _walk(tight, tight_clock, per_day=1.02, days=20)
    _c2, _a2, loose_day, _f2 = _walk(loose, loose_clock, per_day=1.02, days=20)

    assert tight_day is not None
    assert loose_day is None


def test_legitimate_noisy_data_oscillating_around_a_mean_does_not_alarm() -> None:
    """False-positive test. Small (+/-3 %) oscillation around a stable mean
    must never bind the clamp and never alarm -- a watchdog that fires on
    ordinary noise is worse than useless, because an operator who learns to
    ignore it will ignore the real thing too."""
    writer, clock = _writer(DerivedConfig(baseline_max_delta_pct=10.0, divergence_alarm_pct=25.0))
    writer.update(_PROJECT, _AGENT_TYPE, _KEY, 100.0)

    any_clamped = False
    any_alarmed = False
    high = True
    for _day in range(60):
        clock.advance(days=1)
        value = 103.0 if high else 97.0
        high = not high
        result = writer.update(_PROJECT, _AGENT_TYPE, _KEY, value)
        assert result.version is not None
        any_clamped = any_clamped or result.version.clamped
        any_alarmed = any_alarmed or result.divergence_alarm is not None

    assert any_clamped is False
    assert any_alarmed is False


def test_a_single_legitimate_step_change_alarms_once_and_then_settles() -> None:
    """A real regression (a dependency got slower) SHOULD alarm -- that is
    the alarm working -- but it must stop alarming once the new level has
    been the reference for a slow window, or the operator ends up with a
    permanent red light and no information."""
    writer, clock = _writer(DerivedConfig(baseline_max_delta_pct=10.0, divergence_alarm_pct=25.0))
    writer.update(_PROJECT, _AGENT_TYPE, _KEY, 100.0)

    alarms: list[bool] = []
    for day in range(1, 91):
        clock.advance(days=1)
        target = 100.0 if day < 5 else 200.0
        result = writer.update(_PROJECT, _AGENT_TYPE, _KEY, target)
        assert result.version is not None
        alarms.append(result.divergence_alarm is not None)

    assert any(alarms[:40]), "the step change itself must be reported"
    assert not any(alarms[-10:]), "the alarm must clear once the new level is the reference"


def test_a_burst_inside_one_fast_window_cannot_hide_behind_its_own_average() -> None:
    """The fast reference is a 24-hour MEAN, so a run of updates inside one
    window parks the stored baseline above every average computed over it:
    three clamp-legal +10 % steps put the value 33 % above the reference
    while the window's mean is only 21 % above it. `derived_state`'s
    consumers read the latest row's `value`, not a mean, so the alarm
    compares both against the slow reference and reports the larger."""
    writer, clock = _writer(DerivedConfig(baseline_max_delta_pct=10.0, divergence_alarm_pct=25.0))
    writer.update(_PROJECT, _AGENT_TYPE, _KEY, 100.0)
    clock.advance(days=2)  # push the anchor out of the fast window

    result = None
    for target in (110.0, 121.0, 133.1):
        clock.advance(minutes=1)
        result = writer.update(_PROJECT, _AGENT_TYPE, _KEY, target)
        assert result.version is not None
        assert result.version.clamped is False  # every step is exactly at the bound

    assert result is not None
    fast_mean = (110.0 + 121.0 + 133.1) / 3
    assert divergence_pct(100.0, fast_mean) < 25.0  # the mean alone would say nothing is wrong
    assert result.divergence_alarm is not None
    assert result.divergence_alarm.current_value == pytest.approx(133.1)
    assert result.divergence_alarm.divergence_pct == pytest.approx(33.1)


def test_the_detection_floor_is_pinned_not_assumed() -> None:
    """Honest limit. Comparing against a reference `SLOW_WINDOW` old cannot
    detect drift slower than `divergence_alarm_pct` per `SLOW_WINDOW`
    (25 % / 30 days ~= 0.74 %/day). A 0.5 %/day walk is invisible here and
    reaches 1.35x in 60 days. Whoever wants that caught must change the
    config numbers, not expect this code to do more than they say -- and this
    test exists so nobody discovers the floor from an incident."""
    writer, clock = _writer(DerivedConfig(baseline_max_delta_pct=10.0, divergence_alarm_pct=25.0))

    _clamped, _alert, alarm_day, final = _walk(writer, clock, per_day=1.005, days=60)

    assert alarm_day is None
    assert final == pytest.approx(100.0 * 1.005**60, rel=1e-6)


def test_detection_does_not_depend_on_how_often_the_writer_runs() -> None:
    """Update frequency is a scheduling detail, never a security parameter.
    The same wall-clock drift delivered once a day and twelve times a day
    must be caught at the same time; a per-sample-weighted reference makes
    the detector's sensitivity a function of the schedule."""
    daily, daily_clock = _writer(DerivedConfig(divergence_alarm_pct=25.0))
    hourly, hourly_clock = _writer(DerivedConfig(divergence_alarm_pct=25.0))

    _c1, _a1, daily_day, _f1 = _walk(daily, daily_clock, per_day=1.02, days=30)
    _c2, _a2, dense_day, _f2 = _walk(hourly, hourly_clock, per_day=1.02, days=30, updates_per_day=12)

    assert daily_day is not None
    assert dense_day is not None
    assert abs(daily_day - dense_day) <= 1


def test_an_adaptive_attacker_who_never_trips_either_watchdog_is_bounded() -> None:
    """The real red-team question: not "does a naive walk alarm" but "how far
    can an attacker who reads this source get without ever alarming".

    The attacker below is greedy-optimal against this implementation: at
    every update it binary-searches for the largest move that neither clamps
    nor alarms, using the writer's own `compute_references`/`divergence_pct`
    as its model, so it adapts automatically to whatever the implementation
    does. It runs at 12 updates/day, because the rate bound is "10 per
    update" (PLAN.md section 6) and therefore bounds nothing per unit time --
    update frequency is the obvious lever, and this test exists so that lever
    is measured rather than assumed harmless.

    What is asserted is the quantity that matters to a defender: how far the
    baseline gets while the alarm is still silent. Measured over 40 simulated
    days from a baseline of 100, with the attacker re-optimised against each
    variant:
        this implementation           156.2  (1.56x, and never alarms)
        30-day-mean slow reference    556.8  (5.57x, and never alarms)
    1.56x over 40 days is the configured 25 % per 30 days and nothing more,
    which is what "the alarm means what the config says" looks like when an
    optimal adversary is the one measuring it.
    """
    cfg = DerivedConfig(baseline_max_delta_pct=10.0, divergence_alarm_pct=25.0)
    writer, clock = _writer(cfg)
    updates_per_day = 12
    step = timedelta(days=1) / updates_per_day
    ceiling = 1.0 + cfg.baseline_max_delta_pct / 100.0

    first = writer.update(_PROJECT, _AGENT_TYPE, _KEY, 100.0)
    assert first.version is not None
    mirror: list[Reading] = [Reading(clock.now(), first.version.value)]
    value = first.version.value
    reached_while_silent = value
    alarm_day: int | None = None

    for tick in range(40 * updates_per_day):
        clock.advance(step)
        now = clock.now()
        window = [r for r in mirror if now - SLOW_WINDOW < r.at]
        low, high = 1.0, ceiling
        for _ in range(16):
            mid = (low + high) / 2.0
            trial = [*window, Reading(now, value * mid)]
            refs = compute_references(trial, now=now)
            if refs.slow is None or refs.fast is None:
                low = mid  # nothing can alarm yet; take the whole rate bound
                continue
            worst = max(divergence_pct(refs.slow, refs.fast), divergence_pct(refs.slow, value * mid))
            if worst > cfg.divergence_alarm_pct:
                high = mid
            else:
                low = mid
        result = writer.update(_PROJECT, _AGENT_TYPE, _KEY, value * low)
        assert result.version is not None
        assert result.version.clamped is False, "this attacker deliberately never trips the rate bound"
        value = result.version.value
        mirror = [*window, Reading(now, value)]
        if alarm_day is None:
            if result.divergence_alarm is None:
                reached_while_silent = max(reached_while_silent, value)
            else:
                alarm_day = 1 + tick // updates_per_day

    assert alarm_day is None  # a perfect model never alarms; the drift is the measurement
    assert reached_while_silent < 200.0, (
        f"the baseline reached {reached_while_silent:.1f} before anything noticed"
    )
