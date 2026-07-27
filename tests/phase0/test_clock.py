"""FakeClock behaviour (PHASE-0 Task 2).

`clock.py` is [frozen] — owned by no chunk, already implemented — but the
task list assigns this file to domain-config to prove the two properties
every later chunk's time-dependent test relies on: `.advance()` is
observable by a consumer, and time cannot run backwards.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone

import pytest

from tracebed.domain.clock import Clock, FakeClock, SystemClock


class _RunAgeProbe:
    """A minimal `Clock` consumer: reports elapsed time since it was built.

    Stands in for the many Phase 0 components (TTL guards, the incomplete-run
    sweeper, spend-ledger day bucketing) that take `clock: Clock` and derive
    a duration from it — exactly the shape `test_state_machine.py` and
    `test_trace_writer.py` will exercise later.
    """

    def __init__(self, clock: Clock) -> None:
        self._clock = clock
        self._started_at = clock.now()

    def age(self) -> timedelta:
        return self._clock.now() - self._started_at


@pytest.mark.phase0
def test_advance_days_observed_by_a_consumer(fake_clock: FakeClock) -> None:
    """Task 2's proving test: `FakeClock.advance(days=2)` is observable by a consumer."""
    probe = _RunAgeProbe(fake_clock)
    assert probe.age() == timedelta(0)

    fake_clock.advance(days=2)

    assert probe.age() == timedelta(days=2)


@pytest.mark.phase0
def test_advance_accepts_timedelta_or_kwargs(fake_clock: FakeClock) -> None:
    start = fake_clock.now()

    fake_clock.advance(timedelta(hours=1))
    assert fake_clock.now() == start + timedelta(hours=1)

    fake_clock.advance(minutes=30, ms=500)
    assert fake_clock.now() == start + timedelta(hours=1, minutes=30, milliseconds=500)


@pytest.mark.phase0
def test_advance_zero_is_a_noop(fake_clock: FakeClock) -> None:
    start = fake_clock.now()
    fake_clock.advance(timedelta(0))
    assert fake_clock.now() == start


@pytest.mark.phase0
def test_advance_refuses_to_move_backwards(fake_clock: FakeClock) -> None:
    with pytest.raises(ValueError, match="backwards"):
        fake_clock.advance(timedelta(seconds=-1))


@pytest.mark.phase0
def test_advance_refuses_negative_kwargs(fake_clock: FakeClock) -> None:
    with pytest.raises(ValueError, match="backwards"):
        fake_clock.advance(days=-1)


@pytest.mark.phase0
def test_monotonic_ms_advances_with_advance(fake_clock: FakeClock) -> None:
    before = fake_clock.monotonic_ms()
    fake_clock.advance(seconds=1)
    after = fake_clock.monotonic_ms()
    assert after - before == pytest.approx(1000.0)


@pytest.mark.phase0
def test_now_ms_is_unix_epoch_milliseconds(fake_clock: FakeClock) -> None:
    """Absolute values, not a restatement of the implementation.

    `now_ms()` feeds `uuid7(now_ms=...)`, which packs it into the top 48 bits
    of every run id — so a wrong epoch or a seconds/milliseconds mixup is a
    corrupt, non-time-ordered id space, not a cosmetic bug. Asserting
    `now_ms() == int(now().timestamp() * 1000)` would only re-derive the
    formula under test and pass for any consistent-but-wrong unit.
    """
    # 2026-01-01T00:00:00Z (PHASE0_EPOCH, §13.1) in Unix milliseconds.
    assert fake_clock.now_ms() == 1767225600000

    fake_clock.advance(days=1, ms=250)

    assert fake_clock.now() == datetime(2026, 1, 2, 0, 0, 0, 250_000, tzinfo=UTC)
    assert fake_clock.now_ms() == 1767225600000 + 86_400_000 + 250


@pytest.mark.phase0
def test_fake_clock_starts_at_the_phase0_epoch_by_default() -> None:
    """§13.1 pins the shared fixture's start instant; other chunks' expected
    timestamps are written against it, so a change here is a cross-chunk break."""
    assert FakeClock().now() == datetime(2026, 1, 1, tzinfo=UTC)


@pytest.mark.phase0
def test_advance_returns_the_new_instant(fake_clock: FakeClock) -> None:
    returned = fake_clock.advance(hours=3)
    assert returned == fake_clock.now() == datetime(2026, 1, 1, 3, tzinfo=UTC)


@pytest.mark.phase0
def test_non_utc_start_is_normalised_to_utc() -> None:
    """A tz-aware but non-UTC instant must not survive as a local time.

    Every timestamp this clock feeds is compared against `TIMESTAMPTZ`
    columns and against other components' `Clock`s; one offset-carrying
    datetime leaking through would make TTL guards off by the offset.
    """
    kolkata = timezone(timedelta(hours=5, minutes=30))
    clock = FakeClock(datetime(2026, 1, 1, 5, 30, tzinfo=kolkata))

    assert clock.now().tzinfo is UTC
    assert clock.now() == datetime(2026, 1, 1, 0, 0, tzinfo=UTC)


@pytest.mark.phase0
def test_set_is_an_absolute_reset_and_requires_tz_aware() -> None:
    clock = FakeClock(datetime(2026, 1, 1, tzinfo=UTC))
    target = datetime(2030, 6, 15, 12, tzinfo=UTC)

    clock.set(target)
    assert clock.now() == target

    with pytest.raises(ValueError, match="timezone-aware"):
        clock.set(datetime(2030, 6, 15, 12))


@pytest.mark.phase0
def test_fake_clock_rejects_naive_start() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        FakeClock(datetime(2026, 1, 1))


@pytest.mark.phase0
def test_fake_clock_satisfies_the_clock_protocol(fake_clock: FakeClock) -> None:
    # runtime_checkable only checks that the names exist, so exercise the
    # three members through the protocol type as well.
    assert isinstance(fake_clock, Clock)
    clock: Clock = fake_clock
    assert clock.now().tzinfo is UTC
    assert isinstance(clock.now_ms(), int)
    assert isinstance(clock.monotonic_ms(), float)


@pytest.mark.phase0
def test_system_clock_satisfies_the_clock_protocol() -> None:
    clock = SystemClock()
    assert isinstance(clock, Clock)
    # Sanity, not a determinism claim: now() is tz-aware and monotonic_ms
    # never regresses across two calls a moment apart.
    assert clock.now().tzinfo is not None
    first = clock.monotonic_ms()
    second = clock.monotonic_ms()
    assert second >= first
