"""PHASE-0 Task 16 / PHASE0-CONTRACT.md §5.4, §13.2: `SpendMeter` and its UTC day bucketing.

Per §13.2 this file's job is "accumulation by day sums correctly (offline via fake repo;
integration variant optional)" -- unlike `test_telemetry.py`, this suite is NOT marked
`[integration]` in the contract's test-ownership table, so the offline path below is the primary
proof, not a secondary one. The day-bucketing and cap arithmetic are pure functions
(`tracebed.workers.spend._utc_day`, `_cap_status`), extracted specifically so they are testable
without a database (task description); the `FakeRepo`-backed `SpendMeter` tests then prove the
class wires those pure functions to `Repo.spend_add` / `Repo.spend_by_day` correctly, including
across a `FakeClock` that advances over a UTC midnight boundary. One integration test at the end
exercises the same accumulation against a real `spend_ledger`, when Postgres is available.
"""

from __future__ import annotations

from datetime import UTC, date, datetime, timedelta, timezone
from typing import Any

import pytest

from tracebed.domain.clock import FakeClock
from tracebed.domain.config import SpendConfig
from tracebed.domain.ids import ProjectId, uuid7
from tracebed.stores.pg.rows import SpendRow
from tracebed.workers.spend import CapStatus, SpendMeter, _cap_status, _utc_day

pytestmark = pytest.mark.phase0


def _require_fixture(request: pytest.FixtureRequest, name: str) -> Any:
    """Same skip-safe fixture lookup as `test_telemetry.py` -- see that file's docstring."""
    try:
        return request.getfixturevalue(name)
    except pytest.FixtureLookupError:
        pytest.skip(f"fixture {name!r} unavailable (tests/phase0/conftest.py, owner: harness)")


class FakeRepo:
    """In-memory `spend_ledger`, replicating the real `Repo.spend_add` accumulation semantics
    (`ON CONFLICT (project_id, day, worker, model_id) DO UPDATE SET ... += ...`) exactly, so
    `SpendMeter` tests against this fake exercise the same accumulation behaviour the real
    repository provides -- the fake would otherwise silently test a different contract than the
    one `spend.py`'s docstring promises.
    """

    def __init__(self) -> None:
        self.add_calls: list[tuple[ProjectId, date, str, str, int, int, float]] = []
        self._ledger: dict[tuple[ProjectId, date, str, str], SpendRow] = {}

    def spend_add(
        self,
        project_id: ProjectId,
        day: date,
        worker: str,
        model_id: str,
        tokens_in: int,
        tokens_out: int,
        cost_usd: float,
    ) -> None:
        self.add_calls.append((project_id, day, worker, model_id, tokens_in, tokens_out, cost_usd))
        key = (project_id, day, worker, model_id)
        existing = self._ledger.get(key)
        if existing is None:
            self._ledger[key] = SpendRow(
                day=day,
                worker=worker,
                model_id=model_id,
                tokens_in=tokens_in,
                tokens_out=tokens_out,
                cost_usd=cost_usd,
            )
        else:
            self._ledger[key] = SpendRow(
                day=day,
                worker=worker,
                model_id=model_id,
                tokens_in=existing.tokens_in + tokens_in,
                tokens_out=existing.tokens_out + tokens_out,
                cost_usd=existing.cost_usd + cost_usd,
            )

    def spend_by_day(self, project_id: ProjectId, day: date) -> list[SpendRow]:
        return [
            row for (pid, d, _worker, _model), row in self._ledger.items() if pid == project_id and d == day
        ]


# --------------------------------------------------------------------------------- #
# Pure day-bucketing and cap arithmetic -- no repo, no clock object, no database.
# --------------------------------------------------------------------------------- #


def test_utc_day_of_a_utc_instant() -> None:
    assert _utc_day(datetime(2026, 7, 25, 23, 59, tzinfo=UTC)) == date(2026, 7, 25)
    assert _utc_day(datetime(2026, 7, 26, 0, 0, tzinfo=UTC)) == date(2026, 7, 26)


def test_utc_day_rejects_a_naive_instant_instead_of_guessing_a_timezone() -> None:
    """`datetime.astimezone(UTC)` reads a naive datetime as HOST-local time. A `Clock`
    implementation that returned naive instants (nothing stops one -- `Clock` is a structural
    Protocol) would therefore bucket spend against the deployment's local day and do it
    silently. This asserts the guard is enforcement, not a docstring: mutate `_utc_day` back to
    a bare `instant.astimezone(UTC).date()` and this test goes red."""
    with pytest.raises(ValueError, match="timezone-aware"):
        _utc_day(datetime(2026, 7, 25, 23, 30))


def test_utc_day_normalises_a_non_utc_offset_before_bucketing() -> None:
    """The exact bug the task description warns about: bucketing on the instant's own local
    calendar date (rather than its UTC date) would put this instant in `2026-07-25`, one day
    off -- `23:30` in UTC-05:00 is `2026-07-26 04:30` UTC. A ledger keyed the wrong way here
    would disagree with itself across two deployments in different timezones for the exact same
    wall-clock spend event."""
    minus_five = timezone(timedelta(hours=-5))
    instant = datetime(2026, 7, 25, 23, 30, tzinfo=minus_five)

    assert instant.date() == date(2026, 7, 25)  # the naive-local-date trap
    assert _utc_day(instant) == date(2026, 7, 26)  # the correct UTC bucket


def test_cap_status_boundary_exactly_at_cap_is_not_exceeded() -> None:
    rows = [SpendRow(day=date(2026, 1, 1), worker="w", model_id="m", tokens_in=1, tokens_out=1, cost_usd=25.0)]
    status = _cap_status(rows, cap_usd=25.0)
    assert status == CapStatus(spent_today_usd=25.0, cap_usd=25.0, exceeded=False)


def test_cap_status_one_cent_over_is_exceeded() -> None:
    rows = [SpendRow(day=date(2026, 1, 1), worker="w", model_id="m", tokens_in=1, tokens_out=1, cost_usd=25.01)]
    status = _cap_status(rows, cap_usd=25.0)
    assert status.exceeded is True


def test_cap_status_sums_across_multiple_worker_model_cells() -> None:
    rows = [
        SpendRow(day=date(2026, 1, 1), worker="distiller", model_id="gemini-3.1-pro", tokens_in=1, tokens_out=1, cost_usd=10.0),
        SpendRow(day=date(2026, 1, 1), worker="scorer", model_id="gemini-3.1-pro", tokens_in=1, tokens_out=1, cost_usd=8.0),
        SpendRow(day=date(2026, 1, 1), worker="distiller", model_id="gemini-3.1-flash", tokens_in=1, tokens_out=1, cost_usd=4.0),
    ]
    status = _cap_status(rows, cap_usd=25.0)
    assert status.spent_today_usd == pytest.approx(22.0)
    assert status.exceeded is False


def test_cap_status_empty_ledger_is_zero_and_not_exceeded() -> None:
    status = _cap_status([], cap_usd=25.0)
    assert status == CapStatus(spent_today_usd=0.0, cap_usd=25.0, exceeded=False)


# --------------------------------------------------------------------------------- #
# SpendMeter wired to a fake repo + FakeClock.
# --------------------------------------------------------------------------------- #


def _project() -> ProjectId:
    return ProjectId(uuid7())


def test_add_buckets_by_the_clocks_utc_day_not_by_the_wall_clock() -> None:
    """Deliberately dated far from any plausible run date. An earlier version of this test used
    the day it was written, which meant a `SpendMeter` that ignored its injected `Clock` and
    called `date.today()` still passed -- the assertion could not distinguish clock-driven from
    wall-clock-driven bucketing on the day it was authored. `date.today()` is asserted to differ
    so the distinction is proven, not assumed."""
    bucket_day = date(2019, 3, 7)
    assert date.today() != bucket_day, "pick a bucket day that is not the host's today"

    clock = FakeClock(datetime(2019, 3, 7, 12, 0, tzinfo=UTC))
    repo = FakeRepo()
    meter = SpendMeter(repo, clock, SpendConfig())  # type: ignore[arg-type]
    project_id = _project()

    meter.add(project_id, worker="distiller", model_id="gemini-3.1-pro", tokens_in=100, tokens_out=50, cost_usd=1.5)

    assert repo.add_calls == [(project_id, bucket_day, "distiller", "gemini-3.1-pro", 100, 50, 1.5)]


@pytest.mark.parametrize(
    ("tokens_in", "tokens_out", "cost_usd"),
    [
        (1, 1, -5.0),  # a "refund" subtracts from the capped total
        (-1, 1, 1.0),
        (1, -1, 1.0),
        (1, 1, float("nan")),  # NaN: sum() propagates it and `nan > cap` is False, forever
    ],
)
def test_add_rejects_deltas_that_would_disable_the_cap(
    tokens_in: int, tokens_out: int, cost_usd: float
) -> None:
    """`spend_ledger` constrains neither sign nor NaN (migrations/0002) and `Repo.spend_add` is
    an unconditional `+= EXCLUDED`, so either kind of delta makes `check_cap` under-report the
    total it is the sole input to. Rejected at the meter; nothing reaches the repository and an
    already-exceeded project stays exceeded."""
    clock = FakeClock(datetime(2026, 7, 25, 12, 0, tzinfo=UTC))
    repo = FakeRepo()
    meter = SpendMeter(repo, clock, SpendConfig(daily_llm_cap_usd=10.0))  # type: ignore[arg-type]
    project_id = _project()

    meter.add(project_id, "distiller", "gemini-3.1-pro", 1000, 500, 12.0)
    assert meter.check_cap(project_id).exceeded is True

    with pytest.raises(ValueError, match="non-negative, non-NaN"):
        meter.add(project_id, "distiller", "gemini-3.1-pro", tokens_in, tokens_out, cost_usd)

    assert len(repo.add_calls) == 1, "a rejected delta must not reach the repository"
    assert meter.check_cap(project_id).exceeded is True


def test_add_accumulates_multiple_calls_same_day_same_cell() -> None:
    clock = FakeClock(datetime(2026, 7, 25, 1, 0, tzinfo=UTC))
    repo = FakeRepo()
    meter = SpendMeter(repo, clock, SpendConfig())  # type: ignore[arg-type]
    project_id = _project()

    meter.add(project_id, "distiller", "gemini-3.1-pro", 100, 50, 1.5)
    clock.advance(hours=2)
    meter.add(project_id, "distiller", "gemini-3.1-pro", 200, 75, 2.25)

    rows = repo.spend_by_day(project_id, date(2026, 7, 25))
    assert len(rows) == 1
    row = rows[0]
    assert row.tokens_in == 300
    assert row.tokens_out == 125
    assert row.cost_usd == pytest.approx(3.75)


def test_add_keeps_distinct_worker_model_cells_separate() -> None:
    clock = FakeClock(datetime(2026, 7, 25, 1, 0, tzinfo=UTC))
    repo = FakeRepo()
    meter = SpendMeter(repo, clock, SpendConfig())  # type: ignore[arg-type]
    project_id = _project()

    meter.add(project_id, "distiller", "gemini-3.1-pro", 100, 50, 1.0)
    meter.add(project_id, "scorer", "gemini-3.1-pro", 10, 5, 0.1)
    meter.add(project_id, "distiller", "gemini-3.1-flash", 40, 20, 0.05)

    rows = repo.spend_by_day(project_id, date(2026, 7, 25))
    assert len(rows) == 3


def test_ledger_rolls_over_at_utc_midnight_not_at_a_local_one() -> None:
    """The scenario the task description names explicitly: a `FakeClock` advancing across a
    midnight boundary must land two separate day buckets, and `check_cap` on the new day must
    not see yesterday's spend -- proving the rollover happens at UTC midnight, driven by the
    clock, not by wall-clock/local time."""
    clock = FakeClock(datetime(2026, 7, 25, 23, 0, tzinfo=UTC))
    repo = FakeRepo()
    cfg = SpendConfig(daily_llm_cap_usd=10.0)
    meter = SpendMeter(repo, clock, cfg)  # type: ignore[arg-type]
    project_id = _project()

    meter.add(project_id, "distiller", "gemini-3.1-pro", 1000, 500, 9.0)
    day_one_status = meter.check_cap(project_id)
    assert day_one_status == CapStatus(spent_today_usd=9.0, cap_usd=10.0, exceeded=False)

    clock.advance(hours=2)  # 2026-07-25T23:00Z -> 2026-07-26T01:00Z, crosses UTC midnight
    day_two_status = meter.check_cap(project_id)
    assert day_two_status == CapStatus(spent_today_usd=0.0, cap_usd=10.0, exceeded=False), (
        "yesterday's spend leaked into today's cap check -- the ledger did not roll over at UTC "
        "midnight"
    )

    meter.add(project_id, "distiller", "gemini-3.1-pro", 100, 50, 5.0)
    day_two_status_after_add = meter.check_cap(project_id)
    assert day_two_status_after_add == CapStatus(spent_today_usd=5.0, cap_usd=10.0, exceeded=False)

    # Both days independently queryable -- the day-one cell was not overwritten by day two's add.
    day_one_rows = repo.spend_by_day(project_id, date(2026, 7, 25))
    day_two_rows = repo.spend_by_day(project_id, date(2026, 7, 26))
    assert len(day_one_rows) == 1 and day_one_rows[0].cost_usd == pytest.approx(9.0)
    assert len(day_two_rows) == 1 and day_two_rows[0].cost_usd == pytest.approx(5.0)


def test_check_cap_exceeded_true_once_spend_passes_the_configured_cap() -> None:
    clock = FakeClock(datetime(2026, 7, 25, 12, 0, tzinfo=UTC))
    repo = FakeRepo()
    cfg = SpendConfig(daily_llm_cap_usd=5.0)
    meter = SpendMeter(repo, clock, cfg)  # type: ignore[arg-type]
    project_id = _project()

    meter.add(project_id, "distiller", "gemini-3.1-pro", 1, 1, 5.01)

    assert meter.check_cap(project_id) == CapStatus(spent_today_usd=5.01, cap_usd=5.0, exceeded=True)


def test_check_cap_with_no_spend_recorded_yet() -> None:
    clock = FakeClock(datetime(2026, 7, 25, 12, 0, tzinfo=UTC))
    meter = SpendMeter(FakeRepo(), clock, SpendConfig())  # type: ignore[arg-type]
    project_id = _project()

    assert meter.check_cap(project_id) == CapStatus(spent_today_usd=0.0, cap_usd=25.0, exceeded=False)


def test_spend_meter_never_aggregates_across_projects() -> None:
    """Restates the module's documented asymmetry from the consuming side: two projects, spend
    recorded on both, `check_cap` for project A must be blind to project B's spend even though
    both cells sit in the same `FakeRepo` ledger dict."""
    clock = FakeClock(datetime(2026, 7, 25, 12, 0, tzinfo=UTC))
    repo = FakeRepo()
    cfg = SpendConfig(daily_llm_cap_usd=10.0)
    meter = SpendMeter(repo, clock, cfg)  # type: ignore[arg-type]
    project_a, project_b = _project(), _project()

    meter.add(project_a, "distiller", "gemini-3.1-pro", 1, 1, 3.0)
    meter.add(project_b, "distiller", "gemini-3.1-pro", 1, 1, 9.0)

    assert meter.check_cap(project_a) == CapStatus(spent_today_usd=3.0, cap_usd=10.0, exceeded=False)
    assert meter.check_cap(project_b) == CapStatus(spent_today_usd=9.0, cap_usd=10.0, exceeded=False)


# --------------------------------------------------------------------------------- #
# Integration variant (optional per §13.2): the same accumulation against a real spend_ledger.
# --------------------------------------------------------------------------------- #


@pytest.mark.integration
def test_spend_accumulates_and_isolates_against_a_real_ledger(
    request: pytest.FixtureRequest, fake_clock: FakeClock
) -> None:
    repo = _require_fixture(request, "repo")
    scope_a, scope_b = _require_fixture(request, "two_projects")
    cfg = SpendConfig(daily_llm_cap_usd=100.0)
    meter = SpendMeter(repo, fake_clock, cfg)

    meter.add(scope_a.project_id, "distiller", "gemini-3.1-pro", 500, 200, 12.5)
    meter.add(scope_a.project_id, "distiller", "gemini-3.1-pro", 500, 200, 12.5)
    meter.add(scope_b.project_id, "distiller", "gemini-3.1-pro", 1, 1, 1.0)

    status_a = meter.check_cap(scope_a.project_id)
    assert status_a.spent_today_usd == pytest.approx(25.0)
    assert status_a.exceeded is False

    status_b = meter.check_cap(scope_b.project_id)
    assert status_b.spent_today_usd == pytest.approx(1.0)
