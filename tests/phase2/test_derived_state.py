"""PLAN.md section 5 `derived_state`, section 6 `derived.*` --
`workers.derived_state.DerivedStateWriter`.

Offline by construction (task instruction: "all offline with FakeClock"):
`DerivedStateStorePort` is satisfied here by `FakeDerivedStateStore`, an
in-memory double that mirrors the real primary key
`(project_id, agent_type_id, key, version)` -- no Postgres, no
`@pytest.mark.integration`.

Covers defence 1 (rate bound / clamp), defence 2 (clamp-binding alert),
version pruning, the config refusals, the guardrail-flag drop, and the
restart-seeding path. Defence 3 (slow/fast divergence) and the drift-attack
scenarios live in `test_baseline_drift.py`, per this chunk's file list.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from tracebed.domain.clock import FakeClock
from tracebed.domain.config import DerivedConfig
from tracebed.domain.errors import ConfigError
from tracebed.domain.ids import AgentTypeId, ProjectId
from tracebed.workers.derived_state import (
    ClampAlert,
    DerivedStateStorePort,
    DerivedStateVersion,
    DerivedStateWriter,
)

pytestmark = pytest.mark.phase2

_PROJECT = ProjectId.parse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
_AGENT_TYPE = AgentTypeId.parse("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")
_KEY = "avg_tool_latency_ms"
_START = datetime(2026, 1, 1, tzinfo=UTC)


class FakeDerivedStateStore:
    """In-memory `DerivedStateStorePort`: one append-only list per
    `(project_id, agent_type_id, key)`, ordered by version;
    `prune_versions` trims from the front exactly like a real
    `DELETE ... WHERE version <= (max - keep)` would."""

    def __init__(self) -> None:
        self._rows: dict[tuple[ProjectId, AgentTypeId, str], list[DerivedStateVersion]] = {}

    def _bucket(
        self, project_id: ProjectId, agent_type_id: AgentTypeId, key: str
    ) -> list[DerivedStateVersion]:
        return self._rows.setdefault((project_id, agent_type_id, key), [])

    def recent_versions(
        self, project_id: ProjectId, agent_type_id: AgentTypeId, key: str
    ) -> list[DerivedStateVersion]:
        return sorted(self._bucket(project_id, agent_type_id, key), key=lambda row: row.version)

    def append_version(self, version: DerivedStateVersion) -> None:
        self._bucket(version.project_id, version.agent_type_id, version.key).append(version)

    def prune_versions(
        self, project_id: ProjectId, agent_type_id: AgentTypeId, key: str, *, keep: int
    ) -> None:
        bucket = self._bucket(project_id, agent_type_id, key)
        bucket.sort(key=lambda row: row.version)
        if len(bucket) > keep:
            del bucket[: len(bucket) - keep]


def _writer(cfg: DerivedConfig | None = None) -> tuple[DerivedStateWriter, FakeDerivedStateStore, FakeClock]:
    store = FakeDerivedStateStore()
    clock = FakeClock(_START)
    writer = DerivedStateWriter(store, clock, cfg or DerivedConfig())
    return writer, store, clock


def test_the_in_memory_double_satisfies_the_declared_store_port() -> None:
    """`DerivedStateStorePort` is `runtime_checkable`; if the writer grows a
    method the fake does not have, every other test here would fail with an
    `AttributeError` deep inside the writer instead of saying so."""
    assert isinstance(FakeDerivedStateStore(), DerivedStateStorePort)


# --------------------------------------------------------------------------- #
# Defence 1 -- the rate bound.
# --------------------------------------------------------------------------- #


def test_first_write_establishes_baseline_unclamped() -> None:
    writer, _store, _clock = _writer()

    result = writer.update(_PROJECT, _AGENT_TYPE, _KEY, 100.0)

    assert result.version is not None
    assert result.version.value == 100.0
    assert result.version.clamped is False
    assert result.version.delta_pct == 0.0
    assert result.version.version == 1
    assert result.clamp_alert is None
    # Nothing older than the fast window exists yet, so the divergence alarm
    # cannot answer -- and must say so rather than report an all-clear.
    assert result.divergence_evaluated is False


def test_single_large_jump_is_clamped_and_recorded() -> None:
    writer, _store, clock = _writer(DerivedConfig(baseline_max_delta_pct=10.0))
    writer.update(_PROJECT, _AGENT_TYPE, _KEY, 100.0)
    clock.advance(days=1)

    result = writer.update(_PROJECT, _AGENT_TYPE, _KEY, 150.0)  # +50% requested

    assert result.version is not None
    assert result.version.clamped is True
    assert result.version.delta_pct == pytest.approx(10.0)
    assert result.version.value == pytest.approx(110.0)  # 100 + 10% of 100
    assert result.version.version == 2


def test_the_clamp_uses_the_configured_percentage_not_a_literal() -> None:
    """Every other clamp test in this file happens to use the shipped default
    (10), so a `baseline_max_delta_pct` hardcoded in the writer would survive
    all of them."""
    writer, _store, clock = _writer(DerivedConfig(baseline_max_delta_pct=25.0))
    writer.update(_PROJECT, _AGENT_TYPE, _KEY, 100.0)
    clock.advance(days=1)

    result = writer.update(_PROJECT, _AGENT_TYPE, _KEY, 400.0)

    assert result.version is not None
    assert result.version.value == pytest.approx(125.0)
    assert result.version.delta_pct == pytest.approx(25.0)


def test_movement_exactly_at_the_bound_is_not_clamped() -> None:
    """The bound is `|delta| <= baseline_max_delta_pct` (PLAN.md section 5's
    own words); a `>=` comparison here would record a clamp for a move that
    was never actually reduced, and the clamp-binding alert counts clamps."""
    writer, _store, clock = _writer(DerivedConfig(baseline_max_delta_pct=10.0))
    writer.update(_PROJECT, _AGENT_TYPE, _KEY, 100.0)
    clock.advance(days=1)

    result = writer.update(_PROJECT, _AGENT_TYPE, _KEY, 110.0)

    assert result.version is not None
    assert result.version.clamped is False
    assert result.version.value == pytest.approx(110.0)


def test_small_movement_within_bound_is_not_clamped() -> None:
    writer, _store, clock = _writer(DerivedConfig(baseline_max_delta_pct=10.0))
    writer.update(_PROJECT, _AGENT_TYPE, _KEY, 100.0)
    clock.advance(days=1)

    result = writer.update(_PROJECT, _AGENT_TYPE, _KEY, 105.0)  # +5%, under bound

    assert result.version is not None
    assert result.version.clamped is False
    assert result.version.value == pytest.approx(105.0)
    assert result.version.delta_pct == pytest.approx(5.0)


def test_downward_jump_is_clamped_in_the_negative_direction() -> None:
    writer, _store, clock = _writer(DerivedConfig(baseline_max_delta_pct=10.0))
    writer.update(_PROJECT, _AGENT_TYPE, _KEY, 100.0)
    clock.advance(days=1)

    result = writer.update(_PROJECT, _AGENT_TYPE, _KEY, 40.0)  # -60% requested

    assert result.version is not None
    assert result.version.clamped is True
    assert result.version.delta_pct == pytest.approx(-10.0)
    assert result.version.value == pytest.approx(90.0)


def test_a_negative_baseline_is_clamped_by_magnitude_in_the_right_direction() -> None:
    """`derived_state` values are not sign-constrained anywhere, and the
    clamp works in percent of |previous|; the direction must not invert for a
    negative baseline."""
    writer, _store, clock = _writer(DerivedConfig(baseline_max_delta_pct=10.0))
    writer.update(_PROJECT, _AGENT_TYPE, _KEY, -100.0)
    clock.advance(days=1)

    result = writer.update(_PROJECT, _AGENT_TYPE, _KEY, -400.0)

    assert result.version is not None
    assert result.version.value == pytest.approx(-110.0)
    assert result.version.delta_pct == pytest.approx(-10.0)


def test_zero_valued_baseline_passes_its_next_write_through_unclamped() -> None:
    """Percent-of-zero has no defined value; a zero baseline must not be
    permanently stuck at zero because 10% of a zero magnitude is always
    zero."""
    writer, _store, clock = _writer()
    writer.update(_PROJECT, _AGENT_TYPE, _KEY, 0.0)
    clock.advance(days=1)

    result = writer.update(_PROJECT, _AGENT_TYPE, _KEY, 500.0)

    assert result.version is not None
    assert result.version.clamped is False
    assert result.version.value == 500.0


def test_distinct_keys_are_independently_rate_bounded() -> None:
    writer, _store, clock = _writer()
    writer.update(_PROJECT, _AGENT_TYPE, "key_a", 100.0)
    writer.update(_PROJECT, _AGENT_TYPE, "key_b", 100.0)
    clock.advance(days=1)

    result_a = writer.update(_PROJECT, _AGENT_TYPE, "key_a", 1_000.0)
    result_b = writer.update(_PROJECT, _AGENT_TYPE, "key_b", 105.0)

    assert result_a.version is not None
    assert result_b.version is not None
    assert result_a.version.clamped is True
    assert result_b.version.clamped is False


def test_the_same_key_in_two_projects_does_not_share_a_baseline() -> None:
    """`derived_state`'s primary key is scoped by project (PLAN.md section 5,
    invariant 4); a writer keyed on `key` alone would let one project's
    baseline rate-bound another's."""
    other_project = ProjectId.parse("cccccccc-cccc-cccc-cccc-cccccccccccc")
    writer, _store, clock = _writer()
    writer.update(_PROJECT, _AGENT_TYPE, _KEY, 100.0)
    clock.advance(days=1)

    result = writer.update(other_project, _AGENT_TYPE, _KEY, 9_999.0)

    assert result.version is not None
    assert result.version.version == 1
    assert result.version.value == 9_999.0  # a first write for that project, not a clamped move


# --------------------------------------------------------------------------- #
# Defence 2 -- the clamp-binding alert.
# --------------------------------------------------------------------------- #


def test_three_consecutive_clamps_raise_alert_and_fourth_does_not_double_raise() -> None:
    cfg = DerivedConfig(baseline_max_delta_pct=10.0, clamp_alert_consecutive=3)
    writer, _store, clock = _writer(cfg)
    writer.update(_PROJECT, _AGENT_TYPE, _KEY, 100.0)

    alerts: list[ClampAlert | None] = []
    for _ in range(4):
        clock.advance(days=1)
        result = writer.update(_PROJECT, _AGENT_TYPE, _KEY, 1_000_000.0)  # always clamps
        assert result.version is not None
        assert result.version.clamped is True
        alerts.append(result.clamp_alert)

    assert alerts[0] is None  # streak 1
    assert alerts[1] is None  # streak 2
    assert alerts[2] is not None  # streak 3 -- alert fires
    assert alerts[2].consecutive_clamps == 3
    assert alerts[3] is None  # streak 4 -- already alerted this streak, no re-raise


def test_the_alert_threshold_comes_from_config_not_a_literal() -> None:
    cfg = DerivedConfig(baseline_max_delta_pct=10.0, clamp_alert_consecutive=2)
    writer, _store, clock = _writer(cfg)
    writer.update(_PROJECT, _AGENT_TYPE, _KEY, 100.0)

    clock.advance(days=1)
    first = writer.update(_PROJECT, _AGENT_TYPE, _KEY, 1_000_000.0)
    clock.advance(days=1)
    second = writer.update(_PROJECT, _AGENT_TYPE, _KEY, 1_000_000.0)

    assert first.clamp_alert is None
    assert second.clamp_alert is not None
    assert second.clamp_alert.consecutive_clamps == 2


def test_clamp_streak_resets_after_an_unclamped_update() -> None:
    cfg = DerivedConfig(baseline_max_delta_pct=10.0, clamp_alert_consecutive=3)
    writer, _store, clock = _writer(cfg)
    writer.update(_PROJECT, _AGENT_TYPE, _KEY, 100.0)

    for _ in range(2):
        clock.advance(days=1)
        writer.update(_PROJECT, _AGENT_TYPE, _KEY, 1_000_000.0)  # clamps, streak -> 2

    clock.advance(days=1)
    # previous applied value is 121.0 (100 -> +10% -> 110 -> +10% -> 121); 115.0 is
    # within 10% of 121.0 (~-4.96%), a genuine within-bound move that resets the streak.
    reset_result = writer.update(_PROJECT, _AGENT_TYPE, _KEY, 115.0)
    assert reset_result.version is not None
    assert reset_result.version.clamped is False

    clock.advance(days=1)
    third_clamp = writer.update(_PROJECT, _AGENT_TYPE, _KEY, 1_000_000.0)
    assert third_clamp.version is not None
    assert third_clamp.version.clamped is True
    assert third_clamp.clamp_alert is None  # streak restarted at 1, not a continuation


def test_a_second_clamp_incident_alerts_again_after_the_first_one_ended() -> None:
    """The "already alerted, do not repeat" latch must be cleared by the
    same unclamped update that resets the streak. A latch that is only ever
    set silences every incident after the first -- and the test above cannot
    see it, because its first streak stops at 2 and never sets the latch at
    all."""
    cfg = DerivedConfig(baseline_max_delta_pct=10.0, clamp_alert_consecutive=3)
    writer, _store, clock = _writer(cfg)
    writer.update(_PROJECT, _AGENT_TYPE, _KEY, 100.0)

    def three_clamps() -> ClampAlert | None:
        alert: ClampAlert | None = None
        for _ in range(3):
            clock.advance(days=1)
            alert = writer.update(_PROJECT, _AGENT_TYPE, _KEY, 1_000_000.0).clamp_alert or alert
        return alert

    assert three_clamps() is not None  # first incident

    clock.advance(days=1)
    settled = writer.update(_PROJECT, _AGENT_TYPE, _KEY, 130.0)  # within 10% of 133.1
    assert settled.version is not None
    assert settled.version.clamped is False

    second = three_clamps()
    assert second is not None
    assert second.consecutive_clamps == 3


# --------------------------------------------------------------------------- #
# Restart safety -- both watchdogs are seeded from the store.
# --------------------------------------------------------------------------- #


def test_a_restarted_writer_continues_the_clamp_streak_instead_of_restarting_it() -> None:
    """The streak lives in process memory. Without seeding it from the
    persisted `clamped` flags, anything that recycles the process -- a
    deploy, a crash, an attacker who can cause either -- buys
    `clamp_alert_consecutive` more unreported clamps, forever."""
    cfg = DerivedConfig(baseline_max_delta_pct=10.0, clamp_alert_consecutive=3)
    store = FakeDerivedStateStore()
    clock = FakeClock(_START)

    first = DerivedStateWriter(store, clock, cfg)
    first.update(_PROJECT, _AGENT_TYPE, _KEY, 100.0)
    for _ in range(2):
        clock.advance(days=1)
        assert first.update(_PROJECT, _AGENT_TYPE, _KEY, 1_000_000.0).clamp_alert is None

    restarted = DerivedStateWriter(store, clock, cfg)
    clock.advance(days=1)
    result = restarted.update(_PROJECT, _AGENT_TYPE, _KEY, 1_000_000.0)

    assert result.clamp_alert is not None
    assert result.clamp_alert.consecutive_clamps == 3


def test_a_restarted_writer_can_still_evaluate_divergence_from_persisted_history() -> None:
    """The divergence alarm needs a reading older than the fast window. A
    writer that starts with an empty history is blind for 24 simulated hours,
    during which only the per-update rate bound applies."""
    store = FakeDerivedStateStore()
    clock = FakeClock(_START)

    first = DerivedStateWriter(store, clock, DerivedConfig())
    first.update(_PROJECT, _AGENT_TYPE, _KEY, 100.0)
    clock.advance(days=2)

    restarted = DerivedStateWriter(store, clock, DerivedConfig())
    result = restarted.update(_PROJECT, _AGENT_TYPE, _KEY, 105.0)

    assert result.divergence_evaluated is True
    assert result.divergence_alarm is None  # +5% is well under the 25% alarm


def test_the_writer_does_not_depend_on_the_stores_row_order() -> None:
    """`recent_versions` documents oldest-first, but the row the rate bound
    clamps against and the trailing run of `clamped` flags are both too
    load-bearing to rest on an adapter honouring a docstring -- a
    newest-first adapter would clamp against the oldest retained value and
    reconstruct the streak from the wrong end."""

    class ReversedStore(FakeDerivedStateStore):
        def recent_versions(
            self, project_id: ProjectId, agent_type_id: AgentTypeId, key: str
        ) -> list[DerivedStateVersion]:
            return list(reversed(super().recent_versions(project_id, agent_type_id, key)))

    cfg = DerivedConfig(baseline_max_delta_pct=10.0, clamp_alert_consecutive=3)
    store = ReversedStore()
    clock = FakeClock(_START)
    first = DerivedStateWriter(store, clock, cfg)
    first.update(_PROJECT, _AGENT_TYPE, _KEY, 100.0)
    for _ in range(2):
        clock.advance(days=1)
        first.update(_PROJECT, _AGENT_TYPE, _KEY, 1_000_000.0)

    restarted = DerivedStateWriter(store, clock, cfg)
    clock.advance(days=1)
    result = restarted.update(_PROJECT, _AGENT_TYPE, _KEY, 1_000_000.0)

    assert result.version is not None
    assert result.version.value == pytest.approx(133.1)  # clamped against 121.0, the newest row
    assert result.clamp_alert is not None
    assert result.clamp_alert.consecutive_clamps == 3


def test_a_restarted_writer_does_not_double_count_seeded_readings() -> None:
    """Seeding happens once per key per process; re-seeding on every update
    would weight the persisted rows more heavily each call and quietly drag
    the reference toward them."""
    store = FakeDerivedStateStore()
    clock = FakeClock(_START)
    first = DerivedStateWriter(store, clock, DerivedConfig())
    first.update(_PROJECT, _AGENT_TYPE, _KEY, 100.0)

    restarted = DerivedStateWriter(store, clock, DerivedConfig())
    clock.advance(days=1)
    restarted.update(_PROJECT, _AGENT_TYPE, _KEY, 100.0)
    clock.advance(days=1)
    restarted.update(_PROJECT, _AGENT_TYPE, _KEY, 100.0)

    rows = store.recent_versions(_PROJECT, _AGENT_TYPE, _KEY)
    assert [row.version for row in rows] == [1, 2, 3]


# --------------------------------------------------------------------------- #
# Versioning, guardrail flag, and input/config refusals.
# --------------------------------------------------------------------------- #


def test_version_pruning_keeps_exactly_keep_versions() -> None:
    writer, store, clock = _writer(DerivedConfig(keep_versions=5))

    for i in range(12):
        clock.advance(days=1)
        writer.update(_PROJECT, _AGENT_TYPE, _KEY, 100.0 + i)  # small, unclamped moves

    kept = store.recent_versions(_PROJECT, _AGENT_TYPE, _KEY)
    assert len(kept) == 5
    # pruning drops the OLDEST rows, keeping the most recent versions contiguous.
    assert [row.version for row in kept] == [8, 9, 10, 11, 12]


def test_pruning_never_deletes_the_row_the_rate_bound_reads() -> None:
    """`keep_versions` is the debugging-retention knob, but the writer also
    reads the newest row to clamp against. With `keep=1` the rate bound must
    still bind on every subsequent update."""
    writer, _store, clock = _writer(DerivedConfig(keep_versions=1, baseline_max_delta_pct=10.0))
    writer.update(_PROJECT, _AGENT_TYPE, _KEY, 100.0)

    applied: list[float] = []
    for _ in range(3):
        clock.advance(days=1)
        result = writer.update(_PROJECT, _AGENT_TYPE, _KEY, 1_000_000.0)
        assert result.version is not None
        assert result.version.clamped is True
        applied.append(result.version.value)

    assert applied == pytest.approx([110.0, 121.0, 133.1])  # 100 * 1.1**n, never reset


def test_a_guardrail_flagged_reading_contributes_nothing() -> None:
    """D-022: "guardrail-flagged runs are excluded from baseline
    contribution". Excluded means excluded -- no row, no reference sample, no
    clamp streak movement. An implementation that still applied the value and
    merely hid it from the reference windows would be strictly worse than no
    flag at all: the suspect run moves the baseline AND is invisible to the
    one watchdog that could have noticed."""
    writer, store, clock = _writer()
    writer.update(_PROJECT, _AGENT_TYPE, _KEY, 100.0)
    clock.advance(days=1)

    result = writer.update(_PROJECT, _AGENT_TYPE, _KEY, 108.0, guardrail_flagged=True)

    assert result.guardrail_skipped is True
    assert result.version is None
    assert result.clamp_alert is None
    assert result.divergence_alarm is None
    rows = store.recent_versions(_PROJECT, _AGENT_TYPE, _KEY)
    assert [row.value for row in rows] == [100.0]


def test_non_finite_raw_value_is_refused() -> None:
    writer, _store, _clock = _writer()
    with pytest.raises(ValueError):
        writer.update(_PROJECT, _AGENT_TYPE, _KEY, float("nan"))
    with pytest.raises(ValueError):
        writer.update(_PROJECT, _AGENT_TYPE, _KEY, float("inf"))


def test_empty_key_is_refused() -> None:
    writer, _store, _clock = _writer()
    with pytest.raises(ValueError):
        writer.update(_PROJECT, _AGENT_TYPE, "", 1.0)


def test_a_clock_that_moves_backwards_is_refused() -> None:
    """Every window here is measured as "how long ago", and the slow
    reference is picked by age; a backwards clock re-dates readings into
    periods they did not happen in."""
    writer, _store, clock = _writer()
    writer.update(_PROJECT, _AGENT_TYPE, _KEY, 100.0)
    clock.set(_START - timedelta(days=1))

    with pytest.raises(ValueError):
        writer.update(_PROJECT, _AGENT_TYPE, _KEY, 101.0)


_DEGENERATE_DERIVED_FIELDS: list[dict[str, object]] = [
    {"keep_versions": 0},
    {"keep_versions": -1},
    {"baseline_max_delta_pct": 0.0},
    {"baseline_max_delta_pct": -10.0},
    {"clamp_alert_consecutive": 0},
    {"divergence_alarm_pct": -1.0},
]


@pytest.mark.parametrize("fields", _DEGENERATE_DERIVED_FIELDS)
def test_a_degenerate_derived_override_is_refused_by_the_config_layer(
    fields: dict[str, object],
) -> None:
    """`derived` is an OVERRIDABLE_SECTION, so each of these is reachable from
    a `project_config` jsonb row. `keep_versions=0` is the dangerous one: it
    prunes away the row the rate bound reads, so every update looks like a
    first write and nothing is ever clamped -- the clamp silently disabled by
    a retention knob. The field constraints kill it where the override is
    parsed, which is what lets `ConfigResolver` name the offending section."""
    with pytest.raises(ValidationError):
        DerivedConfig(**fields)


@pytest.mark.parametrize("fields", _DEGENERATE_DERIVED_FIELDS)
def test_a_degenerate_derived_config_is_still_refused_at_construction(
    fields: dict[str, object],
) -> None:
    """Defence in depth, deliberately kept after the field constraints landed.

    `model_construct` is pydantic's documented validation bypass and is used
    across this repo's test doubles; a future non-pydantic config source (an
    operator tool, a migration script) reaches this writer the same way. The
    writer's refusal is what makes the control's absence impossible rather
    than merely improbable, so it gets its own test on a config the field
    constraints never saw."""
    unvalidated = DerivedConfig.model_construct(**{**DerivedConfig().model_dump(), **fields})
    with pytest.raises(ConfigError):
        DerivedStateWriter(FakeDerivedStateStore(), FakeClock(_START), unvalidated)
