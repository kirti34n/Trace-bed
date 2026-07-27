"""workers.epochs: scoring_epoch resolution and cross-epoch refusal.

Entirely offline — `EpochStorePort` is satisfied here by an in-memory fake
that never touches Postgres; `workers.epochs` has no store or LLM dependency
of its own to fake around.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from tracebed.domain.clock import FakeClock
from tracebed.domain.errors import CrossEpochComparison
from tracebed.workers.epochs import (
    EpochStorePort,
    EpochStoreViolation,
    JudgePin,
    ScoringEpoch,
    assert_same_epoch,
    resolve_epoch,
)

pytestmark = pytest.mark.phase3


class FakeEpochStore:
    """In-memory `EpochStorePort`. `current_epoch` is the most recently
    started one; `start_epoch` is insert-or-return-existing keyed on the pin,
    exactly as the port's docstring requires (a store that minted a row per
    call would mint one per alternating worker, forever). Nothing is ever
    mutated or deleted, matching the contract's "old epochs stay queryable"
    guarantee."""

    def __init__(self) -> None:
        self._epochs: list[ScoringEpoch] = []
        self._next_id = 1
        self.start_calls = 0

    def current_epoch(self) -> ScoringEpoch | None:
        return self._epochs[-1] if self._epochs else None

    def start_epoch(self, pin: JudgePin, started_at: datetime) -> ScoringEpoch:
        self.start_calls += 1
        for existing in self._epochs:
            if existing.pin() == pin:
                return existing
        epoch = ScoringEpoch(
            epoch_id=self._next_id,
            judge_model_id=pin.judge_model_id,
            judge_model_version=pin.judge_model_version,
            sampling_params=pin.sampling_params,
            prompt_hash=pin.prompt_hash,
            started_at=started_at,
        )
        self._next_id += 1
        self._epochs.append(epoch)
        return epoch

    @property
    def history(self) -> tuple[ScoringEpoch, ...]:
        return tuple(self._epochs)


def test_the_fake_store_satisfies_the_port_structurally() -> None:
    assert isinstance(FakeEpochStore(), EpochStorePort)


def _pin(**overrides: object) -> JudgePin:
    base: dict[str, object] = {
        "judge_model_id": "gemini-3.1-pro",
        "judge_model_version": "001",
        "sampling_params": {"temperature": 0.0, "max_tokens": 8},
        "prompt_hash": "a" * 64,
    }
    base.update(overrides)
    return JudgePin(**base)  # type: ignore[arg-type]


# --------------------------------------------------------------------------- #
# resolve_epoch: starts fresh with no history, reuses on a matching pin, and
# starts a NEW epoch automatically the moment any pin field differs.
# --------------------------------------------------------------------------- #


def test_resolve_epoch_starts_the_first_epoch_when_the_store_has_none() -> None:
    store = FakeEpochStore()
    clock = FakeClock()

    epoch = resolve_epoch(_pin(), store=store, clock=clock)

    assert epoch.epoch_id == 1
    assert epoch.started_at == clock.now()
    assert store.current_epoch() == epoch


def test_resolve_epoch_reuses_the_current_epoch_when_the_pin_is_unchanged() -> None:
    store = FakeEpochStore()
    clock = FakeClock()
    first = resolve_epoch(_pin(), store=store, clock=clock)

    clock.advance(hours=1)
    second = resolve_epoch(_pin(), store=store, clock=clock)

    assert second == first
    assert len(store.history) == 1


def test_a_changed_judge_model_starts_a_new_epoch_automatically() -> None:
    store = FakeEpochStore()
    clock = FakeClock()
    first = resolve_epoch(_pin(judge_model_id="gemini-3.1-pro"), store=store, clock=clock)

    second = resolve_epoch(_pin(judge_model_id="gemini-4.0-pro"), store=store, clock=clock)

    assert second.epoch_id != first.epoch_id
    assert len(store.history) == 2


def test_a_changed_judge_model_version_starts_a_new_epoch_automatically() -> None:
    store = FakeEpochStore()
    clock = FakeClock()
    first = resolve_epoch(_pin(judge_model_version="001"), store=store, clock=clock)

    second = resolve_epoch(_pin(judge_model_version="002"), store=store, clock=clock)

    assert second.epoch_id != first.epoch_id


def test_a_changed_sampling_param_starts_a_new_epoch_automatically() -> None:
    store = FakeEpochStore()
    clock = FakeClock()
    first = resolve_epoch(
        _pin(sampling_params={"temperature": 0.0, "max_tokens": 8}), store=store, clock=clock
    )

    second = resolve_epoch(
        _pin(sampling_params={"temperature": 0.0, "max_tokens": 16}), store=store, clock=clock
    )

    assert second.epoch_id != first.epoch_id


def test_a_changed_prompt_hash_starts_a_new_epoch_automatically() -> None:
    """This is the 'nobody remembers to bump a version number' guarantee in
    practice: a code edit to a judge prompt only ever shows up here as a
    different `prompt_hash`, and that alone is enough."""
    store = FakeEpochStore()
    clock = FakeClock()
    first = resolve_epoch(_pin(prompt_hash="a" * 64), store=store, clock=clock)

    second = resolve_epoch(_pin(prompt_hash="b" * 64), store=store, clock=clock)

    assert second.epoch_id != first.epoch_id


def test_resolve_epoch_never_mutates_or_drops_a_prior_epoch() -> None:
    store = FakeEpochStore()
    clock = FakeClock()
    first = resolve_epoch(_pin(judge_model_id="gemini-3.1-pro"), store=store, clock=clock)
    resolve_epoch(_pin(judge_model_id="gemini-4.0-pro"), store=store, clock=clock)

    assert store.history[0] == first
    assert len(store.history) == 2


def test_reverting_to_an_old_pin_reclaims_that_pins_epoch_rather_than_minting() -> None:
    """A pin that has been seen before keeps its original epoch id: the epoch
    IS the pin, so artifacts stamped before and after the revert really were
    produced under the same ruler and really are comparable. Minting a fresh
    id would make `assert_same_epoch` refuse two identically-judged updates."""
    store = FakeEpochStore()
    clock = FakeClock()
    original = resolve_epoch(_pin(judge_model_id="gemini-3.1-pro"), store=store, clock=clock)
    resolve_epoch(_pin(judge_model_id="gemini-4.0-pro"), store=store, clock=clock)

    reverted = resolve_epoch(_pin(judge_model_id="gemini-3.1-pro"), store=store, clock=clock)

    assert reverted.epoch_id == original.epoch_id
    assert reverted.started_at == original.started_at  # the ORIGINAL row, not a rewritten one
    assert len(store.history) == 2


def test_two_pinned_workers_sharing_one_store_settle_on_stable_epoch_ids() -> None:
    """D-008 pins the judge, the shadow validator and the distiller to this
    one table, each with its own prompt_hash. They alternate through
    `current_epoch()`, so an insert-unconditionally store would mint an epoch
    on EVERY call -- and two judge runs a minute apart, under a completely
    unchanged judge, would then be cross-epoch and refuse comparison."""
    store = FakeEpochStore()
    clock = FakeClock()
    judge_pin = _pin(prompt_hash="a" * 64)
    distiller_pin = _pin(prompt_hash="d" * 64)

    ids: list[tuple[int, int]] = []
    for _ in range(5):
        judge = resolve_epoch(judge_pin, store=store, clock=clock)
        distiller = resolve_epoch(distiller_pin, store=store, clock=clock)
        clock.advance(minutes=1)
        ids.append((judge.epoch_id, distiller.epoch_id))

    assert len(set(ids)) == 1  # every round resolved the same two ids
    assert len(store.history) == 2
    assert ids[0][0] != ids[0][1]


def test_resolve_epoch_refuses_a_store_that_returns_a_different_pin() -> None:
    """`assert_same_epoch` compares ids, so an id that is consistently WRONG
    passes every downstream check while meaning nothing. The one place that
    can catch it is the moment the store hands the epoch back."""

    class LyingStore:
        def current_epoch(self) -> ScoringEpoch | None:
            return None

        def start_epoch(self, pin: JudgePin, started_at: datetime) -> ScoringEpoch:
            return ScoringEpoch(
                epoch_id=99,
                judge_model_id="some-other-model",
                judge_model_version=pin.judge_model_version,
                sampling_params=pin.sampling_params,
                prompt_hash=pin.prompt_hash,
                started_at=started_at,
            )

    with pytest.raises(EpochStoreViolation):
        resolve_epoch(_pin(), store=LyingStore(), clock=FakeClock())


# --------------------------------------------------------------------------- #
# The pin is genuinely frozen: `sampling_params` cannot be mutated out from
# under an epoch that has already stamped artifacts.
# --------------------------------------------------------------------------- #


def test_mutating_the_dict_passed_as_sampling_params_cannot_change_a_pin() -> None:
    params: dict[str, object] = {"temperature": 0.0, "max_tokens": 8}
    pin = JudgePin(
        judge_model_id="gemini-3.1-pro",
        judge_model_version="001",
        sampling_params=params,
        prompt_hash="a" * 64,
    )

    params["temperature"] = 0.9  # the caller still holds the original dict

    assert pin.sampling_params["temperature"] == 0.0
    assert pin == _pin()


def test_a_pins_sampling_params_are_not_writable_through_the_pin_either() -> None:
    pin = _pin()
    with pytest.raises(TypeError):
        pin.sampling_params["temperature"] = 0.9  # type: ignore[index]


def test_a_stored_epochs_sampling_params_are_frozen_the_same_way() -> None:
    params: dict[str, object] = {"temperature": 0.0, "max_tokens": 8}
    epoch = ScoringEpoch(
        epoch_id=1,
        judge_model_id="gemini-3.1-pro",
        judge_model_version="001",
        sampling_params=params,
        prompt_hash="a" * 64,
        started_at=FakeClock().now(),
    )

    params["max_tokens"] = 4096

    assert epoch.pin() == _pin()


def test_a_frozen_pin_still_compares_equal_to_one_built_from_a_plain_dict() -> None:
    """The freeze must not change equality semantics -- `resolve_epoch`'s only
    branch is a pin comparison, and a store reading `sampling_params` back out
    of jsonb hands over a plain dict."""
    stored = ScoringEpoch(
        epoch_id=1,
        judge_model_id="gemini-3.1-pro",
        judge_model_version="001",
        sampling_params={"temperature": 0.0, "max_tokens": 8},
        prompt_hash="a" * 64,
        started_at=FakeClock().now(),
    )
    assert stored.pin() == _pin()


# --------------------------------------------------------------------------- #
# assert_same_epoch: the cross-epoch-comparison refusal.
# --------------------------------------------------------------------------- #


def test_assert_same_epoch_does_not_raise_for_matching_epoch_ids() -> None:
    store = FakeEpochStore()
    clock = FakeClock()
    epoch = resolve_epoch(_pin(), store=store, clock=clock)

    assert_same_epoch(epoch, epoch)  # no raise


def test_assert_same_epoch_raises_cross_epoch_comparison_for_differing_ids() -> None:
    store = FakeEpochStore()
    clock = FakeClock()
    first = resolve_epoch(_pin(judge_model_id="gemini-3.1-pro"), store=store, clock=clock)
    second = resolve_epoch(_pin(judge_model_id="gemini-4.0-pro"), store=store, clock=clock)

    with pytest.raises(CrossEpochComparison):
        assert_same_epoch(first, second)


def test_assert_same_epoch_refuses_in_BOTH_directions() -> None:
    """Difference, not ordering. A one-sided comparison (`a < b`) passes every
    test that only ever puts the older epoch first, while silently accepting
    the case that actually happens in `workers.scorer.run_scorer_batch`: a
    judge answering under a NEWER epoch than the one the scorer resolved for
    the tick, because something re-pinned the judge mid-batch. Both orders
    have to refuse or the guard has a direction-shaped hole."""
    store = FakeEpochStore()
    clock = FakeClock()
    older = resolve_epoch(_pin(judge_model_id="gemini-3.1-pro"), store=store, clock=clock)
    newer = resolve_epoch(_pin(judge_model_id="gemini-4.0-pro"), store=store, clock=clock)
    assert older.epoch_id < newer.epoch_id

    with pytest.raises(CrossEpochComparison):
        assert_same_epoch(older, newer)
    with pytest.raises(CrossEpochComparison):
        assert_same_epoch(newer, older)


# --------------------------------------------------------------------------- #
# `scoring_epoch.started_at` is `timestamptz NOT NULL` in the migration.
# --------------------------------------------------------------------------- #


def test_a_timezone_naive_started_at_is_refused() -> None:
    """This row dates every stamped artifact for an audit ('which judge was in
    force when this Q moved'). A naive value is D-043's hazard verbatim:
    Postgres reinterprets it in the session TimeZone and two epochs minted
    hours apart can end up ordered wrongly against the updates they stamped."""
    with pytest.raises(EpochStoreViolation):
        ScoringEpoch(
            epoch_id=1,
            judge_model_id="gemini-3.1-pro",
            judge_model_version="001",
            sampling_params={"temperature": 0.0},
            prompt_hash="a" * 64,
            started_at=datetime(2026, 7, 26, 12, 0),
        )


def test_an_aware_started_at_in_any_offset_is_accepted() -> None:
    epoch = ScoringEpoch(
        epoch_id=1,
        judge_model_id="gemini-3.1-pro",
        judge_model_version="001",
        sampling_params={"temperature": 0.0},
        prompt_hash="a" * 64,
        started_at=datetime(2026, 7, 26, 12, 0, tzinfo=timezone(timedelta(hours=5, minutes=30))),
    )
    assert epoch.started_at.utcoffset() == timedelta(hours=5, minutes=30)


def test_assert_same_epoch_works_structurally_on_any_epoch_stamped_value() -> None:
    """`EpochStamped` is a structural Protocol -- any object with an
    `epoch_id` property satisfies it, not only `ScoringEpoch`. This is what
    lets `workers.contribution_judge.ContributionVerdict` be checked against
    a `ScoringEpoch` with no inheritance relationship between the two."""

    class _Stamped:
        def __init__(self, epoch_id: int) -> None:
            self._epoch_id = epoch_id

        @property
        def epoch_id(self) -> int:
            return self._epoch_id

    with pytest.raises(CrossEpochComparison):
        assert_same_epoch(_Stamped(1), _Stamped(2))
    assert_same_epoch(_Stamped(5), _Stamped(5))  # no raise
