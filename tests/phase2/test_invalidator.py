"""`workers.invalidator` — provenance-selector resolution, cache_flush, and the raw
payload parser (PLAN.md §7 Phase 2).

Fully offline: `_FakeRepo` holds `LifecycleMemoryRow`s in memory and records every
`persist()` call, so these tests assert directly that (a) only the memories whose
provenance selector matched go stale, (b) NOTHING else does — over-invalidation is as bad
as under-invalidation — and (c) every status change this module writes is exactly what
`domain.state_machine.apply()` returned for the same evidence, never an invented value.

`EffectiveConfig` is built from the real Phase 0 section models (same pattern as
`tests/phase2/test_prefix_builder.py`), so a field rename in `domain/config.py` breaks this
test rather than staying silently green.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest

from tracebed.adapters.invalidation import (
    CACHE_FLUSH_EVENT_TYPE,
    PollingInvalidationSource,
    WebhookInvalidationSource,
)
from tracebed.adapters.ports import InvalidationPort
from tracebed.domain.clock import FakeClock
from tracebed.domain.config import (
    AbstentionConfig,
    BudgetConfig,
    CacheConfig,
    DerivedConfig,
    EffectiveConfig,
    KillswitchConfig,
    LifecycleConfig,
    PromotionConfig,
    ProposalConfig,
    QueueConfig,
    RetirementConfig,
    RetrievalConfig,
    ScoreConfig,
    ScoringConfig,
    SessionConfig,
    SpendConfig,
    TierAConfig,
)
from tracebed.domain.enums import MemType, ProvenanceClass, TrustTier
from tracebed.domain.errors import TracebedError
from tracebed.domain.ids import MemoryId, ProjectId, RunId
from tracebed.domain.memory import Provenance
from tracebed.domain.state_machine import Status, TransitionEvidence, TransitionLimits, apply
from tracebed.workers.invalidator import (
    InvalidationEvent,
    InvalidationSelector,
    Invalidator,
    LifecycleMemoryRow,
    LifecycleTransitionWrite,
    parse_invalidation_payload,
    selector_matches,
)

pytestmark = pytest.mark.phase2

PROJECT = ProjectId(uuid4())
EPOCH = datetime(2026, 1, 1, tzinfo=UTC)


def _effective_config(**overrides: object) -> EffectiveConfig:
    sections: dict[str, object] = {
        "retrieval": RetrievalConfig(),
        "abstention": AbstentionConfig(),
        "score": ScoreConfig(),
        "budget": BudgetConfig(),
        "scoring": ScoringConfig(),
        "promotion": PromotionConfig(),
        "retirement": RetirementConfig(),
        "lifecycle": LifecycleConfig(),
        "derived": DerivedConfig(),
        "proposals": ProposalConfig(),
        "tier_a": TierAConfig(),
        "killswitch": KillswitchConfig(),
        "spend": SpendConfig(),
        "cache": CacheConfig(),
        "session": SessionConfig(),
        "queue": QueueConfig(),
    }
    sections.update(overrides)
    return EffectiveConfig(**sections)


def _mid(tag: int) -> MemoryId:
    return MemoryId(UUID(int=tag))


def _row(
    tag: int,
    *,
    status: Status,
    tool_refs: tuple[str, ...] = (),
    trace_ids: tuple[RunId, ...] = (),
    input_sig_hashes: tuple[bytes, ...] = (),
    status_changed_at: datetime = EPOCH,
    strike_count: int = 0,
) -> LifecycleMemoryRow:
    return LifecycleMemoryRow(
        id=_mid(tag),
        project_id=PROJECT,
        status=status,
        trust_tier=TrustTier.B,
        mem_type=MemType.LESSON,
        provenance=Provenance(
            cls=ProvenanceClass.DISTILLER,
            trace_ids=trace_ids or (RunId(uuid4()),),
            tool_refs=tool_refs,
            input_sig_hashes=input_sig_hashes,
        ),
        status_changed_at=status_changed_at,
        strike_count=strike_count,
        last_retrieved_at=None,
        created_at=EPOCH,
    )


class _FakeRepo:
    """Also carries an unrelated, never-consulted `trace_row_count` — this module's
    `select_by_provenance` must scale with matching memory rows only, never with it."""

    def __init__(self, rows: Sequence[LifecycleMemoryRow], *, trace_row_count: int = 0) -> None:
        self._rows: dict[MemoryId, LifecycleMemoryRow] = {r.id: r for r in rows}
        self.trace_row_count = trace_row_count
        self.persisted: list[LifecycleTransitionWrite] = []
        self.provenance_calls = 0

    def select_by_provenance(
        self,
        project_id: ProjectId,
        *,
        tool_refs: Sequence[str] = (),
        trace_ids: Sequence[RunId] = (),
        input_sig_hashes: Sequence[bytes] = (),
    ) -> Sequence[LifecycleMemoryRow]:
        self.provenance_calls += 1
        tool_set = set(tool_refs)
        trace_set = set(trace_ids)
        hash_set = set(input_sig_hashes)
        out = []
        for row in self._rows.values():
            if (
                tool_set & set(row.provenance.tool_refs)
                or trace_set & set(row.provenance.trace_ids)
                or hash_set & set(row.provenance.input_sig_hashes)
            ):
                out.append(row)
        return out

    def select_by_status(
        self, project_id: ProjectId, statuses: Sequence[Status], *, limit: int = 10_000
    ) -> Sequence[LifecycleMemoryRow]:
        return [r for r in self._rows.values() if r.status in statuses][:limit]

    def select_due_for_revalidation(
        self, project_id: ProjectId, *, older_than: datetime, limit: int = 10_000
    ) -> Sequence[LifecycleMemoryRow]:
        return []

    def persist(self, project_id: ProjectId, write: LifecycleTransitionWrite) -> None:
        self.persisted.append(write)
        old = self._rows[write.memory_id]
        self._rows[write.memory_id] = LifecycleMemoryRow(
            id=old.id,
            project_id=old.project_id,
            status=write.to_status,
            trust_tier=old.trust_tier,
            mem_type=old.mem_type,
            provenance=old.provenance,
            status_changed_at=write.now if write.from_status != write.to_status else old.status_changed_at,
            strike_count=write.strike_count if write.strike_count is not None else old.strike_count,
            last_retrieved_at=old.last_retrieved_at,
            created_at=old.created_at,
        )


def test_flipping_a_tool_definition_marks_only_its_dependents_stale() -> None:
    validated_dependent = _row(1, status=Status.VALIDATED, tool_refs=("tool-x",))
    other_tool = _row(2, status=Status.VALIDATED, tool_refs=("tool-y",))
    quarantined_dependent = _row(3, status=Status.QUARANTINED, tool_refs=("tool-x",))
    unrelated = _row(4, status=Status.VALIDATED, tool_refs=("tool-z",))

    repo = _FakeRepo([validated_dependent, other_tool, quarantined_dependent, unrelated])
    clock = FakeClock(EPOCH)
    invalidator = Invalidator(repo, clock)
    cfg = _effective_config()

    event = InvalidationEvent(
        event_type="tool_changed", selector=InvalidationSelector(tool_refs=("tool-x",))
    )
    result = invalidator.process_event(PROJECT, event, cfg)

    assert result.transitioned_to_stale == (validated_dependent.id,)
    assert set(result.considered) == {validated_dependent.id, quarantined_dependent.id}
    assert other_tool.id not in result.considered
    assert unrelated.id not in result.considered

    # Only one row was actually written, and its target status is exactly what apply()
    # itself would authorise for this evidence -- not a direct status UPDATE.
    assert len(repo.persisted) == 1
    write = repo.persisted[0]
    limits = TransitionLimits.from_config(cfg)
    evidence = TransitionEvidence(
        now=clock.now(),
        provenance_class=ProvenanceClass.DISTILLER,
        trust_tier=TrustTier.B,
        mem_type=MemType.LESSON,
        status_changed_at=EPOCH,
        invalidation_event=True,
    )
    assert write.to_status == apply(Status.VALIDATED, Status.STALE, evidence, limits)
    assert write.strike_count == 1

    # The quarantined row, though a provenance match, was never persisted.
    assert quarantined_dependent.id not in {w.memory_id for w in repo.persisted}


def test_empty_selector_is_a_no_op() -> None:
    repo = _FakeRepo([_row(1, status=Status.VALIDATED, tool_refs=("tool-x",))])
    invalidator = Invalidator(repo, FakeClock(EPOCH))
    event = InvalidationEvent(event_type="tool_changed", selector=InvalidationSelector())

    result = invalidator.process_event(PROJECT, event, _effective_config())

    assert result.considered == ()
    assert result.transitioned_to_stale == ()
    assert repo.provenance_calls == 0


def test_cache_flush_flushes_and_touches_no_memory() -> None:
    repo = _FakeRepo([_row(1, status=Status.VALIDATED, tool_refs=("tool-x",))])
    flushed: list[ProjectId] = []

    def _flush(project_id: ProjectId) -> int:
        flushed.append(project_id)
        return 42

    invalidator = Invalidator(repo, FakeClock(EPOCH), flush_cache=_flush)
    event = InvalidationEvent(
        event_type=CACHE_FLUSH_EVENT_TYPE, selector=InvalidationSelector(tool_refs=("tool-x",))
    )

    result = invalidator.process_event(PROJECT, event, _effective_config())

    assert result.cache_flushed is True
    assert result.flushed_keys == 42
    assert flushed == [PROJECT]
    assert result.considered == ()
    assert result.transitioned_to_stale == ()
    assert repo.provenance_calls == 0
    assert repo.persisted == []


def test_cache_flush_with_no_flush_callable_reports_that_nothing_was_flushed() -> None:
    """A deployment wired without a flusher must not report a flush that never happened —
    the tool cache would keep serving exactly the results the event exists to discard."""
    invalidator = Invalidator(_FakeRepo([]), FakeClock(EPOCH))
    event = InvalidationEvent(event_type=CACHE_FLUSH_EVENT_TYPE, selector=InvalidationSelector())
    result = invalidator.process_event(PROJECT, event, _effective_config())
    assert result.cache_flushed is False
    assert result.flushed_keys == 0


# --------------------------------------------------------------------------- #
# Over-reach: the store resolves the selector, this module re-asserts the result.
# --------------------------------------------------------------------------- #


class _OverReachingRepo(_FakeRepo):
    """A `select_by_provenance` that returns the whole vault regardless of the selector —
    a hand-written variant, a `LIKE` over content, or a cache in front of the real query."""

    def select_by_provenance(
        self,
        project_id: ProjectId,
        *,
        tool_refs: Sequence[str] = (),
        trace_ids: Sequence[RunId] = (),
        input_sig_hashes: Sequence[bytes] = (),
    ) -> Sequence[LifecycleMemoryRow]:
        self.provenance_calls += 1
        return list(self._rows.values())


def test_a_store_that_over_matches_is_refused_before_a_single_write() -> None:
    dependent = _row(1, status=Status.VALIDATED, tool_refs=("tool-x",))
    mentions_only = _row(2, status=Status.VALIDATED, tool_refs=("tool-y",))
    repo = _OverReachingRepo([dependent, mentions_only])
    invalidator = Invalidator(repo, FakeClock(EPOCH))
    event = InvalidationEvent(
        event_type="tool_changed", selector=InvalidationSelector(tool_refs=("tool-x",))
    )

    with pytest.raises(TracebedError, match="shares no tool_ref"):
        invalidator.process_event(PROJECT, event, _effective_config())

    # Nothing at all was written -- not even the row that genuinely did match. A partially
    # invalidated vault with an exception in the caller's hand is worse than no invalidation.
    assert repo.persisted == []


def test_a_store_returning_another_projects_row_is_refused() -> None:
    foreign = LifecycleMemoryRow(
        id=_mid(1),
        project_id=ProjectId(uuid4()),  # not PROJECT
        status=Status.VALIDATED,
        trust_tier=TrustTier.B,
        mem_type=MemType.LESSON,
        provenance=Provenance(
            cls=ProvenanceClass.DISTILLER,
            trace_ids=(RunId(uuid4()),),
            tool_refs=("tool-x",),
        ),
        status_changed_at=EPOCH,
        strike_count=0,
        last_retrieved_at=None,
        created_at=EPOCH,
    )
    repo = _FakeRepo([foreign])
    invalidator = Invalidator(repo, FakeClock(EPOCH))
    event = InvalidationEvent(
        event_type="tool_changed", selector=InvalidationSelector(tool_refs=("tool-x",))
    )

    with pytest.raises(TracebedError, match="invariant 4"):
        invalidator.process_event(PROJECT, event, _effective_config())
    assert repo.persisted == []


def test_selector_matches_reads_provenance_only() -> None:
    """"Depends on" is a provenance entry, never a textual mention: a memory produced by a
    run that used `tool-y` is not a dependent of `tool-x` no matter what it says."""
    dependent = Provenance(cls=ProvenanceClass.DISTILLER, tool_refs=("tool-x",))
    unrelated = Provenance(cls=ProvenanceClass.DISTILLER, tool_refs=("tool-y",))
    selector = InvalidationSelector(tool_refs=("tool-x",))
    assert selector_matches(dependent, selector) is True
    assert selector_matches(unrelated, selector) is False
    # An empty selector field must not match an empty provenance field (() & () is empty).
    assert selector_matches(unrelated, InvalidationSelector()) is False


def test_parse_invalidation_payload_roundtrips_every_selector_field() -> None:
    run_id = RunId(uuid4())
    raw = {
        "event_type": "tool_changed",
        "selector": {
            "tool_refs": ["tool-x", "tool-y"],
            "trace_ids": [str(run_id)],
            "input_sig_hashes": [b"\x01\x02".hex()],
        },
        "fired_at": "2026-01-01T00:00:00+00:00",
    }
    event = parse_invalidation_payload(raw)
    assert event.event_type == "tool_changed"
    assert event.selector.tool_refs == ("tool-x", "tool-y")
    assert event.selector.trace_ids == (run_id,)
    assert event.selector.input_sig_hashes == (b"\x01\x02",)
    assert event.fired_at == datetime(2026, 1, 1, tzinfo=UTC)


@pytest.mark.parametrize(
    "raw",
    [
        {},
        {"event_type": ""},
        {"event_type": "x", "selector": "not-a-mapping"},
        {"event_type": "x", "selector": {"tool_refs": "not-a-list"}},
        # bytes is a Sequence too: iterating it yields ints, so this would silently become
        # the two selectors ("97", "98") rather than being refused.
        {"event_type": "x", "selector": {"tool_refs": b"ab"}},
        # A naive `fired_at` is refused at the wire boundary (D-043): the column is
        # timestamptz and Postgres would reinterpret it in the session TimeZone.
        {"event_type": "x", "selector": {}, "fired_at": "2026-01-01T00:00:00"},
    ],
)
def test_parse_invalidation_payload_rejects_malformed_input(raw: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        parse_invalidation_payload(raw)


def test_lifecycle_memory_row_refuses_a_naive_timestamp() -> None:
    """`now - last_retrieved_at` is either a TypeError or a silent whole-offset skew of
    every idle window; `state_machine` refuses naive values for the two fields it sees and
    this is where the other two are first read."""
    with pytest.raises(ValueError, match="timezone-aware"):
        LifecycleMemoryRow(
            id=_mid(1),
            project_id=PROJECT,
            status=Status.VALIDATED,
            trust_tier=TrustTier.B,
            mem_type=MemType.LESSON,
            provenance=Provenance(cls=ProvenanceClass.DISTILLER, trace_ids=(RunId(uuid4()),)),
            status_changed_at=None,
            strike_count=0,
            last_retrieved_at=datetime(2026, 1, 1),  # a naive value is the point of the test
            created_at=EPOCH,
        )


def test_process_raw_batch_drains_multiple_payloads() -> None:
    dependent = _row(1, status=Status.VALIDATED, tool_refs=("tool-x",))
    repo = _FakeRepo([dependent])
    invalidator = Invalidator(repo, FakeClock(EPOCH), flush_cache=lambda _p: 7)
    raw_events = [
        {"event_type": "tool_changed", "selector": {"tool_refs": ["tool-x"]}},
        {"event_type": CACHE_FLUSH_EVENT_TYPE, "selector": {}},
    ]

    results = invalidator.process_raw_batch(PROJECT, raw_events, _effective_config())

    assert len(results) == 2
    assert results[0].transitioned_to_stale == (dependent.id,)
    assert results[1].cache_flushed is True
    assert results[1].flushed_keys == 7


def test_process_raw_batch_refuses_the_whole_batch_before_writing_anything() -> None:
    """A malformed payload anywhere in a drained batch must not leave the memories named by
    the payloads BEFORE it already transitioned, with only an exception to say so."""
    dependent = _row(1, status=Status.VALIDATED, tool_refs=("tool-x",))
    repo = _FakeRepo([dependent])
    invalidator = Invalidator(repo, FakeClock(EPOCH))
    raw_events: list[dict[str, object]] = [
        {"event_type": "tool_changed", "selector": {"tool_refs": ["tool-x"]}},
        {"selector": {}},  # no event_type -> ValueError
    ]

    with pytest.raises(ValueError):
        invalidator.process_raw_batch(PROJECT, raw_events, _effective_config())

    assert repo.persisted == []
    assert repo.provenance_calls == 0


def test_webhook_source_satisfies_invalidation_port_and_drains_once() -> None:
    source = WebhookInvalidationSource()
    assert isinstance(source, InvalidationPort)
    source.receive("tool_changed", {"tool_refs": ["tool-x"]})
    source.receive("tool_changed", {"tool_refs": ["tool-y"]})

    drained = source.poll()
    assert len(drained) == 2
    assert list(source.poll()) == []  # a second drain sees nothing new


class _FakeSource:
    def __init__(self) -> None:
        self.items: list[dict[str, object]] = []

    def fetch(self) -> Sequence[dict[str, object]]:
        return list(self.items)


def _poller(
    source: _FakeSource, *, initial_snapshot: dict[str, str] | None = None
) -> PollingInvalidationSource:
    return PollingInvalidationSource(
        source,
        item_key=lambda item: str(item["id"]),
        build_selector=lambda item: {"tool_refs": [str(item["id"])]},
        event_type="tool_changed",
        build_removed_selector=lambda key: {"tool_refs": [key]},
        initial_snapshot=initial_snapshot,
    )


def test_polling_source_diffs_added_changed_and_removed_items() -> None:
    source = _FakeSource()
    poller = _poller(source)
    assert isinstance(poller, InvalidationPort)

    # First tick establishes the baseline and reports nothing (see below for why).
    source.items = [{"id": "a", "v": 1}, {"id": "b", "v": 1}]
    assert list(poller.poll()) == []

    # Second tick: nothing changed -> nothing reported.
    assert list(poller.poll()) == []

    # Third tick: "a" changed, "b" removed, "c" added.
    source.items = [{"id": "a", "v": 2}, {"id": "c", "v": 1}]
    third = poller.poll()
    assert {e["event_type"] for e in third} == {"tool_changed"}
    selectors: list[object] = [e["selector"] for e in third]
    assert {"tool_refs": ["a"]} in selectors
    assert {"tool_refs": ["b"]} in selectors
    assert {"tool_refs": ["c"]} in selectors
    assert len(third) == 3


def test_first_poll_primes_instead_of_reporting_the_whole_source_as_changed() -> None:
    """Without priming, every process restart reports the ENTIRE source as changed, and each
    of those events stales every validated memory naming the item — a redeploy would demote
    the project's whole vault out of RETRIEVABLE_STATUSES."""
    source = _FakeSource()
    source.items = [{"id": str(i), "v": 1} for i in range(50)]

    poller = _poller(source)
    assert list(poller.poll()) == []
    assert dict(poller.snapshot()).keys() == {str(i) for i in range(50)}

    # A restart that hands the persisted snapshot back diffs against real prior state, so
    # the blind spot priming costs is recoverable by a host that wants to pay for it.
    source.items = [{"id": "0", "v": 2}] + [{"id": str(i), "v": 1} for i in range(1, 50)]
    restarted = _poller(source, initial_snapshot=dict(poller.snapshot()))
    events = restarted.poll()
    assert [e["selector"] for e in events] == [{"tool_refs": ["0"]}]


def test_polling_source_ignores_key_order_within_an_item() -> None:
    """The content hash is canonical JSON, so a source that serialises its items in a
    different key order on the next tick must not read as "everything changed"."""
    source = _FakeSource()
    source.items = [{"id": "a", "x": 1, "y": 2}]
    poller = _poller(source)
    poller.poll()  # prime

    source.items = [{"y": 2, "id": "a", "x": 1}]
    assert list(poller.poll()) == []


def test_polling_source_refuses_duplicate_item_keys() -> None:
    """Two items with one identity means the loser's changes can never be reported again."""
    source = _FakeSource()
    source.items = [{"id": "a", "v": 1}, {"id": "a", "v": 2}]
    poller = _poller(source)
    with pytest.raises(ValueError, match="duplicate key"):
        poller.poll()
