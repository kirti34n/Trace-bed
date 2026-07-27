"""`workers.tier_a_lane` -- the coordinator that makes the lane's two
lane-level guarantees true rather than merely available.

Neither guarantee could be tested inside a single extractor, which is why
neither was: `tier_a.candidate_cap_per_run` is per RUN and four extractors
each held their own budget, and idempotency is a property of "the same batch,
run twice", which no single `extract()` call can exhibit.

Fully offline: `FakeClock`, a fake `MemoryWriterPort`, and a fake
`KnownContentPort` standing in for the store query that does not exist yet.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from tracebed.core.scans.tier_a_template import ErrorClassEnum
from tracebed.domain.canonical import content_hash
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
from tracebed.domain.events import ErrorEvent, RunStart, TraceEvent
from tracebed.domain.ids import (
    AgentTypeId,
    MemoryId,
    PrincipalId,
    ProjectId,
    RunId,
    mint_memory_id,
)
from tracebed.domain.memory import NewMemoryItem
from tracebed.domain.scan import ScanVerdict
from tracebed.domain.scope import ProjectScope
from tracebed.workers.extractors import (
    ExtractionOutcome,
    SchemaFailureExtractor,
    ToolFailureExtractor,
)
from tracebed.workers.tier_a_lane import TierALane, default_extractors

pytestmark = pytest.mark.phase2

_BASE_TS = datetime(2026, 7, 25, tzinfo=UTC)
_MANIFEST = ["tool_a", "tool_b", "tool_c"]


def _scope() -> ProjectScope:
    return ProjectScope(
        project_id=ProjectId(uuid4()),
        agent_type_id=AgentTypeId(uuid4()),
        principal_id=PrincipalId(uuid4()),
    )


def _cfg(*, candidate_cap_per_run: int = 1) -> EffectiveConfig:
    return EffectiveConfig(
        retrieval=RetrievalConfig(),
        abstention=AbstentionConfig(),
        score=ScoreConfig(),
        budget=BudgetConfig(),
        scoring=ScoringConfig(),
        promotion=PromotionConfig(),
        retirement=RetirementConfig(),
        lifecycle=LifecycleConfig(),
        derived=DerivedConfig(),
        proposals=ProposalConfig(),
        tier_a=TierAConfig(candidate_cap_per_run=candidate_cap_per_run),
        killswitch=KillswitchConfig(),
        spend=SpendConfig(),
        cache=CacheConfig(),
        session=SessionConfig(),
        queue=QueueConfig(),
        killswitch_overlay={},
    )


class _FakeWriter:
    def __init__(self) -> None:
        self.inserted: list[NewMemoryItem] = []
        self.projects: list[ProjectId] = []

    def insert_memory_item(
        self, project_id: ProjectId, item: NewMemoryItem, scan_verdict: ScanVerdict
    ) -> MemoryId:
        self.inserted.append(item)
        self.projects.append(project_id)
        return mint_memory_id()


class _FakeVault:
    """`KnownContentPort` over an in-memory (project_id, content_hash) index.

    `remember` is how a test says "a previous batch already wrote this",
    which is the only way to exercise the cross-batch half of the dedupe
    without a store.
    """

    def __init__(self) -> None:
        self.rows: dict[tuple[ProjectId, str], MemoryId] = {}
        self.queries: list[tuple[ProjectId, str]] = []

    def remember(self, project_id: ProjectId, content: str) -> MemoryId:
        memory_id = mint_memory_id()
        self.rows[(project_id, content_hash(content))] = memory_id
        return memory_id

    def find_memory_by_content_hash(
        self, project_id: ProjectId, content_hash_hex: str
    ) -> MemoryId | None:
        self.queries.append((project_id, content_hash_hex))
        return self.rows.get((project_id, content_hash_hex))


def _start(ts: datetime = _BASE_TS) -> RunStart:
    return RunStart(
        type="run_start", ts=ts, payload={"query_text": "q", "tool_manifest": list(_MANIFEST)}
    )


def _error(
    ts: datetime,
    tool_id: str,
    error_class: ErrorClassEnum,
    *,
    schema_fields: list[str] | None = None,
) -> ErrorEvent:
    payload: dict[str, object] = {
        "tool_id": tool_id,
        "tool_version": "v1",
        "error_class": error_class.value,
        "duration_ms": 50,
        "error_body": "",
    }
    if schema_fields is not None:
        payload["schema_fields"] = schema_fields
    return ErrorEvent(type="error", ts=ts, payload=payload)


def _one_run_two_extractors_would_both_fire() -> Mapping[RunId, Sequence[TraceEvent]]:
    """One run carrying BOTH a repeated plain tool error and a repeated schema
    violation, so `ToolFailureExtractor` and `SchemaFailureExtractor` each have
    a genuine pattern to emit -- which is what makes the shared cap observable.
    """
    run = RunId(uuid4())
    return {
        run: [
            _start(),
            _error(_BASE_TS, "tool_a", ErrorClassEnum.TIMEOUT),
            _error(_BASE_TS + timedelta(seconds=1), "tool_a", ErrorClassEnum.TIMEOUT),
            _error(
                _BASE_TS + timedelta(seconds=2),
                "tool_b",
                ErrorClassEnum.SCHEMA_VALIDATION,
                schema_fields=["amount", "currency"],
            ),
            _error(
                _BASE_TS + timedelta(seconds=3),
                "tool_b",
                ErrorClassEnum.SCHEMA_VALIDATION,
                schema_fields=["amount", "currency"],
            ),
        ]
    }


def _lane(writer: _FakeWriter, **kwargs: object) -> TierALane:
    return TierALane(
        cfg=kwargs.pop("cfg", None) or _cfg(),  # type: ignore[arg-type]
        clock=FakeClock(_BASE_TS),
        writer=writer,
        **kwargs,  # type: ignore[arg-type]
    )


# --------------------------------------------------------------------------- #
# The shared cap -- the defect that made this module necessary
# --------------------------------------------------------------------------- #


def test_the_four_extractors_share_one_per_run_candidate_budget() -> None:
    """`tier_a.candidate_cap_per_run` is 1. Two extractors each have a real
    pattern for the SAME run; exactly one note may be written."""
    writer = _FakeWriter()
    result = _lane(writer).run_batch(_scope(), _one_run_two_extractors_would_both_fire())

    assert len(result.inserted) == 1
    assert len(writer.inserted) == 1


def test_without_the_lane_the_same_traces_write_one_note_per_extractor() -> None:
    """Guard the guard. If the extractors did not actually contend for one
    budget, the assertion above would pass for the wrong reason -- so run the
    same traces WITHOUT a shared tracker and prove the count differs. This is
    the defect as it existed: a cap of 1 behaving as a cap of 4.
    """
    scope = _scope()
    traces = _one_run_two_extractors_would_both_fire()
    writer = _FakeWriter()

    for extractor in (ToolFailureExtractor(), SchemaFailureExtractor()):
        extractor.extract(scope, traces, cfg=_cfg(), clock=FakeClock(_BASE_TS), writer=writer)

    assert len(writer.inserted) == 2


def test_a_raised_cap_lets_both_extractors_through() -> None:
    """The cap must come from config, not from the lane hardcoding "one"."""
    writer = _FakeWriter()
    lane = TierALane(cfg=_cfg(candidate_cap_per_run=2), clock=FakeClock(_BASE_TS), writer=writer)

    result = lane.run_batch(_scope(), _one_run_two_extractors_would_both_fire())

    assert len(result.inserted) == 2


def test_the_cap_is_per_run_not_per_batch() -> None:
    """Three runs, each failing a DIFFERENT tool, so each forms its own group
    charged to its own run. One shared tracker must not turn a per-run cap
    into a per-batch one -- all three notes are written.

    Distinct tools deliberately: the extractors group across runs by
    (tool_id, tool_version, error_class), so three runs failing the SAME tool
    are one group charged to one primary run, which would test grouping
    rather than the cap's scope.
    """
    writer = _FakeWriter()
    traces: dict[RunId, Sequence[TraceEvent]] = {}
    for tool in _MANIFEST:
        traces[RunId(uuid4())] = [
            _start(),
            _error(_BASE_TS, tool, ErrorClassEnum.TIMEOUT),
            _error(_BASE_TS + timedelta(seconds=1), tool, ErrorClassEnum.TIMEOUT),
        ]

    result = _lane(writer).run_batch(_scope(), traces)

    assert len(result.inserted) == len(_MANIFEST)
    assert len({o.primary_run_id for o in result.inserted}) == len(_MANIFEST)


def test_the_extractor_order_is_fixed_so_the_contended_slot_is_reproducible() -> None:
    """The cap is first-come. If `default_extractors()` reordered between
    processes, the same batch would charge a DIFFERENT note against the same
    run's one slot, and the soak's vault-growth curve would stop being
    reproducible."""
    assert [type(e).__name__ for e in default_extractors()] == [
        "ToolFailureExtractor",
        "SchemaFailureExtractor",
        "LatencyOutlierExtractor",
        "SequencePatternExtractor",
    ]

    scope = _scope()
    traces = _one_run_two_extractors_would_both_fire()
    contents = set()
    for _ in range(5):
        writer = _FakeWriter()
        result = _lane(writer).run_batch(scope, traces)
        contents.add(result.inserted[0].content)
    assert len(contents) == 1


# --------------------------------------------------------------------------- #
# Idempotency -- the queue redelivers, and the store has no unique constraint
# --------------------------------------------------------------------------- #


def test_a_redelivered_batch_writes_nothing_new() -> None:
    """`queue.lease_seconds`/`max_attempts` make redelivery ordinary and
    `memory_item` has no uniqueness constraint on content, so without this the
    same batch inserts the same candidate twice -- straight into the metric
    Phase 2's soak gate measures."""
    scope = _scope()
    traces = _one_run_two_extractors_would_both_fire()
    writer = _FakeWriter()
    vault = _FakeVault()
    lane = TierALane(
        cfg=_cfg(), clock=FakeClock(_BASE_TS), writer=writer, known_content=vault
    )

    first = lane.run_batch(scope, traces)
    assert len(first.inserted) == 1
    # The store now holds it, exactly as a real insert would have left it.
    stored_id = vault.remember(scope.project_id, first.inserted[0].content)

    second = lane.run_batch(scope, traces)

    assert second.inserted == ()
    assert len(second.deduplicated) == 1
    assert second.deduplicated[0].memory_id == stored_id
    assert len(writer.inserted) == 1  # the store was written exactly once


def test_a_duplicate_names_the_existing_row_rather_than_vanishing() -> None:
    """A dropped outcome and a deduplicated one look identical to a caller
    that only counts writes. The run really did re-observe the condition; the
    only thing that did not happen is a second INSERT, so the outcome still
    carries the id of the row that holds the content."""
    scope = _scope()
    traces = _one_run_two_extractors_would_both_fire()
    writer = _FakeWriter()
    vault = _FakeVault()
    lane = TierALane(cfg=_cfg(), clock=FakeClock(_BASE_TS), writer=writer, known_content=vault)

    probe = lane.run_batch(scope, traces)
    existing = vault.remember(scope.project_id, probe.inserted[0].content)

    result = lane.run_batch(scope, traces)

    assert result.deduplicated[0].memory_id == existing
    assert result.deduplicated[0].skipped_reason is None
    assert len(writer.inserted) == 1  # the probe's insert, and nothing since


def test_the_dedupe_is_scoped_to_one_project() -> None:
    """A content hash another project holds must not suppress this project's
    write (invariant 4). The port is asked with THIS project's id and the fake
    vault keys on the pair."""
    traces = _one_run_two_extractors_would_both_fire()
    vault = _FakeVault()

    a_writer = _FakeWriter()
    scope_a = _scope()
    a = TierALane(cfg=_cfg(), clock=FakeClock(_BASE_TS), writer=a_writer, known_content=vault)
    first = a.run_batch(scope_a, traces)
    vault.remember(scope_a.project_id, first.inserted[0].content)

    b_writer = _FakeWriter()
    scope_b = _scope()
    b = TierALane(cfg=_cfg(), clock=FakeClock(_BASE_TS), writer=b_writer, known_content=vault)
    second = b.run_batch(scope_b, traces)

    assert len(second.inserted) == 1
    assert len(b_writer.inserted) == 1
    assert all(project == scope_b.project_id for project in b_writer.projects)
    assert all(project_id == scope_b.project_id for project_id, _ in vault.queries[-1:])


def test_dedupe_is_durable_is_false_without_a_store_port() -> None:
    """The in-batch guarantee and the cross-batch one are different promises,
    and a caller must be able to tell which one it has. With no port injected,
    a redelivered batch DOES duplicate -- asserted here rather than left as a
    docstring claim."""
    scope = _scope()
    traces = _one_run_two_extractors_would_both_fire()
    writer = _FakeWriter()
    lane = TierALane(cfg=_cfg(), clock=FakeClock(_BASE_TS), writer=writer)

    first = lane.run_batch(scope, traces)
    second = lane.run_batch(scope, traces)

    assert first.dedupe_is_durable is False
    assert len(first.inserted) == 1
    assert len(second.inserted) == 1
    assert len(writer.inserted) == 2


def test_the_store_is_consulted_once_per_note_not_once_per_trace() -> None:
    """The dedupe query runs after the cap and the scan, so its call count is
    bounded by candidates, not by trace volume -- the same "cost scales with
    vault size, not trace volume" property Phase 2's gate asserts for sweeps.
    """
    scope = _scope()
    vault = _FakeVault()
    writer = _FakeWriter()
    traces: dict[RunId, Sequence[TraceEvent]] = {}
    for _ in range(20):
        traces[RunId(uuid4())] = [
            _start(),
            _error(_BASE_TS, "tool_a", ErrorClassEnum.TIMEOUT),
            _error(_BASE_TS + timedelta(seconds=1), "tool_a", ErrorClassEnum.TIMEOUT),
        ]

    result = TierALane(
        cfg=_cfg(), clock=FakeClock(_BASE_TS), writer=writer, known_content=vault
    ).run_batch(scope, traces)

    assert len(vault.queries) == len(result.inserted) + len(result.deduplicated)


def test_identical_content_rendered_twice_in_one_batch_is_one_insert_and_one_duplicate() -> None:
    """A set of "duplicate hashes" cannot split these two: the first render is
    a real insert and the second is a duplicate of it. The writer keeps a
    per-call log for exactly this case."""
    scope = _scope()
    writer = _FakeWriter()
    traces = _one_run_two_extractors_would_both_fire()
    # Two instances of the SAME extractor over the same traces: the second
    # renders content byte-identical to the first's. The cap is raised to 4 so
    # the second instance is stopped by the DEDUPE and not by the budget --
    # otherwise this test would pass without the dedupe existing at all.
    lane = TierALane(
        cfg=_cfg(candidate_cap_per_run=4),
        clock=FakeClock(_BASE_TS),
        writer=writer,
        extractors=(ToolFailureExtractor(), ToolFailureExtractor()),
    )

    result = lane.run_batch(scope, traces)

    assert len(result.inserted) == 2  # tool_a/timeout and tool_b/schema
    assert len(result.deduplicated) == 2  # the second instance's re-renders
    assert {o.content for o in result.inserted} == {o.content for o in result.deduplicated}
    by_content = {o.content: o.memory_id for o in result.inserted}
    assert all(o.memory_id == by_content[o.content] for o in result.deduplicated)
    assert len(writer.inserted) == 2


# --------------------------------------------------------------------------- #
# Project homogeneity and construction
# --------------------------------------------------------------------------- #


def test_every_write_carries_the_batch_s_own_project_id() -> None:
    scope = _scope()
    writer = _FakeWriter()
    _lane(writer).run_batch(scope, _one_run_two_extractors_would_both_fire())

    assert writer.projects == [scope.project_id]


def test_no_state_survives_between_batches_of_different_projects() -> None:
    """The cap tracker and the dedupe cache are both built per call. A tracker
    that outlived a batch would let one project's run counts bind another
    project's cap; a dedupe cache that did would be a cross-project read."""
    writer = _FakeWriter()
    lane = _lane(writer)
    traces = _one_run_two_extractors_would_both_fire()

    a = lane.run_batch(_scope(), traces)
    b = lane.run_batch(_scope(), traces)

    assert len(a.inserted) == 1
    assert len(b.inserted) == 1


def test_a_lane_with_no_extractors_is_refused() -> None:
    with pytest.raises(ValueError):
        TierALane(cfg=_cfg(), clock=FakeClock(_BASE_TS), writer=_FakeWriter(), extractors=())


def test_outcomes_reports_everything_considered_including_the_capped_ones() -> None:
    """A capped pattern is a detection the operator should be able to see. It
    is in `outcomes` with a `skipped_reason`, not silently absent."""
    writer = _FakeWriter()
    result = _lane(writer).run_batch(_scope(), _one_run_two_extractors_would_both_fire())

    capped = [o for o in result.outcomes if o.memory_id is None]
    # tool_failure sees BOTH conditions (it groups every error class), so it
    # emits one and is capped on the second; schema_failure then sees its own
    # group and is capped too. Two detections, one written note, and the two
    # refusals are visible with the reason rather than silently absent.
    assert len(capped) == 2
    assert all("candidate_cap_per_run" in (o.skipped_reason or "") for o in capped)
    assert all(isinstance(o, ExtractionOutcome) for o in capped)


def test_an_empty_batch_writes_nothing_and_does_not_raise() -> None:
    writer = _FakeWriter()
    result = _lane(writer).run_batch(_scope(), {})

    assert result.outcomes == ()
    assert result.inserted == ()
    assert writer.inserted == []
