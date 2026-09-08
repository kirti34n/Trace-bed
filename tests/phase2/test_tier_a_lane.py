"""Pure planning boundary for the Tier-A trace-learning lane."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import UTC, datetime, timedelta
from typing import cast
from uuid import uuid4

import pytest

import tracebed.workers.tier_a_lane as tier_a_lane_module
from tracebed.core.scans import SUITE_VERSION, ScanResult, verify_verdict
from tracebed.core.scans import scan as real_scan
from tracebed.core.scans.tier_a_template import ErrorClassEnum, render_note
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
from tracebed.domain.enums import Lane, MemType, ProvenanceClass, ScopeType, TrustTier
from tracebed.domain.events import ErrorEvent, RunStart, ToolCall, ToolResult, TraceEvent
from tracebed.domain.ids import AgentTypeId, PrincipalId, ProjectId, RunId
from tracebed.domain.scope import ProjectScope
from tracebed.domain.state_machine import Status
from tracebed.workers.extractors import (
    TIER_A_KIND_MEM_TYPES,
    CandidateCapTracker,
    TierACandidateProposal,
    ToolFailureExtractor,
    try_build_note,
)
from tracebed.workers.tier_a_lane import TierALane, TierAPlan, default_extractors

pytestmark = pytest.mark.phase2

_TS = datetime(2026, 7, 25, tzinfo=UTC)


def _scope() -> ProjectScope:
    return ProjectScope(ProjectId(uuid4()), AgentTypeId(uuid4()), PrincipalId(uuid4()))


def _cfg(*, cap: int = 1) -> EffectiveConfig:
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
        tier_a=TierAConfig(candidate_cap_per_run=cap),
        killswitch=KillswitchConfig(),
        spend=SpendConfig(),
        cache=CacheConfig(),
        session=SessionConfig(),
        queue=QueueConfig(),
        killswitch_overlay={},
    )


def _start() -> RunStart:
    return RunStart(
        type="run_start",
        ts=_TS,
        payload={"query_text": "q", "tool_manifest": ["tool_a", "tool_b"]},
    )


def _error(ts: datetime, tool_id: str, error_class: ErrorClassEnum) -> ErrorEvent:
    return ErrorEvent(
        type="error",
        ts=ts,
        payload={
            "tool_id": tool_id,
            "tool_version": "v1",
            "error_class": error_class.value,
        },
    )


def _traces() -> Mapping[RunId, Sequence[TraceEvent]]:
    run = RunId(uuid4())
    return {
        run: [
            _start(),
            _error(_TS, "tool_a", ErrorClassEnum.TIMEOUT),
            _error(_TS + timedelta(seconds=1), "tool_a", ErrorClassEnum.TIMEOUT),
            _error(_TS + timedelta(seconds=2), "tool_b", ErrorClassEnum.TIMEOUT),
            _error(_TS + timedelta(seconds=3), "tool_b", ErrorClassEnum.TIMEOUT),
        ]
    }


class _Extractor:
    def __init__(self, proposals: Sequence[TierACandidateProposal]) -> None:
        self._proposals = tuple(proposals)

    def propose(
        self,
        _traces: Mapping[RunId, Sequence[TraceEvent]],
        *,
        require_declared_tools: bool = True,
    ) -> list[TierACandidateProposal]:
        assert require_declared_tools is True
        return list(self._proposals)


def _proposal(run_id: RunId, tool_id: str) -> TierACandidateProposal:
    note = try_build_note(
        error_class=ErrorClassEnum.TIMEOUT,
        tool_id=tool_id,
        tool_version="v1",
        count=2,
        duration_ms=10,
        payload_class_hash="a" * 64,
    )
    assert note is not None
    return TierACandidateProposal(
        note=note,
        mem_type=MemType.EPISODIC,
        kind="test",
        contributing_run_ids=(run_id,),
        primary_run_id=run_id,
    )


def test_plan_is_pure_and_candidate_is_exactly_tier_a_candidate() -> None:
    lane = TierALane(cfg=_cfg(), clock=FakeClock(_TS), extractors=(ToolFailureExtractor(),))
    scope = _scope()

    plan = lane.plan(scope, _traces())

    assert len(plan.candidates) == 1
    candidate = plan.candidates[0]
    assert candidate.item.lane is Lane.OPERATIONAL
    assert candidate.item.trust_tier is TrustTier.A
    assert candidate.item.status is Status.CANDIDATE
    assert candidate.item.scope_type is ScopeType.AGENT_TYPE
    assert candidate.item.scope_id == scope.agent_type_id.value
    assert candidate.item.provenance.cls is ProvenanceClass.PARSER
    assert candidate.item.provenance.trace_ids == candidate.contributing_run_ids
    assert candidate.item.provenance.tool_refs == (candidate.item.content.split("|ti=")[1].split("|")[0],)
    assert candidate.item.schema_version == 1
    assert candidate.item.token_count >= 0
    assert candidate.scan_result.content_hash == content_hash(candidate.item.content)
    assert candidate.scan_result.passed is True
    verify_verdict(
        candidate.scan_result.verdict(clock=FakeClock(_TS)), candidate.scan_result.content_hash
    )
    assert not hasattr(lane, "writer")
    assert not hasattr(lane, "review_writer")
    assert not hasattr(lane, "queue")


def test_shared_cap_has_fixed_order_and_records_refusal() -> None:
    lane = TierALane(cfg=_cfg(cap=1), clock=FakeClock(_TS), extractors=(ToolFailureExtractor(),))

    plans = [lane.plan(_scope(), _traces()) for _ in range(3)]

    assert all(len(plan.candidates) == 1 for plan in plans)
    assert all(len(plan.outcomes) == 2 for plan in plans)
    assert all("candidate_cap_per_run" in (plan.outcomes[1].skipped_reason or "") for plan in plans)


def test_zero_cap_observes_outcomes_but_never_emits_candidates() -> None:
    lane = TierALane(cfg=_cfg(cap=0), clock=FakeClock(_TS), extractors=(ToolFailureExtractor(),))

    plan = lane.plan(_scope(), _traces())

    assert plan.candidates == ()
    assert len(plan.outcomes) == 2
    assert all("candidate_cap_per_run" in (outcome.skipped_reason or "") for outcome in plan.outcomes)
    assert lane.plan(_scope(), {}) == TierAPlan(candidates=(), rejections=(), outcomes=())


def test_scan_rejection_is_planned_not_persisted_and_does_not_spend_cap(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run = RunId(uuid4())
    rejected, accepted = _proposal(run, "a_rejected"), _proposal(run, "b_accepted")

    def fake_scan(content: str, *, context: object) -> ScanResult:
        del context
        return ScanResult(
            passed="a_rejected" not in content,
            reasons=("test_rejection",) if "a_rejected" in content else (),
            content_hash=content_hash(content),
            suite_version="test/1",
        )

    monkeypatch.setattr(tier_a_lane_module, "scan", fake_scan)
    plan = TierALane(
        cfg=_cfg(cap=1), clock=FakeClock(_TS), extractors=(_Extractor((rejected, accepted)),)
    ).plan(_scope(), {})

    assert len(plan.rejections) == 1
    assert plan.rejections[0].reasons == ("test_rejection",)
    assert len(plan.candidates) == 1
    assert "b_accepted" in plan.candidates[0].item.content
    assert plan.outcomes[0].skipped_reason == "scan_rejected: test_rejection"


def test_cap_is_per_run_shared_across_extractors_and_has_a_fixed_winner() -> None:
    first_run, second_run = RunId(uuid4()), RunId(uuid4())
    same_run = tuple(_Extractor((_proposal(first_run, f"tool_{index}"),)) for index in range(4))
    plan = TierALane(
        cfg=_cfg(cap=1), clock=FakeClock(_TS), extractors=same_run
    ).plan(_scope(), {})

    assert len(plan.candidates) == 1
    assert "tool_0" in plan.candidates[0].item.content
    assert len([outcome for outcome in plan.outcomes if outcome.skipped_reason]) == 3

    per_run = TierALane(
        cfg=_cfg(cap=1),
        clock=FakeClock(_TS),
        extractors=(_Extractor((_proposal(first_run, "first"), _proposal(second_run, "second"))),),
    ).plan(_scope(), {})
    assert len(per_run.candidates) == 2


def test_raised_cap_duplicate_telemetry_and_repeated_plans_do_not_leak_state() -> None:
    run = RunId(uuid4())
    first, duplicate, second = _proposal(run, "same"), _proposal(run, "same"), _proposal(run, "other")
    lane = TierALane(
        cfg=_cfg(cap=2),
        clock=FakeClock(_TS),
        extractors=(_Extractor((first, duplicate, second)),),
    )

    first_plan = lane.plan(_scope(), {})
    second_plan = lane.plan(_scope(), {})

    assert len(first_plan.candidates) == len(second_plan.candidates) == 2
    assert [outcome.skipped_reason for outcome in first_plan.outcomes] == [
        None,
        "duplicate_candidate",
        None,
    ]
    assert [candidate.item.content for candidate in first_plan.candidates] == [
        candidate.item.content for candidate in second_plan.candidates
    ]


def test_duplicate_proposals_do_not_consume_additional_cap() -> None:
    lane = TierALane(
        cfg=_cfg(cap=1),
        clock=FakeClock(_TS),
        extractors=(ToolFailureExtractor(), ToolFailureExtractor()),
    )

    plan = lane.plan(_scope(), _traces())

    assert len(plan.candidates) == 1
    assert len([o for o in plan.outcomes if o.skipped_reason == "duplicate_candidate"]) == 2


def test_default_extractors_keep_the_cross_process_order() -> None:
    assert [type(extractor).__name__ for extractor in default_extractors()] == [
        "ToolFailureExtractor",
        "SchemaFailureExtractor",
        "LatencyOutlierExtractor",
        "SequencePatternExtractor",
    ]


def test_full_plan_is_equal_under_mapping_reorder_clock_advance_and_a_b_a_calls() -> None:
    """Planning is a pure function of one scope/traces input, not call history."""
    scope_a, scope_b = _scope(), _scope()
    base_traces = _traces()
    (first_run, first_events), = base_traces.items()
    second_run = RunId(uuid4())
    traces = {first_run: first_events, second_run: list(first_events)}
    reordered = dict(reversed(tuple(traces.items())))
    lane = TierALane(cfg=_cfg(cap=4), clock=FakeClock(_TS))
    advanced = TierALane(cfg=_cfg(cap=4), clock=FakeClock(_TS + timedelta(days=30)))

    plan_a_first = lane.plan(scope_a, traces)
    plan_reordered = lane.plan(scope_a, reordered)
    plan_b = lane.plan(scope_b, traces)
    plan_a_after_b = lane.plan(scope_a, traces)
    plan_advanced_clock = advanced.plan(scope_a, traces)

    assert plan_a_first == plan_reordered == plan_a_after_b == plan_advanced_clock
    assert plan_b != plan_a_first


def test_empty_plan_and_empty_extractor_set() -> None:
    lane = TierALane(cfg=_cfg(), clock=FakeClock(_TS))
    assert lane.plan(_scope(), {}).candidates == ()
    with pytest.raises(ValueError, match="at least one extractor"):
        TierALane(cfg=_cfg(), clock=FakeClock(_TS), extractors=())


def test_candidate_cap_hard_bound_matches_the_finalizer_capacity() -> None:
    run_id = RunId(uuid4())
    tracker = CandidateCapTracker(cap=100)
    assert [tracker.try_reserve(run_id) for _ in range(100)] == [True] * 100
    assert tracker.try_reserve(run_id) is False
    with pytest.raises(ValueError, match="less than or equal to 100"):
        TierAConfig(candidate_cap_per_run=101)


def _rejection_overflow_plan(
    monkeypatch: pytest.MonkeyPatch,
    *,
    count: int,
    reverse: bool = False,
    omitted_reason: str = "schema:empty_content",
) -> TierAPlan:
    """Build scanner rejections with a stable semantic sort key, not order."""

    run_id = RunId(uuid4())
    proposals = tuple(_proposal(run_id, f"overflow_{index}") for index in range(count))
    indexes = {render_note(proposal.note): index for index, proposal in enumerate(proposals)}

    def reject(content: str, *, context: object) -> ScanResult:
        del context
        index = indexes[content]
        return ScanResult(
            passed=False,
            reasons=(omitted_reason if index == 100 else "schema:empty_content",),
            content_hash=f"{index:064x}",
            suite_version=SUITE_VERSION,
        )

    monkeypatch.setattr(tier_a_lane_module, "scan", reject)
    ordered = tuple(reversed(proposals)) if reverse else proposals
    return TierALane(
        cfg=_cfg(cap=100), clock=FakeClock(_TS), extractors=(_Extractor(ordered),)
    ).plan(_scope(), {})


def test_rejection_overflow_retains_the_first_hundred_and_aggregates_the_101st(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    exact = _rejection_overflow_plan(monkeypatch, count=100)
    assert len(exact.rejections) == 100
    assert exact.rejection_overflow is None

    plan = _rejection_overflow_plan(monkeypatch, count=101)
    overflow = plan.rejection_overflow
    assert len(plan.rejections) == 100
    assert overflow is not None
    assert (overflow.total_count, overflow.omitted_count) == (101, 1)
    assert overflow.mem_type_counts == ((MemType.EPISODIC, 1),)
    assert overflow.reason_counts == (("schema:empty_content", 1),)
    assert all("overflow_" not in value for value in (repr(overflow), str(overflow)))
    assert sum(
        outcome.skipped_reason is not None
        and outcome.skipped_reason.startswith("scan_rejected_aggregated: ")
        for outcome in plan.outcomes
    ) == 1


def test_rejection_overflow_is_order_invariant_and_commits_omitted_semantics(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    forward = _rejection_overflow_plan(monkeypatch, count=101)
    reversed_plan = _rejection_overflow_plan(monkeypatch, count=101, reverse=True)
    changed_omitted = _rejection_overflow_plan(
        monkeypatch, count=101, omitted_reason="schema:control_characters"
    )

    assert [
        (rejection.content_hash, rejection.mem_type, rejection.suite_version, rejection.reasons)
        for rejection in forward.rejections
    ] == [
        (rejection.content_hash, rejection.mem_type, rejection.suite_version, rejection.reasons)
        for rejection in reversed_plan.rejections
    ]
    assert forward.rejection_overflow == reversed_plan.rejection_overflow
    assert forward.rejection_overflow is not None
    assert changed_omitted.rejection_overflow is not None
    assert forward.rejection_overflow.omitted_digest != changed_omitted.rejection_overflow.omitted_digest


def test_rejection_overflow_stays_bounded_for_a_large_scanner_batch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan = _rejection_overflow_plan(monkeypatch, count=512)
    overflow = plan.rejection_overflow
    assert len(plan.rejections) == 100
    assert overflow is not None
    assert (overflow.total_count, overflow.omitted_count) == (512, 412)
    assert len(overflow.omitted_digest) == 32
    assert len(overflow.mem_type_counts) == len(overflow.reason_counts) == 1


def test_all_four_extractors_flow_through_one_real_scan_content_boundary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Every emitted candidate is the exact string scanned and planned.

    The raw body contains zero-width, bidi, and control characters.  It is
    intentionally present on the events that satisfy all four real
    extractors, so a future accidental template/input widening cannot hide
    behind a synthetic proposal fixture.
    """
    raw = "canary\u200b\u202e\x00must-not-reach-tier-a"
    run_a, run_b = RunId(uuid4()), RunId(uuid4())

    def trace(run_id: RunId, offset: int, *, results: bool) -> list[TraceEvent]:
        events: list[TraceEvent] = [
            _start(),
            ToolCall(type="tool_call", ts=_TS + timedelta(seconds=offset), payload={"tool_id": "tool_a", "tool_version": "v1"}),
            ToolCall(type="tool_call", ts=_TS + timedelta(seconds=offset + 1), payload={"tool_id": "tool_b", "tool_version": "v1"}),
            ToolCall(type="tool_call", ts=_TS + timedelta(seconds=offset + 2), payload={"tool_id": "tool_c", "tool_version": "v1"}),
            ErrorEvent(
                type="error",
                ts=_TS + timedelta(seconds=offset + 3),
                payload={
                    "tool_id": "tool_a",
                    "tool_version": "v1",
                    "error_class": ErrorClassEnum.SCHEMA_VALIDATION.value,
                    "schema_fields": ["field_name"],
                    "error_body": raw,
                },
            ),
        ]
        if results:
            events.extend(
                ToolResult(
                    type="tool_result",
                    ts=_TS + timedelta(seconds=offset + 4 + index),
                    payload={
                        "tool_id": "tool_a",
                        "tool_version": "v1",
                        "duration_ms": duration,
                        "result_body": raw,
                    },
                )
                for index, duration in enumerate((10, 11, 12, 13, 14, 100, 110))
            )
        return events

    captured: list[str] = []

    def capture_scan(content: str, *, context: object) -> ScanResult:
        captured.append(content)
        # Preserve the real scan implementation; only its boundary is
        # observed here.
        return real_scan(content, context=context)  # type: ignore[arg-type]

    monkeypatch.setattr(tier_a_lane_module, "scan", capture_scan)
    scope = _scope()
    plan = TierALane(cfg=_cfg(cap=4), clock=FakeClock(_TS)).plan(
        scope,
        {run_a: trace(run_a, 0, results=True), run_b: trace(run_b, 60, results=False)},
    )

    assert {candidate.item.kind for candidate in plan.candidates} == {
        "tool_failure_pattern",
        "schema_failure_pattern",
        "latency_outlier",
        "failure_precursor_sequence",
    }
    assert {
        (candidate.item.kind, candidate.item.mem_type) for candidate in plan.candidates
    } == set(TIER_A_KIND_MEM_TYPES.items())
    with pytest.raises(TypeError):
        cast(dict[str, MemType], TIER_A_KIND_MEM_TYPES)["attacker_kind"] = MemType.LESSON
    assert captured == [outcome.content for outcome in plan.outcomes]
    assert [candidate.item.content for candidate in plan.candidates] == [
        outcome.content for outcome in plan.outcomes if outcome.skipped_reason is None
    ]
    for candidate in plan.candidates:
        matching_outcome = next(
            outcome for outcome in plan.outcomes if outcome.content == candidate.item.content
        )
        assert candidate.item.content == render_note(matching_outcome.note)
        assert candidate.scan_result.content_hash == content_hash(candidate.item.content)
        source = raw.encode("utf-8")
        rendered = candidate.item.content.encode("utf-8")
        assert all(source[index : index + 8] not in rendered for index in range(len(source) - 7))
