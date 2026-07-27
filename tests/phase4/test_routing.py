"""`workflow.routing` — routing records as evidence, never a recommendation
(PLAN.md §7 Phase 4). Offline only: `InMemoryRoutingRecordStore` is the reference
`RoutingRecordStore` this module ships (see its module docstring's contract-gap note —
no `routing_record` table exists in PLAN.md §5, and this chunk's file list does not
include `stores/pg`).

Two tests here exist because their absence let a mutation live: the isolation test used
to vary the agent_type_id along with the project_id, so the signatures differed anyway
and a store that ignored `project_id` entirely still passed it; and nothing pinned the
free-text half of `same_signature_shape`, so dropping `same_cluster` from the predicate
passed too. Both now fail on exactly those mutations.
"""

from __future__ import annotations

import dataclasses
import sys
import threading
from collections.abc import Iterator, Sequence
from uuid import uuid4

import pytest

from tracebed.domain.clock import FakeClock
from tracebed.domain.ids import AgentTypeId, PrincipalId, ProjectId, RunId, mint_run_id
from tracebed.domain.scope import ProjectScope
from tracebed.domain.signatures import input_signature_hash
from tracebed.workflow.routing import (
    InMemoryRoutingRecordStore,
    RoutingEvidence,
    RoutingRecord,
    record_routing_outcome,
    routing_evidence_for,
    same_signature_shape,
)

pytestmark = pytest.mark.phase4


@pytest.fixture
def hair_trigger_thread_switching() -> Iterator[None]:
    """Force the interpreter to switch threads roughly every microsecond instead of
    every 5ms, then restore. Without it, a contention test's threads mostly run to
    completion one after another and a genuine lost-update race stays invisible."""
    previous = sys.getswitchinterval()
    sys.setswitchinterval(1e-6)
    try:
        yield
    finally:
        sys.setswitchinterval(previous)


def _scope(
    *, project_id: ProjectId | None = None, agent_type_id: AgentTypeId | None = None
) -> ProjectScope:
    return ProjectScope(
        project_id=project_id if project_id is not None else ProjectId(uuid4()),
        agent_type_id=agent_type_id if agent_type_id is not None else AgentTypeId(uuid4()),
        principal_id=PrincipalId(uuid4()),
    )


def _record(
    store: InMemoryRoutingRecordStore,
    scope: ProjectScope,
    clock: FakeClock,
    *,
    query_text: str = "restart the failed payment webhook",
    workflow_template: str | None = "incident_response",
    tool_manifest: list[str] | None = None,
    routed_to: str = "agent-runbook",
    outcome: str = "positive",
    free_text_embedding: list[float] | None = None,
) -> RoutingRecord:
    return record_routing_outcome(
        store,
        scope,
        run_id=mint_run_id(now_ms=clock.now_ms()),
        query_text=query_text,
        workflow_template=workflow_template,
        tool_manifest=tool_manifest or ["webhook.retry", "pagerduty.ack"],
        routed_to=routed_to,
        outcome=outcome,  # type: ignore[arg-type]
        free_text_embedding=free_text_embedding,
        clock=clock,
    )


# --------------------------------------------------------------------------- #
# Write/read round trip with the right signature.
# --------------------------------------------------------------------------- #


def test_written_record_carries_the_reused_signature_scheme() -> None:
    store = InMemoryRoutingRecordStore()
    clock = FakeClock()
    scope = _scope()

    record = _record(store, scope, clock)

    expected = input_signature_hash(
        agent_type_id=scope.agent_type_id,
        query_text="restart the failed payment webhook",
        workflow_template="incident_response",
        tool_manifest=["webhook.retry", "pagerduty.ack"],
    )
    assert record.input_signature == expected
    assert record.project_id == scope.project_id
    assert record.principal_id == scope.principal_id
    assert record.recorded_at_ms == clock.now_ms()


def test_read_back_returns_the_written_record_as_evidence() -> None:
    store = InMemoryRoutingRecordStore()
    clock = FakeClock()
    scope = _scope()

    written = _record(store, scope, clock)

    evidence = routing_evidence_for(
        store,
        scope,
        query_text="restart the failed payment webhook",
        workflow_template="incident_response",
        tool_manifest=["webhook.retry", "pagerduty.ack"],
    )

    assert len(evidence) == 1
    assert evidence[0].record == written


def test_near_duplicate_free_text_still_matches_one_shape() -> None:
    """A typo / reordered clause lands in the same SimHash cluster (D-020) — same
    shape, exact wording need not match."""
    store = InMemoryRoutingRecordStore()
    clock = FakeClock()
    scope = _scope()

    _record(store, scope, clock, query_text="restart the failed payment webhook")

    evidence = routing_evidence_for(
        store,
        scope,
        query_text="restart the failed  payment webhook",  # extra whitespace, near-dup
        workflow_template="incident_response",
        tool_manifest=["webhook.retry", "pagerduty.ack"],
    )
    assert len(evidence) == 1


def test_unrelated_shape_never_matches() -> None:
    store = InMemoryRoutingRecordStore()
    clock = FakeClock()
    scope = _scope()

    _record(store, scope, clock, query_text="restart the failed payment webhook")

    evidence = routing_evidence_for(
        store,
        scope,
        query_text="draft a quarterly earnings summary for the board",
        workflow_template="reporting",
        tool_manifest=["docs.create"],
    )
    assert evidence == ()


def test_different_workflow_template_is_a_different_shape() -> None:
    """Structural equality (the leading 32 sha256 bytes) requires the SAME
    `workflow_template`; near-duplicate free text alone must not be enough."""
    store = InMemoryRoutingRecordStore()
    clock = FakeClock()
    scope = _scope()

    _record(
        store,
        scope,
        clock,
        query_text="restart the failed payment webhook",
        workflow_template="incident_response",
    )

    evidence = routing_evidence_for(
        store,
        scope,
        query_text="restart the failed payment webhook",
        workflow_template="dry_run_rehearsal",  # different structural feature
        tool_manifest=["webhook.retry", "pagerduty.ack"],
    )
    assert evidence == ()


def test_identical_structure_but_unrelated_free_text_is_a_different_shape() -> None:
    """The other half of the predicate, which nothing used to pin: same agent_type, same
    workflow_template, same tool_manifest — so the 32 structural bytes match exactly —
    but a completely different request. Dropping `same_cluster` from
    `same_signature_shape` (making it structural-only) used to pass every test in this
    file, which would have made "runs shaped like this one" mean "any run of this agent
    type", i.e. all of them."""
    store = InMemoryRoutingRecordStore()
    clock = FakeClock()
    scope = _scope()

    _record(store, scope, clock, query_text="restart the failed payment webhook")

    evidence = routing_evidence_for(
        store,
        scope,
        query_text="summarise last quarter's revenue by region for the board deck",
        workflow_template="incident_response",  # identical structural features
        tool_manifest=["webhook.retry", "pagerduty.ack"],
    )
    assert evidence == ()


# --------------------------------------------------------------------------- #
# Evidence, never a recommendation.
# --------------------------------------------------------------------------- #


def test_evidence_type_has_no_score_rank_or_recommendation_field() -> None:
    """The type itself is the contract: `RoutingEvidence` never grows a `score`,
    `rank`, or `recommended_agent` field. A name-based check because the whole point is
    that no such field can quietly reappear later without this test naming it."""
    field_names = {f.name for f in dataclasses.fields(RoutingEvidence)}
    assert field_names == {"record", "embedding_similarity"}
    for forbidden in ("score", "rank", "recommended", "best", "decision", "confidence"):
        assert not any(forbidden in name for name in field_names)


def test_evidence_carries_provenance_back_to_the_originating_run() -> None:
    store = InMemoryRoutingRecordStore()
    clock = FakeClock()
    scope = _scope()

    written = _record(store, scope, clock, outcome="negative", routed_to="agent-legacy")

    evidence = routing_evidence_for(
        store,
        scope,
        query_text="restart the failed payment webhook",
        workflow_template="incident_response",
        tool_manifest=["webhook.retry", "pagerduty.ack"],
    )
    assert evidence[0].record.run_id == written.run_id
    assert evidence[0].record.principal_id == written.principal_id
    assert evidence[0].record.routed_to == "agent-legacy"
    assert evidence[0].record.outcome == "negative"


def test_two_conflicting_outcomes_both_survive_as_separate_evidence() -> None:
    """Routing evidence is a log, not a rolling average (module docstring): a later bad
    outcome must not overwrite an earlier good one for the same shape."""
    store = InMemoryRoutingRecordStore()
    clock = FakeClock()
    scope = _scope()

    _record(store, scope, clock, routed_to="agent-a", outcome="positive")
    clock.advance(seconds=1)
    _record(store, scope, clock, routed_to="agent-b", outcome="negative")

    evidence = routing_evidence_for(
        store,
        scope,
        query_text="restart the failed payment webhook",
        workflow_template="incident_response",
        tool_manifest=["webhook.retry", "pagerduty.ack"],
    )
    routed = {(e.record.routed_to, e.record.outcome) for e in evidence}
    assert routed == {("agent-a", "positive"), ("agent-b", "negative")}


# --------------------------------------------------------------------------- #
# Project isolation (invariant 4 is a construction-time discipline everywhere,
# not only in Postgres-backed stores).
# --------------------------------------------------------------------------- #


def test_records_never_leak_across_projects() -> None:
    """Two projects that differ ONLY in project_id — same agent_type_id, same query,
    same template, same tools, therefore a byte-identical `input_signature`. The earlier
    version of this test also varied the agent_type_id, so the signatures differed and a
    store that ignored `project_id` entirely still passed it."""
    store = InMemoryRoutingRecordStore()
    clock = FakeClock()
    shared_agent_type = AgentTypeId(uuid4())
    scope_a = _scope(agent_type_id=shared_agent_type)
    scope_b = _scope(agent_type_id=shared_agent_type)

    written = _record(store, scope_a, clock)

    evidence_b = routing_evidence_for(
        store,
        scope_b,
        query_text="restart the failed payment webhook",
        workflow_template="incident_response",
        tool_manifest=["webhook.retry", "pagerduty.ack"],
    )
    assert evidence_b == ()

    # ... and the signature really was identical, so the emptiness above is isolation,
    # not a shape mismatch doing isolation's job by accident.
    evidence_a = routing_evidence_for(
        store,
        scope_a,
        query_text="restart the failed payment webhook",
        workflow_template="incident_response",
        tool_manifest=["webhook.retry", "pagerduty.ack"],
    )
    assert [e.record for e in evidence_a] == [written]


def test_a_backend_that_leaks_another_project_is_filtered_at_the_boundary() -> None:
    """`RoutingRecordStore` is a Protocol, so its implementations are open-ended. A
    backend with a wrong WHERE clause must not be able to put another project's rows in
    front of a caller: `routing_evidence_for` re-checks `record.project_id` for the same
    reason Postgres RLS backstops the typed repository (invariant 4)."""

    class _LeakyStore:
        """Deliberately ignores `project_id` — the exact bug RLS exists to backstop."""

        def __init__(self) -> None:
            self.records: list[RoutingRecord] = []

        def append(self, record: RoutingRecord) -> None:
            self.records.append(record)

        def for_signature(
            self, project_id: ProjectId, input_signature: bytes
        ) -> Sequence[RoutingRecord]:
            return tuple(self.records)

    store = _LeakyStore()
    clock = FakeClock()
    shared_agent_type = AgentTypeId(uuid4())
    scope_a = _scope(agent_type_id=shared_agent_type)
    scope_b = _scope(agent_type_id=shared_agent_type)

    record_routing_outcome(
        store,
        scope_a,
        run_id=mint_run_id(now_ms=clock.now_ms()),
        query_text="restart the failed payment webhook",
        workflow_template="incident_response",
        tool_manifest=["webhook.retry"],
        routed_to="agent-runbook",
        outcome="positive",
        free_text_embedding=None,
        clock=clock,
    )
    assert len(store.records) == 1

    evidence = routing_evidence_for(
        store,
        scope_b,
        query_text="restart the failed payment webhook",
        workflow_template="incident_response",
        tool_manifest=["webhook.retry"],
    )
    assert evidence == ()


def test_the_store_itself_is_scoped_not_only_its_caller() -> None:
    """`RoutingRecordStore.for_signature` is required to return one project's records —
    every backend, not just the ones read through `routing_evidence_for`. Asserted
    directly against the store, because the boundary re-check in `routing_evidence_for`
    would otherwise mask a store that ignores its `project_id` argument entirely (it
    did: that mutation passed every other test in this file)."""
    store = InMemoryRoutingRecordStore()
    clock = FakeClock()
    shared_agent_type = AgentTypeId(uuid4())
    scope_a = _scope(agent_type_id=shared_agent_type)
    scope_b = _scope(agent_type_id=shared_agent_type)

    written = _record(store, scope_a, clock)

    assert store.for_signature(scope_a.project_id, written.input_signature) == (written,)
    assert store.for_signature(scope_b.project_id, written.input_signature) == ()


def test_concurrent_writers_and_readers_never_lose_or_cross_records(
    hair_trigger_thread_switching: None,
) -> None:
    """Phase 4 is the phase with real concurrent callers (parallel branches of one
    workflow run). Six threads append to two projects while others read evidence; every
    record must land in its own project's evidence exactly once, and no reader may see
    the other project's rows.

    The fixture drops the interpreter's thread-switch interval to a microsecond for the
    duration: at the default 5ms, a whole 300-append run finishes inside one or two
    scheduling quanta, and a store whose `append` is not atomic (read the list, copy,
    append, write it back — the shape a future backend's caching layer could easily take)
    loses hundreds of records with no test noticing. With hair-trigger switching that
    same implementation loses ~65% of its writes on every trial, which is what makes the
    `len(evidence)` assertion below a real check on the lock rather than a description of
    the GIL."""
    store = InMemoryRoutingRecordStore()
    clock = FakeClock()
    shared_agent_type = AgentTypeId(uuid4())
    scope_a = _scope(agent_type_id=shared_agent_type)
    scope_b = _scope(agent_type_id=shared_agent_type)
    per_thread = 150
    errors: list[BaseException] = []
    start = threading.Barrier(6)

    def writer(scope: ProjectScope, tag: str) -> None:
        try:
            start.wait(timeout=5.0)
            for i in range(per_thread):
                _record(store, scope, clock, routed_to=f"{tag}-{i}")
        # Broad on purpose: a thread that dies silently turns a contention bug into a
        # green run, so everything is captured and re-raised on the main thread.
        except BaseException as exc:
            errors.append(exc)

    def reader(scope: ProjectScope) -> None:
        try:
            start.wait(timeout=5.0)
            for _ in range(per_thread):
                evidence = routing_evidence_for(
                    store,
                    scope,
                    query_text="restart the failed payment webhook",
                    workflow_template="incident_response",
                    tool_manifest=["webhook.retry", "pagerduty.ack"],
                )
                for entry in evidence:
                    if entry.record.project_id != scope.project_id:
                        raise AssertionError("evidence crossed the project wall")
        # Broad on purpose: a thread that dies silently turns a contention bug into a
        # green run, so everything is captured and re-raised on the main thread.
        except BaseException as exc:
            errors.append(exc)

    threads = [
        threading.Thread(target=writer, args=(scope_a, "a")),
        threading.Thread(target=writer, args=(scope_a, "a2")),
        threading.Thread(target=writer, args=(scope_b, "b")),
        threading.Thread(target=writer, args=(scope_b, "b2")),
        threading.Thread(target=reader, args=(scope_a,)),
        threading.Thread(target=reader, args=(scope_b,)),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30.0)
        assert not thread.is_alive(), "a routing-store thread deadlocked"

    assert not errors, errors
    for scope, tags in ((scope_a, ("a", "a2")), (scope_b, ("b", "b2"))):
        evidence = routing_evidence_for(
            store,
            scope,
            query_text="restart the failed payment webhook",
            workflow_template="incident_response",
            tool_manifest=["webhook.retry", "pagerduty.ack"],
        )
        assert len(evidence) == 2 * per_thread, "an append was lost under contention"
        assert {e.record.routed_to for e in evidence} == {
            f"{tag}-{i}" for tag in tags for i in range(per_thread)
        }


# --------------------------------------------------------------------------- #
# Free-text-head embedding: attached similarity, never used to filter.
# --------------------------------------------------------------------------- #


def test_embedding_similarity_attached_when_both_sides_have_one() -> None:
    store = InMemoryRoutingRecordStore()
    clock = FakeClock()
    scope = _scope()

    _record(store, scope, clock, free_text_embedding=[1.0, 0.0, 0.0])

    evidence = routing_evidence_for(
        store,
        scope,
        query_text="restart the failed payment webhook",
        workflow_template="incident_response",
        tool_manifest=["webhook.retry", "pagerduty.ack"],
        free_text_embedding=[1.0, 0.0, 0.0],
    )
    assert len(evidence) == 1
    assert evidence[0].embedding_similarity == pytest.approx(1.0)


def test_a_dissimilar_embedding_is_reported_but_never_filters_the_evidence_out() -> None:
    """The similarity number is a second signal for the orchestrator, not a filter this
    module applies: an orthogonal vector still comes back as evidence, carrying its 0.0.
    (A module that quietly dropped low-similarity records would be ranking, which is the
    one thing `routing_evidence_for` must not do.)"""
    store = InMemoryRoutingRecordStore()
    clock = FakeClock()
    scope = _scope()

    _record(store, scope, clock, free_text_embedding=[1.0, 0.0, 0.0])

    evidence = routing_evidence_for(
        store,
        scope,
        query_text="restart the failed payment webhook",
        workflow_template="incident_response",
        tool_manifest=["webhook.retry", "pagerduty.ack"],
        free_text_embedding=[0.0, 1.0, 0.0],
    )
    assert len(evidence) == 1
    assert evidence[0].embedding_similarity == pytest.approx(0.0)


def test_embedding_similarity_is_none_without_both_sides() -> None:
    store = InMemoryRoutingRecordStore()
    clock = FakeClock()
    scope = _scope()

    _record(store, scope, clock, free_text_embedding=None)

    evidence = routing_evidence_for(
        store,
        scope,
        query_text="restart the failed payment webhook",
        workflow_template="incident_response",
        tool_manifest=["webhook.retry", "pagerduty.ack"],
        free_text_embedding=[1.0, 0.0, 0.0],
    )
    assert len(evidence) == 1
    assert evidence[0].embedding_similarity is None


def test_embedding_similarity_none_on_mismatched_dimension() -> None:
    """A stale record from a since-repinned embedding model (different dimension) must
    not crash `routing_evidence_for` or produce a fabricated number."""
    store = InMemoryRoutingRecordStore()
    clock = FakeClock()
    scope = _scope()

    _record(store, scope, clock, free_text_embedding=[1.0, 0.0, 0.0])

    evidence = routing_evidence_for(
        store,
        scope,
        query_text="restart the failed payment webhook",
        workflow_template="incident_response",
        tool_manifest=["webhook.retry", "pagerduty.ack"],
        free_text_embedding=[1.0, 0.0],  # different dimension
    )
    assert evidence[0].embedding_similarity is None


def test_a_zero_vector_reports_no_signal_rather_than_dividing_by_zero() -> None:
    """Cosine is undefined against the zero vector. `None` ("no signal") is the honest
    answer; a `ZeroDivisionError` out of an evidence read, or an invented 0.0 reading as
    "measured and dissimilar", are the two wrong ones."""
    store = InMemoryRoutingRecordStore()
    clock = FakeClock()
    scope = _scope()

    _record(store, scope, clock, free_text_embedding=[0.0, 0.0, 0.0])

    evidence = routing_evidence_for(
        store,
        scope,
        query_text="restart the failed payment webhook",
        workflow_template="incident_response",
        tool_manifest=["webhook.retry", "pagerduty.ack"],
        free_text_embedding=[1.0, 0.0, 0.0],
    )
    assert evidence[0].embedding_similarity is None


def test_non_finite_embedding_components_are_rejected_at_the_boundary() -> None:
    """A NaN component makes cosine return NaN, which is not `None` and therefore reads
    as a measured similarity while comparing false against every threshold applied to
    it. Rejected on both sides — stored and queried."""
    store = InMemoryRoutingRecordStore()
    clock = FakeClock()
    scope = _scope()

    with pytest.raises(ValueError, match="finite"):
        _record(store, scope, clock, free_text_embedding=[float("nan"), 0.0])
    with pytest.raises(ValueError, match="finite"):
        _record(store, scope, clock, free_text_embedding=[float("inf"), 0.0])

    _record(store, scope, clock, free_text_embedding=[1.0, 0.0])
    with pytest.raises(ValueError, match="finite"):
        routing_evidence_for(
            store,
            scope,
            query_text="restart the failed payment webhook",
            workflow_template="incident_response",
            tool_manifest=["webhook.retry", "pagerduty.ack"],
            free_text_embedding=[float("nan"), 0.0],
        )


# --------------------------------------------------------------------------- #
# same_signature_shape / RoutingRecord validation.
# --------------------------------------------------------------------------- #


def test_same_signature_shape_rejects_wrong_length() -> None:
    with pytest.raises(ValueError, match="40-byte"):
        same_signature_shape(b"short", b"also short")


def test_same_signature_shape_is_reflexive_and_symmetric() -> None:
    a = input_signature_hash(
        agent_type_id=AgentTypeId(uuid4()),
        query_text="restart the failed payment webhook",
        workflow_template="incident_response",
        tool_manifest=["webhook.retry"],
    )
    b = input_signature_hash(
        agent_type_id=AgentTypeId(uuid4()),
        query_text="restart the failed payment webhook",
        workflow_template="incident_response",
        tool_manifest=["webhook.retry"],
    )
    assert same_signature_shape(a, a)
    assert same_signature_shape(a, b) == same_signature_shape(b, a)
    assert not same_signature_shape(a, b)  # different agent_type => different structure


def test_routing_record_rejects_malformed_signature() -> None:
    with pytest.raises(ValueError, match="40 bytes"):
        RoutingRecord(
            project_id=ProjectId(uuid4()),
            principal_id=PrincipalId(uuid4()),
            run_id=RunId(uuid4()),
            routed_to="agent-x",
            outcome="positive",
            input_signature=b"too-short",
            free_text_embedding=None,
            recorded_at_ms=0,
        )


def test_routing_record_rejects_empty_routed_to() -> None:
    with pytest.raises(ValueError, match="routed_to"):
        RoutingRecord(
            project_id=ProjectId(uuid4()),
            principal_id=PrincipalId(uuid4()),
            run_id=RunId(uuid4()),
            routed_to="",
            outcome="positive",
            input_signature=_signature(),
            free_text_embedding=None,
            recorded_at_ms=0,
        )


def test_routing_record_rejects_an_outcome_outside_the_vocabulary() -> None:
    """`outcome` arrives from an orchestrator's request body, where the `Literal`
    annotation is a promise the wire cannot keep (the same reason
    `domain.signatures._normalise_tool_manifest` validates a `Sequence[str]`). An
    unchecked third value would be stored and returned as evidence."""
    with pytest.raises(ValueError, match="outcome"):
        RoutingRecord(
            project_id=ProjectId(uuid4()),
            principal_id=PrincipalId(uuid4()),
            run_id=RunId(uuid4()),
            routed_to="agent-x",
            outcome="maybe",  # type: ignore[arg-type]
            input_signature=_signature(),
            free_text_embedding=None,
            recorded_at_ms=0,
        )

    store = InMemoryRoutingRecordStore()
    clock = FakeClock()
    scope = _scope()
    with pytest.raises(ValueError, match="outcome"):
        _record(store, scope, clock, outcome="succeeded-ish")
    # Nothing partial was written before the rejection.
    assert (
        routing_evidence_for(
            store,
            scope,
            query_text="restart the failed payment webhook",
            workflow_template="incident_response",
            tool_manifest=["webhook.retry", "pagerduty.ack"],
        )
        == ()
    )


def _signature() -> bytes:
    return input_signature_hash(
        agent_type_id=AgentTypeId(uuid4()),
        query_text="x",
        workflow_template=None,
        tool_manifest=None,
    )
