"""`/v1/*` SDK-facing routes (PHASE0-CONTRACT.md §9.3).

Landed during the parallel build as `api/routes.py`; renamed to the contract's
§1/§9.3 name at integration (C-28).

Every handler follows the one legal shape (invariant 4): authenticate ->
resolve scope -> pass `scope.project_id` to `queue`/`telemetry`, never to
anything read off the request body. Every enqueue-only route 202s and writes
nothing synchronously (§14 api-auth DO-NOT list) — `ingest.trace_writer` /
`ingest.outcome_intake` (owned by a different chunk) are what turn a queued
envelope into a row.
"""

from __future__ import annotations

from fastapi import APIRouter

from tracebed.api.deps import AppDepsDep, PipelinePort, ScopeDep
from tracebed.api.models import (
    AcceptedOut,
    FeedbackIn,
    InvalidationIn,
    ProposeIn,
    RetrieveIn,
    TraceBatchIn,
    TraceIn,
)
from tracebed.domain.enums import Arm, OutcomeCode
from tracebed.domain.events import RetrieveResult, RunContext, empty_context_block
from tracebed.domain.ids import RunId, mint_run_id
from tracebed.domain.scope import ProjectScope
from tracebed.stores.pg.queue import TOPIC_MEMORY_PROPOSAL, TOPIC_OUTCOME_EVENT, TOPIC_TRACE_EVENT

__all__ = ["router"]


router = APIRouter()


def _trace_envelope(scope: ProjectScope, trace_in: TraceIn) -> dict[str, object]:
    """The exact §9.5 `TOPIC_TRACE_EVENT` shape: scope ids injected server-side,
    never read off the body (invariant 4)."""
    return {
        "project_id": str(scope.project_id),
        "principal_id": str(scope.principal_id),
        "agent_type_id": str(scope.agent_type_id),
        "run_id": str(trace_in.run_id),
        "seq": trace_in.seq,
        "event": trace_in.event.model_dump(mode="json"),
    }


def _outcome_envelope(scope: ProjectScope, feedback_in: FeedbackIn) -> dict[str, object]:
    """The exact §9.5 `TOPIC_OUTCOME_EVENT` shape."""
    return {
        "project_id": str(scope.project_id),
        "principal_id": str(scope.principal_id),
        "run_id": str(feedback_in.run_id),
        "event": feedback_in.event.model_dump(mode="json"),
    }


def _proposal_envelope(scope: ProjectScope, propose_in: ProposeIn) -> dict[str, object]:
    """The exact §9.5 `TOPIC_MEMORY_PROPOSAL` shape."""
    return {
        "project_id": str(scope.project_id),
        "principal_id": str(scope.principal_id),
        "run_id": str(propose_in.run_id),
        "proposal": propose_in.proposal.model_dump(mode="json"),
    }


@router.post("/v1/retrieve", response_model=RetrieveResult)
def retrieve(
    body: RetrieveIn,
    scope: ScopeDep,
    deps: AppDepsDep,
) -> RetrieveResult:
    """Runs the hot read plane (`hotpath.pipeline.Pipeline`) when the
    deployment has one, and otherwise answers exactly as Phase 0 did.

    `deps.pipeline` is `None` for any app built without a Postgres pool — every
    `TestClient` app in this suite, and any process started before the stores
    exist. That path mints a UUIDv7 `run_id`, arm `memory_on`,
    `outcome_code=empty_result`, and the exact-header empty context block, then
    records the `retrieval_event` row every retrieval writes, including the ones
    that returned nothing (contract §8's `TelemetryPort` docstring: this is what
    distinguishes abstention from a timeout). `Pipeline` writes its own
    `retrieval_event`, so exactly one row is written on either path — never two.

    `body.agent_type` is READ BY NOTHING here (invariant 4). The authoritative
    agent type is `scope.agent_type_id`, derived from the caller's
    `agent_registration` row; `Pipeline.retrieve` has no parameter that would
    accept the body's claim, which is what makes the rule structural rather than
    a convention this handler has to remember.

    `RunContext.tool_manifest` is deliberately not populated from the wire
    body: PHASE0-CONTRACT.md §9.3/§3.5 (C-05) say it rides on the `run_start`
    trace event's payload, never on `/v1/retrieve`'s own request.
    """
    pipeline: PipelinePort | None = deps.pipeline
    if pipeline is not None:
        run_ctx = RunContext(
            query_text=body.run_ctx.query_text,
            workflow_template=body.run_ctx.workflow_template,
            user_ref=body.run_ctx.user_ref,
        )
        return pipeline.retrieve(scope, run_ctx, session_id=body.run_ctx.session_id)

    start_ms = deps.clock.monotonic_ms()
    run_id: RunId = mint_run_id(now_ms=deps.clock.now_ms())
    context_block = empty_context_block()
    latency_ms = int(deps.clock.monotonic_ms() - start_ms)
    deps.telemetry.record_retrieval(
        scope.project_id,
        run_id,
        outcome_code=OutcomeCode.EMPTY_RESULT,
        latency_ms=latency_ms,
        embed_latency_ms=None,
        candidates_considered=0,
        top_score=None,
        arm=Arm.MEMORY_ON,
    )
    return RetrieveResult(
        run_id=run_id.value,
        run_id_origin="server",
        arm=Arm.MEMORY_ON,
        outcome_code=OutcomeCode.EMPTY_RESULT,
        context_block=context_block,
    )


@router.post("/v1/trace", response_model=AcceptedOut, status_code=202)
def trace(
    body: TraceIn,
    scope: ScopeDep,
    deps: AppDepsDep,
) -> AcceptedOut:
    deps.queue.enqueue(TOPIC_TRACE_EVENT, scope.project_id, _trace_envelope(scope, body))
    return AcceptedOut()


@router.post("/v1/trace/batch", response_model=AcceptedOut, status_code=202)
def trace_batch(
    body: TraceBatchIn,
    scope: ScopeDep,
    deps: AppDepsDep,
) -> AcceptedOut:
    """C-21: the SDK flusher's endpoint; `TraceBatchIn.events` is capped at
    `MAX_TRACE_BATCH_EVENTS` (500) by the pydantic model itself, so an
    oversized body is a 422 before this handler ever runs."""
    for event_in in body.events:
        deps.queue.enqueue(TOPIC_TRACE_EVENT, scope.project_id, _trace_envelope(scope, event_in))
    return AcceptedOut()


@router.post("/v1/feedback", response_model=AcceptedOut, status_code=202)
def feedback(
    body: FeedbackIn,
    scope: ScopeDep,
    deps: AppDepsDep,
) -> AcceptedOut:
    """`FeedbackEvent` (domain/events.py) has no `weight` field anywhere in
    its definition and forbids extra keys — a `weight` in the body is a 422
    before this handler runs (invariant 8), never a value this route reads."""
    deps.queue.enqueue(TOPIC_OUTCOME_EVENT, scope.project_id, _outcome_envelope(scope, body))
    return AcceptedOut()


@router.post("/v1/propose_memory", response_model=AcceptedOut, status_code=202)
def propose_memory(
    body: ProposeIn,
    scope: ScopeDep,
    deps: AppDepsDep,
) -> AcceptedOut:
    deps.queue.enqueue(TOPIC_MEMORY_PROPOSAL, scope.project_id, _proposal_envelope(scope, body))
    return AcceptedOut()


@router.post("/v1/invalidation", response_model=AcceptedOut, status_code=202)
def invalidation(
    body: InvalidationIn,
    scope: ScopeDep,
    deps: AppDepsDep,
) -> AcceptedOut:
    """C-31. Writes one `invalidation_event` row scoped to `scope.project_id`.

    Synchronous rather than enqueued: §14's queue DO-NOT list forbids a fourth
    topic, and §14's "routes 202 + enqueue — do NOT write trace/outcome rows
    synchronously" names the two high-volume tables this is not. As merged this
    route returned 202 "accepted" while discarding the body entirely, which is
    the one failure mode a 202 must never have — every future integration test
    would have passed by accident.
    """
    deps.invalidations.insert_invalidation_event(scope.project_id, body.kind, body.payload)
    return AcceptedOut()
