"""SDK routes at the authority boundary.

Request bodies contain business facts only. Project, principal, grant,
feedback source, and run-owner facts are bound by authoritative stores; no
body field can shadow them.
"""

from __future__ import annotations

import asyncio
from typing import Any, cast
from uuid import UUID

from fastapi import APIRouter, Request
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse
from pydantic import ValidationError

from tracebed.adapters.ports import (
    AuthorizedQueueWrite,
    OutcomeQueuePayload,
    ProposalQueuePayload,
    TraceQueuePayload,
)
from tracebed.api.deps import (
    AppDeps,
    AppDepsDep,
    DataDep,
    ErasureRequestDep,
    ErasureRequestPort,
    FeedbackDep,
    PipelinePort,
    PrincipalDep,
    authenticate_data_access,
)
from tracebed.api.models import (
    AcceptedOut,
    ErasureRequestIn,
    ErasureRequestOut,
    FeedbackIn,
    InvalidationIn,
    ProposeIn,
    RetrieveIn,
    TraceBatchIn,
    TraceIn,
)
from tracebed.domain.authority import ErasureRequestStatus
from tracebed.domain.enums import Arm, OutcomeCode, ProjectRole
from tracebed.domain.errors import AuthorizationDenied, ConfigError, RetrievalAuditUnavailable
from tracebed.domain.events import RetrieveResult, RunContext, empty_context_block
from tracebed.domain.ids import RunId, mint_run_id
from tracebed.hotpath.budget import Deadline
from tracebed.stores.pg.queue import TOPIC_MEMORY_PROPOSAL, TOPIC_OUTCOME_EVENT, TOPIC_TRACE_EVENT
from tracebed.stores.pg.rows import RetrievalEventInsert

__all__ = ["router"]

router = APIRouter()


def _erasure_store(deps: AppDeps) -> ErasureRequestPort:
    """Resolve the optional E2 store without making an old fixture permissive."""

    store = deps.erasure_requests
    if store is None:
        raise ConfigError("erasure request authority is not configured")
    return store


def _trace_write(trace_in: TraceIn) -> AuthorizedQueueWrite:
    """Build only the persisted trace business payload, never an envelope."""

    return AuthorizedQueueWrite(
        topic=TOPIC_TRACE_EVENT,
        run_id=RunId(trace_in.run_id),
        payload=TraceQueuePayload(seq=trace_in.seq, event=trace_in.event.model_dump(mode="json")),
    )


def _outcome_write(feedback_in: FeedbackIn) -> AuthorizedQueueWrite:
    event = feedback_in.event
    return AuthorizedQueueWrite(
        topic=TOPIC_OUTCOME_EVENT,
        run_id=RunId(feedback_in.run_id),
        payload=OutcomeQueuePayload(
            event_id=event.event_id,
            outcome=event.outcome,
            payload=event.payload,
            occurred_at=event.occurred_at,
        ),
    )


def _proposal_write(propose_in: ProposeIn) -> AuthorizedQueueWrite:
    return AuthorizedQueueWrite(
        topic=TOPIC_MEMORY_PROPOSAL,
        run_id=RunId(propose_in.run_id),
        payload=ProposalQueuePayload(proposal=propose_in.proposal.model_dump(mode="json")),
    )


@router.post(
    "/v1/retrieve",
    response_model=RetrieveResult,
    openapi_extra={
        "requestBody": {
            "required": True,
            "content": {
                "application/json": {"schema": {"$ref": "#/components/schemas/RetrieveIn"}}
            },
        }
    },
)
async def retrieve(request: Request) -> RetrieveResult | JSONResponse:
    """Hold the E2 shared fence through all retrieval work and construction."""

    deps: AppDeps = request.app.state.deps
    deadline: Deadline = request.state.retrieval_deadline
    admission = request.app.state.retrieval_admission
    headers = (request.headers.get("authorization"), request.headers.get("x-api-key"))
    remaining = deadline.remaining_ms()
    if remaining <= 0:
        return JSONResponse(status_code=503, content={"detail": "unavailable"})
    try:
        raw_body = await asyncio.wait_for(request.body(), timeout=remaining / 1000.0)
    except TimeoutError:
        return JSONResponse(status_code=503, content={"detail": "unavailable"})

    def work() -> RetrieveResult:
        access = authenticate_data_access(
            deps, authorization=headers[0], api_key=headers[1], deadline=deadline
        )
        body = RetrieveIn.model_validate_json(raw_body)
        return _retrieve_authorized(body, access, deps, deadline)

    try:
        result = await admission.run(deadline, work)
    except ValidationError as exc:
        errors: list[dict[str, Any]] = []
        for error in exc.errors():
            errors.append({**error, "loc": ("body", *error["loc"])})
        return JSONResponse(status_code=422, content={"detail": jsonable_encoder(errors)})
    if result is None:
        return JSONResponse(status_code=503, content={"detail": "unavailable"})
    return cast(RetrieveResult, result)


def _retrieve_authorized(
    body: RetrieveIn, access: object, deps: AppDeps, deadline: Deadline
) -> RetrieveResult:
    """Runs entirely inside the admission worker after authentication."""
    # The authenticator returns an AccessContext; retain the existing route's
    # authoritative role validation before opening a server-owned run.
    from tracebed.domain.authority import AccessContext

    if type(access) is not AccessContext:
        raise AuthorizationDenied()

    run_id: RunId = mint_run_id(now_ms=deps.clock.now_ms())
    subject_tags = () if body.run_ctx.user_ref is None else (body.run_ctx.user_ref,)
    run_ctx = RunContext(
        query_text=body.run_ctx.query_text,
        workflow_template=body.run_ctx.workflow_template,
        user_ref=body.run_ctx.user_ref,
    )
    pipeline: PipelinePort | None = deps.pipeline

    def _retrieve_while_fenced() -> RetrieveResult:
        start_ms = deps.clock.monotonic_ms()
        context_block = empty_context_block()
        latency_ms = int(deps.clock.monotonic_ms() - start_ms)
        if authorized.audit is None:
            raise RetrievalAuditUnavailable("authorized audit handle is unavailable")
        authorized.audit.record_terminal(
            injections=(),
            row=RetrievalEventInsert(
                run_id=run_id,
                outcome_code=OutcomeCode.EMPTY_RESULT,
                latency_ms=latency_ms,
                embed_latency_ms=None,
                candidates_considered=0,
                top_score=None,
                arm=Arm.MEMORY_ON,
            ),
        )
        return RetrieveResult(
            run_id=run_id.value,
            run_id_origin="server",
            arm=Arm.MEMORY_ON,
            outcome_code=OutcomeCode.EMPTY_RESULT,
            context_block=context_block,
        )

    with deps.retrieval_opener.hold(
        access, run_id, subject_tags=subject_tags, deadline=deadline
    ) as authorized:
        if pipeline is not None:
            if authorized.audit is None:
                raise RetrievalAuditUnavailable("authorized audit handle is unavailable")
            return pipeline.retrieve(
                access.scope,
                run_ctx,
                session_id=body.run_ctx.session_id,
                run_id=run_id,
                deadline=deadline,
                audit=authorized.audit,
            )
        return _retrieve_while_fenced()


@router.post("/v1/trace", response_model=AcceptedOut, status_code=202)
def trace(body: TraceIn, access: DataDep, deps: AppDepsDep) -> AcceptedOut:
    deps.queue.enqueue_many_authorized(access, (_trace_write(body),))
    return AcceptedOut()


@router.post("/v1/trace/batch", response_model=AcceptedOut, status_code=202)
def trace_batch(body: TraceBatchIn, access: DataDep, deps: AppDepsDep) -> AcceptedOut:
    """One producer call preserves its all-or-nothing capacity/run checks."""

    deps.queue.enqueue_many_authorized(access, tuple(_trace_write(event) for event in body.events))
    return AcceptedOut()


@router.post("/v1/feedback", response_model=AcceptedOut, status_code=202)
def feedback(body: FeedbackIn, access: FeedbackDep, deps: AppDepsDep) -> AcceptedOut:
    grant = access.grant_for(ProjectRole.FEEDBACK)
    if (
        grant is None
        or grant.feedback_source is None
        or body.event.adapter.value != grant.feedback_source.value
    ):
        # Deliberately indistinguishable from every other authority denial.
        raise AuthorizationDenied()
    deps.queue.enqueue_many_authorized(access, (_outcome_write(body),))
    return AcceptedOut()


@router.post("/v1/propose_memory", response_model=AcceptedOut, status_code=202)
def propose_memory(body: ProposeIn, access: DataDep, deps: AppDepsDep) -> AcceptedOut:
    deps.queue.enqueue_many_authorized(access, (_proposal_write(body),))
    return AcceptedOut()


@router.post("/v1/invalidation", response_model=AcceptedOut, status_code=202)
def invalidation(body: InvalidationIn, access: DataDep, deps: AppDepsDep) -> AcceptedOut:
    deps.invalidations.insert(access, body.kind, body.payload)
    return AcceptedOut()


@router.post(
    "/v1/erasure-requests",
    response_model=ErasureRequestOut,
    status_code=202,
)
def request_erasure(
    body: ErasureRequestIn,
    access: ErasureRequestDep,
    deps: AppDepsDep,
) -> ErasureRequestStatus:
    """Atomically publish a request only once it and its fences committed.

    The concrete store owns exact replay, closure discovery and all durable
    SQL authority checks.  No raw target or caller-supplied attribution is
    reflected back to the client.
    """

    store = _erasure_store(deps)
    subject_tag = body.subject_tag if body.scope == "subject" else None
    return store.request(access, scope=body.scope, subject_tag=subject_tag)


@router.get(
    "/v1/erasure-requests/{request_id}",
    response_model=ErasureRequestOut,
)
def erasure_request_status(
    request_id: UUID,
    principal: PrincipalDep,
    deps: AppDepsDep,
) -> ErasureRequestStatus:
    """Return only the authenticated caller's bounded request projection."""

    store = _erasure_store(deps)
    return store.status_by_actor(principal, request_id)
