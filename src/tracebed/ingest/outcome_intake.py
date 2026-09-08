"""Outcome intake: TOPIC_OUTCOME_EVENT consumer (PHASE0-CONTRACT.md §11, PHASE-0 Task 15).

Attach-by-run_id, regardless of arrival order: `outcome_event` has no foreign
key to `trace_index` (contract §11/§14) -- a feedback event for a run whose
trace has not landed yet (or never will) still gets a durable row, and any
later query joins the two tables logically on `(project_id, run_id)`. This
consumer never reads `trace_index` at all.

Invariant 8, structurally: `r` is derived from `outcome` (positive/negative
-> 1.0/0.0) and the deduction of a zero weight (`w_zero`) is derived from
`scoring.adapter_weights`[adapter] -- BOTH server-side, from the authenticated
ingest context and `TracebedSettings`, never from caller input.
`FeedbackEvent` (`domain/events.py`) has no `weight` field at all
(`extra="forbid"`), so a raw queue payload naming one fails Pydantic
validation here exactly the way it would 422 at the API edge -- see
`run_once`'s malformed-item path.

Identity comes from the envelope, never from the event body: `principal_id`
and `project_id` are injected server-side from `ProjectScope` when the route
enqueues (§9.5), and this module reads them from there. A `principal_id` or
`project_id` key inside `event.payload` is inert business data -- it is
carried to the row's jsonb and never consulted.
"""

from __future__ import annotations

import logging
from contextlib import nullcontext
from datetime import datetime
from typing import TYPE_CHECKING, Protocol, cast
from uuid import UUID

from pydantic import BaseModel, ConfigDict, ValidationError

from tracebed.domain.enums import AdapterClass, ProjectRole
from tracebed.domain.errors import ActivityBusy, ErasureFenced, ErasureSnapshotStale
from tracebed.domain.events import FeedbackEvent
from tracebed.domain.ids import PrincipalId, ProjectId, RunId
from tracebed.stores.pg.activity import ActivityGate
from tracebed.stores.pg.erasure import ErasureSnapshotGuard
from tracebed.stores.pg.queue import TOPIC_OUTCOME_EVENT, compute_backoff
from tracebed.stores.pg.rows import OutcomeEventInsert, OutcomeReplayConflict

if TYPE_CHECKING:
    from tracebed.adapters.ports import QueueConsumerPort, WorkerQueueConsumerPort
    from tracebed.domain.clock import Clock
    from tracebed.domain.config import TracebedSettings
    from tracebed.stores.pg.queue import QueueItem

__all__ = ["OutcomeIntake", "OutcomeRepoPort"]

logger = logging.getLogger(__name__)


class _OutcomeQueueEnvelope(BaseModel):
    """One `TOPIC_OUTCOME_EVENT` row's payload (contract §9.5). `event` is
    the real `FeedbackEvent` model, so a `weight` key anywhere at that
    level -- exactly the wire shape `POST /v1/feedback` would 422 on --
    fails this same validation here, offline, with no HTTP layer involved."""

    model_config = ConfigDict(extra="forbid")

    project_id: UUID
    principal_id: UUID
    run_id: UUID
    event: FeedbackEvent


class _OutcomeBusinessPayload(BaseModel):
    """Version-one outcome body; identity and adapter are QueueItem facts."""

    model_config = ConfigDict(extra="forbid")

    event_id: UUID
    outcome: str
    payload: dict[str, object]
    occurred_at: datetime | None = None


class OutcomeRepoPort(Protocol):
    """The one `Repo` method this consumer calls (contract §5.1). A Protocol,
    not the concrete `Repo` type contract §11 names, for the same offline
    -testability reason `ingest.trace_writer.TraceRepoPort` is -- see that
    module's docstring; logged once there, not duplicated as a second
    contract_gap entry for the same tension."""

    def insert_outcome_event(self, project_id: ProjectId, row: OutcomeEventInsert) -> bool: ...


class OutcomeIntake:
    """Consumes `TOPIC_OUTCOME_EVENT` (contract §11 / PHASE-0 Task 15)."""

    def __init__(
        self,
        queue: WorkerQueueConsumerPort,
        repo: OutcomeRepoPort,
        clock: Clock,
        settings: TracebedSettings,
        *,
        activity: ActivityGate | None = None,
        erasure_guard: ErasureSnapshotGuard | None = None,
    ) -> None:
        self._queue = queue
        self._repo = repo
        self._clock = clock
        self._settings = settings
        self._activity = activity
        self._erasure_guard = erasure_guard

    def run_once(self, max_batch: int | None = None) -> int:
        """Claim, validate, derive `r`/`w_zero`, insert (dedup on `event_id`
        via the repo's `ON CONFLICT ... DO NOTHING`), ack. Returns the count
        of items successfully handled -- including exact `event_id` replays,
        which insert zero rows (contract: "replay same event_id -> exactly
        one row") but are still a successful, ackable outcome for this
        consumer, not an error to retry.

        A refused item (fails `_OutcomeQueueEnvelope` validation -- e.g. a
        `weight` key on the event, an unrecognised `adapter`, a naive
        `occurred_at` -- or an envelope that disagrees with the queue row it
        rode in on) and an item whose insert raised are `nack`'d with
        `compute_backoff(item.attempts)` and never counted as processed;
        nothing is inserted for either. Failures are isolated per item: one
        bad row must not abandon the rest of a claimed batch to its lease
        timeout.
        """
        n = max_batch if max_batch is not None else self._settings.queue.batch_size
        items = self._queue.claim(TOPIC_OUTCOME_EVENT, n)
        processed = 0
        for item in items:
            envelope = self._parse_item(item)
            if envelope is None:
                continue

            row = self._to_row(envelope, item)
            try:
                gate = self._activity.shared(item.project_id) if self._activity is not None else nullcontext()
                with gate:
                    try:
                        if item.authority_version == 1 and self._erasure_guard is not None:
                            actual = self._erasure_guard.assert_snapshot(
                                item.project_id, row.run_id, item.subject_digests
                            )
                            if actual != item.subject_digests:
                                raise ErasureSnapshotStale()
                        # The queue row's `project_id` column is the scoping authority
                        # (§5.3); `_parse_item` has already proved the envelope agrees
                        # with it, so this cannot be steered by the payload.
                        self._repo.insert_outcome_event(item.project_id, row)
                        # ACK is also a durable queue side effect.  Keep it in
                        # the same shared activity window as the snapshot and
                        # outcome insert so an exclusive erasure request cannot
                        # commit between persistence and settlement.
                        self._ack(item)
                    except (ErasureFenced, ErasureSnapshotStale):
                        # Keep a stale/fenced NACK under the same shared
                        # lifetime as its guard just like an ACK.
                        self._nack(item)
                        continue
                    except OutcomeReplayConflict:
                        logger.warning("outcome_intake: refusing divergent replay item %s", item.id)
                        self._reject(item, "outcome_replay_conflict")
                        continue
                    except Exception:
                        logger.exception(
                            "outcome_intake: failed inserting outcome for run %s", envelope.run_id
                        )
                        self._nack(item)
                        continue
            except ActivityBusy:
                # Fence/stale work must be reclaimed from the propagated row;
                # it is not a malformed business event and cannot be dead-lettered.
                self._nack(item)
                continue
            processed += 1
        return processed

    def _parse_item(self, item: QueueItem) -> _OutcomeQueueEnvelope | None:
        """Envelope validation + the two checks Pydantic cannot make.
        `None` means the item was refused and already nacked."""
        try:
            if item.authority_version == 1:
                if (
                    item.run_id is None
                    or item.source_principal_id is None
                    or item.source_agent_type_id is None
                    or item.source_grant_id is None
                    or item.feedback_source is None
                    or item.required_role is not ProjectRole.FEEDBACK
                    or item.run_owner_principal_id is None
                    or item.run_owner_agent_type_id is None
                    or set(item.payload) not in (
                        {"event_id", "outcome", "payload"},
                        {"event_id", "outcome", "payload", "occurred_at"},
                    )
                ):
                    raise ValueError("v1 outcome authority or business shape is invalid")
                business = _OutcomeBusinessPayload.model_validate(dict(item.payload))
                if business.outcome not in {"positive", "negative"}:
                    raise ValueError("outcome is invalid")
                adapter = AdapterClass(item.feedback_source.value)
                feedback = FeedbackEvent(
                    adapter=adapter,
                    outcome=business.outcome,
                    event_id=business.event_id,
                    payload=business.payload,
                    occurred_at=business.occurred_at,
                )
                envelope = _OutcomeQueueEnvelope(
                    project_id=item.project_id.value,
                    principal_id=item.source_principal_id.value,
                    run_id=item.run_id.value,
                    event=feedback,
                )
            else:
                envelope = _OutcomeQueueEnvelope.model_validate(dict(item.payload))
        except ValidationError:
            logger.warning("outcome_intake: refusing malformed outcome_event item %s", item.id)
            self._reject(item, "malformed_business_payload")
            return None
        except ValueError:
            logger.warning("outcome_intake: refusing invalid v1 outcome item %s", item.id)
            self._reject(item, "malformed_business_payload")
            return None

        if item.authority_version == 0 and ProjectId(envelope.project_id) != item.project_id:
            # A payload-derived project_id must never decide which tenant's
            # partition a row lands in (invariant 4).
            logger.warning(
                "outcome_intake: item %s envelope project_id disagrees with the queue row", item.id
            )
            self._nack(item)
            return None

        occurred_at = envelope.event.occurred_at
        if occurred_at is not None and (
            occurred_at.tzinfo is None or occurred_at.utcoffset() is None
        ):
            # `outcome_event.occurred_at` is `timestamptz`. A naive value is
            # silently reinterpreted in the server session's timezone, which
            # moves the event by hours and is invisible afterwards. Every
            # other wire timestamp is rejected when naive (`_EventBase.ts`);
            # `FeedbackEvent.occurred_at` has no such validator (cross-chunk
            # issue), so the rejection lives here.
            logger.warning("outcome_intake: refusing item %s: naive occurred_at", item.id)
            self._reject(item, "malformed_business_payload")
            return None
        return envelope

    def _to_row(self, envelope: _OutcomeQueueEnvelope, item: QueueItem) -> OutcomeEventInsert:
        feedback = envelope.event
        # r ∈ {1.0, 0.0}: the ONLY two values this maps to (contract §11);
        # `outcome` is a pydantic `Literal["positive", "negative"]`, so no
        # third value can ever reach this branch.
        r = 1.0 if feedback.outcome == "positive" else 0.0
        # w is derived server-side from the AUTHENTICATED adapter class,
        # never accepted from the wire (invariant 8) -- `w` itself is not a
        # schema column (C-10); only whether it is non-positive is recorded,
        # as `payload["_w_zero"]` (Repo's job, contract §5.1).
        weight = self._settings.scoring.adapter_weights.get(feedback.adapter.value)
        now: datetime = self._clock.now()
        if item.authority_version == 1:
            if (
                item.run_id is None
                or item.source_principal_id is None
                or item.source_agent_type_id is None
                or item.source_grant_id is None
                or item.feedback_source is None
                or item.run_owner_principal_id is None
                or item.run_owner_agent_type_id is None
                or item.created_at is None
            ):
                raise ValueError("v1 outcome item lacks authoritative fields")
            return OutcomeEventInsert(
                event_id=feedback.event_id,
                run_id=item.run_id,
                principal_id=item.source_principal_id,
                adapter=AdapterClass(item.feedback_source.value),
                r=r,
                w_zero=not (weight is not None and weight > 0.0),
                payload=feedback.payload,
                occurred_at=feedback.occurred_at
                if feedback.occurred_at is not None
                else item.created_at,
                arrived_at=now,
                occurred_at_is_derived=feedback.occurred_at is None,
                authority_version=1,
                source_agent_type_id=item.source_agent_type_id,
                source_grant_id=item.source_grant_id,
                feedback_source=item.feedback_source,
                run_owner_principal_id=item.run_owner_principal_id,
                run_owner_agent_type_id=item.run_owner_agent_type_id,
                subject_digests=item.subject_digests,
            )
        return OutcomeEventInsert(
            event_id=feedback.event_id,
            run_id=RunId(envelope.run_id),
            principal_id=PrincipalId(envelope.principal_id),
            adapter=feedback.adapter,
            r=r,
            # Not `== 0.0`: an adapter class absent from the configured
            # weights, or configured with a negative weight, must fail closed
            # to "do not score" rather than default to a real learning rate or
            # to an inverted one (invariant 8: a guessed reward is worse than
            # none). `not > 0` also catches NaN.
            w_zero=not (weight is not None and weight > 0.0),
            payload=feedback.payload,
            occurred_at=feedback.occurred_at if feedback.occurred_at is not None else now,
            arrived_at=now,
        )

    def _ack(self, item: QueueItem) -> None:
        if item.authority_version == 1:
            self._queue.ack(item)
        else:
            cast("QueueConsumerPort", self._queue).ack(item.id)

    def _nack(self, item: QueueItem) -> None:
        if item.authority_version == 1:
            self._queue.nack(item, compute_backoff(item.attempts))
        else:
            cast("QueueConsumerPort", self._queue).nack(item.id, compute_backoff(item.attempts))

    def _reject(self, item: QueueItem, reason: str) -> None:
        if item.authority_version == 1:
            self._queue.reject(item, reason)
            return
        self._nack(item)
