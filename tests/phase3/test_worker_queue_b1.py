"""B1 worker queue authority boundary: no producer capability, no stale lease mutation."""

from __future__ import annotations

from datetime import UTC, datetime
from types import MappingProxyType
from uuid import UUID, uuid4

import pytest

from tracebed.domain.enums import FeedbackSource, ProjectRole
from tracebed.domain.ids import AgentTypeId, PrincipalId, ProjectId, RunId
from tracebed.ingest.outcome_intake import OutcomeIntake
from tracebed.stores.pg.queue import (
    _ACK_SQL,
    _CLAIM_SQL,
    _DEAD_LETTER_SQL,
    _NACK_SQL,
    _REJECT_SQL,
    QueueItem,
    WorkerQueue,
    _row_to_item,
)

pytestmark = pytest.mark.phase3


def _row(*, topic: str = "outcome_event", digests: object = ()) -> dict[str, object]:
    project, run, source, agent, owner, owner_agent = (uuid4() for _ in range(6))
    now = datetime(2026, 1, 1, tzinfo=UTC)
    return {
        "id": 9,
        "project_id": project,
        "topic": topic,
        "payload": {"event_id": str(uuid4()), "outcome": "positive", "payload": {}, "occurred_at": None},
        "priority": 7,
        "attempts": 2,
        "max_attempts": 5,
        "available_at": now,
        "created_at": now,
        "lease_expires_at": now,
        "authority_version": 1,
        "run_id": run,
        "source_principal_id": source,
        "source_agent_type_id": agent,
        "source_grant_id": uuid4(),
        "required_role": "feedback",
        "feedback_source": "verdict",
        "run_owner_principal_id": owner,
        "run_owner_agent_type_id": owner_agent,
        "subject_digests": digests,
    }


def test_worker_queue_is_structurally_consumer_only() -> None:
    assert not hasattr(WorkerQueue, "enqueue")
    assert {"claim", "ack", "nack", "reject", "poison"} <= set(vars(WorkerQueue))


def test_claim_sql_returns_the_entire_v1_authority_envelope_and_mutations_fence_lease() -> None:
    for field in (
        "authority_version", "run_id", "source_principal_id", "source_agent_type_id",
        "source_grant_id", "required_role", "feedback_source", "run_owner_principal_id",
        "run_owner_agent_type_id", "subject_digests", "created_at", "lease_expires_at",
    ):
        assert field in _CLAIM_SQL
        assert field in _DEAD_LETTER_SQL
    for statement in (_ACK_SQL, _NACK_SQL, _REJECT_SQL):
        assert "attempts = %(attempts)s" in statement
        assert "lease_expires_at IS NOT DISTINCT FROM %(lease_expires_at)s" in statement
    assert "lease_expires_at" in _DEAD_LETTER_SQL
    assert "subject_digests" in _DEAD_LETTER_SQL


def test_v1_row_decode_is_exact_and_subject_digests_are_immutable() -> None:
    digest_a, digest_b = bytes(32), bytes([1]) * 32
    item = _row_to_item(_row(digests=(digest_a, digest_b)))
    assert item.authority_version == 1
    assert item.required_role is ProjectRole.FEEDBACK
    assert item.feedback_source is FeedbackSource.VERDICT
    assert item.subject_digests == (digest_a, digest_b)
    assert isinstance(item.payload, MappingProxyType)
    assert item.run_id is not None and type(item.run_id) is RunId
    assert item.project_id is not None and type(item.project_id) is ProjectId
    assert item.source_principal_id is not None and type(item.source_principal_id) is PrincipalId
    assert item.source_agent_type_id is not None and type(item.source_agent_type_id) is AgentTypeId


@pytest.mark.parametrize("digests", [(bytes([1]) * 32, bytes(32)), (bytes(32), bytes(32)), (b"x",)])
def test_v1_row_decode_rejects_unsorted_duplicate_or_wrong_size_subject_digests(digests: tuple[bytes, ...]) -> None:
    with pytest.raises(ValueError, match="subject_digests"):
        _row_to_item(_row(digests=digests))


def test_v1_row_decode_rejects_payload_authority_and_wrong_topic_shape() -> None:
    shadow = _row()
    shadow["payload"] = {**dict(shadow["payload"]), "principal_id": str(uuid4())}
    # Row decoding only accepts an object; consumer business parsers perform
    # topic-exact key checks before side effects.
    assert _row_to_item(shadow).topic == "outcome_event"

    wrong = _row(topic="trace_event")
    wrong["required_role"] = "feedback"
    with pytest.raises(ValueError, match="data authority"):
        _row_to_item(wrong)

    non_wire_enum = _row()
    non_wire_enum["required_role"] = ProjectRole.FEEDBACK
    with pytest.raises(ValueError, match="required_role"):
        _row_to_item(non_wire_enum)


def test_v1_outcome_allows_omitted_occurred_at_and_rejects_payload_authority_shadow() -> None:
    class RejectQueue:
        def __init__(self) -> None:
            self.rejections: list[tuple[QueueItem, str]] = []

        def reject(self, item: QueueItem, reason: str) -> bool:
            self.rejections.append((item, reason))
            return True

    queue = RejectQueue()
    intake = OutcomeIntake(queue, object(), object(), object())  # type: ignore[arg-type]
    without_occurred_at = _row()
    without_occurred_at["payload"] = {
        "event_id": str(uuid4()),
        "outcome": "positive",
        "payload": {},
    }
    assert intake._parse_item(_row_to_item(without_occurred_at)) is not None

    shadow = _row()
    shadow["payload"] = {
        **dict(shadow["payload"]),
        "principal_id": str(uuid4()),
    }
    assert intake._parse_item(_row_to_item(shadow)) is None
    assert queue.rejections[-1][1] == "malformed_business_payload"


def test_queue_item_defaults_remain_explicitly_legacy_only() -> None:
    legacy = QueueItem(1, "trace_event", ProjectId(UUID(int=1)), MappingProxyType({}), 1, 1)
    assert legacy.authority_version == 0
