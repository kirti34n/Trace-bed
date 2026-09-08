"""Phase 3A authority values stay strict before a grant store exists."""

from __future__ import annotations

import json
from collections.abc import Callable, Iterator
from dataclasses import FrozenInstanceError
from datetime import UTC, datetime
from types import MappingProxyType
from uuid import UUID, uuid4

import pytest
from psycopg.types.json import Jsonb, JsonbDumper
from pydantic import ValidationError

from tracebed.adapters.ports import (
    AuthorizedQueueWrite,
    OutcomeQueuePayload,
    ProposalQueuePayload,
    TraceQueuePayload,
)
from tracebed.domain.authority import AccessContext, GrantBinding, RunAuthority
from tracebed.domain.enums import AdapterClass, FeedbackSource, ProjectRole, RunOrigin
from tracebed.domain.errors import (
    ActivityBusy,
    AuthorizationDenied,
    ProjectInactive,
    RunAuthorityDenied,
)
from tracebed.domain.events import MAX_TRACE_SEQ
from tracebed.domain.ids import AgentTypeId, PrincipalId, ProjectId, RunId

pytestmark = pytest.mark.phase3


def _ids() -> tuple[ProjectId, AgentTypeId, PrincipalId, RunId]:
    return ProjectId(uuid4()), AgentTypeId(uuid4()), PrincipalId(uuid4()), RunId(uuid4())


def _grant(role: ProjectRole, source: FeedbackSource | None = None) -> GrantBinding:
    if role is ProjectRole.FEEDBACK:
        source = source or FeedbackSource.VERDICT
    return GrantBinding(grant_id=uuid4(), role=role, feedback_source=source)


def _access(*roles: ProjectRole) -> AccessContext:
    project_id, agent_type_id, principal_id, _run_id = _ids()
    return AccessContext(
        project_id=project_id,
        agent_type_id=agent_type_id,
        principal_id=principal_id,
        grants=tuple(_grant(role) for role in roles),
    )


def test_public_feedback_sources_are_exact_and_implicit_is_not_grantable() -> None:
    assert {source.value for source in FeedbackSource} == {
        "verdict",
        "correction_adapter",
        "downstream",
    }
    assert AdapterClass.IMPLICIT.value == "implicit"
    with pytest.raises(ValueError):
        FeedbackSource("implicit")
    with pytest.raises(TypeError):
        GrantBinding(grant_id=uuid4(), role=ProjectRole.FEEDBACK, feedback_source="implicit")  # type: ignore[arg-type]


def test_grant_and_context_require_exact_runtime_types_and_role_source_pairing() -> None:
    project_id, agent_type_id, principal_id, run_id = _ids()
    with pytest.raises(TypeError):
        GrantBinding(grant_id=ProjectId(uuid4()), role=ProjectRole.DATA)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        GrantBinding(grant_id=uuid4(), role="data")  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        GrantBinding(grant_id=uuid4(), role=ProjectRole.FEEDBACK)
    with pytest.raises(ValueError):
        GrantBinding(
            grant_id=uuid4(), role=ProjectRole.DATA, feedback_source=FeedbackSource.VERDICT
        )
    with pytest.raises(TypeError):
        AccessContext(
            project_id=run_id,  # type: ignore[arg-type]
            agent_type_id=agent_type_id,
            principal_id=principal_id,
            grants=(_grant(ProjectRole.DATA),),
        )
    with pytest.raises(TypeError):
        AccessContext(
            project_id=project_id,
            agent_type_id=agent_type_id,
            principal_id=principal_id,
            grants=[_grant(ProjectRole.DATA)],  # type: ignore[arg-type]
        )
    with pytest.raises(ValueError):
        AccessContext(
            project_id=project_id,
            agent_type_id=agent_type_id,
            principal_id=principal_id,
            grants=(),
        )


def test_access_context_rejects_duplicate_roles_and_projects_scope_immutably() -> None:
    project_id, agent_type_id, principal_id, _run_id = _ids()
    with pytest.raises(ValueError, match="duplicate"):
        AccessContext(
            project_id=project_id,
            agent_type_id=agent_type_id,
            principal_id=principal_id,
            grants=(_grant(ProjectRole.DATA), _grant(ProjectRole.DATA)),
        )
    duplicate_id = uuid4()
    with pytest.raises(ValueError, match="duplicate active grant ids"):
        AccessContext(
            project_id=project_id,
            agent_type_id=agent_type_id,
            principal_id=principal_id,
            grants=(
                GrantBinding(grant_id=duplicate_id, role=ProjectRole.DATA),
                GrantBinding(
                    grant_id=duplicate_id,
                    role=ProjectRole.FEEDBACK,
                    feedback_source=FeedbackSource.VERDICT,
                ),
            ),
        )

    access = AccessContext(
        project_id=project_id,
        agent_type_id=agent_type_id,
        principal_id=principal_id,
        grants=(_grant(ProjectRole.DATA), _grant(ProjectRole.FEEDBACK, FeedbackSource.DOWNSTREAM)),
    )
    assert access.roles == frozenset({ProjectRole.DATA, ProjectRole.FEEDBACK})
    assert access.grant_for(ProjectRole.ADMIN) is None
    assert access.feedback_source is FeedbackSource.DOWNSTREAM
    assert access.scope.project_id is project_id
    assert access.scope.agent_type_id is agent_type_id
    assert access.scope.principal_id is principal_id
    with pytest.raises(FrozenInstanceError):
        access.project_id = ProjectId(uuid4())  # type: ignore[misc]
    with pytest.raises(TypeError):
        access.grant_for("data")  # type: ignore[arg-type]


def test_run_authority_is_a_strict_immutable_owner_binding() -> None:
    project_id, agent_type_id, principal_id, run_id = _ids()
    authority = RunAuthority(project_id, run_id, principal_id, agent_type_id, RunOrigin.RETRIEVE)
    assert authority.principal_id is principal_id
    with pytest.raises(TypeError):
        RunAuthority(  # type: ignore[arg-type]
            project_id,
            ProjectId(run_id.value),
            principal_id,
            agent_type_id,
            RunOrigin.RETRIEVE,
        )
    with pytest.raises(FrozenInstanceError):
        authority.run_id = RunId(uuid4())  # type: ignore[misc]


def test_authority_errors_are_opaque_and_have_their_required_semantics() -> None:
    assert str(AuthorizationDenied()) == str(ProjectInactive()) == "access denied"
    assert str(RunAuthorityDenied()) == "not found"
    assert str(ActivityBusy()) == "activity busy"
    assert (AuthorizationDenied.status_code, ProjectInactive.status_code) == (403, 403)
    assert RunAuthorityDenied.status_code == 404
    assert ActivityBusy.status_code == 503 and ActivityBusy.retryable is True
    for error in (AuthorizationDenied, ProjectInactive, RunAuthorityDenied, ActivityBusy):
        with pytest.raises(TypeError):
            error("secret-id")  # type: ignore[call-arg]


def _run_end_event(*, status: str = "ok") -> dict[str, object]:
    return {
        "type": "run_end",
        "ts": "2026-01-01T00:00:00+00:00",
        "payload": {"status": status},
    }


def _proposal() -> dict[str, object]:
    return {
        "mem_type": "lesson",
        "content": "Keep the lock held until the terminal write commits.",
        "claimed_scope": "agent_type",
    }


def test_authorized_queue_payloads_are_deeply_frozen_and_have_only_business_wires() -> None:
    _project_id, _agent_type_id, _principal_id, run_id = _ids()
    raw_event = _run_end_event()
    raw_event["payload"] = {"status": "ok", "values": [1, {"ok": True}]}
    trace = TraceQueuePayload(seq=0, event=raw_event)
    write = AuthorizedQueueWrite(
        topic="trace_event",
        run_id=run_id,
        payload=trace,
        available_at=datetime(2026, 1, 1, tzinfo=UTC),
    )
    raw_event["payload"] = "mutated"
    assert trace.event["payload"] != "mutated"
    assert isinstance(trace.event, MappingProxyType)
    nested = trace.event["payload"]
    assert isinstance(nested, MappingProxyType)
    with pytest.raises(TypeError):
        trace.event["new"] = "value"  # type: ignore[index]
    with pytest.raises(TypeError):
        nested["new"] = "value"  # type: ignore[index]
    with pytest.raises(FrozenInstanceError):
        write.topic = "other"  # type: ignore[misc]
    assert set(trace.as_mapping()) == {"seq", "event"}
    trace_wire = trace.to_json_mapping()
    event_wire = trace_wire["event"]
    assert isinstance(event_wire, dict)
    assert set(event_wire) == {"type", "ts", "payload"}
    assert set(AuthorizedQueueWrite.__dataclass_fields__) == {
        "topic",
        "run_id",
        "payload",
        "priority",
        "available_at",
    }


@pytest.mark.parametrize(
    ("payload", "expected_keys"),
    [
        (
            TraceQueuePayload(seq=0, event=_run_end_event()),
            {"seq", "event"},
        ),
        (
            OutcomeQueuePayload(
                event_id=UUID("00000000-0000-0000-0000-000000000001"),
                outcome="positive",
                payload={"status": "confirmed", "metrics": [1, {"score": 0.5}]},
                occurred_at=datetime(2026, 1, 1, tzinfo=UTC),
            ),
            {"event_id", "outcome", "payload", "occurred_at"},
        ),
        (ProposalQueuePayload(proposal=_proposal()), {"proposal"}),
    ],
)
def test_queue_payload_json_wires_are_detached_and_psycopg_jsonb_safe(
    payload: TraceQueuePayload | OutcomeQueuePayload | ProposalQueuePayload,
    expected_keys: set[str],
) -> None:
    first = payload.to_json_mapping()
    assert set(first) == expected_keys
    json.dumps(first)
    jsonb = Jsonb(first)
    assert JsonbDumper(dict).dump(jsonb.obj) is not None

    if isinstance(payload, TraceQueuePayload):
        first["event"]["payload"]["mutated"] = True  # type: ignore[index]
    elif isinstance(payload, OutcomeQueuePayload):
        first["payload"]["metrics"] = ["mutated"]  # type: ignore[index]
    else:
        first["proposal"]["content"] = "mutated"  # type: ignore[index]

    second = payload.to_json_mapping()
    assert second != first
    assert "mutated" not in json.dumps(second)
    assert second == payload.to_json_mapping()


def test_authorized_queue_write_exposes_a_detached_json_payload_snapshot() -> None:
    _project_id, _agent_type_id, _principal_id, run_id = _ids()
    write = AuthorizedQueueWrite(
        topic="trace_event",
        run_id=run_id,
        payload=TraceQueuePayload(seq=0, event=_run_end_event()),
    )
    wire = write.to_json_payload()
    wire["event"]["payload"]["changed"] = True  # type: ignore[index]
    assert "changed" not in json.dumps(write.to_json_payload())


def test_trace_payload_allows_opaque_business_status_adapter_and_weight() -> None:
    _project_id, _agent_type_id, _principal_id, run_id = _ids()
    payload = TraceQueuePayload(
        seq=7,
        event={
            "type": "tool_result",
            "ts": "2026-01-01T00:00:00+00:00",
            "payload": {"status": "ok", "adapter": "implicit", "weight": 0.5},
        },
    )
    write = AuthorizedQueueWrite(topic="trace_event", run_id=run_id, payload=payload)
    wire_event = write.to_json_payload()["event"]
    assert isinstance(wire_event, dict)
    wire_payload = wire_event["payload"]
    assert isinstance(wire_payload, dict)
    assert wire_payload == {
        "status": "ok",
        "adapter": "implicit",
        "weight": 0.5,
    }


@pytest.mark.parametrize("seq", [True, -1, MAX_TRACE_SEQ + 1])
def test_trace_payload_enforces_the_shared_exact_sequence_bound(seq: object) -> None:
    with pytest.raises((TypeError, ValueError)):
        TraceQueuePayload(seq=seq, event=_run_end_event())  # type: ignore[arg-type]


def test_outcome_payload_has_stable_business_controls_and_opaque_metrics() -> None:
    event_id = uuid4()
    payload = OutcomeQueuePayload(
        event_id=event_id,
        outcome="positive",
        payload={"status": "confirmed", "adapter": "downstream", "diff_ratio": 0.25},
        occurred_at=datetime(2026, 1, 1, tzinfo=UTC),
    )
    assert payload.as_mapping() == {
        "event_id": str(event_id),
        "outcome": "positive",
        "payload": {"status": "confirmed", "adapter": "downstream", "diff_ratio": 0.25},
        "occurred_at": "2026-01-01T00:00:00+00:00",
    }
    assert set(payload.as_mapping()) == {"event_id", "outcome", "payload", "occurred_at"}
    with pytest.raises(TypeError):
        payload.as_mapping()["new"] = "value"  # type: ignore[index]


def test_proposal_payload_validates_the_real_extra_forbid_model() -> None:
    payload = ProposalQueuePayload(proposal=_proposal())
    assert set(payload.as_mapping()) == {"proposal"}
    wire_proposal = payload.to_json_mapping()["proposal"]
    assert isinstance(wire_proposal, dict)
    assert wire_proposal["content"] == _proposal()["content"]
    with pytest.raises(ValidationError):
        ProposalQueuePayload(proposal={**_proposal(), "adapter": "implicit"})


@pytest.mark.parametrize("field", ["adapter", "source", "weight", "r", "w", "diff_ratio"])
def test_outcome_payload_rejects_untyped_control_fields(field: str) -> None:
    kwargs = {
        "event_id": uuid4(),
        "outcome": "positive",
        "payload": {},
        field: "untrusted",
    }
    with pytest.raises(TypeError):
        OutcomeQueuePayload(**kwargs)  # type: ignore[arg-type]


def test_trace_and_proposal_payloads_reject_extra_control_fields() -> None:
    with pytest.raises(ValidationError):
        TraceQueuePayload(seq=0, event={**_run_end_event(), "adapter": "implicit"})
    with pytest.raises(TypeError, match="event payload"):
        TraceQueuePayload(seq=0, event={**_run_end_event(), "payload": ["not", "a", "mapping"]})
    with pytest.raises(ValidationError):
        ProposalQueuePayload(proposal={**_proposal(), "weight": 1})


def test_authorized_queue_write_rejects_topic_payload_mismatch_and_unknown_topic() -> None:
    _project_id, _agent_type_id, _principal_id, run_id = _ids()
    outcome = OutcomeQueuePayload(event_id=uuid4(), outcome="negative", payload={})
    with pytest.raises(TypeError):
        AuthorizedQueueWrite(topic="trace_event", run_id=run_id, payload=outcome)
    with pytest.raises(ValueError):
        AuthorizedQueueWrite(topic="unknown", run_id=run_id, payload=outcome)


def test_queue_payloads_reject_cyclic_and_unbounded_opaque_json() -> None:
    cyclic: dict[str, object] = {}
    cyclic["again"] = cyclic
    with pytest.raises(ValueError, match="cyclic"):
        OutcomeQueuePayload(event_id=uuid4(), outcome="positive", payload=cyclic)

    deep: dict[str, object] = {}
    cursor = deep
    for _index in range(17):
        next_value: dict[str, object] = {}
        cursor["next"] = next_value
        cursor = next_value
    with pytest.raises(ValueError, match="deeply"):
        OutcomeQueuePayload(event_id=uuid4(), outcome="positive", payload=deep)
    with pytest.raises(ValueError, match="string is invalid"):
        OutcomeQueuePayload(
            event_id=uuid4(),
            outcome="positive",
            payload={"metric": "x" * 32_769},
        )
    with pytest.raises(ValueError, match="finite"):
        OutcomeQueuePayload(event_id=uuid4(), outcome="positive", payload={"score": float("nan")})


@pytest.mark.parametrize("value", [-(2**63), 2**63 - 1])
def test_portable_json_int64_boundaries_are_serializable(value: int) -> None:
    trace = TraceQueuePayload(
        seq=0,
        event={
            "type": "tool_result",
            "ts": "2026-01-01T00:00:00+00:00",
            "payload": {"counter": value},
        },
    )
    outcome = OutcomeQueuePayload(event_id=uuid4(), outcome="positive", payload={"counter": value})
    proposal = ProposalQueuePayload(proposal=_proposal())
    for carrier in (trace, outcome, proposal):
        wire = carrier.to_json_mapping()
        assert JsonbDumper(dict).dump(Jsonb(wire).obj) is not None
        json.dumps(wire)


@pytest.mark.parametrize(
    "value",
    [
        pytest.param(-(2**63) - 1, id="below-int64"),
        pytest.param(2**63, id="above-int64"),
        pytest.param(10**5000, id="python-unbounded-int"),
    ],
)
def test_portable_json_integers_reject_outside_signed_64_bit_range(value: int) -> None:
    with pytest.raises(ValueError, match="portable range"):
        TraceQueuePayload(
            seq=0,
            event={
                "type": "tool_result",
                "ts": "2026-01-01T00:00:00+00:00",
                "payload": {"counter": value},
            },
        )
    with pytest.raises(ValueError, match="portable range"):
        OutcomeQueuePayload(event_id=uuid4(), outcome="positive", payload={"counter": value})


@pytest.mark.parametrize("invalid", ["nul\x00value", "high\ud800surrogate", "low\udc00surrogate"])
def test_queue_carriers_reject_nul_and_lone_surrogate_values(invalid: str) -> None:
    with pytest.raises(ValueError, match="invalid"):
        TraceQueuePayload(
            seq=0,
            event={
                "type": "tool_result",
                "ts": "2026-01-01T00:00:00+00:00",
                "payload": {"opaque": invalid},
            },
        )
    with pytest.raises(ValueError, match="invalid"):
        OutcomeQueuePayload(event_id=uuid4(), outcome="positive", payload={"opaque": invalid})
    with pytest.raises(ValueError, match="invalid"):
        ProposalQueuePayload(proposal={**_proposal(), "content": invalid, "subject_tag": invalid})


@pytest.mark.parametrize("invalid_key", ["nul\x00key", "high\ud800key", "low\udc00key"])
def test_trace_and_outcome_reject_nul_and_lone_surrogate_opaque_keys(invalid_key: str) -> None:
    with pytest.raises(ValueError, match="key is invalid"):
        TraceQueuePayload(
            seq=0,
            event={
                "type": "tool_result",
                "ts": "2026-01-01T00:00:00+00:00",
                "payload": {invalid_key: "opaque"},
            },
        )
    with pytest.raises(ValueError, match="key is invalid"):
        OutcomeQueuePayload(event_id=uuid4(), outcome="positive", payload={invalid_key: "opaque"})


def test_all_queue_carriers_preserve_valid_astral_unicode_in_json_wires() -> None:
    astral = "business \U0001f680"
    trace = TraceQueuePayload(
        seq=0,
        event={
            "type": "tool_result",
            "ts": "2026-01-01T00:00:00+00:00",
            "payload": {astral: astral},
        },
    )
    outcome = OutcomeQueuePayload(event_id=uuid4(), outcome="positive", payload={astral: astral})
    proposal = ProposalQueuePayload(proposal={**_proposal(), "content": astral, "subject_tag": astral})
    for carrier in (trace, outcome, proposal):
        wire = carrier.to_json_mapping()
        assert astral in json.dumps(wire, ensure_ascii=False)
        assert JsonbDumper(dict).dump(Jsonb(wire).obj) is not None


def _non_json_cycle() -> object:
    value: dict[str, object] = {}
    value["itself"] = value
    return value


@pytest.mark.parametrize(
    "bad_value_factory",
    [
        lambda: {"set"},
        lambda: frozenset({"frozen"}),
        uuid4,
        lambda: datetime(2026, 1, 1, tzinfo=UTC),
        lambda: b"bytes",
        lambda: {1: "non-string key"},
        _non_json_cycle,
    ],
)
def test_trace_and_outcome_raw_opaque_payloads_reject_non_json_before_model_coercion(
    bad_value_factory: Callable[[], object],
) -> None:
    bad_value = bad_value_factory()
    with pytest.raises((TypeError, ValueError)):
        TraceQueuePayload(
            seq=0,
            event={
                "type": "tool_result",
                "ts": datetime(2026, 1, 1, tzinfo=UTC),
                "payload": {"opaque": bad_value},
            },
        )

    bad_value = bad_value_factory()
    with pytest.raises((TypeError, ValueError)):
        OutcomeQueuePayload(event_id=uuid4(), outcome="positive", payload={"opaque": bad_value})


def test_raw_opaque_generators_are_rejected_without_iteration() -> None:
    consumed: list[bool] = []

    def values() -> Iterator[object]:
        consumed.append(True)
        yield "must not be consumed"

    with pytest.raises(TypeError):
        TraceQueuePayload(
            seq=0,
            event={
                "type": "tool_result",
                "ts": datetime(2026, 1, 1, tzinfo=UTC),
                "payload": {"opaque": values()},
            },
        )
    assert consumed == []

    with pytest.raises(TypeError):
        OutcomeQueuePayload(
            event_id=uuid4(),
            outcome="positive",
            payload={"opaque": values()},
        )
    assert consumed == []


def test_authorized_queue_write_rejects_wrong_id_bool_priority_and_naive_time() -> None:
    _project_id, _agent_type_id, _principal_id, run_id = _ids()
    payload = TraceQueuePayload(seq=0, event=_run_end_event())
    with pytest.raises(TypeError):
        AuthorizedQueueWrite(topic="trace_event", run_id=UUID(run_id.value.hex), payload=payload)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        AuthorizedQueueWrite(topic="trace_event", run_id=run_id, payload=payload, priority=True)
    with pytest.raises(ValueError):
        AuthorizedQueueWrite(
            topic="trace_event", run_id=run_id, payload=payload, available_at=datetime(2026, 1, 1)
        )
