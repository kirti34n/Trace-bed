"""Offline Phase 3A grant dependency matrix; legacy ScopeDep stays untouched."""

from __future__ import annotations

from dataclasses import dataclass, field
from types import SimpleNamespace
from uuid import uuid4

import pytest

from tracebed.adapters.identity import Principal
from tracebed.adapters.ports import AccessResolverPort
from tracebed.api.deps import (
    get_access,
    get_admin_access,
    get_any_role_access,
    get_data_access,
    get_export_access,
    get_feedback_access,
)
from tracebed.domain.authority import AccessContext, GrantBinding
from tracebed.domain.enums import FeedbackSource, ProjectRole
from tracebed.domain.errors import AuthorizationDenied
from tracebed.domain.ids import AgentTypeId, PrincipalId, ProjectId

pytestmark = pytest.mark.phase3


def _access(role: ProjectRole, *, principal_id: PrincipalId | None = None) -> AccessContext:
    source = FeedbackSource.VERDICT if role is ProjectRole.FEEDBACK else None
    return AccessContext(
        project_id=ProjectId(uuid4()),
        agent_type_id=AgentTypeId(uuid4()),
        principal_id=principal_id or PrincipalId(uuid4()),
        grants=(GrantBinding(uuid4(), role, source),),
    )


def _principal(kind: str = "api_key", *, principal_id: PrincipalId | None = None) -> Principal:
    return Principal(
        principal_id=principal_id or PrincipalId(uuid4()),
        kind=kind,  # type: ignore[arg-type]
        external_ref="authority-test",
    )


@dataclass
class _Resolver:
    result: AccessContext | object
    calls: list[PrincipalId] = field(default_factory=list)

    def resolve_access(self, principal_id: PrincipalId) -> AccessContext:
        self.calls.append(principal_id)
        return self.result  # type: ignore[return-value]


def _request(resolver: object | None) -> object:
    return SimpleNamespace(
        app=SimpleNamespace(state=SimpleNamespace(deps=SimpleNamespace(access_resolver=resolver)))
    )


def test_get_access_fails_closed_without_a_grant_resolver_or_from_a_malformed_adapter() -> None:
    principal_id = PrincipalId(uuid4())
    for kind in ("api_key", "oidc_sub"):
        principal = _principal(kind, principal_id=principal_id)
        for resolver in (None, _Resolver(object())):
            with pytest.raises(AuthorizationDenied) as denied:
                get_access(_request(resolver), principal)  # type: ignore[arg-type]
            assert str(denied.value) == "access denied"


@pytest.mark.parametrize(
    ("granted", "guard"),
    [
        (ProjectRole.DATA, get_data_access),
        (ProjectRole.FEEDBACK, get_feedback_access),
        (ProjectRole.ADMIN, get_admin_access),
        (ProjectRole.EXPORT, get_export_access),
    ],
)
def test_each_guard_allows_only_its_exact_role(
    granted: ProjectRole, guard: object
) -> None:
    access = _access(granted)
    assert get_any_role_access(access) is access
    for required, candidate in (
        (ProjectRole.DATA, get_data_access),
        (ProjectRole.FEEDBACK, get_feedback_access),
        (ProjectRole.ADMIN, get_admin_access),
        (ProjectRole.EXPORT, get_export_access),
    ):
        if required is granted:
            assert candidate(access) is access  # type: ignore[operator]
        else:
            with pytest.raises(AuthorizationDenied) as denied:
                candidate(access)  # type: ignore[operator]
            assert str(denied.value) == "access denied"


def test_credential_kind_never_becomes_a_role_and_resolver_receives_the_principal() -> None:
    principal_id = PrincipalId(uuid4())
    access = _access(ProjectRole.DATA, principal_id=principal_id)
    resolver = _Resolver(access)
    assert isinstance(resolver, AccessResolverPort)
    for kind in ("api_key", "oidc_sub"):
        principal = _principal(kind, principal_id=principal_id)
        resolved = get_access(_request(resolver), principal)  # type: ignore[arg-type]
        assert resolved is access
        assert get_data_access(resolved) is access
        with pytest.raises(AuthorizationDenied):
            get_admin_access(resolved)
    assert resolver.calls == [principal_id, principal_id]


def test_resolved_access_must_belong_to_the_authenticated_principal_for_both_kinds() -> None:
    authenticated = PrincipalId(uuid4())
    resolved_elsewhere = _access(ProjectRole.DATA, principal_id=PrincipalId(uuid4()))
    resolver = _Resolver(resolved_elsewhere)
    for kind in ("api_key", "oidc_sub"):
        with pytest.raises(AuthorizationDenied) as denied:
            get_access(_request(resolver), _principal(kind, principal_id=authenticated))  # type: ignore[arg-type]
        assert str(denied.value) == "access denied"
    assert resolver.calls == [authenticated, authenticated]


def test_feedback_authority_is_the_only_role_with_a_public_source() -> None:
    feedback = _access(ProjectRole.FEEDBACK)
    data = _access(ProjectRole.DATA)
    assert get_feedback_access(feedback).feedback_source is FeedbackSource.VERDICT
    assert get_data_access(data).feedback_source is None
    with pytest.raises(AuthorizationDenied):
        get_feedback_access(data)
