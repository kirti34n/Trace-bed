"""One-shot owner-side agent onboarding; deliberately not an HTTP surface.

The normal API process never imports or constructs this store.  It is only
reachable through the operator console command, whose DSN and credentials are
environment values rather than request inputs.
"""

from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass
from typing import Literal
from uuid import UUID, uuid4

import psycopg
from psycopg_pool import ConnectionPool

from tracebed.domain.canonical import sha256_hex
from tracebed.domain.clock import Clock, SystemClock
from tracebed.domain.enums import FeedbackSource, ProjectRole
from tracebed.domain.ids import AgentTypeId, PrincipalId, ProjectId
from tracebed.stores.pg.pool import create_pool

__all__ = ["OnboardingError", "OnboardingGrant", "OwnerOnboardingStore", "main"]


class OnboardingError(RuntimeError):
    """A deliberately opaque owner-operation failure."""


@dataclass(frozen=True, slots=True)
class OnboardingGrant:
    """One explicit role request; feedback has exactly one public source."""

    role: ProjectRole
    feedback_source: FeedbackSource | None = None

    def __post_init__(self) -> None:
        if type(self.role) is not ProjectRole:
            raise TypeError("role must be a ProjectRole")
        if self.role is ProjectRole.FEEDBACK:
            if type(self.feedback_source) is not FeedbackSource:
                raise ValueError("feedback grant requires a feedback source")
        elif self.feedback_source is not None:
            raise ValueError("only feedback grants may have a feedback source")


@dataclass(frozen=True, slots=True)
class OwnerOnboardingStore:
    """The atomic owner transaction for a new registered agent principal."""

    pool: ConnectionPool
    clock: Clock

    def create_agent(
        self,
        *,
        project_id: ProjectId,
        agent_type_name: str,
        principal_kind: Literal["oidc_sub", "api_key"],
        external_ref: str,
        api_key_secret: str | None,
        grants: tuple[OnboardingGrant, ...],
    ) -> tuple[PrincipalId, AgentTypeId]:
        if type(project_id) is not ProjectId:
            raise TypeError("project_id must be a ProjectId")
        if type(agent_type_name) is not str or not agent_type_name:
            raise ValueError("agent type name is required")
        if principal_kind not in {"oidc_sub", "api_key"}:
            raise ValueError("unsupported principal kind")
        if type(external_ref) is not str or not external_ref:
            raise ValueError("external reference is required")
        if type(grants) is not tuple or not grants:
            raise ValueError("at least one explicit grant is required")
        if any(type(grant) is not OnboardingGrant for grant in grants):
            raise TypeError("grants must contain OnboardingGrant values")
        if len({grant.role for grant in grants}) != len(grants):
            raise ValueError("roles must be explicitly unique")
        if principal_kind == "api_key":
            if type(api_key_secret) is not str or not api_key_secret:
                raise ValueError("api key secret is required")
            key_hash: str | None = sha256_hex(api_key_secret.encode("utf-8"))
        elif api_key_secret is not None:
            raise ValueError("oidc onboarding cannot accept an api key secret")
        else:
            key_hash = None

        principal_id = PrincipalId(uuid4())
        agent_type_id = AgentTypeId(uuid4())
        now = self.clock.now()
        try:
            with self.pool.connection() as conn, conn.transaction():
                conn.execute(
                    """
                    INSERT INTO agent_type (agent_type_id, project_id, name, created_at)
                    VALUES (%(agent_type_id)s, %(project_id)s, %(name)s, %(created_at)s)
                    """,
                    {
                        "agent_type_id": agent_type_id.value,
                        "project_id": project_id.value,
                        "name": agent_type_name,
                        "created_at": now,
                    },
                )
                conn.execute(
                    """
                    INSERT INTO principal
                        (principal_id, kind, external_ref, key_hash, created_at)
                    VALUES
                        (%(principal_id)s, %(kind)s, %(external_ref)s, %(key_hash)s, %(created_at)s)
                    """,
                    {
                        "principal_id": principal_id.value,
                        "kind": principal_kind,
                        "external_ref": external_ref,
                        "key_hash": key_hash,
                        "created_at": now,
                    },
                )
                conn.execute(
                    """
                    INSERT INTO agent_registration
                        (principal_id, project_id, agent_type_id, registered_at)
                    VALUES
                        (%(principal_id)s, %(project_id)s, %(agent_type_id)s, %(registered_at)s)
                    """,
                    {
                        "principal_id": principal_id.value,
                        "project_id": project_id.value,
                        "agent_type_id": agent_type_id.value,
                        "registered_at": now,
                    },
                )
                for grant in grants:
                    conn.execute(
                        """
                        INSERT INTO principal_grant
                            (grant_id, principal_id, project_id, role, feedback_source, granted_at)
                        VALUES
                            (%(grant_id)s, %(principal_id)s, %(project_id)s, %(role)s,
                             %(feedback_source)s, %(granted_at)s)
                        """,
                        {
                            "grant_id": uuid4(),
                            "principal_id": principal_id.value,
                            "project_id": project_id.value,
                            "role": grant.role.value,
                            "feedback_source": (
                                grant.feedback_source.value
                                if grant.feedback_source is not None
                                else None
                            ),
                            "granted_at": now,
                        },
                    )
        except psycopg.Error:
            # Never interpolate an external ref, DSN, or API secret into a
            # console error.  The context manager has rolled the whole unit
            # back before this opaque exception leaves the owner boundary.
            raise OnboardingError("onboarding failed") from None
        return principal_id, agent_type_id


def _required_env(name: str) -> str:
    value = os.environ.get(name)
    if value is None or not value:
        raise OnboardingError("onboarding configuration is incomplete")
    return value


def _parse_grants(raw: str) -> tuple[OnboardingGrant, ...]:
    try:
        decoded = json.loads(raw)
        if not isinstance(decoded, list):
            raise ValueError
        grants = tuple(
            OnboardingGrant(
                role=ProjectRole(entry["role"]),
                feedback_source=(
                    FeedbackSource(entry["feedback_source"])
                    if entry.get("feedback_source") is not None
                    else None
                ),
            )
            for entry in decoded
            if isinstance(entry, dict)
        )
    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
        raise OnboardingError("onboarding configuration is invalid") from None
    if not grants or len(grants) != len(decoded):
        raise OnboardingError("onboarding configuration is invalid")
    return grants


def main() -> None:
    """Run once from an owner-controlled shell; it never opens a listener."""

    pool: ConnectionPool | None = None
    try:
        dsn = _required_env("TB_ONBOARDING_PG_DSN")
        project_id = ProjectId(UUID(_required_env("TB_ONBOARDING_PROJECT_ID")))
        agent_type_name = _required_env("TB_ONBOARDING_AGENT_TYPE")
        raw_principal_kind = _required_env("TB_ONBOARDING_PRINCIPAL_KIND")
        if raw_principal_kind == "oidc_sub":
            principal_kind: Literal["oidc_sub", "api_key"] = "oidc_sub"
            external_ref = _required_env("TB_ONBOARDING_OIDC_SUB")
            secret: str | None = None
        elif raw_principal_kind == "api_key":
            principal_kind = "api_key"
            external_ref = _required_env("TB_ONBOARDING_API_KEY_ID")
            secret = _required_env("TB_ONBOARDING_API_KEY_SECRET")
        else:
            raise OnboardingError("onboarding configuration is invalid")
        grants = _parse_grants(_required_env("TB_ONBOARDING_GRANTS"))
        pool = create_pool(dsn)
        principal_id, agent_type_id = OwnerOnboardingStore(pool, SystemClock()).create_agent(
            project_id=project_id,
            agent_type_name=agent_type_name,
            principal_kind=principal_kind,
            external_ref=external_ref,
            api_key_secret=secret,
            grants=grants,
        )
    except Exception:
        # The command is the secret boundary too: a connection failure can
        # otherwise render a DSN or server diagnostic into an operator shell.
        print("onboarding failed", file=sys.stderr)
        raise SystemExit(1) from None
    finally:
        if pool is not None:
            pool.close()
    # Principal and agent-type ids are public references, unlike any secret.
    print(json.dumps({"principal_id": str(principal_id.value), "agent_type_id": str(agent_type_id.value)}))
