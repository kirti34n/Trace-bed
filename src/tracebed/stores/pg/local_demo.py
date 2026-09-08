"""Owner-store replay verification for the explicitly local demo utility."""

from __future__ import annotations

from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool

from tracebed.domain.canonical import sha256_hex
from tracebed.domain.clock import Clock
from tracebed.domain.enums import ProjectRole
from tracebed.domain.ids import AgentTypeId, PrincipalId, ProjectId
from tracebed.stores.pg.onboarding import OnboardingGrant, OwnerOnboardingStore

__all__ = ["LocalDemoOwnerStore"]

_LOCK_NAMESPACE = 1_487_220_611


class LocalDemoOwnerStore:
    """Idempotently bind the one fixed demo API principal to its project."""

    def __init__(self, pool: ConnectionPool, clock: Clock) -> None:
        self._pool = pool
        self._clock = clock

    def ensure_api_principal(
        self, project_id: ProjectId, api_key_id: str, api_key_secret: str, agent_name: str
    ) -> tuple[PrincipalId, AgentTypeId]:
        # This session lock spans the delegated onboarding transaction as
        # well, so two owner invocations cannot both observe an absent key.
        with self._pool.connection() as lock_conn:
            lock_conn.execute(
                "SELECT pg_advisory_lock(%s, hashtext(%s))", (_LOCK_NAMESPACE, api_key_id)
            )
            try:
                with lock_conn.transaction(), lock_conn.cursor(row_factory=dict_row) as cursor:
                    cursor.execute(
                        "SELECT principal_id, key_hash FROM principal WHERE external_ref = %s AND kind = 'api_key' AND revoked_at IS NULL",
                        (api_key_id,),
                    )
                    principal = cursor.fetchone()
                    if principal is not None:
                        if principal["key_hash"] != sha256_hex(api_key_secret.encode("utf-8")):
                            raise ValueError("local demo principal conflicts")
                        cursor.execute(
                            """
                            SELECT registration.agent_type_id, agent_type.name
                            FROM agent_registration AS registration
                            JOIN agent_type ON agent_type.agent_type_id = registration.agent_type_id
                            WHERE registration.principal_id = %s AND registration.project_id = %s
                            """,
                            (principal["principal_id"], project_id.value),
                        )
                        registration = cursor.fetchone()
                        if registration is None or registration["name"] != agent_name:
                            raise ValueError("local demo principal conflicts")
                        cursor.execute(
                            "SELECT role FROM principal_grant WHERE principal_id = %s AND project_id = %s AND revoked_at IS NULL",
                            (principal["principal_id"], project_id.value),
                        )
                        if {row["role"] for row in cursor.fetchall()} != {
                            "data",
                            "admin",
                            "export",
                        }:
                            raise ValueError("local demo principal conflicts")
                        return PrincipalId(principal["principal_id"]), AgentTypeId(
                            registration["agent_type_id"]
                        )
                return OwnerOnboardingStore(self._pool, self._clock).create_agent(
                    project_id=project_id,
                    agent_type_name=agent_name,
                    principal_kind="api_key",
                    external_ref=api_key_id,
                    api_key_secret=api_key_secret,
                    grants=(
                        OnboardingGrant(ProjectRole.DATA),
                        OnboardingGrant(ProjectRole.ADMIN),
                        OnboardingGrant(ProjectRole.EXPORT),
                    ),
                )
            finally:
                lock_conn.execute(
                    "SELECT pg_advisory_unlock(%s, hashtext(%s))", (_LOCK_NAMESPACE, api_key_id)
                )
