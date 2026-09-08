"""Atomic, idempotent project provisioning on the dedicated admin pool.

The ordinary application pool is intentionally never accepted here: its role
is forced through RLS and has no DDL privilege.  A project is useful only
after its registry row, all partitions, and the reserved project KEK exist, so
this module makes those three writes one transaction on one owner connection.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Final
from uuid import UUID, uuid4

import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Json
from psycopg_pool import ConnectionPool

from tracebed.crypto.shred import MasterKeyProvider, SubjectKeyManager, SubjectKeyStore
from tracebed.crypto.subject_digest import subject_digest
from tracebed.domain.clock import Clock
from tracebed.domain.errors import ProjectProvisioningConflict
from tracebed.domain.ids import ProjectId
from tracebed.stores.pg.partitions import create_project_partitions
from tracebed.stores.pg.rows import SubjectKeyRow

__all__ = ["ProjectProvisioner"]

# A stable advisory-lock namespace.  The second key is Postgres's stable
# hashtext result for the already-hashed idempotency key; raw client material
# is never sent to or persisted by Postgres.
_PROJECT_PROVISION_LOCK_NAMESPACE: Final = 1_407_020_401
_LOCK_SQL: Final = "SELECT pg_advisory_xact_lock(%(namespace)s, hashtext(%(key_hash)s))"
_EXISTING_SQL: Final = (
    "SELECT project_id, provisioning_request_hash FROM project "
    "WHERE provisioning_key_hash = %(key_hash)s"
)
_INSERT_PROJECT_SQL: Final = (
    "INSERT INTO project (project_id, name, status, retention_policy, created_at, "
    "provisioning_key_hash, provisioning_request_hash) "
    "VALUES (%(project_id)s, %(name)s, %(status)s, %(retention_policy)s, %(created_at)s, "
    "%(key_hash)s, %(request_hash)s)"
)
_SET_PROJECT_SCOPE_SQL: Final = (
    "SELECT set_config('tracebed.project_id', %(project_id)s::text, true)"
)
_GET_SUBJECT_KEY_SQL: Final = (
    "SELECT subject_tag, subject_digest, wrap_version, key_id, wrapped_kek, created_at, destroyed_at "
    "FROM subject_key WHERE project_id = %(project_id)s AND subject_tag = %(subject_tag)s"
)
_GET_SUBJECT_KEY_BY_DIGEST_SQL: Final = (
    "SELECT subject_tag, subject_digest, wrap_version, key_id, wrapped_kek, created_at, destroyed_at "
    "FROM subject_key WHERE project_id = %(project_id)s AND subject_digest = %(subject_digest)s"
)
_INSERT_SUBJECT_KEY_SQL: Final = (
    "INSERT INTO subject_key (project_id, subject_tag, subject_digest, wrap_version, key_id, wrapped_kek, created_at) "
    "VALUES (%(project_id)s, %(subject_tag)s, %(subject_digest)s, 1, %(key_id)s, %(wrapped_kek)s, %(created_at)s)"
)
_INSERT_SUBJECT_KEY_V2_SQL: Final = (
    "INSERT INTO subject_key (project_id, subject_tag, subject_digest, wrap_version, key_id, wrapped_kek, created_at) "
    "VALUES (%(project_id)s, NULL, %(subject_digest)s, 2, %(key_id)s, %(wrapped_kek)s, %(created_at)s)"
)


class _ConnectionSubjectKeyStore(SubjectKeyStore):
    """A `SubjectKeyStore` bound to the provisioning transaction's connection.

    `Repo` deliberately opens a fresh scoped application connection for each
    operation.  That is correct for request work but would make KEK creation a
    separate commit here, so the provisioner uses this tiny connection-bound
    adapter while retaining `SubjectKeyManager` as the sole owner of wrapping
    semantics.
    """

    def __init__(self, conn: psycopg.Connection[Any], clock: Clock) -> None:
        self._conn = conn
        self._clock = clock

    def get_subject_key(self, project_id: ProjectId, subject_tag: str) -> SubjectKeyRow | None:
        with self._conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                _GET_SUBJECT_KEY_SQL,
                {"project_id": project_id, "subject_tag": subject_tag},
            )
            row = cur.fetchone()
        if row is None:
            return None
        return SubjectKeyRow(
            subject_tag=row["subject_tag"],
            subject_digest=bytes(row["subject_digest"]),
            wrap_version=int(row["wrap_version"]),
            key_id=row["key_id"],
            wrapped_kek=bytes(row["wrapped_kek"]),
            created_at=row["created_at"],
            destroyed_at=row["destroyed_at"],
        )

    def insert_subject_key(
        self, project_id: ProjectId, subject_tag: str, key_id: UUID, wrapped_kek: bytes
    ) -> None:
        self._conn.execute(
            _INSERT_SUBJECT_KEY_SQL,
            {
                "project_id": project_id,
                "subject_tag": subject_tag,
                "subject_digest": subject_digest(project_id, subject_tag),
                "key_id": key_id,
                "wrapped_kek": wrapped_kek,
                "created_at": self._clock.now(),
            },
        )

    def get_subject_key_by_digest(
        self, project_id: ProjectId, digest: bytes
    ) -> SubjectKeyRow | None:
        with self._conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                _GET_SUBJECT_KEY_BY_DIGEST_SQL,
                {"project_id": project_id, "subject_digest": digest},
            )
            row = cur.fetchone()
        if row is None:
            return None
        return SubjectKeyRow(
            subject_tag=row["subject_tag"],
            subject_digest=bytes(row["subject_digest"]),
            wrap_version=int(row["wrap_version"]),
            key_id=row["key_id"],
            wrapped_kek=bytes(row["wrapped_kek"]),
            created_at=row["created_at"],
            destroyed_at=row["destroyed_at"],
        )

    def insert_subject_key_v2(
        self, project_id: ProjectId, digest: bytes, key_id: UUID, wrapped_kek: bytes
    ) -> None:
        self._conn.execute(
            _INSERT_SUBJECT_KEY_V2_SQL,
            {
                "project_id": project_id,
                "subject_digest": digest,
                "key_id": key_id,
                "wrapped_kek": wrapped_kek,
                "created_at": self._clock.now(),
            },
        )


class ProjectProvisioner:
    """Create or replay one project provisioning request atomically."""

    def __init__(self, pool: ConnectionPool, master: MasterKeyProvider, clock: Clock) -> None:
        self._pool = pool
        self._master = master
        self._clock = clock

    def provision_project(
        self,
        *,
        name: str,
        retention_policy: Mapping[str, object] | None,
        idempotency_key_hash: str,
        request_hash: str,
    ) -> ProjectId:
        """Provision the project or return the result of an identical replay.

        The transaction-scoped advisory lock serializes callers using the same
        key before either reads the registry.  The partial unique index added
        by migration 0007 remains a durable backstop against accidental paths
        that bypass this method.
        """
        with self._pool.connection() as conn, conn.transaction():
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute(
                    _LOCK_SQL,
                    {
                        "namespace": _PROJECT_PROVISION_LOCK_NAMESPACE,
                        "key_hash": idempotency_key_hash,
                    },
                )
                cur.execute(_EXISTING_SQL, {"key_hash": idempotency_key_hash})
                existing = cur.fetchone()
                if existing is not None:
                    if existing["provisioning_request_hash"] != request_hash:
                        raise ProjectProvisioningConflict("idempotency key request mismatch")
                    return ProjectId(existing["project_id"])

                project_id = ProjectId(uuid4())
                cur.execute(
                    _INSERT_PROJECT_SQL,
                    {
                        "project_id": project_id,
                        "name": name,
                        "status": "active",
                        "retention_policy": Json(dict(retention_policy))
                        if retention_policy is not None
                        else None,
                        "created_at": self._clock.now(),
                        "key_hash": idempotency_key_hash,
                        "request_hash": request_hash,
                    },
                )

            # This connection may be a table-owning, NOBYPASSRLS admin role:
            # FORCE RLS therefore still applies to its newly-created
            # `subject_key` partition.  Set the scope before any partitioned
            # access and make it transaction-local so a pool checkout cannot
            # retain a previous project's scope.
            with conn.cursor() as cur:
                cur.execute(_SET_PROJECT_SCOPE_SQL, {"project_id": str(project_id)})
            create_project_partitions(conn, project_id)
            keys = SubjectKeyManager(
                store=_ConnectionSubjectKeyStore(conn, self._clock),
                master=self._master,
                clock=self._clock,
            )
            keys.ensure_project_kek(project_id)
            return project_id
