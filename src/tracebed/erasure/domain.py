"""Strict, non-public values used by the E3 erasure executor.

The values in this module are deliberately unable to carry a target subject,
project locator, trace ref, credential, or lease token in a printable status
shape.  Those values stay inside the database adapter and destructive store
ports.  This keeps the executor's logs and CLI output from accidentally
turning compliance metadata into another data store.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Final, Literal
from uuid import UUID

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

__all__ = [
    "ERASURE_PHASES",
    "ERASURE_RESULT_CODES",
    "ERASURE_STEPS",
    "EXTERNAL_STORE_CODES",
    "ErasureLease",
    "ErasureSettings",
    "ExternalWork",
    "StepOutcome",
    "StoreResult",
    "canonical_manifest",
]

ErasurePhase = Literal[
    "requested",
    "fenced",
    "crypto_erased",
    "primary_purged",
    "external_purged",
    "verified",
    "scope_complete",
]
ErasureStep = Literal[
    "fence",
    "crypto",
    "postgres",
    "queue",
    "valkey",
    "trace_store",
    "vector",
    "graph",
    "verify",
    "complete",
]
ErasureResult = Literal["succeeded", "retryable", "blocked"]
ErasureResultCode = Literal[
    "ok",
    "already_absent",
    "not_configured",
    "embedded_primary",
    "closure_changed",
    "dependency_unavailable",
    "dependency_timeout",
    "verification_failed",
    "configuration_mismatch",
    "store_refused",
    "catalog_mismatch",
    "unsafe_path",
    "integrity_failed",
    "operator_resumed",
]
ExternalStoreCode = Literal[
    "trace_fs_v1",
    "trace_s3_v1",
    "valkey_v1",
    "vector_postgres",
    "vector_qdrant",
    "vector_none",
    "graph_postgres",
    "graph_age",
    "graph_none",
]

ERASURE_PHASES: Final[frozenset[str]] = frozenset(ErasurePhase.__args__)  # type: ignore[attr-defined]
ERASURE_STEPS: Final[frozenset[str]] = frozenset(ErasureStep.__args__)  # type: ignore[attr-defined]
ERASURE_RESULT_CODES: Final[frozenset[str]] = frozenset(ErasureResultCode.__args__)  # type: ignore[attr-defined]
EXTERNAL_STORE_CODES: Final[frozenset[str]] = frozenset(ExternalStoreCode.__args__)  # type: ignore[attr-defined]


def _exact(value: object, expected: type[object], name: str) -> None:
    if type(value) is not expected:
        raise TypeError(f"{name} must be an exact {expected.__name__}")


def _uuid(value: object, name: str) -> UUID:
    _exact(value, UUID, name)
    return value  # type: ignore[return-value]


def canonical_manifest(codes: tuple[str, ...] | list[str]) -> tuple[ExternalStoreCode, ...]:
    """Validate the immutable four-store E3 manifest.

    PostgreSQL's ``COLLATE \"C\"`` ordering is bytewise ASCII for this
    vocabulary, which is exactly Python's Unicode ordering here.  We require
    the caller to supply the canonical order rather than sorting it for them:
    a changed/tampered manifest is an operator block, not a convenience fix.
    """

    if type(codes) not in {tuple, list}:
        raise TypeError("manifest must be a concrete tuple or list")
    raw = tuple(codes)
    if len(raw) != 4 or any(type(code) is not str for code in raw):
        raise ValueError("manifest shape is invalid")
    if raw != tuple(sorted(raw)) or len(set(raw)) != len(raw):
        raise ValueError("manifest is not canonical")
    groups = (
        {"trace_fs_v1", "trace_s3_v1"},
        {"valkey_v1"},
        {"vector_postgres", "vector_qdrant", "vector_none"},
        {"graph_postgres", "graph_age", "graph_none"},
    )
    if any(sum(code in group for code in raw) != 1 for group in groups):
        raise ValueError("manifest must contain exactly one code from every store category")
    return raw  # type: ignore[return-value]


@dataclass(frozen=True, slots=True)
class ErasureLease:
    """One database-authorized, short-lived E3 lease.

    The token is intentionally not repr-suppressed because this is an internal
    non-loggable carrier.  The executor never renders it and the bounded CLI
    status type never contains a lease.
    """

    project_id: UUID = field(repr=False)
    request_id: UUID = field(repr=False)
    scope: Literal["subject", "project"]
    phase: ErasurePhase
    generation: int
    lease_token: UUID = field(repr=False)
    lease_expires_at: datetime
    closure_revision: int

    def __post_init__(self) -> None:
        _uuid(self.project_id, "project_id")
        _uuid(self.request_id, "request_id")
        _uuid(self.lease_token, "lease_token")
        if self.scope not in {"subject", "project"} or self.phase not in ERASURE_PHASES:
            raise ValueError("lease phase or scope is invalid")
        if (
            type(self.generation) is not int
            or isinstance(self.generation, bool)
            or self.generation < 1
        ):
            raise ValueError("lease generation is invalid")
        if (
            type(self.closure_revision) is not int
            or isinstance(self.closure_revision, bool)
            or self.closure_revision < 1
        ):
            raise ValueError("lease closure revision is invalid")
        _exact(self.lease_expires_at, datetime, "lease_expires_at")


@dataclass(frozen=True, slots=True)
class ExternalWork:
    """One opaque, lease-claimed destructive external target."""

    work_id: UUID = field(repr=False)
    target_kind: Literal["run", "project"]
    target_id: UUID | None = field(repr=False)
    work_revision: int
    attempt: int

    def __post_init__(self) -> None:
        _uuid(self.work_id, "work_id")
        if self.target_kind not in {"run", "project"}:
            raise ValueError("external work target kind is invalid")
        if self.target_kind == "run":
            _uuid(self.target_id, "target_id")
        elif self.target_id is not None:
            raise ValueError("project work must not carry a target id")
        if (
            type(self.work_revision) is not int
            or isinstance(self.work_revision, bool)
            or self.work_revision < 1
        ):
            raise ValueError("external work revision is invalid")
        if type(self.attempt) is not int or isinstance(self.attempt, bool) or self.attempt < 1:
            raise ValueError("external work attempt is invalid")


@dataclass(frozen=True, slots=True)
class StoreResult:
    """Opaque delete-and-verify outcome from one destructive adapter."""

    result_code: ErasureResultCode
    affected_rows: int
    postcondition_digest: bytes

    def __post_init__(self) -> None:
        if self.result_code not in ERASURE_RESULT_CODES:
            raise ValueError("store result code is invalid")
        if (
            type(self.affected_rows) is not int
            or isinstance(self.affected_rows, bool)
            or self.affected_rows < 0
        ):
            raise ValueError("store affected rows is invalid")
        if type(self.postcondition_digest) is not bytes or len(self.postcondition_digest) != 32:
            raise ValueError("store postcondition digest is invalid")


@dataclass(frozen=True, slots=True)
class StepOutcome:
    """One bounded state transition result returned to the runner."""

    phase: ErasurePhase
    affected_rows: int
    closure_revision: int
    result_code: ErasureResultCode

    def __post_init__(self) -> None:
        if self.phase not in ERASURE_PHASES or self.result_code not in ERASURE_RESULT_CODES:
            raise ValueError("step outcome is invalid")
        if (
            type(self.affected_rows) is not int
            or isinstance(self.affected_rows, bool)
            or self.affected_rows < 0
        ):
            raise ValueError("step outcome affected rows is invalid")
        if (
            type(self.closure_revision) is not int
            or isinstance(self.closure_revision, bool)
            or self.closure_revision < 1
        ):
            raise ValueError("step outcome closure revision is invalid")


class ErasureSettings(BaseSettings):
    """Deployment-only executor configuration with no normal-runtime fallback."""

    model_config = SettingsConfigDict(
        env_prefix="TB_ERASURE_", extra="forbid", frozen=True, case_sensitive=False
    )

    db_dsn: SecretStr
    poll_seconds: float = Field(default=2.0, gt=0.0, le=60.0)
    lease_seconds: int = Field(default=90, ge=30, le=900)
    heartbeat_seconds: int = Field(default=20, ge=1, le=299)
    batch_size: int = Field(default=100, ge=1, le=10_000)
    external_timeout_seconds: float = Field(default=10.0, gt=0.0, le=299.0)
    trace_store: Literal["trace_fs_v1", "trace_s3_v1"] = "trace_fs_v1"
    vector_store: Literal["vector_postgres", "vector_qdrant", "vector_none"] = "vector_postgres"
    graph_store: Literal["graph_postgres", "graph_age", "graph_none"] = "graph_postgres"

    @model_validator(mode="after")
    def _validate_lease_timing(self) -> ErasureSettings:
        if 3 * self.heartbeat_seconds >= self.lease_seconds:
            raise ValueError("lease_seconds must exceed three heartbeat_seconds")
        if self.external_timeout_seconds >= self.heartbeat_seconds:
            raise ValueError("external_timeout_seconds must be below heartbeat_seconds")
        canonical_manifest(
            sorted([self.trace_store, "valkey_v1", self.vector_store, self.graph_store])
        )
        return self

    @property
    def manifest(self) -> tuple[ExternalStoreCode, ...]:
        return canonical_manifest(
            sorted([self.trace_store, "valkey_v1", self.vector_store, self.graph_store])
        )

    def db_dsn_value(self) -> str:
        """The sole intentionally explicit SecretStr unwrap site."""

        return self.db_dsn.get_secret_value()
