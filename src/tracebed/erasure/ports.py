"""Narrow destructive E3 ports, deliberately separate from hot-path ports."""

from __future__ import annotations

from collections.abc import Callable
from typing import Protocol
from uuid import UUID

from tracebed.erasure.domain import ExternalStoreCode, StoreResult

__all__ = [
    "ExternalErasurePort",
    "TraceErasurePort",
    "ValkeyErasurePort",
]


class ExternalErasurePort(Protocol):
    """Erase then independently prove absence for one configured store."""

    store_code: ExternalStoreCode

    def erase_run(
        self,
        project_id: UUID,
        run_id: UUID,
        *,
        timeout_seconds: float,
        before_page: Callable[[], None] | None = None,
    ) -> StoreResult: ...

    def verify_run_absent(
        self,
        project_id: UUID,
        run_id: UUID,
        *,
        timeout_seconds: float,
        before_page: Callable[[], None] | None = None,
    ) -> StoreResult: ...

    def erase_project(
        self,
        project_id: UUID,
        *,
        timeout_seconds: float,
        before_page: Callable[[], None] | None = None,
    ) -> StoreResult: ...

    def verify_project_absent(
        self,
        project_id: UUID,
        *,
        timeout_seconds: float,
        before_page: Callable[[], None] | None = None,
    ) -> StoreResult: ...


class TraceErasurePort(ExternalErasurePort, Protocol):
    """Trace-only destructive surface; normal TraceStorePort stays read/write only."""

    def validate_manifest_ref(self, project_id: UUID, run_id: UUID, payload_ref: str) -> bytes: ...


class ValkeyErasurePort(Protocol):
    """Namespace flush + two-empty-scan proof for the rebuildable cache."""

    store_code: ExternalStoreCode

    def erase_project(
        self,
        project_id: UUID,
        *,
        timeout_seconds: float,
        before_page: Callable[[], None] | None = None,
    ) -> StoreResult: ...

    def verify_project_absent(
        self,
        project_id: UUID,
        *,
        timeout_seconds: float,
        before_page: Callable[[], None] | None = None,
    ) -> StoreResult: ...
