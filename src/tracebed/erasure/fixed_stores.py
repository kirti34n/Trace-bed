"""Fixed-result adapters for stores whose authoritative data is PostgreSQL."""

from __future__ import annotations

import hashlib
import math
from collections.abc import Callable
from uuid import UUID

from tracebed.domain.errors import ErasureOperatorBlocked
from tracebed.erasure.domain import ErasureResultCode, StoreResult

__all__ = ["EmbeddedPrimaryStore", "NotConfiguredStore"]


class _FixedStore:
    def __init__(self, store_code: str, result_code: ErasureResultCode) -> None:
        self.store_code = store_code
        self._result_code = result_code

    def _result(self, project_id: UUID) -> StoreResult:
        return StoreResult(
            self._result_code,
            0,
            hashlib.sha256(
                f"tracebed.erasure.fixed/v1:{self.store_code}".encode() + project_id.bytes
            ).digest(),
        )

    @staticmethod
    def _check(
        timeout_seconds: float, before_page: Callable[[], None] | None
    ) -> None:
        if (
            type(timeout_seconds) not in {int, float}
            or isinstance(timeout_seconds, bool)
            or not math.isfinite(timeout_seconds)
            or timeout_seconds <= 0
            or (before_page is not None and not callable(before_page))
        ):
            raise ErasureOperatorBlocked()
        if before_page is not None:
            before_page()

    def erase_run(
        self,
        project_id: UUID,
        run_id: UUID,
        *,
        timeout_seconds: float,
        before_page: Callable[[], None] | None = None,
    ) -> StoreResult:
        del run_id
        self._check(timeout_seconds, before_page)
        return self._result(project_id)

    def verify_run_absent(
        self,
        project_id: UUID,
        run_id: UUID,
        *,
        timeout_seconds: float,
        before_page: Callable[[], None] | None = None,
    ) -> StoreResult:
        del run_id
        self._check(timeout_seconds, before_page)
        return self._result(project_id)

    def erase_project(
        self,
        project_id: UUID,
        *,
        timeout_seconds: float,
        before_page: Callable[[], None] | None = None,
    ) -> StoreResult:
        self._check(timeout_seconds, before_page)
        return self._result(project_id)

    def verify_project_absent(
        self,
        project_id: UUID,
        *,
        timeout_seconds: float,
        before_page: Callable[[], None] | None = None,
    ) -> StoreResult:
        self._check(timeout_seconds, before_page)
        return self._result(project_id)


class EmbeddedPrimaryStore(_FixedStore):
    def __init__(self, store_code: str) -> None:
        if store_code not in {"vector_postgres", "graph_postgres"}:
            raise ValueError("embedded primary store code is invalid")
        super().__init__(store_code, "embedded_primary")


class NotConfiguredStore(_FixedStore):
    def __init__(self, store_code: str) -> None:
        if store_code not in {"vector_none", "graph_none"}:
            raise ValueError("not-configured store code is invalid")
        super().__init__(store_code, "not_configured")
