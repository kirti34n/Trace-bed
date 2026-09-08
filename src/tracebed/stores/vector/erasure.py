"""E3-only Qdrant erasure companion; hot ``VectorStorePort`` is unchanged."""

from __future__ import annotations

import hashlib
import math
import time
from collections.abc import Callable
from typing import Protocol, cast
from uuid import UUID

from tracebed.domain.errors import (
    ErasureDependencyTimeout,
    ErasureLeaseLost,
    ErasureOperatorBlocked,
)
from tracebed.erasure.domain import StoreResult

__all__ = ["QdrantErasureAdapter", "QdrantErasureClient"]


class QdrantErasureClient(Protocol):
    """Minimal project-filtered E3 client seam.

    Implementations must bind the UUID as a filter value and bind
    ``timeout_seconds`` to the actual RPC cancellation/socket timeout;
    callers cannot pass a collection/query/selector through this port.
    """

    def delete_project(self, project_id: UUID, *, wait: bool, timeout_seconds: float) -> object: ...

    def count_project(self, project_id: UUID, *, timeout_seconds: float) -> object: ...

    def scroll_project(self, project_id: UUID, *, timeout_seconds: float) -> object: ...


def _digest(project_id: UUID) -> bytes:
    return hashlib.sha256(b"tracebed.erasure.qdrant/v1\x00" + project_id.bytes).digest()


class _Deadline:
    """Bound all RPCs in one erase/proof call by one transport deadline."""

    def __init__(
        self,
        timeout_seconds: float,
        monotonic: Callable[[], float],
        before_page: Callable[[], None] | None,
    ) -> None:
        if (
            type(timeout_seconds) not in {int, float}
            or isinstance(timeout_seconds, bool)
            or not math.isfinite(timeout_seconds)
            or timeout_seconds <= 0
            or (before_page is not None and not callable(before_page))
        ):
            raise ErasureOperatorBlocked()
        self._deadline = monotonic() + float(timeout_seconds)
        self._monotonic = monotonic
        self._before_page = before_page

    def call(self, operation: Callable[[float], object]) -> object:
        if self._before_page is not None:
            self._before_page()
        remaining = self._deadline - self._monotonic()
        if remaining <= 0:
            raise ErasureDependencyTimeout()
        try:
            result = operation(remaining)
        except TimeoutError as exc:
            raise ErasureDependencyTimeout() from exc
        if self._monotonic() >= self._deadline:
            raise ErasureDependencyTimeout()
        return result


class QdrantErasureAdapter:
    """Erase entire project index for either subject or project scope."""

    store_code = "vector_qdrant"

    def __init__(
        self, client: QdrantErasureClient, *, monotonic: Callable[[], float] = time.monotonic
    ) -> None:
        if not callable(monotonic):
            raise TypeError("erasure monotonic clock is invalid")
        self._client = client
        self._monotonic = monotonic

    def erase_run(
        self,
        project_id: UUID,
        run_id: UUID,
        *,
        timeout_seconds: float,
        before_page: Callable[[], None] | None = None,
    ) -> StoreResult:
        del run_id
        return self.erase_project(
            project_id, timeout_seconds=timeout_seconds, before_page=before_page
        )

    def verify_run_absent(
        self,
        project_id: UUID,
        run_id: UUID,
        *,
        timeout_seconds: float,
        before_page: Callable[[], None] | None = None,
    ) -> StoreResult:
        del run_id
        return self.verify_project_absent(
            project_id, timeout_seconds=timeout_seconds, before_page=before_page
        )

    def erase_project(
        self,
        project_id: UUID,
        *,
        timeout_seconds: float,
        before_page: Callable[[], None] | None = None,
    ) -> StoreResult:
        if type(project_id) is not UUID:
            raise ErasureOperatorBlocked()
        deadline = _Deadline(timeout_seconds, self._monotonic, before_page)
        try:
            # ``wait=True`` is load-bearing: a queued delete cannot be marked
            # as verification-ready by a worker that may lose its lease.
            result = deadline.call(
                lambda remaining: self._client.delete_project(
                    project_id, wait=True, timeout_seconds=remaining
                )
            )
        except ErasureDependencyTimeout:
            raise
        except ErasureLeaseLost:
            raise
        except Exception as exc:
            raise ErasureOperatorBlocked() from exc
        if result is False:
            raise ErasureOperatorBlocked()
        return StoreResult("ok", 0, _digest(project_id))

    def verify_project_absent(
        self,
        project_id: UUID,
        *,
        timeout_seconds: float,
        before_page: Callable[[], None] | None = None,
    ) -> StoreResult:
        if type(project_id) is not UUID:
            raise ErasureOperatorBlocked()
        deadline = _Deadline(timeout_seconds, self._monotonic, before_page)
        try:
            count = deadline.call(
                lambda remaining: self._client.count_project(project_id, timeout_seconds=remaining)
            )
            page = deadline.call(
                lambda remaining: self._client.scroll_project(project_id, timeout_seconds=remaining)
            )
        except ErasureDependencyTimeout:
            raise
        except ErasureLeaseLost:
            raise
        except Exception as exc:
            raise ErasureOperatorBlocked() from exc
        if type(count) is not int or isinstance(count, bool) or count != 0:
            raise ErasureOperatorBlocked()
        if type(page) not in {tuple, list}:
            raise ErasureOperatorBlocked()
        page_values = cast(tuple[object, ...] | list[object], page)
        if len(page_values) != 0:
            raise ErasureOperatorBlocked()
        return StoreResult("already_absent", 0, _digest(project_id))
