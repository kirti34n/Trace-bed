"""E3-only parameterized Apache AGE project erasure companion."""

from __future__ import annotations

import hashlib
import math
import time
from collections.abc import Callable, Mapping, Sequence
from typing import Protocol
from uuid import UUID

from tracebed.domain.errors import (
    ErasureDependencyTimeout,
    ErasureLeaseLost,
    ErasureOperatorBlocked,
)
from tracebed.erasure.domain import StoreResult

__all__ = ["AgeErasureAdapter", "AgeErasureExecutor"]

_DELETE_PROJECT = "MATCH (n {project_id: $project_id}) DETACH DELETE n"
_COUNT_PROJECT = "MATCH (n {project_id: $project_id}) RETURN count(n) AS count"


class AgeErasureExecutor(Protocol):
    """Parameterized-only Cypher execution seam for the configured graph.

    ``timeout_seconds`` is a driver/query cancellation boundary, not a
    post-hoc accounting value.  Implementations raise ``TimeoutError`` when
    it expires.
    """

    def execute_erasure(
        self, cypher: str, params: Mapping[str, object], *, timeout_seconds: float
    ) -> Sequence[Mapping[str, object]]: ...


def _digest(project_id: UUID) -> bytes:
    return hashlib.sha256(b"tracebed.erasure.age/v1\x00" + project_id.bytes).digest()


class _Deadline:
    """Bound all AGE queries in one erase/proof call with a heartbeat boundary."""

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

    def call(
        self, operation: Callable[[float], Sequence[Mapping[str, object]]]
    ) -> Sequence[Mapping[str, object]]:
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


class AgeErasureAdapter:
    """Subject erasure intentionally flushes the entire project graph index."""

    store_code = "graph_age"

    def __init__(
        self, executor: AgeErasureExecutor, *, monotonic: Callable[[], float] = time.monotonic
    ) -> None:
        if not callable(monotonic):
            raise TypeError("erasure monotonic clock is invalid")
        self._executor = executor
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
            deadline.call(
                lambda remaining: self._executor.execute_erasure(
                    _DELETE_PROJECT, {"project_id": str(project_id)}, timeout_seconds=remaining
                )
            )
        except ErasureDependencyTimeout:
            raise
        except ErasureLeaseLost:
            raise
        except Exception as exc:
            raise ErasureOperatorBlocked() from exc
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
            rows = deadline.call(
                lambda remaining: self._executor.execute_erasure(
                    _COUNT_PROJECT, {"project_id": str(project_id)}, timeout_seconds=remaining
                )
            )
        except ErasureDependencyTimeout:
            raise
        except ErasureLeaseLost:
            raise
        except Exception as exc:
            raise ErasureOperatorBlocked() from exc
        if len(rows) != 1 or type(rows[0].get("count")) is not int or rows[0]["count"] != 0:
            raise ErasureOperatorBlocked()
        return StoreResult("already_absent", 0, _digest(project_id))
