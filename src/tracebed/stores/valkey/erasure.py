"""E3-only Valkey namespace erasure with a two-empty-scan proof."""

from __future__ import annotations

import hashlib
import math
import time
from collections.abc import Callable
from typing import Any, Protocol, cast
from uuid import UUID

from valkey import Valkey
from valkey.exceptions import TimeoutError as ValkeyTimeoutError

from tracebed.domain.errors import (
    ErasureDependencyTimeout,
    ErasureLeaseLost,
    ErasureOperatorBlocked,
)
from tracebed.domain.ids import ProjectId
from tracebed.erasure.domain import StoreResult
from tracebed.stores.valkey.keys import project_key_pattern

__all__ = ["FreshValkeyErasureCommands", "ValkeyErasureAdapter", "ValkeyErasureCommands"]


class ValkeyErasureCommands(Protocol):
    """The cursor-level surface needed to prove a complete namespace scan.

    Each command implementation must bind ``timeout_seconds`` to its socket
    or driver-level cancellation boundary and raise :class:`TimeoutError` if
    it expires.  A post-call wall-clock check cannot rescue a SCAN/UNLINK
    invocation that is allowed to hang while an E3 lease expires.
    """

    def scan(
        self, cursor: int, *, match: str, count: int, timeout_seconds: float
    ) -> tuple[object, object]: ...

    def unlink(self, *names: str | bytes, timeout_seconds: float) -> object: ...


class FreshValkeyErasureCommands:
    """One short-lived Valkey client per destructive protocol command.

    A long-lived client can retain a socket whose deadline was chosen for an
    earlier lease.  This wrapper creates the client immediately before each
    SCAN/UNLINK, applies the caller's *remaining* deadline to both connect and
    socket I/O, then closes and disconnects the pool before returning.  The
    timeout is therefore enforced by the transport rather than merely checked
    after a command that may already have outlived the erasure lease.
    """

    def __init__(self, url: str) -> None:
        if not isinstance(url, str) or not url.startswith("valkey://"):
            raise ValueError("erasure Valkey URL is invalid")
        self._url = url

    def _call(self, timeout_seconds: float, operation: Callable[[Valkey], object]) -> object:
        if (
            type(timeout_seconds) not in {int, float}
            or isinstance(timeout_seconds, bool)
            or not math.isfinite(timeout_seconds)
            or timeout_seconds <= 0
        ):
            raise TimeoutError()
        client: Valkey | None = None
        try:
            client = Valkey.from_url(
                self._url,
                decode_responses=False,
                socket_connect_timeout=float(timeout_seconds),
                socket_timeout=float(timeout_seconds),
            )
            return operation(client)
        except (TimeoutError, ValkeyTimeoutError) as exc:
            raise TimeoutError() from exc
        finally:
            if client is not None:
                try:
                    cast(Any, client).close()
                finally:
                    # ``close()`` is not a stable promise to flush all pooled
                    # sockets across valkey-py versions.  Disconnect exactly
                    # this one-command pool before any subsequent operation.
                    cast(Any, client).connection_pool.disconnect()

    def scan(
        self, cursor: int, *, match: str, count: int, timeout_seconds: float
    ) -> tuple[object, object]:
        result = self._call(
            timeout_seconds,
            lambda client: client.scan(cursor=cursor, match=match, count=count),
        )
        if not isinstance(result, tuple) or len(result) != 2:
            raise ValueError("erasure Valkey SCAN result is invalid")
        return result

    def unlink(self, *names: str | bytes, timeout_seconds: float) -> object:
        return self._call(timeout_seconds, lambda client: client.unlink(*names))


def _digest(project_id: UUID, pass_count: int) -> bytes:
    return hashlib.sha256(
        b"tracebed.erasure.valkey/v1\x00" + project_id.bytes + pass_count.to_bytes(8, "big")
    ).digest()


class _Deadline:
    """Bound every SCAN/UNLINK call and offer a heartbeat between pages."""

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

    def remaining(self) -> float:
        if self._before_page is not None:
            self._before_page()
        remaining = self._deadline - self._monotonic()
        if remaining <= 0:
            raise ErasureDependencyTimeout()
        return remaining

    def check(self) -> None:
        self.remaining()


class ValkeyErasureAdapter:
    """Flush only one project's known namespace, then independently prove zero."""

    store_code = "valkey_v1"

    def __init__(
        self,
        client: ValkeyErasureCommands,
        *,
        scan_count: int = 500,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        if type(scan_count) is not int or isinstance(scan_count, bool) or scan_count < 1:
            raise ValueError("erasure scan_count is invalid")
        if not callable(monotonic):
            raise TypeError("erasure monotonic clock is invalid")
        self._client = client
        self._scan_count = scan_count
        self._monotonic = monotonic

    def erase_project(
        self,
        project_id: UUID,
        *,
        timeout_seconds: float,
        before_page: Callable[[], None] | None = None,
    ) -> StoreResult:
        if type(project_id) is not UUID:
            raise ErasureOperatorBlocked()
        pattern = project_key_pattern(ProjectId(project_id))
        deadline = _Deadline(timeout_seconds, self._monotonic, before_page)
        removed = 0
        # A pass that observes data is deletion only; it is never evidence.
        # Keep sweeping until one pass sees zero, then verify() obtains the
        # required second independent complete zero pass.
        while True:
            seen, pass_removed = self._scan_unlink_pass(pattern, deadline)
            removed += pass_removed
            if not seen:
                break
        return StoreResult("ok" if removed else "already_absent", removed, _digest(project_id, 1))

    def verify_project_absent(
        self,
        project_id: UUID,
        *,
        timeout_seconds: float,
        before_page: Callable[[], None] | None = None,
    ) -> StoreResult:
        if type(project_id) is not UUID:
            raise ErasureOperatorBlocked()
        pattern = project_key_pattern(ProjectId(project_id))
        deadline = _Deadline(timeout_seconds, self._monotonic, before_page)
        # Any key during either complete pass is a failed proof, not a signal
        # to optimistically clean it during verification.
        first_seen, _ = self._scan_unlink_pass(pattern, deadline, unlink=False)
        second_seen, _ = self._scan_unlink_pass(pattern, deadline, unlink=False)
        if first_seen or second_seen:
            raise ErasureOperatorBlocked()
        return StoreResult("already_absent", 0, _digest(project_id, 2))

    def _scan_unlink_pass(
        self, pattern: str, deadline: _Deadline, *, unlink: bool = True
    ) -> tuple[bool, int]:
        cursor = 0
        seen_cursors: set[int] = set()
        saw_key = False
        removed = 0
        while True:
            try:
                deadline.check()
                raw_next, raw_keys = self._client.scan(
                    cursor,
                    match=pattern,
                    count=self._scan_count,
                    timeout_seconds=deadline.remaining(),
                )
                deadline.check()
            except ErasureDependencyTimeout:
                raise
            except ErasureLeaseLost:
                # The progress callback is the executor's exact-live lease
                # check.  Preserve it so no later SCAN/UNLINK or work mark
                # can turn a lost lease into an operator-blocked mutation.
                raise
            except TimeoutError as exc:
                raise ErasureDependencyTimeout() from exc
            except Exception as exc:
                raise ErasureOperatorBlocked() from exc
            if type(raw_next) is bool or not isinstance(raw_next, int) or raw_next < 0:
                raise ErasureOperatorBlocked()
            if type(raw_keys) not in {list, tuple}:
                raise ErasureOperatorBlocked()
            raw_key_values = cast(tuple[object, ...] | list[object], raw_keys)
            if any(type(key) not in {str, bytes} for key in raw_key_values):
                raise ErasureOperatorBlocked()
            keys: tuple[str | bytes, ...] = tuple(cast(str | bytes, key) for key in raw_key_values)
            # SCAN's MATCH is advisory at the protocol seam: a malformed or
            # hostile client response must never turn this into an unlink of a
            # foreign namespace.  Validate every returned key before issuing
            # a single destructive command.
            text_prefix = pattern.removesuffix("*")
            byte_prefix = text_prefix.encode("utf-8")
            for key in keys:
                if isinstance(key, str):
                    matches_namespace = key.startswith(text_prefix)
                else:
                    matches_namespace = key.startswith(byte_prefix)
                if not matches_namespace:
                    raise ErasureOperatorBlocked()
            if keys:
                saw_key = True
                if unlink:
                    try:
                        deadline.check()
                        count = self._client.unlink(*keys, timeout_seconds=deadline.remaining())
                        deadline.check()
                    except ErasureDependencyTimeout:
                        raise
                    except ErasureLeaseLost:
                        raise
                    except TimeoutError as exc:
                        raise ErasureDependencyTimeout() from exc
                    except Exception as exc:
                        raise ErasureOperatorBlocked() from exc
                    if (
                        type(count) is not int
                        or isinstance(count, bool)
                        or count < 0
                        or count > len(keys)
                    ):
                        raise ErasureOperatorBlocked()
                    removed += count
            next_cursor = raw_next
            if next_cursor == 0:
                return saw_key, removed
            # A repeated/nonadvancing cursor can otherwise turn a temporary
            # cache response into an unbounded loop or false completion.
            if next_cursor == cursor or next_cursor in seen_cursors:
                raise ErasureOperatorBlocked()
            seen_cursors.add(cursor)
            cursor = next_cursor
