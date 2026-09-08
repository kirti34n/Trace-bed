"""Bounded execution for the retrieve endpoint only.

The ASGI handler stops waiting at the shared deadline.  A blocking worker is
not killed: it retains both its executor slot and admission permit until it
actually returns, which bounds outstanding work during a downstream stall.
"""

from __future__ import annotations

import asyncio
import threading
from collections.abc import Callable
from concurrent.futures import Future, ThreadPoolExecutor
from contextlib import suppress
from typing import Any, TypeVar, cast

from tracebed.hotpath.budget import Deadline

__all__ = ["RetrievalAdmission"]

T = TypeVar("T")


class RetrievalAdmission:
    """A non-queueing fixed executor whose permits outlive abandoned waits."""

    def __init__(self, *, capacity: int) -> None:
        self._permits = threading.BoundedSemaphore(capacity)
        self._executor = ThreadPoolExecutor(max_workers=capacity, thread_name_prefix="tb-retrieve")
        self._closed = False
        self._lock = threading.Lock()

    async def run(self, deadline: Deadline, work: Callable[[], T]) -> T | None:
        """Return ``None`` when admission or the cooperative wait expires."""
        if deadline.total_exceeded() or not self._permits.acquire(blocking=False):
            return None
        with self._lock:
            if self._closed:
                self._permits.release()
                return None
            try:
                future: Future[T] = self._executor.submit(work)
            except BaseException:
                self._permits.release()
                raise

        def release_when_done(done: Future[T]) -> None:
            if not done.cancelled():
                with suppress(BaseException):
                    done.result()
            self._permits.release()

        future.add_done_callback(release_when_done)
        wrapped = asyncio.ensure_future(asyncio.wrap_future(future))

        def consume_wrapped_exception(done: asyncio.Future[T]) -> None:
            with suppress(BaseException):
                done.result()

        wrapped.add_done_callback(consume_wrapped_exception)
        wake = asyncio.Event()
        loop = asyncio.get_running_loop()
        listener_live = threading.Event()
        listener_live.set()

        # The callback is intentionally request-local; a project-budget
        # narrowing changes only this request's waiter.
        def notify_narrowed() -> None:
            if listener_live.is_set():
                loop.call_soon_threadsafe(wake.set)

        listener_token = deadline.add_narrow_listener(notify_narrowed)
        try:
            while True:
                remaining = deadline.remaining_ms()
                if remaining <= 0:
                    return None
                waiter = asyncio.create_task(wake.wait())
                try:
                    done, _ = await asyncio.wait(
                        {cast(asyncio.Future[Any], wrapped), cast(asyncio.Future[Any], waiter)},
                        timeout=remaining / 1000.0,
                        return_when=asyncio.FIRST_COMPLETED,
                    )
                finally:
                    if not waiter.done():
                        waiter.cancel()
                    with suppress(asyncio.CancelledError):
                        await waiter
                if wrapped in done:
                    if deadline.total_exceeded():
                        return None
                    return wrapped.result()
                if wake.is_set():
                    wake.clear()
                    continue
                return None
        except asyncio.CancelledError:
            # The future's callback deliberately retains the permit after an
            # HTTP disconnect; consume its later exception there.
            raise
        finally:
            listener_live.clear()
            deadline.remove_narrow_listener(listener_token)

    def close(self) -> None:
        """Stop accepting work and wait for retained workers before teardown."""
        with self._lock:
            self._closed = True
        self._executor.shutdown(wait=True)
