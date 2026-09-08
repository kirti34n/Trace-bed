"""B2B1 retrieval-only bounded admission and absolute-deadline behavior."""

from __future__ import annotations

import asyncio
import gc
import threading
from contextlib import suppress
from datetime import UTC, datetime

from tracebed.api.retrieval_admission import RetrievalAdmission
from tracebed.domain.clock import FakeClock
from tracebed.hotpath.budget import Deadline


def _deadline(clock: FakeClock, total_ms: int = 1_000) -> Deadline:
    return Deadline(clock=clock, total_budget_ms=total_ms, embed_timeout_ms=total_ms)


def test_capacity_is_nonqueueing_and_permit_survives_abandoned_wait() -> None:
    async def scenario() -> None:
        clock = FakeClock(datetime(2026, 1, 1, tzinfo=UTC))
        admission = RetrievalAdmission(capacity=1)
        entered = threading.Event()
        release = threading.Event()
        completed = threading.Event()

        def blocked() -> str:
            entered.set()
            release.wait()
            completed.set()
            return "done"

        first = asyncio.create_task(admission.run(_deadline(clock), blocked))
        await asyncio.to_thread(entered.wait)
        assert await admission.run(_deadline(clock), lambda: "second") is None
        first.cancel()
        with suppress(asyncio.CancelledError):
            await first
        assert await admission.run(_deadline(clock), lambda: "third") is None
        release.set()
        await asyncio.to_thread(completed.wait)
        assert await admission.run(_deadline(clock), lambda: "fourth") == "fourth"
        admission.close()

    asyncio.run(scenario())


def test_project_budget_narrowing_wakes_the_request_waiter() -> None:
    async def scenario() -> None:
        clock = FakeClock(datetime(2026, 1, 1, tzinfo=UTC))
        admission = RetrievalAdmission(capacity=1)
        entered = threading.Event()
        listener_registered = threading.Event()
        allow_narrow = threading.Event()
        release = threading.Event()

        class _SignallingDeadline(Deadline):
            def add_narrow_listener(self, listener: object) -> int:
                token = super().add_narrow_listener(listener)  # type: ignore[arg-type]
                listener_registered.set()
                return token

        deadline = _SignallingDeadline(clock=clock, total_budget_ms=1_000, embed_timeout_ms=1_000)

        def resolves_config_then_blocks() -> str:
            entered.set()
            allow_narrow.wait()
            clock.advance(ms=800)
            deadline.narrow_total_budget_ms(300)
            release.wait()
            return "late"

        task = asyncio.create_task(admission.run(deadline, resolves_config_then_blocks))
        try:
            await asyncio.wait_for(asyncio.to_thread(entered.wait), timeout=0.2)
            await asyncio.wait_for(asyncio.to_thread(listener_registered.wait), timeout=0.2)
            await asyncio.sleep(0)
            allow_narrow.set()
            assert await asyncio.wait_for(task, timeout=0.2) is None
        finally:
            allow_narrow.set()
            release.set()
            admission.close()

    asyncio.run(scenario())


def test_timeout_retains_permit_and_consumes_late_worker_error() -> None:
    async def scenario() -> None:
        clock = FakeClock(datetime(2026, 1, 1, tzinfo=UTC))
        admission = RetrievalAdmission(capacity=1)
        deadline = _deadline(clock)
        entered = threading.Event()
        release = threading.Event()
        completed = threading.Event()
        errors: list[dict[str, object]] = []
        loop = asyncio.get_running_loop()
        old_handler = loop.get_exception_handler()
        loop.set_exception_handler(lambda _loop, context: errors.append(context))

        def late_failure() -> str:
            entered.set()
            release.wait()
            try:
                raise RuntimeError("late worker failure")
            finally:
                completed.set()

        task = asyncio.create_task(admission.run(deadline, late_failure))
        try:
            await asyncio.wait_for(asyncio.to_thread(entered.wait), timeout=0.2)
            clock.advance(ms=1_001)
            deadline.narrow_total_budget_ms(999)
            assert await asyncio.wait_for(task, timeout=0.2) is None
            assert await admission.run(_deadline(clock), lambda: "queued") is None
        finally:
            release.set()
            await asyncio.wait_for(asyncio.to_thread(completed.wait), timeout=0.2)
            await asyncio.sleep(0)
            gc.collect()
            await asyncio.sleep(0)
            admission.close()
            loop.set_exception_handler(old_handler)
        assert errors == []

    asyncio.run(scenario())


def test_completed_private_result_is_not_returned_after_expiry_or_leaving_a_waiter() -> None:
    async def scenario() -> None:
        clock = FakeClock(datetime(2026, 1, 1, tzinfo=UTC))
        admission = RetrievalAdmission(capacity=1)
        deadline = _deadline(clock)

        def expires_then_returns() -> str:
            clock.advance(ms=1_001)
            return "private-result"

        assert await admission.run(deadline, expires_then_returns) is None
        await asyncio.sleep(0)
        current = asyncio.current_task()
        assert all(task is current or task.done() for task in asyncio.all_tasks())
        admission.close()

    asyncio.run(scenario())


def test_gated_completed_future_is_withheld_after_expiry() -> None:
    async def scenario() -> None:
        clock = FakeClock(datetime(2026, 1, 1, tzinfo=UTC))
        admission = RetrievalAdmission(capacity=1)
        deadline = _deadline(clock)
        entered = threading.Event()
        release = threading.Event()

        def gated_expiry() -> str:
            entered.set()
            release.wait()
            clock.advance(ms=1_001)
            return "private-result"

        task = asyncio.create_task(admission.run(deadline, gated_expiry))
        await asyncio.to_thread(entered.wait)
        release.set()
        assert await task is None
        admission.close()

    asyncio.run(scenario())
