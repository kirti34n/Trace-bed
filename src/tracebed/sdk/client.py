"""TracebedClient — the fire-and-forget SDK (PHASE0-CONTRACT.md §10 / PHASE-0.md Task 13).

This module is invariant 5 (async writes) and half of invariant 2 (fail-open)
made concrete: `trace()`, `feedback()`, and `propose_memory()` never block the
caller on I/O and never raise, no matter what the server is doing. The only
synchronous work on those paths is a dict-build and a `RingBuffer.append()`
(see `buffer.py`) — everything else (HTTP, retries, batching) happens on a
daemon background thread that owns all I/O and swallows every exception into
a counter, because a monitoring dependency that can take down the host
application it's monitoring has failed at its one job.

That "never raises" obligation extends to everything the host can call
*synchronously* — `retrieve()`, `flush()`, `run_end()` — and to the background
thread itself: a thread that dies on one bad event stops flushing forever, so
every loop body and every per-event serialisation is individually guarded.
`TraceEvent.payload` is `dict[str, Any]`, i.e. the host can put an object in it
that has no JSON form; that must cost exactly that one event.

Import discipline (§14, chunk `sdk`): `tracebed.domain.*` and `httpx` only.
Never `stores`, `api`, or `ingest` — the SDK runs inside a *caller's* process,
which may not even have those packages installed, and it must not compute
anything the server is the authority on (`input_signature_hash` in
particular: the SDK ships the raw C-05 payload keys and lets the server
derive the hash, it does not derive one itself).
"""

from __future__ import annotations

import contextlib
import logging
import threading
import weakref
from collections import OrderedDict
from collections.abc import Callable, Mapping, Sequence
from typing import Final, Literal

import httpx
from pydantic import BaseModel

from tracebed.domain.clock import Clock, SystemClock
from tracebed.domain.enums import Arm, OutcomeCode
from tracebed.domain.events import (
    ContextBlock,
    FeedbackEvent,
    MemoryProposal,
    RetrieveResult,
    RunContext,
    RunEnd,
    RunStart,
    TraceEvent,
    empty_context_block,
)
from tracebed.domain.ids import RunId, mint_run_id
from tracebed.sdk.buffer import BufferedItem, FlushReport, RingBuffer

__all__ = ["TracebedClient"]

logger = logging.getLogger("tracebed.sdk")

# Generous margin over the server's own 300ms retrieval budget (PHASE0-CONTRACT.md
# §3.4 RetrievalConfig.total_budget_ms): the SDK must return promptly even if the
# server is unreachable rather than ignores its own budget, but a bound tighter
# than the server's stated budget would turn "the server took 290ms" into a false
# degraded result.
_RETRIEVE_TIMEOUT_S: Final = 1.0
# Wall-clock budget for one *background* flush pass. A dead/slow server must not
# wedge the flusher thread: whatever is undrained at the deadline stays buffered
# for the next wake instead of being drained-then-destroyed (see `_do_flush`).
_FLUSH_SEND_TIMEOUT_S: Final = 5.0
# C-05: bounded so a long-lived host process's run_id->arm memory cannot grow
# without limit across a session with millions of runs.
_ARM_MEMORY_CAPACITY: Final = 4096
# §9.3 C-21 caps POST /v1/trace/batch at 500 events, so one drain can never
# produce a batch the route would 422.
_MAX_DRAIN_BATCH: Final = 500


class _BoundedArmMemory:
    """A tiny thread-safe LRU: `run_id -> Arm`, capped at `_ARM_MEMORY_CAPACITY`.

    Backs C-05's "SDK stamps `run_start.payload['arm']` from the last
    `retrieve()` result for that run" behavior. Bounded and LRU-evicting so a
    process that never restarts (a long-running agent host) cannot leak
    memory proportional to lifetime run count.
    """

    __slots__ = ("_capacity", "_data", "_lock")

    def __init__(self, capacity: int) -> None:
        self._data: OrderedDict[RunId, Arm] = OrderedDict()
        self._capacity = capacity
        self._lock = threading.Lock()

    def set(self, run_id: RunId, arm: Arm) -> None:
        with self._lock:
            self._data[run_id] = arm
            self._data.move_to_end(run_id)
            while len(self._data) > self._capacity:
                self._data.popitem(last=False)

    def get(self, run_id: RunId) -> Arm | None:
        with self._lock:
            value = self._data.get(run_id)
            if value is not None:
                self._data.move_to_end(run_id)
            return value


def _shutdown(stop_event: threading.Event, http: httpx.Client) -> None:
    """Finalizer body: stop the flusher and release the connection pool.

    Registered via `weakref.finalize` on the client, so it runs when the host
    drops its last reference (and, failing that, at interpreter exit). It takes
    only the two owned resources — never the client — because a finalizer that
    closed over `self` would keep the client alive forever, which is the leak
    it exists to prevent.
    """
    stop_event.set()
    with contextlib.suppress(Exception):
        http.close()


def _flusher_loop(
    client_ref: weakref.ReferenceType[TracebedClient],
    stop_event: threading.Event,
    interval_s: float,
) -> None:
    """Background flush loop.

    Holds a *weak* reference to the client: the thread must not be what keeps a
    discarded `TracebedClient` (and its whole ring buffer) resident for the life
    of the host process. When the client is collected the loop returns and the
    thread exits.

    The body is guarded because an escaping exception kills the thread
    permanently — after which nothing is ever flushed again and the buffer just
    drops in silence. Fail-open means degrade, not stop.
    """
    while not stop_event.wait(interval_s):
        client = client_ref()
        if client is None:
            return
        try:
            client._do_flush(_FLUSH_SEND_TIMEOUT_S, report_drops=False)
        except Exception:
            logger.debug("tracebed sdk: background flush pass failed", exc_info=True)
        finally:
            # Do not hold the strong reference across the next wait(), or the
            # client stays alive for a whole flush interval after being dropped.
            del client


class TracebedClient:
    """The exact PHASE-0 Task 13 surface. Do not add public methods."""

    def __init__(
        self,
        base_url: str,
        *,
        api_key: str | None = None,
        token_provider: Callable[[], str] | None = None,
        buffer_capacity: int = 10_000,
        flush_interval_s: float = 1.0,
    ) -> None:
        if flush_interval_s <= 0:
            # A non-positive interval turns `Event.wait()` into a no-op and the
            # flusher into a spin loop that pegs a core of the *host* process —
            # the precise class of harm invariant 2 exists to prevent. Rejected
            # at construction (the one SDK entry point allowed to raise), never
            # silently clamped.
            raise ValueError("flush_interval_s must be > 0")
        self._api_key = api_key
        self._token_provider = token_provider
        self._buffer = RingBuffer(buffer_capacity)
        self._flush_interval_s = flush_interval_s
        self._arm_memory = _BoundedArmMemory(_ARM_MEMORY_CAPACITY)
        # datetime.now() is confined to SystemClock (hard rule 4); run_end's
        # `ts` and every flush deadline below need "now", and the Task 13
        # surface has no injectable-clock parameter to carry a FakeClock
        # through, so this is a private, non-configurable instance.
        self._clock: Clock = SystemClock()

        self._http = httpx.Client(base_url=base_url.rstrip("/"))

        # Serializes flush operations (explicit `flush()` calls and the
        # background loop) so drain-then-send cycles and the drop-count
        # watermark below never interleave across threads. Never held on the
        # trace()/feedback()/propose_memory() hot path.
        self._flush_lock = threading.Lock()
        self._last_reported_dropped = 0
        self._flush_errors = 0

        self._stop_event = threading.Event()
        self._flusher = threading.Thread(
            target=_flusher_loop,
            args=(weakref.ref(self), self._stop_event, flush_interval_s),
            name="tracebed-sdk-flusher",
            daemon=True,
        )
        self._flusher.start()
        # Task 13's surface has no close()/__exit__, so this is the only hook
        # that can stop the thread and release the socket pool of a client the
        # host has finished with.
        weakref.finalize(self, _shutdown, self._stop_event, self._http)

    # -- headers -------------------------------------------------------------

    def _auth_headers(self) -> dict[str, str]:
        """Built at send time (background thread) only — never on the hot path."""
        headers: dict[str, str] = {}
        if self._token_provider is not None:
            try:
                headers["Authorization"] = f"Bearer {self._token_provider()}"
            except Exception:
                logger.debug("tracebed sdk: token_provider raised", exc_info=True)
        if self._api_key is not None:
            headers["X-API-Key"] = self._api_key
        return headers

    # -- retrieve --------------------------------------------------------------

    def retrieve(
        self,
        *,
        agent_type: str,
        run_ctx: RunContext,
        session_id: str | None = None,
        prefetch_for: str | None = None,
    ) -> RetrieveResult:
        """Sync HTTP against the server's 300ms retrieval budget.

        `run_ctx.tool_manifest` is deliberately not sent here (C-05: it rides
        the `run_start` trace event payload instead). On any transport error,
        timeout, or non-2xx response this returns the degraded result and
        never raises — the one hard requirement of invariant 2's fail-open
        contract that applies to a *synchronous* SDK call.
        """
        body = {
            "agent_type": agent_type,
            "run_ctx": {
                "query_text": run_ctx.query_text,
                "workflow_template": run_ctx.workflow_template,
                "user_ref": run_ctx.user_ref,
                "session_id": session_id,
                "prefetch_for": prefetch_for,
            },
        }
        result = self._do_retrieve(body)
        try:
            self._arm_memory.set(RunId(result.run_id), result.arm)
        except Exception:
            # Bookkeeping for a Phase-1 nicety (arm stamping) must never turn a
            # successful retrieval into an exception in the host's hot loop.
            logger.debug("tracebed sdk: arm memory update failed", exc_info=True)
        return result

    def _do_retrieve(self, body: Mapping[str, object]) -> RetrieveResult:
        try:
            response = self._http.post(
                "/v1/retrieve",
                json=body,
                headers=self._auth_headers(),
                timeout=_RETRIEVE_TIMEOUT_S,
            )
            response.raise_for_status()
            return RetrieveResult.model_validate(response.json())
        except Exception:
            logger.debug("tracebed sdk: retrieve() degraded", exc_info=True)
            return RetrieveResult(
                run_id=mint_run_id().value,
                run_id_origin="sdk",
                arm=Arm.MEMORY_ON,
                outcome_code=OutcomeCode.STORE_ERROR,
                context_block=empty_context_block(),
            )

    # -- fire-and-forget writes --------------------------------------------

    def trace(self, run_id: RunId, event: TraceEvent) -> None:
        """Enqueue one trace event. Never raises, never blocks on I/O.

        The ring-buffer append is the ONLY synchronous work here besides a
        one-key dict build (and, for `run_start` events with a known arm, a
        cheap `model_copy` to stamp it — not JSON serialization).
        """
        try:
            stamped: TraceEvent = event
            if isinstance(event, RunStart) and "arm" not in event.payload:
                arm = self._arm_memory.get(run_id)
                if arm is not None:
                    stamped = event.model_copy(update={"payload": {**event.payload, "arm": arm.value}})
            self._buffer.append(run_id, "trace", {"event": stamped})
        except Exception:
            logger.debug("tracebed sdk: trace() suppressed an internal error", exc_info=True)

    def feedback(self, run_id: RunId, event: FeedbackEvent) -> None:
        """Enqueue one feedback event. Never raises, never blocks on I/O."""
        try:
            self._buffer.append(run_id, "feedback", {"event": event})
        except Exception:
            logger.debug("tracebed sdk: feedback() suppressed an internal error", exc_info=True)

    def propose_memory(self, run_id: RunId, proposal: MemoryProposal) -> None:
        """Enqueue one memory proposal. Never raises, never blocks on I/O."""
        try:
            self._buffer.append(run_id, "proposal", {"proposal": proposal})
        except Exception:
            logger.debug("tracebed sdk: propose_memory() suppressed an internal error", exc_info=True)

    def on_operational_event(self, run_id: RunId, event: TraceEvent) -> ContextBlock | None:
        """JIT-injection hook. Phase 0/1: always `None` (trigger logic is Phase 2,
        CUTTABLE improvement 5) — this ships the hook, not a placeholder decision."""
        del run_id, event
        return None

    def run_end(self, run_id: RunId, status: Literal["ok", "error", "cancelled"]) -> None:
        """Emit the `run_end` completeness sentinel with the final seq, then flush.

        Unlike `trace()`/`feedback()`, this is documented (PHASE0-CONTRACT.md
        §10) to call `flush()`, i.e. it does synchronous I/O — callers that
        need a non-blocking end-of-run signal should not expect sub-millisecond
        latency from this specific method. It is still bounded: `flush()`'s
        `timeout_s` is a wall-clock budget for the whole drain, so a dead
        server costs the host that budget once, not once per batch.
        """
        try:
            event = RunEnd(type="run_end", ts=self._clock.now(), payload={"status": status})
            self.trace(run_id, event)
        except Exception:
            logger.debug("tracebed sdk: run_end() suppressed an internal error", exc_info=True)
        self.flush()

    # -- flush -----------------------------------------------------------------

    def flush(self, timeout_s: float = 5.0) -> FlushReport:
        """Force a synchronous drain-and-send. Never raises.

        `timeout_s` is the budget for the WHOLE call, not per request: a host
        calling `run_end()` at the end of every run must be able to bound what
        an unreachable Tracebed costs it, and "5s per batch, N batches" is not
        a bound.
        """
        try:
            return self._do_flush(timeout_s, report_drops=True)
        except Exception:
            logger.debug("tracebed sdk: flush() suppressed an internal error", exc_info=True)
            return FlushReport(sent=0, dropped=0)

    def _do_flush(self, timeout_s: float, *, report_drops: bool) -> FlushReport:
        """Drain-and-send until the buffer is empty or the deadline passes.

        `report_drops` is False for background passes: `FlushReport.dropped` is
        specified (§10) as "cumulative drops since last flush() return", and the
        default 1s background cadence would otherwise consume every drop before
        the host's own `flush()` could ever see one — leaving D-033's data-loss
        counter reading zero precisely when data is being lost.
        """
        with self._flush_lock:
            deadline_ms = self._clock.monotonic_ms() + max(timeout_s, 0.0) * 1000.0
            sent = 0
            while self._clock.monotonic_ms() < deadline_ms:
                # The deadline is checked BEFORE draining: items only leave the
                # ring when there is budget left to send them, so an expired
                # budget leaves them buffered for the next pass instead of
                # drained-then-destroyed.
                items = self._buffer.drain(_MAX_DRAIN_BATCH)
                if not items:
                    break
                sent += self._dispatch(items, deadline_ms)
                if len(items) < _MAX_DRAIN_BATCH:
                    break
            dropped = 0
            if report_drops:
                current_dropped = self._buffer.dropped_total
                dropped = current_dropped - self._last_reported_dropped
                self._last_reported_dropped = current_dropped
            return FlushReport(sent=sent, dropped=dropped)

    def _dispatch(self, items: Sequence[BufferedItem], deadline_ms: float) -> int:
        """Group one drained batch by kind and send each group. Never raises."""
        traces = [item for item in items if item.kind == "trace"]
        feedbacks = [item for item in items if item.kind == "feedback"]
        proposals = [item for item in items if item.kind == "proposal"]

        sent = 0
        if traces:
            sent += self._send_trace_batch(traces, deadline_ms)
        for item in feedbacks:
            encoded = self._encode(item, "event")
            if encoded is None:
                continue
            sent += self._post(
                "/v1/feedback",
                {"run_id": str(item.run_id.value), "event": encoded},
                1,
                deadline_ms,
            )
        for item in proposals:
            encoded = self._encode(item, "proposal")
            if encoded is None:
                continue
            sent += self._post(
                "/v1/propose_memory",
                {"run_id": str(item.run_id.value), "proposal": encoded},
                1,
                deadline_ms,
            )
        return sent

    def _encode(self, item: BufferedItem, key: str) -> dict[str, object] | None:
        """JSON-encode one buffered model, or None if it cannot be encoded.

        `TraceEvent.payload` / `FeedbackEvent.payload` are `dict[str, Any]`, so
        a host can buffer a value with no JSON form. Serialisation therefore
        happens per item, not per batch: one unencodable event costs that one
        event. Batch-level serialisation would let it destroy the other 499 —
        and, uncaught, kill the flusher thread outright.
        """
        model = item.body.get(key)
        if not isinstance(model, BaseModel):
            self._flush_errors += 1
            logger.warning("tracebed sdk: dropped a buffered item with no %r model", key)
            return None
        try:
            return model.model_dump(mode="json")
        except Exception:
            self._flush_errors += 1
            # WARNING, not DEBUG: unlike a network failure this is permanent
            # data loss from a caller bug, and `_flush_errors` is private.
            logger.warning(
                "tracebed sdk: dropped an unserialisable %s payload for run %s",
                item.kind,
                item.run_id,
                exc_info=True,
            )
            return None

    def _send_trace_batch(self, items: Sequence[BufferedItem], deadline_ms: float) -> int:
        events: list[dict[str, object]] = []
        for item in items:
            encoded = self._encode(item, "event")
            if encoded is None:
                continue
            events.append(
                {
                    "run_id": str(item.run_id.value),
                    "seq": item.seq,
                    "event": encoded,
                }
            )
        if not events:
            return 0
        return self._post("/v1/trace/batch", {"events": events}, len(events), deadline_ms)

    def _post(
        self, path: str, payload: Mapping[str, object], count: int, deadline_ms: float
    ) -> int:
        """POST one batch/single. On any failure: swallow, count, return 0 sent.

        Items are already drained from the ring buffer by the time this runs
        (§10: drain happens before send), so a failed send loses those items —
        the same fail-open trade-off as an unbuffered fire-and-forget call:
        Tracebed being down costs Tracebed data, never host application
        correctness or latency.
        """
        remaining_s = (deadline_ms - self._clock.monotonic_ms()) / 1000.0
        if remaining_s <= 0:
            self._flush_errors += 1
            return 0
        try:
            response = self._http.post(
                path, json=payload, headers=self._auth_headers(), timeout=remaining_s
            )
            response.raise_for_status()
            return count
        except Exception:
            self._flush_errors += 1
            logger.debug("tracebed sdk: flush POST %s failed", path, exc_info=True)
            return 0
