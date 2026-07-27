"""PHASE0-CONTRACT.md §10 / PHASE-0.md Task 13 — sdk.client.TracebedClient.

The load-bearing property (invariant 5, half of invariant 2): `trace()` and
`feedback()` return in <=1ms p99 WITH THE SERVER DOWN and NEVER raise. Per
the contract, the dead-server case is exercised against a genuinely closed
TCP port -- not a mocked transport -- so a ConnectError really does happen on
the wire and the SDK still has to eat it. The flush-side tests (run_end,
flush() accuracy, arm stamping, seq-over-the-wire) run against a tiny stdlib
HTTP server started in-process, since the real `/v1/trace/batch` route
belongs to a different, independently-built chunk (api-auth) that this chunk
must not depend on.
"""

from __future__ import annotations

import gc
import http.server
import json
import logging
import socket
import threading
import time
from collections.abc import Callable, Iterator, Sequence
from datetime import UTC, datetime
from typing import Any, cast
from uuid import uuid4

import pytest

from tracebed.domain.enums import AdapterClass, Arm, OutcomeCode
from tracebed.domain.events import (
    MEMORY_HEADER,
    FeedbackEvent,
    MemoryProposal,
    RunContext,
    RunStart,
    ToolCall,
)
from tracebed.domain.ids import RunId, mint_run_id, uuid7
from tracebed.sdk.buffer import FlushReport
from tracebed.sdk.client import TracebedClient

pytestmark = pytest.mark.phase0

_NOW = datetime(2026, 1, 1, tzinfo=UTC)


def _run_ctx() -> RunContext:
    return RunContext(query_text="how do I retry a failed payment capture?")


def _closed_port_url() -> str:
    """A loopback URL nothing is listening on -- a real ConnectError, not a mock."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    # The socket is closed on context-manager exit, so `port` is free again --
    # the connection attempt below fails for real, on the real network stack.
    return f"http://127.0.0.1:{port}"


def _p99_ms(durations_ns: Sequence[int]) -> float:
    ordered = sorted(durations_ns)
    idx = max(0, -(-99 * len(ordered) // 100) - 1)  # ceil(0.99 * n) - 1
    return ordered[idx] / 1_000_000


# --------------------------------------------------------------------------- #
# A tiny recording HTTP server -- real sockets, real JSON bodies, no transport
# mocking. Stands in for the api-auth chunk's not-yet-integrated routes.
# --------------------------------------------------------------------------- #


class _RecordingServer(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def __init__(
        self, server_address: tuple[str, int], handler: type[http.server.BaseHTTPRequestHandler]
    ) -> None:
        super().__init__(server_address, handler)
        self.received: list[tuple[str, dict[str, Any]]] = []
        self.received_headers: list[dict[str, str]] = []
        self.stall_s = 0.0
        self.retrieve_response: dict[str, Any] = {
            "run_id": str(uuid7()),
            "run_id_origin": "server",
            "arm": "memory_on",
            "outcome_code": "empty_result",
            "context_block": {
                "placement": "append_last",
                "header": MEMORY_HEADER,
                "slots": [],
                "rendered": "",
            },
        }

    def response_for(self, path: str) -> dict[str, Any]:
        if path == "/v1/retrieve":
            return self.retrieve_response
        return {"status": "accepted"}

    def handle_error(self, request: object, client_address: object) -> None:
        # A client that hits its own deadline mid-request closes the socket while
        # this server is still stalling; the resulting BrokenPipeError is the
        # expected shape of that test, not a failure to report.
        pass


class _RecordingHandler(http.server.BaseHTTPRequestHandler):
    def _handle(self) -> None:
        server = cast(_RecordingServer, self.server)
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length) if length else b"{}"
        try:
            body: dict[str, Any] = json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            body = {"_raw": raw.decode("utf-8", "replace")}
        server.received.append((self.path, body))
        server.received_headers.append(dict(self.headers.items()))
        if server.stall_s:
            time.sleep(server.stall_s)
        response = server.response_for(self.path)
        code = 200 if self.path == "/v1/retrieve" else 202
        payload = json.dumps(response).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_POST(self) -> None:
        self._handle()

    def log_message(self, format: str, *args: object) -> None:  # silence stdlib access logs
        pass


@pytest.fixture
def fake_server() -> Iterator[_RecordingServer]:
    server = _RecordingServer(("127.0.0.1", 0), _RecordingHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


@pytest.fixture
def fake_server_url(fake_server: _RecordingServer) -> str:
    host_raw, port = fake_server.server_address[0], fake_server.server_address[1]
    host = host_raw.decode() if isinstance(host_raw, bytes) else host_raw
    return f"http://{host}:{port}"


def _wait_until(predicate: Callable[[], bool], timeout_s: float = 5.0) -> bool:
    """Poll for a background-thread effect. Polling, not sleeping, so the test
    fails on the *absence* of the effect rather than on a slow machine."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.01)
    return predicate()


def _sent_trace_events(server: _RecordingServer) -> list[dict[str, Any]]:
    return [
        evt
        for path, body in list(server.received)
        if path == "/v1/trace/batch"
        for evt in body["events"]
    ]


# --------------------------------------------------------------------------- #
# retrieve() against a dead server
# --------------------------------------------------------------------------- #


class TestRetrieveDegraded:
    def test_dead_server_returns_degraded_result_and_never_raises(self) -> None:
        client = TracebedClient(_closed_port_url(), flush_interval_s=3600)
        result = client.retrieve(agent_type="support-bot", run_ctx=_run_ctx())

        assert result.run_id_origin == "sdk"
        assert result.outcome_code == OutcomeCode.STORE_ERROR
        assert result.arm == Arm.MEMORY_ON
        assert result.context_block.slots == []
        assert result.context_block.rendered == ""
        assert result.context_block.header == MEMORY_HEADER

    def test_dead_server_mints_a_fresh_run_id_each_call(self) -> None:
        client = TracebedClient(_closed_port_url(), flush_interval_s=3600)
        first = client.retrieve(agent_type="support-bot", run_ctx=_run_ctx())
        second = client.retrieve(agent_type="support-bot", run_ctx=_run_ctx())
        assert first.run_id != second.run_id

    def test_retrieve_against_a_live_server_returns_its_response(
        self, fake_server: _RecordingServer, fake_server_url: str
    ) -> None:
        client = TracebedClient(fake_server_url, flush_interval_s=3600)
        result = client.retrieve(agent_type="support-bot", run_ctx=_run_ctx())
        assert result.run_id_origin == "server"
        assert str(result.run_id) == fake_server.retrieve_response["run_id"]
        [(path, body)] = [(p, b) for p, b in fake_server.received if p == "/v1/retrieve"]
        assert path == "/v1/retrieve"
        assert body["agent_type"] == "support-bot"
        # tool_manifest never rides on retrieve (C-05) -- run_ctx carries no such key
        assert "tool_manifest" not in body["run_ctx"]


# --------------------------------------------------------------------------- #
# The load-bearing latency property
# --------------------------------------------------------------------------- #


class TestHotPathLatency:
    def test_trace_and_feedback_p99_under_1ms_with_server_down_zero_exceptions(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        caplog.set_level(logging.DEBUG, logger="tracebed.sdk")
        client = TracebedClient(
            _closed_port_url(), buffer_capacity=200_000, flush_interval_s=3600
        )
        run = mint_run_id()
        n = 2500

        # Warm-up, discarded: absorbs one-time costs (lock object touch, first
        # method-resolution cache fill) that are not representative of steady
        # state and would otherwise pad the tail on a cold run.
        for _ in range(50):
            client.trace(run, ToolCall(type="tool_call", ts=_NOW, payload={}))

        trace_durations_ns: list[int] = []
        for i in range(n):
            event = ToolCall(type="tool_call", ts=_NOW, payload={"i": i})
            start = time.perf_counter_ns()
            client.trace(run, event)
            trace_durations_ns.append(time.perf_counter_ns() - start)

        feedback_durations_ns: list[int] = []
        for _ in range(n):
            feedback_event = FeedbackEvent(
                adapter=AdapterClass.VERDICT, outcome="positive", event_id=uuid4()
            )
            start = time.perf_counter_ns()
            client.feedback(run, feedback_event)
            feedback_durations_ns.append(time.perf_counter_ns() - start)

        trace_p99_ms = _p99_ms(trace_durations_ns)
        feedback_p99_ms = _p99_ms(feedback_durations_ns)

        assert trace_p99_ms <= 1.0, f"trace() p99={trace_p99_ms}ms over {n} calls"
        assert feedback_p99_ms <= 1.0, f"feedback() p99={feedback_p99_ms}ms over {n} calls"
        # No record means the internal except-and-log fail-open branch never
        # fired -- i.e. trace()/feedback() did not merely avoid *propagating*
        # an exception, none occurred internally at all.
        assert caplog.records == []

    def test_propose_memory_never_raises_with_server_down(self) -> None:
        client = TracebedClient(_closed_port_url(), flush_interval_s=3600)
        run = mint_run_id()
        proposal = MemoryProposal(
            mem_type="lesson", content="retry with backoff", claimed_scope="agent_type"
        )
        client.propose_memory(run, proposal)  # must not raise

    def test_propose_memory_reaches_the_propose_route_verbatim(
        self, fake_server: _RecordingServer, fake_server_url: str
    ) -> None:
        # "does not raise" alone is also satisfied by a no-op body, so pin the
        # actual effect: the proposal must reach POST /v1/propose_memory with
        # its fields intact and the run id the caller supplied.
        client = TracebedClient(fake_server_url, flush_interval_s=3600)
        run = mint_run_id()
        client.propose_memory(
            run,
            MemoryProposal(
                mem_type="lesson",
                content="retry with backoff",
                subject_tag="payments",
                claimed_scope="agent_type",
            ),
        )
        assert client.flush().sent == 1

        [(_, body)] = [(p, b) for p, b in fake_server.received if p == "/v1/propose_memory"]
        assert body["run_id"] == str(run.value)
        assert body["proposal"] == {
            "mem_type": "lesson",
            "content": "retry with backoff",
            "subject_tag": "payments",
            "claimed_scope": "agent_type",
        }

    def test_feedback_reaches_the_feedback_route_verbatim(
        self, fake_server: _RecordingServer, fake_server_url: str
    ) -> None:
        client = TracebedClient(fake_server_url, flush_interval_s=3600)
        run = mint_run_id()
        event_id = uuid4()
        client.feedback(
            run,
            FeedbackEvent(adapter=AdapterClass.DOWNSTREAM, outcome="negative", event_id=event_id),
        )
        assert client.flush().sent == 1

        [(_, body)] = [(p, b) for p, b in fake_server.received if p == "/v1/feedback"]
        assert body["run_id"] == str(run.value)
        assert body["event"]["adapter"] == "downstream"
        assert body["event"]["outcome"] == "negative"
        assert body["event"]["event_id"] == str(event_id)
        # The SDK never invents a weight — the wire model has no such field
        # (§3.5) and the server derives w from the adapter class (Task 15).
        assert "weight" not in body["event"]

    def test_flush_interval_must_be_positive(self) -> None:
        # A non-positive interval makes Event.wait() return instantly, turning
        # the flusher into a spin loop inside the *host* process.
        with pytest.raises(ValueError, match="flush_interval_s"):
            TracebedClient(_closed_port_url(), flush_interval_s=0)

    def test_on_operational_event_returns_none_in_phase_0(self) -> None:
        client = TracebedClient(_closed_port_url(), flush_interval_s=3600)
        run = mint_run_id()
        event = ToolCall(type="tool_call", ts=_NOW, payload={})
        assert client.on_operational_event(run, event) is None


# --------------------------------------------------------------------------- #
# flush(), run_end(), and arm stamping -- against the recording server
# --------------------------------------------------------------------------- #


class TestFlush:
    def test_flush_reports_sent_and_dropped_accurately(
        self, fake_server: _RecordingServer, fake_server_url: str
    ) -> None:
        client = TracebedClient(fake_server_url, buffer_capacity=5, flush_interval_s=3600)
        run = mint_run_id()
        for i in range(8):  # capacity 5: the first 3 must be dropped before any flush
            client.trace(run, ToolCall(type="tool_call", ts=_NOW, payload={"i": i}))

        report = client.flush()
        assert report == FlushReport(sent=5, dropped=3)

        # "dropped" is cumulative *since the last flush() return* (§10) -- a
        # second, empty flush must report zero of both, not re-report the drops.
        second = client.flush()
        assert second == FlushReport(sent=0, dropped=0)

        sent_events = [
            evt
            for path, body in fake_server.received
            if path == "/v1/trace/batch"
            for evt in body["events"]
        ]
        assert len(sent_events) == 5
        assert [evt["seq"] for evt in sent_events] == [3, 4, 5, 6, 7]

    def test_flush_against_dead_server_never_raises_and_reports_zero_sent(self) -> None:
        client = TracebedClient(_closed_port_url(), buffer_capacity=100, flush_interval_s=3600)
        run = mint_run_id()
        for i in range(4):
            client.trace(run, ToolCall(type="tool_call", ts=_NOW, payload={"i": i}))
        report = client.flush()
        assert report.sent == 0
        assert report.dropped == 0

    def test_run_end_appends_sentinel_with_final_seq_then_flushes(
        self, fake_server: _RecordingServer, fake_server_url: str
    ) -> None:
        client = TracebedClient(fake_server_url, flush_interval_s=3600)
        run = mint_run_id()
        client.trace(run, ToolCall(type="tool_call", ts=_NOW, payload={}))
        client.trace(run, ToolCall(type="tool_call", ts=_NOW, payload={}))

        client.run_end(run, "ok")  # documented to call flush() itself (§10)

        sent_events = [
            evt
            for path, body in fake_server.received
            if path == "/v1/trace/batch"
            for evt in body["events"]
            if evt["run_id"] == str(run.value)
        ]
        assert [evt["seq"] for evt in sent_events] == [0, 1, 2]
        assert sent_events[-1]["event"]["type"] == "run_end"
        assert sent_events[-1]["event"]["payload"]["status"] == "ok"

    def test_arm_is_stamped_onto_run_start_from_the_last_retrieve(
        self, fake_server: _RecordingServer, fake_server_url: str
    ) -> None:
        fake_server.retrieve_response = {
            **fake_server.retrieve_response,
            "arm": "holdout",
        }
        client = TracebedClient(fake_server_url, flush_interval_s=3600)
        result = client.retrieve(agent_type="support-bot", run_ctx=_run_ctx())
        run = RunId(result.run_id)
        assert result.arm == Arm.HOLDOUT

        client.trace(
            run, RunStart(type="run_start", ts=_NOW, payload={"query_text": "hi"})
        )
        report = client.flush()
        assert report.sent == 1

        [(_, body)] = [(p, b) for p, b in fake_server.received if p == "/v1/trace/batch"]
        assert body["events"][0]["event"]["payload"]["arm"] == "holdout"

    def test_caller_supplied_arm_is_never_overwritten(
        self, fake_server: _RecordingServer, fake_server_url: str
    ) -> None:
        fake_server.retrieve_response = {**fake_server.retrieve_response, "arm": "holdout"}
        client = TracebedClient(fake_server_url, flush_interval_s=3600)
        result = client.retrieve(agent_type="support-bot", run_ctx=_run_ctx())
        run = RunId(result.run_id)

        client.trace(
            run,
            RunStart(type="run_start", ts=_NOW, payload={"query_text": "hi", "arm": "memory_on"}),
        )
        client.flush()

        [(_, body)] = [(p, b) for p, b in fake_server.received if p == "/v1/trace/batch"]
        assert body["events"][0]["event"]["payload"]["arm"] == "memory_on"


class TestUnserialisablePayload:
    """`TraceEvent.payload` is `dict[str, Any]`, so a host CAN buffer a value
    with no JSON form. That must cost exactly that one event — not the batch,
    not the flusher thread, and never an exception thrown back at the host."""

    def test_one_unserialisable_event_does_not_take_the_batch_with_it(
        self, fake_server: _RecordingServer, fake_server_url: str
    ) -> None:
        client = TracebedClient(fake_server_url, flush_interval_s=3600)
        run = mint_run_id()
        client.trace(run, ToolCall(type="tool_call", ts=_NOW, payload={"i": 0}))
        client.trace(run, ToolCall(type="tool_call", ts=_NOW, payload={"bad": object()}))
        client.trace(run, ToolCall(type="tool_call", ts=_NOW, payload={"i": 2}))

        report = client.flush()  # must not raise

        assert report.sent == 2
        assert [evt["seq"] for evt in _sent_trace_events(fake_server)] == [0, 2]

    def test_run_end_does_not_raise_into_the_host_over_a_poison_event(
        self, fake_server: _RecordingServer, fake_server_url: str
    ) -> None:
        client = TracebedClient(fake_server_url, flush_interval_s=3600)
        run = mint_run_id()
        # A plain object(): pydantic happily coerces sets/Decimals in JSON mode,
        # so only a genuinely unknown type exercises the failure path.
        client.trace(run, ToolCall(type="tool_call", ts=_NOW, payload={"bad": object()}))

        client.run_end(run, "ok")  # run_end() flushes; it must still not raise

        sentinels = [
            evt for evt in _sent_trace_events(fake_server) if evt["event"]["type"] == "run_end"
        ]
        assert len(sentinels) == 1
        assert sentinels[0]["seq"] == 1

    def test_background_flusher_survives_a_poison_event(
        self, fake_server: _RecordingServer, fake_server_url: str
    ) -> None:
        # The thread-death case: an exception escaping the flush loop kills the
        # daemon thread permanently, after which nothing is ever sent again and
        # the ring silently fills. Proof of life = a later event still arrives
        # without any explicit flush().
        client = TracebedClient(fake_server_url, flush_interval_s=0.05)
        run = mint_run_id()
        client.trace(run, ToolCall(type="tool_call", ts=_NOW, payload={"bad": object()}))
        assert _wait_until(lambda: client._flush_errors > 0)

        client.trace(run, ToolCall(type="tool_call", ts=_NOW, payload={"i": 1}))
        assert _wait_until(lambda: len(_sent_trace_events(fake_server)) == 1)
        assert _sent_trace_events(fake_server)[0]["seq"] == 1
        assert client._flusher.is_alive()


class TestBackgroundFlusher:
    def test_events_are_sent_without_any_explicit_flush(
        self, fake_server: _RecordingServer, fake_server_url: str
    ) -> None:
        # Nothing else in this module exercises the background thread (every
        # other test pins flush_interval_s=3600), so without this a client that
        # never started its flusher would still look green.
        client = TracebedClient(fake_server_url, flush_interval_s=0.05)
        run = mint_run_id()
        client.trace(run, ToolCall(type="tool_call", ts=_NOW, payload={"i": 0}))
        client.feedback(
            run, FeedbackEvent(adapter=AdapterClass.VERDICT, outcome="positive", event_id=uuid4())
        )

        assert _wait_until(lambda: len(_sent_trace_events(fake_server)) == 1)
        assert _wait_until(
            lambda: any(p == "/v1/feedback" for p, _ in list(fake_server.received))
        )

    def test_background_pass_does_not_consume_the_drop_counter(
        self, fake_server: _RecordingServer, fake_server_url: str
    ) -> None:
        # §10: FlushReport.dropped is "cumulative drops since last flush()
        # return". If a background pass advanced that watermark, the default 1s
        # cadence would eat every drop before the host's own flush() saw one and
        # D-033's data-loss counter would read zero exactly while data is lost.
        client = TracebedClient(fake_server_url, buffer_capacity=5, flush_interval_s=0.2)
        run = mint_run_id()
        for i in range(8):  # capacity 5 => the oldest 3 are dropped
            client.trace(run, ToolCall(type="tool_call", ts=_NOW, payload={"i": i}))

        assert _wait_until(lambda: len(_sent_trace_events(fake_server)) == 5)

        report = client.flush()
        assert report.sent == 0  # the background pass already delivered them
        assert report.dropped == 3  # ...but the drops are still the host's to see
        assert client.flush().dropped == 0  # and are reported exactly once

    def test_dropping_the_client_stops_its_flusher_thread(self) -> None:
        # The thread must not be what keeps a discarded client (and its whole
        # ring buffer and connection pool) resident for the life of the host.
        client = TracebedClient(_closed_port_url(), flush_interval_s=0.05)
        thread = client._flusher
        assert thread.is_alive()

        del client
        gc.collect()

        thread.join(timeout=5)
        assert not thread.is_alive()


class TestFlushDeadline:
    def test_timeout_s_bounds_the_whole_flush_not_each_batch(
        self, fake_server: _RecordingServer, fake_server_url: str
    ) -> None:
        # run_end() flushes on every run, so an unreachable/stalled server must
        # cost the host its stated budget ONCE, not once per 500-item batch.
        fake_server.stall_s = 2.0
        client = TracebedClient(fake_server_url, buffer_capacity=2000, flush_interval_s=3600)
        run = mint_run_id()
        for i in range(1200):  # three drain batches (500 + 500 + 200)
            client.trace(run, ToolCall(type="tool_call", ts=_NOW, payload={"i": i}))

        started = time.monotonic()
        report = client.flush(timeout_s=0.25)
        elapsed = time.monotonic() - started

        assert report.sent == 0
        # The property is that timeout_s bounds the WHOLE call: a per-request
        # interpretation would have drained and destroyed all three batches
        # against the stall, so fewer than three attempts is the assertion that
        # actually distinguishes the two readings.
        #
        # NOT `== 1`. `_do_flush` re-checks `monotonic_ms() < deadline_ms` at the
        # top of each iteration, so when the first stalled request returns a
        # hair BEFORE the deadline the loop legitimately issues a second batch
        # with the sliver of budget left, which `_post` then refuses or times
        # out on. The server records that request on arrival, so `received`
        # becomes 2 while the deadline is still honoured -- correct behaviour
        # that `== 1` scored as a failure. It reproduced roughly one run in
        # three under full-suite CPU contention and was reported as flaky by
        # three separate Phase 3 chunks.
        attempts = len(fake_server.received)
        assert 1 <= attempts < 3
        assert elapsed < 1.5
        # And the undrained remainder is still buffered, not thrown away.
        # Derived from `attempts` rather than hardcoded, because `_post`'s own
        # docstring makes a drained-then-failed batch lost by design: exactly
        # `_MAX_DRAIN_BATCH` items go with each attempt that reached the wire.
        fake_server.stall_s = 0.0
        assert client.flush(timeout_s=10.0).sent == 1200 - 500 * attempts


class TestAuthHeaders:
    def test_api_key_and_bearer_token_are_attached_to_flushed_writes(
        self, fake_server: _RecordingServer, fake_server_url: str
    ) -> None:
        client = TracebedClient(
            fake_server_url,
            api_key="tb_sk_deadbeef.secret",
            token_provider=lambda: "jwt-token",
            flush_interval_s=3600,
        )
        run = mint_run_id()
        client.trace(run, ToolCall(type="tool_call", ts=_NOW, payload={}))
        client.flush()

        [headers] = fake_server.received_headers
        assert headers["X-API-Key"] == "tb_sk_deadbeef.secret"
        assert headers["Authorization"] == "Bearer jwt-token"

    def test_a_raising_token_provider_never_reaches_the_caller(
        self, fake_server: _RecordingServer, fake_server_url: str
    ) -> None:
        def boom() -> str:
            raise RuntimeError("token endpoint down")

        client = TracebedClient(fake_server_url, token_provider=boom, flush_interval_s=3600)
        result = client.retrieve(agent_type="support-bot", run_ctx=_run_ctx())  # must not raise
        assert result.run_id_origin == "server"
        assert "Authorization" not in fake_server.received_headers[0]


class TestWireShapeMatchesTheServerModels:
    """The one thing the recording server cannot check: whether the bodies the
    SDK emits are actually ACCEPTED by the routes they target.

    Every other flush test asserts against a fake that happily accepts any
    JSON, so a field rename or a missing `seq` would stay green here and 422 in
    production. These validate the captured bodies against api-auth's real
    `extra="forbid"` wire models (§9.3). The import is test-only — §14's
    "no imports beyond domain + httpx" governs `src/tracebed/sdk/`, and the
    point of this test is precisely to couple the two chunks' expectations.
    """

    def test_every_body_the_sdk_posts_validates_against_its_route_model(
        self, fake_server: _RecordingServer, fake_server_url: str
    ) -> None:
        from tracebed.api.models import FeedbackIn, ProposeIn, RetrieveIn, TraceBatchIn

        client = TracebedClient(fake_server_url, flush_interval_s=3600)
        client.retrieve(
            agent_type="support-bot",
            run_ctx=RunContext(
                query_text="q",
                workflow_template="wf",
                user_ref="u",
                tool_manifest=["search", "refund"],
            ),
            session_id="s-1",
            prefetch_for="next-step",
        )
        run = mint_run_id()
        client.trace(run, RunStart(type="run_start", ts=_NOW, payload={"query_text": "q"}))
        client.trace(run, ToolCall(type="tool_call", ts=_NOW, payload={"tool": "search"}))
        client.feedback(
            run, FeedbackEvent(adapter=AdapterClass.VERDICT, outcome="positive", event_id=uuid4())
        )
        client.propose_memory(
            run,
            MemoryProposal(mem_type="semantic", content="c", claimed_scope="project_shared"),
        )
        client.run_end(run, "ok")

        models = {
            "/v1/retrieve": RetrieveIn,
            "/v1/trace/batch": TraceBatchIn,
            "/v1/feedback": FeedbackIn,
            "/v1/propose_memory": ProposeIn,
        }
        seen: set[str] = set()
        for path, body in fake_server.received:
            assert path in models, f"SDK posted to an unmodelled route: {path}"
            models[path].model_validate(body)  # extra="forbid" => a stray key is a failure
            seen.add(path)
        assert seen == set(models), f"never exercised: {set(models) - seen}"

    def test_a_full_drain_never_exceeds_the_batch_route_cap(
        self, fake_server: _RecordingServer, fake_server_url: str
    ) -> None:
        from tracebed.api.models import MAX_TRACE_BATCH_EVENTS

        client = TracebedClient(fake_server_url, buffer_capacity=5000, flush_interval_s=3600)
        run = mint_run_id()
        for i in range(1200):
            client.trace(run, ToolCall(type="tool_call", ts=_NOW, payload={"i": i}))
        client.flush(timeout_s=30.0)

        batches = [b for p, b in fake_server.received if p == "/v1/trace/batch"]
        assert batches, "nothing was sent"
        assert max(len(b["events"]) for b in batches) <= MAX_TRACE_BATCH_EVENTS


class TestConcurrentTraceOverTheWire:
    def test_n_threads_tracing_same_run_produce_gapless_seq_end_to_end(
        self, fake_server: _RecordingServer, fake_server_url: str
    ) -> None:
        client = TracebedClient(fake_server_url, buffer_capacity=100_000, flush_interval_s=3600)
        run = mint_run_id()
        n_threads = 16
        per_thread = 100

        def worker() -> None:
            for i in range(per_thread):
                client.trace(run, ToolCall(type="tool_call", ts=_NOW, payload={"i": i}))

        threads = [threading.Thread(target=worker) for _ in range(n_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        report = client.flush()
        assert report.sent == n_threads * per_thread

        seqs = sorted(
            evt["seq"]
            for path, body in fake_server.received
            if path == "/v1/trace/batch"
            for evt in body["events"]
            if evt["run_id"] == str(run.value)
        )
        assert seqs == list(range(n_threads * per_thread))
