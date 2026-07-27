"""Fake agent runtime — SDK overhead measurement (PHASE-0 Task 18).

Simulates N agent runs — `retrieve() -> tool events -> run_end() -> a later
feedback()` — through the real `tracebed.sdk.client.TracebedClient`, and
measures per-call latency at p50/p99. Runs in exactly one of two modes,
determined by a real reachability probe (never a guessed default):

  * **live**  — `TB_HARNESS_BASE_URL` (default `http://127.0.0.1:8110`)
    answers `GET /healthz`. If `TB_HARNESS_API_KEY` is also set, runs are
    authenticated and every call is a genuine round trip; unauthenticated,
    `retrieve()` still measures a real HTTP round trip (against a 401), which
    is reported (`authenticated=False`) rather than silently presented as
    equivalent to an authenticated one.
  * **fakes** — no live server. `TracebedClient` is pointed at a throwaway
    local HTTP stub (bound on an ephemeral port, answers every request with a
    prompt 503) rather than at a genuinely unreachable address: a build
    machine's TCP stack does not reliably refuse a connection to a closed
    local port *fast* (observed on this repo's own dev machine — connecting
    to an unbound `127.0.0.1` port silently ate the full connect timeout
    instead of an instant ECONNREFUSED, turning a 200-run measurement into
    minutes), and a slow-to-fail address would leak that wait time into every
    `retrieve()`/`run_end()` sample. The stub answers in microseconds, so
    "the queue is stopped" is simulated by what the SERVER does with the
    request (refuse it), not by how long the OS takes to notice nobody is
    listening. `trace()`/`feedback()` never touch the network either way
    (PHASE0-CONTRACT.md §10) — the stub exists for `retrieve()`/`run_end()`'s
    sake, and this is exactly the condition under which the hot path's
    sub-millisecond budget is provable.

The one number the Phase 0 gate cares about is `hot_path_p99_ms` — the
combined p99 of every `trace()` and `feedback()` call (the two operations the
contract promises are ≤1ms, dict-build-and-ring-append only). `retrieve()`
and `run_end()` (which internally calls `flush()`, i.e. does real I/O) are
reported separately because the contract makes no sub-millisecond promise
about either.

Callable as a library (`run_fake_runtime(...)`, what `harness/phase0_gate.py`
uses) or as a script: `python harness/fake_runtime.py [--n-runs N] [--json]`.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import threading
import time
import uuid
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Literal

import httpx

from tracebed.domain.enums import AdapterClass
from tracebed.domain.events import (
    FeedbackEvent,
    RunContext,
    RunStart,
    ToolCall,
    ToolResult,
)
from tracebed.domain.ids import RunId
from tracebed.sdk.client import TracebedClient

__all__ = [
    "DEFAULT_BASE_URL",
    "HOT_PATH_BUDGET_MS",
    "FakeRuntimeReport",
    "LatencyStats",
    "detect_mode",
    "main",
    "run_fake_runtime",
]

DEFAULT_BASE_URL = "http://127.0.0.1:8110"
# PHASE-0.md Task 18 / PHASE0-CONTRACT.md §10: trace()/feedback() overhead
# ceiling under a stopped queue.
HOT_PATH_BUDGET_MS = 1.0
_HEALTHZ_TIMEOUT_S = 0.5
_STUB_RESPONSE_BODY = b"{}"


class _StubServerHandler(BaseHTTPRequestHandler):
    """Answers every request with an immediate 503 — the `fakes`-mode
    backend (module docstring: a fast, deliberately-unavailable server, not
    a slow-to-refuse closed port)."""

    server_version = "tracebed-fake-runtime-stub/1"

    def _reply(self) -> None:
        self.send_response(503)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(_STUB_RESPONSE_BODY)))
        self.end_headers()
        self.wfile.write(_STUB_RESPONSE_BODY)

    def do_GET(self) -> None:
        self._reply()

    def do_POST(self) -> None:
        self._reply()

    def log_message(self, format: str, *args: object) -> None:
        pass  # silence per-request stderr logging -- this runs N*(3+2K) times


@contextmanager
def _stub_server() -> Iterator[str]:
    """A throwaway local HTTP server bound to an ephemeral port, answering
    every request with a prompt 503. See module docstring for why this
    exists instead of pointing at a closed port."""
    server = ThreadingHTTPServer(("127.0.0.1", 0), _StubServerHandler)
    thread = threading.Thread(
        target=server.serve_forever, name="fake-runtime-stub-server", daemon=True
    )
    thread.start()
    try:
        port = server.server_address[1]
        yield f"http://127.0.0.1:{port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5.0)


@dataclass(frozen=True, slots=True)
class LatencyStats:
    count: int
    p50_ms: float
    p99_ms: float
    max_ms: float
    mean_ms: float


@dataclass(frozen=True, slots=True)
class FakeRuntimeReport:
    mode: Literal["live", "fakes"]
    base_url: str
    authenticated: bool
    n_runs: int
    tool_events_per_run: int
    retrieve: LatencyStats
    trace: LatencyStats
    feedback: LatencyStats
    run_end: LatencyStats
    hot_path_p99_ms: float
    """p99 over the MERGED trace()+feedback() samples — the number the gate checks."""
    hot_path_budget_ms: float
    hot_path_ok: bool
    outcome_codes: dict[str, int]
    """`RetrieveResult.outcome_code` tally — lets a reader see at a glance
    whether `retrieve()` samples reflect real 200s or degraded fail-open
    results (expected and correct in `fakes` mode)."""


def _percentile(samples: Sequence[float], pct: float) -> float:
    """Linear-interpolation percentile (the common "R-7" method) — no numpy
    dependency (D-036's closed dependency set), and this harness is not on
    the hot path so a few float ops per call is not a purity concern."""
    if not samples:
        return 0.0
    ordered = sorted(samples)
    if len(ordered) == 1:
        return ordered[0]
    rank = (len(ordered) - 1) * (pct / 100.0)
    lo = math.floor(rank)
    hi = math.ceil(rank)
    if lo == hi:
        return ordered[int(rank)]
    frac = rank - lo
    return ordered[int(lo)] * (1.0 - frac) + ordered[int(hi)] * frac


def _stats(samples: list[float]) -> LatencyStats:
    return LatencyStats(
        count=len(samples),
        p50_ms=_percentile(samples, 50),
        p99_ms=_percentile(samples, 99),
        max_ms=max(samples) if samples else 0.0,
        mean_ms=(sum(samples) / len(samples)) if samples else 0.0,
    )


def detect_mode(base_url: str, *, timeout_s: float = _HEALTHZ_TIMEOUT_S) -> bool:
    """True iff `GET {base_url}/healthz` answers 200 within `timeout_s`.

    A real probe, not a flag: `TB_HARNESS_BASE_URL` being *set* is not
    evidence a server is actually listening there, and reporting "live" for
    an address nothing answers would make the gate report claim a mode that
    never ran.
    """
    try:
        response = httpx.get(f"{base_url.rstrip('/')}/healthz", timeout=timeout_s)
    except (httpx.TransportError, httpx.HTTPError):
        return False
    return response.status_code == 200


def _run_one(
    client: TracebedClient, agent_type: str, run_index: int, tool_events_per_run: int
) -> tuple[float, str, list[float], list[float], float]:
    """One simulated run. Returns (retrieve_ms, outcome_code, trace_samples_ms,
    feedback_samples_ms, run_end_ms)."""
    trace_samples: list[float] = []

    t0 = time.perf_counter()
    result = client.retrieve(
        agent_type=agent_type,
        run_ctx=RunContext(query_text=f"fake-runtime probe query #{run_index}"),
    )
    retrieve_ms = (time.perf_counter() - t0) * 1000.0
    run_id = RunId(result.run_id)

    t0 = time.perf_counter()
    client.trace(
        run_id,
        RunStart(
            type="run_start",
            ts=datetime.now(UTC),
            payload={"query_text": f"fake-runtime probe query #{run_index}"},
        ),
    )
    trace_samples.append((time.perf_counter() - t0) * 1000.0)

    for tool_index in range(tool_events_per_run):
        tool_id = f"fake-tool-{tool_index}"
        t0 = time.perf_counter()
        client.trace(
            run_id,
            ToolCall(type="tool_call", ts=datetime.now(UTC), payload={"tool_id": tool_id}),
        )
        trace_samples.append((time.perf_counter() - t0) * 1000.0)

        t0 = time.perf_counter()
        client.trace(
            run_id,
            ToolResult(
                type="tool_result", ts=datetime.now(UTC), payload={"tool_id": tool_id, "ok": True}
            ),
        )
        trace_samples.append((time.perf_counter() - t0) * 1000.0)

    t0 = time.perf_counter()
    client.feedback(
        run_id,
        FeedbackEvent(adapter=AdapterClass.IMPLICIT, outcome="positive", event_id=uuid.uuid4()),
    )
    feedback_ms = (time.perf_counter() - t0) * 1000.0

    # run_end() calls flush() internally (real I/O) -- measured separately,
    # never folded into the hot-path budget (module docstring).
    t0 = time.perf_counter()
    client.run_end(run_id, "ok")
    run_end_ms = (time.perf_counter() - t0) * 1000.0

    return retrieve_ms, result.outcome_code.value, trace_samples, [feedback_ms], run_end_ms


def _simulate(
    dial_url: str,
    api_key: str | None,
    n_runs: int,
    tool_events_per_run: int,
    agent_type: str,
) -> tuple[list[float], list[float], list[float], list[float], dict[str, int]]:
    """Builds one `TracebedClient` against `dial_url` and runs the whole
    simulation loop. Split out from `run_fake_runtime` so the `fakes`-mode
    caller can hold `dial_url`'s stub server open for exactly this call's
    lifetime, no longer (`_stub_server()` is a context manager)."""
    client = TracebedClient(
        dial_url,
        api_key=api_key,
        buffer_capacity=10_000,
        # Explicit flush() per run_end() already drains the buffer; a short
        # background interval just keeps any stray leftovers (feedback/proposal
        # items the background loop, not run_end, is responsible for) from
        # sitting around for the whole measurement window.
        flush_interval_s=0.25,
    )

    retrieve_ms: list[float] = []
    trace_ms: list[float] = []
    feedback_ms: list[float] = []
    run_end_ms: list[float] = []
    outcome_codes: dict[str, int] = {}

    try:
        for i in range(n_runs):
            r_ms, outcome_code, t_samples, f_samples, e_ms = _run_one(
                client, agent_type, i, tool_events_per_run
            )
            retrieve_ms.append(r_ms)
            outcome_codes[outcome_code] = outcome_codes.get(outcome_code, 0) + 1
            trace_ms.extend(t_samples)
            feedback_ms.extend(f_samples)
            run_end_ms.append(e_ms)
    finally:
        client.flush(timeout_s=2.0)

    return retrieve_ms, trace_ms, feedback_ms, run_end_ms, outcome_codes


def run_fake_runtime(
    *,
    n_runs: int = 200,
    tool_events_per_run: int = 3,
    base_url: str | None = None,
    api_key: str | None = None,
    agent_type: str = "fake-runtime-agent",
) -> FakeRuntimeReport:
    """Runs the simulation and returns a `FakeRuntimeReport`. Never raises on
    a dead server — that is the entire point of `fakes` mode; it raises only
    for a genuinely programmer-error argument (`n_runs < 1`)."""
    if n_runs < 1:
        raise ValueError("n_runs must be >= 1")
    if tool_events_per_run < 0:
        raise ValueError("tool_events_per_run must be >= 0")

    resolved_base_url = base_url if base_url is not None else os.environ.get(
        "TB_HARNESS_BASE_URL", DEFAULT_BASE_URL
    )
    resolved_api_key = api_key if api_key is not None else os.environ.get("TB_HARNESS_API_KEY")

    live = detect_mode(resolved_base_url)
    mode: Literal["live", "fakes"] = "live" if live else "fakes"
    authenticated = bool(live and resolved_api_key)

    if live:
        dial_url = resolved_base_url
        measurement = _simulate(
            dial_url, resolved_api_key, n_runs, tool_events_per_run, agent_type
        )
    else:
        with _stub_server() as dial_url:
            measurement = _simulate(dial_url, None, n_runs, tool_events_per_run, agent_type)

    retrieve_ms, trace_ms, feedback_ms, run_end_ms, outcome_codes = measurement
    hot_path_samples = trace_ms + feedback_ms
    hot_path_p99 = _percentile(hot_path_samples, 99)

    return FakeRuntimeReport(
        mode=mode,
        base_url=dial_url,
        authenticated=authenticated,
        n_runs=n_runs,
        tool_events_per_run=tool_events_per_run,
        retrieve=_stats(retrieve_ms),
        trace=_stats(trace_ms),
        feedback=_stats(feedback_ms),
        run_end=_stats(run_end_ms),
        hot_path_p99_ms=hot_path_p99,
        hot_path_budget_ms=HOT_PATH_BUDGET_MS,
        hot_path_ok=hot_path_p99 <= HOT_PATH_BUDGET_MS,
        outcome_codes=outcome_codes,
    )


def render_text(report: FakeRuntimeReport) -> str:
    lines = [
        f"mode: {report.mode} ({report.base_url})"
        + (" [authenticated]" if report.authenticated else " [no credential]" if report.mode == "live" else ""),
        f"runs: {report.n_runs}, tool events/run: {report.tool_events_per_run}",
        "",
        f"{'op':<10} {'n':>6} {'p50 (ms)':>10} {'p99 (ms)':>10} {'max (ms)':>10} {'mean (ms)':>10}",
    ]
    for label, stats in (
        ("retrieve", report.retrieve),
        ("trace", report.trace),
        ("feedback", report.feedback),
        ("run_end", report.run_end),
    ):
        lines.append(
            f"{label:<10} {stats.count:>6} {stats.p50_ms:>10.4f} {stats.p99_ms:>10.4f} "
            f"{stats.max_ms:>10.4f} {stats.mean_ms:>10.4f}"
        )
    lines.append("")
    lines.append(f"retrieve outcome_code tally: {report.outcome_codes}")
    lines.append("")
    verdict = "PASS" if report.hot_path_ok else "FAIL"
    lines.append(
        f"hot-path (trace+feedback) p99 = {report.hot_path_p99_ms:.4f}ms "
        f"(budget {report.hot_path_budget_ms:.2f}ms): {verdict}"
    )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--n-runs", type=int, default=200)
    parser.add_argument("--tool-events-per-run", type=int, default=3)
    parser.add_argument("--base-url", default=None)
    parser.add_argument("--api-key", default=None)
    parser.add_argument("--json", action="store_true", help="emit JSON instead of a text table")
    args = parser.parse_args(argv)

    report = run_fake_runtime(
        n_runs=args.n_runs,
        tool_events_per_run=args.tool_events_per_run,
        base_url=args.base_url,
        api_key=args.api_key,
    )

    if args.json:
        print(json.dumps(_report_to_json(report), indent=2, sort_keys=True))
    else:
        print(render_text(report))

    return 0 if report.hot_path_ok else 1


def _report_to_json(report: FakeRuntimeReport) -> dict[str, Any]:
    return asdict(report)


if __name__ == "__main__":
    raise SystemExit(main())
