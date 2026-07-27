"""Tests for the Gemini `/embeddings` driver (`gemini.py`).

Every test fakes the HTTP transport with `httpx.MockTransport` (or a
hand-rolled `httpx.BaseTransport` when a *streaming* response is needed) --
never mocks `GeminiEmbeddingClient` itself, per the chunk's testing rule: the
class under test runs its real code path down to the wire, and only the socket
is replaced. Time is `FakeClock`, so the budget tests are deterministic and
cost no wall-clock seconds.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Iterator, Sequence

import httpx
import pytest

from tracebed.adapters.embedding.gemini import GeminiEmbeddingClient
from tracebed.adapters.embedding.pinning import (
    EmbeddingDimensionMismatch,
    EmbeddingProviderError,
    ModelPin,
)
from tracebed.adapters.ports import EmbeddingPort
from tracebed.domain.clock import Clock, FakeClock
from tracebed.domain.errors import EmbeddingTimeout

# `pytest -m phase1` is what `harness/phase1_gate.py` runs; an unmarked file is
# not merely skipped by that selector, it is never collected, so its coverage is
# invisible to the gate report rather than reported as missing.
pytestmark = pytest.mark.phase1

PIN = ModelPin(model_id="gemini-embedding-2", model_version="2026-01", dim=3)

Handler = Callable[[httpx.Request], httpx.Response]


def _client(handler: Handler, *, clock: Clock | None = None) -> GeminiEmbeddingClient:
    transport = httpx.MockTransport(handler)
    return GeminiEmbeddingClient(
        base_url="https://embeddings.example/v1",
        api_key="test-key",
        pin=PIN,
        http=httpx.Client(transport=transport),
        # A FakeClock that never advances by default: no test outside the two
        # budget tests below may depend on how fast the machine running it is,
        # or a loaded CI box turns a correct driver red.
        clock=clock if clock is not None else FakeClock(),
    )


def _ok(vectors: Sequence[Sequence[float]]) -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "data": [
                {"index": i, "embedding": list(vector)} for i, vector in enumerate(vectors)
            ]
        },
    )


class _DripTransport(httpx.BaseTransport):
    """Headers instantly, then the body one small chunk at a time.

    Each chunk costs `ms_per_chunk` of the FakeClock's budget, so *no single
    read* ever exceeds the per-operation `httpx.Timeout` -- exactly the shape
    that a per-operation timeout cannot catch and only a total deadline can.
    """

    def __init__(self, clock: FakeClock, body: bytes, *, chunk_size: int, ms_per_chunk: float):
        self._clock = clock
        self._body = body
        self._chunk_size = chunk_size
        self._ms_per_chunk = ms_per_chunk
        self.requests: list[httpx.Request] = []

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        body, chunk_size, ms = self._body, self._chunk_size, self._ms_per_chunk
        clock = self._clock

        def stream() -> Iterator[bytes]:
            for start in range(0, len(body), chunk_size):
                clock.advance(ms=ms)
                yield body[start : start + chunk_size]

        return httpx.Response(
            200, content=stream(), headers={"content-type": "application/json"}
        )


def test_satisfies_embedding_port_protocol() -> None:
    embedder = _client(lambda request: _ok([]))
    assert isinstance(embedder, EmbeddingPort)


def test_model_id_and_version_come_from_the_pin() -> None:
    embedder = _client(lambda request: _ok([]))
    assert embedder.model_id == "gemini-embedding-2"
    assert embedder.model_version == "2026-01"


def test_empty_input_returns_empty_without_a_network_call() -> None:
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        raise AssertionError("must not reach the transport for an empty batch")

    embedder = _client(handler)
    assert embedder.embed([], timeout_ms=200) == []
    assert calls == []


def test_batch_returns_vectors_in_input_order_even_when_the_wire_scrambles_them() -> None:
    """The fake returns `data` out of request order with distinguishable
    vectors; a driver that trusted list position instead of the `index`
    field would silently attribute vector B to input A -- the "silent and
    catastrophic" failure mode this test exists to catch."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "data": [
                    {"index": 2, "embedding": [2.0, 2.1, 2.2]},
                    {"index": 0, "embedding": [0.0, 0.1, 0.2]},
                    {"index": 1, "embedding": [1.0, 1.1, 1.2]},
                ]
            },
        )

    embedder = _client(handler)
    vectors = embedder.embed(["zero", "one", "two"], timeout_ms=200)
    assert vectors == [[0.0, 0.1, 0.2], [1.0, 1.1, 1.2], [2.0, 2.1, 2.2]]


@pytest.mark.parametrize(
    "indices",
    [
        pytest.param([0, 0], id="duplicate-index"),
        pytest.param([1, 2], id="out-of-range-index"),
        pytest.param([-1, 0], id="negative-index"),
    ],
)
def test_indices_that_are_not_a_permutation_of_the_batch_are_rejected(
    indices: list[int],
) -> None:
    """Right count, wrong identities. Sorting by `index` would accept every one
    of these and silently attribute one input's vector to another -- the count
    check and the sort both pass, so only an explicit permutation check
    catches it."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "data": [
                    {"index": idx, "embedding": [float(idx), 0.0, 0.0]} for idx in indices
                ]
            },
        )

    embedder = _client(handler)
    with pytest.raises(EmbeddingProviderError):
        embedder.embed(["a", "b"], timeout_ms=200)


def test_request_carries_model_input_and_an_explicit_derived_timeout() -> None:
    seen: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["timeout"] = request.extensions.get("timeout")
        seen["body"] = json.loads(request.content)
        seen["auth"] = request.headers.get("authorization")
        return _ok([[1.0, 2.0, 3.0]])

    embedder = _client(handler)
    embedder.embed(["hello"], timeout_ms=250)

    # The timeout passed to httpx is derived from THIS call's argument, not a
    # constructor-level default -- the caller owns the budget per call.
    assert seen["timeout"] == {"connect": 0.25, "read": 0.25, "write": 0.25, "pool": 0.25}
    assert seen["body"] == {"model": "gemini-embedding-2", "input": ["hello"]}
    assert seen["auth"] == "Bearer test-key"


def test_timeout_raises_embedding_timeout_and_does_not_retry() -> None:
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        raise httpx.ReadTimeout("simulated slow embedding endpoint", request=request)

    embedder = _client(handler)
    with pytest.raises(EmbeddingTimeout):
        embedder.embed(["slow"], timeout_ms=150)
    # Exactly one transport call: an internal retry would spend the whole
    # 300ms total budget and turn a would-be `degraded_lexical` outcome into
    # `timeout_prefix_only` instead.
    assert len(calls) == 1


def test_an_exhausted_budget_never_opens_a_socket() -> None:
    """A caller arriving with nothing left of its sub-budget must get
    `EmbeddingTimeout` *before* any work -- connecting is itself unbounded
    work charged against a budget of zero."""
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return _ok([[1.0, 2.0, 3.0]])

    embedder = _client(handler)
    for spent_budget in (0, -25):
        with pytest.raises(EmbeddingTimeout):
            embedder.embed(["anything"], timeout_ms=spent_budget)
    assert calls == []


def test_slow_drip_body_is_cut_off_by_the_total_deadline() -> None:
    """THE case a per-operation `httpx.Timeout` cannot catch.

    Headers arrive instantly and every individual read completes well inside
    the 200ms read timeout, but the body drips: 12 chunks x 40ms = 480ms,
    more than double the embed sub-budget, while httpx sees nothing wrong.
    Without a total deadline re-checked between chunks this returns a vector
    long after the 300ms total retrieval budget is gone (PLAN.md §2
    invariant 2), and the run blocks instead of degrading to lexical-only.
    """
    clock = FakeClock()
    body = json.dumps({"data": [{"index": 0, "embedding": [1.0, 2.0, 3.0]}]}).encode()
    chunk_size = max(1, len(body) // 12)
    transport = _DripTransport(clock, body, chunk_size=chunk_size, ms_per_chunk=40.0)
    embedder = GeminiEmbeddingClient(
        base_url="https://embeddings.example/v1",
        api_key="test-key",
        pin=PIN,
        http=httpx.Client(transport=transport),
        clock=clock,
    )

    with pytest.raises(EmbeddingTimeout):
        embedder.embed(["slow body"], timeout_ms=200)
    assert len(transport.requests) == 1
    assert clock.monotonic_ms() > 200.0


def test_a_chunked_body_that_arrives_inside_the_budget_still_succeeds() -> None:
    """The control for the drip test above: same streamed, multi-chunk shape,
    same code path, but the whole body lands inside the budget. Guards against
    the deadline check degenerating into "any chunked response fails"."""
    clock = FakeClock()
    body = json.dumps({"data": [{"index": 0, "embedding": [1.0, 2.0, 3.0]}]}).encode()
    chunk_size = max(1, len(body) // 12)
    transport = _DripTransport(clock, body, chunk_size=chunk_size, ms_per_chunk=1.0)
    embedder = GeminiEmbeddingClient(
        base_url="https://embeddings.example/v1",
        api_key="test-key",
        pin=PIN,
        http=httpx.Client(transport=transport),
        clock=clock,
    )

    assert embedder.embed(["fast body"], timeout_ms=200) == [[1.0, 2.0, 3.0]]
    assert clock.monotonic_ms() < 200.0


def test_an_oversized_body_is_refused_before_it_is_buffered() -> None:
    """The payload is otherwise perfectly valid -- a driver without a size cap
    parses it and returns vectors. The cap exists so a compromised or
    misbehaving endpoint cannot make the hot path allocate arbitrary memory
    inside a 200ms budget."""
    padding = "x" * 400_000
    body = json.dumps(
        {
            "data": [{"index": 0, "embedding": [1.0, 2.0, 3.0]}],
            "usage": {"note": padding},
        }
    ).encode()

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=body, headers={"content-type": "application/json"})

    embedder = _client(handler)
    with pytest.raises(EmbeddingProviderError):
        embedder.embed(["big"], timeout_ms=200)


def test_a_body_within_the_cap_is_accepted() -> None:
    """Control for the cap test: the same envelope shape, comfortably under
    the bound, must still parse -- the cap must not reject real responses that
    carry `usage`/`model` fields alongside the vectors."""
    body = json.dumps(
        {
            "object": "list",
            "model": "gemini-embedding-2",
            "data": [{"index": 0, "embedding": [1.0, 2.0, 3.0]}],
            "usage": {"prompt_tokens": 4, "total_tokens": 4},
        }
    ).encode()

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=body, headers={"content-type": "application/json"})

    embedder = _client(handler)
    assert embedder.embed(["small"], timeout_ms=200) == [[1.0, 2.0, 3.0]]


@pytest.mark.parametrize(
    "literal",
    [
        pytest.param(b"NaN", id="nan"),
        pytest.param(b"Infinity", id="infinity"),
        pytest.param(b"-Infinity", id="negative-infinity"),
        pytest.param(b"1e999", id="overflowing-literal"),
    ],
)
def test_non_finite_components_are_rejected(literal: bytes) -> None:
    """`json.loads` accepts the bare `NaN`/`Infinity` literals and `1e999`
    overflows to `inf`. Every one of these has the pinned dimension and the
    right count, so nothing else in the pipeline would ever raise on it -- it
    would just silently poison every ANN distance the vector participates
    in."""
    body = b'{"data": [{"index": 0, "embedding": [1.0, ' + literal + b", 3.0]}]}"

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=body, headers={"content-type": "application/json"})

    embedder = _client(handler)
    with pytest.raises(EmbeddingProviderError):
        embedder.embed(["poisoned"], timeout_ms=200)


def test_dimension_mismatch_against_the_pin_raises() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        # PIN.dim is 3; this driver only returns a 2-length vector.
        return httpx.Response(200, json={"data": [{"index": 0, "embedding": [0.1, 0.2]}]})

    embedder = _client(handler)
    with pytest.raises(EmbeddingDimensionMismatch) as exc_info:
        embedder.embed(["short"], timeout_ms=200)
    assert exc_info.value.actual_dim == 2
    assert exc_info.value.configured is PIN


def test_http_status_error_raises_embedding_provider_error() -> None:
    """The error response carries a perfectly well-formed embeddings payload:
    a driver that skipped the status check would parse it and return vectors,
    so only the status check can make this test pass."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            500, json={"data": [{"index": 0, "embedding": [0.1, 0.2, 0.3]}]}
        )

    embedder = _client(handler)
    with pytest.raises(EmbeddingProviderError) as exc_info:
        embedder.embed(["x"], timeout_ms=200)
    assert "500" in str(exc_info.value)


def test_transport_failure_raises_embedding_provider_error_not_a_raw_httpx_error() -> None:
    """A refused connection is "the endpoint is broken", not "we ran out of
    time" -- the retriever's degradation ladder keys on that distinction."""

    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    embedder = _client(handler)
    with pytest.raises(EmbeddingProviderError):
        embedder.embed(["x"], timeout_ms=200)


@pytest.mark.parametrize(
    "payload",
    [
        pytest.param({"not_data": []}, id="missing-data-key"),
        pytest.param({"data": {"index": 0}}, id="data-is-not-a-list"),
        pytest.param({"data": [{"index": 0}]}, id="item-missing-embedding"),
        pytest.param({"data": [{"embedding": [1.0, 2.0, 3.0]}]}, id="item-missing-index"),
        pytest.param(
            {"data": [{"index": "0", "embedding": [1.0, 2.0, 3.0]}]}, id="index-not-an-int"
        ),
        pytest.param(
            {"data": [{"index": 0, "embedding": ["a", "b", "c"]}]}, id="non-numeric-components"
        ),
        pytest.param({"data": [["index", 0]]}, id="item-is-not-a-mapping"),
    ],
)
def test_malformed_payloads_raise_embedding_provider_error(payload: object) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=payload)

    embedder = _client(handler)
    with pytest.raises(EmbeddingProviderError):
        embedder.embed(["x"], timeout_ms=200)


def test_body_that_is_not_json_at_all_raises_embedding_provider_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"<html>gateway says no</html>")

    embedder = _client(handler)
    with pytest.raises(EmbeddingProviderError):
        embedder.embed(["x"], timeout_ms=200)


@pytest.mark.parametrize(
    "returned",
    [pytest.param(1, id="too-few"), pytest.param(3, id="too-many")],
)
def test_vector_count_mismatch_raises_embedding_provider_error(returned: int) -> None:
    """The count is checked against the batch up front and reported as a
    count, not as a downstream side effect: the message pins the branch, so a
    driver that leaned on the permutation check to notice would go red."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "data": [
                    {"index": i, "embedding": [0.1, 0.2, 0.3]} for i in range(returned)
                ]
            },
        )

    embedder = _client(handler)
    with pytest.raises(EmbeddingProviderError) as exc_info:
        embedder.embed(["one", "two"], timeout_ms=200)
    assert f"returned {returned} vectors for 2 inputs" in str(exc_info.value)
