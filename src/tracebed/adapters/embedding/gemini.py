"""Gemini embedding driver (PLAN.md §3 ports table, §6 `embedding.*`; D-007).

The default `EmbeddingPort` implementation: an OpenAI-compatible `/embeddings`
call over `httpx`, spoken against `llm.base_url` (PLAN.md §3's ports table —
the same OpenAI-compatible endpoint the judge/distiller workers use; Google
direct / LiteLLM / any gateway is one config line there, and this driver
inherits that flexibility for free). Model default `gemini-embedding-2`,
dimension 768 (`halfvec(768)`, D-007) — both carried on the injected
`ModelPin`, never hardcoded here, so a deployment's configured pin and this
driver's wire request always agree.

THE BUDGET IS THE CONTRACT (PLAN.md §2 invariant 1, §6 `retrieval.embed_timeout_ms`):
`embed()` enforces a *total* deadline for the whole call, not merely a
per-socket-operation timeout. `httpx.Timeout` alone is not enough and getting
this wrong is the difference between a `degraded_lexical` outcome and a run
that blocks: httpx's timeouts are per operation (connect / write / one read /
pool acquisition), so an endpoint that answers headers instantly and then
drips one byte per read stays inside every individual read timeout while
consuming unbounded total time. The 200ms embed sub-budget inside the 300ms
p99 total (PLAN.md §2 invariant 2) would be silently blown. So the body is
streamed and the deadline — anchored to a single `clock.monotonic_ms()`
reading, never a bare wall-clock call — is re-checked after every chunk, and
the per-operation `httpx.Timeout` derived from `timeout_ms` bounds how long
any one blocked read can overshoot it. (A sync client cannot pre-empt a read
already in flight without a watchdog thread this driver deliberately does not
spin up; the residual overshoot is one read operation, versus unbounded
without the deadline check.)

There is no retry loop: the caller (the retriever) owns the sub-budget, and an
internal retry would silently spend the whole budget, turning what should be a
`degraded_lexical` outcome into a `timeout_prefix_only` one instead.
`httpx.TimeoutException` and an exhausted total deadline are the only cases
mapped to `EmbeddingTimeout`; every other transport or payload failure is
`EmbeddingProviderError`, so a caller can tell "ran out of time" from "the
endpoint or its response was broken" without inspecting exception text.

The response is treated as untrusted input throughout: the buffered body is
capped at a size derived from what a well-formed answer can possibly be
(§`_max_response_bytes`), the per-item `index` fields must form an exact
permutation of the request batch (a duplicate index would silently attribute
one input's vector to another), and every float must be finite (`json.loads`
accepts the `NaN`/`Infinity` literals, and a single NaN poisons every ANN
distance the vector ever participates in).
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from typing import Any, Final

import httpx

from tracebed.adapters.embedding.pinning import (
    EmbeddingProviderError,
    ModelPin,
    validate_batch,
)
from tracebed.domain.clock import Clock, SystemClock
from tracebed.domain.errors import EmbeddingTimeout

__all__ = ["GeminiEmbeddingClient"]

# Wire-format facts used to bound how much of an untrusted response body this
# driver is willing to buffer. These are NOT tunable policy thresholds (hard
# rule 4 / PLAN.md §6 has no knob for them, and a deployment has no business
# raising them): a JSON float64 never needs more than 32 characters including
# its separator, and the fixed slack covers the envelope fields an
# OpenAI-compatible response carries around the vectors themselves (`object`,
# `model`, `usage`, each item's `index`).
_JSON_BYTES_PER_FLOAT: Final = 32
_RESPONSE_ENVELOPE_SLACK_BYTES: Final = 64 * 1024


class GeminiEmbeddingClient:
    """OpenAI-compatible `/embeddings` client. Satisfies `EmbeddingPort` structurally.

    `http` is an injected `httpx.Client` so tests can install a
    `httpx.MockTransport` at the transport boundary (per the task's testing
    rule: fake the transport, never mock this class) instead of needing a
    live endpoint or patching this class's methods. `clock` is injected for
    the same reason: the total-deadline enforcement below is the single most
    important behaviour of this driver and it must be testable without any
    real time passing.
    """

    def __init__(
        self,
        *,
        base_url: str,
        api_key: str,
        pin: ModelPin,
        http: httpx.Client | None = None,
        clock: Clock | None = None,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._pin = pin
        self._http = http if http is not None else httpx.Client()
        self._clock: Clock = clock if clock is not None else SystemClock()

    @property
    def model_id(self) -> str:
        return self._pin.model_id

    @property
    def model_version(self) -> str:
        return self._pin.model_version

    def embed(self, texts: Sequence[str], *, timeout_ms: int) -> list[list[float]]:
        """Raises `EmbeddingTimeout` past `timeout_ms`. Never retries internally.

        Empty `texts` returns `[]` without a network call — an empty batch is
        never a reason to spend budget or hold a connection open.
        """
        if not texts:
            return []

        # The budget is checked BEFORE the work, never after: a caller whose
        # sub-budget is already spent must not open a socket at all, because
        # connecting is itself unbounded work charged to a budget of zero.
        if timeout_ms <= 0:
            raise EmbeddingTimeout(
                f"embedding called with a {timeout_ms}ms budget; refusing to start a request"
            )

        deadline_ms = self._clock.monotonic_ms() + timeout_ms
        expected = len(texts)
        # Per-operation bound. It does not bound the call (see module
        # docstring); the deadline below does. It is still derived from the
        # caller's argument on every call — never a constructor-level default
        # — so no single socket operation can outlive the budget either.
        timeout = httpx.Timeout(timeout_ms / 1000.0)

        try:
            with self._http.stream(
                "POST",
                f"{self._base_url}/embeddings",
                headers={"Authorization": f"Bearer {self._api_key}"},
                json={"model": self._pin.model_id, "input": list(texts)},
                timeout=timeout,
            ) as response:
                if response.is_error:
                    # Deliberately does not read the body: an error response's
                    # payload is unbounded, unused, and would be charged to a
                    # budget that only exists to produce vectors.
                    raise EmbeddingProviderError(
                        f"embedding endpoint returned HTTP {response.status_code}"
                    )
                body = self._read_within_deadline(
                    response, deadline_ms=deadline_ms, expected=expected, timeout_ms=timeout_ms
                )
        except httpx.TimeoutException as exc:
            raise EmbeddingTimeout(
                f"embedding request exceeded its {timeout_ms}ms budget"
            ) from exc
        except httpx.HTTPError as exc:
            # Connect refused, TLS failure, protocol error: the endpoint is
            # broken rather than slow, and the caller must be able to tell
            # those apart without inspecting exception text.
            raise EmbeddingProviderError("embedding endpoint transport failure") from exc

        vectors = self._parse_vectors(body, expected=expected)
        validate_batch(vectors, expected=expected, configured=self._pin)
        return vectors

    def _max_response_bytes(self, *, expected: int) -> int:
        """The largest body a well-formed answer to THIS request could be.

        Derived from the request rather than fixed, so the bound tightens
        automatically for small batches: an endpoint (or anything that can
        answer as one) must not be able to make this process buffer an
        arbitrary amount of memory inside a 200ms hot-path budget.
        """
        return _RESPONSE_ENVELOPE_SLACK_BYTES + expected * (self._pin.dim + 1) * _JSON_BYTES_PER_FLOAT

    def _read_within_deadline(
        self,
        response: httpx.Response,
        *,
        deadline_ms: float,
        expected: int,
        timeout_ms: int,
    ) -> bytes:
        """Buffers the streamed body under both the total deadline and a size cap.

        The deadline re-check after every chunk is what makes a slow-drip body
        (headers fast, then one byte per read) a `degraded_lexical` outcome
        instead of a blown 300ms total budget — every individual read stays
        inside `httpx.Timeout`, so nothing else in the stack would catch it.
        """
        max_bytes = self._max_response_bytes(expected=expected)
        body = bytearray()
        for chunk in response.iter_bytes():
            body.extend(chunk)
            if len(body) > max_bytes:
                raise EmbeddingProviderError(
                    f"embedding response exceeded {max_bytes} bytes for {expected} input(s) "
                    "-- refusing to buffer more"
                )
            if self._clock.monotonic_ms() > deadline_ms:
                raise EmbeddingTimeout(
                    f"embedding response body exceeded the {timeout_ms}ms budget while streaming"
                )
        return bytes(body)

    def _parse_vectors(self, body: bytes, *, expected: int) -> list[list[float]]:
        """Parses the OpenAI-compatible payload and restores input order.

        The wire shape is `{"data": [{"index": int, "embedding": [float, ...]},
        ...]}`; the spec promises `data` arrives in request order, but this
        driver never trusts that promise — it places each vector by its own
        `index` field and requires those indices to be an exact permutation of
        `range(expected)`. Sorting alone is not enough: a response whose
        indices are all `0` sorts "fine", has the right length, and silently
        attributes one input's vector to another. An order-scrambling response
        is silent and catastrophic (every downstream vector attributed to the
        wrong memory row), so this is the one place that gets to be paranoid
        about a contract the wire format only *implies*.
        """
        try:
            payload: Any = json.loads(body)
            data = payload["data"]
        except RecursionError as exc:
            # `json.loads` recurses once per nesting level, so a body of `b"[" * 9000` is
            # ~9000 interpreter frames and the scanner raises `RecursionError` -- a
            # `RuntimeError`, not a `ValueError`, so the clause below never saw it. The
            # driver's contract is that ONE exception name means "the provider's answer was
            # unusable"; without this clause the cheapest malformed body there is escaped
            # that vocabulary and unwound whatever batch was embedding. Same rule, same
            # reason, as `workers.distiller._parse_response` and
            # `adapters.llm.openai_compat._parse_content` -- this was the third
            # untrusted-JSON edge and the one they did not reach.
            raise EmbeddingProviderError("embeddings response nested too deeply") from exc
        except (KeyError, TypeError, ValueError) as exc:
            raise EmbeddingProviderError("malformed embeddings response payload") from exc

        if not isinstance(data, list):
            raise EmbeddingProviderError("malformed embeddings response payload")
        if len(data) != expected:
            raise EmbeddingProviderError(
                f"embedding endpoint returned {len(data)} vectors for {expected} inputs"
            )

        by_index: dict[int, list[float]] = {}
        try:
            for item in data:
                index = item["index"]
                if not isinstance(index, int) or isinstance(index, bool):
                    raise EmbeddingProviderError(
                        "embeddings response carries a non-integer `index`"
                    )
                if not 0 <= index < expected:
                    raise EmbeddingProviderError(
                        f"embeddings response index {index} is outside the {expected}-input batch"
                    )
                by_index[index] = [float(x) for x in item["embedding"]]
        except (KeyError, TypeError, ValueError) as exc:
            raise EmbeddingProviderError("malformed embeddings response payload") from exc

        if len(by_index) != expected:
            raise EmbeddingProviderError(
                "embeddings response indices are not a permutation of the input batch"
            )
        # Keys are exactly `range(expected)`: every index was range-checked and
        # there are `expected` distinct ones, so this cannot raise KeyError.
        return [by_index[position] for position in range(expected)]
