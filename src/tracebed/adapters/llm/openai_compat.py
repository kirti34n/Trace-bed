"""OpenAI-compatible chat-completion client (PLAN.md §3 ports table; D-008).

The default `LLMProviderPort` implementation for the workers that gate Q and promotion -- the
contribution judge, the shadow validator, and the distiller (PLAN.md §7 Phase 3). An
OpenAI-compatible `/chat/completions` call over `httpx`, spoken against `llm.base_url`
(`domain.config.LLMProviderConfig`) -- Google direct / LiteLLM / any other OpenAI-compatible
gateway is one config line, this driver does not change (PLAN.md §3: "Google-direct / LiteLLM /
any gateway is one config line").

Structured like `adapters.embedding.gemini.GeminiEmbeddingClient` on purpose, for the same
reasons: this chunk's own test list requires "a malformed/hostile LLM response (prose instead of
JSON, JSON with injected instructions, enormous output) is rejected safely and bounded", and a
background worker calling an untrusted-shaped endpoint has exactly the same two hazards a hot-path
embedding call does -- an unbounded response body, and a slow-drip response that stays inside
every individual `httpx` read timeout while consuming unbounded total time. Both are handled the
same way here: the streamed body is buffered under a byte ceiling derived from the request's own
`max_tokens`, and a wall-clock deadline (anchored to one `clock.monotonic_ms()` reading, never a
bare wall-clock call, per hard rule 3) is re-checked after every chunk.

"JSON with injected instructions" is deliberately NOT this driver's problem to solve: an
injection payload sitting inside a syntactically valid `content` string is not malformed at the
transport layer at all, and this driver has no memory-item context to scan it against. That
defence lives where the parsed content is about to become storable content
(`workers.distiller`'s `core.scans.scan` call, per D-024) -- this driver's job stops at "did the
provider return a well-formed chat-completion payload".

No retry loop, matching `GeminiEmbeddingClient`: the caller owns whatever budget or backoff
policy it has for the call, and an internal retry here would silently spend it while masking a
provider fault as a slow success.
"""

from __future__ import annotations

import json
import math
from typing import Any, Final

import httpx

from tracebed.adapters.llm.pinning import LLMProviderError, LLMProviderTimeout
from tracebed.domain.clock import Clock, SystemClock

__all__ = ["OpenAiCompatibleLLMProvider"]

# Same reasoning as `adapters.embedding.gemini._RESPONSE_ENVELOPE_SLACK_BYTES`/
# `_JSON_BYTES_PER_FLOAT`: bounds an untrusted response body BEFORE it is fully buffered, derived
# from the request's own `max_tokens` rather than one global constant so the bound tightens
# automatically for small calls. English text averages ~4 characters per token; 8 is deliberately
# generous (CJK text, heavy JSON-escaping of quotes/newlines inside the completion) because this
# is a PARSE-SAFETY ceiling protecting this driver's own buffering, not a token-accounting
# estimate -- `core.scans`'s own per-mem_type ceiling (a few KB, `schema_check.max_content_chars`)
# is what actually bounds what a worker may eventually store.
_CHARS_PER_TOKEN_CEILING: Final = 8
# UTF-8 worst case is 4 bytes per character; folded in so a high-multibyte-ratio response cannot
# slip past a bound sized for plain ASCII.
_BYTES_PER_CHAR_CEILING: Final = 4
_RESPONSE_ENVELOPE_SLACK_BYTES: Final = 64 * 1024


class OpenAiCompatibleLLMProvider:
    """OpenAI-compatible `/chat/completions` client. Satisfies `LLMProviderPort` structurally.

    `http`/`clock` are injected for the same reasons `GeminiEmbeddingClient` injects them: tests
    install an `httpx.MockTransport` at the transport boundary instead of mocking this class, and
    the deadline enforcement below has to be testable with zero wall-clock time passing.

    `timeout_s` is a constructor-level deployment setting rather than a per-call argument
    (CONTRACT GAP: `LLMProviderConfig` has no field for it) because `LLMProviderPort.complete`'s
    signature is fixed by the contract (`model`, `prompt`, `temperature`, `max_tokens` only) --
    there is no parameter on the Protocol method this driver could receive a per-call budget
    through, unlike `EmbeddingPort.embed`'s explicit `timeout_ms`.
    """

    def __init__(
        self,
        *,
        base_url: str,
        api_key: str,
        http: httpx.Client | None = None,
        clock: Clock | None = None,
        timeout_s: float = 60.0,
    ) -> None:
        if timeout_s <= 0:
            raise ValueError(f"timeout_s must be positive, got {timeout_s}")
        self._base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._http = http if http is not None else httpx.Client()
        self._clock: Clock = clock if clock is not None else SystemClock()
        self._timeout_s = timeout_s

    def complete(self, *, model: str, prompt: str, temperature: float, max_tokens: int) -> str:
        """Satisfies `adapters.ports.LLMProviderPort.complete`.

        Raises `LLMProviderTimeout` past this driver's configured deadline, `LLMProviderError`
        for any other transport or payload failure. Never retries internally (module docstring).
        """
        if not model:
            raise ValueError("complete() requires a non-empty model id")
        if max_tokens <= 0:
            raise ValueError(f"max_tokens must be positive, got {max_tokens}")
        if not math.isfinite(temperature) or temperature < 0.0:
            # `json.dumps` emits bare `NaN`/`Infinity` for non-finite floats, which is invalid
            # JSON: the request body would be rejected (or, worse, silently reinterpreted) by
            # the gateway rather than by this driver, turning a caller bug into an opaque
            # provider error. A negative temperature is equally not a sampling parameter.
            raise ValueError(f"temperature must be finite and non-negative, got {temperature}")

        timeout_ms = self._timeout_s * 1000.0
        deadline_ms = self._clock.monotonic_ms() + timeout_ms
        # Per-operation bound only -- see the module docstring; the deadline check inside
        # `_read_within_deadline` is what actually bounds the whole call.
        timeout = httpx.Timeout(self._timeout_s)

        try:
            with self._http.stream(
                "POST",
                f"{self._base_url}/chat/completions",
                headers={"Authorization": f"Bearer {self._api_key}"},
                json={
                    "model": model,
                    "messages": [{"role": "user", "content": prompt}],
                    "temperature": temperature,
                    "max_tokens": max_tokens,
                },
                timeout=timeout,
            ) as response:
                if response.is_error:
                    # Deliberately does not read the body: an error response's payload is
                    # unbounded, unused, and would be charged to a call budget that only exists
                    # to produce a completion.
                    raise LLMProviderError(f"LLM endpoint returned HTTP {response.status_code}")
                body = self._read_within_deadline(
                    response, deadline_ms=deadline_ms, max_tokens=max_tokens
                )
        except httpx.TimeoutException as exc:
            raise LLMProviderTimeout(
                f"LLM request exceeded its {self._timeout_s}s budget"
            ) from exc
        except httpx.HTTPError as exc:
            # Connect refused, TLS failure, protocol error: the endpoint is broken rather than
            # slow, and a caller must be able to tell those apart without inspecting exception
            # text.
            raise LLMProviderError("LLM endpoint transport failure") from exc

        return self._parse_content(body)

    def _max_response_bytes(self, *, max_tokens: int) -> int:
        """The largest body a well-formed answer to a `max_tokens`-bounded request could
        plausibly be. Protects this driver's own buffering against a misbehaving or hostile
        endpoint; it is not a token-accounting estimate (see the module-level constants)."""
        return _RESPONSE_ENVELOPE_SLACK_BYTES + (
            max_tokens * _CHARS_PER_TOKEN_CEILING * _BYTES_PER_CHAR_CEILING
        )

    def _read_within_deadline(
        self, response: httpx.Response, *, deadline_ms: float, max_tokens: int
    ) -> bytes:
        """Buffers the streamed body under both the wall-clock deadline and the size cap.

        The deadline re-check after every chunk is what makes a slow-drip body (headers fast,
        then one byte per read) a bounded `LLMProviderTimeout` instead of an unbounded hang --
        every individual `httpx` read stays inside its own per-operation timeout, so nothing
        else in the stack would catch a drip attack.
        """
        max_bytes = self._max_response_bytes(max_tokens=max_tokens)
        body = bytearray()
        for chunk in response.iter_bytes():
            body.extend(chunk)
            if len(body) > max_bytes:
                raise LLMProviderError(
                    f"LLM response exceeded {max_bytes} bytes for a {max_tokens}-token request "
                    "-- refusing to buffer more"
                )
            if self._clock.monotonic_ms() > deadline_ms:
                raise LLMProviderTimeout(
                    f"LLM response body exceeded the {self._timeout_s}s budget while streaming"
                )
        return bytes(body)

    def _parse_content(self, body: bytes) -> str:
        """Parses the OpenAI-compatible `{"choices": [{"message": {"content": ...}}]}` shape.

        Every failure mode this chunk's test list names -- prose instead of JSON, a JSON object
        missing the expected keys, a `choices` list that is empty or not a list, a non-string
        `content` -- raises `LLMProviderError` rather than propagating a raw `json.JSONDecodeError`
        or `KeyError`/`IndexError`/`TypeError`, so a caller can catch one name for "the provider's
        answer was unusable" regardless of which part of the shape was wrong.
        """
        try:
            payload: Any = json.loads(body)
            choices = payload["choices"]
        except RecursionError as exc:
            # `json.loads` recurses once per nesting level, so a body of `b"[" * 9000` -- far
            # inside the byte ceiling `_read_within_deadline` enforces -- raises
            # `RecursionError` out of the scanner. It is a `RuntimeError`, not a `ValueError`,
            # so the clause below never saw it and this driver's documented promise ("one name
            # for 'the provider's answer was unusable'") was false for the cheapest hostile
            # body there is. `domain.canonical.canonical_json` converts the same hazard on the
            # serialise side.
            raise LLMProviderError("chat-completion response nests too deeply to parse") from exc
        except (KeyError, TypeError, ValueError) as exc:
            raise LLMProviderError("malformed chat-completion response payload") from exc

        if not isinstance(choices, list) or not choices:
            raise LLMProviderError("chat-completion response carries no choices")

        try:
            content = choices[0]["message"]["content"]
        except (KeyError, TypeError, IndexError) as exc:
            raise LLMProviderError("malformed chat-completion response payload") from exc

        if not isinstance(content, str):
            raise LLMProviderError("chat-completion response content is not a string")
        return content
