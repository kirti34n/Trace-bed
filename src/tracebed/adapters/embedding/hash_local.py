"""Deterministic, dependency-free local embeddings for offline evaluation.

This is deliberately a fallback driver, not the production default.  It
normalizes text with NFKC plus ``casefold()``, hashes unigram and adjacent
bigram features with SHA-256, and L2-normalizes the resulting fixed-width
vector.  It makes no network calls and stores no text, which is useful for
tests and constrained local environments; hash collisions mean it is not a
semantic-model substitute.
"""

from __future__ import annotations

import hashlib
import math
import re
import unicodedata
from collections.abc import Sequence
from itertools import pairwise
from typing import Final

from tracebed.adapters.embedding.pinning import ModelPin, validate_batch
from tracebed.domain.clock import Clock, SystemClock
from tracebed.domain.config import HASH_LOCAL_MODEL_ID, HASH_LOCAL_MODEL_VERSION
from tracebed.domain.errors import ConfigError, EmbeddingTimeout

__all__ = ["HashLocalEmbeddingClient"]


_TOKEN_PATTERN: Final = re.compile(r"\w+", flags=re.UNICODE)
_BIGRAM_SEPARATOR: Final = "\x1f"
_EMPTY_FEATURE: Final = "<tracebed:empty>"
_ZERO_FEATURE: Final = "<tracebed:zero>"


class HashLocalEmbeddingClient:
    """A deterministic hash-projection implementation of ``EmbeddingPort``.

    Every feature contributes either ``+1`` or ``-1`` to one SHA-256-selected
    bucket.  The bucket uses the first eight digest bytes and the sign uses a
    disjoint digest byte, avoiding Python's randomized ``hash()`` and keeping
    results stable across processes and platforms.
    """

    def __init__(self, *, pin: ModelPin, clock: Clock | None = None) -> None:
        if (
            pin.model_id != HASH_LOCAL_MODEL_ID
            or pin.model_version != HASH_LOCAL_MODEL_VERSION
        ):
            raise ConfigError(
                "hash-local embedding identity must be "
                f"{HASH_LOCAL_MODEL_ID!r}/{HASH_LOCAL_MODEL_VERSION!r}, got "
                f"{pin.model_id!r}/{pin.model_version!r}"
            )
        if pin.dim <= 0:
            raise ValueError(f"hash-local embedding dimension must be positive, got {pin.dim!r}")
        self._pin = pin
        self._clock: Clock = clock if clock is not None else SystemClock()

    @property
    def model_id(self) -> str:
        return self._pin.model_id

    @property
    def model_version(self) -> str:
        return self._pin.model_version

    def embed(self, texts: Sequence[str], *, timeout_ms: int) -> list[list[float]]:
        """Return one L2-normalized vector per input within the supplied budget.

        The clock is checked before and after normalizing/tokenizing every
        input and while projecting its features.  A local CPU calculation
        cannot be interrupted midway through a regular-expression operation,
        but it never starts another material unit of work after its deadline.
        """
        if not texts:
            return []
        if timeout_ms <= 0:
            raise EmbeddingTimeout(
                f"hash-local embedding called with a {timeout_ms}ms budget; refusing to start"
            )

        deadline_ms = self._clock.monotonic_ms() + timeout_ms
        vectors: list[list[float]] = []
        for text in texts:
            self._require_within_budget(deadline_ms, timeout_ms)
            features = _features(text)
            self._require_within_budget(deadline_ms, timeout_ms)
            vectors.append(self._project(features, deadline_ms=deadline_ms, timeout_ms=timeout_ms))

        self._require_within_budget(deadline_ms, timeout_ms)
        validate_batch(vectors, expected=len(texts), configured=self._pin)
        return vectors

    def _project(
        self, features: Sequence[str], *, deadline_ms: float, timeout_ms: int
    ) -> list[float]:
        vector = [0.0] * self._pin.dim
        for feature in features:
            self._require_within_budget(deadline_ms, timeout_ms)
            bucket, sign = _bucket_and_sign(feature, self._pin.dim)
            vector[bucket] += sign

        norm = math.sqrt(sum(component * component for component in vector))
        if norm == 0.0:
            # Feature collisions with opposing signs can cancel a non-empty
            # input.  Empty input must always be nonzero too, so use a separate
            # sentinel whose single contribution cannot cancel.
            bucket, sign = _bucket_and_sign(_ZERO_FEATURE, self._pin.dim)
            vector[bucket] = sign
            norm = 1.0
        return [component / norm for component in vector]

    def _require_within_budget(self, deadline_ms: float, timeout_ms: int) -> None:
        if self._clock.monotonic_ms() > deadline_ms:
            raise EmbeddingTimeout(f"hash-local embedding exceeded its {timeout_ms}ms budget")


def _features(text: str) -> list[str]:
    """Return normalized unigram and ordered-adjacent-bigram features."""
    normalized = unicodedata.normalize("NFKC", text).casefold()
    tokens = _TOKEN_PATTERN.findall(normalized)
    if not tokens:
        return [_EMPTY_FEATURE]
    return tokens + [f"{left}{_BIGRAM_SEPARATOR}{right}" for left, right in pairwise(tokens)]


def _bucket_and_sign(feature: str, dim: int) -> tuple[int, float]:
    digest = hashlib.sha256(feature.encode("utf-8")).digest()
    bucket = int.from_bytes(digest[:8], byteorder="big", signed=False) % dim
    sign = 1.0 if digest[8] & 1 else -1.0
    return bucket, sign
