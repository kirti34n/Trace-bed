"""Canonical JSON serialisation and hashing — the one function everyone imports.

PHASE0-CONTRACT.md §2 (C-01): every content_hash, canonical_args, and
input_signature_hash computation in Tracebed goes through THIS module so the
same logical value always hashes to the same bytes no matter which chunk
computed it. Nobody else re-implements JSON canonicalisation — a second
implementation is how `content_hash` drifts from what `ScanVerdict` signed
(invariant 6 / D-024) or how two chunks compute different Valkey cache keys
for identical tool args (invariant 4 / the wall covers every key).
"""

from __future__ import annotations

import hashlib
import json
import unicodedata
from collections.abc import Mapping

__all__ = ["canonical_args", "canonical_json", "content_hash", "sha256_hex"]


def canonical_json(obj: object) -> bytes:
    """Deterministic JSON bytes: sorted keys, no whitespace, UTF-8, no NaN/Infinity.

    PHASE0-CONTRACT.md §2/C-01: `sort_keys=True`, separators `(",", ":")`,
    `ensure_ascii=False`, `allow_nan=False`. Two logically-equal dicts built in
    different key order (e.g. two chunks constructing the same tool-args
    mapping independently) must serialise to byte-identical output — that is
    the whole point of a *canonical* serialiser feeding a hash.

    Raises ValueError, loudly, on anything json can't represent (NaN,
    Infinity, sets, datetimes, custom objects, ...) rather than silently
    coercing it — a coerced value hashing differently than intended would be
    a silent content_hash / ScanVerdict mismatch.

    `RecursionError` is caught and re-raised as `ValueError` too: `obj` is
    attacker-reachable (a `TraceEvent.payload` / `canonical_args` mapping
    arrives straight off the wire), and a deeply-nested payload would
    otherwise escape as a `RecursionError` — an exception type no caller on
    the ingest path expects or catches, which turns a malformed body into a
    consumer crash rather than a rejected row.
    """
    try:
        text = json.dumps(
            obj,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
    except RecursionError as exc:
        raise ValueError("canonical_json: input nested too deeply to canonicalise") from exc
    except (TypeError, ValueError) as exc:
        raise ValueError(f"canonical_json: not JSON-canonicalisable: {exc}") from exc
    return text.encode("utf-8")


def sha256_hex(data: bytes) -> str:
    """sha256 hex digest of raw bytes. The one hashing primitive other hashes build on."""
    return hashlib.sha256(data).hexdigest()


def content_hash(text: str) -> str:
    """sha256 hex digest of NFC-normalised text.

    PHASE0-CONTRACT.md §2/C-01. THE hash stored in `memory_item.content_hash`
    and bound into `ScanVerdict.content_hash` (§3.7) — `Repo.insert_memory_item`
    recomputes this and compares it against the verdict before insert, so this
    function must be byte-identical across every chunk that calls it.
    NFC normalisation first means two Unicode-equivalent-but-differently-coded
    strings (e.g. combining-character vs precomposed accents) hash the same,
    instead of a cosmetic encoding difference silently invalidating a verdict.
    """
    normalized = unicodedata.normalize("NFC", text)
    return sha256_hex(normalized.encode("utf-8"))


def canonical_args(args: Mapping[str, object]) -> bytes:
    """= canonical_json(args); the tool-cache key input (PLAN.md §5 key spec, C-17).

    Kept as a separate named entry point (rather than callers using
    canonical_json directly) because it is a documented hashing *site* —
    `stores/valkey/keys.py`'s tool_cache_key hashes exactly this output, and
    naming the seam makes it greppable.
    """
    return canonical_json(args)
