"""PHASE0-CONTRACT.md §2/C-01 — `domain.canonical`, THE one serialisation.

§13.2 assigns this file to chunk `domain-events-scan` and scopes it to
"canonical_json stability; content_hash NFC". Everything downstream that has
to agree byte-for-byte across chunks — `memory_item.content_hash`, the value
bound into a `ScanVerdict`, `input_signature_hash`'s structured half, the
Valkey tool-cache key — is this module's output, so a drift here is a silent
cross-chunk mismatch rather than a visible failure.
"""

from __future__ import annotations

import math
import unicodedata

import pytest

from tracebed.domain.canonical import canonical_args, canonical_json, content_hash, sha256_hex

pytestmark = pytest.mark.phase0


# --------------------------------------------------------------------------- #
# canonical_json — C-01's four settings, each pinned by a test that fails if
# that specific setting is flipped.
# --------------------------------------------------------------------------- #


def test_canonical_json_stable_across_dict_key_ordering() -> None:
    # Fails if sort_keys is dropped.
    a = {"z": 1, "a": 2, "m": {"y": 1, "b": 2}}
    b = {"a": 2, "m": {"b": 2, "y": 1}, "z": 1}
    assert canonical_json(a) == canonical_json(b)


def test_canonical_json_is_compact_no_whitespace() -> None:
    # Fails if separators drift back to json's defaults (", ", ": ").
    out = canonical_json({"a": 1, "b": [1, 2, 3]})
    assert out == b'{"a":1,"b":[1,2,3]}'


def test_canonical_json_sorts_nested_keys_too() -> None:
    # sort_keys is documented as recursive; assert it rather than assume it,
    # since a hand-rolled top-level-only sort would pass the test above.
    assert canonical_json({"outer": {"b": 1, "a": 2}}) == b'{"outer":{"a":2,"b":1}}'


def test_canonical_json_rejects_nan() -> None:
    # Fails if allow_nan reverts to True: json would emit bare `NaN`, which is
    # not JSON, and two NaNs would hash equal despite never comparing equal.
    with pytest.raises(ValueError, match="canonicalisable"):
        canonical_json({"x": math.nan})


def test_canonical_json_rejects_infinity() -> None:
    with pytest.raises(ValueError, match="canonicalisable"):
        canonical_json({"x": math.inf})


def test_canonical_json_rejects_negative_infinity() -> None:
    with pytest.raises(ValueError, match="canonicalisable"):
        canonical_json({"x": -math.inf})


def test_canonical_json_rejects_non_json_types() -> None:
    with pytest.raises(ValueError, match="canonicalisable"):
        canonical_json({"x", "not", "json", "serialisable", "as", "a", "set"})


def test_canonical_json_rejects_circular_reference() -> None:
    circular: dict[str, object] = {}
    circular["self"] = circular
    with pytest.raises(ValueError, match="canonicalisable"):
        canonical_json(circular)


def test_canonical_json_rejects_deeply_nested_input_as_valueerror() -> None:
    # The payload dict on a TraceEvent is attacker-controlled. Before the fix
    # this escaped as RecursionError — an exception type no ingest caller
    # catches, i.e. a consumer crash instead of a rejected event. Every
    # non-canonicalisable input must leave here as ValueError.
    nested: object = "leaf"
    for _ in range(20_000):  # comfortably past sys.getrecursionlimit()
        nested = [nested]
    with pytest.raises(ValueError):
        canonical_json(nested)


def test_canonical_json_preserves_non_ascii_utf8() -> None:
    # Fails if ensure_ascii reverts to True (é escapes instead of UTF-8).
    out = canonical_json({"name": "café"})
    assert "café".encode() in out
    assert b"\\u00e9" not in out


def test_canonical_json_returns_utf8_bytes_not_str() -> None:
    assert isinstance(canonical_json({"a": 1}), bytes)


# --------------------------------------------------------------------------- #
# sha256_hex / content_hash
# --------------------------------------------------------------------------- #


def test_sha256_hex_matches_a_known_vector() -> None:
    # A literal vector, not a self-comparison: a self-comparison would still
    # pass if sha256 were swapped for any other deterministic digest.
    assert sha256_hex(b"abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


def test_sha256_hex_is_sensitive_to_every_byte() -> None:
    assert sha256_hex(b"abc") != sha256_hex(b"abd")


# Built from ASCII source, never from two literal accented characters: the
# NFC and NFD forms are visually identical in an editor, so a literal pair
# would silently degrade into "assert x == x" the first time an editor or a
# tool re-normalised this file.
_DECOMPOSED = "cafe" + chr(0x0301)  # e + COMBINING ACUTE ACCENT (NFD)
_PRECOMPOSED = unicodedata.normalize("NFC", _DECOMPOSED)  # single codepoint (NFC)


def test_content_hash_nfc_normalises() -> None:
    assert _PRECOMPOSED != _DECOMPOSED, "fixture must actually differ in bytes"
    assert content_hash(_PRECOMPOSED) == content_hash(_DECOMPOSED)


def test_content_hash_is_the_nfc_sha256_hex_vector() -> None:
    # Pins the exact algorithm (NFC -> UTF-8 -> sha256 hex), not merely that
    # it is stable: a mutation to NFD, or to hashing before normalising,
    # moves this value and would otherwise go unnoticed until a cross-chunk
    # content_hash mismatch at insert time.
    assert content_hash(_DECOMPOSED) == sha256_hex(_PRECOMPOSED.encode())


def test_content_hash_is_sha256_hex_length_and_lowercase() -> None:
    digest = content_hash("hello")
    assert len(digest) == 64
    assert digest == digest.lower()
    int(digest, 16)  # raises if not valid hex


def test_content_hash_distinguishes_different_content() -> None:
    assert content_hash("always retry with backoff") != content_hash("never retry with backoff")


def test_content_hash_does_not_strip_or_collapse_whitespace() -> None:
    # content_hash is NOT a fuzzy match: near-identical content must produce
    # different verdicts, or a scanned string could vouch for a variant of
    # itself at insert time.
    assert content_hash("drop table") != content_hash("drop  table")
    assert content_hash("drop table") != content_hash(" drop table")


# --------------------------------------------------------------------------- #
# canonical_args
# --------------------------------------------------------------------------- #


def test_canonical_args_matches_canonical_json() -> None:
    args = {"tool": "stripe.charge", "amount": 500}
    assert canonical_args(args) == canonical_json(args)


def test_canonical_args_is_order_insensitive() -> None:
    # The Valkey tool-cache key hashes this output: two callers building the
    # same args in different order must hit the same cache entry.
    assert canonical_args({"a": 1, "b": 2}) == canonical_args({"b": 2, "a": 1})
