"""Trace-payload envelope format — the wire bytes `crypto/shred.py` reads and writes.

PHASE0-CONTRACT.md §6.1/C-12/C-13 (PHASE-0 Task 10): UTF-8 JSONL, one header
line then one line per section. AES-256-GCM per section with a fresh nonce
every time (never reused — `tests/phase0/test_crypto_shred.py` fuzzes many
sections for exactly this) and AAD binding (project_id, run_id, seq_from,
seq_to) so a section cannot be relocated between runs or projects without
decryption failing loudly.

Kept separate from `shred.py` purely so the higher-level key-lifecycle logic
in that file stays readable; every name a consumer needs is re-exported from
`tracebed.crypto` and `tracebed.crypto.shred` (PHASE0-CONTRACT.md §1 assigns
the public surface to `shred.py` — this file's existence is noted as a
contract_gap in this chunk's build report).

Key wrapping (multi-subject erasure, C-13): a section's DEK is split into one
XOR share per referenced subject tag (untagged sections use a single share
under the reserved `"__project__"` tag). Reconstructing the DEK needs EVERY
share, so destroying any one referenced subject's KEK makes the section
undecryptable — "wrapped under every KEK" (PHASE-0 Task 10's original
wording) would leave a multi-subject section readable after only one
erasure, which fails the erasure semantics the state machine promises.
"""

from __future__ import annotations

import base64
import binascii
import json
import os
from collections.abc import Mapping, Sequence
from typing import Any, Final
from uuid import UUID

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from tracebed.crypto.subject_digest import subject_digest
from tracebed.domain.ids import ProjectId, RunId

__all__ = [
    "ENVELOPE_ALG",
    "ENVELOPE_FMT",
    "ENVELOPE_VERSION",
    "KEY_LEN",
    "MAX_SUBJECT_DIGESTS",
    "NONCE_LEN",
    "V2_ENVELOPE_FMT",
    "V2_ENVELOPE_VERSION",
    "V2_SPLIT",
    "V2_WRAP_ALG",
    "aesgcm_decrypt",
    "aesgcm_encrypt",
    "b64d",
    "b64d_canonical",
    "b64e",
    "build_aad",
    "build_v2_kek_aad",
    "build_v2_section_aad",
    "build_v2_share_aad",
    "combine_shares",
    "dumps_line",
    "dumps_v2_line",
    "loads_lines",
    "loads_v2_lines",
    "random_bytes",
    "serialize_v2_envelope",
    "split_dek",
    "validate_v2_envelope",
]

ENVELOPE_VERSION: Final = 1
ENVELOPE_FMT: Final = "tb-env/1"
ENVELOPE_ALG: Final = "AES-256-GCM"
V2_ENVELOPE_VERSION: Final = 2
V2_ENVELOPE_FMT: Final = "tb-env/2"
V2_SPLIT: Final = "XOR-ALL/v1"
V2_WRAP_ALG: Final = "AES-256-GCM"
KEY_LEN: Final = 32  # AES-256 key length — shared by every DEK/KEK/master key
NONCE_LEN: Final = 12  # AES-GCM's standard nonce length
MAX_SUBJECT_DIGESTS: Final = 64
_MAX_SEQ: Final = 1 << 40
_V2_SECTION_AAD_DOMAIN: Final = b"tracebed.section-aad/v2\0"
_V2_SHARE_AAD_DOMAIN: Final = b"tracebed.share-aad/v2\0"
_V2_KEK_AAD_DOMAIN: Final = b"tracebed.kek-aad/v2\0"


def random_bytes(n: int) -> bytes:
    """`os.urandom`, named so every fresh-key/fresh-nonce site in this package
    is greppable — nonce uniqueness (never-reused, per §6.1) is exactly the
    property `test_crypto_shred.py` fuzzes for across many sections."""
    return os.urandom(n)


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"))


def b64d_canonical(data: object) -> bytes:
    """Decode exactly standard, padded canonical Base64 without reflecting it.

    The envelope is untrusted archive data.  Checking the re-encoding closes
    alternate padding, whitespace, URL-safe alphabet, and non-canonical-bit
    spellings before they can become different byte representations of one
    authenticated field.
    """

    if not isinstance(data, str):
        raise ValueError("envelope base64 field is invalid")
    try:
        encoded = data.encode("ascii")
        decoded = base64.b64decode(encoded, validate=True)
    except (UnicodeEncodeError, binascii.Error, ValueError):
        raise ValueError("envelope base64 field is invalid") from None
    if b64e(decoded) != data:
        raise ValueError("envelope base64 field is not canonical")
    return decoded


def build_aad(project_id: ProjectId, run_id: RunId, seq_from: int, seq_to: int) -> bytes:
    """AAD = project_id 0x1F run_id 0x1F seq_from 0x1F seq_to (C-12): binds a
    section's ciphertext to exactly the run and sequence range it was
    encrypted for. Re-presenting the same ciphertext/nonce under a changed
    field fails AES-GCM's tag check — the AAD-tamper case the contract's
    test list names explicitly ("change run_id fails decryption")."""
    return "\x1f".join([str(project_id), str(run_id), str(seq_from), str(seq_to)]).encode("utf-8")


def build_v2_section_aad(
    project_id: ProjectId,
    run_id: RunId,
    section_index: int,
    seq_from: int,
    seq_to: int,
    subject_digests: Sequence[bytes],
) -> bytes:
    """Build the byte-exact ``tb-env/2`` section binding.

    The list is binary-sorted and complete before it reaches this primitive;
    validating it here makes the encryption and strict-reader paths share one
    unambiguous frame.
    """

    _validate_v2_uint(section_index, "section index", bits=32)
    _validate_v2_sequence(seq_from)
    _validate_v2_sequence(seq_to)
    if seq_from > seq_to:
        raise ValueError("section sequence range is invalid")
    digests = _validate_subject_digest_bytes(subject_digests)
    return (
        _V2_SECTION_AAD_DOMAIN
        + project_id.value.bytes
        + run_id.value.bytes
        + section_index.to_bytes(4, byteorder="big", signed=False)
        + seq_from.to_bytes(8, byteorder="big", signed=False)
        + seq_to.to_bytes(8, byteorder="big", signed=False)
        + len(digests).to_bytes(2, byteorder="big", signed=False)
        + b"".join(digests)
    )


def build_v2_share_aad(
    section_aad: bytes, wrap_index: int, wrap_digest: bytes, key_id: UUID
) -> bytes:
    """Bind each wrapped DEK share to one exact v2 section and key row."""

    _validate_v2_uint(wrap_index, "wrap index", bits=16)
    if not isinstance(section_aad, bytes):
        raise TypeError("section AAD must be bytes")
    digest = _validate_subject_digest_bytes((wrap_digest,))[0]
    if not isinstance(key_id, UUID):
        raise TypeError("key id must be a UUID")
    from hashlib import sha256

    return (
        _V2_SHARE_AAD_DOMAIN
        + sha256(section_aad).digest()
        + wrap_index.to_bytes(2, byteorder="big", signed=False)
        + digest
        + key_id.bytes
    )


def build_v2_kek_aad(project_id: ProjectId, digest: bytes, key_id: UUID) -> bytes:
    """Bind an encrypted subject KEK to its opaque project-scoped identity."""

    checked_digest = _validate_subject_digest_bytes((digest,))[0]
    if not isinstance(key_id, UUID):
        raise TypeError("key id must be a UUID")
    return _V2_KEK_AAD_DOMAIN + project_id.value.bytes + checked_digest + key_id.bytes


def aesgcm_encrypt(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
    return AESGCM(key).encrypt(nonce, plaintext, aad)


def aesgcm_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
    """Raises `cryptography.exceptions.InvalidTag` on any tamper of
    ciphertext, nonce, or AAD — the one and only signal a caller needs to
    know a section's binding has been violated."""
    return AESGCM(key).decrypt(nonce, ciphertext, aad)


def split_dek(dek: bytes, n: int) -> list[bytes]:
    """N XOR shares of `dek`; XOR-reducing all N reconstructs it exactly
    (C-13). `n=1` returns `[dek]` unchanged — still one required share, so
    an untagged (project-only) section is shredded by destroying the
    project KEK exactly like a tagged one is shredded by its subject KEK."""
    if n < 1:
        raise ValueError("split_dek: n must be >= 1")
    if n == 1:
        return [dek]
    shares = [random_bytes(len(dek)) for _ in range(n - 1)]
    last = bytearray(dek)
    for share in shares:
        for i, b in enumerate(share):
            last[i] ^= b
    shares.append(bytes(last))
    return shares


def combine_shares(shares: Sequence[bytes]) -> bytes:
    """XOR-reduce every share back into the DEK. Missing even one share makes
    this impossible by construction — callers must hold ALL shares first,
    which is exactly what a destroyed subject KEK prevents."""
    if not shares:
        raise ValueError("combine_shares: at least one share required")
    out = bytearray(shares[0])
    for share in shares[1:]:
        if len(share) != len(out):
            raise ValueError("combine_shares: share length mismatch")
        for i, b in enumerate(share):
            out[i] ^= b
    return bytes(out)


def dumps_line(obj: Mapping[str, Any]) -> bytes:
    """One JSON object per line, compact separators. Deliberately NOT
    `domain.canonical.canonical_json`: this is a storage format, never
    hashed or signed, and preserves the caller's field order (header keys
    first, section's `wraps` last) for human legibility on disk."""
    return (json.dumps(obj, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")


def dumps_v2_line(obj: Mapping[str, Any]) -> bytes:
    """Render one ``tb-env/2`` line in its sole canonical wire spelling."""

    try:
        rendered = json.dumps(
            obj,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
    except (TypeError, ValueError):
        raise ValueError("v2 envelope line is not JSON encodable") from None
    return rendered.encode("ascii") + b"\n"


def loads_lines(raw: bytes) -> list[dict[str, Any]]:
    """Inverse of repeated `dumps_line` calls; blank trailing lines ignored."""
    text = raw.decode("utf-8")
    return [json.loads(line) for line in text.split("\n") if line]


def _no_duplicate_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("v2 envelope contains duplicate JSON keys")
        result[key] = value
    return result


def loads_v2_lines(raw: bytes) -> list[dict[str, Any]]:
    """Parse only canonical v2 JSONL; never repair a legacy-looking input."""

    if not raw or raw.startswith(b"\xef\xbb\xbf") or not raw.endswith(b"\n") or b"\r" in raw:
        raise ValueError("v2 envelope framing is invalid")
    lines = raw[:-1].split(b"\n")
    if not lines or any(not line for line in lines):
        raise ValueError("v2 envelope framing is invalid")

    parsed: list[dict[str, Any]] = []
    for line in lines:
        try:
            decoded = line.decode("utf-8", "strict")
            item = json.loads(decoded, object_pairs_hook=_no_duplicate_json_object)
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
            raise ValueError("v2 envelope JSON is invalid") from None
        if not isinstance(item, dict) or dumps_v2_line(item) != line + b"\n":
            raise ValueError("v2 envelope JSON is not canonical")
        parsed.append(item)
    return parsed


def _validate_v2_uint(value: object, label: str, *, bits: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value < (1 << bits):
        raise ValueError(f"v2 envelope {label} is invalid")
    return value


def _validate_v2_sequence(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value < _MAX_SEQ:
        raise ValueError("v2 envelope sequence is invalid")
    return value


def _canonical_uuid(value: object) -> UUID:
    if not isinstance(value, str):
        raise ValueError("v2 envelope UUID is invalid")
    try:
        parsed = UUID(value)
    except ValueError:
        raise ValueError("v2 envelope UUID is invalid") from None
    if str(parsed) != value:
        raise ValueError("v2 envelope UUID is not canonical")
    return parsed


def _validate_subject_digest_bytes(digests: Sequence[bytes]) -> tuple[bytes, ...]:
    if len(digests) > MAX_SUBJECT_DIGESTS:
        raise ValueError("v2 envelope has too many subject digests")
    result = tuple(digests)
    if any(not isinstance(digest, bytes) or len(digest) != KEY_LEN for digest in result):
        raise ValueError("v2 envelope subject digest is invalid")
    if tuple(sorted(result)) != result or len(set(result)) != len(result):
        raise ValueError("v2 envelope subject digests are not sorted and unique")
    return result


def _v2_digests(value: object) -> tuple[bytes, ...]:
    if not isinstance(value, list):
        raise ValueError("v2 envelope subject digests are invalid")
    return _validate_subject_digest_bytes(tuple(b64d_canonical(item) for item in value))


def validate_v2_envelope(header: Mapping[str, Any], sections: Sequence[Mapping[str, Any]]) -> None:
    """Validate all v2 structural, canonical-value, and ordering invariants.

    This is shared by the serializer and parser.  It intentionally reports
    only field classes, never raw subject values, object data, or attacker
    text from archive bytes.
    """

    expected_header = {
        "alg",
        "first_seq",
        "fmt",
        "last_seq",
        "project_id",
        "run_id",
        "section_count",
        "split",
        "v",
        "wrap_alg",
    }
    if set(header) != expected_header:
        raise ValueError("v2 envelope header keys are invalid")
    if (
        header.get("alg") != ENVELOPE_ALG
        or header.get("fmt") != V2_ENVELOPE_FMT
        or header.get("split") != V2_SPLIT
        or header.get("v") != V2_ENVELOPE_VERSION
        or header.get("wrap_alg") != V2_WRAP_ALG
    ):
        raise ValueError("v2 envelope header values are invalid")
    project = ProjectId(_canonical_uuid(header.get("project_id")))
    _canonical_uuid(header.get("run_id"))
    section_count = _validate_v2_uint(header.get("section_count"), "section count", bits=32)
    if not 1 <= section_count <= 10_000 or section_count != len(sections):
        raise ValueError("v2 envelope section count is invalid")
    first_seq = _validate_v2_sequence(header.get("first_seq"))
    last_seq = _validate_v2_sequence(header.get("last_seq"))
    if first_seq > last_seq:
        raise ValueError("v2 envelope sequence range is invalid")

    expected_section = {
        "ct",
        "nonce",
        "section_index",
        "seq_from",
        "seq_to",
        "subject_digests",
        "wraps",
    }
    expected_wrap = {"digest", "key_id", "nonce", "share"}
    observed_first: int | None = None
    observed_last: int | None = None
    previous_seq_to: int | None = None
    sentinel = subject_digest(project, "__project__")
    for index, section in enumerate(sections):
        if set(section) != expected_section:
            raise ValueError("v2 envelope section keys are invalid")
        if _validate_v2_uint(section.get("section_index"), "section index", bits=32) != index:
            raise ValueError("v2 envelope section order is invalid")
        seq_from = _validate_v2_sequence(section.get("seq_from"))
        seq_to = _validate_v2_sequence(section.get("seq_to"))
        if seq_from > seq_to:
            raise ValueError("v2 envelope section sequence range is invalid")
        if previous_seq_to is not None and seq_from <= previous_seq_to:
            raise ValueError("v2 envelope sections are not strictly ordered")
        digests = _v2_digests(section.get("subject_digests"))
        if sentinel in digests:
            raise ValueError("v2 envelope subject digest is reserved")
        nonce = b64d_canonical(section.get("nonce"))
        ciphertext = b64d_canonical(section.get("ct"))
        if len(nonce) != NONCE_LEN or len(ciphertext) <= 16:
            raise ValueError("v2 envelope ciphertext is invalid")
        wraps = section.get("wraps")
        if not isinstance(wraps, list):
            raise ValueError("v2 envelope wraps are invalid")
        expected_digests = digests or (sentinel,)
        if len(wraps) != len(expected_digests):
            raise ValueError("v2 envelope wrap count is invalid")
        for wrap_index, (wrap, expected_digest) in enumerate(
            zip(wraps, expected_digests, strict=True)
        ):
            if not isinstance(wrap, dict) or set(wrap) != expected_wrap:
                raise ValueError("v2 envelope wrap keys are invalid")
            if b64d_canonical(wrap.get("digest")) != expected_digest:
                raise ValueError("v2 envelope wrap order is invalid")
            _canonical_uuid(wrap.get("key_id"))
            wrap_nonce = b64d_canonical(wrap.get("nonce"))
            share = b64d_canonical(wrap.get("share"))
            if len(wrap_nonce) != NONCE_LEN or len(share) != KEY_LEN + 16:
                raise ValueError("v2 envelope wrapped share is invalid")
            if wrap_index > 0 and expected_digests[wrap_index - 1] >= expected_digest:
                raise ValueError("v2 envelope wrap order is invalid")
        observed_first = seq_from if observed_first is None else min(observed_first, seq_from)
        observed_last = seq_to if observed_last is None else max(observed_last, seq_to)
        previous_seq_to = seq_to
    if observed_first != first_seq or observed_last != last_seq:
        raise ValueError("v2 envelope header sequence range is invalid")


def serialize_v2_envelope(
    header: Mapping[str, Any], sections: Sequence[Mapping[str, Any]]
) -> bytes:
    """Return strict canonical v2 JSONL after validating its full wire shape."""

    materialized_sections = tuple(sections)
    validate_v2_envelope(header, materialized_sections)
    return dumps_v2_line(header) + b"".join(
        dumps_v2_line(section) for section in materialized_sections
    )
