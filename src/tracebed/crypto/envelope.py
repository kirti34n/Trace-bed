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
import json
import os
from collections.abc import Mapping, Sequence
from typing import Any, Final

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from tracebed.domain.ids import ProjectId, RunId

__all__ = [
    "ENVELOPE_ALG",
    "ENVELOPE_FMT",
    "ENVELOPE_VERSION",
    "KEY_LEN",
    "NONCE_LEN",
    "aesgcm_decrypt",
    "aesgcm_encrypt",
    "b64d",
    "b64e",
    "build_aad",
    "combine_shares",
    "dumps_line",
    "loads_lines",
    "random_bytes",
    "split_dek",
]

ENVELOPE_VERSION: Final = 1
ENVELOPE_FMT: Final = "tb-env/1"
ENVELOPE_ALG: Final = "AES-256-GCM"
KEY_LEN: Final = 32  # AES-256 key length — shared by every DEK/KEK/master key
NONCE_LEN: Final = 12  # AES-GCM's standard nonce length


def random_bytes(n: int) -> bytes:
    """`os.urandom`, named so every fresh-key/fresh-nonce site in this package
    is greppable — nonce uniqueness (never-reused, per §6.1) is exactly the
    property `test_crypto_shred.py` fuzzes for across many sections."""
    return os.urandom(n)


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"))


def build_aad(project_id: ProjectId, run_id: RunId, seq_from: int, seq_to: int) -> bytes:
    """AAD = project_id 0x1F run_id 0x1F seq_from 0x1F seq_to (C-12): binds a
    section's ciphertext to exactly the run and sequence range it was
    encrypted for. Re-presenting the same ciphertext/nonce under a changed
    field fails AES-GCM's tag check — the AAD-tamper case the contract's
    test list names explicitly ("change run_id fails decryption")."""
    return "\x1f".join([str(project_id), str(run_id), str(seq_from), str(seq_to)]).encode("utf-8")


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


def loads_lines(raw: bytes) -> list[dict[str, Any]]:
    """Inverse of repeated `dumps_line` calls; blank trailing lines ignored."""
    text = raw.decode("utf-8")
    return [json.loads(line) for line in text.split("\n") if line]
