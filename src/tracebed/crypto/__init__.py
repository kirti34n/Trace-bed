"""Crypto-shredding package (PHASE0-CONTRACT.md §6, PHASE-0 Task 10).

Re-exports the chunk's public surface from `shred.py` — PHASE0-CONTRACT.md
§1 names `crypto/shred.py` as the file that owns `SubjectKeyManager`,
`EncryptedPayload`, and the envelope format; the low-level AES-GCM/XOR-share
primitives live in the sibling `envelope.py` module purely so `shred.py`
stays readable. Every name a consumer needs is importable from
`tracebed.crypto` (this file) or `tracebed.crypto.shred`, matching the
contract's file table exactly — see this chunk's `contract_gaps` for why
`envelope.py` exists as a physically separate file.
"""

from __future__ import annotations

from tracebed.crypto.shred import (
    PROJECT_SUBJECT_TAG,
    EncryptedPayload,
    EnvMasterKeyProvider,
    MasterKeyProvider,
    PlainSection,
    SubjectKeyManager,
    SubjectKeyStore,
    TombstonedSection,
)

__all__ = [
    "PROJECT_SUBJECT_TAG",
    "EncryptedPayload",
    "EnvMasterKeyProvider",
    "MasterKeyProvider",
    "PlainSection",
    "SubjectKeyManager",
    "SubjectKeyStore",
    "TombstonedSection",
]
