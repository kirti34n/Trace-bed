"""Crypto-shredding: subject-key lifecycle and trace-payload envelope encryption.

PHASE0-CONTRACT.md §6 (PHASE-0 Task 10). This is what makes GDPR-style
erasure coexist with an immutable, object-locked trace archive (PLAN.md §5,
`subject_key` table comment): a trace payload's sections are envelope-
encrypted per subject, and destroying a subject's KEK makes every section
that referenced it permanently unreadable while the stored object's bytes
never change — `stores.tracestore` never sees plaintext, and it never
rewrites an object to "apply" an erasure. The `crypto` package executes NO
SQL (§14 do-not list): `SubjectKeyStore` below is a `Protocol` that `Repo`
satisfies structurally; this module never imports `stores.pg`.

`decrypt()` treats the payload it is handed as UNTRUSTED input. It comes off
an object store whose keys are text in `trace_index.payload_ref`, so every
field is bounds-checked and type-checked before use, the header's
`project_id` is required to match the caller's resolved scope (invariant 4 —
a payload from another tenant is `NotFound`, the same uniform answer every
other by-id path gives), and the per-section wrap list is required to name
exactly the subject tags the section claims, so a rewritten `subject_tags`
field cannot make a shredded section look untagged.
"""

from __future__ import annotations

import base64
import binascii
import os
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Final, Protocol
from uuid import UUID, uuid4

from tracebed.crypto import envelope
from tracebed.domain.clock import Clock
from tracebed.domain.errors import MasterKeyMissing, NotFound, Tombstoned
from tracebed.domain.ids import ProjectId, RunId

if TYPE_CHECKING:
    # Referenced as a string annotation only (`from __future__ import
    # annotations`), same pattern `domain/errors.py` uses for `Status` from
    # `state_machine.py`: crypto must not import a store at runtime (§14
    # crypto-tracestore: "crypto executes NO SQL").
    from tracebed.stores.pg.rows import SubjectKeyRow

__all__ = [
    "MAX_SECTIONS",
    "MAX_WRAPS_PER_SECTION",
    "PROJECT_SUBJECT_TAG",
    "EncryptedPayload",
    "EnvMasterKeyProvider",
    "MasterKeyProvider",
    "PlainSection",
    "SubjectKeyManager",
    "SubjectKeyStore",
    "TombstonedSection",
]

PROJECT_SUBJECT_TAG: Final = "__project__"

# Bounds on untrusted payload structure. A trace batch is at most a few
# hundred events (C-25 splits long runs across objects) and a section can
# reference at most a handful of subjects; these caps stop a malformed or
# hostile object turning one decrypt() into unbounded work against the
# subject-key store.
MAX_SECTIONS: Final = 10_000
MAX_WRAPS_PER_SECTION: Final = 64
_MAX_SEQ: Final = 1 << 40


class MasterKeyProvider(Protocol):
    """Documents the KMS seam (PHASE-0 Task 10): a real deployment swaps
    `EnvMasterKeyProvider` for a KMS-backed implementation (AWS KMS, Vault
    transit, ...) without touching `SubjectKeyManager` — it only ever calls
    `.master_key()`."""

    def master_key(self) -> bytes: ...


class EnvMasterKeyProvider:
    """Reads a base64, 32-byte key from env `TB_MASTER_KEY` (C-15).

    Kept out of `TracebedSettings` deliberately — `pydantic-settings` objects
    get `repr()`'d in logs and error messages, and a key-material field there
    is one accidental `str(settings)` away from a leak. Fails fast at
    construction, not first use (`MasterKeyMissing`), so a misconfigured
    deployment never accepts a single trace byte with a broken crypto seam.
    """

    __slots__ = ("_env_var",)

    def __init__(self, env_var: str = "TB_MASTER_KEY") -> None:
        self._env_var = env_var
        self.master_key()  # fail fast (C-15) — validated eagerly, not lazily

    def master_key(self) -> bytes:
        raw = os.environ.get(self._env_var)
        if not raw:
            raise MasterKeyMissing(f"{self._env_var} is not set")
        try:
            key = base64.b64decode(raw, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise MasterKeyMissing(f"{self._env_var} is not valid base64") from exc
        if len(key) != envelope.KEY_LEN:
            raise MasterKeyMissing(
                f"{self._env_var} must decode to {envelope.KEY_LEN} bytes, got {len(key)}"
            )
        return key


class SubjectKeyStore(Protocol):
    """`Repo` satisfies this structurally (PHASE0-CONTRACT.md §5.1); fakes
    stand in for every offline test in this chunk (§12). `crypto` never
    imports `stores.pg` (§14 do-not list) — this Protocol is the only
    coupling between the two."""

    def get_subject_key(self, project_id: ProjectId, subject_tag: str) -> SubjectKeyRow | None: ...

    def insert_subject_key(
        self, project_id: ProjectId, subject_tag: str, key_id: UUID, wrapped_kek: bytes
    ) -> None: ...

    def destroy_subject_key(self, project_id: ProjectId, subject_tag: str) -> bool: ...


@dataclass(frozen=True, slots=True)
class PlainSection:
    """One section's plaintext, pre-encryption. `lines` are the exact JSONL
    wire-envelope lines (`{"seq": n, "event": {...}}` per line — the C-24
    section-boundary unit) `ingest.trace_writer` hands in, each WITHOUT a
    trailing newline."""

    seq_from: int
    seq_to: int
    subject_tags: tuple[str, ...]
    lines: tuple[bytes, ...]


@dataclass(frozen=True, slots=True)
class TombstonedSection:
    """Sentinel for a section whose DEK can no longer be reconstructed — NOT
    an exception, because one shredded subject must not make the rest of the
    same trace unreadable (the crypto-shred test's central assertion)."""

    seq_from: int
    seq_to: int
    subject_tags: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class EncryptedPayload:
    """The parsed form of the §6.1 JSONL wire format: one header line, then
    one section line per `PlainSection` originally encrypted."""

    header: Mapping[str, object]
    sections: tuple[Mapping[str, object], ...]

    def to_bytes(self) -> bytes:
        out = envelope.dumps_line(self.header)
        for section in self.sections:
            out += envelope.dumps_line(section)
        return out

    @classmethod
    def from_bytes(cls, raw: bytes) -> EncryptedPayload:
        """Parses §6.1 JSONL and rejects anything this build cannot read.

        The version/format check is what keeps a future `tb-env/2` object
        (different AAD, different wrapping) from being silently mis-parsed by
        an old node into a wrong-looking-but-plausible tombstone; an explicit
        `ValueError` is loud, a silent tombstone is an invisible data loss.
        """
        try:
            lines = envelope.loads_lines(raw)
        except (UnicodeDecodeError, ValueError) as exc:
            raise ValueError(f"EncryptedPayload.from_bytes: not valid JSONL: {exc}") from exc
        if not lines:
            raise ValueError("EncryptedPayload.from_bytes: empty payload")
        if not all(isinstance(line, dict) for line in lines):
            # A JSONL line that is an array or a scalar is still valid JSON;
            # without this every `.get()` below becomes an AttributeError
            # escaping as a 500 rather than a typed envelope error.
            raise ValueError("EncryptedPayload.from_bytes: every line must be a JSON object")
        header, *sections = lines
        if header.get("fmt") != envelope.ENVELOPE_FMT or header.get("v") != envelope.ENVELOPE_VERSION:
            raise ValueError(
                f"EncryptedPayload.from_bytes: unsupported envelope "
                f"{header.get('fmt')!r} v{header.get('v')!r}"
            )
        if header.get("alg") != envelope.ENVELOPE_ALG:
            raise ValueError(f"EncryptedPayload.from_bytes: unsupported alg {header.get('alg')!r}")
        if len(sections) > MAX_SECTIONS:
            raise ValueError(
                f"EncryptedPayload.from_bytes: {len(sections)} sections exceeds {MAX_SECTIONS}"
            )
        return cls(header=header, sections=tuple(sections))


def _as_int(raw: object, field: str) -> int:
    """Untrusted-payload integer coercion: bools, floats, and out-of-range
    values are rejected rather than silently truncated into a seq number that
    would then be bound into the AAD."""
    if isinstance(raw, bool) or not isinstance(raw, int):
        raise ValueError(f"envelope: {field} must be an int, got {type(raw).__name__}")
    if not 0 <= raw < _MAX_SEQ:
        raise ValueError(f"envelope: {field} out of range: {raw}")
    return raw


def _as_str(raw: object, field: str) -> str:
    if not isinstance(raw, str):
        raise ValueError(f"envelope: {field} must be a string, got {type(raw).__name__}")
    return raw


def _as_b64(raw: object, field: str) -> bytes:
    try:
        return envelope.b64d(_as_str(raw, field))
    except (binascii.Error, ValueError, UnicodeEncodeError) as exc:
        raise ValueError(f"envelope: {field} is not valid base64") from exc


def _as_wrap(raw: object) -> Mapping[str, Any]:
    """Untrusted `wraps[]` entries must be JSON objects before any field of
    theirs is read — a bare string here would otherwise raise `TypeError`
    deep inside the decrypt loop instead of a typed envelope error."""
    if not isinstance(raw, dict):
        raise ValueError("envelope: each entry of section.wraps must be an object")
    return raw


class SubjectKeyManager:
    """Owns the subject-KEK lifecycle and the envelope encrypt/decrypt path.

    Never executes SQL (§14): every persistence call goes through the
    `SubjectKeyStore` Protocol, which `Repo` satisfies at runtime and a
    plain in-memory fake satisfies in every offline test.

    Holds NO key cache. That is deliberate and load-bearing: a cached KEK
    would keep decrypting sections after `destroy_subject()`, which would
    make erasure a property of process lifetime instead of a property of the
    stored key material.
    """

    def __init__(self, store: SubjectKeyStore, master: MasterKeyProvider, clock: Clock) -> None:
        self._store = store
        self._master = master
        self._clock = clock

    # -- KEK lifecycle ------------------------------------------------------

    def ensure_project_kek(self, project_id: ProjectId) -> None:
        """Provisions the reserved `"__project__"` KEK row if absent (C-14) —
        called by `POST /admin/projects` at project creation."""
        self.get_or_create_subject_kek(project_id, PROJECT_SUBJECT_TAG)

    def get_or_create_subject_kek(self, project_id: ProjectId, subject_tag: str) -> bytes:
        kek, _key_id = self._get_or_create_kek(project_id, subject_tag)
        return kek

    def destroy_subject(self, project_id: ProjectId, subject_tag: str) -> bool:
        """Erasure = state-machine `*->tombstoned` for every memory derived
        from this subject (PLAN.md §5 table) PLUS this: the KEK itself is
        gone, so even the raw trace sections referencing it become
        permanently unreadable — crypto-shredding is what makes that
        coexist with an object-locked archive (`subject_key` table comment,
        PLAN.md §5). Returns False if the subject has no KEK row at all."""
        return self._store.destroy_subject_key(project_id, subject_tag)

    def _get_or_create_kek(self, project_id: ProjectId, subject_tag: str) -> tuple[bytes, UUID]:
        if not subject_tag:
            raise ValueError("subject_tag must be non-empty")
        row = self._store.get_subject_key(project_id, subject_tag)
        if row is not None:
            if row.destroyed_at is not None:
                # A destroyed subject's KEK is gone by design (wrapped_kek is
                # zeroed server-side, §5.1) — fetching it again to encrypt
                # NEW content would silently resurrect a shredded subject.
                raise Tombstoned(f"subject {subject_tag!r} has been shredded")
            kek = self._unwrap_kek(
                row.wrapped_kek, project_id=project_id, subject_tag=subject_tag, key_id=row.key_id
            )
            return kek, row.key_id

        kek = envelope.random_bytes(envelope.KEY_LEN)
        key_id = uuid4()
        wrapped = self._wrap_kek(kek, project_id=project_id, subject_tag=subject_tag, key_id=key_id)
        self._store.insert_subject_key(project_id, subject_tag, key_id, wrapped)
        return kek, key_id

    def _kek_wrap_aad(self, project_id: ProjectId, subject_tag: str, key_id: UUID) -> bytes:
        # Binds a wrapped KEK to (project, subject, key_id) so a KEK blob
        # tampered/swapped at the storage layer fails AES-GCM's tag check
        # instead of silently unwrapping under the wrong subject.
        return "\x1f".join([str(project_id), subject_tag]).encode("utf-8") + b"\x1f" + key_id.bytes

    def _wrap_kek(
        self, kek: bytes, *, project_id: ProjectId, subject_tag: str, key_id: UUID
    ) -> bytes:
        master = self._master.master_key()
        nonce = envelope.random_bytes(envelope.NONCE_LEN)
        aad = self._kek_wrap_aad(project_id, subject_tag, key_id)
        ct = envelope.aesgcm_encrypt(master, nonce, kek, aad)
        return nonce + ct

    def _unwrap_kek(
        self, wrapped: bytes, *, project_id: ProjectId, subject_tag: str, key_id: UUID
    ) -> bytes:
        master = self._master.master_key()
        nonce, ct = wrapped[: envelope.NONCE_LEN], wrapped[envelope.NONCE_LEN :]
        aad = self._kek_wrap_aad(project_id, subject_tag, key_id)
        return envelope.aesgcm_decrypt(master, nonce, ct, aad)

    # -- envelope encrypt/decrypt --------------------------------------------

    def encrypt(
        self, project_id: ProjectId, run_id: RunId, sections: Sequence[PlainSection]
    ) -> EncryptedPayload:
        """Encrypts each `PlainSection` under a fresh DEK (§6.1); the DEK is
        split into one XOR share per subject tag (C-13) so destroying ANY
        referenced subject cryptographically tombstones the whole section —
        not just once every referenced subject is destroyed."""
        if not sections:
            raise ValueError("SubjectKeyManager.encrypt: at least one section required")
        if len(sections) > MAX_SECTIONS:
            raise ValueError(
                f"SubjectKeyManager.encrypt: {len(sections)} sections exceeds {MAX_SECTIONS}"
            )

        encoded_sections: list[dict[str, object]] = []
        first_seq = min(s.seq_from for s in sections)
        last_seq = max(s.seq_to for s in sections)

        for section in sections:
            tags = self._section_tags(section)
            dek = envelope.random_bytes(envelope.KEY_LEN)
            nonce = envelope.random_bytes(envelope.NONCE_LEN)
            aad = envelope.build_aad(project_id, run_id, section.seq_from, section.seq_to)
            plaintext = b"".join(line + b"\n" for line in section.lines)
            ct = envelope.aesgcm_encrypt(dek, nonce, plaintext, aad)

            shares = envelope.split_dek(dek, len(tags))
            wraps: list[dict[str, object]] = []
            for tag, share in zip(tags, shares, strict=True):
                kek, key_id = self._get_or_create_kek(project_id, tag)
                wrap_nonce = envelope.random_bytes(envelope.NONCE_LEN)
                share_ct = envelope.aesgcm_encrypt(kek, wrap_nonce, share, key_id.bytes)
                wraps.append(
                    {
                        "tag": tag,
                        "key_id": str(key_id),
                        "nonce": envelope.b64e(wrap_nonce),
                        "share": envelope.b64e(share_ct),
                    }
                )

            encoded_sections.append(
                {
                    "seq_from": section.seq_from,
                    "seq_to": section.seq_to,
                    "subject_tags": list(section.subject_tags),
                    "nonce": envelope.b64e(nonce),
                    "ct": envelope.b64e(ct),
                    "wraps": wraps,
                }
            )

        header = {
            "v": envelope.ENVELOPE_VERSION,
            "fmt": envelope.ENVELOPE_FMT,
            "alg": envelope.ENVELOPE_ALG,
            "project_id": str(project_id),
            "run_id": str(run_id),
            "first_seq": first_seq,
            "last_seq": last_seq,
        }
        return EncryptedPayload(header=header, sections=tuple(encoded_sections))

    @staticmethod
    def _section_tags(section: PlainSection) -> tuple[str, ...]:
        """The tags a section's DEK is actually split across: its own, or the
        reserved project tag when it has none (C-13/C-14).

        Duplicates are rejected rather than deduplicated: two shares under one
        KEK is not a security failure, but it means the section's declared
        `subject_tags` no longer matches its wrap list, and `decrypt()`
        enforces that they match to stop a rewritten `subject_tags` field
        disguising which subjects a section belongs to.
        """
        if not 0 <= section.seq_from <= section.seq_to < _MAX_SEQ:
            raise ValueError(
                f"PlainSection: bad seq range [{section.seq_from}, {section.seq_to}]"
            )
        for line in section.lines:
            if b"\n" in line:
                # Sections are JSONL; an embedded newline would come back as
                # extra lines on decrypt and silently change the event count.
                raise ValueError("PlainSection.lines must not contain newlines")
        tags = section.subject_tags or (PROJECT_SUBJECT_TAG,)
        if len(set(tags)) != len(tags):
            raise ValueError(f"PlainSection: duplicate subject_tags {tags!r}")
        if any(not tag for tag in tags):
            raise ValueError("PlainSection: subject_tags must not contain empty strings")
        if len(tags) > MAX_WRAPS_PER_SECTION:
            raise ValueError(
                f"PlainSection: {len(tags)} subject tags exceeds {MAX_WRAPS_PER_SECTION}"
            )
        return tags

    def decrypt(
        self, project_id: ProjectId, payload: EncryptedPayload
    ) -> list[PlainSection | TombstonedSection]:
        """Returns a `TombstonedSection` sentinel — never an exception — for
        any section whose referenced subject KEK is missing or destroyed, and
        keeps decrypting the rest of the payload (crypto-shred test's core
        assertion: one shredded subject must not blind the whole trace).

        Raises `NotFound` when the payload belongs to another project
        (invariant 4: the uniform by-id answer, never a partial read), and
        `ValueError` when the envelope is structurally malformed — a
        distinction that matters because "tombstoned" is a durable claim
        about erasure and must never be produced by a parse failure.
        """
        header = payload.header
        header_project = _as_str(header.get("project_id"), "header.project_id")
        if header_project != str(project_id):
            # The trace store's key check (stores/tracestore/base.py) is the
            # first wall; this is the second, and it is the one that holds
            # when the bytes arrived by some other route entirely.
            raise NotFound("trace payload not found")
        run_id = RunId(_as_str(header.get("run_id"), "header.run_id"))

        if len(payload.sections) > MAX_SECTIONS:
            raise ValueError(f"envelope: {len(payload.sections)} sections exceeds {MAX_SECTIONS}")

        results: list[PlainSection | TombstonedSection] = []
        for raw_section in payload.sections:
            results.append(self._decrypt_section(project_id, run_id, raw_section))
        return results

    def _decrypt_section(
        self, project_id: ProjectId, run_id: RunId, raw_section: Mapping[str, object]
    ) -> PlainSection | TombstonedSection:
        seq_from = _as_int(raw_section.get("seq_from"), "section.seq_from")
        seq_to = _as_int(raw_section.get("seq_to"), "section.seq_to")
        if seq_from > seq_to:
            raise ValueError(f"envelope: section seq_from {seq_from} > seq_to {seq_to}")

        raw_tags = raw_section.get("subject_tags")
        if not isinstance(raw_tags, list):
            raise ValueError("envelope: section.subject_tags must be a list")
        tags = tuple(_as_str(t, "section.subject_tags[]") for t in raw_tags)

        raw_wraps = raw_section.get("wraps")
        if not isinstance(raw_wraps, list) or not raw_wraps:
            raise ValueError("envelope: section.wraps must be a non-empty list")
        if len(raw_wraps) > MAX_WRAPS_PER_SECTION:
            raise ValueError(f"envelope: {len(raw_wraps)} wraps exceeds {MAX_WRAPS_PER_SECTION}")

        wrap_tags = tuple(_as_str(_as_wrap(w).get("tag"), "wrap.tag") for w in raw_wraps)
        expected = tags or (PROJECT_SUBJECT_TAG,)
        if wrap_tags != expected:
            # `subject_tags` is what trace_subject rows and the erasure UI are
            # built from; if it disagrees with the wrap list, a rewritten
            # payload could present a shredded section as belonging to nobody.
            raise ValueError(
                f"envelope: section.subject_tags {expected!r} does not match wraps {wrap_tags!r}"
            )

        shares: list[bytes] = []
        for raw_wrap in raw_wraps:
            wrap = _as_wrap(raw_wrap)
            tag = _as_str(wrap.get("tag"), "wrap.tag")
            try:
                key_id = UUID(_as_str(wrap.get("key_id"), "wrap.key_id"))
            except ValueError as exc:
                raise ValueError("envelope: wrap.key_id is not a UUID") from exc
            row = self._store.get_subject_key(project_id, tag)
            if row is None or row.destroyed_at is not None or row.key_id != key_id:
                # Absent, destroyed, or rotated to a different key_id — the
                # share is unrecoverable, so the whole section is (C-13).
                return TombstonedSection(seq_from=seq_from, seq_to=seq_to, subject_tags=tags)
            kek = self._unwrap_kek(
                row.wrapped_kek, project_id=project_id, subject_tag=tag, key_id=row.key_id
            )
            wrap_nonce = _as_b64(wrap.get("nonce"), "wrap.nonce")
            share_ct = _as_b64(wrap.get("share"), "wrap.share")
            shares.append(envelope.aesgcm_decrypt(kek, wrap_nonce, share_ct, key_id.bytes))

        dek = envelope.combine_shares(shares)
        if len(dek) != envelope.KEY_LEN:
            raise ValueError(f"envelope: reconstructed DEK is {len(dek)} bytes")
        nonce = _as_b64(raw_section.get("nonce"), "section.nonce")
        ct = _as_b64(raw_section.get("ct"), "section.ct")
        aad = envelope.build_aad(project_id, run_id, seq_from, seq_to)
        plaintext = envelope.aesgcm_decrypt(dek, nonce, ct, aad)
        lines = tuple(line for line in plaintext.split(b"\n") if line)
        return PlainSection(seq_from=seq_from, seq_to=seq_to, subject_tags=tags, lines=lines)
