"""Strict, privacy-safe reader for completed encrypted trace archives.

The reader is deliberately separate from the writer: P2A can validate the
durable archive and hand Tier A immutable typed events without also granting
Tier A any write or scheduling capability.  It hashes ciphertext framing
only; plaintext, refs, subject tags, and provider exception text never enter
an error or receipt.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import struct
from base64 import b64decode
from binascii import Error as BinasciiError
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Final, NoReturn, Protocol, runtime_checkable
from uuid import UUID

import httpx
import psycopg
from cryptography.exceptions import InvalidTag
from psycopg_pool import PoolClosed, PoolTimeout
from pydantic import TypeAdapter, ValidationError

from tracebed.crypto import envelope
from tracebed.crypto.shred import (
    MAX_WRAPS_PER_SECTION,
    PROJECT_SUBJECT_TAG,
    EncryptedPayload,
    KeyBindingMismatch,
    KeyMaterialUnavailable,
    PlainSection,
    SubjectKeyManager,
    TombstonedSection,
)
from tracebed.crypto.subject_digest import subject_digest, subject_digest_pairs
from tracebed.domain.errors import MasterKeyMissing, NotFound, TracebedError
from tracebed.domain.events import MAX_SUBJECT_TAG_CHARS, TraceEvent
from tracebed.domain.ids import ProjectId, RunId
from tracebed.ingest.trace_writer import (
    MAX_TRACE_SEQ,
    PATH_END_SEQ,
    PATH_END_STATUS,
    PATH_PAYLOAD_REFS,
    PATH_SEQ_RANGES,
    TERMINAL_TRACE_OUTCOMES,
    parse_end_status,
    parse_seq,
    subject_tags_for,
)
from tracebed.stores.pg.rows import TraceIndexRow
from tracebed.stores.tracestore import PayloadRef, TraceStorePort
from tracebed.stores.tracestore.base import is_safe_key

__all__ = [
    "ARCHIVE_AUTH_FAILED",
    "ARCHIVE_DIGEST_MISMATCH",
    "ARCHIVE_INVALID",
    "PRIVACY_TOMBSTONED",
    "TRACE_UNAVAILABLE",
    "ArchivedTrace",
    "SubjectKeyBinding",
    "TraceArchiveDisposition",
    "TraceArchiveReadError",
    "TraceArchiveReader",
    "TraceIndexReadPort",
]

TRACE_UNAVAILABLE: Final = "trace_unavailable"
ARCHIVE_INVALID: Final = "archive_invalid"
ARCHIVE_AUTH_FAILED: Final = "archive_auth_failed"
ARCHIVE_DIGEST_MISMATCH: Final = "archive_digest_mismatch"
PRIVACY_TOMBSTONED: Final = "privacy_tombstoned"
_DIGEST_DOMAIN: Final = b"tracebed.archive-ciphertext/v1\0"
_EVENT_ADAPTER: Final[TypeAdapter[TraceEvent]] = TypeAdapter(TraceEvent)
# Only connection/pool availability failures are retryable here.  Do not
# catch psycopg.Error wholesale: query/programming errors are bugs or durable
# inconsistencies and must remain visible to the caller/test harness.
_RETRYABLE_PG_ERRORS: Final = (
    psycopg.OperationalError,
    psycopg.InterfaceError,
    PoolClosed,
    PoolTimeout,
)


class TraceArchiveDisposition(StrEnum):
    RETRY = "retry"
    DEAD = "dead"
    PRIVACY_SKIP = "privacy_skip"


class TraceArchiveReadError(TracebedError):
    """Sanitized reader result: its message is the fixed code only."""

    def __init__(
        self,
        disposition: TraceArchiveDisposition,
        code: str,
        *,
        observed_digest: bytes | None = None,
    ) -> None:
        super().__init__(code)
        self.disposition = disposition
        self.code = code
        self.observed_digest = observed_digest


@runtime_checkable
class TraceIndexReadPort(Protocol):
    """The read-only repository subset required by the archive reader."""

    def get_trace_index(self, project_id: ProjectId, run_id: RunId) -> TraceIndexRow: ...


@dataclass(frozen=True, slots=True)
class SubjectKeyBinding:
    """One exact archived subject-tag/key identity used by a trace section.

    The reader derives this from every already shape-validated ciphertext wrap
    before it decrypts.  Finalization can then lock the same sorted bindings
    in its fenced transaction, closing the read/finalize erasure race without
    carrying tags in a receipt or error.
    """

    subject_tag: str | None
    key_id: UUID
    subject_digest: bytes | None = None


@dataclass(frozen=True, slots=True)
class ArchivedTrace:
    index: TraceIndexRow
    events: tuple[TraceEvent, ...]
    trace_digest: bytes
    subject_key_bindings: tuple[SubjectKeyBinding, ...]


@dataclass(frozen=True, slots=True)
class _ArchiveObject:
    ref: PayloadRef
    ref_text: str
    raw: bytes
    payload: EncryptedPayload
    first_seq: int
    last_seq: int
    version: int


class TraceArchiveReader:
    """Reads only a complete terminal archive and validates every binding."""

    def __init__(
        self,
        indexes: TraceIndexReadPort,
        store: TraceStorePort,
        keys: SubjectKeyManager,
    ) -> None:
        self._indexes = indexes
        self._store = store
        self._keys = keys

    def read_complete(
        self,
        project_id: ProjectId,
        run_id: RunId,
        *,
        expected_digest: bytes | None = None,
        expected_ended_at: datetime | None = None,
    ) -> ArchivedTrace:
        """Return one fully verified archive or a safe typed disposition."""
        try:
            if expected_digest is not None and (
                not isinstance(expected_digest, bytes) or len(expected_digest) != 32
            ):
                self._dead_invalid()
            return self._read_complete(
                project_id,
                run_id,
                expected_digest=expected_digest,
                expected_ended_at=expected_ended_at,
            )
        except TraceArchiveReadError:
            raise
        except (MasterKeyMissing, KeyMaterialUnavailable, OSError, ImportError):
            raise TraceArchiveReadError(TraceArchiveDisposition.RETRY, TRACE_UNAVAILABLE) from None
        except KeyBindingMismatch:
            raise TraceArchiveReadError(TraceArchiveDisposition.DEAD, ARCHIVE_INVALID) from None
        except NotFound:
            # An index lookup miss (or a key-store/header binding that somehow
            # escaped the explicit checks) is a deterministic inconsistency.
            # `_read_objects` translates a *validated object* miss locally,
            # before it gets here, to the retryable store disposition.
            raise TraceArchiveReadError(TraceArchiveDisposition.DEAD, ARCHIVE_INVALID) from None
        except InvalidTag:
            raise TraceArchiveReadError(TraceArchiveDisposition.DEAD, ARCHIVE_AUTH_FAILED) from None
        except (UnicodeError, ValidationError, ValueError, TypeError, KeyError, RecursionError, struct.error):
            raise TraceArchiveReadError(TraceArchiveDisposition.DEAD, ARCHIVE_INVALID) from None

    def _read_complete(
        self,
        project_id: ProjectId,
        run_id: RunId,
        *,
        expected_digest: bytes | None,
        expected_ended_at: datetime | None,
    ) -> ArchivedTrace:
        try:
            index = self._indexes.get_trace_index(project_id, run_id)
        except NotFound:
            self._dead_invalid()
        except _RETRYABLE_PG_ERRORS:
            self._retry_unavailable()
        if index.project_id != project_id or index.run_id != run_id:
            self._dead_invalid()
        if index.outcome_status not in TERMINAL_TRACE_OUTCOMES or index.ended_at is None:
            self._dead_invalid()
        if expected_ended_at is not None and index.ended_at != expected_ended_at:
            self._dead_invalid()

        end_seq, end_status, refs = self._strict_index_path(index)
        objects = self._read_objects(project_id, run_id, refs, end_seq=end_seq)
        subject_key_bindings = self._subject_key_bindings(project_id, objects)
        observed_versions = tuple(sorted({obj.version for obj in objects}))
        if (
            index.envelope_versions is not None
            and index.envelope_versions != observed_versions
        ):
            self._dead_invalid()
        digest = self._ciphertext_digest(project_id, run_id, objects)
        if expected_digest is not None and not hmac.compare_digest(expected_digest, digest):
            raise TraceArchiveReadError(
                TraceArchiveDisposition.DEAD,
                ARCHIVE_DIGEST_MISMATCH,
                observed_digest=digest,
            )

        decoded: dict[int, TraceEvent] = {}
        run_ends: list[tuple[int, TraceEvent]] = []
        tombstoned = False
        for obj in objects:
            try:
                # SubjectKeyManager reaches the scoped repository for every
                # wrap.  A real pool/connection availability failure is
                # retryable, whereas its deterministic key-binding errors are
                # deliberately handled by the outer typed-error mapping.
                sections = self._keys.decrypt(project_id, obj.payload)
            except _RETRYABLE_PG_ERRORS:
                self._retry_unavailable()
            for section in sections:
                if isinstance(section, TombstonedSection):
                    tombstoned = True
                    continue
                self._validate_plain_section(project_id, section, decoded, run_ends)

        if tombstoned:
            # Other objects/sections were still decrypted and authenticated
            # above, so corruption wins over a privacy disposition.  Never
            # expose the readable prefix as a partial archive.
            raise TraceArchiveReadError(
                TraceArchiveDisposition.PRIVACY_SKIP,
                PRIVACY_TOMBSTONED,
                observed_digest=digest,
            )

        if set(decoded) != set(range(end_seq + 1)):
            self._dead_invalid()
        if len(run_ends) != 1:
            self._dead_invalid()
        end_event_seq, end_event = run_ends[0]
        if end_event_seq != end_seq or end_event.type != "run_end":
            self._dead_invalid()
        if parse_end_status(end_event.payload.get("status")) != end_status:
            self._dead_invalid()
        if end_status != index.outcome_status.value or end_event.ts != index.ended_at:
            self._dead_invalid()
        return ArchivedTrace(
            index=index,
            events=tuple(decoded[seq] for seq in range(end_seq + 1)),
            trace_digest=digest,
            subject_key_bindings=subject_key_bindings,
        )

    def _strict_index_path(self, index: TraceIndexRow) -> tuple[int, str, tuple[str, ...]]:
        path = index.path
        if not isinstance(path, Mapping):
            self._dead_invalid()
        end_seq = parse_seq(path.get(PATH_END_SEQ))
        end_status = parse_end_status(path.get(PATH_END_STATUS))
        if end_seq is None or end_status is None:
            self._dead_invalid()
        ranges = path.get(PATH_SEQ_RANGES)
        # A complete terminal archive has one closed canonical range.  Split
        # but adjacent ranges are semantically equivalent, yet accepting them
        # would make this a loose parser for a writer-owned invariant.
        if not isinstance(ranges, list) or len(ranges) != 1:
            self._dead_invalid()
        entry = ranges[0]
        if not isinstance(entry, list) or len(entry) != 2:
            self._dead_invalid()
        lo, hi = entry
        if (
            isinstance(lo, bool)
            or isinstance(hi, bool)
            or not isinstance(lo, int)
            or not isinstance(hi, int)
            or lo != 0
            or hi != end_seq
            or hi > MAX_TRACE_SEQ
        ):
            self._dead_invalid()
        raw_refs = path.get(PATH_PAYLOAD_REFS)
        if not isinstance(raw_refs, list) or not raw_refs:
            self._dead_invalid()
        if not all(isinstance(ref, str) and ref.strip() for ref in raw_refs):
            self._dead_invalid()
        refs = tuple(raw_refs)
        if len(set(refs)) != len(refs) or index.payload_ref != refs[0]:
            self._dead_invalid()
        return end_seq, end_status, refs

    def _read_objects(
        self, project_id: ProjectId, run_id: RunId, refs: Sequence[str], *, end_seq: int
    ) -> tuple[_ArchiveObject, ...]:
        # Every writer object begins at at least one distinct sequence in the
        # closed terminal range.  Ref-count and key-range validation belong
        # before TraceStore I/O so an impossible persisted path cannot turn a
        # deterministic archive defect into a retryable object miss.
        if len(refs) > end_seq + 1:
            self._dead_invalid()
        validated_refs: list[tuple[str, PayloadRef, int]] = []
        for ref_text in refs:
            ref = PayloadRef.parse(ref_text)
            if not is_safe_key(ref.key):
                self._dead_invalid()
            ref_first = self._ref_first_seq(ref, project_id, run_id)
            if ref_first > end_seq or ref_first > MAX_TRACE_SEQ:
                self._dead_invalid()
            validated_refs.append((ref_text, ref, ref_first))

        # Resolve only after every persisted ref is structurally bound.  A
        # temporary miss for an earlier valid object must not hide a later
        # deterministic bad ref by making the disposition order-dependent.
        objects: list[_ArchiveObject] = []
        for ref_text, ref, ref_first in validated_refs:
            try:
                raw = self._store.get(project_id, ref)
            except (NotFound, OSError, ImportError, httpx.HTTPError):
                # A validated ref may be temporarily unavailable or the
                # object store may collapse absence/permission to NotFound.
                # This is deliberately local: index/key binding failures are
                # deterministic archive-invalid, not retryable storage.
                raise TraceArchiveReadError(
                    TraceArchiveDisposition.RETRY, TRACE_UNAVAILABLE
                ) from None
            payload = self._strict_payload(raw)
            first_seq, last_seq = self._validate_header(payload, project_id, run_id)
            if first_seq != ref_first:
                self._dead_invalid()
            self._validate_encrypted_section_ranges(payload, first_seq, last_seq)
            version = payload.header.get("v")
            if (
                isinstance(version, bool)
                or not isinstance(version, int)
                or version not in (envelope.ENVELOPE_VERSION, envelope.V2_ENVELOPE_VERSION)
            ):
                self._dead_invalid()
            objects.append(
                _ArchiveObject(
                    ref=ref,
                    ref_text=ref_text,
                    raw=raw,
                    payload=payload,
                    first_seq=first_seq,
                    last_seq=last_seq,
                    version=version,
                )
            )
        return tuple(sorted(objects, key=lambda item: (item.first_seq, item.ref_text.encode("utf-8"))))

    def _strict_payload(self, raw: bytes) -> EncryptedPayload:
        # `json.loads` accepts NaN/Infinity and duplicate object keys by
        # default.  It also makes blank JSONL lines disappear if callers use
        # a comprehension.  Reject all three before the crypto parser sees
        # bytes, so a malformed archive cannot normalize into plausibility.
        text = raw.decode("utf-8")
        if "\r" in text or not text.endswith("\n"):
            self._dead_invalid()
        pieces = text.split("\n")
        lines = pieces[:-1]
        if not lines or any(not line for line in lines):
            self._dead_invalid()
        for line in lines:
            value = json.loads(
                line,
                parse_constant=self._reject_json_constant,
                object_pairs_hook=self._reject_duplicate_keys,
            )
            if not isinstance(value, dict):
                self._dead_invalid()
        return EncryptedPayload.from_bytes(raw)

    @staticmethod
    def _reject_json_constant(value: str) -> object:
        raise ValueError(f"non-finite JSON constant {value}")

    @staticmethod
    def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
        out: dict[str, object] = {}
        for key, value in pairs:
            if key in out:
                raise ValueError("duplicate JSON object key")
            out[key] = value
        return out

    def _validate_header(
        self, payload: EncryptedPayload, project_id: ProjectId, run_id: RunId
    ) -> tuple[int, int]:
        header = payload.header
        if header.get("fmt") == envelope.V2_ENVELOPE_FMT or header.get("v") == envelope.V2_ENVELOPE_VERSION:
            if (
                header.get("v") != envelope.V2_ENVELOPE_VERSION
                or header.get("fmt") != envelope.V2_ENVELOPE_FMT
                or header.get("project_id") != str(project_id)
                or header.get("run_id") != str(run_id)
            ):
                self._dead_invalid()
            # ``EncryptedPayload.from_bytes`` has already performed all v2
            # exact-key/canonical/range validation.  Do not rebuild a looser
            # secondary parser here.
            first = parse_seq(header.get("first_seq"))
            last = parse_seq(header.get("last_seq"))
            if first is None or last is None or first > last:
                self._dead_invalid()
            return first, last
        if set(header) != {"v", "fmt", "alg", "project_id", "run_id", "first_seq", "last_seq"}:
            self._dead_invalid()
        if (
            header.get("v") != envelope.ENVELOPE_VERSION
            or header.get("fmt") != envelope.ENVELOPE_FMT
            or header.get("alg") != envelope.ENVELOPE_ALG
            or header.get("project_id") != str(project_id)
            or header.get("run_id") != str(run_id)
        ):
            self._dead_invalid()
        first = parse_seq(header.get("first_seq"))
        last = parse_seq(header.get("last_seq"))
        if first is None or last is None or first > last:
            self._dead_invalid()
        return first, last

    def _validate_encrypted_section_ranges(
        self, payload: EncryptedPayload, first: int, last: int
    ) -> None:
        if not payload.sections:
            self._dead_invalid()
        if payload.header.get("v") == envelope.V2_ENVELOPE_VERSION:
            # The v2 parser validates every exact structural property before
            # this reader sees the value.  Its header min/max is the same
            # bound check this helper provides for permissive legacy v1.
            return
        ranges: list[tuple[int, int]] = []
        for section in payload.sections:
            if not isinstance(section, Mapping) or set(section) != {
                "seq_from",
                "seq_to",
                "subject_tags",
                "nonce",
                "ct",
                "wraps",
            }:
                self._dead_invalid()
            lo = parse_seq(section.get("seq_from"))
            hi = parse_seq(section.get("seq_to"))
            if lo is None or hi is None or lo > hi:
                self._dead_invalid()
            wraps = section.get("wraps")
            if not isinstance(wraps, list) or not wraps:
                self._dead_invalid()
            raw_tags = section.get("subject_tags")
            if (
                not isinstance(raw_tags, list)
                or len(raw_tags) > MAX_WRAPS_PER_SECTION
                or not all(
                    isinstance(tag, str) and tag and len(tag) <= MAX_SUBJECT_TAG_CHARS
                    for tag in raw_tags
                )
                or len(set(raw_tags)) != len(raw_tags)
            ):
                self._dead_invalid()
            expected_tags = tuple(raw_tags) or (PROJECT_SUBJECT_TAG,)
            if len(wraps) != len(expected_tags) or len(wraps) > MAX_WRAPS_PER_SECTION:
                self._dead_invalid()
            observed_tags: list[str] = []
            for wrap in wraps:
                if not isinstance(wrap, Mapping) or set(wrap) != {
                    "tag",
                    "key_id",
                    "nonce",
                    "share",
                }:
                    self._dead_invalid()
                tag = wrap.get("tag")
                if not isinstance(tag, str) or not tag:
                    self._dead_invalid()
                observed_tags.append(tag)
                key_id = wrap.get("key_id")
                if not isinstance(key_id, str):
                    self._dead_invalid()
                try:
                    UUID(key_id)
                except ValueError:
                    self._dead_invalid()
                nonce = self._strict_b64(wrap.get("nonce"))
                share = self._strict_b64(wrap.get("share"))
                if len(nonce) != envelope.NONCE_LEN or len(share) != envelope.KEY_LEN + 16:
                    self._dead_invalid()
            if tuple(observed_tags) != expected_tags:
                self._dead_invalid()
            nonce = self._strict_b64(section.get("nonce"))
            ciphertext = self._strict_b64(section.get("ct"))
            if len(nonce) != envelope.NONCE_LEN or len(ciphertext) <= 16:
                self._dead_invalid()
            if ranges and lo <= ranges[-1][1]:
                self._dead_invalid()
            ranges.append((lo, hi))
        if min(lo for lo, _hi in ranges) != first or max(hi for _lo, hi in ranges) != last:
            self._dead_invalid()

    def _subject_key_bindings(
        self, project_id: ProjectId, objects: Sequence[_ArchiveObject]
    ) -> tuple[SubjectKeyBinding, ...]:
        """Aggregate exact wrap identities and reject a tag/key equivocation.

        `_validate_encrypted_section_ranges` ran before this helper, so every
        section and wrap has an exact key set and UUID-shaped ``key_id``.
        Rechecking defensively keeps this public archive value safe if a
        future caller rearranges the validation sequence.
        """

        by_digest: dict[bytes, tuple[str | None, UUID]] = {}
        for obj in objects:
            for section in obj.payload.sections:
                wraps = section.get("wraps")
                if not isinstance(wraps, list):
                    self._dead_invalid()
                for wrap in wraps:
                    if not isinstance(wrap, Mapping):
                        self._dead_invalid()
                    raw_key_id = wrap.get("key_id")
                    if not isinstance(raw_key_id, str):
                        self._dead_invalid()
                    try:
                        key_id = UUID(raw_key_id)
                    except ValueError:
                        self._dead_invalid()
                    if obj.version == envelope.V2_ENVELOPE_VERSION:
                        try:
                            digest = envelope.b64d_canonical(wrap.get("digest"))
                        except ValueError:
                            self._dead_invalid()
                        tag: str | None = None
                    else:
                        tag = wrap.get("tag")
                        if not isinstance(tag, str):
                            self._dead_invalid()
                        digest = subject_digest(project_id, tag)
                    old = by_digest.setdefault(digest, (tag, key_id))
                    if old[1] != key_id:
                        self._dead_invalid()
        return tuple(
            SubjectKeyBinding(
                subject_tag=tag,
                key_id=key_id,
                # Preserve the legacy v1 DTO exactly; the finalizer derives
                # its opaque lock input from that tag.  A v2 wrap remains
                # digest-only and never materializes a tag in this process.
                subject_digest=digest if tag is None else None,
            )
            for digest, (tag, key_id) in sorted(
                by_digest.items(), key=lambda item: (item[1][0] is None, item[1][0] or item[0])
            )
        )

    @staticmethod
    def _strict_b64(raw: object) -> bytes:
        if not isinstance(raw, str):
            raise ValueError("invalid base64")
        try:
            return b64decode(raw.encode("ascii"), validate=True)
        except (BinasciiError, UnicodeEncodeError) as exc:
            raise ValueError("invalid base64") from exc

    def _validate_plain_section(
        self,
        project_id: ProjectId,
        section: PlainSection,
        decoded: dict[int, TraceEvent],
        run_ends: list[tuple[int, TraceEvent]],
    ) -> None:
        if not section.lines:
            self._dead_invalid()
        actual: list[int] = []
        previous = -1
        for line in section.lines:
            value = json.loads(
                line.decode("utf-8"),
                parse_constant=self._reject_json_constant,
                object_pairs_hook=self._reject_duplicate_keys,
            )
            if not isinstance(value, dict) or set(value) != {"seq", "event"}:
                self._dead_invalid()
            seq = value["seq"]
            event_raw = value["event"]
            if (
                isinstance(seq, bool)
                or not isinstance(seq, int)
                or not section.seq_from <= seq <= section.seq_to
                or seq <= previous
                or not isinstance(event_raw, dict)
                or seq in decoded
            ):
                self._dead_invalid()
            event = _EVENT_ADAPTER.validate_python(event_raw)
            tags = subject_tags_for(event)
            if section.envelope_version == envelope.V2_ENVELOPE_VERSION:
                try:
                    actual_digests = tuple(digest for digest, _tag in subject_digest_pairs(project_id, tags))
                except ValueError:
                    self._dead_invalid()
                if actual_digests != section.subject_digests:
                    self._dead_invalid()
            elif tags != section.subject_tags:
                self._dead_invalid()
            decoded[seq] = event
            actual.append(seq)
            previous = seq
            if event.type == "run_end":
                run_ends.append((seq, event))
        if min(actual) != section.seq_from or max(actual) != section.seq_to:
            self._dead_invalid()

    @staticmethod
    def _ciphertext_digest(
        project_id: ProjectId, run_id: RunId, objects: Sequence[_ArchiveObject]
    ) -> bytes:
        digest = hashlib.sha256()
        digest.update(_DIGEST_DOMAIN)
        digest.update(project_id.value.bytes)
        digest.update(run_id.value.bytes)
        digest.update(struct.pack(">I", len(objects)))
        for obj in objects:
            ref_bytes = obj.ref_text.encode("utf-8")
            digest.update(struct.pack(">QQI", obj.first_seq, obj.last_seq, len(ref_bytes)))
            digest.update(ref_bytes)
            digest.update(struct.pack(">Q", len(obj.raw)))
            digest.update(obj.raw)
        return digest.digest()

    @staticmethod
    def _ref_first_seq(ref: PayloadRef, project_id: ProjectId, run_id: RunId) -> int:
        project = str(project_id)
        run = str(run_id)
        parts = ref.key.split("/")
        leaf: str
        if ref.driver == "fs":
            if len(parts) != 3 or parts[:2] != [project, run] or not parts[2].endswith(".tbz"):
                raise ValueError("invalid fs archive key")
            leaf = parts[2][:-4]
        elif ref.driver == "s3":
            if len(parts) != 5 or not parts[0] or parts[1:4] != ["tb", project, run]:
                raise ValueError("invalid s3 archive key")
            leaf = parts[4]
        else:  # PayloadRef's type is static, but parsed persisted text is untrusted.
            raise ValueError("invalid archive driver")
        if len(leaf) != 8 or not leaf.isascii() or not leaf.isdecimal():
            raise ValueError("invalid archive sequence key")
        return int(leaf)

    @staticmethod
    def _dead_invalid() -> NoReturn:
        raise TraceArchiveReadError(TraceArchiveDisposition.DEAD, ARCHIVE_INVALID)

    @staticmethod
    def _retry_unavailable() -> NoReturn:
        raise TraceArchiveReadError(TraceArchiveDisposition.RETRY, TRACE_UNAVAILABLE)
