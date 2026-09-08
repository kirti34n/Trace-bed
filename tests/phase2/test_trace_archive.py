"""Strict archive-reader proofs for the P2A trace-learning hand-off.

These use a real envelope/key manager but in-memory index and object seams:
the reader's result must depend only on authenticated ciphertext and the
writer-owned index binding, never on an accidental partial plaintext read.
"""

from __future__ import annotations

import base64
import json
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import psycopg
import pytest

from tracebed.crypto.shred import EncryptedPayload, PlainSection, SubjectKeyManager
from tracebed.crypto.subject_digest import subject_digest
from tracebed.domain.clock import Clock, FakeClock
from tracebed.domain.enums import Arm, InstrumentationSource, TraceOutcomeStatus
from tracebed.domain.errors import NotFound
from tracebed.domain.events import RunEnd, RunStart, StateNote, TraceEvent
from tracebed.domain.ids import AgentTypeId, PrincipalId, ProjectId, RunId
from tracebed.domain.signatures import ABSENT_SIGNATURE
from tracebed.ingest.trace_archive import (
    ARCHIVE_AUTH_FAILED,
    ARCHIVE_DIGEST_MISMATCH,
    ARCHIVE_INVALID,
    PRIVACY_TOMBSTONED,
    TRACE_UNAVAILABLE,
    ArchivedTrace,
    SubjectKeyBinding,
    TraceArchiveDisposition,
    TraceArchiveReader,
    TraceArchiveReadError,
)
from tracebed.stores.pg.rows import SubjectKeyRow, TraceIndexRow
from tracebed.stores.tracestore import PayloadRef

pytestmark = pytest.mark.phase2


class _Master:
    def master_key(self) -> bytes:
        return b"m" * 32


class _WrongMaster:
    def master_key(self) -> bytes:
        return b"w" * 32


class _KeyStore:
    def __init__(self, clock: Clock) -> None:
        self._clock = clock
        self.rows: dict[tuple[ProjectId, str], SubjectKeyRow] = {}
        self.rows_by_digest: dict[tuple[ProjectId, bytes], SubjectKeyRow] = {}
        self.failure: BaseException | None = None

    def get_subject_key(self, project_id: ProjectId, subject_tag: str) -> SubjectKeyRow | None:
        if self.failure is not None:
            raise self.failure
        return self.rows.get((project_id, subject_tag))

    def get_subject_key_by_digest(
        self, project_id: ProjectId, wanted_digest: bytes
    ) -> SubjectKeyRow | None:
        if self.failure is not None:
            raise self.failure
        v2 = self.rows_by_digest.get((project_id, wanted_digest))
        if v2 is not None:
            return v2
        for (row_project_id, tag), row in self.rows.items():
            if row_project_id == project_id and subject_digest(project_id, tag) == wanted_digest:
                return row
        return None

    def insert_subject_key(
        self, project_id: ProjectId, subject_tag: str, key_id: UUID, wrapped_kek: bytes
    ) -> None:
        self.rows[(project_id, subject_tag)] = SubjectKeyRow(
            subject_tag=subject_tag,
            key_id=key_id,
            wrapped_kek=wrapped_kek,
            created_at=self._clock.now(),
            destroyed_at=None,
        )

    def insert_subject_key_v2(
        self, project_id: ProjectId, digest: bytes, key_id: UUID, wrapped_kek: bytes
    ) -> None:
        self.rows_by_digest[(project_id, digest)] = SubjectKeyRow(
            subject_tag=None,
            subject_digest=digest,
            wrap_version=2,
            key_id=key_id,
            wrapped_kek=wrapped_kek,
            created_at=self._clock.now(),
            destroyed_at=None,
        )

    def tombstone_fixture_key(self, project_id: ProjectId, subject_tag: str) -> bool:
        row = self.rows.get((project_id, subject_tag))
        if row is None:
            return False
        self.rows[(project_id, subject_tag)] = SubjectKeyRow(
            subject_tag=row.subject_tag,
            key_id=row.key_id,
            wrapped_kek=b"",
            created_at=row.created_at,
            destroyed_at=self._clock.now(),
        )
        return True


class _Objects:
    def __init__(self, objects: dict[str, bytes]) -> None:
        self.objects = objects
        self.get_calls = 0

    def get(self, _project_id: ProjectId, ref: PayloadRef) -> bytes:
        self.get_calls += 1
        try:
            return self.objects[ref.key]
        except KeyError:
            raise NotFound("trace payload not found") from None

    def put(
        self, project_id: ProjectId, run_id: RunId, first_seq: int, payload: bytes
    ) -> PayloadRef:
        ref = PayloadRef(driver="fs", key=f"{project_id}/{run_id}/{first_seq:08d}.tbz")
        self.objects[ref.key] = payload
        return ref

    def exists(self, _project_id: ProjectId, ref: PayloadRef) -> bool:
        return ref.key in self.objects

    def delete_project(self, project_id: ProjectId) -> int:
        keys = [key for key in self.objects if key.startswith(f"{project_id}/")]
        for key in keys:
            del self.objects[key]
        return len(keys)


@dataclass
class _Indexes:
    row: TraceIndexRow | None
    failure: BaseException | None = None

    def get_trace_index(self, project_id: ProjectId, run_id: RunId) -> TraceIndexRow:
        if self.failure is not None:
            raise self.failure
        if self.row is None or self.row.project_id != project_id or self.row.run_id != run_id:
            raise NotFound("not found")
        return self.row


@dataclass
class _Fixture:
    reader: TraceArchiveReader
    indexes: _Indexes
    objects: _Objects
    keys: _KeyStore
    project_id: ProjectId
    run_id: RunId
    ended_at: datetime
    refs: tuple[PayloadRef, ...]
    events: tuple[TraceEvent, ...]


def _wire(seq: int, event: TraceEvent) -> bytes:
    return json.dumps(
        {"seq": seq, "event": event.model_dump(mode="json")},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _row(
    project_id: ProjectId,
    run_id: RunId,
    ended_at: datetime,
    refs: tuple[PayloadRef, ...],
    *,
    ranges: object = None,
    envelope_versions: tuple[int, ...] | None = None,
) -> TraceIndexRow:
    return TraceIndexRow(
        project_id=project_id,
        run_id=run_id,
        agent_type_id=AgentTypeId(uuid4()),
        workflow_template_id=None,
        submitter_principal=PrincipalId(uuid4()),
        input_signature_hash=ABSENT_SIGNATURE,
        instrumentation_source=InstrumentationSource.SDK,
        arm=Arm.MEMORY_ON,
        path={
            "seq_ranges": [[0, 2]] if ranges is None else ranges,
            "payload_refs": [str(ref) for ref in refs],
            "end_seq": 2,
            "end_status": "ok",
        },
        started_at=ended_at - timedelta(seconds=2),
        ended_at=ended_at,
        payload_ref=str(refs[0]),
        outcome_status=TraceOutcomeStatus.OK,
        envelope_versions=envelope_versions,
    )


def _fixture() -> _Fixture:
    clock = FakeClock(datetime(2026, 1, 1, tzinfo=UTC))
    key_store = _KeyStore(clock)
    manager = SubjectKeyManager(key_store, _Master(), clock)
    project_id = ProjectId(uuid4())
    run_id = RunId(uuid4())
    ended_at = clock.now() + timedelta(seconds=2)
    events: tuple[TraceEvent, ...] = (
        RunStart(type="run_start", ts=clock.now(), payload={"query_text": "q"}),
        StateNote(
            type="state_note",
            ts=clock.now() + timedelta(seconds=1),
            payload={"subject_tags": ["user:alice"]},
        ),
        RunEnd(type="run_end", ts=ended_at, payload={"status": "ok"}),
    )

    # Two writer-shaped ciphertext objects.  The path deliberately lists them
    # out of sequence order; authenticated headers determine digest/read order.
    first = manager.encrypt(
        project_id,
        run_id,
        [PlainSection(0, 0, (), (_wire(0, events[0]),))],
    ).to_bytes()
    second = manager.encrypt(
        project_id,
        run_id,
        [
            PlainSection(1, 1, ("user:alice",), (_wire(1, events[1]),)),
            PlainSection(2, 2, (), (_wire(2, events[2]),)),
        ],
    ).to_bytes()
    first_ref = PayloadRef(driver="fs", key=f"{project_id}/{run_id}/00000000.tbz")
    second_ref = PayloadRef(driver="fs", key=f"{project_id}/{run_id}/00000001.tbz")
    refs = (second_ref, first_ref)
    objects = _Objects({first_ref.key: first, second_ref.key: second})
    indexes = _Indexes(_row(project_id, run_id, ended_at, refs))
    return _Fixture(
        reader=TraceArchiveReader(indexes, objects, manager),
        indexes=indexes,
        objects=objects,
        keys=key_store,
        project_id=project_id,
        run_id=run_id,
        ended_at=ended_at,
        refs=refs,
        events=events,
    )


def _untagged_events(f: _Fixture) -> tuple[TraceEvent, TraceEvent, TraceEvent]:
    return (
        RunStart(
            type="run_start",
            ts=f.ended_at - timedelta(seconds=2),
            payload={"query_text": "q"},
        ),
        StateNote(type="state_note", ts=f.ended_at - timedelta(seconds=1), payload={}),
        RunEnd(type="run_end", ts=f.ended_at, payload={"status": "ok"}),
    )


def _install_single_object(f: _Fixture, sections: list[PlainSection]) -> PayloadRef:
    raw = f.reader._keys.encrypt(f.project_id, f.run_id, sections).to_bytes()
    ref = PayloadRef(driver="fs", key=f"{f.project_id}/{f.run_id}/00000000.tbz")
    f.objects.objects = {ref.key: raw}
    f.indexes.row = _row(f.project_id, f.run_id, f.ended_at, (ref,))
    return ref


def _error(call: Callable[[], object]) -> TraceArchiveReadError:
    with pytest.raises(TraceArchiveReadError) as raised:
        call()
    return raised.value


def test_reader_accepts_out_of_order_refs_and_returns_only_verified_events() -> None:
    f = _fixture()

    archive = f.reader.read_complete(f.project_id, f.run_id, expected_ended_at=f.ended_at)

    assert isinstance(archive, ArchivedTrace)
    assert archive.events == f.events
    assert len(archive.trace_digest) == 32
    assert archive.subject_key_bindings == tuple(
        sorted(
            (
                SubjectKeyBinding("__project__", f.keys.rows[(f.project_id, "__project__")].key_id),
                SubjectKeyBinding("user:alice", f.keys.rows[(f.project_id, "user:alice")].key_id),
            ),
            key=lambda binding: (binding.subject_tag is None, binding.subject_tag or ""),
        )
    )
    assert f.objects.get_calls == 2


def test_reader_accepts_mixed_v1_v2_objects_only_with_exact_index_versions() -> None:
    f = _fixture()
    first_ref = PayloadRef(driver="fs", key=f"{f.project_id}/{f.run_id}/00000000.tbz")
    second_ref = PayloadRef(driver="fs", key=f"{f.project_id}/{f.run_id}/00000001.tbz")
    first = f.reader._keys.encrypt(
        f.project_id, f.run_id, [PlainSection(0, 0, (), (_wire(0, f.events[0]),))]
    ).to_bytes()
    second = f.reader._keys.encrypt_v2(
        f.project_id,
        f.run_id,
        [
            PlainSection(1, 1, ("user:alice",), (_wire(1, f.events[1]),)),
            PlainSection(2, 2, (), (_wire(2, f.events[2]),)),
        ],
    ).to_bytes()
    f.objects.objects = {first_ref.key: first, second_ref.key: second}
    f.indexes.row = _row(
        f.project_id,
        f.run_id,
        f.ended_at,
        (first_ref, second_ref),
        envelope_versions=(1, 2),
    )

    archive = f.reader.read_complete(f.project_id, f.run_id)

    assert archive.events == f.events
    assert {binding.subject_tag for binding in archive.subject_key_bindings} == {
        "__project__",
        None,
    }
    assert any(
        binding.subject_digest == subject_digest(f.project_id, "user:alice")
        for binding in archive.subject_key_bindings
    )
    f.indexes.row = replace(f.indexes.row, envelope_versions=(1,))
    error = _error(lambda: f.reader.read_complete(f.project_id, f.run_id))
    assert (error.disposition, error.code) == (TraceArchiveDisposition.DEAD, ARCHIVE_INVALID)


def test_conflicting_archived_key_identity_for_one_subject_is_dead() -> None:
    f = _fixture()
    first_ref = f.refs[1]
    lines = [json.loads(line) for line in f.objects.objects[first_ref.key].decode().splitlines()]
    # Rebind the first object structurally to the same user tag as the next
    # object, but with a different archived key identity. The reader must
    # refuse that equivocation before attempting either section's decrypt.
    lines[1]["subject_tags"] = ["user:alice"]
    lines[1]["wraps"][0]["tag"] = "user:alice"
    lines[1]["wraps"][0]["key_id"] = str(uuid4())
    f.objects.objects[first_ref.key] = b"".join(
        json.dumps(line, sort_keys=True, separators=(",", ":")).encode() + b"\n" for line in lines
    )

    error = _error(lambda: f.reader.read_complete(f.project_id, f.run_id))

    assert (error.disposition, error.code) == (TraceArchiveDisposition.DEAD, ARCHIVE_INVALID)


def test_ciphertext_digest_golden_vector_is_domain_separated() -> None:
    project_id = ProjectId("12345678-1234-5678-1234-567812345678")
    run_id = RunId("87654321-4321-8765-4321-876543214321")
    digest = TraceArchiveReader._ciphertext_digest(project_id, run_id, ())
    # Empty-object framing is enough to freeze the domain/version and UUID/u32
    # encoding independently from randomized AEAD ciphertext.
    assert digest.hex() == "1c314dca2d6bd9ea6a9e331505225c5f671a64249e52834426de48b933d936dd"


def test_index_miss_is_dead_but_validated_object_miss_is_retry() -> None:
    f = _fixture()
    f.indexes.row = None
    index_error = _error(lambda: f.reader.read_complete(f.project_id, f.run_id))
    assert (index_error.disposition, index_error.code) == (
        TraceArchiveDisposition.DEAD,
        ARCHIVE_INVALID,
    )

    f = _fixture()
    f.objects.objects.clear()
    store_error = _error(lambda: f.reader.read_complete(f.project_id, f.run_id))
    assert (store_error.disposition, store_error.code) == (
        TraceArchiveDisposition.RETRY,
        TRACE_UNAVAILABLE,
    )


@pytest.mark.parametrize("boundary", ["index", "subject_key"])
def test_connection_dependency_failures_are_sanitized_retry(boundary: str) -> None:
    f = _fixture()
    secret = "postgresql://canary-user:canary-password@provider.invalid/db"
    failure = psycopg.OperationalError(secret)
    if boundary == "index":
        f.indexes.failure = failure
    else:
        f.keys.failure = failure

    error = _error(lambda: f.reader.read_complete(f.project_id, f.run_id))

    assert (error.disposition, error.code) == (
        TraceArchiveDisposition.RETRY,
        TRACE_UNAVAILABLE,
    )
    assert secret not in str(error)
    assert secret not in repr(error)


def test_reader_does_not_hide_psycopg_programming_errors() -> None:
    f = _fixture()
    f.indexes.failure = psycopg.ProgrammingError("programmer-canary")

    with pytest.raises(psycopg.ProgrammingError, match="programmer-canary"):
        f.reader.read_complete(f.project_id, f.run_id)


def test_pinned_ciphertext_digest_wins_even_after_a_subject_is_shredded() -> None:
    f = _fixture()
    assert f.keys.tombstone_fixture_key(f.project_id, "user:alice")

    error = _error(
        lambda: f.reader.read_complete(f.project_id, f.run_id, expected_digest=b"x" * 32)
    )

    assert (error.disposition, error.code) == (
        TraceArchiveDisposition.DEAD,
        ARCHIVE_DIGEST_MISMATCH,
    )
    assert error.observed_digest is not None and len(error.observed_digest) == 32


@pytest.mark.parametrize("version", (1, 2))
def test_wrong_master_wrapped_kek_is_retryable_for_v1_and_v2_archives(version: int) -> None:
    """Only a master KEK unwrap outage retries; authenticated share tampering is DEAD."""

    f = _fixture()
    if version == 2:
        ref = _install_single_object(
            f,
            [
                PlainSection(
                    0,
                    0,
                    (),
                    (_wire(0, f.events[0]),),
                )
            ],
        )
        raw = f.reader._keys.encrypt_v2(
            f.project_id,
            f.run_id,
            [PlainSection(0, 0, (), (_wire(0, f.events[0]),))],
        ).to_bytes()
        f.objects.objects = {ref.key: raw}
        assert f.indexes.row is not None
        f.indexes.row = replace(f.indexes.row, envelope_versions=(2,))
    f.reader = TraceArchiveReader(
        f.indexes,
        f.objects,
        SubjectKeyManager(f.keys, _WrongMaster(), FakeClock()),
    )

    error = _error(lambda: f.reader.read_complete(f.project_id, f.run_id))
    assert (error.disposition, error.code) == (TraceArchiveDisposition.RETRY, TRACE_UNAVAILABLE)


def test_ciphertext_bitflip_is_archive_auth_failure_even_when_another_section_is_tombstoned() -> (
    None
):
    f = _fixture()
    assert f.keys.tombstone_fixture_key(f.project_id, "user:alice")
    first_ref = f.refs[1]
    lines = [json.loads(line) for line in f.objects.objects[first_ref.key].decode().splitlines()]
    ciphertext = bytearray(base64.b64decode(lines[1]["ct"]))
    ciphertext[-1] ^= 1
    lines[1]["ct"] = base64.b64encode(ciphertext).decode("ascii")
    f.objects.objects[first_ref.key] = b"".join(
        json.dumps(line, sort_keys=True, separators=(",", ":")).encode() + b"\n" for line in lines
    )

    error = _error(lambda: f.reader.read_complete(f.project_id, f.run_id))

    assert (error.disposition, error.code) == (
        TraceArchiveDisposition.DEAD,
        ARCHIVE_AUTH_FAILED,
    )


def test_tombstone_never_masks_invalid_wrap_shape_or_jsonl_syntax() -> None:
    f = _fixture()
    assert f.keys.tombstone_fixture_key(f.project_id, "user:alice")
    tagged_ref = f.refs[0]
    lines = [json.loads(line) for line in f.objects.objects[tagged_ref.key].decode().splitlines()]
    lines[1]["wraps"][0]["key_id"] = "not-a-uuid"
    f.objects.objects[tagged_ref.key] = b"".join(
        json.dumps(line, sort_keys=True, separators=(",", ":")).encode() + b"\n" for line in lines
    )
    error = _error(lambda: f.reader.read_complete(f.project_id, f.run_id))
    assert (error.disposition, error.code) == (TraceArchiveDisposition.DEAD, ARCHIVE_INVALID)

    f = _fixture()
    first_ref = f.refs[1]
    f.objects.objects[first_ref.key] = b'{"v":1,"v":1}\n'
    error = _error(lambda: f.reader.read_complete(f.project_id, f.run_id))
    assert (error.disposition, error.code) == (TraceArchiveDisposition.DEAD, ARCHIVE_INVALID)

    f = _fixture()
    first_ref = f.refs[1]
    f.objects.objects[first_ref.key] = b"{}\n\n{}\n"
    error = _error(lambda: f.reader.read_complete(f.project_id, f.run_id))
    assert (error.disposition, error.code) == (TraceArchiveDisposition.DEAD, ARCHIVE_INVALID)


def test_noncanonical_terminal_ranges_and_unsafe_refs_are_dead_before_store_io() -> None:
    f = _fixture()
    assert f.indexes.row is not None
    f.indexes.row = _row(
        f.project_id,
        f.run_id,
        f.ended_at,
        f.refs,
        ranges=[[0, 0], [1, 2]],
    )
    error = _error(lambda: f.reader.read_complete(f.project_id, f.run_id))
    assert (error.disposition, error.code) == (TraceArchiveDisposition.DEAD, ARCHIVE_INVALID)
    assert f.objects.get_calls == 0


def test_invalid_later_ref_wins_over_an_earlier_missing_object_without_io() -> None:
    f = _fixture()
    valid_ref = f.refs[1]
    impossible_ref = PayloadRef(driver="fs", key=f"{f.project_id}/{f.run_id}/99999999.tbz")
    # The valid first ref is deliberately missing.  Validation must inspect
    # the entire persisted path before doing either GET, so the later invalid
    # key deterministically wins over a retryable object miss.
    f.objects.objects.pop(valid_ref.key)
    f.indexes.row = _row(f.project_id, f.run_id, f.ended_at, (valid_ref, impossible_ref))

    error = _error(lambda: f.reader.read_complete(f.project_id, f.run_id))

    assert (error.disposition, error.code) == (TraceArchiveDisposition.DEAD, ARCHIVE_INVALID)
    assert f.objects.get_calls == 0

    f = _fixture()
    impossible_ref = PayloadRef(driver="fs", key=f"{f.project_id}/{f.run_id}/99999999.tbz")
    f.indexes.row = _row(f.project_id, f.run_id, f.ended_at, (impossible_ref,))
    error = _error(lambda: f.reader.read_complete(f.project_id, f.run_id))
    assert (error.disposition, error.code) == (TraceArchiveDisposition.DEAD, ARCHIVE_INVALID)
    assert f.objects.get_calls == 0


def test_wrong_identity_path_status_and_end_time_bindings_are_dead() -> None:
    f = _fixture()
    wrong_project = ProjectId(uuid4())
    error = _error(lambda: f.reader.read_complete(wrong_project, f.run_id))
    assert (error.disposition, error.code) == (TraceArchiveDisposition.DEAD, ARCHIVE_INVALID)

    f = _fixture()
    wrong_run = RunId(uuid4())
    error = _error(lambda: f.reader.read_complete(f.project_id, wrong_run))
    assert (error.disposition, error.code) == (TraceArchiveDisposition.DEAD, ARCHIVE_INVALID)

    f = _fixture()
    assert f.indexes.row is not None
    f.indexes.row = _row(f.project_id, f.run_id, f.ended_at, f.refs)
    path = dict(f.indexes.row.path or {})
    path["end_status"] = "error"
    f.indexes.row = replace(f.indexes.row, path=path)
    error = _error(lambda: f.reader.read_complete(f.project_id, f.run_id))
    assert (error.disposition, error.code) == (TraceArchiveDisposition.DEAD, ARCHIVE_INVALID)

    f = _fixture()
    error = _error(
        lambda: f.reader.read_complete(
            f.project_id,
            f.run_id,
            expected_ended_at=f.ended_at + timedelta(microseconds=1),
        )
    )
    assert (error.disposition, error.code) == (TraceArchiveDisposition.DEAD, ARCHIVE_INVALID)


def test_wrong_ref_run_and_header_run_are_dead_without_cross_archive_read() -> None:
    f = _fixture()
    wrong_ref = PayloadRef(driver="fs", key=f"{f.project_id}/{RunId(uuid4())}/00000000.tbz")
    f.indexes.row = _row(f.project_id, f.run_id, f.ended_at, (wrong_ref,))
    error = _error(lambda: f.reader.read_complete(f.project_id, f.run_id))
    assert (error.disposition, error.code) == (TraceArchiveDisposition.DEAD, ARCHIVE_INVALID)
    assert f.objects.get_calls == 0

    f = _fixture()
    first_ref = f.refs[1]
    lines = [json.loads(line) for line in f.objects.objects[first_ref.key].decode().splitlines()]
    lines[0]["run_id"] = str(RunId(uuid4()))
    f.objects.objects[first_ref.key] = b"".join(
        json.dumps(line, sort_keys=True, separators=(",", ":")).encode() + b"\n" for line in lines
    )
    error = _error(lambda: f.reader.read_complete(f.project_id, f.run_id))
    assert (error.disposition, error.code) == (TraceArchiveDisposition.DEAD, ARCHIVE_INVALID)

    f = _fixture()
    assert f.indexes.row is not None
    bad_ref = PayloadRef(driver="fs", key=f"{f.project_id}/../{f.run_id}/00000000.tbz")
    f.indexes.row = _row(f.project_id, f.run_id, f.ended_at, (bad_ref,))
    error = _error(lambda: f.reader.read_complete(f.project_id, f.run_id))
    assert (error.disposition, error.code) == (TraceArchiveDisposition.DEAD, ARCHIVE_INVALID)
    assert f.objects.get_calls == 0


@pytest.mark.parametrize(
    "lines",
    [
        lambda f: (
            _wire(0, _untagged_events(f)[0]),
            b'{"seq":NaN,"event":{}}',
            _wire(2, _untagged_events(f)[2]),
        ),
        lambda f: (
            _wire(0, _untagged_events(f)[0]),
            b'{"seq":1,"event":{"type":"not_an_event","ts":"2026-01-01T00:00:01Z","payload":{}}}',
            _wire(2, _untagged_events(f)[2]),
        ),
        lambda f: (
            _wire(0, _untagged_events(f)[0]),
            _wire(0, _untagged_events(f)[0]),
            _wire(2, _untagged_events(f)[2]),
        ),
        lambda f: (
            _wire(0, _untagged_events(f)[0]),
            _wire(1, _untagged_events(f)[1]),
        ),
        lambda f: (
            _wire(0, _untagged_events(f)[0]),
            _wire(3, _untagged_events(f)[1]),
            _wire(2, _untagged_events(f)[2]),
        ),
    ],
    ids=["nonfinite", "bad-event", "duplicate", "gap", "extra"],
)
def test_malformed_nonfinite_duplicate_gap_and_extra_plaintext_sequences_are_dead(
    lines: Callable[[_Fixture], tuple[bytes, ...]],
) -> None:
    f = _fixture()
    _install_single_object(f, [PlainSection(0, 2, (), lines(f))])

    error = _error(lambda: f.reader.read_complete(f.project_id, f.run_id))

    assert (error.disposition, error.code) == (TraceArchiveDisposition.DEAD, ARCHIVE_INVALID)


def test_sparse_authenticated_section_is_legal_when_other_object_supplies_the_gap() -> None:
    f = _fixture()
    start, middle, end = _untagged_events(f)
    sparse = f.reader._keys.encrypt(
        f.project_id,
        f.run_id,
        [PlainSection(0, 2, (), (_wire(0, start), _wire(2, end)))],
    ).to_bytes()
    gap = f.reader._keys.encrypt(
        f.project_id,
        f.run_id,
        [PlainSection(1, 1, (), (_wire(1, middle),))],
    ).to_bytes()
    first_ref = PayloadRef(driver="fs", key=f"{f.project_id}/{f.run_id}/00000000.tbz")
    gap_ref = PayloadRef(driver="fs", key=f"{f.project_id}/{f.run_id}/00000001.tbz")
    f.objects.objects = {first_ref.key: sparse, gap_ref.key: gap}
    # The overlap is across objects, which is legal for gap-fill batches;
    # section ranges inside each ciphertext object remain monotone.
    f.indexes.row = _row(f.project_id, f.run_id, f.ended_at, (gap_ref, first_ref))

    archive = f.reader.read_complete(f.project_id, f.run_id)

    assert archive.events == (start, middle, end)


def test_sanitized_reader_errors_never_echo_archive_canaries() -> None:
    f = _fixture()
    secret = "provider://canary-ref-user:alice"
    first_ref = f.refs[1]
    f.objects.objects[first_ref.key] = secret.encode("utf-8")

    error = _error(lambda: f.reader.read_complete(f.project_id, f.run_id))

    assert error.code == ARCHIVE_INVALID
    assert secret not in str(error)
    assert secret not in repr(error)


def test_deeply_nested_archive_json_is_sanitized_as_invalid() -> None:
    f = _fixture()
    first_ref = f.refs[1]
    canary = "deep-provider-canary"
    f.objects.objects[first_ref.key] = (
        (b"[" * 10_000) + (b'"' + canary.encode("utf-8") + b'"') + (b"]" * 10_000) + b"\n"
    )

    error = _error(lambda: f.reader.read_complete(f.project_id, f.run_id))

    assert (error.disposition, error.code) == (TraceArchiveDisposition.DEAD, ARCHIVE_INVALID)
    assert canary not in str(error)
    assert canary not in repr(error)


def test_tombstoned_section_is_privacy_skip_with_ciphertext_digest_and_no_partial_events() -> None:
    f = _fixture()
    assert f.keys.tombstone_fixture_key(f.project_id, "user:alice")

    error = _error(lambda: f.reader.read_complete(f.project_id, f.run_id))

    assert (error.disposition, error.code) == (
        TraceArchiveDisposition.PRIVACY_SKIP,
        PRIVACY_TOMBSTONED,
    )
    assert error.observed_digest is not None and len(error.observed_digest) == 32


def test_missing_or_mismatched_live_key_is_dead_not_a_privacy_skip() -> None:
    f = _fixture()
    del f.keys.rows[(f.project_id, "user:alice")]
    error = _error(lambda: f.reader.read_complete(f.project_id, f.run_id))
    assert (error.disposition, error.code) == (TraceArchiveDisposition.DEAD, ARCHIVE_INVALID)

    f = _fixture()
    tagged_ref = f.refs[0]
    lines = [json.loads(line) for line in f.objects.objects[tagged_ref.key].decode().splitlines()]
    lines[1]["wraps"][0]["key_id"] = str(uuid4())
    f.objects.objects[tagged_ref.key] = b"".join(
        json.dumps(line, sort_keys=True, separators=(",", ":")).encode() + b"\n" for line in lines
    )
    error = _error(lambda: f.reader.read_complete(f.project_id, f.run_id))
    assert (error.disposition, error.code) == (TraceArchiveDisposition.DEAD, ARCHIVE_INVALID)


def test_destroyed_key_with_a_mismatched_wrap_is_dead_not_privacy_skip() -> None:
    f = _fixture()
    assert f.keys.tombstone_fixture_key(f.project_id, "user:alice")
    tagged_ref = f.refs[0]
    lines = [json.loads(line) for line in f.objects.objects[tagged_ref.key].decode().splitlines()]
    lines[1]["wraps"][0]["key_id"] = str(uuid4())
    f.objects.objects[tagged_ref.key] = b"".join(
        json.dumps(line, sort_keys=True, separators=(",", ":")).encode() + b"\n" for line in lines
    )

    error = _error(lambda: f.reader.read_complete(f.project_id, f.run_id))

    assert (error.disposition, error.code) == (TraceArchiveDisposition.DEAD, ARCHIVE_INVALID)


@pytest.mark.parametrize(
    ("tags", "corruption"),
    [
        (("user:alice", "user:bob"), "mismatch"),
        (("user:alice", "user:bob"), "missing"),
        (("user:bob", "user:alice"), "mismatch"),
        (("user:bob", "user:alice"), "missing"),
    ],
    ids=[
        "destroyed-first-mismatch",
        "destroyed-first-missing",
        "destroyed-last-mismatch",
        "destroyed-last-missing",
    ],
)
def test_reader_multi_wrap_binding_corruption_is_not_masked_by_tombstone(
    tags: tuple[str, str], corruption: str
) -> None:
    f = _fixture()
    raw = f.reader._keys.encrypt(
        f.project_id,
        f.run_id,
        [
            PlainSection(0, 0, (), (_wire(0, f.events[0]),)),
            PlainSection(1, 2, tags, (_wire(1, f.events[1]), _wire(2, f.events[2]))),
        ],
    ).to_bytes()
    ref = PayloadRef(driver="fs", key=f"{f.project_id}/{f.run_id}/00000000.tbz")
    f.objects.objects = {ref.key: raw}
    f.indexes.row = _row(f.project_id, f.run_id, f.ended_at, (ref,))
    assert f.keys.tombstone_fixture_key(f.project_id, "user:alice")

    if corruption == "missing":
        del f.keys.rows[(f.project_id, "user:bob")]
    else:
        lines = [json.loads(line) for line in f.objects.objects[ref.key].decode().splitlines()]
        lines[2]["wraps"][tags.index("user:bob")]["key_id"] = str(uuid4())
        f.objects.objects[ref.key] = b"".join(
            json.dumps(line, sort_keys=True, separators=(",", ":")).encode() + b"\n"
            for line in lines
        )

    error = _error(lambda: f.reader.read_complete(f.project_id, f.run_id))

    assert (error.disposition, error.code) == (TraceArchiveDisposition.DEAD, ARCHIVE_INVALID)


def test_overlapping_ciphertext_sections_and_out_of_order_plain_lines_are_dead() -> None:
    f = _fixture()
    first_ref = f.refs[1]
    original = EncryptedPayload.from_bytes(f.objects.objects[first_ref.key])
    duplicated = EncryptedPayload(
        header=original.header, sections=(original.sections[0], original.sections[0])
    )
    f.objects.objects[first_ref.key] = duplicated.to_bytes()
    error = _error(lambda: f.reader.read_complete(f.project_id, f.run_id))
    assert (error.disposition, error.code) == (TraceArchiveDisposition.DEAD, ARCHIVE_INVALID)


def test_same_plaintext_reencrypted_under_fresh_aead_has_a_new_ciphertext_digest() -> None:
    f = _fixture()
    before = f.reader.read_complete(f.project_id, f.run_id).trace_digest
    first_ref = f.refs[1]
    replacement = f.reader._keys.encrypt(
        f.project_id,
        f.run_id,
        [PlainSection(0, 0, (), (_wire(0, f.events[0]),))],
    ).to_bytes()
    f.objects.objects[first_ref.key] = replacement

    after = f.reader.read_complete(f.project_id, f.run_id).trace_digest

    assert after != before


def test_authenticated_out_of_order_plain_lines_are_dead() -> None:
    f = _fixture()
    clock = FakeClock(f.ended_at - timedelta(seconds=2))
    manager = SubjectKeyManager(f.keys, _Master(), clock)
    # A validly authenticated envelope can still contain an invalid archive
    # ordering; do not let a sparse-section reader sort it into plausibility.
    event0 = StateNote(
        type="state_note",
        ts=f.ended_at - timedelta(seconds=2),
        payload={"subject_tags": ["user:alice"]},
    )
    event1 = StateNote(
        type="state_note",
        ts=f.ended_at - timedelta(seconds=1),
        payload={"subject_tags": ["user:alice"]},
    )
    out_of_order = manager.encrypt(
        f.project_id,
        f.run_id,
        [PlainSection(0, 1, ("user:alice",), (_wire(1, event1), _wire(0, event0)))],
    ).to_bytes()
    only_ref = PayloadRef(driver="fs", key=f"{f.project_id}/{f.run_id}/00000000.tbz")
    f.objects.objects = {only_ref.key: out_of_order}
    assert f.indexes.row is not None
    f.indexes.row = _row(f.project_id, f.run_id, f.ended_at, (only_ref,))
    error = _error(lambda: f.reader.read_complete(f.project_id, f.run_id))
    assert (error.disposition, error.code) == (TraceArchiveDisposition.DEAD, ARCHIVE_INVALID)
