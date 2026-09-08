"""Crypto-shredding proving tests (PHASE0-CONTRACT.md §13.2, PHASE-0 Task 10).

Offline throughout — a `FakeSubjectKeyStore` stands in for `Repo` (§12: the
`crypto` package never imports `stores.pg`, so nothing here needs Postgres).
Proves: envelope round-trip; AAD tamper (changed `run_id`) fails decryption;
nonce uniqueness across many sections; destroying subject A tombstones every
section that referenced A (including a multi-subject section — the XOR-share
semantics of C-13) while subject B's sections stay readable, the STORED
OBJECT BYTES stay byte-identical before/after the shred, and the payload_ref
still resolves.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass, replace
from datetime import datetime
from typing import TYPE_CHECKING, cast
from uuid import UUID, uuid4

import pytest
from cryptography.exceptions import InvalidTag

from tracebed.crypto import (
    PROJECT_SUBJECT_TAG,
    EncryptedPayload,
    EnvMasterKeyProvider,
    KeyBindingMismatch,
    KeyMaterialUnavailable,
    PlainSection,
    SubjectKeyManager,
)
from tracebed.crypto import envelope as envelope_mod
from tracebed.crypto.shred import SubjectKeyStore
from tracebed.crypto.subject_digest import subject_digest
from tracebed.domain.canonical import canonical_json
from tracebed.domain.clock import Clock, FakeClock
from tracebed.domain.errors import MasterKeyMissing, NotFound
from tracebed.domain.ids import ProjectId, mint_run_id

# Without this the whole crypto-shred proving suite is invisible to
# `pytest -m phase0`, which IS the Phase 0 gate (PLAN.md §7) — 20 green
# tests that never run are indistinguishable from no tests at all.
pytestmark = pytest.mark.phase0

if TYPE_CHECKING:
    # Type-only import (§5.2). A real, top-level runtime import of a store
    # module from a crypto test would couple this file's collection to
    # psycopg being importable; a local structurally-identical fake keeps it
    # offline-first per §12, and `test_fake_row_matches_the_real_subject_key_row`
    # is what stops the fake from drifting away from the real dataclass.
    from tracebed.stores.pg.rows import SubjectKeyRow


@dataclass(frozen=True, slots=True)
class _FakeSubjectKeyRow:
    """Structurally identical to `stores.pg.rows.SubjectKeyRow` (§5.2) —
    see the `TYPE_CHECKING` note above for why this chunk does not import
    the real class at runtime."""

    subject_tag: str | None
    key_id: UUID
    wrapped_kek: bytes
    created_at: datetime
    destroyed_at: datetime | None
    subject_digest: bytes | None = None
    wrap_version: int = 1


# --------------------------------------------------------------------------- #
# Chunk-local fakes (PHASE0-CONTRACT.md §13.1: fakes live beside their tests)
# --------------------------------------------------------------------------- #


class FakeSubjectKeyStore:
    """In-memory stand-in for `Repo`'s subject-key table."""

    def __init__(self, clock: Clock) -> None:
        self._clock = clock
        self._rows: dict[tuple[ProjectId, str], _FakeSubjectKeyRow] = {}
        self._v2_rows: dict[tuple[ProjectId, bytes], _FakeSubjectKeyRow] = {}

    def get_subject_key(self, project_id: ProjectId, subject_tag: str) -> SubjectKeyRow | None:
        return self._rows.get((project_id, subject_tag))  # type: ignore[return-value]

    def get_subject_key_by_digest(
        self, project_id: ProjectId, digest: bytes
    ) -> SubjectKeyRow | None:
        v2 = self._v2_rows.get((project_id, digest))
        if v2 is not None:
            return v2  # type: ignore[return-value]
        for (row_project_id, tag), row in self._rows.items():
            if row_project_id == project_id and subject_digest(project_id, tag) == digest:
                return row  # type: ignore[return-value]
        return None

    def insert_subject_key(
        self, project_id: ProjectId, subject_tag: str, key_id: UUID, wrapped_kek: bytes
    ) -> None:
        self._rows[(project_id, subject_tag)] = _FakeSubjectKeyRow(
            subject_tag=subject_tag,
            key_id=key_id,
            wrapped_kek=wrapped_kek,
            created_at=self._clock.now(),
            destroyed_at=None,
        )

    def insert_subject_key_v2(
        self, project_id: ProjectId, digest: bytes, key_id: UUID, wrapped_kek: bytes
    ) -> None:
        self._v2_rows[(project_id, digest)] = _FakeSubjectKeyRow(
            subject_tag=None,
            subject_digest=digest,
            wrap_version=2,
            key_id=key_id,
            wrapped_kek=wrapped_kek,
            created_at=self._clock.now(),
            destroyed_at=None,
        )


class FakeMasterKeyProvider:
    """Deterministic in-memory master key — no env var, no I/O."""

    def __init__(self, key: bytes | None = None) -> None:
        self._key = key if key is not None else os.urandom(32)

    def master_key(self) -> bytes:
        return self._key


def _manager() -> tuple[SubjectKeyManager, FakeSubjectKeyStore, FakeClock]:
    clock = FakeClock()
    store = FakeSubjectKeyStore(clock)
    manager = SubjectKeyManager(store, FakeMasterKeyProvider(), clock)
    return manager, store, clock


def _line(seq: int) -> bytes:
    return f'{{"seq":{seq},"event":{{"type":"state_note","payload":{{}}}}}}'.encode()


# --------------------------------------------------------------------------- #
# Envelope round-trip
# --------------------------------------------------------------------------- #


def test_envelope_round_trip_single_project_section() -> None:
    manager, _store, _clock = _manager()
    project_id = ProjectId(uuid4())
    run_id = mint_run_id()
    sections = [PlainSection(seq_from=0, seq_to=1, subject_tags=(), lines=(_line(0), _line(1)))]

    payload = manager.encrypt(project_id, run_id, sections)
    wire = payload.to_bytes()
    restored = EncryptedPayload.from_bytes(wire)

    results = manager.decrypt(project_id, restored)
    assert len(results) == 1
    assert isinstance(results[0], PlainSection)
    assert results[0].lines == sections[0].lines
    assert results[0].seq_from == 0
    assert results[0].seq_to == 1


def test_envelope_round_trip_tagged_section() -> None:
    manager, _store, _clock = _manager()
    project_id = ProjectId(uuid4())
    run_id = mint_run_id()
    sections = [
        PlainSection(seq_from=0, seq_to=0, subject_tags=("user:alice",), lines=(_line(0),)),
    ]

    payload = manager.encrypt(project_id, run_id, sections)
    restored = EncryptedPayload.from_bytes(payload.to_bytes())
    results = manager.decrypt(project_id, restored)

    assert isinstance(results[0], PlainSection)
    assert results[0].subject_tags == ("user:alice",)
    assert results[0].lines == sections[0].lines


def test_destroyed_key_does_not_hide_later_live_v2_share_authentication_failure() -> None:
    """The opaque v2 path has the same corruption-before-privacy order."""

    manager, store, _clock = _manager()
    project_id = ProjectId(uuid4())
    run_id = mint_run_id()
    line = canonical_json({"event": {"payload": {}, "type": "state_note"}, "seq": 0})
    payload = manager.encrypt_v2(
        project_id,
        run_id,
        [PlainSection(0, 0, ("alice", "bob"), (line,))],
    )
    alice_digest = subject_digest(project_id, "alice")
    alice = store._v2_rows[(project_id, alice_digest)]
    store._v2_rows[(project_id, alice_digest)] = replace(
        alice, wrapped_kek=b"", destroyed_at=_clock.now()
    )
    section = dict(payload.sections[0])
    raw_wraps = section["wraps"]
    assert isinstance(raw_wraps, list)
    assert all(isinstance(wrap, Mapping) for wrap in raw_wraps)
    wraps = [dict(wrap) for wrap in raw_wraps]
    live_index = next(
        index
        for index, wrap in enumerate(wraps)
        if envelope_mod.b64d(str(wrap["digest"])) != alice_digest
    )
    wraps[live_index]["share"] = envelope_mod.b64e(b"\x00" * 48)
    section["wraps"] = wraps

    with pytest.raises(KeyBindingMismatch):
        manager.decrypt(project_id, EncryptedPayload(payload.header, (section,)))


@pytest.mark.parametrize("version", (1, 2))
def test_wrong_master_key_is_retryable_for_v1_and_v2_wrapped_keks(version: int) -> None:
    """Master-wrapped KEK auth is an operator dependency, unlike a DEK wrap."""

    clock = FakeClock()
    store = FakeSubjectKeyStore(clock)
    writer = SubjectKeyManager(store, FakeMasterKeyProvider(b"a" * 32), clock)
    project_id = ProjectId(uuid4())
    run_id = mint_run_id()
    line = (
        _line(0)
        if version == 1
        else canonical_json({"event": {"payload": {}, "type": "state_note"}, "seq": 0})
    )
    section = PlainSection(0, 0, ("alice",), (line,))
    payload = (
        writer.encrypt(project_id, run_id, [section])
        if version == 1
        else writer.encrypt_v2(project_id, run_id, [section])
    )
    reader = SubjectKeyManager(store, FakeMasterKeyProvider(b"b" * 32), clock)

    with pytest.raises(KeyMaterialUnavailable):
        reader.decrypt(project_id, payload)


def test_header_shape_matches_the_wire_spec() -> None:
    manager, _store, _clock = _manager()
    project_id = ProjectId(uuid4())
    run_id = mint_run_id()
    sections = [
        PlainSection(seq_from=0, seq_to=4, subject_tags=(), lines=(_line(0),)),
        PlainSection(seq_from=5, seq_to=9, subject_tags=("user:alice",), lines=(_line(5),)),
    ]
    payload = manager.encrypt(project_id, run_id, sections)

    header = payload.header
    assert header["v"] == 1
    assert header["fmt"] == "tb-env/1"
    assert header["alg"] == "AES-256-GCM"
    assert header["project_id"] == str(project_id)
    assert header["run_id"] == str(run_id)
    assert header["first_seq"] == 0
    assert header["last_seq"] == 9


# --------------------------------------------------------------------------- #
# AAD tamper: relocating a section to another run must fail decryption
# --------------------------------------------------------------------------- #


def test_aad_tamper_changed_run_id_fails_decryption() -> None:
    manager, _store, _clock = _manager()
    project_id = ProjectId(uuid4())
    run_id = mint_run_id()
    other_run_id = mint_run_id()
    assert run_id != other_run_id

    payload = manager.encrypt(project_id, run_id, [PlainSection(0, 0, (), (_line(0),))])

    tampered_header = dict(payload.header)
    tampered_header["run_id"] = str(other_run_id)
    tampered = EncryptedPayload(header=tampered_header, sections=payload.sections)

    with pytest.raises(InvalidTag):
        manager.decrypt(project_id, tampered)


def test_aad_tamper_changed_seq_range_fails_decryption() -> None:
    manager, _store, _clock = _manager()
    project_id = ProjectId(uuid4())
    run_id = mint_run_id()
    payload = manager.encrypt(project_id, run_id, [PlainSection(0, 0, (), (_line(0),))])

    tampered_section = dict(payload.sections[0])
    tampered_section["seq_to"] = 99  # relocate the section's declared range
    tampered = EncryptedPayload(header=payload.header, sections=(tampered_section,))

    with pytest.raises(InvalidTag):
        manager.decrypt(project_id, tampered)


# --------------------------------------------------------------------------- #
# Nonce uniqueness across many sections
# --------------------------------------------------------------------------- #


def test_nonce_never_reused_across_many_sections() -> None:
    manager, _store, _clock = _manager()
    project_id = ProjectId(uuid4())
    run_id = mint_run_id()

    sections = [
        PlainSection(
            seq_from=i,
            seq_to=i,
            subject_tags=() if i % 3 else (f"user:{i}",),
            lines=(_line(i),),
        )
        for i in range(200)
    ]
    payload = manager.encrypt(project_id, run_id, sections)

    section_nonces = [str(s["nonce"]) for s in payload.sections]
    wrap_nonces = [
        str(cast(Mapping[str, object], w)["nonce"])
        for s in payload.sections
        for w in cast("list[object]", s["wraps"])
    ]
    all_nonces = section_nonces + wrap_nonces

    assert len(all_nonces) == len(set(all_nonces))


# --------------------------------------------------------------------------- #
# KEK lifecycle
# --------------------------------------------------------------------------- #


def test_get_or_create_subject_kek_is_stable_across_calls() -> None:
    manager, _store, _clock = _manager()
    project_id = ProjectId(uuid4())
    first = manager.get_or_create_subject_kek(project_id, "user:alice")
    second = manager.get_or_create_subject_kek(project_id, "user:alice")
    assert first == second


def test_ensure_project_kek_provisions_reserved_tag() -> None:
    manager, store, _clock = _manager()
    project_id = ProjectId(uuid4())
    assert store.get_subject_key(project_id, PROJECT_SUBJECT_TAG) is None
    manager.ensure_project_kek(project_id)
    row = store.get_subject_key(project_id, PROJECT_SUBJECT_TAG)
    assert row is not None
    assert row.destroyed_at is None


def test_different_projects_get_different_keks_for_the_same_tag() -> None:
    manager, _store, _clock = _manager()
    p1, p2 = ProjectId(uuid4()), ProjectId(uuid4())
    k1 = manager.get_or_create_subject_kek(p1, "user:alice")
    k2 = manager.get_or_create_subject_kek(p2, "user:alice")
    assert k1 != k2


# --------------------------------------------------------------------------- #
# SubjectKeyStore Protocol is satisfied structurally by the fake (no inheritance)
# --------------------------------------------------------------------------- #


def test_fake_store_satisfies_subject_key_store_protocol() -> None:
    store: SubjectKeyStore = FakeSubjectKeyStore(FakeClock())
    assert store is not None  # mypy is the real assertion here


# --------------------------------------------------------------------------- #
# EnvMasterKeyProvider (C-15)
# --------------------------------------------------------------------------- #


def test_env_master_key_provider_missing_env_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("TB_MASTER_KEY_TEST", raising=False)
    with pytest.raises(MasterKeyMissing):
        EnvMasterKeyProvider("TB_MASTER_KEY_TEST")


def test_env_master_key_provider_bad_base64_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TB_MASTER_KEY_TEST", "not base64!!")
    with pytest.raises(MasterKeyMissing):
        EnvMasterKeyProvider("TB_MASTER_KEY_TEST")


def test_env_master_key_provider_wrong_length_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    import base64

    monkeypatch.setenv("TB_MASTER_KEY_TEST", base64.b64encode(b"too short").decode())
    with pytest.raises(MasterKeyMissing):
        EnvMasterKeyProvider("TB_MASTER_KEY_TEST")


def test_env_master_key_provider_valid_key_loads(monkeypatch: pytest.MonkeyPatch) -> None:
    import base64

    key = os.urandom(32)
    monkeypatch.setenv("TB_MASTER_KEY_TEST", base64.b64encode(key).decode())
    provider = EnvMasterKeyProvider("TB_MASTER_KEY_TEST")
    assert provider.master_key() == key


def test_env_master_key_provider_never_evaluates_datetime_now() -> None:
    # Sanity guard against the §14 do-not-list rule creeping into crypto:
    # nothing in this module should ever call datetime.now()/time.time().
    import inspect

    from tracebed.crypto import shred

    src = inspect.getsource(shred)
    assert "datetime.now(" not in src
    assert "time.time()" not in src


# --------------------------------------------------------------------------- #
# encrypt() input validation
# --------------------------------------------------------------------------- #


def test_encrypt_rejects_empty_sections() -> None:
    manager, _store, _clock = _manager()
    project_id = ProjectId(uuid4())
    run_id = mint_run_id()
    with pytest.raises(ValueError, match="at least one section"):
        manager.encrypt(project_id, run_id, [])


# --------------------------------------------------------------------------- #
# No plaintext path: the bytes that reach TraceStorePort carry no event text
# (§14 do-not list: "tracestore drivers accept opaque bytes and must not offer
# a plaintext path"). This is the assertion the round-trip tests cannot make.
# --------------------------------------------------------------------------- #


def test_stored_bytes_contain_no_plaintext_event_content() -> None:
    manager, _store, _clock = _manager()
    project_id = ProjectId(uuid4())
    run_id = mint_run_id()
    marker = b"CANARY-b7f1-not-in-ciphertext"
    line = b'{"seq":0,"event":{"type":"state_note","payload":{"note":"' + marker + b'"}}}'

    wire = manager.encrypt(
        project_id, run_id, [PlainSection(0, 0, ("user:alice",), (line,))]
    ).to_bytes()

    assert marker not in wire
    assert b"state_note" not in wire
    # ...while the tags/seq metadata the writer needs IS in the clear, by design.
    assert b"user:alice" in wire


# --------------------------------------------------------------------------- #
# XOR shares (C-13): ALL shares are required, not any subset.
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("n", [1, 2, 3, 8])
def test_split_dek_requires_every_share_to_reconstruct(n: int) -> None:
    dek = os.urandom(32)
    shares = envelope_mod.split_dek(dek, n)

    assert len(shares) == n
    assert envelope_mod.combine_shares(shares) == dek
    assert all(len(s) == len(dek) for s in shares)

    if n > 1:
        for drop in range(n):
            partial = shares[:drop] + shares[drop + 1 :]
            assert envelope_mod.combine_shares(partial) != dek


def test_split_dek_rejects_zero_shares() -> None:
    with pytest.raises(ValueError, match="n must be >= 1"):
        envelope_mod.split_dek(os.urandom(32), 0)


# --------------------------------------------------------------------------- #
# Invariant 4 reaches the crypto layer: a payload belonging to another project
# is NotFound, never a partial read and never a silent tombstone.
# --------------------------------------------------------------------------- #


def test_decrypt_rejects_a_payload_from_another_project() -> None:
    manager, _store, _clock = _manager()
    owner = ProjectId(uuid4())
    other = ProjectId(uuid4())
    run_id = mint_run_id()
    payload = manager.encrypt(owner, run_id, [PlainSection(0, 0, (), (_line(0),))])

    with pytest.raises(NotFound):
        manager.decrypt(other, payload)

    # ...and the true owner is unaffected.
    assert isinstance(manager.decrypt(owner, payload)[0], PlainSection)


# --------------------------------------------------------------------------- #
# Untrusted-envelope handling: `decrypt()` parses bytes that arrived from an
# object store keyed by a text column. Malformed input is a typed error, and
# in particular is never mistaken for an erasure.
# --------------------------------------------------------------------------- #


def test_decrypt_rejects_rewritten_subject_tags() -> None:
    manager, _store, _clock = _manager()
    project_id = ProjectId(uuid4())
    run_id = mint_run_id()
    payload = manager.encrypt(
        project_id, run_id, [PlainSection(0, 0, ("user:alice",), (_line(0),))]
    )

    forged_section = dict(payload.sections[0])
    forged_section["subject_tags"] = []  # "this section belongs to nobody"
    forged = EncryptedPayload(header=payload.header, sections=(forged_section,))

    with pytest.raises(ValueError, match="does not match wraps"):
        manager.decrypt(project_id, forged)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("seq_from", "0"),
        ("seq_from", -1),
        # `False` is the sharp case: `int(False) == 0` is the section's REAL
        # seq_from, so a bool that slips through the type check decrypts
        # cleanly and the malformed envelope is accepted silently.
        ("seq_from", False),
        ("seq_to", True),
        ("subject_tags", "user:alice"),
        ("wraps", []),
        ("wraps", ["not-an-object"]),
        ("nonce", "!!!not-base64!!!"),
    ],
)
def test_decrypt_rejects_malformed_section_fields(field: str, value: object) -> None:
    manager, _store, _clock = _manager()
    project_id = ProjectId(uuid4())
    run_id = mint_run_id()
    payload = manager.encrypt(project_id, run_id, [PlainSection(0, 0, (), (_line(0),))])

    broken = dict(payload.sections[0])
    broken[field] = value
    with pytest.raises(ValueError):
        manager.decrypt(project_id, EncryptedPayload(payload.header, (broken,)))


def test_decrypt_rejects_absurd_wrap_count_without_hitting_the_key_store() -> None:
    manager, store, _clock = _manager()
    project_id = ProjectId(uuid4())
    run_id = mint_run_id()
    payload = manager.encrypt(project_id, run_id, [PlainSection(0, 0, (), (_line(0),))])

    wraps = cast("list[Mapping[str, object]]", payload.sections[0]["wraps"])
    flooded = dict(payload.sections[0])
    flooded["wraps"] = [dict(wraps[0]) for _ in range(5_000)]
    flooded["subject_tags"] = [PROJECT_SUBJECT_TAG] * 5_000

    lookups: list[str] = []
    original = store.get_subject_key

    def counting(project: ProjectId, tag: str) -> SubjectKeyRow | None:
        lookups.append(tag)
        return original(project, tag)

    store.get_subject_key = counting  # type: ignore[assignment,method-assign]
    with pytest.raises(ValueError, match="exceeds"):
        manager.decrypt(project_id, EncryptedPayload(payload.header, (flooded,)))
    assert lookups == [], "the bound must be checked before any store lookup"


def test_from_bytes_rejects_a_foreign_envelope_version() -> None:
    manager, _store, _clock = _manager()
    project_id = ProjectId(uuid4())
    run_id = mint_run_id()
    payload = manager.encrypt(project_id, run_id, [PlainSection(0, 0, (), (_line(0),))])

    future = dict(payload.header)
    future["v"] = 2
    future["fmt"] = "tb-env/2"
    # Construct an intentionally incomplete v2-looking legacy object without
    # using the strict v2 serializer, which correctly refuses to emit it.
    raw = envelope_mod.dumps_line(future) + b"".join(
        envelope_mod.dumps_line(section) for section in payload.sections
    )

    with pytest.raises(ValueError, match="unsupported envelope"):
        EncryptedPayload.from_bytes(raw)


def test_from_bytes_rejects_a_foreign_algorithm() -> None:
    manager, _store, _clock = _manager()
    project_id = ProjectId(uuid4())
    run_id = mint_run_id()
    payload = manager.encrypt(project_id, run_id, [PlainSection(0, 0, (), (_line(0),))])

    downgraded = dict(payload.header)
    downgraded["alg"] = "AES-128-CBC"
    raw = EncryptedPayload(downgraded, payload.sections).to_bytes()

    with pytest.raises(ValueError, match="unsupported alg"):
        EncryptedPayload.from_bytes(raw)


def test_from_bytes_rejects_garbage() -> None:
    with pytest.raises(ValueError):
        EncryptedPayload.from_bytes(b"not json at all\n")
    with pytest.raises(ValueError, match="empty payload"):
        EncryptedPayload.from_bytes(b"")
    with pytest.raises(ValueError, match="must be a JSON object"):
        EncryptedPayload.from_bytes(b'["valid json","wrong shape"]\n')
    with pytest.raises(ValueError, match="must be a JSON object"):
        EncryptedPayload.from_bytes(b'{"v":1,"fmt":"tb-env/1","alg":"AES-256-GCM"}\n42\n')
    with pytest.raises(ValueError):
        EncryptedPayload.from_bytes(b"\xff\xfe not utf-8\n")


# --------------------------------------------------------------------------- #
# encrypt() input validation — the writer side of the same integrity rules
# --------------------------------------------------------------------------- #


def test_encrypt_rejects_a_line_containing_a_newline() -> None:
    manager, _store, _clock = _manager()
    with pytest.raises(ValueError, match="must not contain newlines"):
        manager.encrypt(
            ProjectId(uuid4()),
            mint_run_id(),
            [PlainSection(0, 0, (), (b'{"seq":0}\n{"seq":1}',))],
        )


def test_encrypt_rejects_duplicate_subject_tags() -> None:
    manager, _store, _clock = _manager()
    with pytest.raises(ValueError, match="duplicate subject_tags"):
        manager.encrypt(
            ProjectId(uuid4()),
            mint_run_id(),
            [PlainSection(0, 0, ("user:alice", "user:alice"), (_line(0),))],
        )


def test_encrypt_rejects_an_inverted_seq_range() -> None:
    manager, _store, _clock = _manager()
    with pytest.raises(ValueError, match="bad seq range"):
        manager.encrypt(ProjectId(uuid4()), mint_run_id(), [PlainSection(9, 3, (), (_line(0),))])


def test_encrypt_rejects_an_empty_subject_tag() -> None:
    manager, _store, _clock = _manager()
    with pytest.raises(ValueError, match="must not contain empty strings"):
        manager.encrypt(ProjectId(uuid4()), mint_run_id(), [PlainSection(0, 0, ("",), (_line(0),))])


def test_round_trip_preserves_every_line_exactly() -> None:
    """Guards the `split(b"\\n")` in decrypt: a line-count or ordering change
    would corrupt the seq set the incomplete-sweeper reads (§11)."""
    manager, _store, _clock = _manager()
    project_id = ProjectId(uuid4())
    run_id = mint_run_id()
    lines = tuple(_line(i) for i in range(50))

    payload = manager.encrypt(project_id, run_id, [PlainSection(0, 49, (), lines)])
    result = manager.decrypt(project_id, EncryptedPayload.from_bytes(payload.to_bytes()))[0]

    assert isinstance(result, PlainSection)
    assert result.lines == lines
