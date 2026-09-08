"""E1 subject-digest and strict ``tb-env/2`` wire-contract tests."""

from __future__ import annotations

from pathlib import Path
from uuid import UUID

import pytest

from tracebed.crypto import (
    EncryptedPayload,
    PlainSection,
    SubjectKeyManager,
    envelope,
    subject_digest,
)
from tracebed.crypto.subject_digest import (
    PROJECT_SUBJECT_TAG,
    subject_digest_pairs,
    validate_subject_tag,
)
from tracebed.domain.canonical import canonical_json
from tracebed.domain.clock import FakeClock
from tracebed.domain.ids import ProjectId, RunId
from tracebed.domain.subject_tags import (
    PROJECT_SUBJECT_TAG as DOMAIN_PROJECT_SUBJECT_TAG,
)
from tracebed.domain.subject_tags import validate_subject_tag as domain_validate_subject_tag

from .test_crypto_shred import FakeMasterKeyProvider, FakeSubjectKeyStore

pytestmark = pytest.mark.phase0

_PROJECT = ProjectId(UUID("00112233-4455-6677-8899-aabbccddeeff"))
_RUN = RunId(UUID("ffeeddcc-bbaa-9988-7766-554433221100"))


@pytest.mark.parametrize(
    ("tag", "expected"),
    (
        ("alice", "231cb4fd20107668416188e76f6ccdcef632642bd307e9666631b6db25854a0d"),
        ("\u00c5", "fdf31a769aa97fb8ea55a6106a15a04c0353f9de68ebd3aea5665d12302b14cc"),
        ("A\u030a", "9aa42a809c8ad1d3978cfea0aeec1d4dca973a6d2167ed27248ad02dd2fa4224"),
        ("__project__", "93379ae8caf61a9100fd94f19e50222398ecfccdb2fbeab95f9a757e1977f15b"),
    ),
)
def test_subject_digest_golden_vectors(tag: str, expected: str) -> None:
    assert subject_digest(_PROJECT, tag) == bytes.fromhex(expected)


def test_subject_digest_is_project_scoped_and_does_not_normalize_unicode() -> None:
    other_project = ProjectId(UUID("00112233-4455-6677-8899-aabbccddeefe"))
    assert subject_digest(_PROJECT, "\u00c5") != subject_digest(_PROJECT, "A\u030a")
    assert subject_digest(_PROJECT, "alice") != subject_digest(other_project, "alice")


def test_subject_digest_rejects_invalid_input_without_echoing_the_tag() -> None:
    with pytest.raises(TypeError) as type_error:
        subject_digest(_PROJECT, object())  # type: ignore[arg-type]
    assert "object" not in str(type_error.value)

    malformed = "unsafe\ud800tag"
    with pytest.raises(ValueError) as value_error:
        subject_digest(_PROJECT, malformed)
    assert "unsafe" not in str(value_error.value)


@pytest.mark.parametrize(
    "tag",
    ("", "   ", "x\x00y", "x\u0085y", PROJECT_SUBJECT_TAG, "x" * 129, "\u00c5" * 257),
)
def test_subject_tag_ingress_validation_fails_closed(tag: str) -> None:
    with pytest.raises(ValueError):
        validate_subject_tag(tag)


def test_subject_tag_validation_is_domain_owned_and_crypto_keeps_its_compatibility_export() -> None:
    """Retrieval models can validate tags without reaching write-path crypto."""

    assert validate_subject_tag is domain_validate_subject_tag
    assert PROJECT_SUBJECT_TAG == DOMAIN_PROJECT_SUBJECT_TAG
    assert domain_validate_subject_tag("A\u030a") == "A\u030a"
    events_source = (
        Path(__file__).parents[2] / "src" / "tracebed" / "domain" / "events.py"
    ).read_text(encoding="utf-8")
    assert "tracebed.domain.subject_tags import validate_subject_tag" in events_source
    assert "tracebed.crypto.subject_digest" not in events_source


def test_subject_tag_set_is_bytewise_digest_sorted_and_never_normalized() -> None:
    pairs = subject_digest_pairs(_PROJECT, ("bob", "alice", "\u00c5", "A\u030a"))
    assert tuple(digest for digest, _tag in pairs) == tuple(
        sorted(digest for digest, _tag in pairs)
    )
    assert {tag for _digest, tag in pairs} == {"bob", "alice", "\u00c5", "A\u030a"}
    with pytest.raises(ValueError):
        subject_digest_pairs(_PROJECT, ("alice", "alice"))


def _v2_payload() -> EncryptedPayload:
    digest = subject_digest(_PROJECT, "alice")
    header: dict[str, object] = {
        "alg": "AES-256-GCM",
        "first_seq": 7,
        "fmt": "tb-env/2",
        "last_seq": 7,
        "project_id": str(_PROJECT),
        "run_id": str(_RUN),
        "section_count": 1,
        "split": "XOR-ALL/v1",
        "v": 2,
        "wrap_alg": "AES-256-GCM",
    }
    section: dict[str, object] = {
        "ct": "rK1jSYeF6A9DFGOK8MxV1NU1kqiAC+BDwKHCuJqnD9pgoA9J2em35tnmaqAofbuLG9OyqA==",
        "nonce": "oKGio6Slpqeoqaqr",
        "section_index": 0,
        "seq_from": 7,
        "seq_to": 7,
        "subject_digests": [envelope.b64e(digest)],
        "wraps": [
            {
                "digest": envelope.b64e(digest),
                "key_id": "12345678-1234-5678-9abc-def012345678",
                "nonce": "sLGys7S1tre4ubq7",
                "share": "drtoBNZmjkl6RFexT3DTecZi8MjeHcJmuB31A4l6U4AMk75vquVzr78kP698nWR6",
            }
        ],
    }
    return EncryptedPayload(header=header, sections=(section,))


def test_v2_serialization_and_parse_are_single_canonical_wire_spelling() -> None:
    payload = _v2_payload()
    wire = payload.to_bytes()
    assert wire.endswith(b"\n")
    assert b"\r" not in wire

    parsed = EncryptedPayload.from_bytes(wire)
    assert parsed == payload
    assert parsed.to_bytes() == wire
    assert len(wire) == 672
    import hashlib

    assert (
        hashlib.sha256(wire).hexdigest()
        == "9ae6e84cee718cd4d62a5ac463867e7951de8eff71ec473018874ac9538c5639"
    )


@pytest.mark.parametrize(
    "mutate",
    (
        lambda wire: wire.replace(b'"v":2', b'"v":2,"v":2', 1),
        lambda wire: b"\xef\xbb\xbf" + wire,
        lambda wire: wire.replace(b"\n", b"\r\n"),
        lambda wire: wire.replace(b"\n", b"\n\n", 1),
        lambda wire: wire.replace(b'"fmt":"tb-env/2"', b'"fmt":"tb-env/2" ', 1),
        lambda wire: wire[:-1],
    ),
)
def test_v2_parser_rejects_noncanonical_or_ambiguous_jsonl(mutate: object) -> None:
    wire = _v2_payload().to_bytes()
    with pytest.raises(ValueError):
        EncryptedPayload.from_bytes(mutate(wire))  # type: ignore[operator]


def test_v2_parser_rejects_raw_subject_tag_shadow() -> None:
    payload = _v2_payload()
    section = dict(payload.sections[0])
    section["subject_tags"] = ["sensitive-subject"]
    with pytest.raises(ValueError) as error:
        EncryptedPayload(payload.header, (section,)).to_bytes()
    assert "sensitive-subject" not in str(error.value)


def test_v2_aad_is_length_framed_and_exact() -> None:
    digest = subject_digest(_PROJECT, "alice")
    aad = envelope.build_v2_section_aad(_PROJECT, _RUN, 0, 7, 7, (digest,))
    expected = (
        b"tracebed.section-aad/v2\0"
        + _PROJECT.value.bytes
        + _RUN.value.bytes
        + (0).to_bytes(4, "big")
        + (7).to_bytes(8, "big")
        + (7).to_bytes(8, "big")
        + (1).to_bytes(2, "big")
        + digest
    )
    assert aad == expected
    assert aad.hex() == (
        "74726163656265642e73656374696f6e2d6161642f763200"
        "00112233445566778899aabbccddeeff"
        "ffeeddccbbaa99887766554433221100"
        "00000000000000000000000700000000000000070001"
        "231cb4fd20107668416188e76f6ccdcef632642bd307e9666631b6db25854a0d"
    )
    key_id = UUID("12345678-1234-5678-9abc-def012345678")
    share_aad = envelope.build_v2_share_aad(aad, 0, digest, key_id)
    assert share_aad.hex() == (
        "74726163656265642e73686172652d6161642f763200"
        "40011035b501ae9837d58656e3a0cbda7b41a11c54b8be025be174bb8c3d483b"
        "0000"
        "231cb4fd20107668416188e76f6ccdcef632642bd307e9666631b6db25854a0d"
        "12345678123456789abcdef012345678"
    )
    kek_aad = envelope.build_v2_kek_aad(_PROJECT, digest, key_id)
    assert kek_aad.hex() == (
        "74726163656265642e6b656b2d6161642f763200"
        "00112233445566778899aabbccddeeff"
        "231cb4fd20107668416188e76f6ccdcef632642bd307e9666631b6db25854a0d"
        "12345678123456789abcdef012345678"
    )
    master = bytes(range(0x00, 0x20))
    kek = bytes(range(0x20, 0x40))
    dek = bytes(range(0x40, 0x60))
    plaintext = b'{"event":{"type":"golden"},"seq":7}\n'
    content_ct = envelope.aesgcm_encrypt(
        dek, bytes.fromhex("a0a1a2a3a4a5a6a7a8a9aaab"), plaintext, aad
    )
    assert envelope.b64e(content_ct) == (
        "rK1jSYeF6A9DFGOK8MxV1NU1kqiAC+BDwKHCuJqnD9pgoA9J2em35tnmaqAofbuLG9OyqA=="
    )
    encrypted_share = envelope.aesgcm_encrypt(
        kek,
        bytes.fromhex("b0b1b2b3b4b5b6b7b8b9babb"),
        dek,
        share_aad,
    )
    assert envelope.b64e(encrypted_share) == (
        "drtoBNZmjkl6RFexT3DTecZi8MjeHcJmuB31A4l6U4AMk75vquVzr78kP698nWR6"
    )
    persisted_kek = bytes.fromhex("c0c1c2c3c4c5c6c7c8c9cacb") + envelope.aesgcm_encrypt(
        master,
        bytes.fromhex("c0c1c2c3c4c5c6c7c8c9cacb"),
        kek,
        kek_aad,
    )
    assert envelope.b64e(persisted_kek) == (
        "wMHCw8TFxsfIycrLIGkFRFNdsHmw8NeJHoHGeXxC0QwI1ymNEvpxMQtAQYlXOWlfDT1qgk8Dz/s0nQg9"
    )


def test_existing_runtime_writer_stays_v1_until_the_authority_cutover_is_gated() -> None:
    clock = FakeClock()
    manager = SubjectKeyManager(FakeSubjectKeyStore(clock), FakeMasterKeyProvider(), clock)
    payload = manager.encrypt(_PROJECT, _RUN, [PlainSection(0, 0, (), (b'{"seq":0}',))])
    assert payload.header["fmt"] == "tb-env/1"
    assert payload.header["v"] == 1


def test_explicit_v2_writer_round_trips_without_switching_runtime_emission() -> None:
    clock = FakeClock()
    manager = SubjectKeyManager(FakeSubjectKeyStore(clock), FakeMasterKeyProvider(), clock)
    line = canonical_json({"event": {"type": "golden"}, "seq": 7})
    payload = manager.encrypt_v2(_PROJECT, _RUN, [PlainSection(7, 7, ("alice",), (line,))])
    assert payload.header["fmt"] == "tb-env/2"
    parsed = EncryptedPayload.from_bytes(payload.to_bytes())
    result = manager.decrypt(_PROJECT, parsed)
    assert len(result) == 1
    assert isinstance(result[0], PlainSection)
    assert result[0].lines == (line,)
    assert result[0].subject_tags == ()


def test_v2_writer_persists_only_digest_addressed_v2_key_material() -> None:
    """The E1 primitive must not recreate a raw-tag shadow for tb-env/2."""

    clock = FakeClock()
    store = FakeSubjectKeyStore(clock)
    manager = SubjectKeyManager(store, FakeMasterKeyProvider(), clock)
    line = canonical_json({"event": {"type": "golden"}, "seq": 7})
    manager.encrypt_v2(_PROJECT, _RUN, [PlainSection(7, 7, ("alice",), (line,))])

    digest = subject_digest(_PROJECT, "alice")
    row = store.get_subject_key_by_digest(_PROJECT, digest)
    assert row is not None
    assert row.subject_digest == digest
    assert row.wrap_version == 2
    assert row.subject_tag is None
    assert store.get_subject_key(_PROJECT, "alice") is None


def test_v2_writer_reuses_only_an_already_bound_legacy_key_for_mixed_archives() -> None:
    """A v2 writer never creates v1 rows, but can read an immutable v1 row."""

    clock = FakeClock()
    manager = SubjectKeyManager(FakeSubjectKeyStore(clock), FakeMasterKeyProvider(), clock)
    manager.get_or_create_subject_kek(_PROJECT, "alice")
    line = canonical_json({"event": {"type": "golden"}, "seq": 7})
    payload = manager.encrypt_v2(_PROJECT, _RUN, [PlainSection(7, 7, ("alice",), (line,))])
    assert payload.header["v"] == 2
