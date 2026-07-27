"""TraceStorePort proving tests (PHASE0-CONTRACT.md §13.2, PHASE-0 Task 11).

fs round-trip runs offline unconditionally. sigv4 is tested offline against
the AWS-published test suite (`awslabs/aws-c-auth`,
`tests/aws-signing-test-suite/v4/`) — fixed credentials/timestamp, so the
expected canonical requests/signatures below are copied verbatim from that
suite, not computed by the code under test. The S3 round-trip is
`@pytest.mark.integration` and skips cleanly when no S3-compatible endpoint
is configured (§12's offline-first rule) via a fixture local to this file —
`tests/phase0/conftest.py` is owned by the `harness` chunk and may not exist
yet in a parallel Phase 0 build (contract_gap: see this chunk's build
report).
"""

from __future__ import annotations

import os
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import httpx
import pytest

from tracebed.domain.config import TraceStoreConfig
from tracebed.domain.errors import ConfigError, NotFound
from tracebed.domain.ids import ProjectId, mint_run_id
from tracebed.stores.tracestore import PayloadRef, TraceStorePort
from tracebed.stores.tracestore.base import MAX_KEY_LEN, is_safe_key
from tracebed.stores.tracestore.fs import FsTraceStore
from tracebed.stores.tracestore.sigv4 import (
    SigV4Signer,
    build_canonical_request,
    canonical_query_string,
    sha256_hex,
)

pytestmark = pytest.mark.phase0


# --------------------------------------------------------------------------- #
# PayloadRef
# --------------------------------------------------------------------------- #


def test_payload_ref_str_and_parse_round_trip_fs() -> None:
    ref = PayloadRef(driver="fs", key="p1/r1/00000000.tbz")
    assert str(ref) == "fs://p1/r1/00000000.tbz"
    assert PayloadRef.parse(str(ref)) == ref


def test_payload_ref_str_and_parse_round_trip_s3() -> None:
    ref = PayloadRef(driver="s3", key="my-bucket/tb/p1/r1/00000000")
    assert str(ref) == "s3://my-bucket/tb/p1/r1/00000000"
    assert PayloadRef.parse(str(ref)) == ref


def test_payload_ref_parse_rejects_unknown_scheme() -> None:
    with pytest.raises(ValueError, match="unrecognised ref"):
        PayloadRef.parse("gs://bucket/key")


# --------------------------------------------------------------------------- #
# fs driver — offline, unconditional
# --------------------------------------------------------------------------- #


def test_fs_put_get_round_trip(tmp_path: Path) -> None:
    store: TraceStorePort = FsTraceStore(tmp_path)
    project_id = ProjectId(uuid4())
    run_id = mint_run_id()
    payload = b"some encrypted envelope bytes"

    ref = store.put(project_id, run_id, 0, payload)
    assert store.get(project_id, ref) == payload
    assert store.exists(project_id, ref) is True


def test_fs_key_embeds_project_id_and_layout(tmp_path: Path) -> None:
    store = FsTraceStore(tmp_path)
    project_id = ProjectId(uuid4())
    run_id = mint_run_id()

    ref = store.put(project_id, run_id, 7, b"x")
    assert ref.driver == "fs"
    assert ref.key == f"{project_id}/{run_id}/00000007.tbz"
    assert (tmp_path / str(project_id) / str(run_id) / "00000007.tbz").is_file()


def test_fs_get_missing_object_raises_not_found(tmp_path: Path) -> None:
    store = FsTraceStore(tmp_path)
    project_id = ProjectId(uuid4())
    ref = PayloadRef(driver="fs", key=f"{project_id}/{uuid4()}/00000000.tbz")
    with pytest.raises(NotFound):
        store.get(project_id, ref)


def test_fs_exists_false_for_missing_object(tmp_path: Path) -> None:
    store = FsTraceStore(tmp_path)
    project_id = ProjectId(uuid4())
    ref = PayloadRef(driver="fs", key=f"{project_id}/{uuid4()}/00000000.tbz")
    assert store.exists(project_id, ref) is False


def test_fs_cross_project_ref_rejected(tmp_path: Path) -> None:
    store = FsTraceStore(tmp_path)
    owner_project = ProjectId(uuid4())
    other_project = ProjectId(uuid4())
    run_id = mint_run_id()

    ref = store.put(owner_project, run_id, 0, b"secret bytes")

    # A caller authenticated as `other_project` presenting `owner_project`'s
    # ref must 404 -- this is the leak-suite's by-id cross-project probe
    # (invariant 4) applied to the trace store.
    with pytest.raises(NotFound):
        store.get(other_project, ref)
    assert store.exists(other_project, ref) is False

    # the true owner can still read it
    assert store.get(owner_project, ref) == b"secret bytes"


def test_fs_cross_project_ref_rejected_without_creating_any_file(tmp_path: Path) -> None:
    store = FsTraceStore(tmp_path)
    owner_project = ProjectId(uuid4())
    other_project = ProjectId(uuid4())
    ref = PayloadRef(driver="fs", key=f"{owner_project}/{uuid4()}/00000000.tbz")

    with pytest.raises(NotFound):
        store.get(other_project, ref)

    # nothing under tmp_path was touched by the rejected read
    assert list(tmp_path.rglob("*")) == []


def test_fs_path_traversal_in_ref_key_rejected(tmp_path: Path) -> None:
    store = FsTraceStore(tmp_path)
    project_id = ProjectId(uuid4())
    outside = tmp_path.parent / "escaped.txt"
    ref = PayloadRef(driver="fs", key=f"{project_id}/../../{outside.name}")

    with pytest.raises(NotFound):
        store.get(project_id, ref)


def test_fs_delete_project_removes_only_that_projects_objects(tmp_path: Path) -> None:
    store = FsTraceStore(tmp_path)
    p1, p2 = ProjectId(uuid4()), ProjectId(uuid4())
    run_id = mint_run_id()

    ref1 = store.put(p1, run_id, 0, b"a")
    store.put(p1, mint_run_id(), 5, b"b")
    ref2 = store.put(p2, run_id, 0, b"c")

    removed = store.delete_project(p1)
    assert removed == 2
    assert store.exists(p2, ref2) is True
    assert store.get(p2, ref2) == b"c"
    with pytest.raises(NotFound):
        store.get(p1, ref1)


def test_fs_delete_project_on_never_seen_project_is_a_noop(tmp_path: Path) -> None:
    store = FsTraceStore(tmp_path)
    assert store.delete_project(ProjectId(uuid4())) == 0


def test_fs_delete_project_leaves_no_remnant_of_any_kind(tmp_path: Path) -> None:
    """Erasure means the project's directory is gone, not "the `.tbz` files are
    gone" — a `.tmp` from an interrupted put() is the same trace bytes, and a
    project directory that survives deletion is a finding in any audit."""
    store = FsTraceStore(tmp_path)
    project_id = ProjectId(uuid4())
    run_id = mint_run_id()
    store.put(project_id, run_id, 0, b"a")
    stray = tmp_path / str(project_id) / str(run_id) / "00000005.tbz.9999.tmp"
    stray.write_bytes(b"half an envelope")

    assert store.delete_project(project_id) == 1  # counts objects, not remnants
    assert not (tmp_path / str(project_id)).exists()
    assert list(tmp_path.rglob("*.tmp")) == []


def test_fs_get_on_a_directory_key_is_not_found_not_an_os_error(tmp_path: Path) -> None:
    """`read_bytes()` on a directory raises `IsADirectoryError` on POSIX and
    `PermissionError` on Windows. Either escaping the driver is a 500 with a
    platform-dependent shape where the contract promises a uniform `NotFound`."""
    store = FsTraceStore(tmp_path)
    project_id = ProjectId(uuid4())
    run_id = mint_run_id()
    store.put(project_id, run_id, 0, b"a")

    directory_ref = PayloadRef(driver="fs", key=f"{project_id}/{run_id}")
    with pytest.raises(NotFound):
        store.get(project_id, directory_ref)
    assert store.exists(project_id, directory_ref) is False


# --------------------------------------------------------------------------- #
# sigv4 — offline against the AWS-published test suite
# (awslabs/aws-c-auth: tests/aws-signing-test-suite/v4/*)
# --------------------------------------------------------------------------- #

_ACCESS_KEY = "AKIDEXAMPLE"
_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
_TIMESTAMP = datetime(2015, 8, 30, 12, 36, 0, tzinfo=UTC)
_EMPTY_PAYLOAD_HASH = sha256_hex(b"")


def test_sigv4_get_vanilla_matches_aws_test_vector() -> None:
    """`v4/get-vanilla`: GET /, no query, no body, host+x-amz-date only."""
    signer = SigV4Signer(_ACCESS_KEY, _SECRET_KEY, "us-east-1", service="service")
    result = signer.sign(
        method="GET",
        path="/",
        query={},
        headers={"host": "example.amazonaws.com"},
        payload_hash=_EMPTY_PAYLOAD_HASH,
        now=_TIMESTAMP,
        include_content_sha256=False,
    )
    assert result["x-amz-date"] == "20150830T123600Z"
    assert (
        result["Authorization"]
        == "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, "
        "SignedHeaders=host;x-amz-date, "
        "Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
    )


def test_sigv4_get_vanilla_canonical_request_matches_aws_test_vector() -> None:
    creq = build_canonical_request(
        method="GET",
        path="/",
        query={},
        headers={"host": "example.amazonaws.com", "x-amz-date": "20150830T123600Z"},
        payload_hash=_EMPTY_PAYLOAD_HASH,
    )
    expected = (
        "GET\n/\n\nhost:example.amazonaws.com\nx-amz-date:20150830T123600Z\n\n"
        "host;x-amz-date\n"
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )
    assert creq == expected


def test_sigv4_query_order_and_case_matches_aws_test_vector() -> None:
    """`v4/get-vanilla-query-order-key-case`: query params sorted by key."""
    assert canonical_query_string({"Param2": "value2", "Param1": "value1"}) == "Param1=value1&Param2=value2"

    signer = SigV4Signer(_ACCESS_KEY, _SECRET_KEY, "us-east-1", service="service")
    result = signer.sign(
        method="GET",
        path="/",
        query={"Param2": "value2", "Param1": "value1"},
        headers={"host": "example.amazonaws.com"},
        payload_hash=_EMPTY_PAYLOAD_HASH,
        now=_TIMESTAMP,
        include_content_sha256=False,
    )
    assert result["Authorization"].endswith(
        "Signature=b97d918cfa904a5beff61c982a1b6f458b799221646efd99d3219ec94cdf2500"
    )


def test_sigv4_post_with_body_matches_aws_test_vector() -> None:
    """`v4/post-x-www-form-urlencoded-parameters`: signed body + extra headers."""
    body = b"Param1=value1"
    payload_hash = sha256_hex(body)
    assert payload_hash == "9095672bbd1f56dfc5b65f3e153adc8731a4a654192329106275f4c7b24d0b6e"

    signer = SigV4Signer(_ACCESS_KEY, _SECRET_KEY, "us-east-1", service="service")
    result = signer.sign(
        method="POST",
        path="/",
        query={},
        headers={
            "host": "example.amazonaws.com",
            "content-type": "application/x-www-form-urlencoded; charset=utf-8",
            "content-length": "13",
        },
        payload_hash=payload_hash,
        now=_TIMESTAMP,
    )
    assert result["Authorization"].endswith(
        "Signature=328d1b9eaadca9f5818ef05e8392801e091653bafec24fcab71e7344e7f51422"
    )


def test_sigv4_uri_encoding_preserves_slashes_in_path() -> None:
    from tracebed.stores.tracestore.sigv4 import canonical_uri

    assert canonical_uri("/bucket/tb/proj id/run/00000000") == "/bucket/tb/proj%20id/run/00000000"
    assert canonical_uri("") == "/"


# --------------------------------------------------------------------------- #
# S3 driver — construction-time config validation (offline, no network)
# --------------------------------------------------------------------------- #


def test_s3_store_requires_bucket() -> None:
    from tracebed.stores.tracestore.s3 import S3TraceStore

    cfg = TraceStoreConfig(driver="s3", endpoint="http://localhost:8333", bucket=None)
    with pytest.raises(ConfigError, match="bucket"):
        S3TraceStore(cfg)


def test_s3_store_requires_credentials_env(monkeypatch: pytest.MonkeyPatch) -> None:
    from tracebed.stores.tracestore.s3 import S3TraceStore

    monkeypatch.delenv("TB_S3_ACCESS_KEY", raising=False)
    monkeypatch.delenv("TB_S3_SECRET_KEY", raising=False)
    cfg = TraceStoreConfig(driver="s3", endpoint="http://localhost:8333", bucket="tracebed-test")
    with pytest.raises(ConfigError, match="TB_S3_ACCESS_KEY"):
        S3TraceStore(cfg)


# --------------------------------------------------------------------------- #
# S3 driver — round-trip, integration only, skips cleanly when unconfigured
# --------------------------------------------------------------------------- #


@pytest.fixture
def s3_endpoint_config() -> TraceStoreConfig:
    """Local-to-this-file skip fixture (not the shared §13.1 `conftest.py`,
    which is owned by the `harness` chunk and may not exist yet in a
    parallel Phase 0 build — contract_gap, see this chunk's build report).
    Skips whenever `TB_S3_ENDPOINT`/`TB_S3_BUCKET`/credentials are unset."""
    endpoint = os.environ.get("TB_S3_ENDPOINT")
    bucket = os.environ.get("TB_S3_BUCKET")
    if not endpoint or not bucket:
        pytest.skip("TB_S3_ENDPOINT / TB_S3_BUCKET not set - no S3-compatible endpoint available")
    if not os.environ.get("TB_S3_ACCESS_KEY") or not os.environ.get("TB_S3_SECRET_KEY"):
        pytest.skip("TB_S3_ACCESS_KEY / TB_S3_SECRET_KEY not set")
    return TraceStoreConfig(driver="s3", endpoint=endpoint, bucket=bucket)


@pytest.mark.integration
def test_s3_round_trip(s3_endpoint_config: TraceStoreConfig) -> None:
    from tracebed.stores.tracestore.s3 import S3TraceStore

    store: TraceStorePort = S3TraceStore(s3_endpoint_config)
    project_id = ProjectId(uuid4())
    run_id = mint_run_id()
    payload = b"integration round-trip payload"

    ref = store.put(project_id, run_id, 0, payload)
    assert store.get(project_id, ref) == payload
    assert store.exists(project_id, ref) is True

    removed = store.delete_project(project_id)
    assert removed >= 1
    assert store.exists(project_id, ref) is False


def test_s3_cross_project_ref_rejected_before_network_call(monkeypatch: pytest.MonkeyPatch) -> None:
    """Offline, unconditional: a TEST-NET-1 (RFC 5737) unroutable endpoint
    proves the prefix check short-circuits BEFORE any connection attempt --
    if it did not, this would hang/error on the connection instead of
    raising `NotFound` immediately."""
    from tracebed.stores.tracestore.s3 import S3TraceStore

    monkeypatch.setenv("TB_S3_ACCESS_KEY", "unused")
    monkeypatch.setenv("TB_S3_SECRET_KEY", "unused")
    cfg = TraceStoreConfig(driver="s3", endpoint="http://192.0.2.1:1", bucket="tracebed-test")
    store = S3TraceStore(cfg)

    owner_project = ProjectId(uuid4())
    other_project = ProjectId(uuid4())
    ref = PayloadRef(driver="s3", key=f"tracebed-test/tb/{owner_project}/{uuid4()}/00000000")

    with pytest.raises(NotFound):
        store.get(other_project, ref)


# --------------------------------------------------------------------------- #
# Cross-project traversal: the leak a bare prefix comparison does NOT catch.
#
# `PayloadRef.key` reaches a driver from `trace_index.payload_ref`, a text
# column. "{mine}/../{yours}/..." starts with MY project prefix and yet lands
# in another tenant's data once `Path.resolve()` (fs) or httpx's RFC 3986
# dot-segment removal (s3) collapses it. Invariant 4, leak probe (b).
# --------------------------------------------------------------------------- #


def test_fs_cross_project_traversal_ref_is_rejected(tmp_path: Path) -> None:
    store = FsTraceStore(tmp_path)
    mine, yours = ProjectId(uuid4()), ProjectId(uuid4())
    run_id = mint_run_id()

    victim = store.put(yours, run_id, 0, b"PROJECT B SECRET")
    traversal = PayloadRef(driver="fs", key=f"{mine}/../{victim.key}")

    assert traversal.key.startswith(f"{mine}/"), "the ref does pass a naive prefix check"
    with pytest.raises(NotFound):
        store.get(mine, traversal)
    assert store.exists(mine, traversal) is False


@pytest.mark.parametrize(
    "suffix",
    [
        "../{victim}",
        "./{victim}",
        "..\\{victim}",  # Windows separator: Path honours it, startswith() does not
        "/{victim}",
    ],
)
def test_fs_rejects_every_relative_segment_form(tmp_path: Path, suffix: str) -> None:
    store = FsTraceStore(tmp_path)
    mine, yours = ProjectId(uuid4()), ProjectId(uuid4())
    victim = store.put(yours, mint_run_id(), 0, b"PROJECT B SECRET")

    ref = PayloadRef(driver="fs", key=f"{mine}/" + suffix.format(victim=victim.key))
    with pytest.raises(NotFound):
        store.get(mine, ref)
    assert store.exists(mine, ref) is False


def test_fs_symlinked_run_directory_cannot_escape_the_project(tmp_path: Path) -> None:
    """A symlink planted inside a project (by a co-tenant mount, a restore, a
    backup tool) must not become a read path into another project: containment
    is re-checked after `resolve()`, which follows links."""
    store = FsTraceStore(tmp_path)
    mine, yours = ProjectId(uuid4()), ProjectId(uuid4())
    victim = store.put(yours, mint_run_id(), 0, b"PROJECT B SECRET")

    link = tmp_path / str(mine) / "linked"
    link.parent.mkdir(parents=True, exist_ok=True)
    try:
        link.symlink_to(tmp_path / str(yours), target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation not permitted on this platform/account")

    ref = PayloadRef(driver="fs", key=f"{mine}/linked/{victim.key.split('/', 1)[1]}")
    with pytest.raises(NotFound):
        store.get(mine, ref)
    assert store.exists(mine, ref) is False


def test_fs_rejects_a_ref_belonging_to_the_other_driver(tmp_path: Path) -> None:
    store = FsTraceStore(tmp_path)
    project_id = ProjectId(uuid4())
    run_id = mint_run_id()
    store.put(project_id, run_id, 0, b"payload")

    s3_shaped = PayloadRef(driver="s3", key=f"{project_id}/{run_id}/00000000.tbz")
    with pytest.raises(NotFound):
        store.get(project_id, s3_shaped)
    assert store.exists(project_id, s3_shaped) is False


def test_fs_get_never_raises_a_non_tracebed_error_for_a_hostile_key(tmp_path: Path) -> None:
    """An embedded NUL makes `Path.resolve()` raise `ValueError`; a caller must
    still see the uniform `NotFound`, not a 500 with a stack trace."""
    store = FsTraceStore(tmp_path)
    project_id = ProjectId(uuid4())
    for hostile in (f"{project_id}/\x00/x.tbz", f"{project_id}/" + "a" * 4096):
        with pytest.raises(NotFound):
            store.get(project_id, PayloadRef(driver="fs", key=hostile))


def test_fs_containment_is_a_second_independent_gate(tmp_path: Path) -> None:
    """White-box on purpose. `is_safe_key` rejects `..` before the resolved-path
    containment test is ever reached, so the containment test is unreachable
    through the public API on a filesystem where this account cannot create
    symlinks (see the skipped test above). It is still the wall that holds when
    a link exists, so it is asserted directly rather than left unproven."""
    store = FsTraceStore(tmp_path)
    mine, yours = ProjectId(uuid4()), ProjectId(uuid4())
    victim = store.put(yours, mint_run_id(), 0, b"PROJECT B SECRET")

    escaping = PayloadRef(driver="fs", key=f"{mine}/../{victim.key}")
    assert store._contained_path(mine, escaping) is None
    assert store._contained_path(mine, PayloadRef("fs", f"{mine}/../../etc")) is None

    legitimate = PayloadRef(driver="fs", key=f"{mine}/{mint_run_id()}/00000000.tbz")
    assert store._contained_path(mine, legitimate) is not None


def test_fs_put_leaves_no_partial_object_when_the_write_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A truncated envelope decrypts as a tombstone, which is indistinguishable
    from a real erasure — so a half-written object must never appear at the
    final key. Simulates a disk-full/crash mid-write."""
    store = FsTraceStore(tmp_path)
    project_id = ProjectId(uuid4())
    run_id = mint_run_id()
    real_write = Path.write_bytes

    def partial_then_fail(self: Path, data: bytes) -> int:
        real_write(self, data[: len(data) // 2])
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(Path, "write_bytes", partial_then_fail)
    with pytest.raises(OSError, match="No space left"):
        store.put(project_id, run_id, 0, b"x" * 1000)
    monkeypatch.undo()

    final = PayloadRef(driver="fs", key=f"{project_id}/{run_id}/00000000.tbz")
    assert store.exists(project_id, final) is False, "a partial object reached the final key"
    with pytest.raises(NotFound):
        store.get(project_id, final)


def test_fs_put_cleans_up_after_itself_on_success(tmp_path: Path) -> None:
    store = FsTraceStore(tmp_path)
    project_id = ProjectId(uuid4())
    ref = store.put(project_id, mint_run_id(), 0, b"x" * 100_000)

    assert store.get(project_id, ref) == b"x" * 100_000
    assert list((tmp_path / str(project_id)).rglob("*.tmp")) == []


def test_s3_cross_project_traversal_ref_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    """Same probe on the s3 driver, offline: the unroutable TEST-NET-1 endpoint
    proves nothing was sent. httpx would have collapsed the `..` in the URL
    path, turning a passing prefix check into a real cross-tenant GET."""
    from tracebed.stores.tracestore.s3 import S3TraceStore

    monkeypatch.setenv("TB_S3_ACCESS_KEY", "unused")
    monkeypatch.setenv("TB_S3_SECRET_KEY", "unused")
    cfg = TraceStoreConfig(driver="s3", endpoint="http://192.0.2.1:1", bucket="tracebed-test")
    store = S3TraceStore(cfg)

    mine, yours = ProjectId(uuid4()), ProjectId(uuid4())
    traversal = PayloadRef(
        driver="s3",
        key=f"tracebed-test/tb/{mine}/../{yours}/{uuid4()}/00000000",
    )

    assert traversal.key.startswith(f"tracebed-test/tb/{mine}/")
    with pytest.raises(NotFound):
        store.get(mine, traversal)
    assert store.exists(mine, traversal) is False


def test_s3_rejects_a_ref_belonging_to_the_other_driver(monkeypatch: pytest.MonkeyPatch) -> None:
    from tracebed.stores.tracestore.s3 import S3TraceStore

    monkeypatch.setenv("TB_S3_ACCESS_KEY", "unused")
    monkeypatch.setenv("TB_S3_SECRET_KEY", "unused")
    cfg = TraceStoreConfig(driver="s3", endpoint="http://192.0.2.1:1", bucket="tracebed-test")
    store = S3TraceStore(cfg)

    project_id = ProjectId(uuid4())
    fs_shaped = PayloadRef(driver="fs", key=f"tracebed-test/tb/{project_id}/r/00000000")
    with pytest.raises(NotFound):
        store.get(project_id, fs_shaped)
    assert store.exists(project_id, fs_shaped) is False


# --------------------------------------------------------------------------- #
# base.is_safe_key — the shared structural test, exercised directly so a
# future driver cannot re-derive a weaker version of it.
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "key",
    [
        "",
        "/abs/key",
        "a/../b",
        "a/./b",
        "a//b",
        "a\\b",
        "a/b\x00c",
        "C:/windows/path",
        "x" * (MAX_KEY_LEN + 1),
    ],
)
def test_is_safe_key_rejects_hostile_shapes(key: str) -> None:
    assert is_safe_key(key) is False


@pytest.mark.parametrize(
    "key",
    [
        "0e2f.../r/00000000.tbz",
        "bucket/tb/proj/run/00000123",
        "a",
    ],
)
def test_is_safe_key_accepts_ordinary_object_keys(key: str) -> None:
    assert is_safe_key(key) is True


# --------------------------------------------------------------------------- #
# S3 query signing: httpx must never build the query string, because its
# encoding (quote_plus: space -> "+") differs from AWS UriEncode ("%20") and
# the request would then carry a different string than the one signed.
# --------------------------------------------------------------------------- #


def test_s3_list_query_uses_aws_encoding_not_httpx_encoding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from tracebed.stores.tracestore.s3 import S3TraceStore

    monkeypatch.setenv("TB_S3_ACCESS_KEY", "unused")
    monkeypatch.setenv("TB_S3_SECRET_KEY", "unused")

    # A continuation token is opaque, server-generated, and NOT restricted to
    # base64 — this one contains the two characters the encoders disagree on
    # (space: AWS "%20" vs httpx/quote_plus "+"; and a literal "+"). If httpx
    # builds the query, the request carries a different byte string than the
    # one the signature covers and the gateway answers 403.
    token = "page two+of/three"
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if request.method == "GET":
            first_page = b"continuation-token" not in request.url.query
            body = '<?xml version="1.0"?><ListBucketResult>'
            if first_page:
                body += f"<NextContinuationToken>{token}</NextContinuationToken>"
            else:
                body += f"<Contents><Key>tb/{project_id}/r/00000000</Key></Contents>"
            return httpx.Response(200, text=body + "</ListBucketResult>")
        return httpx.Response(204)

    project_id = ProjectId(uuid4())
    cfg = TraceStoreConfig(driver="s3", endpoint="http://s3.invalid", bucket="tracebed-test")
    client = httpx.Client(transport=httpx.MockTransport(handler))
    store = S3TraceStore(cfg, http=client)

    assert store.delete_project(project_id) == 1

    first_query = seen[0].url.query.decode()
    assert first_query == canonical_query_string(
        {"list-type": "2", "prefix": f"tb/{project_id}/"}
    ), "the wire query must be byte-identical to the signed canonical query"

    second_query = seen[1].url.query.decode()
    assert second_query == canonical_query_string(
        {"list-type": "2", "prefix": f"tb/{project_id}/", "continuation-token": token}
    )
    assert "%20" in second_query, "a space must be AWS-encoded, not quote_plus'd to '+'"
    assert "+" not in second_query

    delete_request = seen[2]
    assert delete_request.method == "DEL" + "ETE"
    assert delete_request.url.path == f"/tracebed-test/tb/{project_id}/r/00000000"


def test_s3_delete_project_ignores_keys_outside_the_requested_prefix(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A gateway (or a MITM) that echoes another project's keys must not turn
    project deletion into cross-project deletion (invariant 4, write side)."""
    from tracebed.stores.tracestore.s3 import S3TraceStore

    monkeypatch.setenv("TB_S3_ACCESS_KEY", "unused")
    monkeypatch.setenv("TB_S3_SECRET_KEY", "unused")

    mine, yours = ProjectId(uuid4()), ProjectId(uuid4())
    deleted: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            return httpx.Response(
                200,
                text=(
                    '<?xml version="1.0"?><ListBucketResult>'
                    f"<Contents><Key>tb/{mine}/r/00000000</Key></Contents>"
                    f"<Contents><Key>tb/{yours}/r/00000000</Key></Contents>"
                    "</ListBucketResult>"
                ),
            )
        deleted.append(request.url.path)
        return httpx.Response(204)

    cfg = TraceStoreConfig(driver="s3", endpoint="http://s3.invalid", bucket="tracebed-test")
    store = S3TraceStore(cfg, http=httpx.Client(transport=httpx.MockTransport(handler)))

    assert store.delete_project(mine) == 1
    assert deleted == [f"/tracebed-test/tb/{mine}/r/00000000"]
    assert all(str(yours) not in path for path in deleted)


def test_s3_delete_project_stops_on_a_repeating_continuation_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A gateway that keeps returning the same token must not spin forever on
    the erasure path — an unbounded loop here is a DoS on project deletion."""
    from tracebed.stores.tracestore.s3 import S3TraceStore

    monkeypatch.setenv("TB_S3_ACCESS_KEY", "unused")
    monkeypatch.setenv("TB_S3_SECRET_KEY", "unused")

    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            calls["n"] += 1
            return httpx.Response(
                200,
                text=(
                    '<?xml version="1.0"?><ListBucketResult>'
                    "<NextContinuationToken>stuck</NextContinuationToken>"
                    "</ListBucketResult>"
                ),
            )
        return httpx.Response(204)

    cfg = TraceStoreConfig(driver="s3", endpoint="http://s3.invalid", bucket="tracebed-test")
    store = S3TraceStore(cfg, http=httpx.Client(transport=httpx.MockTransport(handler)))

    assert store.delete_project(ProjectId(uuid4())) == 0
    assert calls["n"] == 2, "one page, then one repeat that terminates the loop"


def test_s3_get_collapses_403_and_404_into_one_answer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A gateway denying ListBucket answers 403 for absent keys; if the driver
    forwarded that as a different error, the pair (403, 404) would be an
    existence oracle for keys inside the caller's own prefix."""
    from tracebed.stores.tracestore.s3 import S3TraceStore

    monkeypatch.setenv("TB_S3_ACCESS_KEY", "unused")
    monkeypatch.setenv("TB_S3_SECRET_KEY", "unused")

    project_id = ProjectId(uuid4())
    ref = PayloadRef(driver="s3", key=f"tracebed-test/tb/{project_id}/r/00000000")
    cfg = TraceStoreConfig(driver="s3", endpoint="http://s3.invalid", bucket="tracebed-test")

    for status in (403, 404):

        def handler(_request: httpx.Request, code: int = status) -> httpx.Response:
            return httpx.Response(code)

        store = S3TraceStore(cfg, http=httpx.Client(transport=httpx.MockTransport(handler)))
        with pytest.raises(NotFound):
            store.get(project_id, ref)
        assert store.exists(project_id, ref) is False


def test_s3_put_get_round_trip_against_a_mock_transport(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Offline exercise of the whole signed request path (key layout, ref
    shape, Authorization/x-amz headers) — the integration test only runs where
    a SeaweedFS endpoint exists, and this chunk has none (§12)."""
    from tracebed.stores.tracestore.s3 import S3TraceStore

    monkeypatch.setenv("TB_S3_ACCESS_KEY", "AKIDEXAMPLE")
    monkeypatch.setenv("TB_S3_SECRET_KEY", _SECRET_KEY)

    objects: dict[str, bytes] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["Authorization"].startswith("AWS4-HMAC-SHA256 ")
        assert "x-amz-content-sha256" in request.headers
        assert "x-amz-date" in request.headers
        path = request.url.path
        if request.method == "PUT":
            objects[path] = request.read()
            return httpx.Response(200)
        if request.method in ("GET", "HEAD"):
            if path not in objects:
                return httpx.Response(404)
            return httpx.Response(200, content=objects[path])
        return httpx.Response(405)

    cfg = TraceStoreConfig(driver="s3", endpoint="http://s3.invalid", bucket="tracebed-test")
    store = S3TraceStore(cfg, http=httpx.Client(transport=httpx.MockTransport(handler)))

    project_id = ProjectId(uuid4())
    run_id = mint_run_id()
    ref = store.put(project_id, run_id, 7, b"envelope bytes")

    assert ref.driver == "s3"
    assert ref.key == f"tracebed-test/tb/{project_id}/{run_id}/00000007"
    assert str(ref) == f"s3://tracebed-test/tb/{project_id}/{run_id}/00000007"
    assert store.get(project_id, ref) == b"envelope bytes"
    assert store.exists(project_id, ref) is True

    missing = PayloadRef(driver="s3", key=f"tracebed-test/tb/{project_id}/{uuid4()}/00000000")
    with pytest.raises(NotFound):
        store.get(project_id, missing)
    assert store.exists(project_id, missing) is False


# --------------------------------------------------------------------------- #
# sigv4 mutation guards: the AWS vectors above pin the happy path; these pin
# that the signature actually depends on the things it must depend on.
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "change",
    ["method", "path", "query", "payload", "header", "secret", "region", "service", "time"],
)
def test_sigv4_signature_changes_with_every_signed_input(change: str) -> None:
    base = {
        "method": "GET",
        "path": "/bucket/tb/p/r/00000000",
        "query": {"list-type": "2"},
        "headers": {"host": "s3.example.com"},
        "payload_hash": sha256_hex(b""),
        "now": _TIMESTAMP,
    }
    signer = SigV4Signer(_ACCESS_KEY, _SECRET_KEY, "us-east-1", service="s3")
    reference = signer.sign(**base)["Authorization"]  # type: ignore[arg-type]

    mutated = dict(base)
    mutant = signer
    if change == "method":
        mutated["method"] = "PUT"
    elif change == "path":
        mutated["path"] = "/bucket/tb/OTHER/r/00000000"
    elif change == "query":
        mutated["query"] = {"list-type": "2", "prefix": "tb/"}
    elif change == "payload":
        mutated["payload_hash"] = sha256_hex(b"x")
    elif change == "header":
        mutated["headers"] = {"host": "s3.example.com", "content-length": "5"}
    elif change == "secret":
        mutant = SigV4Signer(_ACCESS_KEY, _SECRET_KEY + "x", "us-east-1", service="s3")
    elif change == "region":
        mutant = SigV4Signer(_ACCESS_KEY, _SECRET_KEY, "eu-west-1", service="s3")
    elif change == "service":
        mutant = SigV4Signer(_ACCESS_KEY, _SECRET_KEY, "us-east-1", service="s3x")
    elif change == "time":
        mutated["now"] = datetime(2015, 8, 30, 12, 36, 1, tzinfo=UTC)

    assert mutant.sign(**mutated)["Authorization"] != reference  # type: ignore[arg-type]
