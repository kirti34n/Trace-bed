"""Focused destructive-store edge cases that do not require network services."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path
from uuid import uuid4

import pytest

from tracebed.domain.clock import FakeClock
from tracebed.domain.errors import (
    ErasureDependencyTimeout,
    ErasureLeaseLost,
    ErasureOperatorBlocked,
)
from tracebed.stores.graph.erasure import AgeErasureAdapter
from tracebed.stores.tracestore import TraceStorePort
from tracebed.stores.tracestore.erasure import FsTraceEraser
from tracebed.stores.tracestore.s3_erasure import S3TraceEraser
from tracebed.stores.valkey.erasure import ValkeyErasureAdapter
from tracebed.stores.vector.erasure import QdrantErasureAdapter

pytestmark = pytest.mark.phase3


def test_hot_trace_port_has_no_destructive_project_operation() -> None:
    """E3 deletion is intentionally discoverable only through TraceErasurePort."""

    assert not hasattr(TraceStorePort, "delete_project")
    assert not hasattr(TraceStorePort, "erase_project")


def test_fs_erasure_removes_nested_run_tree_and_repeats_idempotently(tmp_path: Path) -> None:
    project_id, run_id = uuid4(), uuid4()
    target = tmp_path / str(project_id) / str(run_id) / "nested"
    target.mkdir(parents=True)
    (target / "payload.bin").write_bytes(b"payload")
    eraser = FsTraceEraser(tmp_path)
    assert eraser.erase_run(project_id, run_id, timeout_seconds=1).result_code == "ok"
    assert not (tmp_path / str(project_id) / str(run_id)).exists()
    assert (
        eraser.verify_run_absent(project_id, run_id, timeout_seconds=1).result_code
        == "already_absent"
    )
    assert eraser.erase_run(project_id, run_id, timeout_seconds=1).result_code == "already_absent"


def test_fs_erasure_blocks_a_symlink_before_following_it(tmp_path: Path) -> None:
    project_id, run_id = uuid4(), uuid4()
    run = tmp_path / str(project_id) / str(run_id)
    run.mkdir(parents=True)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "keep").write_text("keep")
    (run / "escape").symlink_to(outside, target_is_directory=True)
    with pytest.raises(ErasureOperatorBlocked):
        FsTraceEraser(tmp_path).erase_run(project_id, run_id, timeout_seconds=1)
    assert (outside / "keep").read_text() == "keep"


def test_fs_erasure_timeout_is_typed_and_leaves_the_result_unmarkable(tmp_path: Path) -> None:
    project_id, run_id = uuid4(), uuid4()
    ticks = iter((0.0, 0.0, 2.0))
    eraser = FsTraceEraser(tmp_path, monotonic=lambda: next(ticks))
    with pytest.raises(ErasureDependencyTimeout):
        eraser.erase_run(project_id, run_id, timeout_seconds=1)


def test_fs_progress_lease_loss_stops_before_opening_the_target(tmp_path: Path) -> None:
    project_id, run_id = uuid4(), uuid4()

    def lose_lease() -> None:
        raise ErasureLeaseLost()

    with pytest.raises(ErasureLeaseLost):
        FsTraceEraser(tmp_path).erase_run(
            project_id, run_id, timeout_seconds=1, before_page=lose_lease
        )


class _Valkey:
    def __init__(self, pages: list[tuple[int, list[str]]]) -> None:
        self._pages = pages
        self.unlinked: list[str] = []
        self.scans = 0
        self.timeouts: list[float] = []

    def scan(
        self, cursor: int, *, match: str, count: int, timeout_seconds: float
    ) -> tuple[object, object]:
        del cursor, match, count
        self.timeouts.append(timeout_seconds)
        self.scans += 1
        return self._pages.pop(0)

    def unlink(self, *names: str | bytes, timeout_seconds: float) -> object:
        self.timeouts.append(timeout_seconds)
        self.unlinked.extend(str(name) for name in names)
        return len(names)


def test_valkey_eraser_rejects_a_foreign_key_returned_despite_match() -> None:
    project_id = uuid4()
    client = _Valkey([(0, ["tb:{foreign}:leak"])])
    with pytest.raises(ErasureOperatorBlocked):
        ValkeyErasureAdapter(client).erase_project(project_id, timeout_seconds=1)
    assert client.unlinked == []


def test_valkey_eraser_requires_two_complete_empty_verification_scans() -> None:
    project_id = uuid4()
    client = _Valkey([(0, []), (0, []), (0, [])])
    eraser = ValkeyErasureAdapter(client)
    assert eraser.erase_project(project_id, timeout_seconds=1).result_code == "already_absent"
    assert (
        eraser.verify_project_absent(project_id, timeout_seconds=1).result_code == "already_absent"
    )


def test_valkey_page_timeout_is_retryable_and_heartbeat_hook_runs() -> None:
    project_id = uuid4()
    ticks = iter((0.0, 0.0, 2.0))
    pulses: list[str] = []
    eraser = ValkeyErasureAdapter(_Valkey([(0, [])]), monotonic=lambda: next(ticks))
    with pytest.raises(ErasureDependencyTimeout):
        eraser.erase_project(
            project_id, timeout_seconds=1, before_page=lambda: pulses.append("pulse")
        )
    assert pulses


def test_valkey_progress_lease_loss_stops_before_the_next_scan() -> None:
    project_id = uuid4()
    client = _Valkey([(0, [])])

    def lose_lease() -> None:
        raise ErasureLeaseLost()

    with pytest.raises(ErasureLeaseLost):
        ValkeyErasureAdapter(client).erase_project(
            project_id, timeout_seconds=1, before_page=lose_lease
        )
    assert client.scans == 0


def test_valkey_binds_each_scan_to_the_remaining_driver_timeout() -> None:
    project_id = uuid4()

    class _TimedOutValkey(_Valkey):
        def scan(
            self, cursor: int, *, match: str, count: int, timeout_seconds: float
        ) -> tuple[object, object]:
            self.timeouts.append(timeout_seconds)
            raise TimeoutError()

    client = _TimedOutValkey([])
    with pytest.raises(ErasureDependencyTimeout):
        ValkeyErasureAdapter(client).erase_project(project_id, timeout_seconds=0.5)
    assert len(client.timeouts) == 1 and 0 < client.timeouts[0] <= 0.5


class _S3Response:
    def __init__(self, status_code: int, text: str) -> None:
        self.status_code = status_code
        self.text = text


class _S3Http:
    def __init__(self, responses: list[_S3Response]) -> None:
        self._responses = responses

    def request(
        self, method: str, url: str, *, headers: dict[str, str], timeout: float
    ) -> _S3Response:
        del method, url, headers, timeout
        return self._responses.pop(0)


class _S3Store:
    def __init__(self, responses: list[_S3Response]) -> None:
        self._bucket = "tracebed-test"
        self._http = _S3Http(responses)
        self._clock = FakeClock()

    def _signed_headers(
        self, *, method: str, object_key: str, query: dict[str, str]
    ) -> dict[str, str]:
        del method, object_key, query
        return {}

    def _url(self, object_key: str, query: dict[str, str]) -> str:
        del object_key, query
        return "https://store.invalid"


def test_s3_absence_proof_rejects_missing_or_invalid_pagination_boolean() -> None:
    project_id = uuid4()
    # First response is the exact unversioned capability response.  The list
    # reply lacks IsTruncated; treating that as ``false`` would fabricate an
    # empty proof.
    eraser = S3TraceEraser(
        _S3Store(
            [
                _S3Response(200, "<VersioningConfiguration />"),
                _S3Response(200, "<ListBucketResult><Contents /></ListBucketResult>"),
            ]
        )  # type: ignore[arg-type]
    )
    with pytest.raises(ErasureOperatorBlocked):
        eraser.verify_project_absent(project_id, timeout_seconds=1)


def test_s3_absence_proof_rejects_an_error_body_that_mimics_a_list_boolean() -> None:
    project_id = uuid4()
    eraser = S3TraceEraser(
        _S3Store(
            [
                _S3Response(200, "<VersioningConfiguration />"),
                _S3Response(200, "<Error><IsTruncated>false</IsTruncated></Error>"),
            ]
        )  # type: ignore[arg-type]
    )
    with pytest.raises(ErasureOperatorBlocked):
        eraser.verify_project_absent(project_id, timeout_seconds=1)


def test_s3_absence_proof_rejects_pagination_fields_inconsistent_with_not_truncated() -> None:
    project_id = uuid4()
    eraser = S3TraceEraser(
        _S3Store(
            [
                _S3Response(200, "<VersioningConfiguration />"),
                _S3Response(
                    200,
                    "<ListBucketResult><IsTruncated>false</IsTruncated>"
                    "<NextContinuationToken>unexpected</NextContinuationToken></ListBucketResult>",
                ),
            ]
        )  # type: ignore[arg-type]
    )
    with pytest.raises(ErasureOperatorBlocked):
        eraser.verify_project_absent(project_id, timeout_seconds=1)


def test_s3_absence_proof_rejects_malformed_contents_even_when_not_truncated() -> None:
    project_id = uuid4()
    eraser = S3TraceEraser(
        _S3Store(
            [
                _S3Response(200, "<VersioningConfiguration />"),
                _S3Response(
                    200,
                    "<ListBucketResult><IsTruncated>false</IsTruncated><Contents /></ListBucketResult>",
                ),
            ]
        )  # type: ignore[arg-type]
    )
    with pytest.raises(ErasureOperatorBlocked):
        eraser.verify_project_absent(project_id, timeout_seconds=1)


def test_s3_absence_proof_accepts_two_complete_empty_not_truncated_pages() -> None:
    project_id = uuid4()
    eraser = S3TraceEraser(
        _S3Store(
            [
                _S3Response(200, "<VersioningConfiguration />"),
                _S3Response(
                    200, "<ListBucketResult><IsTruncated>false</IsTruncated></ListBucketResult>"
                ),
                _S3Response(
                    200, "<ListBucketResult><IsTruncated>false</IsTruncated></ListBucketResult>"
                ),
            ]
        )  # type: ignore[arg-type]
    )
    assert (
        eraser.verify_project_absent(project_id, timeout_seconds=1).result_code == "already_absent"
    )


@pytest.mark.parametrize("entry_name", ("Version", "DeleteMarker"))
def test_s3_absence_proof_rejects_malformed_version_or_delete_marker_entries(
    entry_name: str,
) -> None:
    project_id = uuid4()
    prefix = f"tb/{project_id}/"
    eraser = S3TraceEraser(
        _S3Store(
            [
                _S3Response(
                    200,
                    "<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>",
                ),
                _S3Response(
                    200,
                    "<ListVersionsResult><IsTruncated>false</IsTruncated>"
                    f"<{entry_name}><Key>{prefix}object</Key></{entry_name}></ListVersionsResult>",
                ),
            ]
        )  # type: ignore[arg-type]
    )
    with pytest.raises(ErasureOperatorBlocked):
        eraser.verify_project_absent(project_id, timeout_seconds=1)


def test_s3_progress_lease_loss_stops_before_the_first_request() -> None:
    project_id = uuid4()
    store = _S3Store([_S3Response(200, "<VersioningConfiguration />")])

    def lose_lease() -> None:
        raise ErasureLeaseLost()

    with pytest.raises(ErasureLeaseLost):
        S3TraceEraser(store).verify_project_absent(
            project_id, timeout_seconds=1, before_page=lose_lease
        )
    assert len(store._http._responses) == 1


def test_s3_deadline_uses_its_configured_store_clock() -> None:
    """The destructive path must not read a second wall-clock source."""

    project_id = uuid4()
    store = _S3Store([_S3Response(200, "<VersioningConfiguration />")])

    def exceed_deadline() -> None:
        store._clock.advance(ms=1001)

    with pytest.raises(ErasureDependencyTimeout):
        S3TraceEraser(store).verify_project_absent(
            project_id, timeout_seconds=1, before_page=exceed_deadline
        )
    assert len(store._http._responses) == 1


def test_s3_prepublication_canary_reuses_and_recovers_its_reserved_namespace(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A failed deployment probe cannot strand a random, untracked prefix."""

    class _CanaryHttp:
        def put(
            self, url: str, *, content: bytes, headers: dict[str, str], timeout: float
        ) -> _S3Response:
            del url, content, headers, timeout
            return _S3Response(200, "")

    class _CanaryStore:
        _bucket = "tracebed-test"
        _http = _CanaryHttp()
        _clock = FakeClock()

        def _signed_headers(self, **_: object) -> dict[str, str]:
            return {}

        def _url(self, *_: object) -> str:
            return "https://store.invalid"

    eraser = S3TraceEraser(_CanaryStore())  # type: ignore[arg-type]
    cleared: list[tuple[object, str, float]] = []

    def clear(project_id: object, prefix: str, timeout_seconds: float) -> None:
        cleared.append((project_id, prefix, timeout_seconds))

    responses = iter(
        (
            _S3Response(403, ""),
            _S3Response(204, ""),
            _S3Response(
                200,
                "<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>",
            ),
        )
    )
    monkeypatch.setattr(eraser, "_clear_deployment_canary", clear)
    monkeypatch.setattr(
        eraser,
        "_request",
        lambda method, key, query, deadline: next(responses),
    )

    with pytest.raises(ErasureOperatorBlocked):
        eraser.prepublication_canary(timeout_seconds=1)
    eraser.prepublication_canary(timeout_seconds=1)

    # failed-start cleanup + retry pre-cleanup + retry final proof all use one
    # reserved prefix, so the retry cannot leave an earlier UUID namespace.
    assert len(cleared) == 4
    assert len({project_id for project_id, _, _ in cleared}) == 1
    assert len({prefix for _, prefix, _ in cleared}) == 1
    assert all(timeout_seconds == 1 for _, _, timeout_seconds in cleared)


class _Qdrant:
    def __init__(self) -> None:
        self.calls: list[tuple[str, tuple[object, ...]]] = []

    def delete_project(self, project_id: object, *, wait: bool, timeout_seconds: float) -> object:
        self.calls.append(("delete", (project_id, wait, timeout_seconds)))
        return True

    def count_project(self, project_id: object, *, timeout_seconds: float) -> object:
        self.calls.append(("count", (project_id, timeout_seconds)))
        return 0

    def scroll_project(self, project_id: object, *, timeout_seconds: float) -> object:
        self.calls.append(("scroll", (project_id, timeout_seconds)))
        return []


def test_qdrant_e3_adapter_waits_then_requires_count_and_scroll_zero() -> None:
    project_id = uuid4()
    client = _Qdrant()
    eraser = QdrantErasureAdapter(client)

    assert eraser.erase_project(project_id, timeout_seconds=1).result_code == "ok"
    assert (
        eraser.verify_project_absent(project_id, timeout_seconds=1).result_code == "already_absent"
    )
    assert [call[0] for call in client.calls] == ["delete", "count", "scroll"]
    assert client.calls[0][1][0:2] == (project_id, True)
    timeouts = [call[1][-1] for call in client.calls]
    assert all(isinstance(timeout, float) and 0 < timeout <= 1 for timeout in timeouts)


def test_qdrant_progress_lease_loss_is_not_reclassified_as_a_store_block() -> None:
    project_id = uuid4()
    client = _Qdrant()

    def lose_lease() -> None:
        raise ErasureLeaseLost()

    with pytest.raises(ErasureLeaseLost):
        QdrantErasureAdapter(client).erase_project(
            project_id, timeout_seconds=1, before_page=lose_lease
        )
    assert client.calls == []


class _Age:
    def __init__(self) -> None:
        self.calls: list[tuple[str, Mapping[str, object], float]] = []

    def execute_erasure(
        self, cypher: str, params: Mapping[str, object], *, timeout_seconds: float
    ) -> Sequence[Mapping[str, object]]:
        self.calls.append((cypher, params, timeout_seconds))
        return [{"count": 0}] if "RETURN count" in cypher else []


def test_age_e3_adapter_uses_parameterized_project_delete_and_zero_proof() -> None:
    project_id = uuid4()
    executor = _Age()
    eraser = AgeErasureAdapter(executor)

    assert eraser.erase_project(project_id, timeout_seconds=1).result_code == "ok"
    assert (
        eraser.verify_project_absent(project_id, timeout_seconds=1).result_code == "already_absent"
    )
    delete_cypher, delete_params, delete_timeout = executor.calls[0]
    assert "DETACH DELETE" in delete_cypher
    assert delete_params == {"project_id": str(project_id)}
    assert 0 < delete_timeout <= 1
    count_cypher, count_params, count_timeout = executor.calls[1]
    assert "RETURN count" in count_cypher
    assert count_params == {"project_id": str(project_id)}
    assert 0 < count_timeout <= 1


def test_age_progress_lease_loss_is_not_reclassified_as_a_store_block() -> None:
    project_id = uuid4()
    executor = _Age()

    def lose_lease() -> None:
        raise ErasureLeaseLost()

    with pytest.raises(ErasureLeaseLost):
        AgeErasureAdapter(executor).erase_project(
            project_id, timeout_seconds=1, before_page=lose_lease
        )
    assert executor.calls == []
