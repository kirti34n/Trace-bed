"""Process-level loop supervision for the real worker composition root."""

from __future__ import annotations

from dataclasses import dataclass
from threading import Event, current_thread

import httpx
import pytest

from tracebed.adapters.embedding.gemini import GeminiEmbeddingClient
from tracebed.adapters.embedding.pinning import ModelPin
from tracebed.domain.config import TraceStoreConfig
from tracebed.stores.pg import worker_drain
from tracebed.stores.tracestore.s3 import S3TraceStore
from tracebed.workers import drain
from tracebed.workers.runner import (
    WorkerOwnedResources,
    WorkerResourceFactories,
    _run_worker_process,
    supervise_worker_loops,
)

pytestmark = pytest.mark.phase2


def test_lifecycle_drain_uses_the_profiled_metric_for_all_v1_topics(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The c12 worker has no raw queue ACL, so every topic uses its fixed reader."""

    calls: list[tuple[str, object]] = []

    class _Connection:
        def __enter__(self) -> _Connection:
            return self

        def __exit__(self, *_: object) -> None:
            return None

        def execute(self, query: str, parameters: object) -> _Connection:
            calls.append((query, parameters))
            return self

        def fetchone(self) -> tuple[int]:
            return (0,)

    monkeypatch.setattr(drain, "runtime_dsn_from_environment", lambda *_: type("Dsn", (), {"value": "opaque"})())
    monkeypatch.setattr(worker_drain.psycopg, "connect", lambda *_args, **_kwargs: _Connection())

    assert drain.pending_v1_work_count() == 0
    expected_sql = "\nSELECT depth\n  FROM public.tracebed_worker_queue_metrics(%s::text)\n"
    assert calls == [
        (
            expected_sql,
            ("trace_event",),
        ),
        (
            expected_sql,
            ("outcome_event",),
        ),
        (
            expected_sql,
            ("memory_proposal",),
        ),
    ]


def test_five_loop_supervision_uses_non_daemon_threads_and_joins_before_reraise() -> None:
    seen: list[tuple[str, bool]] = []

    def _returned(stop: Event) -> None:
        del stop
        seen.append(("returned", current_thread().daemon))

    def _waiter(name: str):
        def _loop(stop: Event) -> None:
            seen.append((name, current_thread().daemon))
            stop.wait(timeout=1)

        return _loop

    with pytest.raises(RuntimeError, match="returned unexpectedly"):
        supervise_worker_loops(
            (
                ("ingest", _returned),
                ("proposals", _waiter("proposals")),
                ("worker", _waiter("worker")),
                ("scheduler", _waiter("scheduler")),
                ("trace-learning", _waiter("trace-learning")),
            ),
            Event(),
        )

    assert {name for name, _daemon in seen} == {
        "returned",
        "proposals",
        "worker",
        "scheduler",
        "trace-learning",
    }
    assert all(not daemon for _name, daemon in seen)


def test_loop_exception_stops_and_reraises_the_original_error_after_joining() -> None:
    joined = Event()

    def _broken(_stop: Event) -> None:
        raise ValueError("broken loop")

    def _waiter(stop: Event) -> None:
        stop.wait(timeout=1)
        joined.set()

    with pytest.raises(ValueError, match="broken loop"):
        supervise_worker_loops((("broken", _broken), ("waiter", _waiter)), Event())

    assert joined.is_set()


def test_external_stop_is_a_normal_exit_not_an_unsolicited_return() -> None:
    stop = Event()
    stop.set()
    calls: list[str] = []

    def _external(_stop: Event) -> None:
        calls.append("called")

    supervise_worker_loops((("ingest", _external), ("trace-learning", _external)), stop)
    assert calls == ["called", "called"]


def test_concrete_http_resources_expose_close_without_widening_ports(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Worker composition can own concrete client cleanup without changing data ports."""

    monkeypatch.setenv("TEST_S3_ACCESS", "access")
    monkeypatch.setenv("TEST_S3_SECRET", "secret")
    store_http = httpx.Client()
    store = S3TraceStore(
        TraceStoreConfig(
            driver="s3",
            endpoint="http://s3.invalid",
            bucket="test-bucket",
            access_key_env="TEST_S3_ACCESS",
            secret_key_env="TEST_S3_SECRET",
        ),
        http=store_http,
    )
    embed_http = httpx.Client()
    client = GeminiEmbeddingClient(
        base_url="http://embedding.invalid",
        api_key="test",
        pin=ModelPin(model_id="test-model", model_version="v1", dim=2),
        http=embed_http,
    )

    store.close()
    client.close()

    assert store_http.is_closed
    assert embed_http.is_closed


@dataclass
class _ConcreteResource:
    """Closable concrete fake; ``wait`` must never be used as cleanup."""

    name: str
    closed: list[str]

    def close(self) -> None:
        self.closed.append(self.name)

    def wait(self) -> None:
        raise AssertionError(f"{self.name}.wait() is not a cleanup method")


def _resource_factories(
    built: list[str], closed: list[str], *, fail_at: str | None = None
) -> WorkerResourceFactories:
    """Actual-object constructors for the real private ownership context."""

    def _build(name: str):
        def _factory():
            built.append(name)
            if fail_at == name:
                raise RuntimeError(f"{name} construction failed")
            return _ConcreteResource(name, closed)

        return _factory

    return WorkerResourceFactories(
        build_pool=_build("pool"),
        build_tracestore=_build("trace"),
        build_embedding=_build("embedding"),
        build_valkey=_build("valkey"),
    )


def test_run_worker_process_owns_concrete_resources_around_a_normal_body() -> None:
    built: list[str] = []
    closed: list[str] = []
    body_calls: list[WorkerOwnedResources] = []

    _run_worker_process(
        resource_factories=_resource_factories(built, closed),
        process_body=body_calls.append,
    )

    assert built == ["pool", "trace", "embedding", "valkey"]
    assert len(body_calls) == 1
    body = body_calls[0]
    assert [body.pool.name, body.tracestore.name, body.embedding.name, body.valkey.name] == [
        "pool",
        "trace",
        "embedding",
        "valkey",
    ]
    assert closed == ["valkey", "embedding", "trace", "pool"]


def test_run_worker_process_closes_all_owned_resources_after_body_failure() -> None:
    built: list[str] = []
    closed: list[str] = []
    body_calls: list[WorkerOwnedResources] = []

    def _broken_body(owned: WorkerOwnedResources) -> None:
        body_calls.append(owned)
        raise RuntimeError("body failed after Valkey construction")

    with pytest.raises(RuntimeError, match="body failed"):
        _run_worker_process(
            resource_factories=_resource_factories(built, closed),
            process_body=_broken_body,
        )

    assert built == ["pool", "trace", "embedding", "valkey"]
    assert len(body_calls) == 1
    assert closed == ["valkey", "embedding", "trace", "pool"]


@pytest.mark.parametrize(
    ("failed_resource", "expected_built", "expected_closed"),
    [
        ("trace", ["pool", "trace"], ["pool"]),
        ("embedding", ["pool", "trace", "embedding"], ["trace", "pool"]),
        ("valkey", ["pool", "trace", "embedding", "valkey"], ["embedding", "trace", "pool"]),
    ],
)
def test_run_worker_process_closes_partial_resources_and_never_calls_body(
    failed_resource: str,
    expected_built: list[str],
    expected_closed: list[str],
) -> None:
    built: list[str] = []
    closed: list[str] = []
    body_calls: list[WorkerOwnedResources] = []

    with pytest.raises(RuntimeError, match=f"{failed_resource} construction failed"):
        _run_worker_process(
            resource_factories=_resource_factories(built, closed, fail_at=failed_resource),
            process_body=body_calls.append,
        )

    assert built == expected_built
    assert closed == expected_closed
    assert body_calls == []
