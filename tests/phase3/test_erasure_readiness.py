"""Non-destructive E4 dependency-readiness proofs."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from tracebed.domain.clock import FakeClock
from tracebed.domain.errors import ConfigError
from tracebed.erasure import readiness

pytestmark = pytest.mark.phase3


class _VersionedStore:
    def __init__(self) -> None:
        self._clock = FakeClock()

    def bucket_versioning(self) -> SimpleNamespace:
        return SimpleNamespace(
            status_code=200,
            content=b"<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>",
        )


def test_non_destructive_valkey_probe_completes_an_empty_cursor_chain(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[int, float]] = []
    responses = iter(((8, []), (16, ()), (0, [])))

    class _Commands:
        def __init__(self, url: str) -> None:
            assert url == "valkey://valkey:6379/0"

        def scan(
            self, cursor: int, *, match: str, count: int, timeout_seconds: float
        ) -> tuple[object, object]:
            assert match.startswith("__tracebed_erasure_readiness_")
            assert count == 1
            calls.append((cursor, timeout_seconds))
            return next(responses)

    monkeypatch.setattr(readiness, "FreshValkeyErasureCommands", _Commands)

    readiness._non_destructive_probe(
        {"TB_STORAGE__VALKEY_URL": "valkey://valkey:6379/0"}, _VersionedStore()  # type: ignore[arg-type]
    )

    assert [cursor for cursor, _ in calls] == [0, 8, 16]
    assert all(0 < timeout <= readiness._CANARY_TIMEOUT_SECONDS for _, timeout in calls)


def test_non_destructive_valkey_probe_rejects_a_repeated_cursor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _Commands:
        def __init__(self, _url: str) -> None:
            pass

        def scan(
            self, cursor: int, *, match: str, count: int, timeout_seconds: float
        ) -> tuple[object, object]:
            del cursor, match, count, timeout_seconds
            return (8, [])

    monkeypatch.setattr(readiness, "FreshValkeyErasureCommands", _Commands)

    with pytest.raises(ConfigError):
        readiness._non_destructive_probe(
            {"TB_STORAGE__VALKEY_URL": "valkey://valkey:6379/0"}, _VersionedStore()  # type: ignore[arg-type]
        )
