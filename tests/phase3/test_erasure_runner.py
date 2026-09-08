"""Safe-boundary quiesce proofs for the long-lived E4 daemon."""

from __future__ import annotations

import os
import signal
import stat
from pathlib import Path
from types import SimpleNamespace

import pytest

from tracebed.domain.errors import ConfigError
from tracebed.erasure import runner

pytestmark = pytest.mark.phase3


class _ParkedAtBoundary(Exception):
    """Test-only replacement for the acknowledgment wait."""


@pytest.fixture(autouse=True)
def _reset_quiesce_request() -> None:
    runner._quiesce_requested = False
    runner._quiesce_parked = False
    runner._quiesce_resume_requested = False
    yield
    runner._quiesce_requested = False
    runner._quiesce_parked = False
    runner._quiesce_resume_requested = False


def _park_at_boundary(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    calls: list[str] = []

    def park() -> None:
        calls.append("park")
        raise _ParkedAtBoundary

    monkeypatch.setattr(runner, "_park_at_safe_boundary", park)
    return calls


def test_quiesce_requested_during_admission_waits_for_admission_to_return(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    parks = _park_at_boundary(monkeypatch)

    class Executor:
        def run_next(self) -> None:
            events.append("run-next")

    class Runtime:
        settings = SimpleNamespace(poll_seconds=0)
        executor = Executor()

        def admission_open(self) -> bool:
            events.append("admission-enter")
            runner._request_quiesce(signal.SIGUSR1, None)
            events.append("admission-return")
            return True

    with pytest.raises(_ParkedAtBoundary):
        runner._run_loop(Runtime())

    assert events == ["admission-enter", "admission-return"]
    assert parks == ["park"]


def test_quiesce_requested_during_executor_pass_waits_for_it_to_return(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    parks = _park_at_boundary(monkeypatch)

    class Executor:
        def run_next(self) -> None:
            events.append("run-next-enter")
            runner._request_quiesce(signal.SIGUSR1, None)
            events.append("run-next-return")

    class Runtime:
        settings = SimpleNamespace(poll_seconds=0)
        executor = Executor()

        def admission_open(self) -> bool:
            events.append("admission")
            return True

    with pytest.raises(_ParkedAtBoundary):
        runner._run_loop(Runtime())

    assert events == ["admission", "run-next-enter", "run-next-return"]
    assert parks == ["park"]


def test_preexisting_quiesce_request_parks_before_the_next_admission(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    admissions: list[bool] = []
    parks = _park_at_boundary(monkeypatch)

    class Runtime:
        settings = SimpleNamespace(poll_seconds=0)
        executor = SimpleNamespace(run_next=lambda: None)

        def admission_open(self) -> bool:
            admissions.append(True)
            return False

    runner._request_quiesce(signal.SIGUSR1, None)
    with pytest.raises(_ParkedAtBoundary):
        runner._run_loop(Runtime())

    assert admissions == []
    assert parks == ["park"]


def test_quiesce_ack_is_exact_held_and_removed_only_after_continue(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    path = tmp_path / "quiesce-ack"
    monkeypatch.setattr(runner, "_QUIESCE_ACK_PATH", str(path))

    descriptor = runner._publish_quiesce_ack()
    metadata = path.lstat()
    held = os.fstat(descriptor)
    assert stat.S_ISREG(metadata.st_mode)
    assert stat.S_IMODE(metadata.st_mode) == 0o600
    assert metadata.st_nlink == 1
    assert (metadata.st_dev, metadata.st_ino) == (held.st_dev, held.st_ino)
    assert path.read_bytes() == b"tracebed-erasure-quiesced-v1\n"

    runner._remove_quiesce_ack(descriptor)
    assert not path.exists()


def test_park_waits_for_caught_continue_before_unlinking_ack(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    path = tmp_path / "quiesce-ack"
    monkeypatch.setattr(runner, "_QUIESCE_ACK_PATH", str(path))
    observations: list[bool] = []

    def release(_seconds: float) -> None:
        observations.append(path.exists())
        runner._release_quiesce(signal.SIGCONT, None)

    monkeypatch.setattr(runner.time, "sleep", release)
    runner._park_at_safe_boundary()

    assert observations == [True]
    assert not path.exists()


def test_stale_or_wrong_ack_fails_closed(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    path = tmp_path / "quiesce-ack"
    path.write_text("stale", encoding="utf-8")
    path.chmod(0o600)
    monkeypatch.setattr(runner, "_QUIESCE_ACK_PATH", str(path))

    with pytest.raises(ConfigError):
        runner._require_quiesce_ack_absent()


def test_continue_only_releases_an_already_parked_daemon() -> None:
    runner._release_quiesce(signal.SIGCONT, None)
    assert runner._quiesce_resume_requested is False

    runner._quiesce_parked = True
    runner._release_quiesce(signal.SIGCONT, None)
    assert runner._quiesce_resume_requested is True
