"""Deployment-only E4 worker entry point.

The executor has its own login, network, and fixed local-Compose assembly.
It still never starts destructive work while authority admission is closed:
the controller uses that closed interval for the prepublication proof.
"""

from __future__ import annotations

import os
import signal
import socket
import stat
import time
from collections.abc import Mapping
from types import FrameType
from typing import TYPE_CHECKING, Final

from tracebed.domain.errors import ConfigError
from tracebed.erasure.domain import ErasureSettings, ExternalStoreCode
from tracebed.erasure.executor import ErasureDatabasePort, ErasureExecutor, ErasureStatus

if TYPE_CHECKING:
    from tracebed.erasure.composition import ErasureRuntime

__all__ = ["build_executor", "resume", "run", "run_request", "status"]


# ``SIGUSR1`` is an acceptance-only quiesce request for the long-lived E4
# daemon.  Its handler is deliberately inert: it cannot interrupt a database
# context manager or stop the process while a transaction owns locks.  At one
# of the three safe boundaries below the loop publishes a fixed local receipt
# and waits.  Acceptance verifies that receipt and the absence of database
# locks before it sends the external SIGSTOP that freezes PID 1.  SIGCONT is
# caught to remove the receipt and release this no-I/O wait.
_quiesce_requested = False
_quiesce_parked = False
_quiesce_resume_requested = False
_QUIESCE_ACK_PATH: Final = "/tmp/tracebed-erasure-quiesced-v1"  # noqa: S108 - fixed container-local receipt
_QUIESCE_ACK_CONTENT: Final = b"tracebed-erasure-quiesced-v1\n"
_QUIESCE_ACK_MODE: Final = 0o600
_QUIESCE_WAIT_SECONDS: Final = 0.05
_QUIESCE_ACK_FLAGS: Final = os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW


def _owner() -> str:
    raw = os.environ.get("TB_ERASURE_OWNER") or socket.gethostname()
    if not raw or len(raw) > 96:
        raise ConfigError("erasure owner configuration is invalid")
    allowed = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._:-")
    if raw[0] not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" or any(
        character not in allowed for character in raw
    ):
        raise ConfigError("erasure owner configuration is invalid")
    return raw


def build_executor(
    settings: ErasureSettings,
    db: ErasureDatabasePort,
    stores: Mapping[ExternalStoreCode, object],
) -> ErasureExecutor:
    """Explicit composition seam; production must supply all frozen stores."""

    missing = set(settings.manifest).difference(stores)
    if missing:
        raise ConfigError("erasure destructive store configuration is incomplete")
    return ErasureExecutor(
        db,
        manifest=settings.manifest,
        owner=_owner(),
        lease_seconds=settings.lease_seconds,
        heartbeat_seconds=settings.heartbeat_seconds,
        batch_size=settings.batch_size,
        external_timeout_seconds=settings.external_timeout_seconds,
        stores=stores,
        now_monotonic=time.monotonic,
    )


def _request_quiesce(_signal_number: int, _frame: FrameType | None) -> None:
    """Record, but never execute, an asynchronous daemon quiesce request."""

    global _quiesce_requested
    _quiesce_requested = True


def _release_quiesce(_signal_number: int, _frame: FrameType | None) -> None:
    """Release only a daemon that is already parked outside its E4 calls."""

    global _quiesce_resume_requested
    if _quiesce_parked:
        _quiesce_resume_requested = True


def _quiesce_error() -> ConfigError:
    return ConfigError("erasure quiesce acknowledgement is invalid")


def _read_ack(descriptor: int) -> bytes:
    """Read the small fixed acknowledgement through the held descriptor."""

    chunks = bytearray()
    limit = len(_QUIESCE_ACK_CONTENT) + 1
    while len(chunks) < limit:
        block = os.read(descriptor, limit - len(chunks))
        if not block:
            break
        chunks.extend(block)
    return bytes(chunks)


def _write_ack(descriptor: int) -> None:
    """Write the fixed acknowledgement without accepting a short write."""

    remaining = _QUIESCE_ACK_CONTENT
    while remaining:
        written = os.write(descriptor, remaining)
        if written <= 0:
            raise OSError
        remaining = remaining[written:]


def _require_held_quiesce_ack(descriptor: int) -> None:
    """Require the named acknowledgement to be the one kept open by this daemon."""

    try:
        held = os.fstat(descriptor)
        named = os.lstat(_QUIESCE_ACK_PATH)
        if (
            not stat.S_ISREG(held.st_mode)
            or stat.S_IMODE(held.st_mode) != _QUIESCE_ACK_MODE
            or held.st_uid != os.getuid()
            or held.st_nlink != 1
            or not stat.S_ISREG(named.st_mode)
            or stat.S_IMODE(named.st_mode) != _QUIESCE_ACK_MODE
            or named.st_uid != os.getuid()
            or named.st_nlink != 1
            or (held.st_dev, held.st_ino, held.st_nlink)
            != (named.st_dev, named.st_ino, named.st_nlink)
        ):
            raise _quiesce_error()
    except OSError:
        raise _quiesce_error() from None


def _require_quiesce_ack_absent() -> None:
    """Fail closed rather than treating an old acknowledgement as a new pause."""

    try:
        os.lstat(_QUIESCE_ACK_PATH)
    except FileNotFoundError:
        return
    except OSError:
        raise _quiesce_error() from None
    raise _quiesce_error()


def _publish_quiesce_ack() -> int:
    """Atomically publish and retain the exact acknowledgement file descriptor."""

    try:
        descriptor = os.open(_QUIESCE_ACK_PATH, _QUIESCE_ACK_FLAGS, _QUIESCE_ACK_MODE)
    except OSError:
        raise _quiesce_error() from None
    try:
        os.fchmod(descriptor, _QUIESCE_ACK_MODE)
        _write_ack(descriptor)
        os.fsync(descriptor)
        os.lseek(descriptor, 0, os.SEEK_SET)
        if _read_ack(descriptor) != _QUIESCE_ACK_CONTENT:
            raise _quiesce_error()
        _require_held_quiesce_ack(descriptor)
    except (OSError, ValueError):
        os.close(descriptor)
        raise _quiesce_error() from None
    except Exception:
        os.close(descriptor)
        raise
    return descriptor


def _remove_quiesce_ack(descriptor: int) -> None:
    """Unlink the held acknowledgement only after the caught SIGCONT release."""

    try:
        _require_held_quiesce_ack(descriptor)
        os.unlink(_QUIESCE_ACK_PATH)
        if os.fstat(descriptor).st_nlink != 0:
            raise _quiesce_error()
    except OSError:
        raise _quiesce_error() from None
    finally:
        os.close(descriptor)


def _park_at_safe_boundary() -> None:
    """Publish the receipt and wait without any database or external-store I/O."""

    global _quiesce_parked, _quiesce_resume_requested
    _quiesce_resume_requested = False
    _quiesce_parked = True
    descriptor = -1
    try:
        descriptor = _publish_quiesce_ack()
        while not _quiesce_resume_requested:
            time.sleep(_QUIESCE_WAIT_SECONDS)
        _remove_quiesce_ack(descriptor)
        descriptor = -1
    finally:
        _quiesce_parked = False
        if descriptor != -1:
            os.close(descriptor)


def _quiesce_at_safe_boundary() -> None:
    """Park only after any preceding transactional operation returned."""

    global _quiesce_requested
    if not _quiesce_requested:
        return
    _quiesce_requested = False
    _park_at_safe_boundary()


def _run_loop(runtime: ErasureRuntime) -> None:
    """Run the normal poller, honouring a requested pause only at safe boundaries."""

    while True:
        # Before admission: no daemon query has started in this iteration.
        _quiesce_at_safe_boundary()
        admission_open = runtime.admission_open()
        # Immediately after admission: its transaction context has exited,
        # before a destructive claim can begin.
        _quiesce_at_safe_boundary()
        if admission_open:
            runtime.executor.run_next()
        # After a possible claim/executor pass: no E4 operation remains in
        # flight before the daemon can become externally quiescent.
        _quiesce_at_safe_boundary()
        time.sleep(runtime.settings.poll_seconds)


def run() -> None:
    """Run the fixed E4 composition, waiting without claiming while closed."""

    from tracebed.erasure.composition import build_runtime

    global _quiesce_parked, _quiesce_requested, _quiesce_resume_requested
    _quiesce_requested = False
    _quiesce_parked = False
    _quiesce_resume_requested = False
    _require_quiesce_ack_absent()
    previous_quiesce_handler = signal.signal(signal.SIGUSR1, _request_quiesce)
    previous_continue_handler = signal.signal(signal.SIGCONT, _release_quiesce)
    runtime: ErasureRuntime | None = None
    try:
        runtime = build_runtime()
        _run_loop(runtime)
    finally:
        try:
            if runtime is not None:
                runtime.close()
        finally:
            signal.signal(signal.SIGUSR1, previous_quiesce_handler)
            signal.signal(signal.SIGCONT, previous_continue_handler)
            _quiesce_requested = False
            _quiesce_parked = False
            _quiesce_resume_requested = False


def run_request(request_id: object) -> None:
    """Run one operator-selected request through the same closed admission gate."""

    from uuid import UUID

    from tracebed.erasure.composition import build_runtime

    if type(request_id) is not UUID:
        raise ConfigError("erasure request id is invalid")
    runtime = build_runtime()
    try:
        if runtime.admission_open():
            runtime.executor.run_request(request_id)
    finally:
        runtime.close()


def status(request_id: object) -> ErasureStatus | None:
    """Return the bounded durable status projection from the erasure identity."""

    from tracebed.erasure.composition import build_runtime

    runtime = build_runtime()
    try:
        return runtime.status(request_id)
    finally:
        runtime.close()


def resume(request_id: object) -> None:
    """Apply only the fixed E4 operator resume code."""

    from tracebed.erasure.composition import build_runtime

    runtime = build_runtime()
    try:
        runtime.resume(request_id)
    finally:
        runtime.close()
