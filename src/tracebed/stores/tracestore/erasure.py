"""E3-only destructive trace-store adapters.

These adapters intentionally do not extend :class:`TraceStorePort`: ordinary
ingest/read callers cannot discover a deletion method structurally.  Every
path is derived from canonical UUID segments and the filesystem implementation
uses directory file descriptors so a symlink/rename race cannot turn a scoped
erase into a path traversal.
"""

from __future__ import annotations

import hashlib
import math
import os
import stat
import time
from collections.abc import Callable
from pathlib import Path
from typing import Final
from uuid import UUID

from tracebed.domain.errors import ErasureDependencyTimeout, ErasureOperatorBlocked
from tracebed.erasure.domain import StoreResult
from tracebed.stores.tracestore import PayloadRef
from tracebed.stores.tracestore.base import is_safe_key

__all__ = ["FsTraceEraser"]

_DIR_FLAGS: Final[int] = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0)
_FILE_FLAGS: Final[int] = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)


class _Deadline:
    """Post-call deadline guard for local syscalls that cannot be cancelled.

    A filesystem syscall may finish after the lease-sized external timeout.
    We still refuse to mark its result: the successor safely repeats the
    idempotent erase and independent absence proof.  ``before_page`` gives
    the executor a renewal point between every bounded directory operation.
    """

    def __init__(
        self,
        timeout_seconds: float,
        monotonic: Callable[[], float],
        before_page: Callable[[], None] | None,
    ) -> None:
        if (
            type(timeout_seconds) not in {int, float}
            or isinstance(timeout_seconds, bool)
            or not math.isfinite(timeout_seconds)
            or timeout_seconds <= 0
            or (before_page is not None and not callable(before_page))
        ):
            raise ErasureOperatorBlocked()
        self._deadline = monotonic() + float(timeout_seconds)
        self._monotonic = monotonic
        self._before_page = before_page

    def check(self) -> None:
        if self._before_page is not None:
            self._before_page()
        if self._monotonic() >= self._deadline:
            raise ErasureDependencyTimeout()


def _digest(kind: str, project_id: UUID, run_id: UUID | None = None) -> bytes:
    value = b"tracebed.erasure.fs/v1\x00" + kind.encode("ascii") + project_id.bytes
    if run_id is not None:
        value += run_id.bytes
    return hashlib.sha256(value).digest()


def _segment(value: UUID) -> str:
    # UUID's canonical string is exact ASCII lower-case UUID syntax.  Do not
    # accept a caller supplied string here: this is the filesystem boundary.
    return str(value)


class FsTraceEraser:
    """Secure delete-and-absence proof for ``{root}/{project}/{run}`` trees."""

    store_code = "trace_fs_v1"

    def __init__(self, root: Path, *, monotonic: Callable[[], float] = time.monotonic) -> None:
        self._root = Path(root)
        if not self._root.is_dir():
            raise ValueError("erasure trace root must be an existing directory")
        if not callable(monotonic):
            raise TypeError("erasure monotonic clock is invalid")
        self._monotonic = monotonic

    def validate_manifest_ref(self, project_id: UUID, run_id: UUID, payload_ref: str) -> bytes:
        if type(project_id) is not UUID or type(run_id) is not UUID or type(payload_ref) is not str:
            raise ErasureOperatorBlocked()
        try:
            ref = PayloadRef.parse(payload_ref)
        except ValueError as exc:
            raise ErasureOperatorBlocked() from exc
        prefix = f"{project_id}/{run_id}/"
        if ref.driver != "fs" or not is_safe_key(ref.key) or not ref.key.startswith(prefix):
            raise ErasureOperatorBlocked()
        tail = ref.key[len(prefix) :]
        # Payload refs may name a nested immutable chunk.  The entire run
        # prefix is the deletion target, so only the trusted driver/project/
        # run prefix and the generic no-dot-segment proof matter here.
        if not tail:
            raise ErasureOperatorBlocked()
        # Canonical frame, passed directly to the executor's digest hasher.
        # It is not rendered or logged by this adapter.
        raw = payload_ref.encode("utf-8")
        return project_id.bytes + run_id.bytes + len(raw).to_bytes(8, "big") + raw

    def erase_run(
        self,
        project_id: UUID,
        run_id: UUID,
        *,
        timeout_seconds: float,
        before_page: Callable[[], None] | None = None,
    ) -> StoreResult:
        return self._erase(project_id, run_id, _Deadline(timeout_seconds, self._monotonic, before_page))

    def verify_run_absent(
        self,
        project_id: UUID,
        run_id: UUID,
        *,
        timeout_seconds: float,
        before_page: Callable[[], None] | None = None,
    ) -> StoreResult:
        return self._verify(project_id, run_id, _Deadline(timeout_seconds, self._monotonic, before_page))

    def erase_project(
        self,
        project_id: UUID,
        *,
        timeout_seconds: float,
        before_page: Callable[[], None] | None = None,
    ) -> StoreResult:
        return self._erase(project_id, None, _Deadline(timeout_seconds, self._monotonic, before_page))

    def verify_project_absent(
        self,
        project_id: UUID,
        *,
        timeout_seconds: float,
        before_page: Callable[[], None] | None = None,
    ) -> StoreResult:
        return self._verify(project_id, None, _Deadline(timeout_seconds, self._monotonic, before_page))

    def _root_fd(self, deadline: _Deadline) -> int:
        try:
            deadline.check()
            value = os.open(self._root, _DIR_FLAGS)
            try:
                deadline.check()
            except BaseException:
                os.close(value)
                raise
            return value
        except OSError as exc:
            raise ErasureOperatorBlocked() from exc

    @staticmethod
    def _open_dir(parent_fd: int, name: str, deadline: _Deadline) -> int | None:
        try:
            deadline.check()
            value = os.open(name, _DIR_FLAGS, dir_fd=parent_fd)
            try:
                deadline.check()
            except BaseException:
                os.close(value)
                raise
            return value
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise ErasureOperatorBlocked() from exc

    @staticmethod
    def _lstat_absent(parent_fd: int, name: str, deadline: _Deadline) -> bool:
        try:
            deadline.check()
            os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            deadline.check()
        except FileNotFoundError:
            return True
        except OSError as exc:
            raise ErasureOperatorBlocked() from exc
        return False

    def _erase(self, project_id: UUID, run_id: UUID | None, deadline: _Deadline) -> StoreResult:
        if type(project_id) is not UUID or (run_id is not None and type(run_id) is not UUID):
            raise ErasureOperatorBlocked()
        root_fd = self._root_fd(deadline)
        try:
            project_name = _segment(project_id)
            project_fd = self._open_dir(root_fd, project_name, deadline)
            if project_fd is None:
                return StoreResult("already_absent", 0, _digest("project", project_id, run_id))
            try:
                if run_id is None:
                    count = self._unlink_tree(project_fd, deadline)
                    deadline.check()
                    os.rmdir(project_name, dir_fd=root_fd)
                    deadline.check()
                    os.fsync(root_fd)
                    deadline.check()
                    if not self._lstat_absent(root_fd, project_name, deadline):
                        raise ErasureOperatorBlocked()
                    return StoreResult("ok", count, _digest("project", project_id))
                run_name = _segment(run_id)
                run_fd = self._open_dir(project_fd, run_name, deadline)
                if run_fd is None:
                    return StoreResult("already_absent", 0, _digest("run", project_id, run_id))
                try:
                    count = self._unlink_tree(run_fd, deadline)
                finally:
                    os.close(run_fd)
                deadline.check()
                os.rmdir(run_name, dir_fd=project_fd)
                deadline.check()
                os.fsync(project_fd)
                deadline.check()
                if not self._lstat_absent(project_fd, run_name, deadline):
                    raise ErasureOperatorBlocked()
                return StoreResult("ok", count, _digest("run", project_id, run_id))
            finally:
                os.close(project_fd)
        except OSError as exc:
            # Includes a non-empty directory from an unsafe concurrent swap,
            # permission/refusal and filesystem durability failure.
            raise ErasureOperatorBlocked() from exc
        finally:
            os.close(root_fd)

    def _unlink_tree(self, directory_fd: int, deadline: _Deadline) -> int:
        """Remove only regular files and child directories, bottom-up.

        ``os.listdir(fd)`` and every child operation remains anchored to the
        already-open parent descriptor.  We reject a symlink or special file
        rather than following/removing an ambiguous external target.
        """

        try:
            deadline.check()
            entries = os.listdir(directory_fd)
            deadline.check()
        except OSError as exc:
            raise ErasureOperatorBlocked() from exc
        count = 0
        for name in entries:
            try:
                deadline.check()
                entry = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                deadline.check()
            except OSError as exc:
                raise ErasureOperatorBlocked() from exc
            mode = entry.st_mode
            if stat.S_ISLNK(mode) or not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)):
                raise ErasureOperatorBlocked()
            if stat.S_ISREG(mode):
                try:
                    deadline.check()
                    os.unlink(name, dir_fd=directory_fd)
                    deadline.check()
                    os.fsync(directory_fd)
                    deadline.check()
                except OSError as exc:
                    raise ErasureOperatorBlocked() from exc
                count += 1
                continue
            child_fd = self._open_dir(directory_fd, name, deadline)
            if child_fd is None:
                # A concurrent deletion cannot count as proof; caller retries
                # through a fresh delete+verify operation.
                raise ErasureOperatorBlocked()
            try:
                count += self._unlink_tree(child_fd, deadline)
            finally:
                os.close(child_fd)
            try:
                deadline.check()
                os.rmdir(name, dir_fd=directory_fd)
                deadline.check()
                os.fsync(directory_fd)
                deadline.check()
            except OSError as exc:
                raise ErasureOperatorBlocked() from exc
        return count

    def _verify(self, project_id: UUID, run_id: UUID | None, deadline: _Deadline) -> StoreResult:
        if type(project_id) is not UUID or (run_id is not None and type(run_id) is not UUID):
            raise ErasureOperatorBlocked()
        root_fd = self._root_fd(deadline)
        try:
            project_name = _segment(project_id)
            if run_id is None:
                absent = self._lstat_absent(root_fd, project_name, deadline)
                if not absent:
                    raise ErasureOperatorBlocked()
                return StoreResult("already_absent", 0, _digest("project", project_id))
            project_fd = self._open_dir(root_fd, project_name, deadline)
            if project_fd is None:
                return StoreResult("already_absent", 0, _digest("run", project_id, run_id))
            try:
                if not self._lstat_absent(project_fd, _segment(run_id), deadline):
                    raise ErasureOperatorBlocked()
            finally:
                os.close(project_fd)
            return StoreResult("already_absent", 0, _digest("run", project_id, run_id))
        finally:
            os.close(root_fd)
