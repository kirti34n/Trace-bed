"""Filesystem `TraceStorePort` driver (PHASE0-CONTRACT.md §6.3) — the Phase 0 default.

Root layout `{root}/{project_id}/{run_id}/{first_seq:08d}.tbz`; every key
therefore embeds `project_id`, which is what makes the leak-suite's
cross-project by-id probe (invariant 4) fail closed for `get()` without a
network call — there is none to make here; the check is a string comparison
against the local key before the file is even opened.

Two independent gates guard that probe, because a prefix comparison alone is
defeated by `"{caller}/../{victim}/..."` (see `base.py`): the structural key
test in `base.ref_matches_project`, and then a resolved-path containment test
against the caller's OWN project directory — not merely against the store
root, which would still permit the traversal to land in a sibling project.
"""

from __future__ import annotations

import contextlib
import os
from pathlib import Path
from typing import Final, Literal

from tracebed.domain.errors import NotFound
from tracebed.domain.ids import ProjectId, RunId
from tracebed.stores.tracestore import PayloadRef
from tracebed.stores.tracestore.base import ref_matches_project, require_project_prefix

__all__ = ["FsTraceStore"]

_SUFFIX = ".tbz"
_DRIVER: Final[Literal["fs"]] = "fs"


class FsTraceStore:
    """`TraceStorePort` over a local or mounted directory tree."""

    def __init__(self, root: Path) -> None:
        self._root = Path(root)
        self._root.mkdir(parents=True, exist_ok=True)

    def _project_segment(self, project_id: ProjectId) -> str:
        return f"{project_id}/"

    def _project_dir(self, project_id: ProjectId) -> Path:
        return self._root / str(project_id)

    def _object_path(self, project_id: ProjectId, run_id: RunId, first_seq: int) -> Path:
        if first_seq < 0:
            raise ValueError(f"FsTraceStore: first_seq must be >= 0, got {first_seq}")
        return self._project_dir(project_id) / str(run_id) / f"{first_seq:08d}{_SUFFIX}"

    def _contained_path(self, project_id: ProjectId, ref: PayloadRef) -> Path | None:
        """Resolves `ref.key` to a path provably inside the CALLER's project
        directory, or `None`.

        Containment is re-checked after `resolve()` rather than trusted from
        the key text, so a symlink planted under one project that points into
        another (or outside the root entirely) is caught too — `resolve()`
        follows links, `is_relative_to` then rejects the result.
        """
        try:
            candidate = (self._root / ref.key).resolve()
            project_root = self._project_dir(project_id).resolve()
        except (OSError, ValueError, RuntimeError):
            # Unresolvable keys (NUL bytes, over-long names, symlink loops)
            # are indistinguishable from "does not exist" to the caller.
            return None
        if not candidate.is_relative_to(project_root):
            return None
        return candidate

    def _resolve_ref(self, project_id: ProjectId, ref: PayloadRef) -> Path:
        """`get()`'s form: validates driver/shape/project prefix (before any
        I/O), then containment, raising the uniform `NotFound` for all of
        them — cross-project, traversal, and absent are one answer by design.
        """
        require_project_prefix(
            ref, driver=_DRIVER, project_segment=self._project_segment(project_id)
        )
        path = self._contained_path(project_id, ref)
        if path is None:
            raise NotFound("trace payload not found")
        return path

    def put(
        self, project_id: ProjectId, run_id: RunId, first_seq: int, payload: bytes
    ) -> PayloadRef:
        path = self._object_path(project_id, run_id, first_seq)
        path.parent.mkdir(parents=True, exist_ok=True)
        # Write-then-rename: a reader (or a crash) never observes a truncated
        # envelope, which would decrypt as a tombstone and be indistinguishable
        # from a real erasure.
        tmp = path.with_name(f"{path.name}.{os.getpid()}.tmp")
        tmp.write_bytes(payload)
        os.replace(tmp, path)
        key = f"{project_id}/{run_id}/{first_seq:08d}{_SUFFIX}"
        return PayloadRef(driver="fs", key=key)

    def get(self, project_id: ProjectId, ref: PayloadRef) -> bytes:
        path = self._resolve_ref(project_id, ref)
        try:
            return path.read_bytes()
        except OSError as exc:
            # Absent, a directory, or unreadable — all one answer. Any other
            # mapping would hand a caller an existence oracle for keys it is
            # allowed to name but not allowed to read (leak probe 2).
            raise NotFound("trace payload not found") from exc

    def exists(self, project_id: ProjectId, ref: PayloadRef) -> bool:
        if not ref_matches_project(
            ref, driver=_DRIVER, project_segment=self._project_segment(project_id)
        ):
            return False
        path = self._contained_path(project_id, ref)
        return path is not None and path.is_file()

    def delete_project(self, project_id: ProjectId) -> int:
        proj_dir = self._project_dir(project_id)
        if not proj_dir.is_dir():
            return 0
        count = 0
        # Every regular file, not only `*.tbz`: a partial `.tmp` from an
        # interrupted put() is still this project's data, and project deletion
        # must not leave a readable remnant behind (PLAN.md §5 erasure).
        for obj in list(proj_dir.rglob("*")):
            if obj.is_file() or obj.is_symlink():
                obj.unlink()
                if obj.suffix == _SUFFIX:
                    count += 1
        # Remove now-empty subdirectories bottom-up, then the project dir
        # itself — O(objects), no partial-drop half-state left behind.
        for d in sorted(
            (p for p in proj_dir.rglob("*") if p.is_dir()), key=lambda p: -len(p.parts)
        ):
            with contextlib.suppress(OSError):
                d.rmdir()
        with contextlib.suppress(OSError):
            proj_dir.rmdir()
        return count
