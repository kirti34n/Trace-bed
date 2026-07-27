"""TraceStorePort — the object-storage abstraction over trace payload blobs.

PHASE0-CONTRACT.md §6.3 (PHASE-0 Task 11). C-16: the port speaks opaque
`bytes`, never `EncryptedPayload` — that conversion happens in
`ingest.trace_writer` — so `tracebed.crypto` never appears in the
`stores.*` import graph and `purity_check.py`'s hotpath-purity gate
(invariant 1) has nothing to trip over here even though `hotpath/` may
import `stores.*`.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Protocol

from tracebed.domain.ids import ProjectId, RunId

__all__ = ["PayloadRef", "TraceStorePort"]

_DRIVER_PREFIXES: dict[str, Literal["fs", "s3"]] = {"fs://": "fs", "s3://": "s3"}


@dataclass(frozen=True, slots=True)
class PayloadRef:
    """A driver-opaque pointer to one stored trace-payload object.

    `key` always embeds `project_id` — the invariant-4 "every key in every
    store" rule extends to the trace store, and it is what lets `get()`
    reject a cross-project ref by string comparison alone, before any
    network or filesystem call. Fixed layouts (PHASE0-CONTRACT.md §6.3):
    fs `{project_id}/{run_id}/{first_seq:08d}.tbz`; s3 `{bucket}/tb/
    {project_id}/{run_id}/{first_seq:08d}` — the bucket is folded into `key`
    itself so `__str__` alone reproduces `"s3://{bucket}/{key}"` without a
    second dataclass field (this dataclass has exactly the two fields the
    contract specifies: `driver`, `key`).
    """

    driver: Literal["fs", "s3"]
    key: str

    def __str__(self) -> str:
        return f"{self.driver}://{self.key}"

    @classmethod
    def parse(cls, ref: str) -> PayloadRef:
        for prefix, driver in _DRIVER_PREFIXES.items():
            if ref.startswith(prefix):
                return cls(driver=driver, key=ref[len(prefix) :])
        raise ValueError(f"PayloadRef.parse: unrecognised ref {ref!r}")


class TraceStorePort(Protocol):
    """Host-implements port (PLAN.md §3 Ports table): object storage for
    traces. Shipped defaults: filesystem (`fs.py`) and generic S3
    (`s3.py`, SeaweedFS primary target, legacy-MinIO compatible)."""

    def put(
        self, project_id: ProjectId, run_id: RunId, first_seq: int, payload: bytes
    ) -> PayloadRef: ...

    def get(self, project_id: ProjectId, ref: PayloadRef) -> bytes:
        """Raises `NotFound` on a missing object AND on a ref outside the
        caller's project prefix — checked BEFORE any network call (the
        leak-suite's cross-project by-id probe, invariant 4)."""
        ...

    def exists(self, project_id: ProjectId, ref: PayloadRef) -> bool: ...

    def delete_project(self, project_id: ProjectId) -> int:
        """Removes every object under the project's prefix; returns the
        count of objects removed."""
        ...
