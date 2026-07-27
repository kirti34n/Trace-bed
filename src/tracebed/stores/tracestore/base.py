"""Shared ref-validation for `TraceStorePort` drivers (`fs.py`, `s3.py`).

Not itself named in PHASE0-CONTRACT.md §6.3's file table, but both drivers
need the identical "does this ref belong to the caller's project" check
enforced BEFORE any I/O — the leak-suite's cross-project by-id probe
(invariant 4) requires a `get()` on another project's ref to 404 without
touching the network or filesystem, and `exists()` (whose return type is
plain `bool`, not an exception) to answer `False` the same way. Factored
here once so neither check can drift between the two drivers.

A prefix comparison ALONE is not that check. `PayloadRef.key` reaches these
drivers from `trace_index.payload_ref`, which is a text column — an attacker
who can influence it (or a caller who hand-builds a ref) can present
`"{their_project}/../{victim_project}/{run}/00000000.tbz"`, which starts with
their own project prefix and yet resolves into another tenant's data on BOTH
drivers: `Path.resolve()` collapses `..` on the fs driver, and `httpx` (RFC
3986 dot-segment removal) collapses it in the URL on the s3 driver. So the
prefix test is paired here with a structural key test that rejects relative
segments outright, and the fs driver additionally re-checks containment
against the resolved project directory (symlinks included).
"""

from __future__ import annotations

from typing import Final, Literal

from tracebed.domain.errors import NotFound
from tracebed.stores.tracestore import PayloadRef

__all__ = ["MAX_KEY_LEN", "is_safe_key", "ref_matches_project", "require_project_prefix"]

# A trace-store key is `{project}/{run}/{08d}.tbz` or `{bucket}/tb/{project}/
# {run}/{08d}` — well under 256 chars. The cap bounds work done on a
# caller-influenced string before anything else looks at it.
MAX_KEY_LEN: Final = 512

_FORBIDDEN_SEGMENTS: Final = frozenset({"", ".", ".."})


def is_safe_key(key: str) -> bool:
    """True iff `key` is a plain relative POSIX-style object key.

    Rejects: empty keys, keys over `MAX_KEY_LEN`, absolute keys, backslashes
    (a Windows path separator that `Path` honours but a prefix comparison
    does not), embedded NULs (which make `Path.resolve()` raise instead of
    return), and any empty / `.` / `..` segment. The `..` rejection is the
    load-bearing one: it is what stops a ref that passes the project-prefix
    test from resolving into another project (invariant 4).
    """
    if not key or len(key) > MAX_KEY_LEN:
        return False
    if "\\" in key or "\x00" in key or key.startswith("/"):
        return False
    segments = key.split("/")
    if ":" in segments[0]:  # a Windows drive letter or a smuggled URL scheme
        return False
    return all(segment not in _FORBIDDEN_SEGMENTS for segment in segments)


def ref_matches_project(
    ref: PayloadRef, *, driver: Literal["fs", "s3"], project_segment: str
) -> bool:
    """True iff `ref` is this driver's, structurally safe, and under the
    caller's project prefix.

    `project_segment` is computed by the caller from its own key layout (fs:
    `"{project_id}/"`; s3: `"{bucket}/tb/{project_id}/"`) from the CALLER's
    resolved `ProjectId` — this function carries no layout knowledge itself,
    only the three tests, so the invariant holds identically for both drivers
    and there is exactly one place each driver can get it wrong.

    The `driver` test matters because `PayloadRef` is a plain frozen
    dataclass: nothing else stops an `s3://` ref reaching `FsTraceStore`,
    where its `{bucket}/...` first segment would be compared against a
    completely different prefix layout.
    """
    return ref.driver == driver and is_safe_key(ref.key) and ref.key.startswith(project_segment)


def require_project_prefix(
    ref: PayloadRef, *, driver: Literal["fs", "s3"], project_segment: str
) -> None:
    """`get()`'s form: raises `NotFound` instead of returning `False`.

    The message is the uniform one (§9.4 / errors.NotFound): "not yours",
    "malformed", and "does not exist" are deliberately indistinguishable to
    a caller — leak probe 2 asserts exactly that there is no oracle here.
    """
    if not ref_matches_project(ref, driver=driver, project_segment=project_segment):
        raise NotFound("trace payload not found")
