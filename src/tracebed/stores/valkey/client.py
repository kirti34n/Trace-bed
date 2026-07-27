"""ValkeyClient — the thin, project-scoped wrapper over valkey-py.

PHASE0-CONTRACT.md §7 / PLAN.md §5. Mirrors `stores.pg.pool.scoped`'s shape
by design: every public method takes `ProjectId` first and reaches Valkey
only through a key built by `stores.valkey.keys` — there is no accessor that
reads or writes a bare, caller-supplied key string. `keys.py` is the only
module allowed to contain a `tb` key-prefix literal (`scripts/raw_sql_lint.py`
enforces this for the whole source tree); this module never constructs one
itself, it only calls the builders and hands the result to valkey-py.

The connection is injected, not constructed in `__init__` (`from_url` is the
named site that builds a real one). There is no Valkey on the build machine
(contract §12), so a class that could only ever hold a real `Valkey` would be
a class that could never be tested — and the batching in `delete_project`,
the TTL enforcement, and the response narrowing below are exactly the logic
that must not ship unexercised.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from typing import Protocol, Self, cast

from valkey import Valkey

from tracebed.domain.ids import AgentTypeId, ProjectId, RunId
from tracebed.stores.valkey.keys import (
    current_prefix_version_key,
    project_key_pattern,
    static_prefix_key,
    tool_cache_key,
    working_memory_key,
)

__all__ = ["ValkeyClient", "ValkeyCommands"]

# Client-side batch size for the SCAN sweep in delete_project. Valkey's SCAN
# is already cursor-based/incremental server-side (it never blocks like
# KEYS); this only bounds how many keys we accumulate before issuing one
# UNLINK round-trip, so a large project doesn't hold an ever-growing Python
# list for the whole sweep.
_SCAN_BATCH = 500


class ValkeyCommands(Protocol):
    """Exactly the five commands this module uses.

    Narrowing the surface here is what lets `delete_project`'s sweep be
    tested against an in-memory double instead of only against a server this
    machine does not have.
    """

    def get(self, name: str) -> object: ...

    def set(self, name: str, value: bytes, ex: int | None = ...) -> object: ...

    def unlink(self, *names: str | bytes) -> object: ...

    def scan_iter(self, match: str, count: int) -> Iterator[str | bytes]: ...

    def close(self) -> None: ...


def _require_ttl(ttl_seconds: object) -> int:
    """Every value this module writes must expire.

    `delete_project` is the only other reaper, and it runs on project
    deletion — a key written without a TTL therefore outlives the run,
    the session, and the cache generation that produced it, and grows the
    keyspace without bound. An optional TTL defaulting to None makes
    "never expires" the value you get by forgetting, which is why the
    setters below take it as a required, validated argument.
    """
    # bool is an int subclass; `ttl_seconds=True` would silently mean 1s.
    if isinstance(ttl_seconds, bool) or not isinstance(ttl_seconds, int):
        raise TypeError(f"ttl_seconds: expected int, got {type(ttl_seconds).__name__}")
    if ttl_seconds <= 0:
        # Valkey rejects EX <= 0 at the wire ("invalid expire time"); failing
        # here names the caller instead of surfacing as an opaque ResponseError.
        raise ValueError("ttl_seconds: must be positive")
    return ttl_seconds


def _as_value(raw: object) -> bytes | None:
    """Narrow a GET response to the type this module promises its callers.

    valkey-py types every command as `Awaitable[Any] | Any` because one class
    backs both the sync and async clients. Casting that to `bytes | None`
    would be an assertion; checking it is a check — and it is what turns a
    misconfigured client (`decode_responses=True`, an async client passed in
    by mistake) into a named error rather than a `str` leaking out of a
    `bytes`-typed accessor into a caller that will index it as bytes.
    """
    if raw is None:
        return None
    if isinstance(raw, bytes):
        return raw
    raise TypeError(f"valkey returned {type(raw).__name__}, expected bytes (decode_responses off)")


class ValkeyClient:
    """Every public method is `ProjectId`-scoped; every key it touches is
    built by `stores.valkey.keys`, never inline here. No unscoped accessor
    is exported (contract §7, invariant 4 — "the wall covers every key in
    every store")."""

    def __init__(self, client: ValkeyCommands) -> None:
        self._client = client

    @classmethod
    def from_url(cls, url: str) -> Self:
        # The one site that builds a real connection. valkey-py is lazy — no
        # socket opens until the first command — so constructing this at
        # import/wiring time does not violate contract §12's "connecting at
        # collection time is forbidden".
        return cls(cast("ValkeyCommands", Valkey.from_url(url)))

    def close(self) -> None:
        self._client.close()

    # -- tool cache ----------------------------------------------------- #

    def tool_cache_get(
        self,
        project_id: ProjectId,
        *,
        tool_id: str,
        tool_version: str,
        auth_context_fingerprint: str,
        args: Mapping[str, object],
    ) -> bytes | None:
        """Returns the cached result, or None on a miss. `auth_context_fingerprint`
        must be the caller's own fingerprint — passing another caller's would
        be the confused-deputy hole `tool_cache_key` exists to prevent
        (keys.py docstring)."""
        key = tool_cache_key(
            project_id,
            tool_id=tool_id,
            tool_version=tool_version,
            auth_context_fingerprint=auth_context_fingerprint,
            args=args,
        )
        return _as_value(self._client.get(key))

    def tool_cache_set(
        self,
        project_id: ProjectId,
        *,
        tool_id: str,
        tool_version: str,
        auth_context_fingerprint: str,
        args: Mapping[str, object],
        value: bytes,
        ttl_seconds: int,
    ) -> None:
        key = tool_cache_key(
            project_id,
            tool_id=tool_id,
            tool_version=tool_version,
            auth_context_fingerprint=auth_context_fingerprint,
            args=args,
        )
        self._client.set(key, value, ex=_require_ttl(ttl_seconds))

    # -- working memory --------------------------------------------------- #

    def working_memory_get(self, project_id: ProjectId, run_id: RunId, key: str) -> bytes | None:
        return _as_value(self._client.get(working_memory_key(project_id, run_id, key)))

    def working_memory_set(
        self,
        project_id: ProjectId,
        run_id: RunId,
        key: str,
        value: bytes,
        *,
        ttl_seconds: int,
    ) -> None:
        self._client.set(
            working_memory_key(project_id, run_id, key), value, ex=_require_ttl(ttl_seconds)
        )

    def working_memory_delete(self, project_id: ProjectId, run_id: RunId, key: str) -> None:
        self._client.unlink(working_memory_key(project_id, run_id, key))

    # -- static prefix ------------------------------------------------------ #

    def static_prefix_get(
        self, project_id: ProjectId, agent_type_id: AgentTypeId, prefix_version: int
    ) -> bytes | None:
        return _as_value(
            self._client.get(static_prefix_key(project_id, agent_type_id, prefix_version))
        )

    def static_prefix_set(
        self,
        project_id: ProjectId,
        agent_type_id: AgentTypeId,
        prefix_version: int,
        value: bytes,
        *,
        ttl_seconds: int,
    ) -> None:
        self._client.set(
            static_prefix_key(project_id, agent_type_id, prefix_version),
            value,
            ex=_require_ttl(ttl_seconds),
        )

    def current_prefix_version_get(
        self, project_id: ProjectId, agent_type_id: AgentTypeId
    ) -> int | None:
        """Which `static_prefix_set` version is live, or `None` if none is.

        A reader holding only a `ProjectScope` cannot derive the content-hashed
        `prefix_version` (see `keys.current_prefix_version_key`), so this is
        the entry point to the cache; without it the block that
        `workers.prefix_builder` publishes is unreachable.

        A pointer whose stored bytes are not a non-negative decimal integer is
        reported as "no current version" rather than raised on: the caller is
        `hotpath`, on the degradation ladder's prefix-only rung, and a corrupt
        pointer must degrade to an empty prefix exactly like a cache miss —
        the next builder run repairs it. `_as_value` still raises for a
        misconfigured CLIENT (a `str` from `decode_responses=True`), which is a
        deployment fault, not a cache-content fault.
        """
        raw = _as_value(self._client.get(current_prefix_version_key(project_id, agent_type_id)))
        if raw is None:
            return None
        try:
            text = raw.decode("ascii")
        except UnicodeDecodeError:
            return None
        # `str.isdigit()` before `int()`: int() accepts leading "+"/"-",
        # surrounding whitespace, and underscores ("1_0" -> 10), each of which
        # would resolve a pointer to a version no writer ever published.
        if not text.isdigit():
            return None
        return int(text)

    def current_prefix_version_set(
        self,
        project_id: ProjectId,
        agent_type_id: AgentTypeId,
        prefix_version: int,
        *,
        ttl_seconds: int,
    ) -> None:
        """Repoint this agent type at a version already written by
        `static_prefix_set`. Publish in that order: a pointer written first
        names a block that is not there yet, which is a hard miss on the one
        rung of the ladder that exists to avoid one.

        `static_prefix_key`'s own validation is reused for `prefix_version`
        (bool rejection, non-negative, int) by building the key and discarding
        it, so the pointer can never name a version the block key could not
        have been written under.
        """
        static_prefix_key(project_id, agent_type_id, prefix_version)
        self._client.set(
            current_prefix_version_key(project_id, agent_type_id),
            str(prefix_version).encode("ascii"),
            ex=_require_ttl(ttl_seconds),
        )

    # -- project lifecycle -------------------------------------------------- #

    def delete_project(self, project_id: ProjectId) -> int:
        """Removes every key under the project's namespace; returns the
        count removed. This is what the `cache_flush` invalidation event
        (Phase 1) and project deletion both route through — SCAN+UNLINK over
        `project_key_pattern`, the identical namespace every builder in
        `keys.py` writes under and the one leak probe 6 sweeps, so "every
        key this project owns" has exactly one definition across flush,
        deletion, and audit.

        The count is of keys UNLINK actually removed, not of keys SCAN
        returned: SCAN may yield the same key twice when the keyspace
        rehashes mid-cursor, and UNLINK reports 0 for an already-removed
        key, so the two differ and only the former is a truthful answer to
        "how much did this erase".
        """
        pattern = project_key_pattern(project_id)
        removed = 0
        batch: list[str | bytes] = []
        for scanned in self._client.scan_iter(match=pattern, count=_SCAN_BATCH):
            batch.append(scanned)
            if len(batch) >= _SCAN_BATCH:
                removed += self._unlink(batch)
                batch.clear()
        if batch:
            removed += self._unlink(batch)
        return removed

    def _unlink(self, names: list[str | bytes]) -> int:
        count = self._client.unlink(*names)
        if isinstance(count, bool) or not isinstance(count, int):
            # A deletion sweep that cannot count what it deleted must not
            # report a plausible number; erasure evidence is the product.
            raise TypeError(f"valkey UNLINK returned {type(count).__name__}, expected int")
        return count
