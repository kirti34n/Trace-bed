"""The tool-result cache: `cache.ttl_class` map (PLAN.md §5 key spec, §6 `cache.*`).

Builds on `stores.valkey.client.ValkeyClient` (the commands) and, through it,
`stores.valkey.keys` (the one module permitted a key-prefix literal) — this
module adds exactly the one thing neither owns: turning a *TTL class name*
("intel", "registry", ...) into a concrete TTL in seconds, read from
`CacheConfig.ttl_class` rather than a literal anywhere in code (hard rule 4 —
every threshold is a config field, never a magic number).

`ValkeyClient.tool_cache_get`/`tool_cache_set` already require
`auth_context_fingerprint` as a keyword-only argument with no default —
`stores.valkey.keys.tool_cache_key`'s docstring explains why: a missing
fingerprint would serve one caller's cached tool result to a caller with
different privilege on the same tool (the confused-deputy hole the key
format's fingerprint segment exists to close). `ToolCache` below is a thin
wrapper around those two calls and therefore inherits the same signature —
there is no path through this class that reaches Valkey without a real
fingerprint, because there is no path through `ValkeyClient` that does
either, and this module adds no default of its own.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Final

from tracebed.domain.config import CacheConfig
from tracebed.domain.ids import ProjectId
from tracebed.stores.valkey.client import ValkeyClient

__all__ = ["ToolCache", "resolve_ttl_class"]

# `cache.ttl_class` values are documented (PLAN.md §6) as simple durations:
# "24h", "14d". Only the two units the shipped defaults use are accepted —
# an unrecognised unit is a config error that must fail loudly at the call
# site, not silently round to zero or forever.
#
# `\Z`, not `$`: in Python `$` also matches immediately before a trailing
# newline, so `"24h\n"` — a value that arrives that way from a mounted
# config file or a here-doc env var — would parse under `$` and the anchor
# would not be the anchor this comment claims. `[0-9]`, not `\d`, for the
# same reason in the other direction: `\d` matches every Unicode decimal
# digit, so a fullwidth or Arabic-Indic numeral would silently become a TTL.
_DURATION: Final = re.compile(r"^(?P<qty>[0-9]+)(?P<unit>[hd])\Z")
_UNIT_SECONDS: Final[Mapping[str, int]] = {"h": 3600, "d": 86400}


def resolve_ttl_class(ttl_class: str, cfg: CacheConfig) -> int:
    """Resolves a `cache.ttl_class` name to a TTL in seconds.

    Raises `ValueError` for a `ttl_class` this `CacheConfig` does not define,
    or for a configured duration that does not parse as `<int><h|d>` — either
    is an operator-facing config mistake (a typo'd class name, a hand-edited
    override with a bad unit) and must surface as a named error at the call
    site rather than as a cache entry with a silently wrong lifetime.
    """
    try:
        raw = cfg.ttl_class[ttl_class]
    except KeyError:
        raise ValueError(
            f"unknown cache.ttl_class {ttl_class!r}; configured classes: "
            f"{sorted(cfg.ttl_class)}"
        ) from None
    match = _DURATION.match(raw)
    if match is None:
        raise ValueError(
            f"cache.ttl_class[{ttl_class!r}] = {raw!r} is not of the form '<int><h|d>'"
        )
    seconds = int(match["qty"]) * _UNIT_SECONDS[match["unit"]]
    if seconds <= 0:
        # "0h" parses. This function is exported, so the zero it would return
        # travels to whatever store the caller hands it to — and a TTL of 0 is
        # either rejected at the wire or, in a store without its own guard, a
        # key with no expiry at all. `ValkeyClient._require_ttl` catches it one
        # layer down, but it names `ttl_seconds`; the operator needs to be
        # pointed at the config field that is actually wrong.
        raise ValueError(
            f"cache.ttl_class[{ttl_class!r}] = {raw!r} must be a positive duration"
        )
    return seconds


class ToolCache:
    """Project-scoped tool-result cache, TTL'd by `cache.ttl_class` name.

    Every accessor takes `project_id` first (invariant 4) and
    `auth_context_fingerprint` as a required keyword-only argument with no
    default (module docstring) — there is no call shape that reaches Valkey
    without both.
    """

    def __init__(self, client: ValkeyClient, cfg: CacheConfig) -> None:
        self._client = client
        self._cfg = cfg

    def get(
        self,
        project_id: ProjectId,
        *,
        tool_id: str,
        tool_version: str,
        auth_context_fingerprint: str,
        args: Mapping[str, object],
    ) -> bytes | None:
        """Returns the cached result for this exact
        (tool, version, args, caller-privilege) tuple, or `None` on a miss.

        `auth_context_fingerprint` must be the CALLING principal's own
        fingerprint. Passing another caller's is precisely the
        confused-deputy read this cache's key format exists to prevent — a
        fingerprint borrowed from a higher-privilege caller would return
        that caller's cached result to a lower-privilege one.
        """
        return self._client.tool_cache_get(
            project_id,
            tool_id=tool_id,
            tool_version=tool_version,
            auth_context_fingerprint=auth_context_fingerprint,
            args=args,
        )

    def set(
        self,
        project_id: ProjectId,
        *,
        tool_id: str,
        tool_version: str,
        auth_context_fingerprint: str,
        args: Mapping[str, object],
        value: bytes,
        ttl_class: str,
    ) -> None:
        """Caches `value`, expiring it after `cache.ttl_class[ttl_class]`.

        `ttl_class` selects the lifetime from config (e.g. "intel" -> 24h,
        "registry" -> 14d) rather than taking a raw second count — the
        source-freshness policy for a *kind* of tool result lives in one
        config field (`CacheConfig.ttl_class`), not scattered across call
        sites re-deriving seconds from hours by hand.
        """
        ttl_seconds = resolve_ttl_class(ttl_class, self._cfg)
        self._client.tool_cache_set(
            project_id,
            tool_id=tool_id,
            tool_version=tool_version,
            auth_context_fingerprint=auth_context_fingerprint,
            args=args,
            value=value,
            ttl_seconds=ttl_seconds,
        )
