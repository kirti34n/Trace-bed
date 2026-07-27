"""Valkey key builders — the only module permitted to contain a `tb:` literal.

PHASE0-CONTRACT.md §7 (C-17), PLAN.md §5 "Tool-cache key spec". Invariant 4
("the wall covers every key in every store", PLAN.md §2) does not stop at
Postgres — every Valkey key must embed `project_id`, and every builder below
takes `ProjectId` as its first parameter with no default, so there is no call
shape that produces a key without a project scope. `scripts/raw_sql_lint.py`
enforces the static half of that claim: no other module under `src/` may
contain a `tb:` string literal.

`auth_context_fingerprint` on `tool_cache_key` is not decoration. Two callers
in the same project can carry different privilege (different principals,
different scopes on the tool being cached); without the fingerprint in the
hash input, a tool result cached under one caller's auth context would be
served verbatim to a lower-privileged caller who supplied identical
`tool_id`/`tool_version`/`args` — a confused-deputy hole. The parameter is
keyword-only, has no default, and is rejected when empty: there is no call
shape that produces a tool-cache key without a real auth context in it.

C-17 fixes the hash input as 0x1F-joined fields. A join is only a faithful
encoding of a tuple if no field can contain the separator — otherwise
`("a\\x1fb", "c")` and `("a", "b\\x1fc")` join to the identical string and
hash to the identical key, which is a cache-poisoning primitive across
`tool_id`/`tool_version` and (given a separator-bearing fingerprint) across
the privilege boundary the fingerprint exists to draw. `_require_field`
below ENFORCES that precondition rather than asserting it in prose, so the
join is injective on every input this module accepts. Rejecting is the
right failure: no legitimate tool identifier, version, or fingerprint
contains a C0 unit separator.

`canonical_args` (`domain/canonical.py`) is the same function that feeds
`content_hash` elsewhere, so this key and the content hash can never
disagree about what "canonical" means for the same mapping (contract §2).
It is also why the trailing field needs no separate guard: `json.dumps`
escapes every C0 control character (`\\u001f`) regardless of `ensure_ascii`,
so canonical JSON is separator-free by construction.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Final

from tracebed.domain.canonical import canonical_args, sha256_hex
from tracebed.domain.ids import AgentTypeId, ProjectId, RunId

__all__ = [
    "current_prefix_version_key",
    "project_key_pattern",
    "static_prefix_key",
    "tool_cache_key",
    "working_memory_key",
]

# Unit separator (0x1F, ASCII "information separator one"): joins the
# tool-cache hash input fields (C-17). `_require_field` rejects it in every
# caller-supplied field so the join cannot be re-segmented — "a\x1fb" + "c"
# and "a" + "b\x1fc" must never hash the same.
_RS: Final[str] = "\x1f"

# Caps every caller-supplied string that reaches a key. Two distinct jobs:
# `working_memory_key`'s `key` lands VERBATIM in the Valkey keyspace, so an
# unbounded one is attacker-controlled allocation in the server's dict, not
# just in this process; the tool-cache fields are hashed to a fixed 64 hex
# chars, so the cap there bounds only the transient join. No real tool id,
# version, fingerprint, or scratch key approaches this.
_MAX_FIELD_LEN: Final[int] = 512


def _require(value: object, expected: type, label: str) -> None:
    # mypy --strict is the build-time gate on every call site we control;
    # this is the runtime backstop for a caller that reaches this module
    # through an `Any`-typed edge (mirrors `stores.pg.pool.scoped`'s guard
    # for the identical reason — invariant 4 must hold even where a type
    # checker can't see the call). TypedId subclasses are siblings, never
    # subclasses of one another, so a RunId fails an `expected=ProjectId`
    # check here instead of silently scoping a key to the wrong wall.
    if not isinstance(value, expected):
        raise TypeError(f"{label}: expected {expected.__name__}, got {type(value).__name__}")


def _require_field(value: object, label: str, *, allow_empty: bool) -> str:
    """The separator-freedom and length guard the joined key format assumes."""
    if not isinstance(value, str):
        raise TypeError(f"{label}: expected str, got {type(value).__name__}")
    if not allow_empty and not value:
        raise ValueError(f"{label}: must not be empty")
    if len(value) > _MAX_FIELD_LEN:
        raise ValueError(f"{label}: exceeds {_MAX_FIELD_LEN} characters")
    if _RS in value:
        # Without this the join is not injective and two different logical
        # tuples share one cache entry (see module docstring).
        raise ValueError(f"{label}: must not contain the 0x1F field separator")
    return value


def tool_cache_key(
    project_id: ProjectId,
    *,
    tool_id: str,
    tool_version: str,
    auth_context_fingerprint: str,
    args: Mapping[str, object],
) -> str:
    """``tb:{project_id}:tc:{sha256(project_id RS tool_id RS tool_version RS
    auth_context_fingerprint RS canonical_args(args))}`` (PLAN.md §5, C-17).

    Identical `tool_id`/`tool_version`/`args` in two different projects
    produce different keys because `project_id` is both the first field
    hashed *and* the key's literal prefix — the hash alone is never the
    isolation boundary, the prefix is. Reordering the keys of `args` cannot
    change the result (`canonical_args` sorts); changing any value in `args`
    always does.

    Raises ValueError if any field contains the 0x1F separator (which would
    make the join ambiguous) or if `auth_context_fingerprint` is empty (an
    empty fingerprint is one shared bucket for every privilege level in the
    project — the confused-deputy hole with the guard nominally in place).
    """
    _require(project_id, ProjectId, "project_id")
    joined = _RS.join(
        (
            str(project_id),
            _require_field(tool_id, "tool_id", allow_empty=True),
            _require_field(tool_version, "tool_version", allow_empty=True),
            _require_field(
                auth_context_fingerprint, "auth_context_fingerprint", allow_empty=False
            ),
            canonical_args(args).decode("utf-8"),
        )
    )
    digest = sha256_hex(joined.encode("utf-8"))
    return f"tb:{project_id}:tc:{digest}"


def working_memory_key(project_id: ProjectId, run_id: RunId, key: str) -> str:
    """``tb:{project_id}:wm:{run_id}:{key}`` (PLAN.md §5).

    `key` is caller-chosen and lands unhashed in the keyspace, so it is
    length-capped here. It cannot forge across a run or a project however
    long it is: `project_id` and `run_id` are both fixed-width canonical
    UUID strings at fixed offsets, so the segment `key` occupies begins at
    the same index for every call and nothing `key` contains can shift it.
    """
    _require(project_id, ProjectId, "project_id")
    _require(run_id, RunId, "run_id")
    _require_field(key, "key", allow_empty=True)
    return f"tb:{project_id}:wm:{run_id}:{key}"


def static_prefix_key(project_id: ProjectId, agent_type_id: AgentTypeId, prefix_version: int) -> str:
    """``tb:{project_id}:px:{agent_type_id}:{prefix_version}`` (PLAN.md §5)."""
    _require(project_id, ProjectId, "project_id")
    _require(agent_type_id, AgentTypeId, "agent_type_id")
    # bool is an int subclass, and `True` would render as "px:...:True" — a
    # key no version number can ever produce, i.e. a silent cache partition.
    if isinstance(prefix_version, bool) or not isinstance(prefix_version, int):
        raise TypeError(f"prefix_version: expected int, got {type(prefix_version).__name__}")
    if prefix_version < 0:
        raise ValueError("prefix_version: must not be negative")
    return f"tb:{project_id}:px:{agent_type_id}:{prefix_version}"


def current_prefix_version_key(project_id: ProjectId, agent_type_id: AgentTypeId) -> str:
    """``tb:{project_id}:pxcur:{agent_type_id}`` — the pointer naming which
    `static_prefix_key` version is live for this agent type.

    Not in PLAN.md §5's three-line key spec, and added deliberately: without
    it the static prefix cache is WRITE-ONLY. `workers.prefix_builder` derives
    `prefix_version` from the packed content, and `hotpath.pipeline`'s
    `StaticPrefixPort.get(scope)` receives only (project_id, agent_type_id,
    principal_id) — a content-derived version is by construction not
    computable by a reader that does not already hold the content it is trying
    to fetch, and `ValkeyClient` exposes no pattern scan a reader could use to
    go looking. One indirection resolves it: the builder publishes the block
    under the versioned key, then repoints this key at that version, so a
    reader does GET pointer -> GET block.

    Deliberately a separate key rather than a wider `px:` value: the versioned
    key stays immutable and content-addressed (two readers resolving the same
    version can never disagree about the bytes), and rebuilding under a new
    version leaves the old block readable for any request already mid-flight
    until its own TTL expires. It shares the `tb:{project_id}:` prefix, so
    `project_key_pattern` — and therefore `delete_project`, `cache_flush`, and
    leak probe 6 — already covers it with no change.
    """
    _require(project_id, ProjectId, "project_id")
    _require(agent_type_id, AgentTypeId, "agent_type_id")
    return f"tb:{project_id}:pxcur:{agent_type_id}"


def project_key_pattern(project_id: ProjectId) -> str:
    """``tb:{project_id}:*`` — the namespace-scoped SCAN pattern a project's
    keys are flushed and swept through (contract §7; leak-suite probe 6;
    `ValkeyClient.delete_project`). Every key any builder above produces
    starts with exactly this prefix, so "every key this project owns" has
    one definition, shared by flush and by the leak probe that audits it.
    """
    _require(project_id, ProjectId, "project_id")
    return f"tb:{project_id}:*"
