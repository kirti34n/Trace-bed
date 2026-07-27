"""PHASE0-CONTRACT.md §7 — `stores.valkey.keys`: the only `tb:` construction site.

Pure key-string tests, no Valkey server needed (contract §13.2: "key formats;
distinct projects → distinct keys; pattern shape (pure — no valkey needed)").
Backs invariant 4 ("the wall covers every key in every store", PLAN.md §2):
these assert the isolation and confused-deputy properties the leak suite's
Valkey key-collision probe (probe 6) later exercises against a live server.
"""

from __future__ import annotations

import pytest

from tracebed.domain.ids import AgentTypeId, ProjectId, RunId, uuid7
from tracebed.stores.valkey.keys import (
    current_prefix_version_key,
    project_key_pattern,
    static_prefix_key,
    tool_cache_key,
    working_memory_key,
)

pytestmark = pytest.mark.phase0

_PROJECT_A = ProjectId.parse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
_PROJECT_B = ProjectId.parse("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")
_AGENT = AgentTypeId.parse("55555555-5555-5555-5555-555555555555")
_RUN = RunId.parse("77777777-7777-7777-7777-777777777777")


def _tool_key(project_id: ProjectId, **overrides: object) -> str:
    kwargs: dict[str, object] = {
        "tool_id": "stripe.charge",
        "tool_version": "1.2.3",
        "auth_context_fingerprint": "fp-alice",
        "args": {"amount": 500, "currency": "usd"},
    }
    kwargs.update(overrides)
    return tool_cache_key(project_id, **kwargs)  # type: ignore[arg-type]


# --------------------------------------------------------------------------- #
# tool_cache_key — isolation, confused-deputy, canonicalisation
# --------------------------------------------------------------------------- #


def test_tool_cache_key_shape() -> None:
    key = _tool_key(_PROJECT_A)
    prefix, digest = key.rsplit(":", 1)
    assert prefix == f"tb:{_PROJECT_A}:tc"
    assert len(digest) == 64  # sha256 hex
    assert all(c in "0123456789abcdef" for c in digest)


def test_tool_cache_key_differs_across_projects_for_identical_args() -> None:
    # Invariant 4's Valkey key-collision probe, offline half: the exact same
    # tool_id/tool_version/fingerprint/args in two projects must not collide.
    key_a = _tool_key(_PROJECT_A)
    key_b = _tool_key(_PROJECT_B)
    assert key_a != key_b
    assert key_a.startswith(f"tb:{_PROJECT_A}:")
    assert key_b.startswith(f"tb:{_PROJECT_B}:")
    # And the hash tail itself differs — project_id is hashed, not just
    # prefixed, so a stripped prefix still can't be replayed cross-project.
    assert key_a.rsplit(":", 1)[-1] != key_b.rsplit(":", 1)[-1]


def test_tool_cache_key_embeds_its_own_project_id() -> None:
    for project in (_PROJECT_A, _PROJECT_B):
        key = _tool_key(project)
        assert f":{project}:" in key
        other = _PROJECT_B if project is _PROJECT_A else _PROJECT_A
        assert f":{other}:" not in key


def test_tool_cache_key_differs_by_auth_context_fingerprint() -> None:
    # The confused-deputy property: same project/tool/args, different caller
    # privilege context, must never share a cache entry.
    key_alice = _tool_key(_PROJECT_A, auth_context_fingerprint="fp-alice")
    key_bob = _tool_key(_PROJECT_A, auth_context_fingerprint="fp-bob")
    assert key_alice != key_bob


def test_tool_cache_key_requires_auth_context_fingerprint() -> None:
    # No default exists for this parameter — a caller cannot accidentally
    # omit it and get a fingerprint-less (cross-privilege-shared) key.
    with pytest.raises(TypeError):
        tool_cache_key(  # type: ignore[call-arg]
            _PROJECT_A,
            tool_id="stripe.charge",
            tool_version="1.2.3",
            args={},
        )


def test_tool_cache_key_stable_under_args_key_reordering() -> None:
    key_1 = _tool_key(_PROJECT_A, args={"currency": "usd", "amount": 500})
    key_2 = _tool_key(_PROJECT_A, args={"amount": 500, "currency": "usd"})
    assert key_1 == key_2


def test_tool_cache_key_changes_when_an_arg_value_changes() -> None:
    key_1 = _tool_key(_PROJECT_A, args={"amount": 500, "currency": "usd"})
    key_2 = _tool_key(_PROJECT_A, args={"amount": 501, "currency": "usd"})
    assert key_1 != key_2


def test_tool_cache_key_changes_when_tool_id_or_version_changes() -> None:
    base = _tool_key(_PROJECT_A)
    assert base != _tool_key(_PROJECT_A, tool_id="stripe.refund")
    assert base != _tool_key(_PROJECT_A, tool_version="9.9.9")


def test_tool_cache_key_is_deterministic() -> None:
    assert _tool_key(_PROJECT_A) == _tool_key(_PROJECT_A)


def test_tool_cache_key_delimiter_does_not_let_fields_bleed_into_each_other() -> None:
    # The unit-separator join (C-17) exists precisely so an adversarial
    # tool_id/version pair cannot re-segment into a different logical tuple
    # that a printable delimiter (":", "|") would collide on.
    key_1 = tool_cache_key(
        _PROJECT_A,
        tool_id="a:b",
        tool_version="c",
        auth_context_fingerprint="fp",
        args={},
    )
    key_2 = tool_cache_key(
        _PROJECT_A,
        tool_id="a",
        tool_version="b:c",
        auth_context_fingerprint="fp",
        args={},
    )
    assert key_1 != key_2


def test_tool_cache_key_rejects_non_project_id() -> None:
    with pytest.raises(TypeError):
        tool_cache_key(  # type: ignore[arg-type]
            str(_PROJECT_A),
            tool_id="t",
            tool_version="1",
            auth_context_fingerprint="fp",
            args={},
        )


def test_tool_cache_key_rejects_a_sibling_typed_id_as_project_id() -> None:
    # The dangerous confusion is not `str` (mypy catches that everywhere) but
    # another UUID-backed newtype arriving through an `Any` edge. TypedId
    # subclasses are siblings, so isinstance must reject this, not accept it.
    with pytest.raises(TypeError):
        tool_cache_key(  # type: ignore[arg-type]
            _RUN,
            tool_id="t",
            tool_version="1",
            auth_context_fingerprint="fp",
            args={},
        )


# --------------------------------------------------------------------------- #
# tool_cache_key — the joined-hash-input framing must be INJECTIVE.
#
# C-17 fixes the hash input as 0x1F-joined fields. A join only encodes a tuple
# faithfully if no field can carry the separator; if one can, two different
# logical tuples produce one cache entry. These are the tests that fail if the
# separator guard is removed — the ":" -vs- "\x1f" test above does not, because
# it only proves the delimiter is not a *printable* character.
# --------------------------------------------------------------------------- #

_RS = "\x1f"


def test_tool_cache_key_rejects_separator_in_tool_id() -> None:
    with pytest.raises(ValueError, match="separator"):
        _tool_key(_PROJECT_A, tool_id=f"a{_RS}b")


def test_tool_cache_key_rejects_separator_in_tool_version() -> None:
    with pytest.raises(ValueError, match="separator"):
        _tool_key(_PROJECT_A, tool_version=f"1{_RS}2")


def test_tool_cache_key_rejects_separator_in_auth_context_fingerprint() -> None:
    with pytest.raises(ValueError, match="separator"):
        _tool_key(_PROJECT_A, auth_context_fingerprint=f"fp{_RS}admin")


def test_tool_cache_key_field_boundaries_cannot_be_re_segmented() -> None:
    # Without the guard these two calls hash IDENTICALLY: tool_id "a\x1fb"
    # with version "c" joins to the same string as tool_id "a" with version
    # "b\x1fc". That is one cache entry shared by two different tool versions
    # — a poisoning primitive. Both must now be refused outright.
    for kwargs in (
        {"tool_id": f"a{_RS}b", "tool_version": "c"},
        {"tool_id": "a", "tool_version": f"b{_RS}c"},
    ):
        with pytest.raises(ValueError):
            _tool_key(_PROJECT_A, **kwargs)


def test_tool_cache_key_rejects_empty_auth_context_fingerprint() -> None:
    # An empty fingerprint is a single shared bucket for every privilege level
    # in the project: the parameter is present, the separation is not.
    with pytest.raises(ValueError, match="empty"):
        _tool_key(_PROJECT_A, auth_context_fingerprint="")


def test_tool_cache_key_rejects_oversized_fields() -> None:
    for field in ("tool_id", "tool_version", "auth_context_fingerprint"):
        with pytest.raises(ValueError, match="exceeds"):
            _tool_key(_PROJECT_A, **{field: "x" * 513})


def test_tool_cache_key_accepts_fields_at_the_length_cap() -> None:
    # The cap is a boundary, so pin both sides of it: 512 is allowed, 513 is
    # not (above). An off-by-one here silently rejects legitimate callers.
    assert _tool_key(_PROJECT_A, tool_id="x" * 512)


def test_no_project_b_input_can_forge_a_project_a_tool_cache_key() -> None:
    # The adversarial pair, searched rather than assumed: every accepted
    # combination of separator-adjacent and colon-laden field values in
    # project B, against a project-A key built from each of the same
    # combinations. project_id is the literal key prefix AND the first hashed
    # field, so no field content can reach across the wall.
    hostile: list[dict[str, object]] = []
    for tool_id in ("t", "t:tc", f"tb:{_PROJECT_A}:tc", "t\\x1fu", ""):
        for tool_version in ("1", f"1:{_PROJECT_A}", ""):
            for fingerprint in ("fp", f"fp:{_PROJECT_A}:tc"):
                for args in ({}, {"a": 1}, {"a": f"{_PROJECT_A}"}, {f"{_PROJECT_A}": "tc"}):
                    hostile.append(
                        {
                            "tool_id": tool_id,
                            "tool_version": tool_version,
                            "auth_context_fingerprint": fingerprint,
                            "args": args,
                        }
                    )

    keys_a = {_tool_key(_PROJECT_A, **combo) for combo in hostile}
    keys_b = {_tool_key(_PROJECT_B, **combo) for combo in hostile}

    assert len(keys_a) == len(hostile), "distinct inputs collapsed to one key within a project"
    assert not (keys_a & keys_b), "a project-B input forged a project-A key"


# --------------------------------------------------------------------------- #
# working_memory_key — isolation
# --------------------------------------------------------------------------- #


def test_working_memory_key_shape() -> None:
    assert working_memory_key(_PROJECT_A, _RUN, "scratch") == f"tb:{_PROJECT_A}:wm:{_RUN}:scratch"


def test_working_memory_key_differs_across_projects() -> None:
    key_a = working_memory_key(_PROJECT_A, _RUN, "scratch")
    key_b = working_memory_key(_PROJECT_B, _RUN, "scratch")
    assert key_a != key_b


def test_working_memory_key_for_project_a_is_unreachable_from_project_b() -> None:
    # No (run_id, key) input under project B can ever produce a string that
    # equals a project-A working-memory key — the project segment is a fixed,
    # literal field of the format, not something a caller-controlled run_id
    # or key string could forge into.
    target = working_memory_key(_PROJECT_A, _RUN, "scratch")
    candidate_run_ids = [_RUN, RunId(uuid7()), RunId(uuid7())]
    candidate_keys = ["scratch", f"{_PROJECT_A}:wm:{_RUN}:scratch", "..:..:..", ""]
    for run_id in candidate_run_ids:
        for key in candidate_keys:
            assert working_memory_key(_PROJECT_B, run_id, key) != target


def test_working_memory_key_rejects_non_run_id() -> None:
    with pytest.raises(TypeError):
        working_memory_key(_PROJECT_A, str(_RUN), "scratch")  # type: ignore[arg-type]


def test_working_memory_key_rejects_a_sibling_typed_id_as_run_id() -> None:
    with pytest.raises(TypeError):
        working_memory_key(_PROJECT_A, _PROJECT_B, "scratch")  # type: ignore[arg-type]


def test_working_memory_key_rejects_non_str_key() -> None:
    with pytest.raises(TypeError):
        working_memory_key(_PROJECT_A, _RUN, 7)  # type: ignore[arg-type]


def test_working_memory_key_caps_the_caller_chosen_segment() -> None:
    # `key` is the only caller-controlled string that lands VERBATIM in the
    # Valkey keyspace, so an unbounded one is attacker-controlled allocation
    # in the server, not just in this process.
    assert working_memory_key(_PROJECT_A, _RUN, "k" * 512)
    with pytest.raises(ValueError, match="exceeds"):
        working_memory_key(_PROJECT_A, _RUN, "k" * 513)


def test_working_memory_key_segment_offset_is_fixed_for_every_input() -> None:
    # Why no `key` can forge across a run or a project: project_id and run_id
    # are fixed-width canonical UUID strings, so the offset at which `key`
    # begins is identical for every call and nothing `key` contains shifts it.
    prefix = f"tb:{_PROJECT_A}:wm:{_RUN}:"
    for key in ("", "a", "a:b", "*", "tb:x:wm:y:z", "k" * 512):
        built = working_memory_key(_PROJECT_A, _RUN, key)
        assert built.startswith(prefix)
        assert built[len(prefix) :] == key


# --------------------------------------------------------------------------- #
# static_prefix_key
# --------------------------------------------------------------------------- #


def test_static_prefix_key_shape() -> None:
    assert static_prefix_key(_PROJECT_A, _AGENT, 3) == f"tb:{_PROJECT_A}:px:{_AGENT}:3"


def test_static_prefix_key_differs_across_projects() -> None:
    assert static_prefix_key(_PROJECT_A, _AGENT, 1) != static_prefix_key(_PROJECT_B, _AGENT, 1)


def test_static_prefix_key_differs_by_version() -> None:
    assert static_prefix_key(_PROJECT_A, _AGENT, 1) != static_prefix_key(_PROJECT_A, _AGENT, 2)


def test_static_prefix_key_rejects_a_sibling_typed_id_as_agent_type_id() -> None:
    with pytest.raises(TypeError):
        static_prefix_key(_PROJECT_A, _RUN, 1)  # type: ignore[arg-type]


def test_static_prefix_key_rejects_bool_version() -> None:
    # bool is an int subclass: `True` renders as "px:...:True", a partition no
    # real version number can address, so the entry is written and never read.
    with pytest.raises(TypeError):
        static_prefix_key(_PROJECT_A, _AGENT, True)


def test_static_prefix_key_rejects_negative_version() -> None:
    with pytest.raises(ValueError, match="negative"):
        static_prefix_key(_PROJECT_A, _AGENT, -1)


def test_static_prefix_key_rejects_non_int_version() -> None:
    with pytest.raises(TypeError):
        static_prefix_key(_PROJECT_A, _AGENT, "1")  # type: ignore[arg-type]


# --------------------------------------------------------------------------- #
# project_key_pattern
# --------------------------------------------------------------------------- #


# --------------------------------------------------------------------------- #
# current_prefix_version_key
# --------------------------------------------------------------------------- #


def test_current_prefix_version_key_shape() -> None:
    assert current_prefix_version_key(_PROJECT_A, _AGENT) == f"tb:{_PROJECT_A}:pxcur:{_AGENT}"


def test_current_prefix_version_key_differs_across_projects() -> None:
    assert current_prefix_version_key(_PROJECT_A, _AGENT) != current_prefix_version_key(
        _PROJECT_B, _AGENT
    )


def test_current_prefix_version_key_differs_across_agent_types() -> None:
    other = AgentTypeId.parse("66666666-6666-6666-6666-666666666666")
    assert current_prefix_version_key(_PROJECT_A, _AGENT) != current_prefix_version_key(
        _PROJECT_A, other
    )


def test_the_pointer_key_can_never_collide_with_a_versioned_block_key() -> None:
    """The pointer and the blocks it names live in one keyspace. If any
    `prefix_version` could make the two builders produce the same string, a
    published block would overwrite the pointer that resolves it — the cache
    would silently destroy its own index. The `px` / `pxcur` segments are
    distinct tokens between colons, and `AgentTypeId` is a UUID (no colon can
    be smuggled in to re-segment the key), so the collision is structural."""
    pointer = current_prefix_version_key(_PROJECT_A, _AGENT)
    for version in (0, 1, 2**32, 2**63 + 7):
        assert static_prefix_key(_PROJECT_A, _AGENT, version) != pointer


def test_current_prefix_version_key_rejects_a_sibling_typed_id() -> None:
    with pytest.raises(TypeError):
        current_prefix_version_key(_PROJECT_A, _RUN)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        current_prefix_version_key(str(_PROJECT_A), _AGENT)  # type: ignore[arg-type]


def test_project_key_pattern_shape() -> None:
    assert project_key_pattern(_PROJECT_A) == f"tb:{_PROJECT_A}:*"


def test_project_key_pattern_matches_every_builder_s_output() -> None:
    import fnmatch

    pattern = project_key_pattern(_PROJECT_A)
    assert fnmatch.fnmatchcase(_tool_key(_PROJECT_A), pattern)
    assert fnmatch.fnmatchcase(working_memory_key(_PROJECT_A, _RUN, "k"), pattern)
    assert fnmatch.fnmatchcase(static_prefix_key(_PROJECT_A, _AGENT, 1), pattern)
    assert fnmatch.fnmatchcase(current_prefix_version_key(_PROJECT_A, _AGENT), pattern)


def test_project_key_pattern_does_not_match_another_project() -> None:
    import fnmatch

    pattern = project_key_pattern(_PROJECT_A)
    assert not fnmatch.fnmatchcase(_tool_key(_PROJECT_B), pattern)


def test_project_key_pattern_rejects_non_project_id() -> None:
    with pytest.raises(TypeError):
        project_key_pattern(str(_PROJECT_A))  # type: ignore[arg-type]


def test_project_key_pattern_cannot_be_widened_by_a_hostile_working_memory_key() -> None:
    # A project's flush pattern is derived only from its own project_id, and
    # `key` sits AFTER the anchored prefix — so no scratch key a caller in B
    # invents (glob metacharacters included) can put a B key inside A's sweep
    # or pull an A key out of it.
    import fnmatch

    pattern_a = project_key_pattern(_PROJECT_A)
    for key in ("*", "?", "[a-z]", f"../{_PROJECT_A}/x", "\\", "]["):
        assert not fnmatch.fnmatchcase(working_memory_key(_PROJECT_B, _RUN, key), pattern_a)
        assert fnmatch.fnmatchcase(working_memory_key(_PROJECT_A, _RUN, key), pattern_a)
