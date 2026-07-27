"""PLAN.md §5 key spec, §6 `cache.*` — `stores.valkey.tool_cache`.

Offline by construction (contract §12): `ToolCache` takes its `ValkeyClient`
by injection, so the ttl_class resolution and the confused-deputy guard are
exercised here against an in-memory double, with no `@pytest.mark.integration`.
The live round trip is gated on `valkey_url`, imported from
`tests.phase0.conftest` for the same reason `test_working_memory.py` imports
it — one skip point, not a second one invented in this chunk.
"""

from __future__ import annotations

import fnmatch
from collections.abc import Iterator

import pytest

from tests.phase0.conftest import valkey_url  # noqa: F401
from tracebed.domain.config import CacheConfig
from tracebed.domain.ids import AgentTypeId, ProjectId, uuid7
from tracebed.stores.valkey.client import ValkeyClient
from tracebed.stores.valkey.flush import (
    CACHE_FLUSH_EVENT_TYPE,
    delete_project,
    flush_project_cache,
    is_cache_flush,
)
from tracebed.stores.valkey.keys import project_key_pattern, tool_cache_key
from tracebed.stores.valkey.tool_cache import ToolCache, resolve_ttl_class

pytestmark = pytest.mark.phase1

_PROJECT_A = ProjectId.parse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
_PROJECT_B = ProjectId.parse("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")

_TOOL: dict[str, object] = {
    "tool_id": "stripe.charge",
    "tool_version": "1.2.3",
    "auth_context_fingerprint": "fp-alice",
    "args": {"amount": 500},
}


class FakeValkey:
    """Duplicated per contract §13.1's accepted chunk-local-fake pattern —
    see `tests.phase0.test_valkey_client.FakeValkey` for the original."""

    def __init__(self) -> None:
        self.data: dict[str, bytes] = {}
        self.ttls: dict[str, int | None] = {}

    def get(self, name: str) -> object:
        return self.data.get(name)

    def set(self, name: str, value: bytes, ex: int | None = None) -> object:
        self.data[name] = value
        self.ttls[name] = ex
        return True

    def unlink(self, *names: str | bytes) -> object:
        removed = 0
        for name in names:
            key = name.decode() if isinstance(name, bytes) else name
            if self.data.pop(key, None) is not None:
                self.ttls.pop(key, None)
                removed += 1
        return removed

    def scan_iter(self, match: str, count: int) -> Iterator[str | bytes]:
        for key in list(self.data):
            if fnmatch.fnmatchcase(key, match):
                yield key.encode()

    def close(self) -> None:
        pass


@pytest.fixture
def fake_valkey() -> FakeValkey:
    return FakeValkey()


@pytest.fixture
def cfg() -> CacheConfig:
    return CacheConfig()  # defaults: intel=24h, registry=14d


@pytest.fixture
def cache(fake_valkey: FakeValkey, cfg: CacheConfig) -> ToolCache:
    return ToolCache(ValkeyClient(fake_valkey), cfg)


# --------------------------------------------------------------------------- #
# resolve_ttl_class — the config-driven duration parser
# --------------------------------------------------------------------------- #


def test_resolve_ttl_class_hours(cfg: CacheConfig) -> None:
    assert resolve_ttl_class("intel", cfg) == 24 * 3600


def test_resolve_ttl_class_days(cfg: CacheConfig) -> None:
    assert resolve_ttl_class("registry", cfg) == 14 * 86400


def test_resolve_ttl_class_unknown_name_is_refused(cfg: CacheConfig) -> None:
    with pytest.raises(ValueError, match="unknown"):
        resolve_ttl_class("does-not-exist", cfg)


def test_resolve_ttl_class_unparseable_duration_is_refused() -> None:
    bad_cfg = CacheConfig(ttl_class={"weird": "not-a-duration"})
    with pytest.raises(ValueError, match="not of the form"):
        resolve_ttl_class("weird", bad_cfg)


def test_resolve_ttl_class_rejects_an_unsupported_unit() -> None:
    bad_cfg = CacheConfig(ttl_class={"weird": "5m"})  # minutes: not a supported unit
    with pytest.raises(ValueError, match="not of the form"):
        resolve_ttl_class("weird", bad_cfg)


def test_resolve_ttl_class_anchors_both_ends_of_the_duration() -> None:
    # `$` in Python also matches immediately before a trailing newline, so
    # "24h\n" parses under `$` and the anchor is not the anchor it looks
    # like. A config value can arrive that way from a mounted file or a
    # here-doc env var, and the failure it produces — a TTL that is silently
    # accepted from a malformed value — is exactly the "silently wrong
    # lifetime" this parser exists to refuse.
    for raw in ("24h\n", "24h5", "24hh", " 24h", "24h ", "h", "24"):
        bad_cfg = CacheConfig(ttl_class={"weird": raw})
        with pytest.raises(ValueError, match="not of the form"):
            resolve_ttl_class("weird", bad_cfg)


def test_resolve_ttl_class_rejects_non_ascii_digits() -> None:
    # `\d` matches every Unicode decimal digit, and `int()` accepts them, so
    # under `\d` a fullwidth FULLWIDTH DIGIT TWO/FOUR pair would resolve to a
    # perfectly ordinary 24-hour TTL from a value no operator meant to write.
    # Spelled as escapes so the literal itself is unambiguous on the page.
    bad_cfg = CacheConfig(ttl_class={"weird": "\uff12\uff14h"})
    with pytest.raises(ValueError, match="not of the form"):
        resolve_ttl_class("weird", bad_cfg)


def test_resolve_ttl_class_rejects_a_zero_duration() -> None:
    # "0h" parses. This function is exported, so the 0 travels to whatever
    # store the caller hands it to — a key with no expiry in any store
    # without its own guard.
    bad_cfg = CacheConfig(ttl_class={"weird": "0h"})
    with pytest.raises(ValueError, match="positive"):
        resolve_ttl_class("weird", bad_cfg)


def test_resolve_ttl_class_honours_a_project_override() -> None:
    overridden = CacheConfig(ttl_class={"intel": "1h", "registry": "14d"})
    assert resolve_ttl_class("intel", overridden) == 3600


# --------------------------------------------------------------------------- #
# Round trip and TTL wiring
# --------------------------------------------------------------------------- #


def test_get_on_a_miss_is_none(cache: ToolCache) -> None:
    assert cache.get(_PROJECT_A, **_TOOL) is None  # type: ignore[arg-type]


def test_round_trip(cache: ToolCache) -> None:
    cache.set(_PROJECT_A, value=b"charged", ttl_class="intel", **_TOOL)  # type: ignore[arg-type]
    assert cache.get(_PROJECT_A, **_TOOL) == b"charged"  # type: ignore[arg-type]


def test_set_forwards_the_ttl_class_s_resolved_seconds(
    cache: ToolCache, fake_valkey: FakeValkey
) -> None:
    cache.set(_PROJECT_A, value=b"v", ttl_class="registry", **_TOOL)  # type: ignore[arg-type]
    assert set(fake_valkey.ttls.values()) == {14 * 86400}


def test_set_with_an_unknown_ttl_class_writes_nothing(
    cache: ToolCache, fake_valkey: FakeValkey
) -> None:
    with pytest.raises(ValueError, match="unknown"):
        cache.set(_PROJECT_A, value=b"v", ttl_class="bogus", **_TOOL)  # type: ignore[arg-type]
    assert fake_valkey.data == {}


# --------------------------------------------------------------------------- #
# The confused-deputy guard: no call shape reaches the cache without a
# real auth_context_fingerprint — TypeError at the call site, never a
# runtime None default.
# --------------------------------------------------------------------------- #


def test_get_without_a_fingerprint_is_a_typeerror_at_the_call_site(cache: ToolCache) -> None:
    with pytest.raises(TypeError):
        cache.get(  # type: ignore[call-arg]
            _PROJECT_A,
            tool_id="stripe.charge",
            tool_version="1.2.3",
            args={},
        )


def test_set_without_a_fingerprint_is_a_typeerror_at_the_call_site(cache: ToolCache) -> None:
    with pytest.raises(TypeError):
        cache.set(  # type: ignore[call-arg]
            _PROJECT_A,
            tool_id="stripe.charge",
            tool_version="1.2.3",
            args={},
            value=b"v",
            ttl_class="intel",
        )


def test_fingerprint_cannot_be_passed_positionally_either(cache: ToolCache) -> None:
    # Keyword-only, not merely "required": a caller cannot smuggle a
    # fingerprint-shaped positional argument through either.
    with pytest.raises(TypeError):
        cache.get(  # type: ignore[call-arg]
            _PROJECT_A,
            "stripe.charge",
            "1.2.3",
            "fp-alice",
            {},
        )


def test_different_fingerprints_do_not_share_a_cache_entry(cache: ToolCache) -> None:
    # Confused deputy, end to end through this class: the same project, tool,
    # version, and args, at two different caller-privilege fingerprints, must
    # never read each other's cached result.
    args = dict(_TOOL)
    cache.set(_PROJECT_A, value=b"admin-result", ttl_class="intel", **args)  # type: ignore[arg-type]
    args["auth_context_fingerprint"] = "fp-bob"
    assert cache.get(_PROJECT_A, **args) is None  # type: ignore[arg-type]


def test_an_empty_fingerprint_is_refused_on_both_accessors(
    cache: ToolCache, fake_valkey: FakeValkey
) -> None:
    # A required-but-empty fingerprint is the confused-deputy hole with the
    # guard nominally in place: "" is one shared bucket for every privilege
    # level in the project. Required-ness alone does not close it — a wrapper
    # that "has no auth context yet" and passes "" would type-check.
    empty = dict(_TOOL)
    empty["auth_context_fingerprint"] = ""
    with pytest.raises(ValueError, match="auth_context_fingerprint"):
        cache.get(_PROJECT_A, **empty)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="auth_context_fingerprint"):
        cache.set(_PROJECT_A, value=b"v", ttl_class="intel", **empty)  # type: ignore[arg-type]
    assert fake_valkey.data == {}


def test_a_none_fingerprint_through_an_untyped_edge_is_a_typeerror(
    cache: ToolCache, fake_valkey: FakeValkey
) -> None:
    # mypy --strict covers every call site in this repo; this is the runtime
    # backstop for one arriving through an `Any`-typed edge (a dict splat off
    # a request body, an adapter returning `object`). `None` must not stringify
    # into a shared "None" bucket.
    nulled: dict[str, object] = dict(_TOOL)
    nulled["auth_context_fingerprint"] = None
    with pytest.raises(TypeError):
        cache.get(_PROJECT_A, **nulled)  # type: ignore[arg-type]
    assert fake_valkey.data == {}


def test_a_separator_bearing_fingerprint_cannot_re_segment_the_hash_input(
    cache: ToolCache,
) -> None:
    # The hash input is 0x1F-joined (C-17). A fingerprint carrying the
    # separator could re-segment the join and land on another tuple's entry —
    # across the exact privilege boundary the fingerprint draws.
    smuggled = dict(_TOOL)
    smuggled["auth_context_fingerprint"] = "fp-bob\x1f"
    with pytest.raises(ValueError, match="separator"):
        cache.get(_PROJECT_A, **smuggled)  # type: ignore[arg-type]


# --------------------------------------------------------------------------- #
# cache_flush (stores.valkey.flush): the invalidation-event spelling, and the
# sweep's project scope in both directions.
# --------------------------------------------------------------------------- #


def test_cache_flush_event_type_is_one_exact_spelling() -> None:
    # One constant is what keeps the webhook writer and the future
    # `invalidation_event` consumer from drifting into two strings for what
    # must be one event. `POST /v1/invalidation` persists `kind` verbatim
    # (D-041), so the match is exact — a near-miss must not flush.
    assert CACHE_FLUSH_EVENT_TYPE == "cache_flush"
    assert is_cache_flush(CACHE_FLUSH_EVENT_TYPE)
    assert not is_cache_flush("Cache_Flush")
    assert not is_cache_flush("cache-flush")
    assert not is_cache_flush("cache_flush ")
    assert not is_cache_flush("")


def test_flush_erases_one_projects_cache_and_leaves_the_others(
    fake_valkey: FakeValkey, cfg: CacheConfig
) -> None:
    client = ValkeyClient(fake_valkey)
    cache = ToolCache(client, cfg)
    cache.set(_PROJECT_A, value=b"a-secret", ttl_class="intel", **_TOOL)  # type: ignore[arg-type]
    cache.set(_PROJECT_B, value=b"b-secret", ttl_class="intel", **_TOOL)  # type: ignore[arg-type]

    assert flush_project_cache(client, _PROJECT_A) == 1
    assert cache.get(_PROJECT_A, **_TOOL) is None  # type: ignore[arg-type]
    assert cache.get(_PROJECT_B, **_TOOL) == b"b-secret"  # type: ignore[arg-type]


def test_flush_sweeps_the_whole_project_namespace_not_just_the_tool_cache(
    fake_valkey: FakeValkey, cfg: CacheConfig
) -> None:
    # "Flush this project's cache" means every key builder's namespace, not
    # the `:tc:` prefix alone — a sweep narrowed to one key kind would leave a
    # stale static prefix serving content the flush was fired to invalidate.
    client = ValkeyClient(fake_valkey)
    agent_type = AgentTypeId.parse("cccccccc-cccc-cccc-cccc-cccccccccccc")
    ToolCache(client, cfg).set(_PROJECT_A, value=b"v", ttl_class="intel", **_TOOL)  # type: ignore[arg-type]
    client.static_prefix_set(_PROJECT_A, agent_type, 3, b"prefix", ttl_seconds=60)

    assert flush_project_cache(client, _PROJECT_A) == 2
    assert client.static_prefix_get(_PROJECT_A, agent_type, 3) is None


def test_delete_project_erases_the_same_namespace_flush_does(
    fake_valkey: FakeValkey, cfg: CacheConfig
) -> None:
    client = ValkeyClient(fake_valkey)
    cache = ToolCache(client, cfg)
    cache.set(_PROJECT_A, value=b"a-secret", ttl_class="intel", **_TOOL)  # type: ignore[arg-type]
    cache.set(_PROJECT_B, value=b"b-secret", ttl_class="intel", **_TOOL)  # type: ignore[arg-type]

    assert delete_project(client, _PROJECT_A) == 1
    pattern_a = project_key_pattern(_PROJECT_A)
    assert not [k for k in fake_valkey.data if fnmatch.fnmatchcase(k, pattern_a)]
    assert cache.get(_PROJECT_B, **_TOOL) == b"b-secret"  # type: ignore[arg-type]


# --------------------------------------------------------------------------- #
# Key isolation — invariant 4, offline half (two projects, identical
# everything else -> different keys, neither readable via the other's).
# --------------------------------------------------------------------------- #


def test_identical_tool_call_is_isolated_across_projects(cache: ToolCache) -> None:
    cache.set(_PROJECT_A, value=b"project-a-secret", ttl_class="intel", **_TOOL)  # type: ignore[arg-type]
    assert cache.get(_PROJECT_B, **_TOOL) is None  # type: ignore[arg-type]


def test_project_a_and_b_tool_cache_keys_are_disjoint(fake_valkey: FakeValkey) -> None:
    key_a = tool_cache_key(_PROJECT_A, **_TOOL)  # type: ignore[arg-type]
    key_b = tool_cache_key(_PROJECT_B, **_TOOL)  # type: ignore[arg-type]
    assert key_a != key_b
    pattern_a = project_key_pattern(_PROJECT_A)
    assert fnmatch.fnmatchcase(key_a, pattern_a)
    assert not fnmatch.fnmatchcase(key_b, pattern_a)


# --------------------------------------------------------------------------- #
# Live round trip (integration; skips cleanly with no Valkey — contract §12)
# --------------------------------------------------------------------------- #


@pytest.mark.integration
def test_tool_cache_live_round_trip(valkey_url: str) -> None:  # noqa: F811
    client = ValkeyClient.from_url(valkey_url)
    try:
        cache = ToolCache(client, CacheConfig())
        project = ProjectId(uuid7())
        tool = dict(_TOOL)
        try:
            assert cache.get(project, **tool) is None  # type: ignore[arg-type]
            cache.set(project, value=b"live-result", ttl_class="intel", **tool)  # type: ignore[arg-type]
            assert cache.get(project, **tool) == b"live-result"  # type: ignore[arg-type]
        finally:
            client.delete_project(project)
    finally:
        client.close()
