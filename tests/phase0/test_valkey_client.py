"""PHASE0-CONTRACT.md §7 / §12 — `stores.valkey.client.ValkeyClient`, offline.

There is no Valkey on this machine, and a class whose only collaborator is a
live server is a class that never gets tested. `ValkeyClient` takes its
connection by injection, so the batching in `delete_project`, the TTL
enforcement, the response narrowing, and the project-isolation property of
every accessor are all exercised here against an in-memory double — with no
`@pytest.mark.integration`, because none of it needs a server.

Backs invariant 4 ("the wall covers every key in every store", PLAN.md §2):
these are the offline half of leak probe 6 (PHASE-0.md Task 17) — A's
connection reading B's keys returns nothing, and flushing A leaves B intact.
"""

from __future__ import annotations

import fnmatch
from collections.abc import Iterator

import pytest

from tracebed.domain.ids import AgentTypeId, ProjectId, RunId
from tracebed.stores.valkey.client import ValkeyClient
from tracebed.stores.valkey.keys import project_key_pattern

pytestmark = pytest.mark.phase0

_PROJECT_A = ProjectId.parse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
_PROJECT_B = ProjectId.parse("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")
_AGENT = AgentTypeId.parse("55555555-5555-5555-5555-555555555555")
_RUN = RunId.parse("77777777-7777-7777-7777-777777777777")

_TOOL: dict[str, object] = {
    "tool_id": "stripe.charge",
    "tool_version": "1.2.3",
    "auth_context_fingerprint": "fp-alice",
    "args": {"amount": 500},
}


class FakeValkey:
    """In-memory stand-in satisfying `ValkeyCommands`.

    Records what it was asked to do so the tests can assert on the *shape* of
    the traffic (batch sizes, TTLs actually sent) and not only on the visible
    end state — a sweep that issues one 100k-argument UNLINK and a sweep that
    issues 200 bounded ones leave identical end states.
    """

    def __init__(self, *, decode_responses: bool = False) -> None:
        self.data: dict[str, bytes] = {}
        self.ttls: dict[str, int | None] = {}
        self.unlink_batch_sizes: list[int] = []
        self.scan_calls: list[tuple[str, int]] = []
        self.closed = False
        self._decode_responses = decode_responses
        # Set to a key list to make scan_iter yield exactly that (used to
        # simulate SCAN's documented duplicate-yield under rehashing).
        self.scan_override: list[str] | None = None

    def get(self, name: str) -> object:
        raw = self.data.get(name)
        if raw is not None and self._decode_responses:
            return raw.decode()
        return raw

    def set(self, name: str, value: bytes, ex: int | None = None) -> object:
        self.data[name] = value
        self.ttls[name] = ex
        return True

    def unlink(self, *names: str | bytes) -> object:
        self.unlink_batch_sizes.append(len(names))
        removed = 0
        for name in names:
            key = name.decode() if isinstance(name, bytes) else name
            if self.data.pop(key, None) is not None:
                self.ttls.pop(key, None)
                removed += 1
        return removed

    def scan_iter(self, match: str, count: int) -> Iterator[str | bytes]:
        self.scan_calls.append((match, count))
        if self.scan_override is not None:
            yield from self.scan_override
            return
        # Snapshot: the client deletes while iterating.
        for key in list(self.data):
            if fnmatch.fnmatchcase(key, match):
                yield key.encode()

    def close(self) -> None:
        self.closed = True


@pytest.fixture
def fake() -> FakeValkey:
    return FakeValkey()


@pytest.fixture
def client(fake: FakeValkey) -> ValkeyClient:
    return ValkeyClient(fake)


# --------------------------------------------------------------------------- #
# Round trips
# --------------------------------------------------------------------------- #


def test_tool_cache_round_trip(client: ValkeyClient) -> None:
    assert client.tool_cache_get(_PROJECT_A, **_TOOL) is None  # type: ignore[arg-type]
    client.tool_cache_set(_PROJECT_A, value=b"charged", ttl_seconds=60, **_TOOL)  # type: ignore[arg-type]
    assert client.tool_cache_get(_PROJECT_A, **_TOOL) == b"charged"  # type: ignore[arg-type]


def test_working_memory_round_trip_and_delete(client: ValkeyClient) -> None:
    client.working_memory_set(_PROJECT_A, _RUN, "scratch", b"v", ttl_seconds=30)
    assert client.working_memory_get(_PROJECT_A, _RUN, "scratch") == b"v"
    client.working_memory_delete(_PROJECT_A, _RUN, "scratch")
    assert client.working_memory_get(_PROJECT_A, _RUN, "scratch") is None


def test_static_prefix_round_trip(client: ValkeyClient) -> None:
    client.static_prefix_set(_PROJECT_A, _AGENT, 3, b"prefix", ttl_seconds=900)
    assert client.static_prefix_get(_PROJECT_A, _AGENT, 3) == b"prefix"
    # A different version is a different entry, never a stale hit.
    assert client.static_prefix_get(_PROJECT_A, _AGENT, 4) is None


def test_current_prefix_version_round_trip(client: ValkeyClient) -> None:
    assert client.current_prefix_version_get(_PROJECT_A, _AGENT) is None
    client.current_prefix_version_set(_PROJECT_A, _AGENT, 7, ttl_seconds=900)
    assert client.current_prefix_version_get(_PROJECT_A, _AGENT) == 7


def test_the_pointer_resolves_the_block_a_reader_could_not_have_named(
    client: ValkeyClient,
) -> None:
    """The whole reason this key exists: `prefix_version` is derived from the
    packed content, so a reader holding only (project, agent_type) cannot
    compute it. Pointer first, block second — with nothing else in hand."""
    client.static_prefix_set(_PROJECT_A, _AGENT, 4242, b"the-block", ttl_seconds=900)
    client.current_prefix_version_set(_PROJECT_A, _AGENT, 4242, ttl_seconds=900)

    version = client.current_prefix_version_get(_PROJECT_A, _AGENT)
    assert version is not None
    assert client.static_prefix_get(_PROJECT_A, _AGENT, version) == b"the-block"


def test_current_prefix_version_is_not_readable_across_projects(client: ValkeyClient) -> None:
    client.current_prefix_version_set(_PROJECT_A, _AGENT, 5, ttl_seconds=60)
    assert client.current_prefix_version_get(_PROJECT_B, _AGENT) is None


def test_current_prefix_version_is_not_readable_across_agent_types(client: ValkeyClient) -> None:
    other = AgentTypeId.parse("66666666-6666-6666-6666-666666666666")
    client.current_prefix_version_set(_PROJECT_A, _AGENT, 5, ttl_seconds=60)
    assert client.current_prefix_version_get(_PROJECT_A, other) is None


@pytest.mark.parametrize("raw", [b"", b" 7", b"7 ", b"+7", b"-7", b"1_0", b"7.0", b"abc", b"\xff"])
def test_a_corrupt_pointer_reads_as_a_miss_rather_than_resolving_a_wrong_version(
    client: ValkeyClient, fake: FakeValkey, raw: bytes
) -> None:
    """Every one of these is something `int()` would either accept as a
    DIFFERENT number than was written (`" 7"`, `"+7"`, `"1_0"` -> 10) or raise
    on inside the hot path. The pointer feeds the degradation ladder's
    prefix-only rung, where the correct answer to "this cache entry makes no
    sense" is the same as the answer to a miss: serve no prefix, and let the
    next builder run repair it."""
    from tracebed.stores.valkey.keys import current_prefix_version_key

    fake.data[current_prefix_version_key(_PROJECT_A, _AGENT)] = raw

    assert client.current_prefix_version_get(_PROJECT_A, _AGENT) is None


def test_current_prefix_version_set_refuses_a_version_no_block_key_could_hold(
    client: ValkeyClient,
) -> None:
    """The pointer must never be able to name a version `static_prefix_key`
    would have rejected — that would be a pointer into an unwritable slot."""
    with pytest.raises(ValueError):
        client.current_prefix_version_set(_PROJECT_A, _AGENT, -1, ttl_seconds=60)
    with pytest.raises(TypeError):
        client.current_prefix_version_set(_PROJECT_A, _AGENT, True, ttl_seconds=60)
    with pytest.raises(TypeError):
        client.current_prefix_version_set(_PROJECT_A, _AGENT, "3", ttl_seconds=60)  # type: ignore[arg-type]


def test_current_prefix_version_set_requires_a_ttl(client: ValkeyClient) -> None:
    with pytest.raises(ValueError):
        client.current_prefix_version_set(_PROJECT_A, _AGENT, 1, ttl_seconds=0)
    with pytest.raises(TypeError):
        client.current_prefix_version_set(_PROJECT_A, _AGENT, 1)  # type: ignore[call-arg]


def test_deleting_a_project_removes_its_prefix_pointer_too(client: ValkeyClient) -> None:
    """A surviving pointer after erasure names a block that is gone — and, if
    the project id were ever reused, a block that is not its own."""
    client.current_prefix_version_set(_PROJECT_A, _AGENT, 9, ttl_seconds=60)
    client.current_prefix_version_set(_PROJECT_B, _AGENT, 9, ttl_seconds=60)

    client.delete_project(_PROJECT_A)

    assert client.current_prefix_version_get(_PROJECT_A, _AGENT) is None
    assert client.current_prefix_version_get(_PROJECT_B, _AGENT) == 9


def test_from_url_does_not_connect() -> None:
    # Contract §12: importing/constructing must not open a socket, or every
    # test module that touches this class fails at collection on this machine.
    built = ValkeyClient.from_url("valkey://127.0.0.1:1/0")
    assert isinstance(built, ValkeyClient)


def test_close_closes_the_injected_connection(client: ValkeyClient, fake: FakeValkey) -> None:
    client.close()
    assert fake.closed


# --------------------------------------------------------------------------- #
# Invariant 4 — cross-project isolation through the client, not just the keys
# --------------------------------------------------------------------------- #


def test_tool_cache_is_not_readable_across_projects(client: ValkeyClient) -> None:
    client.tool_cache_set(_PROJECT_A, value=b"secret", ttl_seconds=60, **_TOOL)  # type: ignore[arg-type]
    assert client.tool_cache_get(_PROJECT_B, **_TOOL) is None  # type: ignore[arg-type]


def test_working_memory_is_not_readable_across_projects(client: ValkeyClient) -> None:
    client.working_memory_set(_PROJECT_A, _RUN, "scratch", b"secret", ttl_seconds=30)
    assert client.working_memory_get(_PROJECT_B, _RUN, "scratch") is None


def test_static_prefix_is_not_readable_across_projects(client: ValkeyClient) -> None:
    client.static_prefix_set(_PROJECT_A, _AGENT, 1, b"secret", ttl_seconds=60)
    assert client.static_prefix_get(_PROJECT_B, _AGENT, 1) is None


def test_tool_cache_is_not_readable_across_auth_contexts(client: ValkeyClient) -> None:
    # Confused deputy: same project, same tool, same args, lower privilege.
    args: dict[str, object] = dict(_TOOL)
    client.tool_cache_set(_PROJECT_A, value=b"admin-result", ttl_seconds=60, **args)  # type: ignore[arg-type]
    args["auth_context_fingerprint"] = "fp-bob"
    assert client.tool_cache_get(_PROJECT_A, **args) is None  # type: ignore[arg-type]


def test_every_public_accessor_is_project_scoped() -> None:
    # Structural restatement of "no scope-less constructor exists": a future
    # accessor added without a leading ProjectId fails here rather than at a
    # leak-suite run against a database this machine does not have.
    import inspect

    for name, member in inspect.getmembers(ValkeyClient, inspect.isfunction):
        if name.startswith("_") or name in {"close", "from_url"}:
            continue
        params = list(inspect.signature(member).parameters.values())
        assert params[0].name == "self", name
        assert params[1].name == "project_id", f"{name} is not project-scoped"
        assert params[1].annotation == "ProjectId", name


# --------------------------------------------------------------------------- #
# TTL — nothing this module writes may be immortal
# --------------------------------------------------------------------------- #


def test_ttl_is_forwarded_to_valkey(client: ValkeyClient, fake: FakeValkey) -> None:
    client.working_memory_set(_PROJECT_A, _RUN, "k", b"v", ttl_seconds=45)
    assert set(fake.ttls.values()) == {45}


@pytest.mark.parametrize("bad", [0, -1, -3600])
def test_non_positive_ttl_is_refused(client: ValkeyClient, bad: int) -> None:
    with pytest.raises(ValueError, match="positive"):
        client.working_memory_set(_PROJECT_A, _RUN, "k", b"v", ttl_seconds=bad)


@pytest.mark.parametrize("bad", [None, True, 1.5, "60"])
def test_non_int_ttl_is_refused(client: ValkeyClient, bad: object) -> None:
    # None is the important one: an optional TTL makes "never expires" the
    # value a caller gets by forgetting, and delete_project is the only other
    # reaper this keyspace has.
    with pytest.raises(TypeError):
        client.working_memory_set(_PROJECT_A, _RUN, "k", b"v", ttl_seconds=bad)  # type: ignore[arg-type]


def test_a_refused_ttl_writes_nothing(client: ValkeyClient, fake: FakeValkey) -> None:
    with pytest.raises((TypeError, ValueError)):
        client.static_prefix_set(_PROJECT_A, _AGENT, 1, b"v", ttl_seconds=0)
    assert fake.data == {}


def test_every_setter_requires_a_ttl(client: ValkeyClient) -> None:
    with pytest.raises(TypeError):
        client.working_memory_set(_PROJECT_A, _RUN, "k", b"v")  # type: ignore[call-arg]
    with pytest.raises(TypeError):
        client.static_prefix_set(_PROJECT_A, _AGENT, 1, b"v")  # type: ignore[call-arg]
    with pytest.raises(TypeError):
        client.tool_cache_set(_PROJECT_A, value=b"v", **_TOOL)  # type: ignore[arg-type,call-arg]


# --------------------------------------------------------------------------- #
# Response narrowing
# --------------------------------------------------------------------------- #


def test_a_str_response_is_a_named_error_not_a_silent_leak() -> None:
    # A client built with decode_responses=True returns str. Casting would let
    # that escape a `bytes`-typed accessor and blow up far from the cause.
    fake = FakeValkey(decode_responses=True)
    client = ValkeyClient(fake)
    client.working_memory_set(_PROJECT_A, _RUN, "k", b"v", ttl_seconds=10)
    with pytest.raises(TypeError, match="decode_responses"):
        client.working_memory_get(_PROJECT_A, _RUN, "k")


# --------------------------------------------------------------------------- #
# delete_project — the flush/erasure sweep
# --------------------------------------------------------------------------- #


def _seed(client: ValkeyClient, project: ProjectId, n: int) -> None:
    for i in range(n):
        client.working_memory_set(project, _RUN, f"k{i}", b"v", ttl_seconds=60)


def test_delete_project_removes_only_that_project(
    client: ValkeyClient, fake: FakeValkey
) -> None:
    _seed(client, _PROJECT_A, 7)
    _seed(client, _PROJECT_B, 5)

    removed = client.delete_project(_PROJECT_A)

    assert removed == 7
    assert client.working_memory_get(_PROJECT_A, _RUN, "k0") is None
    assert client.working_memory_get(_PROJECT_B, _RUN, "k0") == b"v"
    assert len(fake.data) == 5


def test_delete_project_sweeps_its_own_pattern(client: ValkeyClient, fake: FakeValkey) -> None:
    _seed(client, _PROJECT_A, 2)
    client.delete_project(_PROJECT_A)
    assert [m for m, _ in fake.scan_calls] == [project_key_pattern(_PROJECT_A)]


def test_delete_project_covers_every_key_kind(client: ValkeyClient, fake: FakeValkey) -> None:
    # "Every key this project owns" must mean every builder's namespace, not
    # just working memory — an erasure that misses the tool cache leaves the
    # tool results behind after the project is gone.
    client.tool_cache_set(_PROJECT_A, value=b"v", ttl_seconds=60, **_TOOL)  # type: ignore[arg-type]
    client.working_memory_set(_PROJECT_A, _RUN, "k", b"v", ttl_seconds=60)
    client.static_prefix_set(_PROJECT_A, _AGENT, 1, b"v", ttl_seconds=60)
    assert len(fake.data) == 3

    assert client.delete_project(_PROJECT_A) == 3
    assert fake.data == {}


def test_delete_project_bounds_each_unlink_batch(client: ValkeyClient, fake: FakeValkey) -> None:
    # 1,201 keys over a 500-key batch: an unbatched sweep issues one UNLINK
    # with 1,201 arguments (an unbounded command built from however many keys
    # a project accumulated). Asserting the end state alone cannot see that.
    total = 1_201
    _seed(client, _PROJECT_A, total)

    assert client.delete_project(_PROJECT_A) == total
    assert fake.data == {}
    assert max(fake.unlink_batch_sizes) <= 500
    assert sum(fake.unlink_batch_sizes) == total
    assert len(fake.unlink_batch_sizes) == 3  # 500 + 500 + 201


def test_delete_project_on_an_empty_namespace_issues_no_unlink(
    client: ValkeyClient, fake: FakeValkey
) -> None:
    _seed(client, _PROJECT_B, 3)
    assert client.delete_project(_PROJECT_A) == 0
    assert fake.unlink_batch_sizes == []


def test_delete_project_counts_keys_removed_not_keys_scanned(
    client: ValkeyClient, fake: FakeValkey
) -> None:
    # SCAN may yield the same key twice when the keyspace rehashes mid-cursor.
    # Counting yields would overstate the erasure; UNLINK reports 0 the second
    # time, which is the truthful number.
    _seed(client, _PROJECT_A, 2)
    fake.scan_override = sorted(fake.data) * 2

    assert client.delete_project(_PROJECT_A) == 2


def test_delete_project_rejects_a_non_int_unlink_reply(client: ValkeyClient) -> None:
    class LyingValkey(FakeValkey):
        def unlink(self, *names: str | bytes) -> object:
            super().unlink(*names)
            return "OK"

    lying = LyingValkey()
    lying_client = ValkeyClient(lying)
    _seed(lying_client, _PROJECT_A, 2)
    # A sweep that cannot count what it deleted must not report a plausible
    # number — erasure evidence is the product.
    with pytest.raises(TypeError, match="UNLINK"):
        lying_client.delete_project(_PROJECT_A)


def test_delete_project_rejects_non_project_id(client: ValkeyClient) -> None:
    with pytest.raises(TypeError):
        client.delete_project(str(_PROJECT_A))  # type: ignore[arg-type]
