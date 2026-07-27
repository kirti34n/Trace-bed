"""PLAN.md §5 key spec, §6 `session.*` — `stores.valkey.working_memory`.

Offline by construction, per contract §12: `WorkingMemory` takes its
`ValkeyClient` and `TraceStorePort` by injection, so the offload arithmetic,
the envelope round-trip, and the project/run isolation properties are all
exercised here against in-memory doubles with no `@pytest.mark.integration`.
A live round-trip against a real Valkey is `test_working_memory_live_round_trip`
below, gated on the `valkey_url` fixture (imported from
`tests.phase0.conftest`, per that module's own skip contract — one skip
point, not a second one invented here).
"""

from __future__ import annotations

import fnmatch
import hashlib
from collections.abc import Iterator

import pytest

# Reused rather than re-invented: tests.phase0.conftest already owns the one
# "is Valkey reachable" skip point (§13.1). Importing the fixture function
# into this module's namespace is how pytest picks it up outside its home
# directory's conftest chain, without a second tests/phase1/conftest.py this
# chunk's file list does not include.
from tests.phase0.conftest import valkey_url  # noqa: F401
from tracebed.domain.config import SessionConfig
from tracebed.domain.errors import NotFound
from tracebed.domain.ids import ProjectId, RunId, uuid7
from tracebed.stores.tracestore import PayloadRef
from tracebed.stores.valkey.client import ValkeyClient
from tracebed.stores.valkey.flush import flush_project_cache
from tracebed.stores.valkey.keys import project_key_pattern, working_memory_key
from tracebed.stores.valkey.working_memory import WorkingMemory, WorkingMemoryEntry

pytestmark = pytest.mark.phase1

_PROJECT_A = ProjectId.parse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
_PROJECT_B = ProjectId.parse("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")
_RUN = RunId.parse("77777777-7777-7777-7777-777777777777")


class FakeValkey:
    """The minimal `ValkeyCommands` double — same shape as
    `tests.phase0.test_valkey_client.FakeValkey`, duplicated per contract
    §13.1's "chunk-local fakes... duplication is accepted; a shared fakes
    module would be a merge collision."
    """

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


class FakeTraceStore:
    """An in-memory `TraceStorePort` double, project-scoped like the real
    drivers: `get()` raises `NotFound` for a ref outside the caller's
    project, matching `fs.py`'s and `s3.py`'s own leak-suite behaviour.
    """

    def __init__(self) -> None:
        self.objects: dict[tuple[str, str], bytes] = {}
        self.put_calls: list[tuple[ProjectId, RunId, int]] = []

    def put(self, project_id: ProjectId, run_id: RunId, first_seq: int, payload: bytes) -> PayloadRef:
        self.put_calls.append((project_id, run_id, first_seq))
        key = f"{project_id}/{run_id}/{first_seq:08d}"
        self.objects[(str(project_id), key)] = payload
        return PayloadRef(driver="fs", key=key)

    def get(self, project_id: ProjectId, ref: PayloadRef) -> bytes:
        if not ref.key.startswith(f"{project_id}/"):
            raise NotFound("trace payload not found")
        found = self.objects.get((str(project_id), ref.key))
        if found is None:
            raise NotFound("trace payload not found")
        return found

    def exists(self, project_id: ProjectId, ref: PayloadRef) -> bool:
        return (str(project_id), ref.key) in self.objects

    def delete_project(self, project_id: ProjectId) -> int:
        prefix = f"{project_id}/"
        keys = [k for k in self.objects if k[0] == str(project_id) and k[1].startswith(prefix)]
        for k in keys:
            del self.objects[k]
        return len(keys)


@pytest.fixture
def fake_valkey() -> FakeValkey:
    return FakeValkey()


@pytest.fixture
def fake_store() -> FakeTraceStore:
    return FakeTraceStore()


@pytest.fixture
def small_threshold_cfg() -> SessionConfig:
    # A tiny threshold, not PLAN.md's 20_000 default, so the spill/no-spill
    # boundary can be exercised with a handful of bytes rather than an
    # actual 20k-token payload — the boundary logic being tested does not
    # depend on the literal value, only on being compared correctly.
    return SessionConfig(idle_ttl_min=5, offload_threshold_tokens=10)


@pytest.fixture
def wm(fake_valkey: FakeValkey, fake_store: FakeTraceStore, small_threshold_cfg: SessionConfig) -> WorkingMemory:
    return WorkingMemory(ValkeyClient(fake_valkey), fake_store, small_threshold_cfg)


# --------------------------------------------------------------------------- #
# Round trip, inline path
# --------------------------------------------------------------------------- #


def test_get_on_a_missing_key_is_none(wm: WorkingMemory) -> None:
    assert wm.get(_PROJECT_A, _RUN, "scratch") is None


def test_inline_round_trip_returns_identical_content(wm: WorkingMemory) -> None:
    wm.set(_PROJECT_A, _RUN, "scratch", b"hello world", token_count=1)
    entry = wm.get(_PROJECT_A, _RUN, "scratch")
    assert entry == WorkingMemoryEntry(value=b"hello world", spilled=False)


def test_inline_write_never_touches_the_trace_store(
    wm: WorkingMemory, fake_store: FakeTraceStore
) -> None:
    wm.set(_PROJECT_A, _RUN, "scratch", b"small", token_count=1)
    assert fake_store.put_calls == []


def test_delete_removes_the_entry(wm: WorkingMemory) -> None:
    wm.set(_PROJECT_A, _RUN, "scratch", b"v", token_count=1)
    wm.delete(_PROJECT_A, _RUN, "scratch")
    assert wm.get(_PROJECT_A, _RUN, "scratch") is None


def test_ttl_is_idle_ttl_min_in_seconds(wm: WorkingMemory, fake_valkey: FakeValkey) -> None:
    wm.set(_PROJECT_A, _RUN, "scratch", b"v", token_count=1)
    assert set(fake_valkey.ttls.values()) == {5 * 60}


# --------------------------------------------------------------------------- #
# Offload threshold — the boundary is exact, in both directions
# --------------------------------------------------------------------------- #


def test_at_threshold_stays_inline(
    wm: WorkingMemory, fake_store: FakeTraceStore, small_threshold_cfg: SessionConfig
) -> None:
    wm.set(_PROJECT_A, _RUN, "scratch", b"x" * 40, token_count=small_threshold_cfg.offload_threshold_tokens)
    entry = wm.get(_PROJECT_A, _RUN, "scratch")
    assert entry is not None
    assert entry.spilled is False
    assert fake_store.put_calls == []


def test_above_threshold_spills(
    wm: WorkingMemory, fake_store: FakeTraceStore, small_threshold_cfg: SessionConfig
) -> None:
    payload = b"y" * 4096
    wm.set(
        _PROJECT_A,
        _RUN,
        "scratch",
        payload,
        token_count=small_threshold_cfg.offload_threshold_tokens + 1,
    )
    assert len(fake_store.put_calls) == 1
    entry = wm.get(_PROJECT_A, _RUN, "scratch")
    assert entry == WorkingMemoryEntry(value=payload, spilled=True)


def test_spilled_content_is_byte_identical_on_read_back(
    wm: WorkingMemory, small_threshold_cfg: SessionConfig
) -> None:
    payload = bytes(range(256)) * 100  # not text; working memory is opaque bytes
    wm.set(
        _PROJECT_A,
        _RUN,
        "scratch",
        payload,
        token_count=small_threshold_cfg.offload_threshold_tokens + 1,
    )
    entry = wm.get(_PROJECT_A, _RUN, "scratch")
    assert entry is not None
    assert entry.value == payload


def test_spilled_entry_stores_only_a_small_pointer_in_valkey(
    wm: WorkingMemory, fake_valkey: FakeValkey, small_threshold_cfg: SessionConfig
) -> None:
    payload = b"z" * 100_000
    wm.set(
        _PROJECT_A,
        _RUN,
        "scratch",
        payload,
        token_count=small_threshold_cfg.offload_threshold_tokens + 1,
    )
    stored = next(iter(fake_valkey.data.values()))
    assert len(stored) < len(payload)


def test_re_set_of_the_same_spilled_key_overwrites_its_own_object(
    wm: WorkingMemory, fake_store: FakeTraceStore, small_threshold_cfg: SessionConfig
) -> None:
    threshold = small_threshold_cfg.offload_threshold_tokens
    wm.set(_PROJECT_A, _RUN, "scratch", b"first" * 1000, token_count=threshold + 1)
    wm.set(_PROJECT_A, _RUN, "scratch", b"second" * 1000, token_count=threshold + 1)
    # Same (project, run, key) spilling twice resolves to the same object
    # path both times — not two orphaned objects.
    first_seqs = {seq for (_, _, seq) in fake_store.put_calls}
    assert len(first_seqs) == 1
    entry = wm.get(_PROJECT_A, _RUN, "scratch")
    assert entry is not None
    assert entry.value == b"second" * 1000


def test_two_different_keys_spill_to_different_objects(
    wm: WorkingMemory, fake_store: FakeTraceStore, small_threshold_cfg: SessionConfig
) -> None:
    threshold = small_threshold_cfg.offload_threshold_tokens
    wm.set(_PROJECT_A, _RUN, "note-a", b"a" * 1000, token_count=threshold + 1)
    wm.set(_PROJECT_A, _RUN, "note-b", b"b" * 1000, token_count=threshold + 1)
    first_seqs = [seq for (_, _, seq) in fake_store.put_calls]
    assert len(set(first_seqs)) == 2
    entry_a = wm.get(_PROJECT_A, _RUN, "note-a")
    entry_b = wm.get(_PROJECT_A, _RUN, "note-b")
    assert entry_a is not None and entry_a.value == b"a" * 1000
    assert entry_b is not None and entry_b.value == b"b" * 1000


def test_negative_token_count_is_refused(wm: WorkingMemory) -> None:
    with pytest.raises(ValueError, match="negative"):
        wm.set(_PROJECT_A, _RUN, "scratch", b"v", token_count=-1)


def test_spill_first_seq_is_anchored_exactly_above_the_trace_seq_ceiling() -> None:
    # `> _TRACE_SEQ_CEILING` alone is a near-unfalsifiable assertion: the
    # offset is a uniform 32-bit value, so an implementation that dropped the
    # anchor entirely and returned the bare offset would still clear a
    # 1,000,000 ceiling for ~99.98% of keys and the test would stay green.
    # Pin the anchor itself, so "the ceiling is applied" is what is checked.
    from tracebed.stores.valkey.working_memory import _TRACE_SEQ_CEILING, _spill_first_seq

    for key in ("", "a", "scratch", "x" * 500, "unicode-é中"):
        offset = int.from_bytes(hashlib.sha256(key.encode("utf-8")).digest()[:4], "big")
        assert _spill_first_seq(key) == _TRACE_SEQ_CEILING + 1 + offset
        assert _spill_first_seq(key) > _TRACE_SEQ_CEILING


def test_trace_seq_ceiling_mirrors_the_trace_writers_own_constant() -> None:
    # D-047 mirrors `MAX_TRACE_SEQ` rather than importing it (`stores.valkey`
    # must not depend on `ingest`) — exactly the move C-33 made for the
    # api/ingest pair, which `tests/phase0/test_integration_seams.py` binds
    # with an equality assertion for the same reason this one exists. An
    # unasserted mirror is a constant that drifts in silence: raise
    # `MAX_TRACE_SEQ` on its own and working-memory spills begin landing
    # inside the range real trace-event objects occupy for the same run,
    # overwriting encrypted trace payloads invariant 6's provenance rests on.
    from tracebed.ingest.trace_writer import MAX_TRACE_SEQ
    from tracebed.stores.valkey.working_memory import _TRACE_SEQ_CEILING

    assert _TRACE_SEQ_CEILING == MAX_TRACE_SEQ


def test_an_invalid_key_is_refused_before_anything_is_spilled(
    wm: WorkingMemory, fake_store: FakeTraceStore, small_threshold_cfg: SessionConfig
) -> None:
    # `keys.py` is the only validator of `key`, and it runs when the Valkey
    # key is built — after the spill, unless `set()` checks first. Since
    # `TraceStorePort` has no per-object delete, a write ordered before the
    # check leaves an object nothing can reclaim short of deleting the whole
    # project: caller-triggered unreclaimable growth on an input the store
    # layer was always going to refuse.
    over_long = "k" * 513
    with pytest.raises(ValueError, match="characters"):
        wm.set(
            _PROJECT_A,
            _RUN,
            over_long,
            b"payload" * 1000,
            token_count=small_threshold_cfg.offload_threshold_tokens + 1,
        )
    assert fake_store.put_calls == []


def test_a_separator_bearing_key_is_refused_before_anything_is_spilled(
    wm: WorkingMemory, fake_store: FakeTraceStore, small_threshold_cfg: SessionConfig
) -> None:
    with pytest.raises(ValueError, match="separator"):
        wm.set(
            _PROJECT_A,
            _RUN,
            "scratch\x1fsmuggled",
            b"payload" * 1000,
            token_count=small_threshold_cfg.offload_threshold_tokens + 1,
        )
    assert fake_store.put_calls == []


# --------------------------------------------------------------------------- #
# Envelope integrity
# --------------------------------------------------------------------------- #


def test_unrecognised_envelope_marker_is_a_named_error(
    wm: WorkingMemory, fake_valkey: FakeValkey
) -> None:
    # Simulates data written by something other than this module (or a
    # future incompatible envelope version) reaching a read path here.
    key = working_memory_key(_PROJECT_A, _RUN, "corrupt")
    fake_valkey.data[key] = b"\x02not-a-real-envelope"
    with pytest.raises(ValueError, match="envelope marker"):
        wm.get(_PROJECT_A, _RUN, "corrupt")


# --------------------------------------------------------------------------- #
# Key isolation — invariant 4, offline half (pure: two projects, identical
# everything else -> different keys, neither readable via the other's).
# --------------------------------------------------------------------------- #


def test_identical_run_and_key_are_isolated_across_projects(wm: WorkingMemory) -> None:
    wm.set(_PROJECT_A, _RUN, "scratch", b"project-a-secret", token_count=1)
    assert wm.get(_PROJECT_B, _RUN, "scratch") is None


def test_project_a_and_b_working_memory_keys_are_disjoint(fake_valkey: FakeValkey) -> None:
    key_a = working_memory_key(_PROJECT_A, _RUN, "scratch")
    key_b = working_memory_key(_PROJECT_B, _RUN, "scratch")
    assert key_a != key_b
    pattern_a = project_key_pattern(_PROJECT_A)
    assert fnmatch.fnmatchcase(key_a, pattern_a)
    assert not fnmatch.fnmatchcase(key_b, pattern_a)


def test_spilled_content_is_isolated_across_projects(
    fake_valkey: FakeValkey, fake_store: FakeTraceStore, small_threshold_cfg: SessionConfig
) -> None:
    wm = WorkingMemory(ValkeyClient(fake_valkey), fake_store, small_threshold_cfg)
    threshold = small_threshold_cfg.offload_threshold_tokens
    wm.set(_PROJECT_A, _RUN, "scratch", b"a-secret" * 1000, token_count=threshold + 1)
    # Project B reading its own (never-written) key must never surface
    # project A's spilled content, even though the two runs share a run_id.
    assert wm.get(_PROJECT_B, _RUN, "scratch") is None


def test_a_pointer_planted_in_another_projects_namespace_fails_closed(
    fake_valkey: FakeValkey, fake_store: FakeTraceStore, small_threshold_cfg: SessionConfig
) -> None:
    # Defence in depth beyond key isolation: the spilled pointer is resolved
    # with the READER's project_id, never with anything the envelope itself
    # carries. So even a Valkey value copied verbatim into project B's
    # namespace — a poisoned cache, a bad restore, a bug in a future writer —
    # cannot resolve project A's blob; the trace store refuses the ref before
    # any I/O. An implementation that parsed the project out of `ref.key` and
    # passed THAT to `store.get` would hand B project A's secret and pass
    # every other isolation test in this file.
    wm = WorkingMemory(ValkeyClient(fake_valkey), fake_store, small_threshold_cfg)
    threshold = small_threshold_cfg.offload_threshold_tokens
    wm.set(_PROJECT_A, _RUN, "scratch", b"a-secret" * 1000, token_count=threshold + 1)
    envelope = fake_valkey.data[working_memory_key(_PROJECT_A, _RUN, "scratch")]
    fake_valkey.data[working_memory_key(_PROJECT_B, _RUN, "scratch")] = envelope

    with pytest.raises(NotFound):
        wm.get(_PROJECT_B, _RUN, "scratch")


def test_flush_erases_one_projects_working_memory_and_leaves_the_others(
    fake_valkey: FakeValkey, fake_store: FakeTraceStore, small_threshold_cfg: SessionConfig
) -> None:
    # `flush.flush_project_cache` is the `cache_flush` handler; a flush that
    # swept a neighbour's keys would be a cross-project erasure, which is the
    # same wall failure as a cross-project read, in the other direction.
    client = ValkeyClient(fake_valkey)
    wm = WorkingMemory(client, fake_store, small_threshold_cfg)
    wm.set(_PROJECT_A, _RUN, "scratch", b"a-value", token_count=1)
    wm.set(_PROJECT_B, _RUN, "scratch", b"b-value", token_count=1)

    assert flush_project_cache(client, _PROJECT_A) == 1
    assert wm.get(_PROJECT_A, _RUN, "scratch") is None
    survivor = wm.get(_PROJECT_B, _RUN, "scratch")
    assert survivor == WorkingMemoryEntry(value=b"b-value", spilled=False)


# --------------------------------------------------------------------------- #
# Live round trip (integration; skips cleanly with no Valkey — contract §12)
# --------------------------------------------------------------------------- #


@pytest.mark.integration
def test_working_memory_live_round_trip(valkey_url: str) -> None:  # noqa: F811
    store = FakeTraceStore()  # the trace-store half stays a double; only Valkey is live here
    client = ValkeyClient.from_url(valkey_url)
    try:
        cfg = SessionConfig(idle_ttl_min=1, offload_threshold_tokens=10)
        wm = WorkingMemory(client, store, cfg)
        project = ProjectId(uuid7())
        run = RunId(uuid7())
        try:
            wm.set(project, run, "scratch", b"live content", token_count=1)
            entry = wm.get(project, run, "scratch")
            assert entry == WorkingMemoryEntry(value=b"live content", spilled=False)

            big = b"z" * 5000
            wm.set(project, run, "big", big, token_count=cfg.offload_threshold_tokens + 1)
            spilled_entry = wm.get(project, run, "big")
            assert spilled_entry == WorkingMemoryEntry(value=big, spilled=True)
        finally:
            client.working_memory_delete(project, run, "scratch")
            client.working_memory_delete(project, run, "big")
    finally:
        client.close()
