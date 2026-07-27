"""`workers.prefix_builder` — static prefix budget splitting, determinism, versioning,
and the Valkey write (PLAN.md §7 Phase 2; D-016).

Fully offline: `MemoryStorePort`/`StaticPrefixCachePort`/`ConfigProvider` are satisfied by
small recording fakes (no Postgres, no Valkey), and `EffectiveConfig` is built from the real
Phase 0 section models so a field rename in `domain/config.py` breaks this test rather than
staying silently green (same pattern as `tests/phase1/test_assembler.py`).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import NAMESPACE_OID, uuid4, uuid5

import pytest

from tracebed.domain.config import (
    AbstentionConfig,
    BudgetConfig,
    CacheConfig,
    DerivedConfig,
    EffectiveConfig,
    KillswitchConfig,
    LifecycleConfig,
    PromotionConfig,
    ProposalConfig,
    QueueConfig,
    RetirementConfig,
    RetrievalConfig,
    ScoreConfig,
    ScoringConfig,
    SessionConfig,
    SpendConfig,
    TierAConfig,
)
from tracebed.domain.enums import Lane, MemType, ScopeType, Slot, TrustTier
from tracebed.domain.errors import TracebedError
from tracebed.domain.ids import AgentTypeId, MemoryId, ProjectId
from tracebed.domain.memory import Provenance, ProvenanceClass
from tracebed.domain.state_machine import Status
from tracebed.stores.pg.repo import MAX_ROW_LIMIT
from tracebed.stores.pg.rows import MemoryItemRow
from tracebed.workers.prefix_builder import (
    ConfigProvider,
    PrefixBuilder,
    build_static_prefix,
)

pytestmark = pytest.mark.phase2

AGENT_TYPE = AgentTypeId(uuid4())
OTHER_AGENT_TYPE = AgentTypeId(uuid4())
PROJECT = ProjectId(uuid4())
NOW = datetime(2026, 7, 26, 12, 0, 0, tzinfo=UTC)


def _effective_config(**overrides: object) -> EffectiveConfig:
    sections: dict[str, object] = {
        "retrieval": RetrievalConfig(),
        "abstention": AbstentionConfig(),
        "score": ScoreConfig(),
        "budget": BudgetConfig(),
        "scoring": ScoringConfig(),
        "promotion": PromotionConfig(),
        "retirement": RetirementConfig(),
        "lifecycle": LifecycleConfig(),
        "derived": DerivedConfig(),
        "proposals": ProposalConfig(),
        "tier_a": TierAConfig(),
        "killswitch": KillswitchConfig(),
        "spend": SpendConfig(),
        "cache": CacheConfig(),
        "session": SessionConfig(),
        "queue": QueueConfig(),
    }
    sections.update(overrides)
    return EffectiveConfig(**sections)


def _mid(tag: str) -> MemoryId:
    """A deterministic `MemoryId` for any short `tag` string (unlike a fixed-width hex
    fill-in, this tolerates multi-character tags like "a0")."""
    return MemoryId(uuid5(NAMESPACE_OID, f"prefix-builder-test-{tag}"))


def _pref(
    tag: str,
    *,
    tokens: int = 50,
    content: str | None = None,
    created_at: datetime | None = None,
    agent_type_id: AgentTypeId = AGENT_TYPE,
    scope_type: ScopeType = ScopeType.AGENT_TYPE,
    status: Status = Status.PINNED,
    provenance_class: ProvenanceClass = ProvenanceClass.OPERATOR,
) -> MemoryItemRow:
    text = content if content is not None else f"preference {tag}"
    return MemoryItemRow(
        id=_mid(tag),
        project_id=PROJECT,
        scope_type=scope_type,
        scope_id=None if scope_type is ScopeType.PROJECT_SHARED else agent_type_id.value,
        mem_type=MemType.PREFERENCE,
        kind="preference",
        lane=Lane.OPERATIONAL,
        trust_tier=TrustTier.A,
        status=status,
        content=text,
        content_hash=text,  # a fixture stand-in; only equality/inequality is exercised
        token_count=tokens,
        subject_tag=None,
        q_value=0.5,
        confidence=1.0,
        scored_use_count=0,
        strike_count=0,
        provenance=Provenance(cls=provenance_class, principal=None),
        scan_verdict_id=uuid4(),
        schema_version=1,
        created_at=created_at if created_at is not None else NOW - timedelta(days=1),
        status_changed_at=None,
    )


def _lesson(
    tag: str,
    *,
    tokens: int = 50,
    content: str | None = None,
    q_value: float = 0.8,
    agent_type_id: AgentTypeId = AGENT_TYPE,
    scope_type: ScopeType = ScopeType.AGENT_TYPE,
    status: Status = Status.VALIDATED,
    provenance_class: ProvenanceClass = ProvenanceClass.DISTILLER,
) -> MemoryItemRow:
    text = content if content is not None else f"lesson {tag}"
    return MemoryItemRow(
        id=_mid(tag),
        project_id=PROJECT,
        scope_type=scope_type,
        scope_id=None if scope_type is ScopeType.PROJECT_SHARED else agent_type_id.value,
        mem_type=MemType.LESSON,
        kind="lesson",
        lane=Lane.QUALITY,
        trust_tier=TrustTier.B,
        status=status,
        content=text,
        content_hash=text,
        token_count=tokens,
        subject_tag=None,
        q_value=q_value,
        confidence=0.9,
        scored_use_count=4,
        strike_count=0,
        provenance=Provenance(cls=provenance_class, trace_ids=()),
        scan_verdict_id=uuid4(),
        schema_version=1,
        created_at=NOW - timedelta(days=2),
        status_changed_at=None,
    )


# Provenance() with an empty trace_ids/no principal is never validated by this module (it
# only reads scope/status/mem_type/content/tokens/q_value/created_at/content_hash), so the
# fixtures above are deliberately loose about provenance completeness.


# --------------------------------------------------------------------------- #
# Budget splitting.
# --------------------------------------------------------------------------- #


def test_prefs_and_lessons_each_respect_their_own_sub_budget() -> None:
    cfg = _effective_config(budget=BudgetConfig(static_prefix_prefs=100, static_prefix_lessons=100))
    prefs = [_pref(str(i), tokens=60) for i in range(3)]  # 180 offered against a 100 cap
    lessons = [_lesson(f"a{i}", tokens=60) for i in range(3)]  # same
    result = build_static_prefix([*prefs, *lessons], agent_type_id=AGENT_TYPE, cfg=cfg)

    assert result.prefs_tokens <= 100
    assert result.lessons_tokens <= 100
    assert result.prefs_tokens == 60  # exactly one 60-token pref fits under 100
    assert result.lessons_tokens == 60


def test_lessons_get_whatever_the_prefs_pool_left_of_the_shared_static_pool() -> None:
    """`static_prefix` (the outer 700-token pool) is shared: prefs spend first, lessons get
    the remainder, capped at their own `static_prefix_lessons`."""
    cfg = _effective_config(
        budget=BudgetConfig(
            static_prefix=150, static_prefix_prefs=200, static_prefix_lessons=200
        )
    )
    prefs = [_pref("1", tokens=100)]
    lessons = [_lesson("a", tokens=100)]
    result = build_static_prefix([*prefs, *lessons], agent_type_id=AGENT_TYPE, cfg=cfg)

    assert result.prefs_tokens == 100
    # Only 50 of the 150-token outer pool remains after prefs spent 100.
    assert result.lessons_tokens == 0
    assert result.dropped_memory_ids == (lessons[0].id,)


def test_total_tokens_clamps_the_static_pool_even_if_the_split_configs_disagree() -> None:
    """An operator override can lower `total_tokens` without also lowering
    `static_prefix`/`static_prefix_prefs`/`static_prefix_lessons` — the outer clamp must
    still hold (mirrors `hotpath.assembler.assemble`'s own clamp test)."""
    cfg = _effective_config(budget=BudgetConfig(total_tokens=50))
    prefs = [_pref("1", tokens=200)]
    result = build_static_prefix(prefs, agent_type_id=AGENT_TYPE, cfg=cfg)
    assert result.prefs_tokens == 0
    assert result.context_block.rendered == ""


def test_a_lesson_larger_than_any_remaining_budget_is_dropped_whole_not_truncated() -> None:
    cfg = _effective_config(budget=BudgetConfig(static_prefix_lessons=10))
    lessons = [_lesson("a", tokens=11)]
    result = build_static_prefix(lessons, agent_type_id=AGENT_TYPE, cfg=cfg)
    assert result.lessons_tokens == 0
    assert result.dropped_memory_ids == (lessons[0].id,)


# --------------------------------------------------------------------------- #
# Scope.
# --------------------------------------------------------------------------- #


def test_a_different_agent_types_scoped_row_is_excluded() -> None:
    cfg = _effective_config()
    other = _pref("1", agent_type_id=OTHER_AGENT_TYPE)
    result = build_static_prefix([other], agent_type_id=AGENT_TYPE, cfg=cfg)
    assert result.context_block.slots == []
    assert result.dropped_memory_ids == ()  # never in scope at all -- not "dropped"


def test_project_shared_rows_are_included_for_every_agent_type() -> None:
    cfg = _effective_config()
    shared = _pref("1", scope_type=ScopeType.PROJECT_SHARED)
    result = build_static_prefix([shared], agent_type_id=AGENT_TYPE, cfg=cfg)
    assert [s.memory_id for s in result.context_block.slots] == [shared.id.value]
    result_other = build_static_prefix([shared], agent_type_id=OTHER_AGENT_TYPE, cfg=cfg)
    assert [s.memory_id for s in result_other.context_block.slots] == [shared.id.value]


def test_only_pinned_preferences_and_validated_lessons_are_eligible() -> None:
    """A quarantined lesson or a candidate-status preference must never reach the prefix
    (PLAN.md §5's retrievable-statuses note: pinned is prefix-only, and a lesson must have
    actually been validated, not merely proposed)."""
    cfg = _effective_config()
    quarantined_lesson = _lesson("a", status=Status.QUARANTINED)
    candidate_pref = _pref("1", status=Status.CANDIDATE)
    result = build_static_prefix([quarantined_lesson, candidate_pref], agent_type_id=AGENT_TYPE, cfg=cfg)
    assert result.context_block.slots == []


# --------------------------------------------------------------------------- #
# Determinism and versioning.
# --------------------------------------------------------------------------- #


def test_deterministic_for_a_given_input_set_regardless_of_input_order() -> None:
    cfg = _effective_config()
    prefs = [_pref(str(i)) for i in range(3)]
    lessons = [_lesson(f"a{i}", q_value=0.5 + i / 10) for i in range(3)]
    rows = [*prefs, *lessons]

    first = build_static_prefix(rows, agent_type_id=AGENT_TYPE, cfg=cfg)
    second = build_static_prefix(list(reversed(rows)), agent_type_id=AGENT_TYPE, cfg=cfg)

    assert first.context_block.rendered == second.context_block.rendered
    assert first.prefix_version == second.prefix_version
    assert first.prefs_tokens == second.prefs_tokens
    assert first.lessons_tokens == second.lessons_tokens


def test_lessons_are_packed_highest_q_value_first() -> None:
    cfg = _effective_config(budget=BudgetConfig(static_prefix_lessons=60))
    low = _lesson("a", tokens=60, q_value=0.1)
    high = _lesson("b", tokens=60, q_value=0.9)
    result = build_static_prefix([low, high], agent_type_id=AGENT_TYPE, cfg=cfg)
    assert [s.memory_id for s in result.context_block.slots] == [high.id.value]


def test_prefs_are_packed_oldest_first() -> None:
    """Pinned preferences carry no meaningful Q (D-014: ungoverned, never scored), so the
    pin's own age is the only ordering signal the schema offers. With room for exactly one,
    the older pin must be the one that survives -- otherwise every new pin silently evicts
    the standing one and the "static" prefix is not static at all."""
    cfg = _effective_config(budget=BudgetConfig(static_prefix_prefs=60))
    older = _pref("1", tokens=60, created_at=NOW - timedelta(days=30))
    newer = _pref("2", tokens=60, created_at=NOW - timedelta(days=1))
    result = build_static_prefix([newer, older], agent_type_id=AGENT_TYPE, cfg=cfg)
    assert [s.memory_id for s in result.context_block.slots] == [older.id.value]


def test_a_row_collapsed_by_content_dedup_is_reported_as_dropped() -> None:
    """`dropped_memory_ids` is the ONLY observable record of an in-scope row that did not
    reach the block. Deriving it from the post-dedup pools reported a deduped row as if it
    had never been in scope, which is indistinguishable from "another agent-type owns it"
    (D-056 removed the same blind spot from `hotpath.assembler`)."""
    cfg = _effective_config()
    a = _pref("1", content="same text")
    b = _pref("2", content="same text")
    result = build_static_prefix([a, b], agent_type_id=AGENT_TYPE, cfg=cfg)

    survivor = min(a.id, b.id, key=str)
    loser = max(a.id, b.id, key=str)
    assert [s.memory_id for s in result.context_block.slots] == [survivor.value]
    assert result.dropped_memory_ids == (loser,)


def test_identical_content_collapses_to_one_entry() -> None:
    cfg = _effective_config()
    a = _pref("1", content="same text")
    b = _pref("2", content="same text")
    result = build_static_prefix([a, b], agent_type_id=AGENT_TYPE, cfg=cfg)
    assert len(result.context_block.slots) == 1
    # Deterministic tie-break: the lower memory_id survives.
    survivor = min(a.id, b.id, key=str)
    assert result.context_block.slots[0].memory_id == survivor.value


def test_a_changed_input_set_bumps_the_prefix_version() -> None:
    cfg = _effective_config()
    base = [_pref("1")]
    changed = [_pref("1"), _lesson("a")]

    version_before = build_static_prefix(base, agent_type_id=AGENT_TYPE, cfg=cfg).prefix_version
    version_after = build_static_prefix(changed, agent_type_id=AGENT_TYPE, cfg=cfg).prefix_version
    assert version_before != version_after

    # And the mirror: re-running on the SAME set reproduces the SAME version.
    again = build_static_prefix(base, agent_type_id=AGENT_TYPE, cfg=cfg).prefix_version
    assert again == version_before


def test_prefix_version_is_a_non_negative_int() -> None:
    cfg = _effective_config()
    result = build_static_prefix([_pref("1")], agent_type_id=AGENT_TYPE, cfg=cfg)
    assert isinstance(result.prefix_version, int)
    assert result.prefix_version >= 0


# --------------------------------------------------------------------------- #
# Rendering: STATIC_PREFIX only, never a dynamic slot.
# --------------------------------------------------------------------------- #


def test_only_the_static_prefix_slot_is_ever_produced() -> None:
    cfg = _effective_config()
    result = build_static_prefix(
        [_pref("1"), _lesson("a")], agent_type_id=AGENT_TYPE, cfg=cfg
    )
    assert {s.slot for s in result.context_block.slots} == {Slot.STATIC_PREFIX}


def test_empty_input_renders_the_empty_block() -> None:
    cfg = _effective_config()
    result = build_static_prefix([], agent_type_id=AGENT_TYPE, cfg=cfg)
    assert result.context_block.slots == []
    assert result.context_block.rendered == ""


# --------------------------------------------------------------------------- #
# Provenance eligibility: the prefix is the one ungated path into every prompt.
# --------------------------------------------------------------------------- #


def test_a_pinned_row_that_is_not_operator_created_is_refused() -> None:
    """`state_machine._guard_none_to_pinned` admits provenance class `operator` only
    (D-014). `pinned` is the ungoverned status -- never scored, never quarantined, never
    shadow-confirmed -- so operator authorship is the entire basis on which it is trusted,
    and a distiller-authored pinned row is content-derived memory in every prompt with the
    whole Tier B quarantine gate bypassed."""
    cfg = _effective_config()
    forged = _pref("1", provenance_class=ProvenanceClass.DISTILLER)
    with pytest.raises(TracebedError, match="only 'operator'"):
        build_static_prefix([forged], agent_type_id=AGENT_TYPE, cfg=cfg)


def test_a_proposal_class_row_is_refused_even_at_validated() -> None:
    """D-023: a `proposal` can never exit quarantine by any route, so a validated proposal
    is a row that could only exist if the state machine had been bypassed -- exactly the
    two-call `propose_memory` Sybil route into context that D-023 exists to close."""
    cfg = _effective_config()
    smuggled = _lesson("a", provenance_class=ProvenanceClass.PROPOSAL)
    with pytest.raises(TracebedError, match="proposal"):
        build_static_prefix([smuggled], agent_type_id=AGENT_TYPE, cfg=cfg)


def test_eligibility_is_only_asserted_on_rows_this_agent_type_would_actually_use() -> None:
    """`build_static_prefix` receives the whole project's pinned/validated population, so a
    bad row belonging to a DIFFERENT agent-type must not take this agent-type's prefix down
    with it -- otherwise one poisoned row denies the feature to the entire project."""
    cfg = _effective_config()
    forged_elsewhere = _pref(
        "1", agent_type_id=OTHER_AGENT_TYPE, provenance_class=ProvenanceClass.DISTILLER
    )
    ours = _pref("2")
    result = build_static_prefix([forged_elsewhere, ours], agent_type_id=AGENT_TYPE, cfg=cfg)
    assert [s.memory_id for s in result.context_block.slots] == [ours.id.value]


# --------------------------------------------------------------------------- #
# PrefixBuilder: the Repo/Valkey wiring, via recording fakes.
# --------------------------------------------------------------------------- #


class _FakeStore:
    def __init__(self, rows: list[MemoryItemRow]) -> None:
        self._rows = rows
        self.calls: list[tuple[ProjectId, list[Status] | None, int]] = []

    def list_memories(
        self, project_id: ProjectId, *, statuses: list[Status] | None = None, limit: int = 100
    ) -> list[MemoryItemRow]:
        self.calls.append((project_id, statuses, limit))
        wanted = None if statuses is None else set(statuses)
        return [r for r in self._rows if wanted is None or r.status in wanted]


class _FakeCache:
    def __init__(self) -> None:
        self.writes: list[dict[str, object]] = []
        self.pointer_writes: list[dict[str, object]] = []
        self.call_order: list[str] = []

    def static_prefix_set(
        self,
        project_id: ProjectId,
        agent_type_id: AgentTypeId,
        prefix_version: int,
        value: bytes,
        *,
        ttl_seconds: int,
    ) -> None:
        self.call_order.append("block")
        self.writes.append(
            {
                "project_id": project_id,
                "agent_type_id": agent_type_id,
                "prefix_version": prefix_version,
                "value": value,
                "ttl_seconds": ttl_seconds,
            }
        )

    def current_prefix_version_set(
        self,
        project_id: ProjectId,
        agent_type_id: AgentTypeId,
        prefix_version: int,
        *,
        ttl_seconds: int,
    ) -> None:
        self.call_order.append("pointer")
        self.pointer_writes.append(
            {
                "project_id": project_id,
                "agent_type_id": agent_type_id,
                "prefix_version": prefix_version,
                "ttl_seconds": ttl_seconds,
            }
        )


class _FakeConfig:
    def __init__(self, cfg: EffectiveConfig) -> None:
        self._cfg = cfg

    def effective(
        self, project_id: ProjectId, agent_type_id: AgentTypeId | None = None
    ) -> EffectiveConfig:
        return self._cfg


def test_fake_config_provider_satisfies_the_real_port() -> None:
    assert isinstance(_FakeConfig(_effective_config()), ConfigProvider)


def test_run_fetches_pinned_and_validated_only() -> None:
    store = _FakeStore([_pref("1"), _lesson("a")])
    builder = PrefixBuilder(store=store, cache=_FakeCache(), config=_FakeConfig(_effective_config()))
    builder.run(PROJECT, AGENT_TYPE)
    (project_id, statuses, _limit) = store.calls[0]
    assert project_id == PROJECT
    assert set(statuses or []) == {Status.PINNED, Status.VALIDATED}


def test_run_writes_the_rendered_block_under_the_returned_version() -> None:
    store = _FakeStore([_pref("1")])
    cache = _FakeCache()
    builder = PrefixBuilder(store=store, cache=cache, config=_FakeConfig(_effective_config()))
    result = builder.run(PROJECT, AGENT_TYPE)

    assert len(cache.writes) == 1
    write = cache.writes[0]
    assert write["project_id"] == PROJECT
    assert write["agent_type_id"] == AGENT_TYPE
    assert write["prefix_version"] == result.prefix_version
    assert write["ttl_seconds"] > 0
    assert write["value"] == result.context_block.model_dump_json().encode("utf-8")


def test_the_cache_key_embeds_project_and_version() -> None:
    """`stores.valkey.keys.static_prefix_key` is the one function permitted to build the
    `px:` key; this proves `PrefixBuilder.run`'s output plugs straight into it and that the
    resulting key names both this project and this exact version."""
    from tracebed.stores.valkey.keys import static_prefix_key

    store = _FakeStore([_pref("1")])
    cache = _FakeCache()
    builder = PrefixBuilder(store=store, cache=cache, config=_FakeConfig(_effective_config()))
    result = builder.run(PROJECT, AGENT_TYPE)

    key = static_prefix_key(PROJECT, AGENT_TYPE, result.prefix_version)
    assert key == f"tb:{PROJECT}:px:{AGENT_TYPE}:{result.prefix_version}"

    other = static_prefix_key(PROJECT, AGENT_TYPE, result.prefix_version + 1)
    assert other != key  # a different version is a different key, never an overwrite


def test_the_published_block_is_reachable_from_a_scope_alone() -> None:
    """The gap that made this worker inert: `prefix_version` is derived from the packed
    content, so a reader holding only a `ProjectScope` could never compute the key segment
    it needs. `current_prefix_version_key` is the indirection that closes it -- this walks
    the exact reader path (GET pointer -> GET block) against the two keys the builder
    published, with nothing but (project_id, agent_type_id) in hand."""
    from tracebed.stores.valkey.keys import current_prefix_version_key, static_prefix_key

    store = _FakeStore([_pref("1")])
    cache = _FakeCache()
    builder = PrefixBuilder(store=store, cache=cache, config=_FakeConfig(_effective_config()))
    result = builder.run(PROJECT, AGENT_TYPE)

    keyspace: dict[str, bytes] = {
        static_prefix_key(
            PROJECT, AGENT_TYPE, int(cache.writes[0]["prefix_version"])  # type: ignore[call-overload]
        ): bytes(cache.writes[0]["value"]),  # type: ignore[call-overload]
        current_prefix_version_key(PROJECT, AGENT_TYPE): str(
            cache.pointer_writes[0]["prefix_version"]
        ).encode("ascii"),
    }

    live_version = int(keyspace[current_prefix_version_key(PROJECT, AGENT_TYPE)])
    block = keyspace[static_prefix_key(PROJECT, AGENT_TYPE, live_version)]

    assert live_version == result.prefix_version
    assert block == result.context_block.model_dump_json().encode("utf-8")


def test_the_pointer_is_published_after_the_block_it_names() -> None:
    """Order is the whole safety property. A pointer written first names bytes that are not
    in the cache yet, so every reader in that interval takes a hard miss on the exact
    degradation-ladder rung the prefix cache exists to serve. Block-then-pointer means the
    worst intermediate state is a pointer still naming the PREVIOUS version: stale but
    complete."""
    cache = _FakeCache()
    builder = PrefixBuilder(
        store=_FakeStore([_pref("1")]), cache=cache, config=_FakeConfig(_effective_config())
    )
    builder.run(PROJECT, AGENT_TYPE)

    assert cache.call_order == ["block", "pointer"]
    assert cache.pointer_writes[0]["prefix_version"] == cache.writes[0]["prefix_version"]
    assert cache.pointer_writes[0]["ttl_seconds"] == cache.writes[0]["ttl_seconds"]


def test_a_refused_build_publishes_neither_the_block_nor_the_pointer() -> None:
    """A refusal must not leave the pointer naming a version whose block was never written.
    The ceiling refusal happens before either write, so both stay untouched and the
    previously published version keeps serving until its own TTL expires."""
    cache = _FakeCache()
    store = _FakeStore([_pref(str(i)) for i in range(MAX_ROW_LIMIT)])
    builder = PrefixBuilder(store=store, cache=cache, config=_FakeConfig(_effective_config()))

    with pytest.raises(TracebedError):
        builder.run(PROJECT, AGENT_TYPE)

    assert cache.writes == []
    assert cache.pointer_writes == []


def test_a_full_page_from_the_store_is_refused_rather_than_built_on() -> None:
    """`Repo.list_memories` is `ORDER BY created_at DESC LIMIT MAX_ROW_LIMIT` with no
    cursor: at the ceiling the worker holds the NEWEST 1000 rows, which silently drops the
    oldest pinned preferences (the ones packed first) and makes the input set -- and
    therefore `prefix_version` -- change on every unrelated insert in the project. Building
    on that window is worse than not building: it publishes a wrong prefix that looks
    right."""
    cache = _FakeCache()
    store = _FakeStore([_pref(str(i)) for i in range(MAX_ROW_LIMIT)])
    builder = PrefixBuilder(store=store, cache=cache, config=_FakeConfig(_effective_config()))

    with pytest.raises(TracebedError, match="row ceiling"):
        builder.run(PROJECT, AGENT_TYPE)
    assert cache.writes == []  # nothing half-built reaches the cache


def test_a_page_one_row_short_of_the_ceiling_still_builds() -> None:
    """The refusal above is `>=` on a full page, so the boundary matters: a project holding
    exactly `MAX_ROW_LIMIT - 1` rows is complete, not truncated, and must still get a
    prefix."""
    store = _FakeStore([_pref(str(i)) for i in range(MAX_ROW_LIMIT - 1)])
    cache = _FakeCache()
    builder = PrefixBuilder(store=store, cache=cache, config=_FakeConfig(_effective_config()))
    builder.run(PROJECT, AGENT_TYPE)
    assert len(cache.writes) == 1
