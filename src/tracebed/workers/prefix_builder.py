"""Static prefix builder: per-agent-type cacheable block (PLAN.md §7 Phase 2; D-016).

A WORKER, not hot-path code — it may import whatever it needs (PLAN.md §3's module table:
"Workers may import anything"). It builds, from pinned preferences and durable (validated)
lessons, the STATIC_PREFIX content the hot path serves back out through
`hotpath.pipeline.StaticPrefixPort` and, going forward, whatever wires the happy-path
assembler to the same cache (see the CONTRACT GAP below) — never the other way around: this
module never runs on the request path itself.

PLACEMENT IS THE POINT, and it is an audit finding, not a preference (PLAN.md §7, D-016,
verbatim): the static prefix is cacheable content and the DYNAMIC memory block goes LAST,
after it. A provider's prompt cache invalidates a changed block AND everything textually
after it; putting the dynamic block first would invalidate the entire cached prefix on
every single call — the exact opposite of the saving the static prefix exists to produce.
This module's own contribution to that invariant is narrow but concrete: it renders
`Slot.STATIC_PREFIX` ONLY (`hotpath.templates.SLOT_ORDER` puts that slot first for exactly
this reason) and never touches a dynamic slot, so a cached prefix built here can never
itself be the thing that ends up after the dynamic block — placement is enforced by
`hotpath.assembler.assemble` / `hotpath.renderer.render` (already built, Phase 1), and this
worker produces input for that enforcement, not a second copy of it.

CONTRACT GAP (reported, not silently patched): on the ORDINARY (non-degraded) retrieval
path, `hotpath.assembly.CandidateAssembly` never surfaces `Slot.STATIC_PREFIX` content,
because pinned preferences live at `Status.PINNED` and `stores.pg.search.SearchStore`'s
dynamic arms deliberately exclude that status (that module's own docstring: "pinned ... is
enforced in the prefix builder, Phase 2"). Wiring the cache this worker writes into the
happy path (today `hotpath.pipeline.StaticPrefixPort` is only consulted on the
`timeout_prefix_only` ladder rung) is `hotpath/pipeline.py`'s responsibility, a Phase 1 file
outside this chunk's file list — reported here rather than edited there.

VERSIONING (`prefix_version`, `stores.valkey.keys.static_prefix_key`'s third segment): no
PLAN.md/PHASE0-CONTRACT.md text pins how a version number is derived, so this chunk derives
it from the packed content itself (a truncated sha256 of the exact `(memory_id,
content_hash)` sequence that was actually selected) rather than maintaining an external
counter — a `memory_item` table row, a Valkey counter key, or similar sequencing state
exists nowhere in the frozen Phase 0 schema for this purpose, and inventing one would be
exactly the kind of un-pinned state hard rule 4 exists to prevent. Content-hash versioning
gets both required properties for free: identical input always yields the identical version
(determinism), and a version can only change if the packed set changed (the same technique
`domain.canonical.content_hash` already uses for `memory_item.content_hash`).

READBACK (was the load-bearing gap; now closed in `stores/valkey/`): a reader holding only
`(project_id, agent_type_id, principal_id)` — which is all `hotpath.pipeline
.StaticPrefixPort.get(scope)` receives — cannot derive a content-hashed `prefix_version`,
and `stores/valkey/client.py` exposes no pattern scan to go looking. The resolution is one
indirection: `stores.valkey.keys.current_prefix_version_key` names a pointer holding the
live version, and `ValkeyClient.current_prefix_version_set` repoints it. `publish` below
takes a `PrefixPublisherPort` covering both writes and performs them in the only safe order
(block first, pointer second); a pointer written first names bytes that are not there yet,
which is a hard miss on the one ladder rung that exists to avoid one. The key format lives
in `stores/valkey/keys.py` — the only module `scripts/raw_sql_lint.py` permits a key prefix
literal — and not here (hard rule 2). What remains open is the LAST hop: nothing constructs
a `StaticPrefixPort` over `ValkeyClient` yet, and `hotpath/pipeline.py` still consults the
port only on the `timeout_prefix_only` rung.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from typing import Final, Protocol, runtime_checkable

from tracebed.domain.canonical import canonical_json, sha256_hex
from tracebed.domain.config import EffectiveConfig
from tracebed.domain.enums import MemType, ProvenanceClass, ScopeType, Slot
from tracebed.domain.errors import TracebedError
from tracebed.domain.events import ContextBlock, ContextSlot
from tracebed.domain.ids import AgentTypeId, MemoryId, ProjectId
from tracebed.domain.state_machine import Status
from tracebed.hotpath.renderer import render
from tracebed.stores.pg.repo import MAX_ROW_LIMIT
from tracebed.stores.pg.rows import MemoryItemRow
from tracebed.stores.valkey.tool_cache import resolve_ttl_class

__all__ = [
    "ConfigProvider",
    "MemoryStorePort",
    "PrefixBuildResult",
    "PrefixBuilder",
    "StaticPrefixCachePort",
    "assert_prefix_eligible",
    "build_static_prefix",
]

# No `cache.ttl_class` key is named for the static prefix by PLAN.md §6 (only "intel" and
# "registry" ship by default). "registry" — the slower-changing class (14d default) — is
# chosen and named here as a decision, not a silent literal: pinned preferences and
# validated lessons for an agent-type change on the same "someone edited the registry of
# durable facts about this agent" cadence "registry" already describes, not the "intel"
# class's 24h freshness window meant for retrieved, per-query content.
_STATIC_PREFIX_TTL_CLASS: Final[str] = "registry"


@runtime_checkable
class MemoryStorePort(Protocol):
    """Exactly `stores.pg.repo.Repo.list_memories`'s call shape — narrowed so this worker's
    tests never need a live Postgres pool (there is none in this environment)."""

    def list_memories(
        self,
        project_id: ProjectId,
        *,
        statuses: Sequence[Status] | None = None,
        limit: int = 100,
    ) -> list[MemoryItemRow]: ...


@runtime_checkable
class StaticPrefixCachePort(Protocol):
    """Both halves of publishing a prefix, mirroring `stores.valkey.client.ValkeyClient`.

    One port, not two, because the two writes are not independently useful:
    a block with no pointer is unreachable (the reader cannot derive the
    version), and a pointer with no block is a hard miss on the ladder rung
    that exists to avoid one. A port that made either write optional would
    make "published" mean two different things.
    """

    def static_prefix_set(
        self,
        project_id: ProjectId,
        agent_type_id: AgentTypeId,
        prefix_version: int,
        value: bytes,
        *,
        ttl_seconds: int,
    ) -> None: ...

    def current_prefix_version_set(
        self,
        project_id: ProjectId,
        agent_type_id: AgentTypeId,
        prefix_version: int,
        *,
        ttl_seconds: int,
    ) -> None: ...


@runtime_checkable
class ConfigProvider(Protocol):
    """What `PrefixBuilder` needs to resolve per-(project, agent_type) settings. Declared
    locally rather than imported from `hotpath.pipeline` (which declares the identical
    shape for the identical reason) so this worker has no import-time dependency on
    hot-path code; `domain.config.ConfigResolver` satisfies both structurally."""

    def effective(
        self, project_id: ProjectId, agent_type_id: AgentTypeId | None = None
    ) -> EffectiveConfig: ...


@dataclass(frozen=True, slots=True)
class PrefixBuildResult:
    """What one build produced — enough for a caller to both cache it and audit it."""

    agent_type_id: AgentTypeId
    prefix_version: int
    context_block: ContextBlock
    prefs_tokens: int
    lessons_tokens: int
    dropped_memory_ids: tuple[MemoryId, ...]
    """Every in-scope pinned preference / validated lesson that did NOT make it into
    `context_block` — dropped by content-dedup or because no budget remained. Sorted by
    `str(memory_id)` for a deterministic, diffable report, mirroring
    `hotpath.assembler.AssembledContext.dropped_memory_ids` exactly."""


def _in_scope(row: MemoryItemRow, agent_type_id: AgentTypeId) -> bool:
    """This agent-type's own scoped rows, plus anything shared project-wide. `USER` and
    `WORKFLOW_TEMPLATE` scoped rows are deliberately excluded: PLAN.md §7 says "per
    agent-type", and neither of those two scopes names an agent type at all."""
    if row.scope_type is ScopeType.PROJECT_SHARED:
        return True
    return row.scope_type is ScopeType.AGENT_TYPE and row.scope_id == agent_type_id.value


def assert_prefix_eligible(row: MemoryItemRow) -> None:
    """Invariant 7's prefix-side half, enforced on the last hop into a prompt rather than
    assumed to have been enforced upstream — the same move `stores.pg.search
    .assert_dynamically_retrievable` makes for the dynamic arms, and for a sharper reason.

    The static prefix is the ONE path by which memory reaches a model with no abstention
    gate, no calibrated score, and no per-query relevance test at all: whatever lands here
    is in EVERY prompt for this agent-type until the next rebuild. So the two provenance
    facts the state machine promises about these rows are re-checked here.

    * A `pinned` row must carry provenance class `operator`. `state_machine
      ._guard_none_to_pinned` (PLAN.md §5 row 3, D-014) admits nothing else, and `pinned`
      is explicitly the UNGOVERNED status: it is never scored, never quarantined, and never
      shadow-confirmed. "Operator-created" is therefore the entire basis on which a pinned
      row is trusted, and a pinned row that is not operator-created has no basis at all.
    * No row here may carry provenance class `proposal`. D-023: a proposal can never exit
      quarantine by any route, so a `pinned`/`validated` proposal is a row that could only
      exist if the machine had been bypassed — and PLAN.md §10 says no bypass exists.

    Raises rather than skipping, and does so before any packing: a breached guarantee is not
    a thin result set. This is a background worker whose failures are retried by the queue,
    so failing loudly here costs a stale prefix (the previous version stays cached and
    readable), while continuing would publish attacker-placed content to every prompt.
    """
    if row.provenance.cls is ProvenanceClass.PROPOSAL:
        # Message deliberately not phrased "... with provenance class ...":
        # `scripts/raw_sql_lint.py` flags any string literal outside `stores/pg/` that opens
        # on a SQL keyword, and `WITH` is one. A false positive in a CI-blocking gate costs
        # exactly as much attention as a true one.
        raise TracebedError(
            f"prefix eligibility breached: memory {row.id} at status {row.status.value!r} "
            "carries provenance class 'proposal', which can never leave quarantine (D-023)"
        )
    if row.status is Status.PINNED and row.provenance.cls is not ProvenanceClass.OPERATOR:
        raise TracebedError(
            f"prefix eligibility breached: pinned memory {row.id} has provenance class "
            f"{row.provenance.cls.value!r}; only 'operator' may create a pinned row (D-014)"
        )


def _dedup(rows: Iterable[MemoryItemRow]) -> list[MemoryItemRow]:
    """Collapses rows carrying identical content to one, keeping the lowest-id survivor —
    an arbitrary but fixed tie-break, chosen only so two runs over the same input set agree
    (mirrors `hotpath.assembler._dedup`'s "the same content must not spend the budget
    twice", applied here to a whole memory_item's `content_hash` rather than a fusion
    candidate's ad hoc dedup_key, since there is no separate one at this layer)."""
    best: dict[str, MemoryItemRow] = {}
    for row in rows:
        current = best.get(row.content_hash)
        if current is None or str(row.id) < str(current.id):
            best[row.content_hash] = row
    return list(best.values())


def _prefs_sort_key(row: MemoryItemRow) -> tuple[float, str]:
    """Oldest-first, id tie-break. Pinned preferences are ungoverned (D-014) — they are
    never scored, so there is no Q to rank them by; recency of the pin itself is the only
    signal this schema offers, and using it (rather than an arbitrary insertion order) is
    what makes the packing deterministic for a given input set. `timestamp()` (a plain
    float), not the `datetime` itself, so both sort keys share one return type and `_pack`
    needs no `Any`/`object` escape hatch to accept either."""
    return (row.created_at.timestamp(), str(row.id))


def _lessons_sort_key(row: MemoryItemRow) -> tuple[float, str]:
    """Highest-Q-first, id tie-break — the same "higher quality wins the budget first"
    rule `hotpath.assembler._pack` already applies to ordinary dynamic candidates, applied
    here because validated lessons, unlike preferences, DO carry a meaningful Q."""
    return (-row.q_value, str(row.id))


def _clamp(cap: int, headroom: int) -> int:
    """The tighter of a configured cap and the budget still unspent, never negative —
    identical to `hotpath.assembler._clamp`."""
    return max(min(cap, headroom), 0)


def _pack(
    rows: Sequence[MemoryItemRow], *, cap: int, sort_key: Callable[[MemoryItemRow], tuple[float, str]]
) -> tuple[list[MemoryItemRow], int]:
    """Greedy, `sort_key`-first fill of one token budget. A row that would overflow `cap`
    is skipped, not stopped on, so a smaller later row can still fill leftover room —
    identical algorithm to `hotpath.assembler._pack`, parameterised over the two different
    orderings prefs/lessons need instead of a single retrieval-time score."""
    ordered = sorted(rows, key=sort_key)
    selected: list[MemoryItemRow] = []
    used = 0
    for row in ordered:
        if used + row.token_count > cap:
            continue
        selected.append(row)
        used += row.token_count
    return selected, used


def _prefix_version(ordered: Sequence[MemoryItemRow]) -> int:
    """Content-derived version number (module docstring): a canonical-JSON hash of exactly
    the `(memory_id, content_hash)` pairs that were packed, in packed order, as a plain
    non-negative `int` (`stores.valkey.keys.static_prefix_key` rejects a negative or
    non-int version).

    64 bits, not 32. A collision here is not benign: two genuinely different packed sets
    sharing a version share a cache key, so the reader serves the older set's block for the
    full TTL while every audit trail says it served the newer one. At 32 bits the birthday
    bound puts an even chance of that at roughly 65k rebuilds for ONE agent-type — reachable
    over a couple of years of invalidation-driven rebuilds, not "practically impossible" as
    this previously claimed. The extra eight hex digits cost one longer key segment."""
    payload = [{"id": str(row.id), "content_hash": row.content_hash} for row in ordered]
    digest = sha256_hex(canonical_json(payload))
    return int(digest[:16], 16)


def build_static_prefix(
    candidates: Sequence[MemoryItemRow],
    *,
    agent_type_id: AgentTypeId,
    cfg: EffectiveConfig,
) -> PrefixBuildResult:
    """Pure: no I/O, no clock. `candidates` is typically every `PINNED`/`VALIDATED` row in
    the project (`PrefixBuilder.run` fetches exactly that); this function does the
    scope-filtering, dedup, budget-splitting, and rendering, and is deterministic for a
    given `candidates` sequence regardless of its input order (both filtering and packing
    sort internally).
    """
    budget = cfg.budget

    eligible_prefs = [
        row
        for row in candidates
        if row.mem_type is MemType.PREFERENCE
        and row.status is Status.PINNED
        and _in_scope(row, agent_type_id)
    ]
    eligible_lessons = [
        row
        for row in candidates
        if row.mem_type is MemType.LESSON
        and row.status is Status.VALIDATED
        and _in_scope(row, agent_type_id)
    ]
    for row in (*eligible_prefs, *eligible_lessons):
        assert_prefix_eligible(row)

    prefs = _dedup(eligible_prefs)
    lessons = _dedup(eligible_lessons)

    # Same split-budget algebra as `hotpath.assembler.assemble`'s STATIC_PREFIX handling:
    # `static_prefix` (700) is the outer pool, `static_prefix_prefs` (200) is carved out of
    # it first, and `static_prefix_lessons` (500) gets whatever the prefs pool did not
    # spend, capped at its own 500 — never a separate, disagreeing budget.
    static_pool = _clamp(budget.static_prefix, budget.total_tokens)
    prefs_selected, prefs_used = _pack(
        prefs, cap=_clamp(budget.static_prefix_prefs, static_pool), sort_key=_prefs_sort_key
    )
    lessons_cap = _clamp(budget.static_prefix_lessons, static_pool - prefs_used)
    lessons_selected, lessons_used = _pack(lessons, cap=lessons_cap, sort_key=_lessons_sort_key)

    ordered = [*prefs_selected, *lessons_selected]
    slots = tuple(
        ContextSlot(
            slot=Slot.STATIC_PREFIX,
            memory_id=row.id.value,
            tokens=row.token_count,
            text=row.content,
        )
        for row in ordered
    )
    context_block = render(slots)

    # Derived from the pre-DEDUP eligible set, not the post-dedup pools: a row collapsed by
    # `_dedup` is a row that did not make it into `context_block`, and `dropped_memory_ids`
    # is the only place that is observable. Subtracting from the post-dedup pools reported
    # every dedup casualty as if it had never been in scope — the same accumulate-as-you-go
    # blind spot D-056 removed from `hotpath.assembler`.
    in_scope_ids = {row.id for row in (*eligible_prefs, *eligible_lessons)}
    selected_ids = {row.id for row in ordered}
    dropped = tuple(sorted(in_scope_ids - selected_ids, key=str))

    return PrefixBuildResult(
        agent_type_id=agent_type_id,
        prefix_version=_prefix_version(ordered),
        context_block=context_block,
        prefs_tokens=prefs_used,
        lessons_tokens=lessons_used,
        dropped_memory_ids=dropped,
    )


class PrefixBuilder:
    """Wires the pure `build_static_prefix` to a real memory store and the Valkey cache."""

    def __init__(
        self,
        *,
        store: MemoryStorePort,
        cache: StaticPrefixCachePort,
        config: ConfigProvider,
    ) -> None:
        self._store = store
        self._cache = cache
        self._config = config

    def run(self, project_id: ProjectId, agent_type_id: AgentTypeId) -> PrefixBuildResult:
        """Fetches every `PINNED`/`VALIDATED` row in the project, builds this agent-type's
        static prefix, and writes it to `stores.valkey.keys.static_prefix_key(project_id,
        agent_type_id, prefix_version)`. Raises on a genuine failure (store error, config
        error) rather than swallowing it — this is a worker, not the hot path; PLAN.md §2
        invariant 2's fail-open guarantee applies to `/v1/retrieve`, not to a background
        build the queue can retry.

        `limit=MAX_ROW_LIMIT` (the same ceiling `stores.pg.repo.Repo.list_memories` already
        clamps to internally) rather than the method's own low default: this worker needs
        every retrievable pinned preference / validated lesson in the project to compute a
        correct pack, not a small page of them.

        A FULL page is refused, loudly, rather than built on. `Repo.list_memories` is
        `ORDER BY created_at DESC LIMIT 1000` with no cursor and no scope/mem_type filter,
        so once a project holds more than `MAX_ROW_LIMIT` pinned+validated rows this worker
        silently receives only the newest 1000 of them. Two things then go wrong at once and
        neither is observable from the output: the oldest pinned preferences — the ones
        `_prefs_sort_key` packs FIRST — fall out of the window entirely, and the window's
        contents change on every unrelated insert anywhere in the project, so the "identical
        input set yields an identical `prefix_version`" property that the whole caching
        scheme rests on stops holding. Raising keeps the previously cached prefix in place
        (it has its own TTL) and names the real defect; see this chunk's contract gap, which
        needs a scoped/paginated read on `stores/pg/repo.py`, a file outside this list.
        """
        cfg = self._config.effective(project_id, agent_type_id)
        rows = self._store.list_memories(
            project_id, statuses=[Status.PINNED, Status.VALIDATED], limit=MAX_ROW_LIMIT
        )
        if len(rows) >= MAX_ROW_LIMIT:
            raise TracebedError(
                f"static prefix for agent_type {agent_type_id} not built: the pinned/validated "
                f"read hit its {MAX_ROW_LIMIT}-row ceiling, so the input set is a truncated, "
                "insertion-order-dependent window rather than the whole population"
            )
        result = build_static_prefix(rows, agent_type_id=agent_type_id, cfg=cfg)

        ttl_seconds = resolve_ttl_class(_STATIC_PREFIX_TTL_CLASS, cfg.cache)
        # Block first, pointer second, never reordered and never made
        # conditional: the pointer is what makes a version reachable, so
        # publishing it before its bytes exist turns the interval between the
        # two calls into a window where every reader takes a hard miss on the
        # exact rung of the degradation ladder that exists to avoid one. If the
        # block write raises, the pointer still names the PREVIOUS version,
        # which is stale but complete — the failure mode worth having.
        self._cache.static_prefix_set(
            project_id,
            agent_type_id,
            result.prefix_version,
            result.context_block.model_dump_json().encode("utf-8"),
            ttl_seconds=ttl_seconds,
        )
        self._cache.current_prefix_version_set(
            project_id, agent_type_id, result.prefix_version, ttl_seconds=ttl_seconds
        )
        return result
