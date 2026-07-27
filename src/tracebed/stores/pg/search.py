"""Hybrid-retrieval read queries: BM25 arm, ANN arm, IDF/df, corpus size (PLAN.md §7 Phase 1).

The ONLY place these queries exist — `scripts/raw_sql_lint.py` (AST walk) fails CI on any SQL
execution outside `stores/pg/`. `hotpath.retriever` depends on this module (permitted: PLAN.md §2
invariant 1 lists `stores` as an allowed hot-path import), never on `Repo` directly — retrieval
reads are a different shape from `Repo`'s write-and-lookup surface, and keeping them apart means a
change to one cannot silently widen the other's SQL surface.

Both arms — and the two support queries the rarity gate needs — share ONE retrievability
predicate, built once (`_RETRIEVABLE_PREDICATE`) and substituted into every statement, so the four
queries cannot drift apart on which rows they let through:

  * `status = ANY(%(statuses)s)` — only `validated` and `candidate` (PLAN.md §5's
    `RETRIEVABLE_STATUSES` minus `pinned`; see the module-level note below on why `pinned` is
    deliberately absent here).
  * `(status <> 'candidate' OR trust_tier = 'A')` — a `candidate` row is retrievable through
    these dynamic arms only when it is Tier A (PLAN.md §7: "candidate (Tier A only, labelled
    lower-trust, cap 1/run)"); a Tier-B row that has merely reached `candidate` status by some
    future transition must not surface here.

`pinned` is a member of `state_machine.RETRIEVABLE_STATUSES` but is deliberately excluded from
every query in this module. PLAN.md §5's retrievable-statuses line parenthesises it
"(prefix only)", `domain.state_machine.RETRIEVABLE_STATUSES`'s own comment says "pinned:
static-prefix placement only (enforced in the prefix builder, Phase 2)", and
`domain.enums.Slot` has no slot a pinned preference could occupy in a BM25/ANN result (its slots
are `fact`/`exemplar`/`pitfall`/`candidate_note`/`jit_lesson`/`static_prefix` — pinned rows are
`mem_type=preference` and only ever render into `static_prefix`, built by Phase 2's prefix
builder). Including it here would hand the fusion/assembler layer rows with no slot to place them
in. Logged as a decision (DECISIONS.md), not silently assumed.

CONTRACT GAP (reported, not silently guessed): neither PLAN.md nor PHASE0-CONTRACT.md specifies
`pg_textsearch`'s actual SQL surface — its match operator, its scoring function, or its DF/IDF
accessor. The migration (`stores/pg/ddl.py`) fixes only the index access method name
(`USING bm25 (content) WITH (text_config='english')`); everything past that is this chunk's
inference, chosen to be internally consistent with that access-method name and stated as a
decision entry (DECISIONS.md) rather than invented silently:

  * Match predicate: `content @@@ %(query)s` (the `@@@` operator, mirroring the established
    match-operator convention for BM25-style Postgres extensions).
  * Score function: `bm25_score(content, query) -> double precision` — the raw, unbounded BM25
    relevance value (D-003: NOT `ts_rank`), named after the index's own access-method (`bm25`).

Every function here is read-only and takes a `ProjectId` positionally with no default, exactly
like every other partitioned-table access in this codebase (contract §5.0) — obtained exclusively
through `stores.pg.pool.scoped()`, which sets the RLS GUC as the first statement of the
transaction. RLS `FORCE ROW LEVEL SECURITY` (migrations Task 6) is the backstop; the explicit
`project_id = %(project_id)s` predicate in every statement below is the primary control, and
`tests/phase1/test_search_sql.py` asserts it is never missing.

Invariant 7 is additionally enforced on the way OUT, in `_assert_retrievable` — applied by BOTH
`_row_to_arm_hit` and `_row_to_candidate`, not only on the way in: a row whose status is not
retrievable (or a `candidate` row that is not Tier A) raises rather than becoming an `ArmHit` or a
`CandidateRow`. Both, because they are two independent statements issued at two different times,
and only the second one carries `content` — the bytes that would actually enter a prompt. The SQL
predicate is the control; this is the assertion that the control
held. It matters because every other guarantee in this module is a property of query TEXT, which a
future edit — a new arm, a UNION, a hand-written variant that forgets one conjunct — can change
without any test noticing until a quarantined row is already in somebody's prompt. Failing closed
here costs one retrieval (the caller sees the ladder's store-error rung, PLAN.md §2 invariant 2:
"a run never fails because of Tracebed", it just gets no memory); failing open costs the vault's
entire quarantine guarantee.
"""

from __future__ import annotations

import math
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Final
from uuid import UUID

from psycopg.rows import DictRow, dict_row
from psycopg_pool import ConnectionPool

from tracebed.domain.enums import MemType, ScopeType, TrustTier
from tracebed.domain.errors import TracebedError
from tracebed.domain.ids import MemoryId, ProjectId
from tracebed.domain.state_machine import Status
from tracebed.stores.pg.pool import scoped

__all__ = [
    "ArmHit",
    "CandidateRow",
    "SearchStore",
    "assert_dynamically_retrievable",
]

# Ceiling on any caller-supplied `top_n`, mirroring `stores.pg.repo.MAX_ROW_LIMIT`'s rationale
# exactly (same value, independently justified here rather than imported — this module must stay
# import-clean of `repo.py`'s write-side surface). This is a defensive engineering bound against a
# pathological caller value, not a retrieval-quality tunable: `retrieval.arm_top_n` in
# `EffectiveConfig` is the field that actually governs recall/latency (PLAN.md §6), and every
# caller in this codebase is expected to pass that value through unchanged. Widening this ceiling
# never improves retrieval quality; it only bounds how large an unbounded-server-side-allocation
# mistake can be.
_MAX_ARM_TOP_N: Final[int] = 1_000

# Ceiling on how many distinct terms one `document_frequency` call may ask about. Same class of
# bound as `_MAX_ARM_TOP_N` and for the same reason, not a retrieval-quality tunable: `terms` is
# derived from caller-supplied query text, and without a bound a pathological query turns into an
# unbounded `text[]` parameter and an unbounded server-side `unnest`. Chosen far above any
# plausible query's distinct-term count so it never binds on real input; the rarity gate needs
# `abstention.rarity_min_shared_terms` (2) rare shared terms, so truncating the tail of an
# absurdly long term list cannot flip an abstain into an inject — it can only make the gate
# stricter, which is the safe direction.
_MAX_DF_TERMS: Final[int] = 512

# PLAN.md §5 `RETRIEVABLE_STATUSES` minus `pinned` (module docstring explains why `pinned` never
# appears in a dynamic-arm query). Values, not enum members, because they are bound as query
# parameters. `_RETRIEVABLE_STATUS_VALUES` is the single source of truth for both halves of the
# guarantee: the bound parameter the SQL filters on, and the membership set `_row_to_arm_hit`
# checks returned rows against — one list, so the query and its post-condition cannot disagree.
_RETRIEVABLE_STATUS_VALUES: Final[tuple[str, ...]] = (Status.VALIDATED.value, Status.CANDIDATE.value)
_RETRIEVABLE_STATUSES: Final[frozenset[str]] = frozenset(_RETRIEVABLE_STATUS_VALUES)


def _retrievable_predicate(column_prefix: str = "") -> str:
    """The one retrievability predicate, parameterised only by column prefix (`""` or `"m."`) so
    every statement below shares identical text apart from that prefix. Only column names
    (`status`, `trust_tier`) take the prefix — the bound-parameter names (`%(statuses)s`,
    `%(candidate_status)s`, `%(tier_a)s`, all supplied by `_retrievability_params`) are never
    touched, which is what keeps this a safe substitution rather than a naive string replace that
    could corrupt a placeholder name containing the word "status" as a substring (e.g.
    `%(statuses)s` itself).
    """
    return (
        f"{column_prefix}status = ANY(%(statuses)s) AND "
        f"({column_prefix}status <> %(candidate_status)s OR {column_prefix}trust_tier = %(tier_a)s)"
    )


_RETRIEVABLE_PREDICATE: Final[str] = _retrievable_predicate()
_RETRIEVABLE_PREDICATE_M: Final[str] = _retrievable_predicate("m.")

# Every statement below is a plain (non-f) triple-quoted template with a `@RETRIEVABLE@` /
# `@RETRIEVABLE_M@` placeholder, substituted via `.replace()` — the exact technique
# `stores.pg.repo._TRACE_INDEX_UPSERT_SQL` already uses for the same reason: an f-string (or
# `.format()`/`%`) assembling a SQL string trips `ruff`'s S608 (possible SQL injection via
# string-based query construction) even when, as here, every substituted value is a fixed
# module-level constant, never caller data. `.replace()` on a plain string is not a construction
# pattern that rule flags, and the import-time guard below (mirroring repo.py's own) proves the
# substitution actually happened rather than silently leaving the placeholder token in the SQL
# psycopg executes.
_LEXICAL_ARM_TEMPLATE: Final[str] = """
SELECT id, trust_tier, status, bm25_score(content, %(query)s) AS raw_score
FROM memory_item
WHERE project_id = %(project_id)s
  AND content @@@ %(query)s
  AND @RETRIEVABLE@
ORDER BY raw_score DESC
LIMIT %(top_n)s
""".strip()
_LEXICAL_ARM_SQL: Final[str] = _LEXICAL_ARM_TEMPLATE.replace("@RETRIEVABLE@", _RETRIEVABLE_PREDICATE)

# `hnsw.iterative_scan` / `hnsw.max_scan_tuples` are pgvector session GUCs (filtered-ANN recall
# vs latency, PLAN.md §6). Same `set_config(..., true)` idiom as `stores.pg.pool.scoped`'s own RLS
# GUC (C-09): `SET LOCAL` cannot bind a parameter, and `is_local=true` reverts the setting at
# COMMIT/ROLLBACK so it never leaks onto a pooled connection's next checkout.
_HNSW_ITERATIVE_SCAN_GUC_SQL: Final[str] = "SELECT set_config('hnsw.iterative_scan', %(mode)s, true)"
_HNSW_MAX_SCAN_TUPLES_GUC_SQL: Final[str] = (
    "SELECT set_config('hnsw.max_scan_tuples', %(max_tuples)s, true)"
)

_VECTOR_ARM_TEMPLATE: Final[str] = """
SELECT id, trust_tier, status, 1 - (embedding <=> %(embedding)s::halfvec) AS raw_score
FROM memory_item
WHERE project_id = %(project_id)s
  AND embedding IS NOT NULL
  AND @RETRIEVABLE@
ORDER BY embedding <=> %(embedding)s::halfvec
LIMIT %(top_n)s
""".strip()
_VECTOR_ARM_SQL: Final[str] = _VECTOR_ARM_TEMPLATE.replace("@RETRIEVABLE@", _RETRIEVABLE_PREDICATE)

_DOCUMENT_FREQUENCY_TEMPLATE: Final[str] = """
SELECT t.term AS term, COUNT(m.id) AS df
FROM unnest(%(terms)s::text[]) AS t(term)
LEFT JOIN memory_item m
  ON m.project_id = %(project_id)s
 AND m.content @@@ t.term
 AND (@RETRIEVABLE_M@)
GROUP BY t.term
""".strip()
_DOCUMENT_FREQUENCY_SQL: Final[str] = _DOCUMENT_FREQUENCY_TEMPLATE.replace(
    "@RETRIEVABLE_M@", _RETRIEVABLE_PREDICATE_M
)

_FETCH_CANDIDATES_TEMPLATE: Final[str] = """
SELECT id, mem_type, trust_tier, status, content, token_count, q_value, confidence, created_at,
       scope_type, scope_id
FROM memory_item
WHERE project_id = %(project_id)s
  AND id = ANY(%(ids)s::uuid[])
  AND @RETRIEVABLE@
""".strip()
_FETCH_CANDIDATES_SQL: Final[str] = _FETCH_CANDIDATES_TEMPLATE.replace(
    "@RETRIEVABLE@", _RETRIEVABLE_PREDICATE
)

_CORPUS_SIZE_TEMPLATE: Final[str] = """
SELECT COUNT(*) AS n
FROM memory_item
WHERE project_id = %(project_id)s
  AND @RETRIEVABLE@
""".strip()
_CORPUS_SIZE_SQL: Final[str] = _CORPUS_SIZE_TEMPLATE.replace("@RETRIEVABLE@", _RETRIEVABLE_PREDICATE)

if "@RETRIEVABLE" in (
    _LEXICAL_ARM_SQL
    + _VECTOR_ARM_SQL
    + _DOCUMENT_FREQUENCY_SQL
    + _CORPUS_SIZE_SQL
    + _FETCH_CANDIDATES_SQL
):  # pragma: no cover - import-time structural guard
    raise RuntimeError(
        "a retrievability-predicate template has an unsubstituted placeholder; a query would "
        "compare against a literal token instead of the real predicate"
    )


def _retrievability_params() -> dict[str, object]:
    """The three bind values every `_RETRIEVABLE_PREDICATE` substitution needs, in one place so
    the four query builders below cannot bind them inconsistently."""
    return {
        "statuses": list(_RETRIEVABLE_STATUS_VALUES),
        "candidate_status": Status.CANDIDATE.value,
        "tier_a": TrustTier.A.value,
    }


def _bounded_top_n(top_n: int) -> int:
    """Clamp into `[1, _MAX_ARM_TOP_N]`. `top_n <= 0` is handled by the caller returning `[]`
    without issuing a statement at all (see `SearchStore.lexical_arm`/`vector_arm`) — this clamp
    only ever fires on the unbounded-above side."""
    return min(top_n, _MAX_ARM_TOP_N)


def _embedding_literal(embedding: Sequence[float]) -> str:
    """pgvector's text input format for a `halfvec`: `[v1,v2,...]`.

    Built here rather than depending on a pgvector Python adapter package (none is in
    `pyproject.toml`'s dependency set — D-036 keeps the dependency list closed) or on psycopg's
    generic list adaptation, which has no way to know the target column is a vector type rather
    than a Postgres array. `repr()` on each component guarantees the text is a plain decimal/
    scientific-notation float literal — never a string that could smuggle SQL, since every value
    started life as a Python `float`, not caller-controlled text.
    """
    if not embedding:
        raise ValueError("embedding must not be empty")
    for component in embedding:
        if math.isnan(component) or math.isinf(component):
            raise ValueError("embedding must not contain NaN or infinite components")
    return "[" + ",".join(repr(float(v)) for v in embedding) + "]"


@dataclass(frozen=True, slots=True)
class ArmHit:
    """One retrievable candidate from a single search arm.

    `raw_score` is the calibrated, un-thresholded signal this arm produced — BM25 relevance for
    `lexical_arm`, cosine similarity for `vector_arm`. This is exactly the value D-015 says
    abstention must consume: never an RRF rank, never anything RRF has touched. `hotpath.fusion`
    reads `raw_score` to compute this arm's contribution to the RRF sum and to attach the
    untouched signal to its fused output; it is the only transformation this value undergoes
    before reaching abstention.
    """

    memory_id: MemoryId
    raw_score: float
    trust_tier: TrustTier
    status: Status


@dataclass(frozen=True, slots=True)
class CandidateRow:
    """The `memory_item` columns the assembler needs to turn a retrieved id into a
    renderable, scoreable slot entry.

    Deliberately NOT `stores.pg.rows.MemoryItemRow`: that is `Repo`'s
    single-row admin/read shape and carries `provenance`, `scan_verdict_id`,
    `content_hash`, `subject_tag` and the rest — none of which the hot path
    reads, all of which it would then be paying to deserialise for every one of
    up to `retrieval.fused_top_n` candidates on a 300ms p99 budget. Narrower is
    also safer: `provenance` and `subject_tag` are exactly the fields that must
    never reach a rendered context block, and a shape that does not carry them
    cannot leak them.

    `scope_type`/`scope_id` are the exception to "narrower is safer": they are not rendered,
    they are what decides whether this row may be rendered AT ALL for this run
    (`domain.visibility.scope_visible`). Carried without a default so a future edit that adds
    a second producer of `CandidateRow` cannot forget them and thereby make every row
    project-visible.
    """

    memory_id: MemoryId
    mem_type: MemType
    trust_tier: TrustTier
    status: Status
    content: str
    token_count: int
    q_value: float
    confidence: float
    created_at: datetime
    scope_type: ScopeType
    scope_id: UUID | None


def assert_dynamically_retrievable(memory_id: MemoryId, status: Status, trust_tier: TrustTier) -> None:
    """Invariant 7's retrieval half, enforced rather than documented — the ONE statement of
    what a dynamic arm may return, exported so no caller has to restate it.

    If a row that is not `validated`, or a `candidate` row that is not Tier A,
    ever comes back from one of this module's queries, the predicate has been broken by an
    edit — and a broken predicate must abort the retrieval, not quietly hand a
    quarantined/retired/tombstoned memory to fusion or, worse, to the renderer. Applied to BOTH
    the arm queries (which return ids) and the content fetch (which returns the text that would
    actually enter a prompt), because those are two independent statements and only the second
    one carries anything a model could read. `hotpath.assembly` calls it a THIRD time, on the
    last hop before `renderer.render()`: everything above is a property of THIS module, and a
    future retrieval driver (PLAN.md §9's Qdrant driver, a second arm, a cache in front of the
    arms) would bypass all of it while still reaching the renderer. The message carries only ids
    and enum values, never `content`.
    """
    if status.value not in _RETRIEVABLE_STATUSES:
        raise TracebedError(
            f"retrievability predicate breached: memory {memory_id} has status "
            f"{status.value!r}, which is not retrievable"
        )
    if status is Status.CANDIDATE and trust_tier is not TrustTier.A:
        raise TracebedError(
            f"retrievability predicate breached: memory {memory_id} is a candidate at trust "
            f"tier {trust_tier.value!r}; only Tier A candidates are retrievable"
        )


def _row_to_candidate(row: DictRow) -> CandidateRow:
    """Parse one content row, refusing any the retrievability predicate should have excluded."""
    candidate = CandidateRow(
        memory_id=MemoryId(row["id"]),
        mem_type=MemType(row["mem_type"]),
        trust_tier=TrustTier(row["trust_tier"]),
        status=Status(row["status"]),
        content=str(row["content"]),
        token_count=int(row["token_count"]),
        q_value=float(row["q_value"]),
        confidence=float(row["confidence"]),
        created_at=row["created_at"],
        scope_type=ScopeType(row["scope_type"]),
        scope_id=row["scope_id"],
    )
    assert_dynamically_retrievable(candidate.memory_id, candidate.status, candidate.trust_tier)
    return candidate


def _row_to_arm_hit(row: DictRow) -> ArmHit:
    """Parse one row, refusing any row the retrievability predicate should have excluded.

    Invariant 7's retrieval half, enforced rather than documented (module docstring): if a row
    that is not `validated`, or a `candidate` row that is not Tier A, ever comes back from one of
    these queries, the predicate has been broken by an edit — and a broken predicate must abort
    the retrieval, not quietly hand a quarantined/retired/tombstoned memory to fusion. The
    message carries only ids and enum values, never `content`.
    """
    hit = ArmHit(
        memory_id=MemoryId(row["id"]),
        raw_score=float(row["raw_score"]),
        trust_tier=TrustTier(row["trust_tier"]),
        status=Status(row["status"]),
    )
    assert_dynamically_retrievable(hit.memory_id, hit.status, hit.trust_tier)
    return hit


class SearchStore:
    """Read-only hybrid-retrieval queries over `memory_item` (PLAN.md §7 Phase 1).

    Every method opens its own `scoped()` transaction (contract §5.0) and is atomic on its own,
    matching `Repo`'s convention — there is no multi-statement composition need here, so no `tx()`
    equivalent exists on this class.
    """

    def __init__(self, pool: ConnectionPool) -> None:
        self._pool = pool

    def lexical_arm(self, project_id: ProjectId, query: str, top_n: int) -> list[ArmHit]:
        """True BM25 via `pg_textsearch` (D-003) — never `ts_rank`, which the audit measured at
        nDCG@10 0.07 on BEIR SciFact against BM25's 0.69, and which exposes no IDF for the
        rarity gate (`document_frequency` below) to read.

        An empty/whitespace-only query or a non-positive `top_n` returns `[]` without issuing a
        statement — `content @@@ ''` is not a query pg_textsearch's match operator can score, and
        "return nothing" is the correct, cheaper answer to "asked for nothing."
        """
        if not query.strip() or top_n <= 0:
            return []
        with scoped(self._pool, project_id) as conn, conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                _LEXICAL_ARM_SQL,
                {
                    "project_id": project_id,
                    "query": query,
                    "top_n": _bounded_top_n(top_n),
                    **_retrievability_params(),
                },
            )
            rows = cur.fetchall()
        return [_row_to_arm_hit(r) for r in rows]

    def vector_arm(
        self,
        project_id: ProjectId,
        embedding: Sequence[float],
        top_n: int,
        *,
        hnsw_iterative_scan: bool,
        hnsw_max_scan_tuples: int,
    ) -> list[ArmHit]:
        """HNSW ANN over `halfvec` with cosine ops, honouring `retrieval.hnsw_iterative_scan` and
        `hnsw_max_scan_tuples` (filtered-ANN recall vs latency, PLAN.md §6).

        `hnsw_iterative_scan` is `EffectiveConfig`'s bool knob; pgvector's own GUC is a
        three-valued enum (`off` / `strict_order` / `relaxed_order`). Mapped `True ->
        'relaxed_order'` (the higher-recall iterative mode) and `False -> 'off'` — logged as a
        decision (DECISIONS.md) since the config surface does not carry pgvector's finer-grained
        `strict_order` distinction.

        A non-positive `top_n` or an empty `embedding` returns `[]` without issuing a statement,
        matching `lexical_arm`'s "asked for nothing" behaviour.
        """
        if top_n <= 0 or not embedding:
            return []
        literal = _embedding_literal(embedding)
        mode = "relaxed_order" if hnsw_iterative_scan else "off"
        with scoped(self._pool, project_id) as conn, conn.cursor(row_factory=dict_row) as cur:
            cur.execute(_HNSW_ITERATIVE_SCAN_GUC_SQL, {"mode": mode})
            cur.execute(_HNSW_MAX_SCAN_TUPLES_GUC_SQL, {"max_tuples": str(hnsw_max_scan_tuples)})
            cur.execute(
                _VECTOR_ARM_SQL,
                {
                    "project_id": project_id,
                    "embedding": literal,
                    "top_n": _bounded_top_n(top_n),
                    **_retrievability_params(),
                },
            )
            rows = cur.fetchall()
        return [_row_to_arm_hit(r) for r in rows]

    def fetch_candidates(
        self, project_id: ProjectId, memory_ids: Sequence[MemoryId]
    ) -> list[CandidateRow]:
        """The content/score columns for already-retrieved candidate ids, in ONE statement.

        The arms return ids and a raw score; nothing that can be rendered, scored by
        `hotpath.calibration`, or budgeted by `hotpath.assembler` comes back with them. This is
        the fetch that closes that gap, and it is a single `id = ANY(...)` rather than a loop of
        by-id reads because `retrieval.fused_top_n` (20) round trips inside a 300ms budget is not
        a hot path, it is a queue.

        Carries the same retrievability predicate as the arms — a row whose status changed between
        the arm query and this one (quarantined by an operator, tombstoned by a subject erasure)
        is simply not returned, so the window between the two statements cannot put a
        no-longer-retrievable memory into a prompt. Rows are returned in whatever order Postgres
        produces; the caller re-joins them to the fused order by id (it must, since a row can be
        legitimately absent).
        """
        ids = [memory_id.value for memory_id in dict.fromkeys(memory_ids)][:_MAX_ARM_TOP_N]
        if not ids:
            return []
        with scoped(self._pool, project_id) as conn, conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                _FETCH_CANDIDATES_SQL,
                {"project_id": project_id, "ids": ids, **_retrievability_params()},
            )
            rows = cur.fetchall()
        return [_row_to_candidate(r) for r in rows]

    def document_frequency(self, project_id: ProjectId, terms: Sequence[str]) -> dict[str, int]:
        """Per-term document frequency among retrievable rows — the IDF source the rarity gate
        needs (`hotpath.abstention.RarityEvidence`, D-003: this is exactly the computation
        `ts_rank` cannot provide).

        A `LEFT JOIN` against `unnest(terms)` rather than one query per term: a term with zero
        matches must report `0`, not be silently absent from the result — the rarity gate reads
        every query term's df, including the ones nothing matched. Empty `terms` returns `{}`
        without issuing a statement, and the deduplicated term list is bounded by `_MAX_DF_TERMS`
        because `terms` is derived from caller-supplied query text (see that constant).
        """
        deduped = list(dict.fromkeys(terms))[:_MAX_DF_TERMS]
        if not deduped:
            return {}
        with scoped(self._pool, project_id) as conn, conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                _DOCUMENT_FREQUENCY_SQL,
                {
                    "project_id": project_id,
                    "terms": deduped,
                    **_retrievability_params(),
                },
            )
            rows = cur.fetchall()
        return {str(r["term"]): int(r["df"]) for r in rows}

    def corpus_size(self, project_id: ProjectId) -> int:
        """Count of retrievable rows in this project — the cold-start abstention floor's
        denominator (`abstention.rarity_min_corpus_docs`, PLAN.md §6)."""
        with scoped(self._pool, project_id) as conn, conn.cursor() as cur:
            cur.execute(_CORPUS_SIZE_SQL, {"project_id": project_id, **_retrievability_params()})
            row = cur.fetchone()
        return int(row[0]) if row is not None else 0
