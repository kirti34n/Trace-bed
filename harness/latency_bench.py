"""The multi-project, concurrent-load latency bench (PLAN.md §7 Phase 1: "the
single-project warm fixture certifies a condition production never has").

Built in Phase 1, reporting at every gate; **not CI-gating** (D-035 / PLAN.md
§7's rules of engagement — informational only until a human flips it). Real
scale is **50 projects x 100,000 items**, concurrent load, measuring p50/p95/p99
for total retrieval latency AND for the embed sub-budget, plus per-project
variance — against `hotpath.retriever.Retriever` and `stores.pg.search
.SearchStore`, the actual Phase 1 hot-path retrieval code, not a simulation of
it.

NEEDS POSTGRES. This machine has none, so this module skips cleanly and says
so — never errors, never silently reports a plausible-looking number for a
run that never happened (`LatencyBenchReport.status == "skipped_no_stack"`),
mirroring `tests/conftest.py::pg`'s own reachability probe and skip message.

WHAT THIS BENCH ACTUALLY SEEDS AND WHY (read before trusting a report):

  * Rows are inserted through `stores.pg.repo.Repo.insert_memory_item` — the
    ONLY sanctioned write path (`scripts/raw_sql_lint.py` bans SQL outside
    `stores/pg/`) — after a real `state_machine.apply()` walk from `None` to
    `candidate` to `validated` (never a hand-invented status), so every seeded
    row is genuinely retrievable, not merely present.
  * KNOWN CONTRACT GAP, discovered while writing this bench, not assumed:
    `Repo.insert_memory_item`'s INSERT statement (verified by reading
    `stores/pg/repo.py`) does not write `memory_item.embedding`,
    `embedding_model_id`, `embedding_model_version`, or `lexemes` at all —
    those four columns have no write path anywhere in `Repo`'s public API.
    Consequently `stores.pg.search.SearchStore.vector_arm`'s `embedding IS
    NOT NULL` predicate matches ZERO rows for any data this bench (or
    anything else in this codebase) seeds through `Repo`. This bench still
    calls the query embedder and still measures its latency honestly (that
    number is real), and the LEXICAL arm's BM25 latency against real content
    at real scale is fully real — but the vector arm's recall is
    structurally absent from every report this module produces, and its
    latency reflects an index scan over zero matching rows, not a
    representative ANN search. Flagged loudly in every report
    (`LatencyBenchReport.known_gaps`) rather than silently producing numbers
    that look like a vector-arm bench and are not one.
  * Seeding goes through the same governed, per-row `Repo.insert_memory_item`
    path production does — there is no bulk-insert primitive anywhere in
    `Repo` (another discovered gap, same root cause: nobody has needed one
    yet). At real scale (50 x 100,000 = 5,000,000 rows) this is the dominant
    cost of a full run and is expected to take a long time; `--seed-workers`
    parallelises it across a thread pool (each row's own `scoped()`
    transaction is independent), but this is still 5,000,000 individual
    `INSERT`s, not a `COPY`.

Callable as a library (`run_latency_bench(...)`, what `harness/phase1_gate.py`
uses — at a drastically reduced, explicitly-labelled "smoke scale" so the
routine gate stays fast) or as a script for the real bench:
`python harness/latency_bench.py --projects 50 --items-per-project 100000`.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import random
import statistics
import time
from collections.abc import Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from typing import Any, Final, Literal

from tracebed.core.scans import ScanContext, scan
from tracebed.domain.clock import SystemClock
from tracebed.domain.config import RetrievalConfig
from tracebed.domain.enums import Lane, MemType, ProvenanceClass, ScopeType, TrustTier
from tracebed.domain.ids import ProjectId, mint_run_id
from tracebed.domain.memory import NewMemoryItem, Provenance
from tracebed.domain.state_machine import Status, TransitionEvidence, TransitionLimits
from tracebed.domain.state_machine import apply as sm_apply
from tracebed.hotpath.retriever import Retriever

__all__ = [
    "DEFAULT_ITEMS_PER_PROJECT",
    "DEFAULT_PROJECTS",
    "LatencyBenchReport",
    "LatencyStats",
    "main",
    "render_text",
    "run_latency_bench",
]

DEFAULT_PROJECTS: Final[int] = 50
DEFAULT_ITEMS_PER_PROJECT: Final[int] = 100_000
DEFAULT_QUERIES_PER_PROJECT: Final[int] = 20
DEFAULT_CONCURRENCY: Final[int] = 50
DEFAULT_SEED_WORKERS: Final[int] = 16
DEFAULT_EMBED_DIM: Final[int] = 768

_VOCAB: Final[tuple[str, ...]] = (
    "payments", "webhook", "retry", "backoff", "database", "migration", "cache",
    "timeout", "auth", "token", "rate", "limiter", "queue", "worker", "deploy",
    "rollback", "schema", "partition", "index", "latency", "budget", "config",
    "invalidation", "staleness", "review", "quarantine", "promotion", "scoring",
    "holdout", "killswitch", "embedding", "vector", "lexical", "fusion", "rank",
)


def _postgres_reachable(dsn: str | None) -> tuple[bool, str]:
    """Mirrors `tests/conftest.py::pg`'s own reachability probe (1s connect
    timeout, never echoes the DSN — it carries the database password)."""
    if not dsn:
        return False, "TB_STORAGE__PG_DSN is not set — no Postgres available"
    try:
        import psycopg
    except ImportError:  # pragma: no cover - psycopg is a hard dependency
        return False, "psycopg is not importable — no Postgres available"
    try:
        with psycopg.connect(dsn, connect_timeout=1):
            return True, ""
    except Exception as exc:
        return False, f"Postgres unreachable (TB_STORAGE__PG_DSN): {exc}"


@dataclass(frozen=True, slots=True)
class LatencyStats:
    count: int
    p50_ms: float
    p95_ms: float
    p99_ms: float
    max_ms: float
    mean_ms: float


def _percentile(samples: Sequence[float], pct: float) -> float:
    """Linear-interpolation percentile ("R-7") — no numpy dependency (D-036's
    closed dependency set), matching `harness/fake_runtime.py`'s own helper."""
    if not samples:
        return 0.0
    ordered = sorted(samples)
    if len(ordered) == 1:
        return ordered[0]
    rank = (len(ordered) - 1) * (pct / 100.0)
    lo = math.floor(rank)
    hi = math.ceil(rank)
    if lo == hi:
        return ordered[int(rank)]
    frac = rank - lo
    return ordered[int(lo)] * (1.0 - frac) + ordered[int(hi)] * frac


def _stats(samples: list[float]) -> LatencyStats:
    return LatencyStats(
        count=len(samples),
        p50_ms=_percentile(samples, 50),
        p95_ms=_percentile(samples, 95),
        p99_ms=_percentile(samples, 99),
        max_ms=max(samples) if samples else 0.0,
        mean_ms=(sum(samples) / len(samples)) if samples else 0.0,
    )


class _DeterministicEmbeddingPort:
    """A REAL `QueryEmbedderPort` implementation for bench purposes only — NOT
    a production embedding driver. Deterministic (seeded per text), so a bench
    run is reproducible; L2-normalised so the resulting vectors are at least
    well-formed `halfvec` input. Its only job here is to give the embed
    sub-budget a genuine function call to time; it makes no claim of semantic
    relevance, and the module docstring's KNOWN CONTRACT GAP note is what
    actually governs how its output should be read.
    """

    def __init__(self, *, dim: int = DEFAULT_EMBED_DIM) -> None:
        self._dim = dim

    @property
    def model_id(self) -> str:
        return "bench-deterministic-embedding"

    @property
    def model_version(self) -> str:
        return "1"

    def embed(self, texts: Sequence[str], *, timeout_ms: int) -> list[list[float]]:
        out: list[list[float]] = []
        for text in texts:
            rng = random.Random(text)
            vec = [rng.uniform(-1.0, 1.0) for _ in range(self._dim)]
            norm = math.sqrt(sum(v * v for v in vec)) or 1.0
            out.append([v / norm for v in vec])
        return out


def _legally_validated_status(limits: TransitionLimits) -> Status:
    """Walks the REAL `state_machine.apply()` from `None` -> `candidate` ->
    `validated` (never a hand-invented status — see module docstring): a
    Tier-A parser insert, then a promotion clearing every threshold in
    `limits` exactly. Computed once (identical for every seeded row) rather
    than per row, since it only depends on `limits`, never on row content.

    NOT the status the bench seeds any more, and the reason is worth stating.
    `Repo.insert_memory_item` now refuses any status that is not a `(None, X)`
    target of the transition table (`state_machine.LEGAL_CREATION_STATUSES`),
    which closed the creation-side bypass invariant 7 names — and there is no
    status-WRITE path in the tree at all (PLAN.md "Known gaps", M1), so a
    `validated` row cannot legally exist yet. The bench therefore seeds Tier-A
    `candidate` rows, which the retrievability predicate treats identically
    (`RETRIEVABLE_STATUSES` includes `candidate` when `trust_tier = 'A'`), so the
    two arms scan the same number of rows and the latency figure is unchanged.
    Kept, called and asserted below so that when the write path lands, the bench
    promotes rather than re-inventing a status.
    """
    from datetime import UTC, datetime

    now = datetime.now(UTC)  # bench-only bookkeeping, not a hot-path timestamp
    entry_evidence = TransitionEvidence(
        now=now,
        provenance_class=ProvenanceClass.PARSER,
        trust_tier=TrustTier.A,
        mem_type=MemType.SEMANTIC,
        scan_passed=True,
        provenance_complete=True,
    )
    candidate_status = sm_apply(None, Status.CANDIDATE, entry_evidence, limits)
    promotion_evidence = TransitionEvidence(
        now=now,
        provenance_class=ProvenanceClass.PARSER,
        trust_tier=TrustTier.A,
        mem_type=MemType.SEMANTIC,
        scan_repass=True,
        promotion_outcomes=limits.promote_min_outcomes,
        promotion_distinct_principals=limits.promotion_min_distinct_principals,
        outcome_consistent=True,
        open_contradiction=False,
    )
    return sm_apply(candidate_status, Status.VALIDATED, promotion_evidence, limits)


def _default_limits() -> TransitionLimits:
    """`domain.config.PromotionConfig`/`RetirementConfig`/`LifecycleConfig`'s
    own shipped defaults (PLAN.md §6), written out directly rather than via a
    full `EffectiveConfig` — this bench needs the state machine's thresholds
    only, not the whole config surface."""
    return TransitionLimits(
        quarantine_ttl_days=30,
        candidate_ttl_days=45,
        promote_min_outcomes=2,
        failure_lesson_outcomes=1,
        promotion_min_distinct_principals=2,
        retire_q_threshold=0.25,
        retire_min_scored_uses=4,
        retire_min_distinct_principals=3,
        archive_floor=0.15,
    )


def _synthetic_content(rng: random.Random, n_words: int = 24) -> str:
    words = [rng.choice(_VOCAB) for _ in range(n_words)]
    return "The " + " ".join(words) + " subsystem behaved as expected during the drill."


def _synthetic_query(rng: random.Random, n_terms: int = 3) -> str:
    return " ".join(rng.choice(_VOCAB) for _ in range(n_terms))


def _seed_project(
    *,
    repo: Any,
    project_id: ProjectId,
    n_items: int,
    seed: int,
    status: Status,
) -> None:
    """Seeds `n_items` real, `scan()`-verdicted, legally-`validated` rows into
    one project through `Repo.insert_memory_item` — the only sanctioned write
    path. Every row is independent (its own `scoped()` transaction, per
    `Repo`'s own convention), which is what makes parallelising this loop
    across a thread pool (see `_seed_all_projects`) safe."""
    rng = random.Random(f"{seed}:{project_id}")
    run_id = mint_run_id()
    for i in range(n_items):
        content = _synthetic_content(rng)
        item = NewMemoryItem(
            scope_type=ScopeType.PROJECT_SHARED,
            scope_id=None,
            mem_type=MemType.SEMANTIC,
            kind="bench-fact",
            lane=Lane.OPERATIONAL,
            trust_tier=TrustTier.A,
            status=status,
            content=content,
            token_count=len(content.split()),
            provenance=Provenance(cls=ProvenanceClass.PARSER, trace_ids=(run_id,)),
        )
        verdict = scan(
            content,
            context=ScanContext(
                project_id=project_id,
                mem_type=MemType.SEMANTIC,
                trust_tier=TrustTier.A,
                provenance_class=ProvenanceClass.PARSER,
                lane=Lane.OPERATIONAL,
            ),
        ).verdict()
        repo.insert_memory_item(project_id, item, verdict)
        _ = i


def _seed_all_projects(
    *,
    repo: Any,
    project_ids: Sequence[ProjectId],
    items_per_project: int,
    seed: int,
    seed_workers: int,
    status: Status,
) -> None:
    with ThreadPoolExecutor(max_workers=seed_workers, thread_name_prefix="tb-bench-seed") as pool:
        futures = [
            pool.submit(
                _seed_project,
                repo=repo,
                project_id=project_id,
                n_items=items_per_project,
                seed=seed,
                status=status,
            )
            for project_id in project_ids
        ]
        for future in futures:
            future.result()


@dataclass(frozen=True, slots=True)
class LatencyBenchReport:
    status: Literal["skipped_no_stack", "ok", "error"]
    reason: str
    n_projects: int
    items_per_project: int
    queries_per_project: int
    concurrency: int
    total_latency: LatencyStats
    embed_latency: LatencyStats
    per_project_p50_ms: Sequence[float] = field(default_factory=list)
    """One p50 per project — what "reporting per-project variance" means."""
    known_gaps: tuple[str, ...] = ()


_SKIPPED_STATS = LatencyStats(count=0, p50_ms=0.0, p95_ms=0.0, p99_ms=0.0, max_ms=0.0, mean_ms=0.0)

_KNOWN_GAPS: Final[tuple[str, ...]] = (
    "Repo.insert_memory_item has no write path for memory_item.embedding/"
    "embedding_model_id/embedding_model_version/lexemes -- every row this bench "
    "seeds has a NULL embedding, so SearchStore.vector_arm matches zero rows "
    "for any project seeded here. Embed-latency numbers are real; vector-arm "
    "recall is structurally absent from this report. See module docstring.",
    "Repo has no bulk-insert primitive; seeding goes through the same governed "
    "per-row Repo.insert_memory_item path production uses, parallelised across "
    "--seed-workers threads. At full scale (50 x 100,000) this dominates total "
    "run time.",
)


def run_latency_bench(
    *,
    pg_dsn: str | None = None,
    n_projects: int = DEFAULT_PROJECTS,
    items_per_project: int = DEFAULT_ITEMS_PER_PROJECT,
    queries_per_project: int = DEFAULT_QUERIES_PER_PROJECT,
    concurrency: int = DEFAULT_CONCURRENCY,
    seed_workers: int = DEFAULT_SEED_WORKERS,
    seed: int = 1337,
    cleanup: bool = True,
) -> LatencyBenchReport:
    """Runs the bench, or reports `status="skipped_no_stack"` immediately and
    cleanly if no Postgres is reachable. Never raises."""
    resolved_dsn = pg_dsn if pg_dsn is not None else os.environ.get("TB_STORAGE__PG_DSN")
    reachable, reason = _postgres_reachable(resolved_dsn)
    if not reachable:
        return LatencyBenchReport(
            status="skipped_no_stack",
            reason=reason,
            n_projects=n_projects,
            items_per_project=items_per_project,
            queries_per_project=queries_per_project,
            concurrency=concurrency,
            total_latency=_SKIPPED_STATS,
            embed_latency=_SKIPPED_STATS,
            per_project_p50_ms=[],
            known_gaps=_KNOWN_GAPS,
        )

    assert resolved_dsn is not None  # narrowed by `reachable` above
    try:
        return _run_against_real_stack(
            dsn=resolved_dsn,
            n_projects=n_projects,
            items_per_project=items_per_project,
            queries_per_project=queries_per_project,
            concurrency=concurrency,
            seed_workers=seed_workers,
            seed=seed,
            cleanup=cleanup,
        )
    except Exception as exc:
        return LatencyBenchReport(
            status="error",
            reason=f"{type(exc).__name__}: {exc}",
            n_projects=n_projects,
            items_per_project=items_per_project,
            queries_per_project=queries_per_project,
            concurrency=concurrency,
            total_latency=_SKIPPED_STATS,
            embed_latency=_SKIPPED_STATS,
            per_project_p50_ms=[],
            known_gaps=_KNOWN_GAPS,
        )


def _run_against_real_stack(
    *,
    dsn: str,
    n_projects: int,
    items_per_project: int,
    queries_per_project: int,
    concurrency: int,
    seed_workers: int,
    seed: int,
    cleanup: bool,
) -> LatencyBenchReport:
    from tracebed.stores.pg import partitions
    from tracebed.stores.pg.migrate import apply_migrations
    from tracebed.stores.pg.pool import create_pool
    from tracebed.stores.pg.repo import Repo
    from tracebed.stores.pg.search import SearchStore

    apply_migrations(dsn)
    pool = create_pool(dsn, min_size=1, max_size=max(10, concurrency))
    clock = SystemClock()
    repo = Repo(pool, clock)
    search = SearchStore(pool)
    embedder = _DeterministicEmbeddingPort()
    retriever = Retriever(search, embedder, clock)

    project_ids: list[ProjectId] = []
    try:
        for i in range(n_projects):
            project_id = repo.create_project(f"latency-bench-{seed}-{i}")
            with pool.connection() as conn:
                partitions.create_project_partitions(conn, project_id)
            project_ids.append(project_id)

        # The status the bench WOULD seed once a status-write path exists; asserted, not
        # used, so this stops compiling the day `validated` becomes reachable.
        assert _legally_validated_status(_default_limits()) is Status.VALIDATED
        status = Status.CANDIDATE
        _seed_all_projects(
            repo=repo,
            project_ids=project_ids,
            items_per_project=items_per_project,
            seed=seed,
            seed_workers=seed_workers,
            status=status,
        )

        total_samples: list[float] = []
        embed_samples: list[float] = []
        per_project_p50: list[float] = []
        cfg = RetrievalConfig()

        def _one_query(project_id: ProjectId, query_text: str) -> tuple[float, int]:
            start = time.perf_counter()
            outcome = retriever.retrieve(project_id, query_text, cfg=cfg)
            elapsed_ms = (time.perf_counter() - start) * 1000.0
            return elapsed_ms, outcome.embed_latency_ms

        with ThreadPoolExecutor(max_workers=concurrency, thread_name_prefix="tb-bench-load") as pool_exec:
            for project_id in project_ids:
                rng = random.Random(f"{seed}:query:{project_id}")
                queries = [_synthetic_query(rng) for _ in range(queries_per_project)]
                futures = [
                    pool_exec.submit(_one_query, project_id, q) for q in queries
                ]
                project_samples = [f.result()[0] for f in futures]
                total_samples.extend(project_samples)
                embed_samples.extend(f.result()[1] for f in futures)
                per_project_p50.append(_percentile(project_samples, 50))

        return LatencyBenchReport(
            status="ok",
            reason="",
            n_projects=n_projects,
            items_per_project=items_per_project,
            queries_per_project=queries_per_project,
            concurrency=concurrency,
            total_latency=_stats(total_samples),
            embed_latency=_stats([float(v) for v in embed_samples]),
            per_project_p50_ms=per_project_p50,
            known_gaps=_KNOWN_GAPS,
        )
    finally:
        retriever.close()
        if cleanup:
            for project_id in project_ids:
                try:
                    with pool.connection() as conn, conn.transaction():
                        partitions.drop_project(conn, project_id)
                except Exception as exc:
                    # Best-effort cleanup: a failure here must never mask the
                    # bench's own result (already returned by the `try` above
                    # this `finally`), but it must not vanish silently either.
                    print(f"latency_bench: cleanup of project {project_id} failed: {exc}")
        pool.close()


def render_text(report: LatencyBenchReport) -> str:
    if report.status == "skipped_no_stack":
        return f"latency bench: SKIPPED-NO-STACK ({report.reason})"
    if report.status == "error":
        return f"latency bench: ERROR ({report.reason})"

    lines = [
        f"latency bench: {report.n_projects} projects x {report.items_per_project} items, "
        f"{report.queries_per_project} queries/project, concurrency={report.concurrency}",
        "",
        f"{'metric':<16} {'n':>8} {'p50 (ms)':>10} {'p95 (ms)':>10} {'p99 (ms)':>10} {'max (ms)':>10}",
        (
            f"{'total':<16} {report.total_latency.count:>8} {report.total_latency.p50_ms:>10.3f} "
            f"{report.total_latency.p95_ms:>10.3f} {report.total_latency.p99_ms:>10.3f} "
            f"{report.total_latency.max_ms:>10.3f}"
        ),
        (
            f"{'embed':<16} {report.embed_latency.count:>8} {report.embed_latency.p50_ms:>10.3f} "
            f"{report.embed_latency.p95_ms:>10.3f} {report.embed_latency.p99_ms:>10.3f} "
            f"{report.embed_latency.max_ms:>10.3f}"
        ),
    ]
    if report.per_project_p50_ms:
        stdev = statistics.pstdev(report.per_project_p50_ms) if len(report.per_project_p50_ms) > 1 else 0.0
        lines.append("")
        lines.append(
            f"per-project p50 variance: mean={statistics.mean(report.per_project_p50_ms):.3f}ms "
            f"stdev={stdev:.3f}ms min={min(report.per_project_p50_ms):.3f}ms "
            f"max={max(report.per_project_p50_ms):.3f}ms"
        )
    lines.append("")
    for gap in report.known_gaps:
        lines.append(f"KNOWN GAP: {gap}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pg-dsn", default=None)
    parser.add_argument("--projects", type=int, default=DEFAULT_PROJECTS)
    parser.add_argument("--items-per-project", type=int, default=DEFAULT_ITEMS_PER_PROJECT)
    parser.add_argument("--queries-per-project", type=int, default=DEFAULT_QUERIES_PER_PROJECT)
    parser.add_argument("--concurrency", type=int, default=DEFAULT_CONCURRENCY)
    parser.add_argument("--seed-workers", type=int, default=DEFAULT_SEED_WORKERS)
    parser.add_argument("--seed", type=int, default=1337)
    parser.add_argument("--keep-data", action="store_true")
    parser.add_argument("--smoke", action="store_true", help="tiny scale, for a quick sanity check")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    n_projects = 2 if args.smoke else args.projects
    items_per_project = 50 if args.smoke else args.items_per_project
    queries_per_project = 5 if args.smoke else args.queries_per_project

    report = run_latency_bench(
        pg_dsn=args.pg_dsn,
        n_projects=n_projects,
        items_per_project=items_per_project,
        queries_per_project=queries_per_project,
        concurrency=args.concurrency,
        seed_workers=args.seed_workers,
        seed=args.seed,
        cleanup=not args.keep_data,
    )

    if args.json:
        print(json.dumps(asdict(report), indent=2, sort_keys=True))
    else:
        print(render_text(report))

    return 0 if report.status != "error" else 1


if __name__ == "__main__":
    raise SystemExit(main())
