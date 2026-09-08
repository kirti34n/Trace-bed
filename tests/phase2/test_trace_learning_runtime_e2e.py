"""Live P2B runtime proof: archive -> Tier A -> embedding -> hybrid retrieval."""

from __future__ import annotations

import os
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import psycopg
import pytest
from psycopg.conninfo import make_conninfo

from tests.phase2.trace_e2e_support import _enqueue, _event, _Master
from tracebed.adapters.embedding.hash_local import HashLocalEmbeddingClient
from tracebed.adapters.embedding.pinning import ModelPin
from tracebed.domain.clock import FakeClock
from tracebed.domain.config import (
    HASH_LOCAL_MODEL_ID,
    HASH_LOCAL_MODEL_VERSION,
    AbstentionConfig,
    ConfigResolver,
    EmbeddingConfig,
    KillswitchConfig,
    TracebedSettings,
)
from tracebed.domain.enums import Slot, TrustTier
from tracebed.domain.events import RunContext
from tracebed.domain.ids import RunId
from tracebed.domain.scope import ProjectScope
from tracebed.domain.state_machine import Status
from tracebed.hotpath.assembly import CandidateAssembly
from tracebed.hotpath.pipeline import Pipeline
from tracebed.hotpath.retriever import Retriever
from tracebed.ingest.trace_writer import TraceWriter
from tracebed.stores.pg.learning import EmbeddingRepo
from tracebed.stores.pg.partitions import create_project_partitions
from tracebed.stores.pg.pool import create_pool, scoped
from tracebed.stores.pg.queue import WorkQueue
from tracebed.stores.pg.repo import Repo
from tracebed.stores.pg.search import SearchStore
from tracebed.stores.pg.telemetry import Telemetry
from tracebed.stores.tracestore.fs import FsTraceStore
from tracebed.workers.composition import build_trace_learning_runner
from tracebed.workers.embedder import Embedder
from tracebed.workers.spend import SpendMeter

pytestmark = [pytest.mark.phase2, pytest.mark.integration]


def _runtime_settings(settings: TracebedSettings) -> TracebedSettings:
    """Make the live proof local/deterministic without changing process defaults."""

    return settings.model_copy(
        update={
            "embedding": EmbeddingConfig(driver="hash-local", dim=768),
            # One freshly-created candidate is enough to exercise the real
            # retrieval path; this E2E is not an evidence-quality benchmark.
            "abstention": AbstentionConfig(
                cos_threshold=-1.0,
                bm25_norm_threshold=0.0,
                rarity_min_shared_terms=0,
                rarity_min_corpus_docs=0,
            ),
            "killswitch": KillswitchConfig(holdout_pct=0.0),
        }
    )


def test_real_trace_learning_runtime_retrieves_only_a_lower_trust_candidate(
    settings: TracebedSettings, tmp_path: Path, scratch_dsn: str
) -> None:
    """No fake core hop: writer, reader, coordinator, finalizer, embedder and reads are real."""

    owner_pool = create_pool(scratch_dsn)
    owner_pool.wait(timeout=5)
    app_dsn = make_conninfo(
        scratch_dsn,
        user="tracebed_app",
        password=os.environ.get("TB_APP_PASSWORD", "tracebed_app_dev_only"),
    )
    app_pool = None
    try:
        with psycopg.connect(app_dsn, connect_timeout=2):
            pass
        app_pool = create_pool(app_dsn)
        app_pool.wait(timeout=5)
    except Exception as exc:  # pragma: no cover - deployment-owned credential
        if app_pool is not None:
            app_pool.close()
        owner_pool.close()
        pytest.skip(f"tracebed_app connection unavailable for runtime E2E: {exc.__class__.__name__}")

    retriever: Retriever | None = None
    try:
        cfg = _runtime_settings(settings)
        clock = FakeClock(datetime(2026, 2, 1, tzinfo=UTC))
        owner_repo = Repo(owner_pool, clock)
        project_id = owner_repo.create_project("p2b-runtime-e2e")
        principal_id = owner_repo.create_principal("api_key", "p2b-runtime-e2e", "hash")
        agent_type_id = owner_repo.create_agent_type(project_id, "p2b-runtime-agent")
        owner_repo.register_agent(project_id, principal_id, agent_type_id)
        with owner_pool.connection() as conn:
            create_project_partitions(conn, project_id)

        repo = Repo(app_pool, clock)
        queue = WorkQueue(app_pool, clock, cfg.queue)
        store = FsTraceStore(tmp_path / "runtime-traces")
        from tracebed.crypto.shred import SubjectKeyManager

        keys = SubjectKeyManager(repo, _Master(), clock)
        writer = TraceWriter(queue, repo, store, keys, clock, cfg)
        run_id = RunId(uuid.uuid4())
        ended_at = clock.now() + timedelta(seconds=3)
        _enqueue(
            queue,
            project_id,
            principal_id,
            agent_type_id,
            run_id,
            [
                (0, _event("run_start", clock.now(), {"tool_manifest": ["tool-a"]})),
                (
                    1,
                    _event(
                        "error",
                        clock.now() + timedelta(seconds=1),
                        {
                            "tool_id": "tool-a",
                            "tool_version": "v1",
                            "error_class": "timeout",
                            "duration_ms": 1,
                        },
                    ),
                ),
                (
                    2,
                    _event(
                        "error",
                        clock.now() + timedelta(seconds=2),
                        {
                            "tool_id": "tool-a",
                            "tool_version": "v1",
                            "error_class": "timeout",
                            "duration_ms": 1,
                        },
                    ),
                ),
                (3, _event("run_end", ended_at, {"status": "ok"})),
            ],
        )
        assert writer.run_once() == 4

        runtime = build_trace_learning_runner(
            pool=app_pool,
            repo=repo,
            tracestore=store,
            keys=keys,
            config_resolver=ConfigResolver(cfg, repo),
            clock=clock,
            lease_seconds=cfg.queue.lease_seconds,
            poll_interval=timedelta(0),
            owner="trace-learning:runtime-e2e",
        )
        assert runtime.run_once() == 1
        with scoped(app_pool, project_id) as conn:
            memories = conn.execute(
                """
                SELECT id, lane, trust_tier, status, embedding,
                       embedding_model_id, embedding_model_version
                FROM memory_item
                WHERE project_id = %s
                """,
                (project_id.value,),
            ).fetchall()
            job = conn.execute(
                """
                SELECT state, trace_digest, result_digest, memory_ids,
                       lease_token, lease_owner, lease_expires_at, finished_at,
                       last_error_code, skip_code
                FROM trace_learning_job
                WHERE project_id = %s AND run_id = %s
                  AND pipeline = 'tier_a' AND pipeline_version = 1
                """,
                (project_id.value, run_id.value),
            ).fetchone()
            outside_tier_a = conn.execute(
                """
                SELECT count(*)
                FROM memory_item
                WHERE project_id = %s
                  AND (lane <> 'operational' OR trust_tier <> 'A' OR status <> 'candidate')
                """,
                (project_id.value,),
            ).fetchone()
        assert len(memories) == 1
        memory = memories[0]
        assert (memory[1], TrustTier(memory[2]), Status(memory[3])) == (
            "operational",
            TrustTier.A,
            Status.CANDIDATE,
        )
        assert memory[4:] == (None, None, None)
        assert job is not None
        assert job[0] == "succeeded"
        assert isinstance(job[1], bytes) and len(job[1]) == 32
        assert isinstance(job[2], bytes) and len(job[2]) == 32
        assert job[3] == [memory[0]]
        assert job[4:7] == (None, None, None)
        assert job[7] is not None
        assert job[8:] == (None, None)
        assert outside_tier_a == (0,)

        pin = ModelPin(
            model_id=cfg.embedding.model_id,
            model_version=cfg.embedding.model_version,
            dim=cfg.embedding.dim,
        )
        embedding = HashLocalEmbeddingClient(pin=pin, clock=clock)
        embedded = Embedder(
            clock=clock,
            embedding_port=embedding,
            repo=EmbeddingRepo(app_pool),
            spend=SpendMeter(repo, clock, cfg.spend),
            pin=pin,
            usd_per_1k_tokens=0.0,
            timeout_ms=cfg.workers.embedding_timeout_ms,
            max_batch=cfg.workers.embedding_max_batch,
        ).run(project_id, limit=10)
        assert embedded.embedded_count == 1

        with scoped(app_pool, project_id) as conn:
            embedded_memory = conn.execute(
                """
                SELECT lane, trust_tier, status, embedding::text,
                       embedding_model_id, embedding_model_version
                FROM memory_item
                WHERE project_id = %s AND id = %s
                """,
                (project_id.value, memory[0]),
            ).fetchone()
        assert embedded_memory is not None
        assert embedded_memory[:3] == ("operational", "A", "candidate")
        assert embedded_memory[3] is not None
        assert len(embedded_memory[3].strip("[]").split(",")) == 768
        assert embedded_memory[4:] == (HASH_LOCAL_MODEL_ID, HASH_LOCAL_MODEL_VERSION)

        search = SearchStore(app_pool)
        lexical = search.lexical_arm(project_id, "tool-a", 10)
        vector = search.vector_arm(
            project_id,
            embedding.embed(["tool-a"], timeout_ms=cfg.retrieval.embed_timeout_ms)[0],
            10,
            hnsw_iterative_scan=cfg.retrieval.hnsw_iterative_scan,
            hnsw_max_scan_tuples=cfg.retrieval.hnsw_max_scan_tuples,
        )
        assert {hit.memory_id.value for hit in lexical} == {memory[0]}
        assert {hit.memory_id.value for hit in vector} == {memory[0]}

        telemetry = Telemetry(repo, clock)
        retriever = Retriever(search, embedding, clock)
        pipeline = Pipeline(
            clock=clock,
            config=ConfigResolver(cfg, repo),
            telemetry=telemetry,
            retriever=retriever,
            assembly=CandidateAssembly(search, clock),
            injections=telemetry,
            holdout_salt="runtime-e2e-test-salt",
        )
        result = pipeline.retrieve(
            ProjectScope(project_id, agent_type_id, principal_id), RunContext(query_text="tool-a")
        )
        assert [slot.slot for slot in result.context_block.slots] == [Slot.CANDIDATE_NOTE]
        assert result.context_block.rendered
        # The narrow P2B claim: the stored row remains a Tier-A candidate;
        # this does not invoke promotion, corroboration, scoring or quality claims.
        with scoped(app_pool, project_id) as conn:
            assert conn.execute(
                """
                SELECT lane, status, trust_tier
                FROM memory_item
                WHERE project_id = %s AND id = %s
                """,
                (project_id.value, memory[0]),
            ).fetchone() == ("operational", "candidate", "A")
    finally:
        if retriever is not None:
            retriever.close()
        if app_pool is not None:
            app_pool.close()
        owner_pool.close()
