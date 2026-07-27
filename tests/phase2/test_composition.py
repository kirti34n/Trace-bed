"""`workers.composition` — the coverage check that stops the learning plane from silently
scheduling nothing.

`workers/registry.py` learned this lesson for queue topics and this module applies it to
periodic workers: the failure being guarded is not "we scheduled the wrong job", it is "we
quietly scheduled none, the process looked healthy, and the only symptom was a vault that never
changed" (FIDELITY-AUDIT.md M2). Every refusal below is production-silent and invisible to a
test of a different configuration, which is why the check lives in the code and not only here.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import timedelta
from types import MappingProxyType
from typing import Any

import pytest

from tracebed.domain.clock import FakeClock
from tracebed.domain.config import WorkersConfig
from tracebed.domain.errors import ConfigError
from tracebed.domain.ids import AgentTypeId, ProjectId
from tracebed.domain.state_machine import Status
from tracebed.workers import composition
from tracebed.workers.composition import (
    NON_PERIODIC_WORKERS,
    UNSCHEDULED_WORKERS,
    discover_worker_modules,
    validate_worker_coverage,
)

pytestmark = pytest.mark.phase2

_GOOD = frozenset({"alpha", "beta", "gamma"})
_LONG = "a reason long enough to clear the placeholder floor because it names the exact port"


def _ok(**kw: Any) -> None:
    validate_worker_coverage(
        kw.pop("scheduled", {"alpha"}),
        unscheduled=kw.pop("unscheduled", {"beta": _LONG}),
        non_periodic=kw.pop("non_periodic", {"gamma": _LONG}),
        all_workers=kw.pop("all_workers", _GOOD),
    )


# --------------------------------------------------------------------------- #
# The positive control -- without it every refusal test below could be passing
# simply because the validator rejects everything.
# --------------------------------------------------------------------------- #


def test_a_correct_three_way_partition_validates() -> None:
    _ok()


# --------------------------------------------------------------------------- #
# Six production-silent arrangements, each refused
# --------------------------------------------------------------------------- #


def test_a_worker_in_no_classification_is_refused() -> None:
    """The omitted-worker case: a module that is neither scheduled nor explained. In a
    deployment this is a pass that never runs, with no error anywhere."""
    with pytest.raises(ConfigError, match="gamma"):
        _ok(non_periodic={})


def test_a_classification_for_a_module_that_does_not_exist_is_refused() -> None:
    """The reverse direction, and it is exactly as bad: a schedule entry for a deleted or
    renamed module runs nothing forever while the schedule looks populated."""
    with pytest.raises(ConfigError, match="delta"):
        _ok(scheduled={"alpha", "delta"})


def test_a_module_in_two_classifications_is_refused() -> None:
    with pytest.raises(ConfigError, match="alpha"):
        _ok(unscheduled={"alpha": _LONG, "beta": _LONG})


def test_an_empty_module_set_is_refused_rather_than_vacuously_satisfied() -> None:
    """The discovery walk feeds every relation above. If it silently returns nothing, every
    one of them is satisfied by scheduling nothing -- a check that has stopped checking."""
    with pytest.raises(ConfigError, match="no modules discovered"):
        validate_worker_coverage(set(), unscheduled={}, non_periodic={}, all_workers=frozenset())


def test_a_placeholder_reason_does_not_discharge_the_check() -> None:
    """"TODO" leaves a worker exactly as unexamined as an omission while passing coverage."""
    with pytest.raises(ConfigError, match="beta"):
        _ok(unscheduled={"beta": "TODO"})


def test_a_placeholder_reason_in_the_non_periodic_table_is_refused_too() -> None:
    """Both tables, not just the interesting one: "this has no cadence" is a claim that needs
    justifying as much as "this is blocked on a port"."""
    with pytest.raises(ConfigError, match="gamma"):
        _ok(non_periodic={"gamma": "n/a"})


# --------------------------------------------------------------------------- #
# The real tables, against the real package
# --------------------------------------------------------------------------- #


def test_the_shipped_classification_covers_every_worker_module() -> None:
    """The check that fires when somebody adds a worker and forgets to decide about it."""
    validate_worker_coverage({"embedder", "corroboration", "gc", "sweeps", "prefix_builder"})


def test_discovery_walks_the_package_rather_than_a_hand_written_list() -> None:
    """A hand-copied list keeps passing the day a new worker lands. Asserted by naming modules
    that exist and one that does not."""
    found = discover_worker_modules()
    assert {"embedder", "corroboration", "gc", "scorer", "killswitch"} <= found
    assert "not_a_worker_module" not in found


def test_both_reason_tables_are_read_only() -> None:
    """They are the evidence half of an invariant checked at process construction; a caller
    mutating one after the check has run rewrites the audit trail a deployed process reports.
    Same reasoning, and same mechanism, as `workers.registry.UNREGISTERED_TOPICS`."""
    assert isinstance(UNSCHEDULED_WORKERS, MappingProxyType)
    assert isinstance(NON_PERIODIC_WORKERS, MappingProxyType)
    with pytest.raises(TypeError):
        UNSCHEDULED_WORKERS["x"] = "y"  # type: ignore[index]
    with pytest.raises(TypeError):
        NON_PERIODIC_WORKERS["x"] = "y"  # type: ignore[index]


def test_every_unscheduled_reason_names_a_port_or_an_audit_finding() -> None:
    """A reason that does not say WHAT is missing is a reason nobody can act on. This is the
    difference between a work queue and an apology."""
    for name, reason in UNSCHEDULED_WORKERS.items():
        assert "Port" in reason or "FIDELITY-AUDIT" in reason, name


# --------------------------------------------------------------------------- #
# build_scheduled_jobs
# --------------------------------------------------------------------------- #


class _Queue:
    """`QueueObservabilityPort` -- exactly what `workers.gc.run_gc_cycle` reads."""

    def depth(self, topic: str) -> int:
        del topic
        return 0

    def dead_letter_count(self, topic: str) -> int:
        del topic
        return 0

    def oldest_age_s(self, topic: str) -> float | None:
        del topic
        return None

    def xmin_horizon_alarm(self) -> bool:
        return False


class _Embedder:
    def __init__(self) -> None:
        self.calls: list[tuple[ProjectId, int]] = []

    def run(self, project_id: ProjectId, *, limit: int) -> object:
        self.calls.append((project_id, limit))
        return object()


def _effective_config() -> Any:
    """A real `EffectiveConfig` from every section's documented default -- what the sweeps job's
    `config_resolver.effective(project_id)` call returns in these tests. Built from concrete
    section models rather than a stub so a sweep body that reached into it would see real
    values, and so the cross-section validator (`q_start > archive_floor`) is exercised."""
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

    return EffectiveConfig(
        retrieval=RetrievalConfig(),
        abstention=AbstentionConfig(),
        score=ScoreConfig(),
        budget=BudgetConfig(),
        scoring=ScoringConfig(),
        promotion=PromotionConfig(),
        retirement=RetirementConfig(),
        lifecycle=LifecycleConfig(),
        derived=DerivedConfig(),
        proposals=ProposalConfig(),
        tier_a=TierAConfig(),
        killswitch=KillswitchConfig(),
        spend=SpendConfig(),
        cache=CacheConfig(),
        session=SessionConfig(),
        queue=QueueConfig(),
    )


class _Resolver:
    """`ConfigProvider` fake: records every `(project_id, agent_type_id)` it resolved so a test
    can assert per-project resolution, and returns a fresh default `EffectiveConfig`."""

    def __init__(self) -> None:
        self.calls: list[tuple[ProjectId, Any]] = []

    def effective(self, project_id: ProjectId, agent_type_id: Any = None) -> Any:
        self.calls.append((project_id, agent_type_id))
        return _effective_config()


class _MemoryStore:
    """`MemoryStorePort` fake (the prefix_builder's `Repo.list_memories` shape)."""

    def list_memories(
        self, project_id: ProjectId, *, statuses: Any = None, limit: int = 100
    ) -> list[Any]:
        del project_id, statuses, limit
        return []


class _PrefixCache:
    """`StaticPrefixCachePort` fake: records each publish so a test can assert both writes."""

    def __init__(self) -> None:
        self.published: list[tuple[str, ProjectId, Any, int]] = []

    def static_prefix_set(
        self,
        project_id: ProjectId,
        agent_type_id: Any,
        prefix_version: int,
        value: bytes,
        *,
        ttl_seconds: int,
    ) -> None:
        del value, ttl_seconds
        self.published.append(("block", project_id, agent_type_id, prefix_version))

    def current_prefix_version_set(
        self,
        project_id: ProjectId,
        agent_type_id: Any,
        prefix_version: int,
        *,
        ttl_seconds: int,
    ) -> None:
        del ttl_seconds
        self.published.append(("pointer", project_id, agent_type_id, prefix_version))


def _plane(**kw: Any) -> Any:
    from tracebed.workers.composition import LearningPlane

    defaults: dict[str, Any] = {
        "lifecycle": object(),
        "edit_ops": object(),
        "forensics": object(),
        "preferences": object(),
        "embedder": _Embedder(),
        "corroboration": None,
        # The now-constructed Postgres store implementations of the store-blocked workers'
        # ports (FIDELITY-AUDIT.md M3). Present on every real plane; still not scheduled,
        # so `build_scheduled_jobs` never reads them and `object()` stand-ins suffice here.
        "memory_lifecycle": object(),
        "derived_state_store": object(),
        "scorer_repo": object(),
        "promotion_repo": object(),
        "shadow_validator_repo": object(),
        "killswitch_writer": object(),
        "known_distillations": object(),
    }
    defaults.update(kw)
    return LearningPlane(**defaults)


def _jobs(plane: Any, projects: Sequence[ProjectId], **kw: Any) -> Any:
    return composition.build_scheduled_jobs(
        plane,
        cfg=kw.pop("cfg", WorkersConfig()),
        list_project_ids=kw.pop("list_project_ids", lambda: list(projects)),
        queue_observability=_Queue(),
        topics=("trace_event",),
        lease_seconds=30,
        clock=kw.pop("clock", FakeClock()),
        config_resolver=kw.pop("config_resolver", _Resolver()),
        memory_store=kw.pop("memory_store", _MemoryStore()),
        prefix_cache=kw.pop("prefix_cache", _PrefixCache()),
        list_agent_type_ids=kw.pop("list_agent_type_ids", lambda pid: []),
        **kw,
    )


def test_the_embedder_and_gc_are_scheduled_and_corroboration_is_not_without_a_source() -> None:
    """The exact production state, asserted rather than described: the always-on jobs, and
    corroboration withheld for a reason the coverage check has seen."""
    jobs = _jobs(_plane(), [])
    assert [job.name for job in jobs] == ["embedder", "sweeps", "prefix_builder", "gc"]


def test_corroboration_is_scheduled_once_a_host_supplies_a_candidate_source() -> None:
    class _Source:
        def candidate_runs(self, project_id: ProjectId, row: object) -> list[Any]:
            del project_id, row
            return []

    class _Writer:
        def run_once(self, project_id: ProjectId, *, source: object) -> object:
            del project_id, source
            return object()

    jobs = _jobs(_plane(corroboration=_Writer()), [], candidate_source=_Source())
    assert [job.name for job in jobs] == [
        "embedder",
        "corroboration",
        "sweeps",
        "prefix_builder",
        "gc",
    ]


def test_the_project_list_is_re_read_on_every_run_not_snapshotted() -> None:
    """A project provisioned after the process started must be swept without a restart. A
    snapshot taken at construction would exclude it forever -- the empty-registry defect one
    layer down, and invisible until somebody provisions a project."""
    projects: list[ProjectId] = []
    embedder = _Embedder()
    jobs = _jobs(_plane(embedder=embedder), projects)
    embed_job = next(j for j in jobs if j.name == "embedder")

    embed_job.run()
    assert embedder.calls == []

    late = ProjectId(__import__("uuid").UUID(int=99))
    projects.append(late)
    embed_job.run()
    assert [pid for pid, _ in embedder.calls] == [late]


def test_one_projects_failure_does_not_stop_the_rest_of_the_sweep() -> None:
    """`Scheduler.tick` already refuses to let one broken JOB stop the schedule; this is the
    same rule one level down, for one broken PROJECT inside a job. A deployment with nine
    hundred projects must not lose the sweep to one of them."""
    import uuid

    good = ProjectId(uuid.UUID(int=1))
    bad = ProjectId(uuid.UUID(int=2))

    class _Exploding:
        def __init__(self) -> None:
            self.seen: list[ProjectId] = []

        def run(self, project_id: ProjectId, *, limit: int) -> object:
            del limit
            self.seen.append(project_id)
            if project_id == bad:
                raise RuntimeError("this project's sweep is broken")
            return object()

    embedder = _Exploding()
    jobs = _jobs(_plane(embedder=embedder), [bad, good])
    next(j for j in jobs if j.name == "embedder").run()
    assert embedder.seen == [bad, good], "the sweep stopped at the failing project"


def test_build_scheduled_jobs_validates_the_map_it_actually_returns(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The wiring, not the validator. A perfect coverage check that `build_scheduled_jobs`
    never calls is exactly the arrangement `workers/registry.py`'s own audit found: an
    invariant asserted in a test of one configuration while the deployed process builds a
    different one. Spies on the real call and asserts it saw the names the caller gets back."""
    seen: list[set[str]] = []
    real = composition.validate_worker_coverage

    def _spy(scheduled: Any, **kw: Any) -> None:
        seen.append(set(scheduled))
        real(scheduled, **kw)

    monkeypatch.setattr(composition, "validate_worker_coverage", _spy)
    jobs = _jobs(_plane(), [])
    assert seen == [{job.name for job in jobs}]


def test_a_job_for_a_module_that_does_not_exist_fails_construction() -> None:
    """The refusal reaching `build_scheduled_jobs` rather than only `validate_worker_coverage`:
    a phantom job name must take the process down at construction, not poll nothing forever."""
    from tracebed.workers.scheduler import ScheduledJob

    real = composition.build_scheduled_jobs

    def _with_phantom(*a: Any, **kw: Any) -> Any:
        jobs = list(real(*a, **kw))
        jobs.append(
            ScheduledJob(name="distil", interval=timedelta(minutes=1), run=lambda: None)
        )
        composition.validate_worker_coverage({j.name for j in jobs})
        return tuple(jobs)

    with pytest.raises(ConfigError, match="distil"):
        _with_phantom(
            _plane(),
            cfg=WorkersConfig(),
            list_project_ids=list,
            queue_observability=_Queue(),
            topics=("trace_event",),
            lease_seconds=30,
            clock=FakeClock(),
            config_resolver=_Resolver(),
            memory_store=_MemoryStore(),
            prefix_cache=_PrefixCache(),
            list_agent_type_ids=lambda pid: [],
        )


def test_every_job_takes_its_cadence_from_config_not_from_a_literal() -> None:
    """Hard rule 4, and the reason `WorkersConfig` exists at all: before it, every worker
    module carried the same standing contract gap ("cadence is a number and there is nowhere
    legitimate to put one"), which is why `Scheduler` was constructed by nothing."""
    cfg = WorkersConfig(embedding_interval_minutes=7, gc_interval_minutes=11)
    jobs = _jobs(_plane(), [], cfg=cfg)
    intervals = {job.name: job.interval for job in jobs}
    assert intervals["embedder"] == timedelta(minutes=7)
    assert intervals["gc"] == timedelta(minutes=11)


def test_the_gc_job_is_process_wide_rather_than_per_project() -> None:
    """`work_queue`/`dead_letter` are unpartitioned (contract §5.3), so queue health is one
    reading. A per-project GC job would report the same numbers once per project and make the
    depth gauge look N times worse than it is."""
    calls: list[int] = []

    class _CountingQueue(_Queue):
        def depth(self, topic: str) -> int:
            calls.append(1)
            return 0

    import uuid

    jobs = composition.build_scheduled_jobs(
        _plane(),
        cfg=WorkersConfig(),
        list_project_ids=lambda: [ProjectId(uuid.UUID(int=i)) for i in (1, 2, 3)],
        queue_observability=_CountingQueue(),
        topics=("trace_event", "outcome_event"),
        lease_seconds=30,
        clock=FakeClock(),
        config_resolver=_Resolver(),
        memory_store=_MemoryStore(),
        prefix_cache=_PrefixCache(),
        list_agent_type_ids=lambda pid: [],
    )
    next(j for j in jobs if j.name == "gc").run()
    assert len(calls) == 2, "one depth read per topic, not per topic per project"


def test_the_scheduler_actually_fires_a_composed_job_on_its_configured_cadence() -> None:
    """The last mile: `build_scheduled_jobs`' output driven by the real `Scheduler` against a
    `FakeClock`. Without this the composition could produce perfectly-shaped jobs that no
    scheduler ever calls -- which is the state the audit found."""
    import uuid

    from tracebed.workers.scheduler import Scheduler

    clock = FakeClock()
    embedder = _Embedder()
    project = ProjectId(uuid.UUID(int=5))
    jobs = _jobs(
        _plane(embedder=embedder), [project], cfg=WorkersConfig(embedding_interval_minutes=5)
    )
    scheduler = Scheduler(clock, list(jobs))

    scheduler.tick()
    assert embedder.calls == [], "a job must not fire before its first interval elapses"

    clock.advance(timedelta(minutes=5))
    fired = scheduler.tick()
    assert fired.get("embedder") == 1
    assert [pid for pid, _ in embedder.calls] == [project]


# --------------------------------------------------------------------------- #
# sweeps: per-project isolation and per-project config resolution.
# --------------------------------------------------------------------------- #


class _SweepStore:
    """A `MemoryLifecycleRepoPort`-shaped fake that records which project each sweep read, and
    returns no rows so `run_all_sweeps` completes without a transition."""

    def __init__(self) -> None:
        self.status_calls: list[tuple[ProjectId, tuple[Any, ...]]] = []

    def select_by_status(
        self, project_id: ProjectId, statuses: Any, *, limit: int = 10_000
    ) -> list[Any]:
        del limit
        self.status_calls.append((project_id, tuple(statuses)))
        return []

    def persist(self, project_id: ProjectId, write: Any) -> None:  # pragma: no cover - no rows
        del project_id, write


def test_the_sweeps_job_resolves_config_per_project_and_never_mixes_projects() -> None:
    """PLAN.md §10: a sweep batch is one project. The job resolves an `EffectiveConfig` PER
    project (project-scoped, agent_type_id=None -- sweeps carry no agent-type layer) and sweeps
    each project's own status populations, never a merged one."""
    import uuid

    a = ProjectId(uuid.UUID(int=10))
    b = ProjectId(uuid.UUID(int=11))
    store = _SweepStore()
    resolver = _Resolver()
    jobs = _jobs(_plane(memory_lifecycle=store), [a, b], config_resolver=resolver)

    next(j for j in jobs if j.name == "sweeps").run()

    # One resolve per project, project-scoped with no agent-type layer.
    assert resolver.calls == [(a, None), (b, None)]
    # Each project swept exactly its own three status populations, one at a time.
    assert store.status_calls == [
        (a, (Status.QUARANTINED,)),
        (a, (Status.CANDIDATE,)),
        (a, (Status.VALIDATED,)),
        (b, (Status.QUARANTINED,)),
        (b, (Status.CANDIDATE,)),
        (b, (Status.VALIDATED,)),
    ]


def test_one_projects_sweep_failure_does_not_stop_the_rest() -> None:
    """The same one-broken-project-does-not-stop-the-loop rule the embedder job holds, for
    sweeps: a project whose resolve raises is logged and skipped, the next is still swept."""
    import uuid

    good = ProjectId(uuid.UUID(int=12))
    bad = ProjectId(uuid.UUID(int=13))
    store = _SweepStore()

    class _HalfBrokenResolver(_Resolver):
        def effective(self, project_id: ProjectId, agent_type_id: Any = None) -> Any:
            self.calls.append((project_id, agent_type_id))
            if project_id == bad:
                raise RuntimeError("this project's config is broken")
            return _effective_config()

    resolver = _HalfBrokenResolver()
    jobs = _jobs(_plane(memory_lifecycle=store), [bad, good], config_resolver=resolver)
    next(j for j in jobs if j.name == "sweeps").run()

    assert [pid for pid, _ in resolver.calls] == [bad, good]
    # `bad` raised before any store read; `good` swept its three populations.
    assert {pid for pid, _ in store.status_calls} == {good}


# --------------------------------------------------------------------------- #
# prefix_builder: per-(project, agent_type) isolation and re-enumeration.
# --------------------------------------------------------------------------- #


def test_prefix_builder_runs_once_per_agent_type_per_project() -> None:
    """The nested loop: for each project, for each of its agent types, one build+publish. The
    agent-type list is passed as a callable and re-read each tick."""
    import uuid

    a = ProjectId(uuid.UUID(int=20))
    at1 = AgentTypeId(uuid.UUID(int=1))
    at2 = AgentTypeId(uuid.UUID(int=2))
    cache = _PrefixCache()
    resolver = _Resolver()
    jobs = _jobs(
        _plane(),
        [a],
        prefix_cache=cache,
        config_resolver=resolver,
        list_agent_type_ids=lambda pid: [at1, at2],
    )

    next(j for j in jobs if j.name == "prefix_builder").run()

    # Each agent type resolved per-(project, agent_type) and published (block + pointer).
    assert resolver.calls == [(a, at1), (a, at2)]
    assert {atid for _, _, atid, _ in cache.published} == {at1, at2}


def test_one_agent_types_prefix_failure_does_not_stop_sibling_agent_types() -> None:
    """Inner isolation: one agent type raising (config error, the MAX_ROW_LIMIT refusal, ...)
    must not stop the other agent types in the same project."""
    import uuid

    a = ProjectId(uuid.UUID(int=21))
    at_bad = AgentTypeId(uuid.UUID(int=3))
    at_ok = AgentTypeId(uuid.UUID(int=4))
    cache = _PrefixCache()

    class _AgentFailingResolver(_Resolver):
        def effective(self, project_id: ProjectId, agent_type_id: Any = None) -> Any:
            self.calls.append((project_id, agent_type_id))
            if agent_type_id == at_bad:
                raise RuntimeError("this agent type's config is broken")
            return _effective_config()

    resolver = _AgentFailingResolver()
    jobs = _jobs(
        _plane(),
        [a],
        prefix_cache=cache,
        config_resolver=resolver,
        list_agent_type_ids=lambda pid: [at_bad, at_ok],
    )

    next(j for j in jobs if j.name == "prefix_builder").run()

    # Both attempted; only the healthy one published anything.
    assert [atid for _, atid in resolver.calls] == [at_bad, at_ok]
    assert {atid for _, _, atid, _ in cache.published} == {at_ok}


def test_a_failing_agent_type_enumeration_does_not_stop_other_projects() -> None:
    """Outer isolation: a project whose `list_agent_type_ids` itself raises is logged and
    skipped by the per-project loop; the next project's agent types are still built."""
    import uuid

    bad = ProjectId(uuid.UUID(int=22))
    good = ProjectId(uuid.UUID(int=23))
    at = AgentTypeId(uuid.UUID(int=5))
    cache = _PrefixCache()

    def _ids(pid: ProjectId) -> list[AgentTypeId]:
        if pid == bad:
            raise RuntimeError("agent-type enumeration broke")
        return [at]

    jobs = _jobs(_plane(), [bad, good], prefix_cache=cache, list_agent_type_ids=_ids)
    next(j for j in jobs if j.name == "prefix_builder").run()

    assert {pid for _, pid, _, _ in cache.published} == {good}


def test_the_agent_type_list_is_re_read_on_every_run_not_snapshotted() -> None:
    """An agent type provisioned after the process started must be built without a restart --
    the same re-read guarantee `list_project_ids` gets, one level down."""
    import uuid

    a = ProjectId(uuid.UUID(int=24))
    agent_types: list[AgentTypeId] = []
    cache = _PrefixCache()
    jobs = _jobs(
        _plane(), [a], prefix_cache=cache, list_agent_type_ids=lambda pid: list(agent_types)
    )
    job = next(j for j in jobs if j.name == "prefix_builder")

    job.run()
    assert cache.published == []

    late = AgentTypeId(uuid.UUID(int=6))
    agent_types.append(late)
    job.run()
    assert {atid for _, _, atid, _ in cache.published} == {late}


def test_the_embedding_batch_limit_reaches_the_worker(embedder_limit: int = 3) -> None:
    """`WorkersConfig.embedding_batch_limit` bounds how much one tick does. A cadence field
    that never reaches its worker is a knob that silently does nothing (E5's defect)."""
    import uuid

    embedder = _Embedder()
    jobs = _jobs(
        _plane(embedder=embedder),
        [ProjectId(uuid.UUID(int=6))],
        cfg=WorkersConfig(embedding_batch_limit=embedder_limit),
    )
    next(j for j in jobs if j.name == "embedder").run()
    assert [limit for _, limit in embedder.calls] == [embedder_limit]
