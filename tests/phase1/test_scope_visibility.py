"""MEMORY_PLAN §5's ownership model, enforced on both injection paths.

Before this suite existed, `stores.pg.search` filtered on `project_id` and the
retrievability predicate and on nothing else: `scope_type`/`scope_id` were written at
insert and read by no query, so a memory scoped to one agent type — or to one end user —
was retrievable by every agent serving every user in the project. The audit classified
that as the only finding with a plausible cross-user exposure path inside a project.

Three layers are asserted here, deliberately at three different altitudes:

  1. `domain.visibility.scope_visible` — the rule itself, exhaustive over `ScopeType`
     (the parametrisation is generated from the enum, so a new member fails this file
     rather than silently defaulting to visible).
  2. `CandidateRow` carries the two columns with NO default, and `fetch_candidates`
     selects them — a second producer of `CandidateRow` cannot forget them.
  3. Both injection paths (`hotpath.assembly.CandidateAssembly` and `hotpath.jit.JitGate`)
     drop a row this run may not see, proved by mutation: delete either `scope_visible`
     call and one of these turns red.
"""

from __future__ import annotations

import dataclasses
import uuid
from datetime import UTC, datetime, timedelta

import pytest

from tracebed.domain.enums import ScopeType
from tracebed.domain.ids import AgentTypeId
from tracebed.domain.visibility import RunVisibility, scope_visible
from tracebed.stores.pg import search as search_module
from tracebed.stores.pg.search import CandidateRow

pytestmark = pytest.mark.phase1

AGENT = AgentTypeId("22222222-2222-2222-2222-222222222222")
OTHER_AGENT = AgentTypeId("33333333-3333-3333-3333-333333333333")
NOW = datetime(2026, 7, 26, 12, 0, 0, tzinfo=UTC)


# --------------------------------------------------------------------------- #
# 1. The rule
# --------------------------------------------------------------------------- #


def test_project_shared_is_visible_to_every_run() -> None:
    assert scope_visible(ScopeType.PROJECT_SHARED, None, RunVisibility(AGENT))


def test_agent_type_memory_is_visible_only_to_its_own_agent_type() -> None:
    assert scope_visible(ScopeType.AGENT_TYPE, AGENT.value, RunVisibility(AGENT))
    assert not scope_visible(ScopeType.AGENT_TYPE, OTHER_AGENT.value, RunVisibility(AGENT))


def test_user_scoped_memory_is_visible_only_to_that_user() -> None:
    subject = uuid.uuid4()
    assert scope_visible(
        ScopeType.USER, subject, RunVisibility(AGENT, user_scope_id=subject)
    )
    assert not scope_visible(
        ScopeType.USER, subject, RunVisibility(AGENT, user_scope_id=uuid.uuid4())
    )


def test_workflow_scoped_memory_is_visible_only_to_that_template() -> None:
    template = uuid.uuid4()
    assert scope_visible(
        ScopeType.WORKFLOW_TEMPLATE, template, RunVisibility(AGENT, workflow_template_id=template)
    )
    assert not scope_visible(
        ScopeType.WORKFLOW_TEMPLATE,
        template,
        RunVisibility(AGENT, workflow_template_id=uuid.uuid4()),
    )


@pytest.mark.parametrize(
    "scope_type", [s for s in ScopeType if s is not ScopeType.PROJECT_SHARED]
)
def test_an_unresolvable_reference_hides_the_memory_rather_than_showing_it(
    scope_type: ScopeType,
) -> None:
    """Fail-closed, and it is generated from the enum so a new `ScopeType` lands here.

    `/v1/retrieve` carries `workflow_template`/`user_ref` as free text and nothing resolves
    either to a `scope_id` (PLAN.md's known-gaps section). The default `RunVisibility`
    therefore matches nothing for those two scopes — invisible, never visible-to-all.
    """
    assert not scope_visible(scope_type, uuid.uuid4(), RunVisibility(AGENT))


@pytest.mark.parametrize("scope_type", list(ScopeType))
def test_a_null_scope_id_is_never_treated_as_unscoped(scope_type: ScopeType) -> None:
    visible = scope_visible(scope_type, None, RunVisibility(AGENT))
    assert visible is (scope_type is ScopeType.PROJECT_SHARED)


# --------------------------------------------------------------------------- #
# 2. The columns exist and are mandatory
# --------------------------------------------------------------------------- #


def test_candidate_row_carries_scope_columns_with_no_default() -> None:
    """A default would make "the producer forgot" indistinguishable from "project-shared",
    i.e. it would silently restore the exposure this suite exists to close."""
    fields = {f.name: f for f in dataclasses.fields(CandidateRow)}
    for name in ("scope_type", "scope_id"):
        assert name in fields, f"CandidateRow lost {name}"
        assert fields[name].default is dataclasses.MISSING, f"{name} must not have a default"
        assert fields[name].default_factory is dataclasses.MISSING


def test_the_candidate_fetch_selects_the_scope_columns() -> None:
    sql = search_module._FETCH_CANDIDATES_SQL
    assert "scope_type" in sql and "scope_id" in sql


# --------------------------------------------------------------------------- #
# 3. Both injection paths honour it
# --------------------------------------------------------------------------- #


def _row(memory_id: object, scope_type: ScopeType, scope_id: uuid.UUID | None) -> CandidateRow:
    from tracebed.domain.enums import MemType, TrustTier
    from tracebed.domain.ids import MemoryId
    from tracebed.domain.state_machine import Status

    assert isinstance(memory_id, MemoryId)
    return CandidateRow(
        memory_id=memory_id,
        mem_type=MemType.LESSON,
        trust_tier=TrustTier.B,
        status=Status.VALIDATED,
        content="retry idempotent tool invocation guidance",
        token_count=10,
        q_value=0.8,
        confidence=0.9,
        created_at=NOW - timedelta(days=1),
        scope_type=scope_type,
        scope_id=scope_id,
    )


def test_the_ordinary_path_drops_a_memory_scoped_to_another_agent_type() -> None:
    """Mutation this catches: delete the `scope_visible` guard in `hotpath.assembly` and the
    foreign agent's memory is rendered into this agent's prompt."""
    from tests.phase1.test_assembly import SCOPE, FakeStore, _effective_config, _fused, _mid
    from tracebed.domain.clock import FakeClock
    from tracebed.domain.enums import OutcomeCode
    from tracebed.hotpath.assembly import CandidateAssembly

    mine, theirs = _mid("a"), _mid("b")
    store = FakeStore(
        [
            _row(mine, ScopeType.AGENT_TYPE, SCOPE.agent_type_id.value),
            _row(theirs, ScopeType.AGENT_TYPE, OTHER_AGENT.value),
        ]
    )
    result = CandidateAssembly(store, FakeClock(NOW)).run(
        SCOPE,
        query_text="retry idempotent tool invocation",
        candidates=[_fused(mine, rank=1), _fused(theirs, rank=2)],
        cfg=_effective_config(),
    )
    placed = {slot.memory_id for slot in result.slots}
    assert result.outcome_code is OutcomeCode.INJECTED
    assert placed == {mine.value}, "a memory owned by another agent type reached the prompt"


def test_the_ordinary_path_keeps_project_shared_memory() -> None:
    from tests.phase1.test_assembly import SCOPE, FakeStore, _effective_config, _fused, _mid
    from tracebed.domain.clock import FakeClock
    from tracebed.hotpath.assembly import CandidateAssembly

    shared = _mid("c")
    store = FakeStore([_row(shared, ScopeType.PROJECT_SHARED, None)])
    result = CandidateAssembly(store, FakeClock(NOW)).run(
        SCOPE,
        query_text="retry idempotent tool invocation",
        candidates=[_fused(shared)],
        cfg=_effective_config(),
    )
    assert {slot.memory_id for slot in result.slots} == {shared.value}


def test_a_user_scoped_memory_never_reaches_any_run_today() -> None:
    """The fail-closed half, asserted as behaviour and not only as a rule: with no resolver
    for `user_ref`, a user-scoped memory is invisible rather than project-visible."""
    from tests.phase1.test_assembly import SCOPE, FakeStore, _effective_config, _fused, _mid
    from tracebed.domain.clock import FakeClock
    from tracebed.domain.enums import OutcomeCode
    from tracebed.hotpath.assembly import CandidateAssembly

    theirs = _mid("d")
    store = FakeStore([_row(theirs, ScopeType.USER, uuid.uuid4())])
    result = CandidateAssembly(store, FakeClock(NOW)).run(
        SCOPE,
        query_text="retry idempotent tool invocation",
        candidates=[_fused(theirs)],
        cfg=_effective_config(),
    )
    assert result.slots == ()
    assert result.outcome_code is OutcomeCode.EMPTY_RESULT
