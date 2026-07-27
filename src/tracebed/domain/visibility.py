"""Scope visibility — which memories a given run is allowed to see (MEMORY_PLAN §5).

`ScopeType` says who a memory belongs to; nothing in the retrieval path used to read it.
Retrieval filtered on `project_id` and the retrievability predicate only, which made a
`user`-scoped memory written for user A retrievable by any agent serving any user in the
same project. This module is the missing predicate, in one place so the two injection
paths (`hotpath.assembly.CandidateAssembly` and `hotpath.jit.JitGate`) cannot disagree
about it.

The rule, exactly MEMORY_PLAN §5's ownership model:

    project_shared     -> visible to every run in the project
    agent_type         -> visible iff scope_id == the run's own agent_type_id
    workflow_template  -> visible iff scope_id == the run's workflow_template_id
    user               -> visible iff scope_id == the run's user_scope_id

DELIBERATELY FAIL-CLOSED. `/v1/retrieve` carries `workflow_template` and `user_ref` as
free-text strings (`domain.events.RunContext`); neither is resolved to the `uuid` that
`memory_item.scope_id` holds, because no resolver exists (there is no
`workflow_template` registry table, and `user_ref` is a subject reference, not a subject
key id). Rather than guess, `RunVisibility` defaults both to `None` and a `None`
reference matches nothing — so today workflow- and user-scoped memories are invisible to
every run instead of visible to every run. That is a narrowing, and it is recorded as a
known gap in PLAN.md ("Known gaps against the original spec") and in DECISIONS.md
(D-097): the correct end state resolves both references server-side and passes them here.

Exhaustive over `ScopeType` via `assert_never`, so adding a scope type is a type error
here rather than a silent "not visible" (or, worse, a silent "visible").
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import assert_never
from uuid import UUID

from tracebed.domain.enums import ScopeType
from tracebed.domain.ids import AgentTypeId

__all__ = ["RunVisibility", "scope_visible"]


@dataclass(frozen=True, slots=True)
class RunVisibility:
    """The three server-derived references a run can match a scoped memory against.

    `agent_type_id` is mandatory and always available (`ProjectScope.agent_type_id`,
    derived from the caller's `agent_registration` row — never caller-asserted). The
    other two are `None` until a resolver exists; see the module docstring.
    """

    agent_type_id: AgentTypeId
    workflow_template_id: UUID | None = None
    user_scope_id: UUID | None = None


def scope_visible(
    scope_type: ScopeType, scope_id: UUID | None, visibility: RunVisibility
) -> bool:
    """Is a memory owned by `(scope_type, scope_id)` visible to this run?

    `scope_id` is `None` only for `project_shared` (`NewMemoryItem.__post_init__`
    enforces that both ways); any other scope type with a `None` scope_id is a row that
    should not exist, and it is refused rather than treated as unscoped.
    """
    match scope_type:
        case ScopeType.PROJECT_SHARED:
            return True
        case ScopeType.AGENT_TYPE:
            return scope_id is not None and scope_id == visibility.agent_type_id.value
        case ScopeType.WORKFLOW_TEMPLATE:
            return (
                scope_id is not None
                and visibility.workflow_template_id is not None
                and scope_id == visibility.workflow_template_id
            )
        case ScopeType.USER:
            return (
                scope_id is not None
                and visibility.user_scope_id is not None
                and scope_id == visibility.user_scope_id
            )
        case _:  # pragma: no cover - exhaustiveness is a mypy error, not a runtime path
            assert_never(scope_type)
