"""ProjectScope — the only carrier of project identity (PHASE0-CONTRACT.md §3.3).

Invariant 4 says project isolation is enforced *at query construction* and that
`project_id` is derived server-side from the authenticated principal, never
accepted from a caller. This type is how that derivation travels.

The flow is fixed and has no other legal shape:

    request -> api.deps.get_principal (authenticates)
            -> api.deps.get_scope
            -> Repo.resolve_project(principal_id)
            -> ProjectScope
            -> route handler passes scope.project_id to every repo/queue/telemetry call

`ProjectScope` is constructed in exactly two places: `Repo.resolve_project` and
test fixtures. No route request model contains a `project_id` field, and every
route model sets `extra="forbid"`, so a caller cannot smuggle one in either as a
declared field or as an unexpected key.
"""

from __future__ import annotations

from dataclasses import dataclass

from tracebed.domain.ids import AgentTypeId, PrincipalId, ProjectId

__all__ = ["ProjectScope"]


@dataclass(frozen=True, slots=True)
class ProjectScope:
    """A resolved, server-derived scope: who is calling, on behalf of what, in which project.

    Frozen because a scope that can be mutated after resolution is a scope that
    can be widened after the authentication check has already passed.
    """

    project_id: ProjectId
    agent_type_id: AgentTypeId
    principal_id: PrincipalId

    def __repr__(self) -> str:
        # Scopes land in log lines and error paths. Keep them readable but do not
        # invent a shorter form that could be mistaken for a bare project id.
        return (
            f"ProjectScope(project={self.project_id}, "
            f"agent_type={self.agent_type_id}, principal={self.principal_id})"
        )
