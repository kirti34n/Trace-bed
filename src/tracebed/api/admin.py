"""`/admin/*` and `/export/project` (PHASE0-CONTRACT.md §9.3).

Two different auth planes on purpose (C-02/C-20):

- `POST /admin/projects` and `POST /admin/agents/register` are the registry
  WRITE path — they authenticate with the static bootstrap `X-Admin-Key`
  (`api.deps.require_admin_key`) because no `agent_registration` row can
  exist yet for the caller they are about to create one for.
- `GET /admin/memory/{memory_id}` and `GET /export/project` are ordinary
  project-scoped READS — they authenticate like every `/v1/*` route
  (`api.deps.get_scope`) and are therefore automatically confined to the
  caller's own project by the same `ProjectScope` mechanism, which is why
  leak-suite probe 3 (cross-project admin read) gets the uniform 404, not a
  privileged bypass.
"""

from __future__ import annotations

import json
import secrets
from collections.abc import Iterator
from datetime import timedelta
from typing import Annotated, Any, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse

from tracebed.api.deps import AppDeps, AppDepsDep, ControlPlaneReadPort, ScopeDep, require_admin_key
from tracebed.api.models import (
    AgentRegisteredOut,
    ConfigOut,
    InvalidationEventOut,
    InvalidationListOut,
    KillswitchCellOut,
    KillswitchStateOut,
    MemoryItemOut,
    MemoryListOut,
    OidcPrincipalIn,
    ProjectCreatedOut,
    ProjectCreateIn,
    RegisterAgentIn,
    ReviewItemOut,
    ReviewQueueOut,
    ScopeOut,
    SpendCellOut,
    SpendOut,
)
from tracebed.domain.canonical import sha256_hex
from tracebed.domain.errors import ConfigError
from tracebed.domain.ids import MemoryId, ProjectId
from tracebed.domain.state_machine import Status
from tracebed.stores.pg.rows import MemoryItemRow

__all__ = ["router"]

router = APIRouter()

# Every control-plane list route (D-093) is bounded at the wire as well as in
# `Repo._bounded_limit`. Two ceilings for one value is not redundancy: the repo's
# protects the database from any caller, this one lets a 422 tell a dashboard
# author they asked for more than the route will ever give, instead of silently
# handing back a smaller page they might read as "that is all there is".
_MAX_LIST_LIMIT = 1_000
_MAX_SPEND_DAYS = 365

# C-19: key_id is a server-minted UUID hex (32 lowercase hex chars, no
# dashes) — distinct in shape from an OIDC `sub`, which an IdP controls.
_API_KEY_PREFIX = "tb_sk_"
_API_KEY_SECRET_BYTES = 32  # secrets.token_urlsafe(32) -> 43 chars (C-19)


def _mint_api_key() -> tuple[str, str, str]:
    """Returns (key_id, secret, key_hash). Only `key_hash` is ever persisted;
    the caller returns `secret` to the admin exactly once, in the response
    body, and Tracebed never stores or logs it again."""
    key_id = secrets.token_hex(16)  # 32 hex chars — a UUIDv4-shaped public id
    secret = secrets.token_urlsafe(_API_KEY_SECRET_BYTES)
    return key_id, secret, sha256_hex(secret.encode("utf-8"))


@router.post(
    "/admin/projects",
    response_model=ProjectCreatedOut,
    status_code=201,
    dependencies=[Depends(require_admin_key)],
)
def create_project(body: ProjectCreateIn, deps: AppDepsDep) -> ProjectCreatedOut:
    """Registry row + partitions + the project's `"__project__"` KEK (C-14),
    composed here rather than inside `Repo` — `Repo` only ever writes the
    registry row; provisioning storage and crypto material is this route's
    job (contract §9.3), through `AppDeps.partitions`/`AppDeps.keys`.
    """
    project_id = deps.admin.create_project(body.name, body.retention_policy)
    deps.partitions.create_project_partitions(project_id)
    deps.keys.ensure_project_kek(project_id)
    return ProjectCreatedOut(project_id=project_id.value)


@router.post(
    "/admin/agents/register",
    response_model=AgentRegisteredOut,
    status_code=201,
    dependencies=[Depends(require_admin_key)],
)
def register_agent(body: RegisterAgentIn, deps: AppDepsDep) -> AgentRegisteredOut:
    """Creates the agent_type, the principal, and the binding that makes
    `Repo.resolve_project` possible at all (contract §9.3) — as ONE registry
    transaction (C-30), not three composed calls.

    The plaintext api key is minted here and never leaves this function except
    in the response body; if `create_agent_registration` raises, the
    `key_hash` it would have stored is rolled back with everything else, so a
    failed registration cannot deposit a credential nobody holds.
    """
    project_id = ProjectId(body.project_id)

    if isinstance(body.principal, OidcPrincipalIn):
        # `sub` is `str` here by the parsed type itself (models.py's
        # discriminated union) — no runtime assertion stands between a
        # malformed body and a NULL external_ref in the registry.
        external_ref = body.principal.sub
        kind: Literal["oidc_sub", "api_key"] = "oidc_sub"
        key_hash: str | None = None
        api_key: str | None = None
    else:
        key_id, secret, key_hash = _mint_api_key()
        external_ref, kind = key_id, "api_key"
        api_key = f"{_API_KEY_PREFIX}{key_id}.{secret}"

    principal_id, agent_type_id = deps.admin.create_agent_registration(
        project_id, body.agent_type, kind, external_ref, key_hash
    )
    return AgentRegisteredOut(
        principal_id=principal_id.value,
        agent_type_id=agent_type_id.value,
        api_key=api_key,
    )


@router.get("/admin/memory/{memory_id}")
def get_memory(memory_id: UUID, scope: ScopeDep, deps: AppDepsDep) -> dict[str, Any]:
    """`NotFound` (raised uniformly for "absent" and "not your project" by
    `Repo.get_memory_by_id`, contract §5.1) is caught by `api/main.py`'s
    single exception handler and turned into the byte-identical 404 body —
    this handler does not special-case either miss reason itself."""
    row: MemoryItemRow = deps.memory_reader.get_memory_by_id(
        scope.project_id, MemoryId(memory_id)
    )
    return _memory_item_out(row).model_dump()


def _memory_item_out(row: MemoryItemRow) -> MemoryItemOut:
    return MemoryItemOut(
        id=str(row.id),
        project_id=str(row.project_id),
        scope_type=row.scope_type.value,
        scope_id=str(row.scope_id) if row.scope_id is not None else None,
        mem_type=row.mem_type.value,
        kind=row.kind,
        lane=row.lane.value,
        trust_tier=row.trust_tier.value,
        status=row.status.value,
        content=row.content,
        content_hash=row.content_hash,
        token_count=row.token_count,
        subject_tag=row.subject_tag,
        q_value=row.q_value,
        confidence=row.confidence,
        scored_use_count=row.scored_use_count,
        strike_count=row.strike_count,
        provenance=row.provenance.to_json(),
        scan_verdict_id=str(row.scan_verdict_id),
        schema_version=row.schema_version,
        created_at=row.created_at.isoformat(),
        status_changed_at=row.status_changed_at.isoformat()
        if row.status_changed_at is not None
        else None,
    )


# --------------------------------------------------------------------------- #
# Control-plane reads (D-093). Same auth plane as `GET /admin/memory/{id}`:
# ordinary project-scoped reads through `ScopeDep`, so leak-suite probe 3
# (cross-project admin read) covers them by construction — none of them accepts
# a project id in any position, and none of them can widen its own scope.
#
# All READ-ONLY. `killswitch_state` has no write route here on purpose: PLAN.md
# §10 forbids changing a memory's status outside the state machine and forbids
# an admin bypass in code, and a kill-switch override is a governing write whose
# authorship (`evidence["source"]`) belongs to `workers.killswitch`, not to a
# route a dashboard can reach.
# --------------------------------------------------------------------------- #


def _control_plane(deps: AppDeps) -> ControlPlaneReadPort:
    """Fail closed when the deployment wired no control-plane reader.

    `ConfigError` is a `TracebedError`, so `api/main.py`'s fallback handler
    turns this into an opaque 500. That is the point: returning an empty list
    would render as "this project has nothing in its review queue", which is a
    governance claim the server has not made.
    """
    port = deps.control_plane
    if port is None:
        raise ConfigError("no control-plane reader is configured on this deployment")
    return port


@router.get("/admin/whoami", response_model=ScopeOut)
def whoami(scope: ScopeDep) -> ScopeOut:
    """The scope the server derived for the presented credential.

    Its absence is why the dashboard previously could not name the project it
    was looking at, and why an operator holding two credentials had no way to
    tell which one was live. Reporting the derived scope back is the inverse of
    accepting one (invariant 4) — nothing here is read off the request.
    """
    return ScopeOut(
        project_id=str(scope.project_id),
        agent_type_id=str(scope.agent_type_id),
        principal_id=str(scope.principal_id),
    )


@router.get("/admin/memory", response_model=MemoryListOut)
def list_memory(
    scope: ScopeDep,
    deps: AppDepsDep,
    status: Annotated[list[Status] | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=_MAX_LIST_LIMIT)] = 100,
) -> MemoryListOut:
    """A bounded, status-filtered page of this project's `memory_item` rows.

    `status` is typed as the `Status` enum, so an unknown value is a 422 rather
    than a filter that silently matches nothing — the difference between "there
    are no quarantined items" and "you spelled quarantined wrong" is exactly the
    difference an operator cannot afford to miss on this table.

    Repeating `?status=` narrows; omitting it entirely returns every status,
    including the non-retrievable ones. That is deliberate: the vault view's job
    is to show what the hot path CANNOT serve as prominently as what it can.
    """
    rows = _control_plane(deps).list_memories(
        scope.project_id, statuses=status, limit=limit
    )
    return MemoryListOut(
        items=[_memory_item_out(r) for r in rows], limit=limit, returned=len(rows)
    )


@router.get("/admin/review_queue", response_model=ReviewQueueOut)
def list_review_queue(
    scope: ScopeDep,
    deps: AppDepsDep,
    include_resolved: bool = False,
    limit: Annotated[int, Query(ge=1, le=_MAX_LIST_LIMIT)] = 100,
) -> ReviewQueueOut:
    """Open `review_queue` items (add `?include_resolved=true` for history).

    Read-only. Resolving an item is a state-machine transition on the memory it
    points at (PLAN.md §5's table), not an edit to this row, so there is no
    resolve endpoint here to hand a dashboard a shortcut around the machine.
    """
    rows = _control_plane(deps).list_review_items(
        scope.project_id, include_resolved=include_resolved, limit=limit
    )
    return ReviewQueueOut(
        items=[
            ReviewItemOut(
                item_id=str(r.item_id),
                reason=r.reason,
                memory_id=str(r.memory_id) if r.memory_id is not None else None,
                opened_at=r.opened_at.isoformat(),
                resolved_at=r.resolved_at.isoformat() if r.resolved_at is not None else None,
                resolution=r.resolution,
            )
            for r in rows
        ],
        limit=limit,
        returned=len(rows),
        include_resolved=include_resolved,
    )


@router.get("/admin/killswitch_state", response_model=KillswitchStateOut)
def get_killswitch_state(scope: ScopeDep, deps: AppDepsDep) -> KillswitchStateOut:
    """Every recorded kill-switch decision for this project, newest first.

    An empty list means no decision has ever been recorded — NOT that everything
    is enabled. `workers.killswitch` writes a row only when it acts, and PLAN.md
    §7's Phase 3 note records that no `Repo.write_killswitch_state` exists yet,
    so on this build the list is empty by construction. The dashboard says so.
    """
    cells = _control_plane(deps).list_killswitch_state(scope.project_id)
    return KillswitchStateOut(
        cells=[
            KillswitchCellOut(
                agent_type_id=str(c.agent_type_id) if c.agent_type_id is not None else None,
                mem_type=c.mem_type.value,
                disabled=c.disabled,
                evidence=dict(c.evidence) if c.evidence is not None else None,
                changed_at=c.changed_at.isoformat(),
            )
            for c in cells
        ]
    )


@router.get("/admin/invalidations", response_model=InvalidationListOut)
def list_invalidations(
    scope: ScopeDep,
    deps: AppDepsDep,
    limit: Annotated[int, Query(ge=1, le=_MAX_LIST_LIMIT)] = 100,
) -> InvalidationListOut:
    """`invalidation_event` rows, newest first — what `POST /v1/invalidation`
    and the platform webhooks have fired."""
    rows = _control_plane(deps).list_invalidation_events(scope.project_id, limit=limit)
    return InvalidationListOut(
        events=[
            InvalidationEventOut(
                event_id=str(r.event_id),
                event_type=r.event_type,
                selector=dict(r.selector) if r.selector is not None else None,
                fired_at=r.fired_at.isoformat(),
            )
            for r in rows
        ],
        limit=limit,
        returned=len(rows),
    )


@router.get("/admin/spend", response_model=SpendOut)
def get_spend(
    scope: ScopeDep,
    deps: AppDepsDep,
    days: Annotated[int, Query(ge=1, le=_MAX_SPEND_DAYS)] = 30,
) -> SpendOut:
    """This project's `spend_ledger` cells for the last `days` days.

    Single-project by construction, like every other route here. PLAN.md §10
    exempts spend/token/latency metering from the cross-project aggregation ban
    as billing metadata — but that exemption belongs to a billing rollup job, not
    to a route the dashboard calls, so this one does not take it.
    """
    since = (deps.clock.now() - timedelta(days=days - 1)).date()
    cells = _control_plane(deps).spend_since(scope.project_id, since)
    return SpendOut(
        since=since.isoformat(),
        days=days,
        cells=[
            SpendCellOut(
                day=c.day.isoformat(),
                worker=c.worker,
                model_id=c.model_id,
                tokens_in=c.tokens_in,
                tokens_out=c.tokens_out,
                cost_usd=c.cost_usd,
            )
            for c in cells
        ],
    )


@router.get("/admin/config", response_model=ConfigOut)
def get_config(scope: ScopeDep, deps: AppDepsDep) -> ConfigOut:
    """The stored `project_config` and `agent_type_config` OVERRIDE layers for
    the caller's own scope (PLAN.md §6's middle two resolution layers).

    Not the resolved config: process defaults live in the server's environment
    and are not this project's data. A route that merged them would report a
    server-wide value as a project setting.
    """
    port = _control_plane(deps)
    return ConfigOut(
        agent_type_id=str(scope.agent_type_id),
        project=dict(port.get_project_config(scope.project_id)),
        agent_type=dict(port.get_agent_type_config(scope.project_id, scope.agent_type_id)),
    )


@router.get("/export/project")
def export_project(scope: ScopeDep, deps: AppDepsDep) -> StreamingResponse:
    """NDJSON stream of `iter_export_rows(scope.project_id)` — single-project
    by construction (contract §9.3), since `scope.project_id` is server-
    derived and every row `Repo.iter_export_rows` yields is already scoped
    by the same RLS GUC every other partitioned-table read uses.
    """
    def _lines() -> Iterator[bytes]:
        for row in deps.exporter.iter_export_rows(scope.project_id):
            yield json.dumps(row, sort_keys=True).encode("utf-8") + b"\n"

    return StreamingResponse(_lines(), media_type="application/x-ndjson")
