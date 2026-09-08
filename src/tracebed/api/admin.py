"""Authority-gated project-admin read routes and project export."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import StreamingResponse

from tracebed.api.deps import (
    AdminReadDep,
    AnyRoleDep,
    AppDeps,
    AppDepsDep,
    ControlPlaneReadPort,
    ExportDep,
)
from tracebed.api.models import (
    ConfigOut,
    InvalidationEventOut,
    InvalidationListOut,
    KillswitchCellOut,
    KillswitchStateOut,
    MemoryItemOut,
    MemoryListOut,
    ReviewItemOut,
    ReviewQueueOut,
    ScopeOut,
    SpendCellOut,
    SpendOut,
)
from tracebed.domain.enums import ProjectRole
from tracebed.domain.errors import ConfigError
from tracebed.domain.ids import MemoryId
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
_MAX_MEMORY_LIMIT = 200
_MAX_SPEND_DAYS = 365
_MEMORY_CURSOR_MAX_BYTES = 1024


class MemoryCursorSigner:
    """Purpose-derived cursor MAC key; never serialises its master material."""

    __slots__ = ("_key",)

    def __init__(self, master_key: bytes) -> None:
        if type(master_key) is not bytes or len(master_key) != 32:
            raise ValueError("memory cursor master key is invalid")
        self._key = hmac.new(
            master_key, b"tracebed/admin-memory-cursor/v1", hashlib.sha256
        ).digest()

    def sign(self, raw: bytes) -> bytes:
        return hmac.new(self._key, raw, hashlib.sha256).digest()


@router.get("/admin/memory/{memory_id}")
def get_memory(memory_id: UUID, access: AdminReadDep, deps: AppDepsDep) -> dict[str, Any]:
    """`NotFound` (raised uniformly for "absent" and "not your project" by
    `Repo.get_memory_by_id`, contract §5.1) is caught by `api/main.py`'s
    single exception handler and turned into the byte-identical 404 body —
    this handler does not special-case either miss reason itself."""
    row: MemoryItemRow = deps.memory_reader.get_memory_by_id(
        access.project_id, MemoryId(memory_id)
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


def _memory_filter(statuses: list[Status] | None) -> tuple[str, ...]:
    return tuple(sorted({status.value for status in statuses or ()}))


def _cursor_encode(
    signer: MemoryCursorSigner,
    *,
    project_id: UUID,
    statuses: tuple[str, ...],
    created_at: datetime,
    memory_id: UUID,
) -> str:
    payload = {
        "v": 1,
        "p": str(project_id),
        "s": list(statuses),
        "c": created_at.astimezone(UTC).isoformat(),
        "i": str(memory_id),
    }
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    signature = signer.sign(raw)
    return base64.urlsafe_b64encode(raw + signature).rstrip(b"=").decode("ascii")


def _cursor_decode(
    value: str, signer: MemoryCursorSigner, *, project_id: UUID, statuses: tuple[str, ...]
) -> tuple[datetime, MemoryId]:
    try:
        if len(value.encode("ascii")) > _MEMORY_CURSOR_MAX_BYTES:
            raise ValueError
        padded = value + "=" * (-len(value) % 4)
        decoded = base64.urlsafe_b64decode(padded.encode("ascii"))
        if len(decoded) <= hashlib.sha256().digest_size:
            raise ValueError
        raw, supplied_signature = decoded[:-32], decoded[-32:]
        expected_signature = signer.sign(raw)
        if not hmac.compare_digest(supplied_signature, expected_signature):
            raise ValueError
        payload = json.loads(raw)
        if not isinstance(payload, dict) or set(payload) != {"v", "p", "s", "c", "i"}:
            raise ValueError
        if payload["v"] != 1 or payload["p"] != str(project_id) or payload["s"] != list(statuses):
            raise ValueError
        created_at = datetime.fromisoformat(payload["c"])
        memory_id = UUID(payload["i"])
        if created_at.tzinfo is None:
            raise ValueError
        return created_at, MemoryId(memory_id)
    except (TypeError, ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=422, detail="invalid memory cursor") from exc


# --------------------------------------------------------------------------- #
# Control-plane reads require the ADMIN grant. None accepts a project id, so a
# caller cannot widen the server-resolved access context.
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
def whoami(access: AnyRoleDep) -> ScopeOut:
    """The scope the server derived for the presented credential.

    Its absence is why the dashboard previously could not name the project it
    was looking at, and why an operator holding two credentials had no way to
    tell which one was live. Reporting the derived scope back is the inverse of
    accepting one (invariant 4) — nothing here is read off the request.
    """
    return ScopeOut(
        project_id=str(access.project_id),
        agent_type_id=str(access.agent_type_id),
        principal_id=str(access.principal_id),
    )


@router.get("/admin/memory", response_model=MemoryListOut)
def list_memory(
    request: Request,
    access: AdminReadDep,
    deps: AppDepsDep,
    status: Annotated[list[Status] | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=_MAX_MEMORY_LIMIT)] = 100,
    cursor: Annotated[str | None, Query(max_length=_MEMORY_CURSOR_MAX_BYTES)] = None,
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
    normalized_statuses = _memory_filter(status)
    signer = getattr(request.app.state, "memory_cursor_signer", None)
    if not isinstance(signer, MemoryCursorSigner):
        raise ConfigError("memory cursor signer is not configured")
    before_created_at: datetime | None = None
    before_id: MemoryId | None = None
    if cursor is not None:
        before_created_at, before_id = _cursor_decode(
            cursor, signer, project_id=access.project_id.value, statuses=normalized_statuses
        )
    rows = _control_plane(deps).list_memories_page(
        access.project_id,
        statuses=status,
        limit=limit,
        before_created_at=before_created_at,
        before_id=before_id,
    )
    has_more = len(rows) > limit
    items = rows[:limit]
    next_cursor = None
    if has_more:
        last = items[-1]
        next_cursor = _cursor_encode(
            signer,
            project_id=access.project_id.value,
            statuses=normalized_statuses,
            created_at=last.created_at,
            memory_id=last.id.value,
        )
    return MemoryListOut(
        items=[_memory_item_out(row) for row in items], next_cursor=next_cursor
    )


@router.get("/admin/review_queue", response_model=ReviewQueueOut)
def list_review_queue(
    access: AdminReadDep,
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
        access.project_id, include_resolved=include_resolved, limit=limit
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
def get_killswitch_state(access: AdminReadDep, deps: AppDepsDep) -> KillswitchStateOut:
    """Every recorded kill-switch decision for this project, newest first.

    An empty list means no decision has ever been recorded — NOT that everything
    is enabled. `workers.killswitch` writes a row only when it acts, and PLAN.md
    §7's Phase 3 note records that no `Repo.write_killswitch_state` exists yet,
    so on this build the list is empty by construction. The dashboard says so.
    """
    cells = _control_plane(deps).list_killswitch_state(access.project_id)
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
    access: AdminReadDep,
    deps: AppDepsDep,
    limit: Annotated[int, Query(ge=1, le=_MAX_LIST_LIMIT)] = 100,
) -> InvalidationListOut:
    """`invalidation_event` rows, newest first — what `POST /v1/invalidation`
    and the platform webhooks have fired."""
    rows = _control_plane(deps).list_invalidation_events(access.project_id, limit=limit)
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
    access: AdminReadDep,
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
    cells = _control_plane(deps).spend_since(access.project_id, since)
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
def get_config(access: AdminReadDep, deps: AppDepsDep) -> ConfigOut:
    """The stored `project_config` and `agent_type_config` OVERRIDE layers for
    the caller's own scope (PLAN.md §6's middle two resolution layers).

    Not the resolved config: process defaults live in the server's environment
    and are not this project's data. A route that merged them would report a
    server-wide value as a project setting.
    """
    port = _control_plane(deps)
    return ConfigOut(
        agent_type_id=str(access.agent_type_id),
        project=dict(port.get_project_config(access.project_id)),
        agent_type=dict(port.get_agent_type_config(access.project_id, access.agent_type_id)),
    )


@router.get("/export/project")
def export_project(access: ExportDep, deps: AppDepsDep) -> StreamingResponse:
    """NDJSON stream of `iter_export_rows(scope.project_id)` — single-project
    by construction (contract §9.3), since `scope.project_id` is server-
    derived and every row `Repo.iter_export_rows` yields is already scoped
    by the same RLS GUC every other partitioned-table read uses.
    """
    def _lines() -> Iterator[bytes]:
        # This generator owns the shared advisory lock rather than the route
        # handler.  A StreamingResponse starts consuming only after the
        # handler returns; holding it here keeps the exact EXPORT grant,
        # durable fence filters and byte serialization in one disclosure
        # lifetime, including exhaustion, errors and client cancellation.
        if deps.read_gate is None:
            rows = deps.exporter.iter_export_rows(access.project_id)
            for row in rows:
                yield json.dumps(row, sort_keys=True).encode("utf-8") + b"\n"
            return
        with deps.read_gate.hold(access, ProjectRole.EXPORT) as connection:
            # The production repository offers this deliberately private
            # same-transaction hook.  It keeps the durable grant/project
            # locks from the read gate through cursor exhaustion and the last
            # streamed byte; old offline exporters retain the simple port.
            in_lifetime = getattr(deps.exporter, "_iter_export_rows_on", None)
            rows = (
                in_lifetime(connection, access.project_id)
                if callable(in_lifetime)
                else deps.exporter.iter_export_rows(access.project_id)
            )
            for row in rows:
                yield json.dumps(row, sort_keys=True).encode("utf-8") + b"\n"

    return StreamingResponse(_lines(), media_type="application/x-ndjson")
