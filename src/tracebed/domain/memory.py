"""Provenance and NewMemoryItem (PHASE0-CONTRACT.md §3.6).

This module carries the offline half of **invariant 6 — provenance-complete-or-rejected**.
`validate_provenance` is deliberately pure: no database, no I/O, no clock. That
matters because the invariant's proving test is an exhaustive matrix over
(provenance class x missing required field), and a matrix that can only run
against a live Postgres is a matrix that does not run.

The database backstops it — `memory_item.provenance` is `jsonb NOT NULL` and
`scan_verdict_id` is `uuid NOT NULL` — but the repository refuses first, with a
typed error naming the missing field, so the failure is diagnosable rather than
a constraint violation.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
from uuid import UUID

from tracebed.domain.enums import Lane, MemType, ProvenanceClass, ScopeType, TrustTier
from tracebed.domain.errors import ProvenanceIncomplete
from tracebed.domain.ids import MemoryId, PrincipalId, RunId
from tracebed.domain.state_machine import Status, assert_legal_creation_status

__all__ = [
    "REQUIRED_PROVENANCE_FIELDS",
    "NewMemoryItem",
    "Provenance",
    "validate_provenance",
]


# The single source of truth for what "complete provenance" means, per class.
# Read by `validate_provenance`, by the repository's error messages, and by the
# invariant-6 test matrix — so the test cannot drift from the rule it is proving.
REQUIRED_PROVENANCE_FIELDS: Mapping[ProvenanceClass, tuple[str, ...]] = {
    ProvenanceClass.PARSER: ("trace_ids",),
    ProvenanceClass.DISTILLER: ("trace_ids",),
    ProvenanceClass.HUMAN_VERDICT: ("verdict_id",),
    ProvenanceClass.PROPOSAL: ("run_id",),
    ProvenanceClass.OPERATOR: ("principal",),
}


@dataclass(frozen=True, slots=True)
class Provenance:
    """Where a memory item came from, in enough detail to walk back down to raw evidence.

    Every derived memory points at the traces that produced it. That pointer is
    what makes Recall & Rollback forensics possible at all: quarantine an item,
    enumerate the runs it touched, flag its descendants.
    """

    cls: ProvenanceClass
    trace_ids: tuple[RunId, ...] = ()
    verdict_id: UUID | None = None
    tool_refs: tuple[str, ...] = ()
    input_sig_hashes: tuple[bytes, ...] = ()
    run_id: RunId | None = None
    """Set for the PROPOSAL class — the run whose agent proposed this."""
    principal: PrincipalId | None = None
    """Set for the OPERATOR class — the human who created this by hand."""

    def to_json(self) -> dict[str, Any]:
        """The fixed on-disk jsonb shape. Absent optionals are omitted, not null.

        Fixed because §3.6 pins it and because `from_json` on a row written by an
        older build must keep working — this is the persisted representation, not
        a debug dump.
        """
        out: dict[str, Any] = {"class": self.cls.value}
        if self.trace_ids:
            out["trace_ids"] = [str(t) for t in self.trace_ids]
        if self.verdict_id is not None:
            out["verdict_id"] = str(self.verdict_id)
        if self.tool_refs:
            out["tool_refs"] = list(self.tool_refs)
        if self.input_sig_hashes:
            out["input_sig_hashes"] = [h.hex() for h in self.input_sig_hashes]
        if self.run_id is not None:
            out["run_id"] = str(self.run_id)
        if self.principal is not None:
            out["principal"] = str(self.principal)
        return out

    @classmethod
    def from_json(cls, raw: Mapping[str, Any]) -> Provenance:
        """Rehydrate from the jsonb column. Raises on an unknown class rather than guessing."""
        try:
            klass = ProvenanceClass(raw["class"])
        except KeyError as exc:
            raise ProvenanceIncomplete("provenance json has no 'class' key") from exc
        except ValueError as exc:
            raise ProvenanceIncomplete(f"unknown provenance class: {raw.get('class')!r}") from exc

        def _seq(key: str) -> Sequence[Any]:
            value = raw.get(key) or ()
            if isinstance(value, str) or not isinstance(value, Sequence):
                raise ProvenanceIncomplete(f"provenance.{key} must be a list, got {type(value).__name__}")
            return value

        verdict_raw = raw.get("verdict_id")
        run_raw = raw.get("run_id")
        principal_raw = raw.get("principal")

        return cls(
            cls=klass,
            trace_ids=tuple(RunId(str(t)) for t in _seq("trace_ids")),
            verdict_id=UUID(str(verdict_raw)) if verdict_raw is not None else None,
            tool_refs=tuple(str(t) for t in _seq("tool_refs")),
            input_sig_hashes=tuple(bytes.fromhex(str(h)) for h in _seq("input_sig_hashes")),
            run_id=RunId(str(run_raw)) if run_raw is not None else None,
            principal=PrincipalId(str(principal_raw)) if principal_raw is not None else None,
        )


def validate_provenance(p: Provenance) -> None:
    """Raise `ProvenanceIncomplete` unless this class's required fields are present.

    Invariant 6. Pure by construction so the exhaustive rejection matrix runs
    with no database. `Repo.insert_memory_item` calls this before it builds a
    statement; the schema's NOT NULL constraints are the backstop, not the gate.
    """
    required = REQUIRED_PROVENANCE_FIELDS.get(p.cls)
    if required is None:  # pragma: no cover - unreachable while the enum is closed
        raise ProvenanceIncomplete(f"no provenance rule for class {p.cls!r}")

    missing = [name for name in required if _is_absent(getattr(p, name))]
    if missing:
        raise ProvenanceIncomplete(
            f"provenance class {p.cls.value!r} requires {', '.join(required)}; "
            f"missing: {', '.join(missing)}"
        )


def _is_absent(value: object) -> bool:
    """None and empty collections are both 'not provided'.

    An empty `trace_ids` tuple is exactly as unprovenanced as a null one — it
    points at no evidence — so both must fail. Treating `()` as present is how a
    provenance check silently stops checking.
    """
    if value is None:
        return True
    return isinstance(value, (tuple, list, set, frozenset, str, bytes)) and len(value) == 0


@dataclass(frozen=True, slots=True)
class NewMemoryItem:
    """An item on its way into the store, before the repository mints ids and stamps rows.

    `status` is not free: it is whatever `state_machine.apply(None, target, evidence)`
    returned. The repository re-checks that the status is a legal creation status,
    because "the caller already validated it" is not a control.
    """

    scope_type: ScopeType
    scope_id: UUID | None
    """None only for PROJECT_SHARED — every other scope type names its subject."""
    mem_type: MemType
    kind: str
    lane: Lane
    trust_tier: TrustTier
    status: Status
    """Whatever `state_machine.apply(None, target, evidence)` returned — never a
    caller's choice. The repository re-checks it is a legal creation status,
    because "the caller already validated it" is not a control."""
    content: str
    token_count: int
    provenance: Provenance
    subject_tag: str | None = None
    cluster_id: UUID | None = None
    ttl_class: str | None = None
    valid_from: datetime | None = None
    valid_to: datetime | None = None
    schema_version: int = 1
    id: MemoryId | None = None
    """None means the repository mints one via `mint_memory_id()`."""

    extra: Mapping[str, Any] = field(default_factory=dict)
    """Forward-compatible slot for per-mem_type fields the schema check validates."""

    def __post_init__(self) -> None:
        # Invariant 7's creation half, at the type level: an item whose status is not a
        # `(None, X)` target of the transition table cannot be CONSTRUCTED, so no repository
        # implementation -- Postgres, an offline fake, a future driver -- can be handed one.
        # `Repo.insert_memory_item` re-checks the same thing against the same derived set;
        # the two are belt and braces, not duplication, because a caller that builds this
        # object is not always the caller that inserts it.
        assert_legal_creation_status(self.status)
        if self.scope_type is not ScopeType.PROJECT_SHARED and self.scope_id is None:
            raise ValueError(f"scope_type {self.scope_type.value!r} requires a scope_id")
        if self.scope_type is ScopeType.PROJECT_SHARED and self.scope_id is not None:
            raise ValueError("PROJECT_SHARED memory must not carry a scope_id")
        if self.token_count < 0:
            raise ValueError("token_count cannot be negative")
        if not self.content.strip():
            raise ValueError("memory content cannot be empty or whitespace-only")
