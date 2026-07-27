"""PHASE-0 Task 7 / PLAN.md §2 invariant 6: provenance-complete-or-rejected.

Two layers, matching the split the contract mandates (§5.1, §12):

- `test_validate_provenance_matrix` is pure and offline: it exercises
  `tracebed.domain.memory.validate_provenance` (owner: domain-events-scan) exhaustively over
  every `ProvenanceClass` x its required field, with no database. This is the half of invariant 6
  that must run on a machine with no Postgres.
- `test_insert_memory_item_rejects_incomplete_provenance` is the integration half: it proves the
  repository actually calls that pure function before writing anything, and that after a
  rejection the row genuinely does not exist (not just that an exception was raised).
"""

from __future__ import annotations

from typing import Any

import pytest

from tracebed.domain.enums import Lane, MemType, ProvenanceClass, ScopeType, TrustTier
from tracebed.domain.errors import NotFound, ProvenanceIncomplete
from tracebed.domain.ids import PrincipalId, mint_memory_id, mint_run_id
from tracebed.domain.memory import NewMemoryItem, Provenance, validate_provenance
from tracebed.domain.state_machine import Status

pytestmark = pytest.mark.phase0

# The exact required-field matrix from PHASE0-CONTRACT.md §3.6 / PLAN.md §2 invariant 6.
_REQUIRED_FIELD_BY_CLASS: dict[ProvenanceClass, str] = {
    ProvenanceClass.PARSER: "trace_ids",
    ProvenanceClass.DISTILLER: "trace_ids",
    ProvenanceClass.HUMAN_VERDICT: "verdict_id",
    ProvenanceClass.PROPOSAL: "run_id",
    ProvenanceClass.OPERATOR: "principal",
}


def _satisfying_value(field: str) -> Any:
    """A minimal value that satisfies `field`'s presence requirement."""
    if field == "trace_ids":
        return (mint_run_id(),)
    if field == "verdict_id":
        from uuid import uuid4

        return uuid4()
    if field == "run_id":
        return mint_run_id()
    if field == "principal":
        from uuid import uuid4

        return PrincipalId(uuid4())
    raise AssertionError(f"unhandled field {field!r}")  # pragma: no cover - matrix guard


def _bare_provenance(cls: ProvenanceClass, **overrides: Any) -> Provenance:
    """A `Provenance` for `cls` with every optional field at its empty/absent default, then
    `overrides` applied -- the minimal instance needed to isolate exactly one required field.
    """
    fields: dict[str, Any] = {
        "cls": cls,
        "trace_ids": (),
        "verdict_id": None,
        "tool_refs": (),
        "input_sig_hashes": (),
        "run_id": None,
        "principal": None,
    }
    fields.update(overrides)
    return Provenance(**fields)


@pytest.mark.parametrize("cls", sorted(ProvenanceClass, key=lambda c: c.value))
def test_validate_provenance_rejects_missing_required_field(cls: ProvenanceClass) -> None:
    """Every class with all-empty optional fields is incomplete -- this is the row that must
    never reach the database (PLAN.md §2 invariant 6's own test description).
    """
    provenance = _bare_provenance(cls)
    with pytest.raises(ProvenanceIncomplete):
        validate_provenance(provenance)


@pytest.mark.parametrize("cls", sorted(ProvenanceClass, key=lambda c: c.value))
def test_validate_provenance_accepts_required_field_present(cls: ProvenanceClass) -> None:
    """Supplying exactly the one required field for each class is sufficient -- proves the guard
    isn't accidentally requiring more than the contract's matrix.
    """
    field = _REQUIRED_FIELD_BY_CLASS[cls]
    provenance = _bare_provenance(cls, **{field: _satisfying_value(field)})
    validate_provenance(provenance)  # must not raise


def test_validate_provenance_matrix_is_exhaustive_over_provenance_class() -> None:
    """Guards against a new `ProvenanceClass` member landing without a matrix entry -- silently
    treating an unknown class as "no requirement" would be an invariant-6 hole.
    """
    assert set(_REQUIRED_FIELD_BY_CLASS) == set(ProvenanceClass)


@pytest.mark.parametrize(
    ("cls", "other_field"),
    [
        (ProvenanceClass.PARSER, "verdict_id"),
        (ProvenanceClass.DISTILLER, "run_id"),
        (ProvenanceClass.HUMAN_VERDICT, "trace_ids"),
        (ProvenanceClass.PROPOSAL, "trace_ids"),
        (ProvenanceClass.OPERATOR, "verdict_id"),
    ],
)
def test_validate_provenance_rejects_wrong_field_populated(
    cls: ProvenanceClass, other_field: str
) -> None:
    """Populating a *different* class's required field must not satisfy this class's guard --
    the matrix is per-class, not "any provenance field present"."""
    provenance = _bare_provenance(cls, **{other_field: _satisfying_value(other_field)})
    with pytest.raises(ProvenanceIncomplete):
        validate_provenance(provenance)


# --------------------------------------------------------------------------------------- #
# Integration half: the repository actually enforces this, and the row is genuinely absent.
# --------------------------------------------------------------------------------------- #


def _new_memory_item(*, provenance: Provenance, memory_id: Any) -> NewMemoryItem:
    return NewMemoryItem(
        scope_type=ScopeType.PROJECT_SHARED,
        scope_id=None,
        mem_type=MemType.LESSON,
        kind="test-kind",
        lane=Lane.OPERATIONAL,
        trust_tier=TrustTier.A,
        status=Status.CANDIDATE,
        content="the tool times out after 30s when the upstream host is unreachable",
        token_count=12,
        provenance=provenance,
        id=memory_id,
    )


def _require_fixture(request: pytest.FixtureRequest, name: str) -> Any:
    """Resolve an integration fixture, or skip cleanly.

    `repo` / `two_projects` come from `tests/phase0/conftest.py` (contract §13.1, owner:
    `harness`), which does not exist yet. Taking them as plain parameters turns a missing
    harness into a fixture-lookup ERROR rather than the SKIP §12 requires.
    """
    try:
        return request.getfixturevalue(name)
    except pytest.FixtureLookupError:
        pytest.skip(f"fixture {name!r} unavailable (tests/phase0/conftest.py, owner: harness)")


@pytest.mark.integration
def test_insert_memory_item_rejects_incomplete_provenance_and_row_stays_absent(
    request: pytest.FixtureRequest,
) -> None:
    """`Repo.insert_memory_item` runs `validate_provenance` before touching the database
    (contract §5.1's fixed order) -- proves both the exception and that no row was written.
    """
    repo = _require_fixture(request, "repo")
    scope_a, _scope_b = _require_fixture(request, "two_projects")
    memory_id = mint_memory_id()
    # PARSER requires trace_ids; leave it empty to trigger ProvenanceIncomplete.
    incomplete = _bare_provenance(ProvenanceClass.PARSER)
    item = _new_memory_item(provenance=incomplete, memory_id=memory_id)

    with pytest.raises(ProvenanceIncomplete):
        # scan_verdict is never reached: validate_provenance raises first (contract order).
        repo.insert_memory_item(scope_a.project_id, item, scan_verdict=None)  # type: ignore[arg-type]

    with pytest.raises(NotFound):
        repo.get_memory_by_id(scope_a.project_id, memory_id)


@pytest.mark.integration
@pytest.mark.parametrize("cls", sorted(ProvenanceClass, key=lambda c: c.value))
def test_insert_memory_item_provenance_matrix_against_real_db(
    request: pytest.FixtureRequest, cls: ProvenanceClass
) -> None:
    """The full matrix, but through the repository instead of the pure function -- the
    integration counterpart of `test_validate_provenance_rejects_missing_required_field`."""
    repo = _require_fixture(request, "repo")
    scope_a, _scope_b = _require_fixture(request, "two_projects")
    memory_id = mint_memory_id()
    item = _new_memory_item(provenance=_bare_provenance(cls), memory_id=memory_id)

    with pytest.raises(ProvenanceIncomplete):
        repo.insert_memory_item(scope_a.project_id, item, scan_verdict=None)  # type: ignore[arg-type]

    with pytest.raises(NotFound):
        repo.get_memory_by_id(scope_a.project_id, memory_id)
