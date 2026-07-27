"""PHASE-0 Task 7 / PLAN.md §2 invariant 4: project isolation at query construction.

- `test_no_public_builder_missing_project_id` is the source-level test PHASE-0.md Task 7 asks
  for: it introspects every public `Repo` method's signature with `inspect` (never grep) and
  asserts `project_id` is the first parameter after `self`, with `REGISTRY_METHODS_WITHOUT_PROJECT_ID`
  as the only allowed exception. Pure, offline, no database.
- `test_cross_project_fetch_is_indistinguishable_from_absent` is the integration counterpart of
  leak-suite probe 2 (PLAN.md §2 invariant 4 / contract Task 17): fetching another project's
  memory by id must raise the exact same `NotFound` as fetching an id that never existed.
"""

from __future__ import annotations

import inspect
from typing import Any

import pytest

from tracebed.core.scans import ScanContext, scan
from tracebed.domain.enums import Lane, MemType, ProvenanceClass, ScopeType, TrustTier
from tracebed.domain.errors import NotFound
from tracebed.domain.ids import ProjectId, mint_memory_id, mint_run_id
from tracebed.domain.memory import NewMemoryItem, Provenance
from tracebed.domain.state_machine import Status
from tracebed.stores.pg.repo import REGISTRY_METHODS_WITHOUT_PROJECT_ID, Repo

pytestmark = pytest.mark.phase0


def _public_methods() -> list[tuple[str, Any]]:
    return [
        (name, member)
        for name, member in inspect.getmembers(Repo, predicate=inspect.isfunction)
        if not name.startswith("_")
    ]


def _require_fixture(request: pytest.FixtureRequest, name: str) -> Any:
    """Resolve an integration fixture, or skip.

    `repo` / `two_projects` live in `tests/phase0/conftest.py`, which contract §13.1 assigns to
    chunk `harness` and which does not exist yet. Requesting them as ordinary parameters turns
    "the harness has not landed" into a fixture-lookup ERROR that reddens the Phase 0 gate for a
    reason unrelated to this chunk; §12 requires integration tests to SKIP cleanly when their
    service (or, here, their fixture surface) is absent.
    """
    try:
        return request.getfixturevalue(name)
    except pytest.FixtureLookupError:
        pytest.skip(f"fixture {name!r} unavailable (tests/phase0/conftest.py, owner: harness)")


def test_registry_allowlist_has_exactly_the_six_contract_methods() -> None:
    """Pins the allowlist itself to contract §5.1's exact wording, so a drift in either
    direction (someone widening it, or someone forgetting to widen it for a new registry
    method) is caught here rather than downstream.
    """
    assert frozenset(
        {
            "resolve_project",
            "create_project",
            "create_principal",
            "get_principal_by_external_ref",
            "list_project_ids",
            "record_embedding_model",
        }
    ) == REGISTRY_METHODS_WITHOUT_PROJECT_ID


def test_no_public_builder_missing_project_id() -> None:
    """Every public `Repo` method not in the registry allowlist takes `project_id` as its first
    parameter after `self`. Introspection, not grep -- PHASE-0.md Task 7's explicit requirement.
    """
    methods = _public_methods()
    assert methods, "Repo exposes no public methods -- introspection found nothing to check"

    violations: list[str] = []
    mistyped: list[str] = []
    positional = (
        inspect.Parameter.POSITIONAL_ONLY,
        inspect.Parameter.POSITIONAL_OR_KEYWORD,
    )
    for name, member in methods:
        params = list(inspect.signature(member).parameters.values())
        assert params and params[0].name == "self", f"Repo.{name} is not a bound instance method"

        if name in REGISTRY_METHODS_WITHOUT_PROJECT_ID:
            continue

        if len(params) < 2 or params[1].name != "project_id":
            violations.append(name)
            continue

        # The NAME `project_id` is not the control -- the TYPE is (PLAN.md §5: "Every query
        # builder takes ProjectId (a newtype; no scope-less constructor is exported)"). A
        # `project_id: str` or `project_id: UUID` parameter satisfies the name check while
        # accepting exactly the caller-asserted scope invariant 4 forbids, and mypy would no
        # longer object. `from __future__ import annotations` makes these strings.
        annotation = params[1].annotation
        if annotation is not ProjectId and str(annotation) != "ProjectId":
            mistyped.append(f"{name}: {annotation!r}")
        if params[1].kind not in positional:
            violations.append(f"{name} (project_id is not positional)")
        if params[1].default is not inspect.Parameter.empty:
            violations.append(f"{name} (project_id has a default)")

    assert not violations, (
        "Repo methods missing project_id as their first positional, non-defaulted parameter "
        f"and not in REGISTRY_METHODS_WITHOUT_PROJECT_ID: {violations}"
    )
    assert not mistyped, (
        "Repo methods whose first parameter is named project_id but is not the ProjectId "
        f"newtype -- a bare str/UUID reopens caller-asserted scope: {mistyped}"
    )


def test_registry_allowlist_methods_exist_on_repo() -> None:
    """The allowlist names real methods -- a typo'd entry would silently exempt nothing."""
    public_names = {name for name, _ in _public_methods()}
    missing = REGISTRY_METHODS_WITHOUT_PROJECT_ID - public_names
    assert not missing, f"allowlist names methods Repo does not define: {missing}"


def _new_memory_item() -> NewMemoryItem:
    provenance = Provenance(cls=ProvenanceClass.PARSER, trace_ids=(mint_run_id(),))
    return NewMemoryItem(
        scope_type=ScopeType.PROJECT_SHARED,
        scope_id=None,
        mem_type=MemType.LESSON,
        kind="test-kind",
        lane=Lane.OPERATIONAL,
        trust_tier=TrustTier.A,
        status=Status.CANDIDATE,
        content="the retry budget for tool X is 3 attempts with jittered backoff",
        token_count=14,
        provenance=provenance,
        id=mint_memory_id(),
    )


@pytest.mark.integration
def test_cross_project_fetch_is_indistinguishable_from_absent(
    request: pytest.FixtureRequest,
) -> None:
    """Leak-suite probe 2: by-id fetch of another project's row, and fetch of an id that never
    existed at all, must be the *same* `NotFound` -- same exception type, same message, and the
    same repr. A distinguishable error shape is itself an oracle (contract Task 17): "this id
    exists but is not yours" is exactly the bit an enumerator wants.
    """
    repo = _require_fixture(request, "repo")
    scope_a, scope_b = _require_fixture(request, "two_projects")

    never_existed_id = mint_memory_id()
    with pytest.raises(NotFound) as absent_exc:
        repo.get_memory_by_id(scope_a.project_id, never_existed_id)

    # A real row, owned by project B.
    item = _new_memory_item()
    verdict = scan(
        item.content,
        context=ScanContext(
            project_id=scope_b.project_id,
            mem_type=item.mem_type,
            trust_tier=item.trust_tier,
            provenance_class=item.provenance.cls,
            lane=Lane.OPERATIONAL,
        ),
    ).verdict()
    b_memory_id = repo.insert_memory_item(scope_b.project_id, item, verdict)

    with pytest.raises(NotFound) as cross_exc:
        repo.get_memory_by_id(scope_a.project_id, b_memory_id)

    assert str(absent_exc.value) == str(cross_exc.value)
    assert repr(absent_exc.value) == repr(cross_exc.value)
    assert type(absent_exc.value) is type(cross_exc.value)

    # Sanity: the row genuinely exists for its own project (isolates "wrong-project 404" from
    # "insert silently failed" -- without this the test passes when nothing was ever written).
    fetched = repo.get_memory_by_id(scope_b.project_id, b_memory_id)
    assert fetched.id == b_memory_id

    # And project A cannot see it in a LIST either -- probe 2 covers by-id, but a by-id 404
    # beside a leaking list is not isolation.
    assert all(row.id != b_memory_id for row in repo.list_memories(scope_a.project_id))


@pytest.mark.integration
def test_cross_project_trace_fetch_is_indistinguishable_from_absent(
    request: pytest.FixtureRequest,
) -> None:
    """The same probe on the other by-id surface named in invariant 4 ("by-id fetch of another
    project's memory/trace"). `get_trace_index` had no leak test at all.
    """
    repo = _require_fixture(request, "repo")
    scope_a, scope_b = _require_fixture(request, "two_projects")

    with pytest.raises(NotFound) as absent_exc:
        repo.get_trace_index(scope_a.project_id, mint_run_id())
    with pytest.raises(NotFound) as cross_exc:
        repo.get_trace_index(scope_b.project_id, mint_run_id())
    assert str(absent_exc.value) == str(cross_exc.value)
    assert type(absent_exc.value) is type(cross_exc.value)
