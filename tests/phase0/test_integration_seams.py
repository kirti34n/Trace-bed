"""Cross-module seam assertions — the checks no single chunk could make.

Every other module in `tests/phase0/` tests one chunk against its own fakes.
Six chunks were built in parallel against PHASE0-CONTRACT.md without seeing
each other's files, and the defects that survived that process were all of one
shape: two modules agreeing with the contract and disagreeing with each other.
A fake that mirrors the wrong signature stays green forever, so the assertions
here deliberately reach across chunk boundaries and read the REAL objects.

Fully offline (§12): no database, no Valkey, no object store, no network. The
only I/O is reading this repository's own source files.

What is pinned here, and why each one is a seam rather than a unit:

- invariant 4, end to end: no wire model can name a `project_id` on a data
  route; `WorkQueue.enqueue` will not accept anything but a `ProjectId`; the
  consumers scope by the queue ROW's column, never by the envelope body.
- RT-03 / invariant 6: no path reaches a `memory_item` insert without a real
  `ScanVerdict`, and a `ScanVerdict` cannot be minted outside the scan suite.
- hard rule 4: no bare `datetime.now()`/`time.time()`/`utcnow()` in `src/`
  outside `SystemClock`. A single hit makes the Phase 2 soak unrunnable,
  because nothing downstream of it can be replayed deterministically.
- the §13.1 fixture surface: `tests/phase0/conftest.py` calls the real
  constructors with the real arities. As merged it did not, and the `pg` probe
  skipped before the bodies ran, so a five-module ERROR storm was one reachable
  database away.
- constants that are mirrored across a deliberate import boundary
  (`api.models.MAX_SEQ` vs `ingest.trace_writer.MAX_TRACE_SEQ`).
"""

from __future__ import annotations

import ast
import inspect
from pathlib import Path
from typing import Any, Final, get_args, get_type_hints

import pytest

from tracebed.api import admin as admin_routes
from tracebed.api import models as api_models
from tracebed.api import routes_v1
from tracebed.api.deps import AppDeps
from tracebed.domain.ids import ProjectId
from tracebed.ingest.trace_writer import MAX_TRACE_SEQ
from tracebed.stores.pg import pool as pg_pool_module
from tracebed.stores.pg.queue import WorkQueue
from tracebed.stores.pg.repo import Repo, ScopedRepo

pytestmark = pytest.mark.phase0

_REPO_ROOT: Final[Path] = Path(__file__).resolve().parents[2]
_SRC: Final[Path] = _REPO_ROOT / "src" / "tracebed"


def _src_files() -> list[Path]:
    files = sorted(_SRC.rglob("*.py"))
    assert files, f"no source files found under {_SRC} — this test would pass vacuously"
    return files


# --------------------------------------------------------------------------- #
# Invariant 4 — project_id is derived, never accepted.
# --------------------------------------------------------------------------- #


_DATA_ROUTE_MODELS: Final = (
    api_models.RunCtxIn,
    api_models.RetrieveIn,
    api_models.TraceIn,
    api_models.TraceBatchIn,
    api_models.FeedbackIn,
    api_models.ProposeIn,
    api_models.InvalidationIn,
)


def test_no_data_route_model_declares_a_project_id() -> None:
    """The first hop. `RegisterAgentIn` is the ONE exception the contract
    grants (§14 api-auth: "the one registry exception is §9.3's admin register
    route"), and it is reachable only behind `require_admin_key` — a separate
    credential plane from every `/v1/*` route.
    """
    for model in _DATA_ROUTE_MODELS:
        assert "project_id" not in model.model_fields, (
            f"{model.__name__} declares project_id — a caller could name its own project"
        )

    # Positive control: the assertion above is only meaningful if a model that
    # DOES declare project_id exists and is found by the same check.
    assert "project_id" in api_models.RegisterAgentIn.model_fields


def test_every_route_model_forbids_extra_keys() -> None:
    """`extra="forbid"` is what turns a smuggled `project_id` (or `weight`, or
    `arm`) into a 422 with no hand-written validation. A model that silently
    ignored unknown keys would make the test above prove nothing."""
    models = [
        *_DATA_ROUTE_MODELS,
        api_models.ProjectCreateIn,
        api_models.RegisterAgentIn,
        api_models.OidcPrincipalIn,
        api_models.ApiKeyPrincipalIn,
        api_models.AcceptedOut,
        api_models.ProjectCreatedOut,
        api_models.AgentRegisteredOut,
        api_models.MemoryItemOut,
    ]
    for model in models:
        assert model.model_config.get("extra") == "forbid", model.__name__


def test_no_v1_handler_accepts_a_project_id_parameter() -> None:
    """The second hop. Even with a clean body model, a handler could take
    `project_id` as a path or query parameter. FastAPI would happily bind it.
    """
    for name, fn in vars(routes_v1).items():
        if not callable(fn) or not hasattr(fn, "__module__"):
            continue
        if getattr(fn, "__module__", None) != routes_v1.__name__:
            continue
        params = inspect.signature(fn).parameters
        assert "project_id" not in params, f"routes_v1.{name} takes a project_id parameter"


def test_only_the_admin_registry_route_names_a_project() -> None:
    """`api/admin.py` has two auth planes. The `require_admin_key` routes may
    name a project (there is no registration yet for the caller creating one);
    the `ScopeDep` routes may not, and get the same server-derived scope as
    `/v1/*`. Read off the real handler signatures, so a route that changed
    planes would fail here."""
    scoped_handlers = (
        "get_memory",
        "export_project",
        # D-093's control-plane reads. Listed by name rather than discovered,
        # so adding a route that quietly takes a `project_id` parameter is a
        # test edit somebody has to justify, not an omission.
        "whoami",
        "list_memory",
        "list_review_queue",
        "get_killswitch_state",
        "list_invalidations",
        "get_spend",
        "get_config",
    )
    for name in scoped_handlers:
        fn = getattr(admin_routes, name)
        params = inspect.signature(fn).parameters
        assert "project_id" not in params, f"admin.{name} takes a project_id"
        assert "scope" in params, f"admin.{name} does not resolve a ProjectScope"

    # And the registry route does name one — the exception, made explicit.
    assert "body" in inspect.signature(admin_routes.register_agent).parameters
    assert "project_id" in api_models.RegisterAgentIn.model_fields


def test_enqueue_requires_a_typed_projectid_not_a_bare_uuid() -> None:
    """The third hop, and the reason `domain.ids.ProjectId` is a newtype rather
    than an alias: a `project_id` lifted out of a request payload is a `str` or
    a `UUID`, and neither satisfies this annotation. The type system is what
    makes "producers inject scope server-side" structural instead of a
    convention every route has to remember."""
    hints = get_type_hints(WorkQueue.enqueue)
    assert hints["project_id"] is ProjectId


def test_queue_items_carry_their_own_project_column() -> None:
    """The fourth hop. A consumer that scoped by `payload["project_id"]` would
    be trusting a value that rode inside the row rather than the row itself.
    `QueueItem.project_id` is a typed column, populated by `enqueue` from the
    producer's `ProjectScope`."""
    from tracebed.stores.pg.queue import QueueItem

    hints = get_type_hints(QueueItem)
    assert hints["project_id"] is ProjectId


@pytest.mark.parametrize(
    "module_name",
    ["tracebed.ingest.trace_writer", "tracebed.ingest.outcome_intake"],
)
def test_consumers_scope_by_the_queue_row_not_the_envelope(module_name: str) -> None:
    """The fifth hop, checked in the source because it is a *choice between two
    available values*, not a signature: both `item.project_id` (the row's own
    column) and `envelope.project_id` (payload data) are in scope at the write
    site. Requiring the row column to appear, and requiring a mismatch check to
    exist, pins the choice.
    """
    relative = module_name.removeprefix("tracebed.").replace(".", "/")
    path = (_SRC / relative).with_suffix(".py")
    assert path.is_file(), path
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source)
    attrs = {
        node.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Attribute) and node.attr == "project_id"
    }
    assert "project_id" in attrs
    assert "item.project_id" in source or "row_project_id" in source, (
        f"{module_name} never reads the queue row's own project_id column"
    )
    # Invariant 4 defence in depth: an envelope that disagrees with the row it
    # rode on must be refused, not silently preferred either way.
    assert "mismatch" in source.lower() or "disagree" in source.lower(), (
        f"{module_name} has no envelope/row project_id disagreement check"
    )


# --------------------------------------------------------------------------- #
# RT-03 / invariant 6 — nothing writes a memory_item without a ScanVerdict.
# --------------------------------------------------------------------------- #


def test_no_memory_insert_path_omits_a_scan_verdict() -> None:
    """`memory_item.scan_verdict_id` is NOT NULL from the first migration (§14
    migrations: "the schema must make skipping it impossible"), but a NOT NULL
    column can still be satisfied by a fabricated id. Both insert entry points
    take a real `ScanVerdict` object, and `ScanVerdict` cannot be constructed
    outside `tracebed.core.scans` (`ScanVerdictForgery`), so possession of one
    is proof the scan suite ran."""
    from tracebed.core.scans import ScanVerdict

    for method in (Repo.insert_memory_item, ScopedRepo.insert_memory_item):
        hints = get_type_hints(method)
        verdict_params = [k for k, v in hints.items() if v is ScanVerdict]
        assert verdict_params, f"{method.__qualname__} takes no ScanVerdict"
        # Not defaulted: a default would let a caller reach the insert without one.
        for name in verdict_params:
            assert inspect.signature(method).parameters[name].default is inspect.Parameter.empty


def test_the_only_memory_insert_statements_bind_the_verdicts_own_id() -> None:
    """A second entry point that built its own INSERT would satisfy the
    signature check above and still skip the verdict. There is exactly one
    `INSERT INTO memory_item` in the whole tree, and it binds
    `scan_verdict.verdict_id` rather than a fresh uuid."""
    hits = [
        path
        for path in _src_files()
        if "INSERT INTO memory_item" in path.read_text(encoding="utf-8")
    ]
    assert [p.name for p in hits] == ["repo.py"], hits

    source = (_SRC / "stores" / "pg" / "repo.py").read_text(encoding="utf-8")
    assert "verify_verdict(" in source, "repo.py never re-verifies the verdict against the content"


def _memory_item_writing_methods() -> list[Any]:
    """Every public `Repo`/`ScopedRepo` method that accepts a `NewMemoryItem`.

    DERIVED, not a hand-written list. A hardcoded pair of method names makes the
    assertion below a statement about the two paths that existed when it was written:
    the third one — the method most likely to have forgotten the check, because it is
    the newest — would be silently exempt. `NewMemoryItem` is the parameter type that
    means "this call writes a governed row", so taking one is the derivable signal.
    """
    found: list[Any] = []
    for owner in (Repo, ScopedRepo):
        for name, method in inspect.getmembers(owner, inspect.isfunction):
            if name.startswith("_"):
                continue
            hints = inspect.signature(method).parameters
            if any(
                getattr(p.annotation, "__name__", str(p.annotation)) == "NewMemoryItem"
                or p.annotation == "NewMemoryItem"
                for p in hints.values()
            ):
                found.append(method)
    return found


def test_every_memory_item_write_path_validates_provenance_and_the_verdict() -> None:
    """`verify_verdict` binds the verdict to THIS content's hash — without it a caller
    could pass a verdict minted for different text — and `validate_provenance` is
    invariant 6 itself. Both must run on EVERY entry point that writes a governed row,
    not just the two that happen to be called `insert_memory_item`.
    """
    methods = _memory_item_writing_methods()
    names = {m.__qualname__ for m in methods}
    # Sanity: the derivation must actually find the paths we know exist, otherwise a
    # broken introspection would make this test vacuously green.
    assert {
        "Repo.insert_memory_item",
        "ScopedRepo.insert_memory_item",
        "Repo.insert_proposal_within_caps",
    } <= names, f"the derivation missed a known write path; found {sorted(names)}"

    for method in methods:
        source = inspect.getsource(method)
        assert "verify_verdict(" in source, f"{method.__qualname__} skips verify_verdict"
        assert "validate_provenance(" in source, f"{method.__qualname__} skips provenance (inv. 6)"


# --------------------------------------------------------------------------- #
# Hard rule 4 — the Phase 2 soak needs a deterministic clock everywhere.
# --------------------------------------------------------------------------- #


_WALL_CLOCK_CALLS: Final = {"now", "today", "utcnow", "time", "monotonic", "time_ns"}
_WALL_CLOCK_MODULES: Final = {"datetime", "date", "time"}
# `SystemClock` IS the sanctioned wrapper; `FakeClock` lives beside it.
_CLOCK_MODULE: Final = "clock.py"

# The ONE named exception, kept as data so it is impossible to widen by accident.
# `domain/ids.py::uuid7` needs a millisecond stamp for the UUIDv7 time prefix.
# It is not a business timestamp: nothing joins, buckets, or expires on it, and
# every caller that cares passes `now_ms=clock.now_ms()` (`mint_run_id`,
# `mint_memory_id`). The fallback exists so an id can still be minted on a path
# with no Clock in scope. Listed rather than silently skipped so a reader sees
# the exception exists and can weigh it.
_WALL_CLOCK_EXCEPTIONS: Final = {("domain/ids.py", "time.time_ns")}


def _dotted(node: ast.expr) -> str | None:
    """`a.b.c` -> "a.b.c"; anything that is not a plain dotted name -> None."""
    parts: list[str] = []
    current: ast.expr = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if not isinstance(current, ast.Name):
        return None
    parts.append(current.id)
    return ".".join(reversed(parts))


def _alias_map(tree: ast.Module) -> dict[str, str]:
    """Local name -> the dotted thing it actually refers to.

    Without this the scanner is trivially evaded: `import datetime as _d`
    followed by `_d.datetime.now()` is the same wall-clock call under a name no
    literal match would recognise. Verified by mutation — the first version of
    this scanner matched only bare `ast.Name` receivers and missed exactly that.
    """
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                aliases[alias.asname or alias.name.split(".")[0]] = alias.name
        elif isinstance(node, ast.ImportFrom) and node.module:
            for alias in node.names:
                aliases[alias.asname or alias.name] = f"{node.module}.{alias.name}"
    return aliases


def _wall_clock_hits(path: Path) -> list[str]:
    """Every `<datetime|date|time>.<now|today|utcnow|time|monotonic|time_ns>()`
    call, with import aliases resolved first.

    `clock.now()` and `self._clock.now()` are correctly NOT hits: their
    receiver resolves to a local attribute whose final segment is a clock, not
    to the `datetime`/`time` module.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"))
    aliases = _alias_map(tree)
    relative = path.relative_to(_SRC).as_posix()
    hits: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        if node.func.attr not in _WALL_CLOCK_CALLS:
            continue
        receiver = _dotted(node.func.value)
        if receiver is None:
            continue
        head, _, tail = receiver.partition(".")
        resolved = f"{aliases.get(head, head)}{'.' + tail if tail else ''}"
        if resolved.rsplit(".", 1)[-1] not in _WALL_CLOCK_MODULES:
            continue
        call = f"{resolved}.{node.func.attr}"
        if (relative, call) in _WALL_CLOCK_EXCEPTIONS:
            continue
        hits.append(f"{relative}:{node.lineno} {call}()")
    return hits


def test_no_bare_wall_clock_call_anywhere_in_src() -> None:
    """One hit and the Phase 2 soak cannot run: a component that reads the wall
    clock directly cannot be replayed, and a soak that cannot be replayed
    cannot distinguish a real drift from a scheduling artefact.

    `stores/tracestore/sigv4.py` was the last offender at integration — its
    `now: datetime | None = None` fell back to `datetime.now(UTC)` on every
    real signed request, which is why `now` is required there now (C-34).
    """
    offenders: list[str] = []
    for path in _src_files():
        if path.name == _CLOCK_MODULE and path.parent.name == "domain":
            continue
        offenders.extend(_wall_clock_hits(path))
    assert offenders == [], "\n".join(offenders)


def test_the_clock_module_is_the_one_place_that_does_call_it() -> None:
    """Positive control. Without this, a scanner that matched nothing at all —
    a typo in the attribute set, a broken glob — would report a clean tree."""
    hits = _wall_clock_hits(_SRC / "domain" / "clock.py")
    assert hits, "domain/clock.py calls no wall clock — the scanner above is not working"


# --------------------------------------------------------------------------- #
# The §13.1 fixture surface — the conftest calls the real constructors.
# --------------------------------------------------------------------------- #


def test_pool_module_exposes_no_scopedpool_class() -> None:
    """`tests/phase0/conftest.py` as merged did `ScopedPool(pg_dsn)`. There is
    no such class: `stores/pg/pool.py` deliberately exposes `create_pool` and
    `scoped()` instead, because the structural gateway to the RLS GUC is a
    context manager that REQUIRES a `ProjectId`, not a pool object someone
    could hold without one. Pinned so the wrong name cannot come back."""
    assert not hasattr(pg_pool_module, "ScopedPool")
    assert set(pg_pool_module.__all__) == {"create_pool", "register_typed_id_adapters", "scoped"}


def test_conftest_constructor_calls_bind_against_the_real_signatures() -> None:
    """The defect this file exists for. `pg_pool`/`work_queue` were wrong for
    the whole parallel build and NOTHING caught it, because `tests/conftest.py::pg`
    skips before either fixture body runs on a machine with no Postgres — so
    the error was one reachable database away from turning five test modules
    into setup ERRORs, which read exactly like a real isolation failure.

    Binds the argument COUNTS the conftest actually passes against the real
    `__init__` signatures, statically, with no database.
    """
    conftest = Path(__file__).with_name("conftest.py")
    tree = ast.parse(conftest.read_text(encoding="utf-8"))

    calls: dict[str, ast.Call] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            calls.setdefault(node.func.id, node)

    for name, target in (("Repo", Repo), ("WorkQueue", WorkQueue)):
        call = calls.get(name)
        assert call is not None, f"conftest.py no longer constructs a {name}"
        params = [
            p
            for p in inspect.signature(target.__init__).parameters.values()
            if p.name != "self"
        ]
        required = [p for p in params if p.default is inspect.Parameter.empty]
        assert len(call.args) + len(call.keywords) == len(required), (
            f"conftest.py calls {name}(...) with {len(call.args) + len(call.keywords)} "
            f"arguments; {name}.__init__ requires {len(required)} ({[p.name for p in required]})"
        )


def test_conftest_defines_every_fixture_the_contract_names() -> None:
    """§13.1 lists the fixture surface by name. `two_projects` — "THE leak-suite
    fixture" — was simply absent, so `test_queue.py`, `test_migrations.py` and
    `test_partitions.py` would have failed fixture lookup outright."""
    from tests.phase0 import conftest as phase0_conftest

    for name in (
        "pg_dsn",
        "pg_pool",
        "repo",
        "work_queue",
        "valkey_url",
        "s3_config",
        "two_projects",
    ):
        fixture = getattr(phase0_conftest, name, None)
        assert fixture is not None, f"§13.1 fixture {name!r} is missing"
        # pytest wraps a decorated fixture in its own object; a plain function
        # left undecorated is the mistake worth catching, and it would be one.
        assert type(fixture).__name__ != "function", f"{name!r} is not a pytest fixture"


def test_appdeps_has_a_port_for_every_router_dependency() -> None:
    """`AppDeps` is the one wiring surface; a route that reached for a
    dependency the container does not declare would only fail at request time,
    against a real deployment. Every field is annotated with a Protocol or a
    Clock — never a concrete store — which is what keeps the API testable
    offline at all (§9.2)."""
    hints = get_type_hints(AppDeps)
    assert set(hints) == {
        "verifier",
        "resolver",
        "queue",
        "telemetry",
        "memory_reader",
        "exporter",
        "invalidations",
        "admin",
        "partitions",
        "keys",
        "clock",
        "pipeline",
        # D-093: the dashboard's read surface. Optional like `pipeline`, and
        # for the same reason — a `TestClient` app built against Phase 0 fakes
        # must keep constructing without one.
        "control_plane",
    }
    for name, annotation in hints.items():
        # `pipeline` is `PipelinePort | None` — optional because a real
        # `hotpath.pipeline.Pipeline` needs a Postgres pool, an `EmbeddingPort`
        # and a killswitch salt, none of which the offline `TestClient` apps in
        # this suite have. The Protocol requirement still applies, to the
        # non-None member: the container must never name a concrete store.
        members = [a for a in get_args(annotation) if a is not type(None)] or [annotation]
        assert all(getattr(member, "_is_protocol", False) for member in members) or name == "clock", (
            f"AppDeps.{name} is a concrete type, not a Protocol"
        )


# --------------------------------------------------------------------------- #
# Constants mirrored across a deliberate import boundary.
# --------------------------------------------------------------------------- #


def test_the_wire_seq_ceiling_matches_the_ingest_one() -> None:
    """C-33. `api` must not import `ingest` (§14 keeps the request plane and
    the consumer plane apart), so the ceiling is stated twice. If the two
    drift, the API answers 202 "accepted" for a seq the consumer will refuse
    and dead-letter — a rejection the caller never sees."""
    assert api_models.MAX_SEQ == MAX_TRACE_SEQ


def test_api_does_not_import_ingest_and_ingest_does_not_import_api() -> None:
    """The boundary the constant above is mirrored across. Stated as a test so
    "just import it" is a visible decision rather than a quiet one."""
    for package, forbidden in (("api", "tracebed.ingest"), ("ingest", "tracebed.api")):
        for path in sorted((_SRC / package).rglob("*.py")):
            source = path.read_text(encoding="utf-8")
            assert f"import {forbidden}" not in source and f"from {forbidden}" not in source, (
                f"{path.name} imports {forbidden}"
            )


# --------------------------------------------------------------------------- #
# Wire-boundary refusals that would otherwise be silent dead letters.
# --------------------------------------------------------------------------- #


def test_a_naive_occurred_at_is_refused_at_the_wire() -> None:
    """C-35. `outcome_event.occurred_at` is `timestamptz`. A naive value is
    reinterpreted by Postgres in the session TimeZone — the event moves by
    hours, silently, and T+2-day feedback attach is a time join.

    `ingest.outcome_intake` already refuses it, but only after `/v1/feedback`
    has returned 202: the caller is told "accepted" and the event is dead-
    lettered out of sight. Both halves must hold, so both are asserted.
    """
    import pydantic

    from tracebed.api.models import FeedbackIn

    body = {
        "adapter": "verdict",
        "outcome": "positive",
        "event_id": "00000000-0000-4000-8000-000000000001",
        "occurred_at": "2026-01-01T00:00:00",  # no offset
    }
    with pytest.raises(pydantic.ValidationError):
        FeedbackIn(run_id="00000000-0000-7000-8000-000000000001", event=body)  # type: ignore[arg-type]

    aware = dict(body, occurred_at="2026-01-01T00:00:00+00:00")
    parsed = FeedbackIn(run_id="00000000-0000-7000-8000-000000000001", event=aware)  # type: ignore[arg-type]
    assert parsed.event.occurred_at is not None
    assert parsed.event.occurred_at.tzinfo is not None

    # None stays legal — `occurred_at` is optional and the consumer stamps
    # `arrived_at` itself.
    assert (
        FeedbackIn(
            run_id="00000000-0000-7000-8000-000000000001",
            event={k: v for k, v in body.items() if k != "occurred_at"},  # type: ignore[arg-type]
        ).event.occurred_at
        is None
    )


def test_a_seq_above_the_ingest_cap_is_refused_at_the_wire() -> None:
    """C-33's other half: the ceiling agreeing is only useful if the wire
    actually enforces it."""
    import pydantic

    from tracebed.api.models import MAX_SEQ, TraceIn

    event = {"type": "tool_call", "ts": "2026-01-01T00:00:00+00:00", "payload": {}}
    run_id = "00000000-0000-7000-8000-000000000001"
    assert TraceIn(run_id=run_id, seq=MAX_SEQ, event=event).seq == MAX_SEQ  # type: ignore[arg-type]
    with pytest.raises(pydantic.ValidationError):
        TraceIn(run_id=run_id, seq=MAX_SEQ + 1, event=event)  # type: ignore[arg-type]


# --------------------------------------------------------------------------- #
# Known schema gaps, pinned so they are visible rather than latent.
# --------------------------------------------------------------------------- #


def test_retrieval_event_is_still_keyed_one_row_per_run() -> None:
    """NOT an endorsement — a tripwire. `retrieval_event PRIMARY KEY
    (project_id, run_id)` permits at most one row per run, while its own DDL
    comment and PLAN.md §5 say "one row per /v1/retrieve call", and
    `Repo.insert_retrieval_event` has no ON CONFLICT clause.

    Unreachable in Phase 0 because `/v1/retrieve` mints a fresh server-side
    `run_id` per call. It becomes a live invariant-2 violation the moment
    C-26's `run_id_origin: "sdk"` ships or an agent retrieves twice in one
    run: `UniqueViolation` propagates out of `Telemetry.record_retrieval`
    into the agent's run, and PLAN.md §2 says a run never fails because of
    Tracebed. Documented in DECISIONS.md as the highest-priority Phase 1
    schema change; this test fails the moment the DDL is corrected, which is
    the prompt to delete it.
    """
    sql = (_REPO_ROOT / "migrations" / "0002_partitioned.sql").read_text(encoding="utf-8")
    block = sql[sql.index("CREATE TABLE retrieval_event") :]
    block = block[: block.index(";")]
    assert "PRIMARY KEY (project_id, run_id)" in block
    assert "ON CONFLICT" not in inspect.getsource(Repo.insert_retrieval_event)


def test_trace_index_has_no_server_side_first_seen_timestamp() -> None:
    """Second tripwire. `find_runs_missing_sentinel` falls back to the epoch
    when `started_at IS NULL`, so a run whose first batch carried no
    `run_start` is sweepable to `incomplete` immediately — before its
    `run_start` could plausibly arrive. A `first_seen_at timestamptz NOT NULL
    DEFAULT now()` column fixes it; deliberately not added here because it is
    a partitioned-table DDL change that cannot be executed, let alone tested,
    on a machine with no Postgres."""
    sql = (_REPO_ROOT / "migrations" / "0002_partitioned.sql").read_text(encoding="utf-8")
    block = sql[sql.index("CREATE TABLE trace_index") :]
    block = block[: block.index(";")]
    assert "first_seen_at" not in block


def test_the_rls_guc_name_is_identical_in_all_three_places() -> None:
    """The last hop of invariant 4, and the one a single chunk could not check:
    `pool.scoped()` SETS the GUC, `migrations/0003_rls.sql` reads it in the
    policy for tables that exist at migration time, and `stores/pg/ddl.py`
    reads it again in the per-partition policy applied to every project created
    afterwards. Three files, one string. A typo in any one of them does not
    error — it silently produces a policy that never matches, i.e. either a
    table that returns nothing or (if the setter is the one that drifts) a GUC
    nobody reads.
    """
    guc = "tracebed.project_id"
    pool_src = (_SRC / "stores" / "pg" / "pool.py").read_text(encoding="utf-8")
    ddl_src = (_SRC / "stores" / "pg" / "ddl.py").read_text(encoding="utf-8")
    rls_sql = (_REPO_ROOT / "migrations" / "0003_rls.sql").read_text(encoding="utf-8")

    assert f"set_config('{guc}'" in pool_src
    assert f"current_setting('{guc}', true)" in ddl_src
    assert f"current_setting('{guc}', true)" in rls_sql

    # Fail-closed shape: an unset GUC must yield NULL (zero rows), never ''.
    # `current_setting(name, true)` returns '' rather than raising when the
    # setting is missing, and `''::uuid` is an ERROR, not a mismatch — the
    # NULLIF is what turns "no scope set" into "no rows" instead of a 500.
    for src in (ddl_src, rls_sql):
        assert f"NULLIF(current_setting('{guc}', true), '')::uuid" in src


def test_every_partitioned_table_is_force_rls_in_the_migration() -> None:
    """`ENABLE` alone exempts the table OWNER, and migrations run as the owner.
    `FORCE` is what makes the policy apply to everyone. Enumerated from
    `stores/pg/ddl.py::PARTITIONED_TABLES` rather than re-typed, so a table
    added later cannot be silently left unprotected."""
    from tracebed.stores.pg.ddl import PARTITIONED_TABLES

    # Every forward migration, not only 0003: a partitioned parent created after
    # 0003 ran (0004_lifecycle.sql's `memory_status_log` is the first) has to
    # apply its own RLS inline, because 0003 cannot protect a table that did not
    # exist when it ran. Reading one file made this check blind to exactly the
    # tables that carry the greater risk of being left unprotected.
    rls_sql = "\n".join(
        path.read_text(encoding="utf-8")
        for path in sorted((_REPO_ROOT / "migrations").glob("*.sql"))
        if not path.name.endswith(".rollback.sql")
    )
    missing = [
        table
        for table in PARTITIONED_TABLES
        if f"ALTER TABLE {table}" not in rls_sql or "FORCE ROW LEVEL SECURITY" not in rls_sql
    ]
    assert missing == [], missing
    for table in PARTITIONED_TABLES:
        assert f"{table}_isolation" in rls_sql, f"{table} has no isolation policy"
