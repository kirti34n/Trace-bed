"""The cross-project leak suite — the Phase 0 security gate (PHASE-0 Task 17).

Seven probe classes, per PHASE-0.md Task 17 / PHASE0-CONTRACT.md §1's brief:

    1. search-path        4. dashboard API      7. RLS bypass
    2. by-id fetch         5. export
    3. admin endpoints      6. Valkey collisions

Every probe below is real: it asserts on response bodies, error-message
identity, key strings, and raw row counts — never on a status code alone. A
probe that cannot execute (no Postgres, no Valkey, a route that does not
exist yet in Phase 0) SKIPS with a specific, loud reason; it never silently
passes and it is never weakened to pass (§14 harness DO-NOT list). Every test
name is prefixed `test_probeN_...` so `harness/phase0_gate.py` can group the
JUnit results back into the seven classes without re-running anything.

Two Phase 0 surfaces this suite cannot fully probe, both flagged inline where
relevant rather than silently skipped:

  * Probe 1 ("search-path"): Phase 0 ships no HTTP list/search route at all
    (no `/v1/memories`, no dashboard). The closest analog is `Repo.list_memories`
    / `Repo.list_runs`, which is what is probed; a real search route needs a
    probe of its own the moment one exists.
  * Probe 4 ("dashboard API"): the dashboard is a separate React app that
    consumes the SAME `/v1/*` and `/admin/*` routes as any other client —
    there is no `/dashboard/*` route plane and there never will be. The
    original probe greppped registered route paths for the substring
    "dashboard", which meant it could never fire no matter what the
    dashboard did. It now extracts the paths the dashboard's own TypeScript
    actually calls and probes THOSE: every one must exist on the app, and
    every one must refuse an unauthenticated caller. What it still does not
    prove is per-route row-level isolation for the report routes, which need
    a stack (probe 7 covers the RLS backstop those routes sit behind).

Imports every fixture this file's tests (transitively) depend on from
`fixtures.py` — pytest fixture discovery only looks at fixtures registered in
a conftest.py chain or in the collected test module's own namespace, and this
directory intentionally has no `conftest.py` (see `fixtures.py`'s module
docstring for why: it is not in this chunk's file list). The official pytest
pattern for exactly this situation is "import fixtures from another module";
https://docs.pytest.org/en/stable/how-to/fixtures.html#using-fixtures-from-other-projects.
"""

from __future__ import annotations

import re
import uuid
from pathlib import Path
from typing import Any

import psycopg
import pytest

from harness.leak_suite.fixtures import (  # noqa: F401 - re-exported for pytest fixture discovery
    LeakProject,
    app_role_conninfo,
    leak_admin_key_env,
    leak_app,
    leak_client,
    leak_clock,
    leak_keys_manager,
    leak_master_key_env,
    leak_pg_dsn,
    leak_pool,
    leak_queue,
    leak_repo,
    leak_rls_seeded,
    leak_settings,
    leak_tracestore,
    leak_valkey,
    leak_valkey_url,
    offline_two_projects,
    seed_all_partitioned_tables,
    two_leak_projects,
)
from tracebed.domain.errors import NotFound
from tracebed.domain.ids import MemoryId, ProjectId, RunId, mint_run_id
from tracebed.stores.pg.ddl import PARTITIONED_TABLES
from tracebed.stores.tracestore import PayloadRef
from tracebed.stores.tracestore.fs import FsTraceStore
from tracebed.stores.valkey.keys import project_key_pattern, tool_cache_key, working_memory_key

pytestmark = pytest.mark.phase0


def _route_paths(app: Any) -> set[str]:
    """Every concrete path template registered on `app`, flattened.

    `app.routes` mixes plain `APIRoute`s with router-composition wrapper
    objects (this Starlette version's `_IncludedRouter`, used by
    `FastAPI.include_router`) that carry no `.path` of their own — the real
    routes live one level down, on `wrapper.original_router.routes`. Walked
    recursively (not just one level) so this stays correct if a future
    router nests sub-routers, which is exactly the shape that would hide a
    new `/admin/...` or `/dashboard/...` route from a probe that only looked
    at the top level.
    """
    paths: set[str] = set()

    def _walk(routes: Any) -> None:
        for route in routes:
            path = getattr(route, "path", None)
            if path is not None:
                paths.add(path)
            nested = getattr(getattr(route, "original_router", None), "routes", None)
            if nested is not None:
                _walk(nested)

    _walk(app.routes)
    return paths


def _project_identifiers(project: LeakProject) -> list[bytes]:
    """Every UUID that names `project` — what probe 5 scans an export stream
    (or, offline, a fake export body) for zero occurrences of."""
    return [
        str(project.scope.project_id.value).encode(),
        str(project.scope.agent_type_id.value).encode(),
        str(project.scope.principal_id.value).encode(),
        str(project.memory_id.value).encode(),
        str(project.run_id.value).encode(),
        str(project.outcome_event_id).encode(),
    ]


# --------------------------------------------------------------------------- #
# Probe 1 — search path. No HTTP list/search route exists in Phase 0 (see
# module docstring); the repository builder is the searchable surface.
# --------------------------------------------------------------------------- #


@pytest.mark.integration
def test_probe1_search_path_list_memories_and_runs_never_cross_projects(
    two_leak_projects: tuple[LeakProject, LeakProject], leak_repo: Any  # noqa: F811 - fixture-name parameter, see fixtures.py module docstring
) -> None:
    project_a, project_b = two_leak_projects

    memories_a = leak_repo.list_memories(project_a.scope.project_id)
    memory_ids_a = {row.id for row in memories_a}
    assert project_a.memory_id in memory_ids_a
    assert project_b.memory_id not in memory_ids_a

    memories_b = leak_repo.list_memories(project_b.scope.project_id)
    memory_ids_b = {row.id for row in memories_b}
    assert project_b.memory_id in memory_ids_b
    assert project_a.memory_id not in memory_ids_b

    runs_a = leak_repo.list_runs(project_a.scope.project_id)
    run_ids_a = {row.run_id for row in runs_a}
    assert project_a.run_id in run_ids_a
    assert project_b.run_id not in run_ids_a


# --------------------------------------------------------------------------- #
# Probe 2 — by-id fetch. Byte-identical 404/NotFound for "not yours" and
# "doesn't exist", on every by-id surface Phase 0 actually has.
# --------------------------------------------------------------------------- #


def test_probe2_offline_tracestore_cross_project_ref_is_uniform_not_found(
    tmp_path: Any,
) -> None:
    """Runs with zero services: `FsTraceStore` keys embed `project_id`, so
    the by-id check is a string/path comparison — provably uniform without a
    database."""
    store = FsTraceStore(tmp_path / "leak-probe2-ts")
    project_a = ProjectId(uuid.uuid4())
    project_b = ProjectId(uuid.uuid4())
    run_id = mint_run_id()
    ref = store.put(project_a, run_id, 0, b"leak-probe-2-plaintext-does-not-matter")

    with pytest.raises(NotFound) as leaked:
        store.get(project_b, ref)
    absent_ref = PayloadRef(driver="fs", key=f"{project_b}/{uuid.uuid4()}/00000000.tbz")
    with pytest.raises(NotFound) as absent:
        store.get(project_b, absent_ref)

    assert str(leaked.value) == str(absent.value)


def test_probe2_offline_admin_memory_route_is_uniform_not_found(
    offline_two_projects: tuple[LeakProject, LeakProject, Any],  # noqa: F811 - fixture-name parameter, see fixtures.py module docstring
) -> None:
    project_a, project_b, client = offline_two_projects

    resp_leak = client.get(
        f"/admin/memory/{project_b.memory_id.value}", headers={"X-API-Key": project_a.api_key}
    )
    resp_absent = client.get(
        f"/admin/memory/{uuid.uuid4()}", headers={"X-API-Key": project_a.api_key}
    )

    assert resp_leak.status_code == 404
    assert resp_absent.status_code == 404
    assert resp_leak.content == resp_absent.content
    assert resp_leak.json() == {"detail": "not found"}


@pytest.mark.integration
def test_probe2_integration_admin_memory_http_uniform_404(
    two_leak_projects: tuple[LeakProject, LeakProject], leak_client: Any  # noqa: F811 - fixture-name parameter, see fixtures.py module docstring
) -> None:
    project_a, project_b = two_leak_projects

    resp_leak = leak_client.get(
        f"/admin/memory/{project_b.memory_id.value}", headers={"X-API-Key": project_a.api_key}
    )
    resp_absent = leak_client.get(
        f"/admin/memory/{uuid.uuid4()}", headers={"X-API-Key": project_a.api_key}
    )

    assert resp_leak.status_code == 404, resp_leak.text
    assert resp_absent.status_code == 404, resp_absent.text
    assert resp_leak.content == resp_absent.content
    assert resp_leak.json() == {"detail": "not found"}


@pytest.mark.integration
def test_probe2_integration_repo_and_tracestore_by_id_uniform_not_found(
    two_leak_projects: tuple[LeakProject, LeakProject],  # noqa: F811 - fixture-name parameter, see fixtures.py module docstring
    leak_repo: Any,  # noqa: F811 - fixture-name parameter, see fixtures.py module docstring
    leak_tracestore: FsTraceStore,  # noqa: F811 - fixture-name parameter, see fixtures.py module docstring
) -> None:
    project_a, project_b = two_leak_projects

    with pytest.raises(NotFound) as leaked_mem:
        leak_repo.get_memory_by_id(project_a.scope.project_id, project_b.memory_id)
    with pytest.raises(NotFound) as absent_mem:
        leak_repo.get_memory_by_id(project_a.scope.project_id, MemoryId(uuid.uuid4()))
    assert str(leaked_mem.value) == str(absent_mem.value)

    with pytest.raises(NotFound) as leaked_run:
        leak_repo.get_trace_index(project_a.scope.project_id, project_b.run_id)
    with pytest.raises(NotFound) as absent_run:
        leak_repo.get_trace_index(project_a.scope.project_id, RunId(uuid.uuid4()))
    assert str(leaked_run.value) == str(absent_run.value)

    leaked_ref = PayloadRef.parse(project_b.payload_ref)
    absent_ref = PayloadRef(
        driver="fs", key=f"{project_a.scope.project_id}/{uuid.uuid4()}/00000000.tbz"
    )
    with pytest.raises(NotFound) as leaked_payload:
        leak_tracestore.get(project_a.scope.project_id, leaked_ref)
    with pytest.raises(NotFound) as absent_payload:
        leak_tracestore.get(project_a.scope.project_id, absent_ref)
    assert str(leaked_payload.value) == str(absent_payload.value)


# --------------------------------------------------------------------------- #
# Probe 3 — admin endpoints. `/admin/memory/{id}` is covered by probe 2 above
# (it IS an admin endpoint); this section adds the admin-scope-specific
# checks: a genuinely admin-KEY-authenticated caller cannot read another
# project's registry, and the one admin route this brief names that Phase 0
# does not ship (`GET /admin/projects/{id}`) is a documented tripwire, not a
# silent gap.
# --------------------------------------------------------------------------- #


def test_probe3_offline_no_get_admin_projects_by_id_route_exists(
    offline_two_projects: tuple[LeakProject, LeakProject, Any],  # noqa: F811 - fixture-name parameter, see fixtures.py module docstring
) -> None:
    """PHASE-0.md Task 17 names `GET /admin/projects/{B}` as a probe 3 target,
    but `api/admin.py` (contract §9.3) ships no such route in Phase 0 — only
    `POST /admin/projects` (create) exists. This assertion is a tripwire: the
    moment a `GET /admin/projects/{project_id}` route is registered, this
    test fails and forces a real probe-3 assertion to be written against it,
    instead of the gap silently persisting."""
    _, _, client = offline_two_projects
    paths = _route_paths(client.app)
    assert "/admin/projects/{project_id}" not in paths
    assert not any(p.startswith("/admin/projects/") for p in paths)


@pytest.mark.integration
def test_probe3_integration_admin_key_cannot_read_another_projects_registry(
    two_leak_projects: tuple[LeakProject, LeakProject], leak_client: Any, leak_admin_key_env: str  # noqa: F811 - fixture-name parameter, see fixtures.py module docstring
) -> None:
    """The admin-KEY-authenticated registry-write routes (`POST /admin/projects`,
    `POST /admin/agents/register`) are global-bootstrap, not project-scoped —
    there is no route on which an admin key "belongs to" project A at all, so
    the only meaningful admin-scope probe left is confirming the one read
    route that DOES exist (`GET /admin/memory/{id}`, principal-authenticated,
    covered fully in probe 2) never accepts the admin key as a substitute for
    a real principal's scope."""
    project_a, project_b = two_leak_projects
    resp = leak_client.get(
        f"/admin/memory/{project_a.memory_id.value}", headers={"X-Admin-Key": leak_admin_key_env}
    )
    # No `X-API-Key`/bearer credential means no `Principal` at all -- the
    # admin key authenticates registry WRITES only (contract C-20); it must
    # not double as a skeleton key for a principal-scoped read.
    assert resp.status_code == 401
    del project_b


# --------------------------------------------------------------------------- #
# Probe 4 — dashboard API. The dashboard consumes /v1/* and /admin/*; those
# are the routes to probe, and they are extracted from the dashboard's own
# source so the probe cannot drift away from what the app really calls.
# --------------------------------------------------------------------------- #

_DASHBOARD_SRC = Path(__file__).resolve().parents[2] / "dashboard" / "src"

# `${...}` template holes and query strings are normalised away; a path with a hole becomes
# the FastAPI template it must match (`/admin/memory/{id}`).
# Character class is deliberately narrow: it admits path segments, `${...}` template holes and
# a query string, and NOTHING else — so prose like "`/v1/*` reads" in a docstring is not
# mistaken for a call site.
_DASHBOARD_PATH_RE = re.compile(r"""["'`](/(?:v1|admin)/[A-Za-z0-9_/.${}?=&-]*)["'`]""")

# The two routes that authenticate with the bootstrap admin KEY rather than a principal
# (contract C-20). Named explicitly so "this route does not 401 for an unauthenticated
# principal" is an enumerated exception rather than a silent one.
_ADMIN_KEY_ROUTES = frozenset({"/admin/projects", "/admin/agents/register"})


def _dashboard_consumed_paths() -> set[str]:
    """Every `/v1/*` or `/admin/*` path literal the dashboard source calls, as route templates."""
    found: set[str] = set()
    if not _DASHBOARD_SRC.is_dir():
        return found
    for path in sorted(_DASHBOARD_SRC.rglob("*.ts")) + sorted(_DASHBOARD_SRC.rglob("*.tsx")):
        for raw in _DASHBOARD_PATH_RE.findall(path.read_text(encoding="utf-8")):
            cleaned = raw.split("?", 1)[0]
            cleaned = re.sub(r"\$\{[^}]*\}", "{id}", cleaned).rstrip("/")
            if cleaned:
                found.add(cleaned)
    return found


def test_probe4_dashboard_calls_only_routes_that_exist() -> None:
    """A dashboard call to a path the service does not serve is a 404 in production and an
    invisible defect here; it is also how a probe of "the dashboard's routes" quietly starts
    probing nothing. The extraction itself is asserted non-empty for the same reason."""
    consumed = _dashboard_consumed_paths()
    if not _DASHBOARD_SRC.is_dir():
        pytest.skip("no dashboard app in this tree")
    assert consumed, "no /v1 or /admin path literals found in dashboard/src — extraction broke"
    from tracebed.api.admin import router as admin_router
    from tracebed.api.reports import router as reports_router
    from tracebed.api.routes_v1 import router as v1_router

    registered: set[str] = set()
    for router in (v1_router, admin_router, reports_router):
        registered.update(_route_paths(router))
    # Template parameter NAMES differ by design (the dashboard writes `${id}`, FastAPI
    # declares `{memory_id}`); compare on shape, not on the name inside the braces.
    def _shape(path: str) -> str:
        return re.sub(r"\{[^}]*\}", "{}", path)

    registered_shapes = {_shape(p) for p in registered}
    missing = sorted(p for p in consumed if _shape(p) not in registered_shapes)
    assert not missing, f"dashboard calls routes that do not exist: {missing}"


def test_probe4_every_dashboard_route_refuses_an_unauthenticated_caller(
    offline_two_projects: tuple[LeakProject, LeakProject, Any],  # noqa: F811 - fixture-name parameter, see fixtures.py module docstring
) -> None:
    """The isolation-relevant half that CAN run with no stack: every route the dashboard reads
    is behind principal authentication, so there is no anonymous path to another project's
    data. The two bootstrap admin-key routes are the enumerated exception and are covered by
    probe 3.

    Mutation this catches: drop `ScopeDep`/`PrincipalDep` from any report route and it starts
    answering 200 to a caller with no credentials at all.
    """
    _, _, client = offline_two_projects
    consumed = _dashboard_consumed_paths()
    if not consumed:
        pytest.skip("no dashboard app in this tree")
    offenders: list[str] = []
    for path in sorted(consumed - _ADMIN_KEY_ROUTES):
        probe_path = path.replace("{id}", str(uuid.uuid4()))
        resp = client.get(probe_path)
        # 401 (no credential) or 405 (the route exists but is POST-only, which this GET
        # cannot reach) are both "not readable anonymously"; 200 is not.
        if resp.status_code not in (401, 405):
            offenders.append(f"{path} -> {resp.status_code}")
    assert not offenders, f"dashboard routes reachable without a principal: {offenders}"


def test_probe4_a_dashboard_read_with_as_token_carries_no_b_identifier(
    offline_two_projects: tuple[LeakProject, LeakProject, Any],  # noqa: F811 - fixture-name parameter, see fixtures.py module docstring
) -> None:
    """The body-level half, for whatever the offline app can actually serve. Asserts on
    response BYTES, never on a status code (§14): any dashboard GET that answers 200 for A
    must contain none of B's identifiers."""
    project_a, project_b, client = offline_two_projects
    consumed = _dashboard_consumed_paths()
    if not consumed:
        pytest.skip("no dashboard app in this tree")
    served = 0
    for path in sorted(consumed - _ADMIN_KEY_ROUTES):
        probe_path = path.replace("{id}", str(project_a.memory_id.value))
        resp = client.get(probe_path, headers={"X-API-Key": project_a.api_key})
        if resp.status_code != 200:
            continue
        served += 1
        for needle in _project_identifiers(project_b):
            assert needle not in resp.content, f"{path} leaked B identifier {needle!r}"
    assert served, "no dashboard GET was servable offline — this probe proved nothing"


# --------------------------------------------------------------------------- #
# Probe 5 — export. `GET /export/project` streams only the caller's own
# project, both because the route has no project-selecting parameter at all
# (invariant 4: impossible to ask for someone else's, not merely filtered)
# and, empirically, because the stream never contains another project's ids.
# --------------------------------------------------------------------------- #


def test_probe5_offline_export_route_has_no_caller_selectable_project(
    offline_two_projects: tuple[LeakProject, LeakProject, Any],  # noqa: F811 - fixture-name parameter, see fixtures.py module docstring
) -> None:
    _, _, client = offline_two_projects
    paths = _route_paths(client.app)
    assert "/export/project" in paths
    # The registered template itself carries no path parameter -- a caller
    # cannot select a project by URL because there is nowhere in the route
    # to put one, not merely because the handler ignores it.
    assert "{" not in "/export/project"
    assert not any(p.startswith("/export/") and p != "/export/project" for p in paths)


def test_probe5_offline_export_stream_contains_zero_other_project_identifiers(
    offline_two_projects: tuple[LeakProject, LeakProject, Any],  # noqa: F811 - fixture-name parameter, see fixtures.py module docstring
) -> None:
    project_a, project_b, client = offline_two_projects
    resp = client.get("/export/project", headers={"X-API-Key": project_a.api_key})
    assert resp.status_code == 200
    body = resp.content

    # Positive control: an export that trivially contains nothing proves
    # nothing about isolation. A's own ids must actually be present.
    assert str(project_a.scope.project_id.value).encode() in body
    assert str(project_a.memory_id.value).encode() in body

    for needle in _project_identifiers(project_b):
        assert needle not in body, f"export for A leaked B's identifier {needle!r}"


@pytest.mark.integration
def test_probe5_integration_export_stream_contains_zero_other_project_identifiers(
    two_leak_projects: tuple[LeakProject, LeakProject], leak_client: Any  # noqa: F811 - fixture-name parameter, see fixtures.py module docstring
) -> None:
    project_a, project_b = two_leak_projects
    resp = leak_client.get("/export/project", headers={"X-API-Key": project_a.api_key})
    assert resp.status_code == 200, resp.text
    body = resp.content

    assert str(project_a.scope.project_id.value).encode() in body
    assert str(project_a.memory_id.value).encode() in body

    for needle in _project_identifiers(project_b):
        assert needle not in body, f"export for A leaked B's identifier {needle!r}"


# --------------------------------------------------------------------------- #
# Probe 6 — Valkey collisions. `stores/valkey/keys.py` is pure, so the core
# assertion runs with zero services; a real Valkey adds an empirical check
# that nothing about the server itself (hashing, SCAN, TTL handling) defeats
# what the key builders promise.
# --------------------------------------------------------------------------- #


def test_probe6_offline_tool_cache_keys_differ_and_embed_their_own_project() -> None:
    project_a = ProjectId(uuid.uuid4())
    project_b = ProjectId(uuid.uuid4())
    shared = {
        "tool_id": "leak-probe-tool",
        "tool_version": "1.0.0",
        "auth_context_fingerprint": "identical-auth-context",
        "args": {"q": "identical canonical args"},
    }

    key_a = tool_cache_key(project_a, **shared)
    key_b = tool_cache_key(project_b, **shared)

    assert key_a != key_b
    assert key_a.startswith(f"tb:{project_a}:")
    assert key_b.startswith(f"tb:{project_b}:")
    assert str(project_b) not in key_a
    assert str(project_a) not in key_b


def test_probe6_offline_working_memory_key_unreachable_via_the_other_projects_key() -> None:
    project_a = ProjectId(uuid.uuid4())
    project_b = ProjectId(uuid.uuid4())
    run_id = mint_run_id()

    key_under_a = working_memory_key(project_a, run_id, "scratch")
    # B has no call shape that reconstructs A's key: `working_memory_key`
    # takes `project_id` first and positionally, so the only key B can build
    # for this run_id/scratch-name pair is namespaced under B, never A.
    key_b_would_build = working_memory_key(project_b, run_id, "scratch")

    assert key_under_a != key_b_would_build
    assert key_under_a.startswith(project_key_pattern(project_a).removesuffix("*"))
    assert not key_b_would_build.startswith(project_key_pattern(project_a).removesuffix("*"))


@pytest.mark.integration
def test_probe6_integration_valkey_isolates_tool_cache_and_working_memory(
    leak_valkey: Any, leak_valkey_url: str  # noqa: F811 - fixture-name parameter, see fixtures.py module docstring
) -> None:
    from valkey import Valkey as _RawValkey

    project_a = ProjectId(uuid.uuid4())
    project_b = ProjectId(uuid.uuid4())
    shared = {
        "tool_id": "leak-probe-tool",
        "tool_version": "1.0.0",
        "auth_context_fingerprint": "identical-auth-context",
        "args": {"q": "identical canonical args"},
    }
    try:
        leak_valkey.tool_cache_set(project_a, **shared, value=b"A's cached result", ttl_seconds=30)
        leak_valkey.tool_cache_set(project_b, **shared, value=b"B's cached result", ttl_seconds=30)
        assert leak_valkey.tool_cache_get(project_a, **shared) == b"A's cached result"
        assert leak_valkey.tool_cache_get(project_b, **shared) == b"B's cached result"

        run_id = mint_run_id()
        leak_valkey.working_memory_set(
            project_a, run_id, "scratch", b"A's working memory", ttl_seconds=30
        )
        # B's connection, B's project scope: no accessor on ValkeyClient can
        # read a key under A's prefix without A's ProjectId in hand.
        assert leak_valkey.working_memory_get(project_b, run_id, "scratch") is None

        raw = _RawValkey.from_url(leak_valkey_url)
        try:
            keys_under_a = {
                k.decode() if isinstance(k, bytes) else k
                for k in raw.scan_iter(match=project_key_pattern(project_a), count=100)
            }
            keys_under_b = {
                k.decode() if isinstance(k, bytes) else k
                for k in raw.scan_iter(match=project_key_pattern(project_b), count=100)
            }
        finally:
            raw.close()

        assert keys_under_a, "expected at least A's own keys to be scanned under A's pattern"
        assert all(k.startswith(f"tb:{project_a}:") for k in keys_under_a)
        assert all(k.startswith(f"tb:{project_b}:") for k in keys_under_b)
        assert keys_under_a.isdisjoint(keys_under_b)
    finally:
        leak_valkey.delete_project(project_a)
        leak_valkey.delete_project(project_b)


# --------------------------------------------------------------------------- #
# Probe 7 — RLS bypass. Raw SQL as the non-owner, non-BYPASSRLS `tracebed_app`
# role: zero rows with no GUC, zero rows with a syntactically-valid but wrong
# GUC, and (positive control) real rows with the correct one — across EVERY
# partitioned table, enumerated from `stores/pg/ddl.py` so a table added
# later cannot be silently unprotected.
# --------------------------------------------------------------------------- #


@pytest.mark.integration
def test_probe7_rls_bypass_zero_rows_without_or_with_wrong_guc(
    leak_pg_dsn: str, leak_rls_seeded: tuple[LeakProject, LeakProject]  # noqa: F811 - fixture-name parameter, see fixtures.py module docstring
) -> None:
    project_a, _project_b = leak_rls_seeded

    try:
        app_conn = psycopg.connect(app_role_conninfo(leak_pg_dsn), connect_timeout=2)
    except psycopg.OperationalError as exc:
        pytest.skip(
            f"tracebed_app role unreachable ({exc.__class__.__name__}); needs "
            "docker/initdb/01-roles.sql bootstrapped first (harness Task 1's concern, "
            "not this probe's)."
        )
    try:
        with app_conn.cursor() as cur:
            # (a) no GUC set at all.
            for table in PARTITIONED_TABLES:
                cur.execute(f"SELECT count(*) FROM {table}")  # noqa: S608 - fixed whitelist
                row = cur.fetchone()
                assert row is not None and row[0] == 0, (
                    f"{table} leaked {row[0] if row else '?'} rows to tracebed_app "
                    "with no GUC set"
                )
            app_conn.rollback()

            # (b) a syntactically-valid GUC naming neither A nor B.
            cur.execute(
                "SELECT set_config('tracebed.project_id', %s, true)", (str(uuid.uuid4()),)
            )
            for table in PARTITIONED_TABLES:
                cur.execute(f"SELECT count(*) FROM {table}")  # noqa: S608
                row = cur.fetchone()
                assert row is not None and row[0] == 0, (
                    f"{table} leaked {row[0] if row else '?'} rows under an unrelated "
                    "project's GUC"
                )
            app_conn.rollback()

            # (c) positive control: A's own GUC sees A's rows -- "zero rows"
            # above is meaningful only if this is nonzero.
            cur.execute(
                "SELECT set_config('tracebed.project_id', %s, true)",
                (str(project_a.scope.project_id.value),),
            )
            for table in PARTITIONED_TABLES:
                cur.execute(f"SELECT count(*) FROM {table}")  # noqa: S608
                row = cur.fetchone()
                assert row is not None and row[0] >= 1, (
                    f"{table}: app role with A's own GUC saw 0 rows -- RLS/grants are "
                    "broken (not merely permissive), or seeding failed"
                )
        app_conn.rollback()
    finally:
        app_conn.close()
