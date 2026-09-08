"""Owner-only onboarding is transactional and never retains an API secret."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from urllib.parse import urlsplit, urlunsplit
from uuid import uuid4

import psycopg
import pytest

from tracebed.domain.clock import FakeClock
from tracebed.domain.enums import FeedbackSource, ProjectRole
from tracebed.domain.ids import ProjectId
from tracebed.stores.pg.migrate import apply_migrations
from tracebed.stores.pg.onboarding import (
    OnboardingError,
    OnboardingGrant,
    OwnerOnboardingStore,
)
from tracebed.stores.pg.pool import create_pool
from tracebed.stores.pg.repo import Repo

pytestmark = pytest.mark.phase3


@dataclass
class _Transaction:
    rolled_back: bool = False

    def __enter__(self) -> _Transaction:
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        del exc, traceback
        self.rolled_back = exc_type is not None


@dataclass
class _Connection:
    fail_on: int | None = None
    calls: list[tuple[str, dict[str, object]]] = field(default_factory=list)
    transaction_context: _Transaction = field(default_factory=_Transaction)

    def __enter__(self) -> _Connection:
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        del exc_type, exc, traceback

    def transaction(self) -> _Transaction:
        return self.transaction_context

    def execute(self, sql: str, params: dict[str, object]) -> None:
        self.calls.append((sql, params))
        if self.fail_on == len(self.calls):
            raise psycopg.errors.UniqueViolation()


@dataclass
class _Pool:
    conn: _Connection

    def connection(self) -> _Connection:
        return self.conn


def _store(conn: _Connection) -> OwnerOnboardingStore:
    return OwnerOnboardingStore(
        pool=_Pool(conn),  # type: ignore[arg-type]
        clock=FakeClock(datetime(2026, 1, 1, tzinfo=UTC)),
    )


def test_owner_onboarding_writes_the_complete_explicit_authority_bundle() -> None:
    conn = _Connection()
    secret = "never-persist-this-plaintext"
    principal_id, agent_type_id = _store(conn).create_agent(
        project_id=ProjectId(uuid4()),
        agent_type_name="worker",
        principal_kind="api_key",
        external_ref="key-id",
        api_key_secret=secret,
        grants=(
            OnboardingGrant(ProjectRole.DATA),
            OnboardingGrant(ProjectRole.FEEDBACK, FeedbackSource.VERDICT),
            OnboardingGrant(ProjectRole.ADMIN),
            OnboardingGrant(ProjectRole.EXPORT),
        ),
    )
    assert principal_id.value != agent_type_id.value
    assert len(conn.calls) == 7  # agent type, principal, registration, four grant rows
    principal_params = conn.calls[1][1]
    assert principal_params["key_hash"] != secret
    assert secret not in repr(conn.calls)
    grant_params = [params for _, params in conn.calls[3:]]
    assert {params["role"] for params in grant_params} == {"data", "feedback", "admin", "export"}
    feedback = next(params for params in grant_params if params["role"] == "feedback")
    assert feedback["feedback_source"] == "verdict"


def test_owner_onboarding_rolls_back_and_emits_no_backend_detail() -> None:
    conn = _Connection(fail_on=4)
    with pytest.raises(OnboardingError, match=r"^onboarding failed$"):
        _store(conn).create_agent(
            project_id=ProjectId(uuid4()),
            agent_type_name="worker",
            principal_kind="oidc_sub",
            external_ref="subject",
            api_key_secret=None,
            grants=(OnboardingGrant(ProjectRole.DATA),),
        )
    assert conn.transaction_context.rolled_back is True


@pytest.mark.integration
def test_owner_onboarding_is_atomic_on_an_isolated_pg18_database(pg: str) -> None:
    """The real owner transaction leaves no partial principal on conflict."""

    scratch = f"tb_onboard_{uuid4().hex}"
    admin = psycopg.connect(pg, autocommit=True)
    pool = None
    try:
        admin.execute(f'CREATE DATABASE "{scratch}"')
        dsn = urlunsplit(urlsplit(pg)._replace(path=f"/{scratch}"))
        try:
            apply_migrations(dsn)
        except psycopg.Error as exc:
            # A reused developer cluster can retain bootstrap role
            # memberships that the authority migration correctly refuses.
            # CI's dedicated PG18 fixture starts clean; never weaken the DDL
            # just to make a contaminated local cluster look healthy.
            pytest.skip(f"isolated authority migration precondition failed ({exc.sqlstate})")
        pool = create_pool(dsn)
        clock = FakeClock(datetime(2026, 1, 1, tzinfo=UTC))
        project_id = Repo(pool, clock).create_project("onboard-live")
        store = OwnerOnboardingStore(pool, clock)
        store.create_agent(
            project_id=project_id,
            agent_type_name="agent",
            principal_kind="oidc_sub",
            external_ref="live-subject",
            api_key_secret=None,
            grants=(
                OnboardingGrant(ProjectRole.DATA),
                OnboardingGrant(ProjectRole.FEEDBACK, FeedbackSource.VERDICT),
            ),
        )
        with pool.connection() as conn:
            assert conn.execute("SELECT count(*) FROM agent_registration").fetchone() == (1,)
            assert conn.execute("SELECT role, feedback_source FROM principal_grant ORDER BY role").fetchall() == [
                ("data", None),
                ("feedback", "verdict"),
            ]
        with pytest.raises(OnboardingError):
            store.create_agent(
                project_id=project_id,
                agent_type_name="agent",  # conflicts before principal insertion
                principal_kind="oidc_sub",
                external_ref="must-not-persist",
                api_key_secret=None,
                grants=(OnboardingGrant(ProjectRole.DATA),),
            )
        with pool.connection() as conn:
            assert conn.execute("SELECT count(*) FROM principal").fetchone() == (1,)
            assert conn.execute("SELECT count(*) FROM agent_registration").fetchone() == (1,)
    finally:
        if pool is not None:
            pool.close()
        admin.execute(f'DROP DATABASE IF EXISTS "{scratch}" WITH (FORCE)')
        admin.close()
