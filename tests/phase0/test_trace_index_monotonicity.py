"""`upsert_trace_index`'s ON CONFLICT merge must not let a later trace event overwrite the
identity evidence `workers.independence` resolves a `ShadowConfirmation` from (PLAN.md
invariant 7 / D-020), and must not pin a run at `ABSENT_SIGNATURE` because its batches arrived
out of order. Chunk trace-index-monotonicity.

Before this fix, `submitter_principal` and `input_signature_hash` were bound straight from
`EXCLUDED` on conflict while their siblings `arm`, `started_at`, and `outcome_status` all had
deliberate monotonicity rules -- a retry, a duplicate delivery, or a late batch for the same run
could silently rewrite the very evidence that decides whether a quarantined memory gets promoted.

There is no Postgres in this environment (PLAN.md's harness notes), so this file proves the fix
two ways, and the second way is the one that matters:

1. STRUCTURALLY -- parses the literal generated SQL and asserts the merge rule each identity
   column got, plus that the pre-existing rules for `arm`/`started_at`/`outcome_status` are
   untouched.
2. BEHAVIOURALLY -- against an in-memory `trace_index` stand-in whose merge is INTERPRETED FROM
   `repo._TRACE_INDEX_UPSERT_SQL`'s own `DO UPDATE SET` clause (`_MergeRules` below), driven
   through the real `Repo.upsert_trace_index`. This is deliberate: a fake that hardcoded
   "identity columns are first-write-wins" would pass identically against the buggy SQL, which
   is the shape of test that let this defect survive 4,000 others. Editing the SQL back to
   `submitter_principal = EXCLUDED.submitter_principal` turns these tests red because the fake
   reads that assignment and obeys it.

The asymmetry the interpreter exposes, and the reason this file exists in its current form:
`submitter_principal` is first-write-wins, but `input_signature_hash` CANNOT be, because it has
a sentinel (`domain.signatures.ABSENT_SIGNATURE`) that `trace_writer._identity_columns` writes
whenever a batch does not carry the run's `run_start`. A plain first-write-wins COALESCE on a
`NOT NULL` column would keep that sentinel forever, and `same_cluster` refuses ABSENT_SIGNATURE
against everything -- so delivery order alone would decide whether a legitimate run can ever
corroborate anything. Its rule is a one-way upgrade instead.
"""

from __future__ import annotations

import logging
import re
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from typing import Any

import pytest

from tracebed.domain.clock import FakeClock
from tracebed.domain.enums import InstrumentationSource, TraceOutcomeStatus
from tracebed.domain.ids import AgentTypeId, PrincipalId, ProjectId, RunId, mint_run_id
from tracebed.domain.signatures import ABSENT_SIGNATURE
from tracebed.stores.pg import repo as repo_module
from tracebed.stores.pg.repo import Repo
from tracebed.stores.pg.rows import TraceIndexUpsert

pytestmark = pytest.mark.phase0

EPOCH = datetime(2026, 1, 1, tzinfo=UTC)
PROJECT = ProjectId(uuid.UUID("33333333-3333-3333-3333-333333333333"))
AGENT_TYPE = AgentTypeId(uuid.uuid4())
REAL_SIG_A = bytes(range(40))
REAL_SIG_B = bytes(range(40, 80))


def _upsert(
    *,
    run_id: RunId,
    principal: PrincipalId,
    signature: bytes,
    agent_type_id: AgentTypeId = AGENT_TYPE,
    started_at: datetime | None = EPOCH,
    outcome_status: TraceOutcomeStatus = TraceOutcomeStatus.PENDING,
) -> TraceIndexUpsert:
    return TraceIndexUpsert(
        run_id=run_id,
        agent_type_id=agent_type_id,
        workflow_template_id=None,
        submitter_principal=principal,
        input_signature_hash=signature,
        instrumentation_source=InstrumentationSource.SDK,
        path=None,
        started_at=started_at,
        ended_at=None,
        payload_ref=None,
        outcome_status=outcome_status,
    )


# --------------------------------------------------------------------------------------- #
# The merge interpreter. Reads `_TRACE_INDEX_UPSERT_SQL`'s own DO UPDATE SET clause and
# evaluates it against (existing row, EXCLUDED row). Only the four expression shapes the
# statement actually uses are implemented; anything else raises rather than being guessed,
# so a future merge rule has to be taught to this file instead of silently defaulting to
# whatever the fake felt like doing. That refusal is the whole point -- it is what stops this
# stand-in from drifting back into asserting its own behaviour.
# --------------------------------------------------------------------------------------- #

_SET_TARGET = re.compile(r"^([a-z_]+) = (.*)$", re.DOTALL)


def _split_top_level(clause: str) -> list[str]:
    """Split a SET clause on commas that are not inside parentheses."""
    parts: list[str] = []
    depth = 0
    current: list[str] = []
    for ch in clause:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append("".join(current))
            current = []
            continue
        current.append(ch)
    parts.append("".join(current))
    return [p.strip() for p in parts if p.strip()]


def _strip_sql_comments(sql: str) -> str:
    return "\n".join(line for line in sql.splitlines() if not line.strip().startswith("--"))


class _MergeRules:
    """`{column: callable(existing_value, excluded_value) -> merged_value}`, built by parsing
    the real SQL. `arm` is skipped: its expression reads `retrieval_event`, which this
    stand-in has no table for, and this chunk does not touch it."""

    def __init__(self, sql: str) -> None:
        clause = _strip_sql_comments(sql).split("DO UPDATE SET", 1)[1]
        self.expressions: dict[str, str] = {}
        for assignment in _split_top_level(clause):
            match = _SET_TARGET.match(" ".join(assignment.split()))
            assert match is not None, f"unparsable SET assignment: {assignment!r}"
            self.expressions[match.group(1)] = match.group(2).strip()

    def merge(self, column: str, existing: Any, excluded: Any) -> Any:
        expr = self.expressions[column]
        if expr == f"EXCLUDED.{column}":
            return excluded
        if expr == f"COALESCE(trace_index.{column}, EXCLUDED.{column})":
            return excluded if existing is None else existing
        if expr == f"COALESCE(EXCLUDED.{column}, trace_index.{column})":
            return existing if excluded is None else excluded
        # `outcome_status`: CASE WHEN EXCLUDED.x = '<literal>' THEN trace_index.x ELSE EXCLUDED.x
        keep_on_excluded = re.fullmatch(
            rf"CASE WHEN EXCLUDED\.{column} = '([^']*)' "
            rf"THEN trace_index\.{column} ELSE EXCLUDED\.{column} END",
            expr,
        )
        if keep_on_excluded is not None:
            return existing if excluded == keep_on_excluded.group(1) else excluded
        # `input_signature_hash`: CASE WHEN trace_index.x = decode('HEX', 'hex')
        #                              THEN EXCLUDED.x ELSE trace_index.x END
        upgrade_from_sentinel = re.fullmatch(
            rf"CASE WHEN trace_index\.{column} = decode\('([0-9a-f]*)', 'hex'\) "
            rf"THEN EXCLUDED\.{column} ELSE trace_index\.{column} END",
            expr,
        )
        if upgrade_from_sentinel is not None:
            sentinel = bytes.fromhex(upgrade_from_sentinel.group(1))
            return excluded if existing == sentinel else existing
        raise AssertionError(
            f"the merge rule for {column} changed to an expression this test cannot evaluate: "
            f"{expr!r} -- teach `_MergeRules.merge` the new shape rather than deleting the case"
        )


_MERGED_COLUMNS = (
    "agent_type_id",
    "submitter_principal",
    "input_signature_hash",
    "started_at",
    "outcome_status",
)


class _FakeCursor:
    def __init__(self, row: Any) -> None:
        self._row = row

    def fetchone(self) -> Any:
        return self._row

    def fetchall(self) -> list[Any]:
        return []

    def __enter__(self) -> _FakeCursor:
        return self

    def __exit__(self, *exc: object) -> None:
        return None


class _TraceIndexFakeConnection:
    def __init__(
        self, log: list[tuple[str, Any]], table: dict[tuple[str, str], dict[str, Any]]
    ) -> None:
        self._log = log
        self._table = table
        self._rules = _MergeRules(repo_module._TRACE_INDEX_UPSERT_SQL)

    def execute(self, sql: str, params: Any = None) -> _FakeCursor:
        self._log.append((sql, params))
        if "INSERT INTO trace_index" in sql:
            key = (str(params["project_id"]), str(params["run_id"]))
            excluded = {
                "agent_type_id": params["agent_type_id"],
                "submitter_principal": params["submitter_principal"],
                "input_signature_hash": bytes(params["input_signature_hash"]),
                "started_at": params["started_at"],
                "outcome_status": params["outcome_status"],
            }
            existing = self._table.get(key)
            if existing is None:
                self._table[key] = dict(excluded)
            else:
                for column in _MERGED_COLUMNS:
                    existing[column] = self._rules.merge(
                        column, existing[column], excluded[column]
                    )
            return _FakeCursor(None)
        if "SELECT submitter_principal, input_signature_hash FROM trace_index" in sql:
            key = (str(params["project_id"]), str(params["run_id"]))
            row = self._table.get(key)
            if row is None:
                return _FakeCursor(None)
            kept_principal = uuid.UUID(str(row["submitter_principal"]))
            return _FakeCursor((kept_principal, row["input_signature_hash"]))
        return _FakeCursor(None)

    def cursor(self, name: str | None = None, **kwargs: Any) -> _FakeCursor:
        return _FakeCursor(None)

    @contextmanager
    def transaction(self) -> Iterator[_TraceIndexFakeConnection]:
        yield self


class _TraceIndexFakePool:
    def __init__(self) -> None:
        self.log: list[tuple[str, Any]] = []
        self.table: dict[tuple[str, str], dict[str, Any]] = {}

    @contextmanager
    def connection(self) -> Iterator[_TraceIndexFakeConnection]:
        yield _TraceIndexFakeConnection(self.log, self.table)


def _repo() -> tuple[Repo, _TraceIndexFakePool]:
    pool = _TraceIndexFakePool()
    return Repo(pool, FakeClock(EPOCH)), pool  # type: ignore[arg-type]


# --------------------------------------------------------------------------------------- #
# The interpreter is only trustworthy if it really does read the SQL. These two prove it:
# the first shows it produces the CURRENT rule, the second replays the literal pre-fix SQL
# through the same interpreter and shows the old text produces the old (wrong) answer.
# --------------------------------------------------------------------------------------- #


def test_the_merge_interpreter_reads_the_real_statement() -> None:
    rules = _MergeRules(repo_module._TRACE_INDEX_UPSERT_SQL)
    assert rules.merge("submitter_principal", "first", "second") == "first"
    assert rules.merge("input_signature_hash", REAL_SIG_A, REAL_SIG_B) == REAL_SIG_A
    assert rules.merge("input_signature_hash", ABSENT_SIGNATURE, REAL_SIG_B) == REAL_SIG_B
    assert rules.merge("outcome_status", "ok", TraceOutcomeStatus.PENDING.value) == "ok"


def test_reverting_the_fix_makes_the_interpreter_report_the_original_defect() -> None:
    """The anti-tautology control. If the SET clause goes back to plain `EXCLUDED.<col>`, the
    stand-in the behavioural tests run against starts overwriting identity again -- which is
    what makes those tests capable of failing at all.
    """
    old_sql = repo_module._TRACE_INDEX_UPSERT_SQL.replace(
        "submitter_principal = COALESCE(trace_index.submitter_principal, "
        "EXCLUDED.submitter_principal)",
        "submitter_principal = EXCLUDED.submitter_principal",
    )
    assert old_sql != repo_module._TRACE_INDEX_UPSERT_SQL, "the fix's text was not found to revert"
    assert _MergeRules(old_sql).merge("submitter_principal", "first", "second") == "second"


# --------------------------------------------------------------------------------------- #
# Behavioural: the first write survives a later, differing claim.
# --------------------------------------------------------------------------------------- #


def test_first_submitter_and_signature_survive_a_later_differing_upsert() -> None:
    """A retry, a duplicate delivery, or a late batch for the SAME run must not rewrite the
    identity `workers.independence.build_confirmations` resolves a `ShadowConfirmation` from.
    """
    repo, pool = _repo()
    run_id = mint_run_id()
    principal_a = PrincipalId(uuid.uuid4())
    principal_b = PrincipalId(uuid.uuid4())

    repo.upsert_trace_index(
        PROJECT, _upsert(run_id=run_id, principal=principal_a, signature=REAL_SIG_A)
    )
    repo.upsert_trace_index(
        PROJECT, _upsert(run_id=run_id, principal=principal_b, signature=REAL_SIG_B)
    )

    kept = pool.table[(str(PROJECT), str(run_id))]
    assert kept["submitter_principal"] == principal_a, (
        "the SECOND upsert's principal overwrote the first -- first-write-wins is broken"
    )
    assert kept["input_signature_hash"] == REAL_SIG_A, (
        "the SECOND upsert's signature overwrote the first -- a real signature must never be "
        "replaced by another real signature"
    )


def test_agent_type_id_is_pinned_by_the_first_write() -> None:
    """`agent_type_id` is an INPUT to `domain.signatures.input_signature_hash`, so a later
    batch moving it would move the cluster the next computed signature lands in.
    """
    repo, pool = _repo()
    run_id = mint_run_id()
    principal = PrincipalId(uuid.uuid4())
    other_type = AgentTypeId(uuid.uuid4())

    repo.upsert_trace_index(
        PROJECT, _upsert(run_id=run_id, principal=principal, signature=REAL_SIG_A)
    )
    repo.upsert_trace_index(
        PROJECT,
        _upsert(
            run_id=run_id, principal=principal, signature=REAL_SIG_A, agent_type_id=other_type
        ),
    )

    assert pool.table[(str(PROJECT), str(run_id))]["agent_type_id"] == AGENT_TYPE


def test_matching_later_upsert_is_a_true_no_op_for_identity() -> None:
    """A retry that resubmits the SAME identity (the ordinary at-least-once case) must not be
    mistaken for a conflict -- only a DIFFERING claim is unusual.
    """
    repo, pool = _repo()
    run_id = mint_run_id()
    principal = PrincipalId(uuid.uuid4())

    repo.upsert_trace_index(
        PROJECT, _upsert(run_id=run_id, principal=principal, signature=REAL_SIG_A)
    )
    repo.upsert_trace_index(
        PROJECT, _upsert(run_id=run_id, principal=principal, signature=REAL_SIG_A)
    )

    kept = pool.table[(str(PROJECT), str(run_id))]
    assert kept["submitter_principal"] == principal
    assert kept["input_signature_hash"] == REAL_SIG_A


# --------------------------------------------------------------------------------------- #
# Behavioural: the ABSENT_SIGNATURE sentinel. This is the half a plain first-write-wins
# COALESCE gets wrong, and the reason `input_signature_hash`'s rule differs from
# `submitter_principal`'s.
# --------------------------------------------------------------------------------------- #


def test_absent_signature_is_upgraded_when_the_run_start_batch_lands_late() -> None:
    """Batch one carries no `run_start`, so `trace_writer._identity_columns` supplies
    ABSENT_SIGNATURE; batch two carries it and supplies the real hash. If the merge kept the
    sentinel (which `NOT NULL` + `COALESCE(trace_index.x, EXCLUDED.x)` would), the run is
    pinned at ABSENT_SIGNATURE forever and `domain.signatures.same_cluster` refuses it against
    everything -- delivery ORDER alone would decide whether the run can corroborate anything.
    """
    repo, pool = _repo()
    run_id = mint_run_id()
    principal = PrincipalId(uuid.uuid4())

    repo.upsert_trace_index(
        PROJECT, _upsert(run_id=run_id, principal=principal, signature=ABSENT_SIGNATURE)
    )
    repo.upsert_trace_index(
        PROJECT, _upsert(run_id=run_id, principal=principal, signature=REAL_SIG_A)
    )

    assert pool.table[(str(PROJECT), str(run_id))]["input_signature_hash"] == REAL_SIG_A


def test_the_sentinel_upgrade_is_one_way() -> None:
    """Once a real signature is recorded, a later batch reporting ABSENT_SIGNATURE (a partial
    batch with no `run_start`) must not regress it -- and a SECOND real signature must not
    replace the first, which is the spoofing direction.
    """
    repo, pool = _repo()
    run_id = mint_run_id()
    principal = PrincipalId(uuid.uuid4())

    repo.upsert_trace_index(
        PROJECT, _upsert(run_id=run_id, principal=principal, signature=REAL_SIG_A)
    )
    repo.upsert_trace_index(
        PROJECT, _upsert(run_id=run_id, principal=principal, signature=ABSENT_SIGNATURE)
    )
    assert pool.table[(str(PROJECT), str(run_id))]["input_signature_hash"] == REAL_SIG_A

    repo.upsert_trace_index(
        PROJECT, _upsert(run_id=run_id, principal=principal, signature=REAL_SIG_B)
    )
    assert pool.table[(str(PROJECT), str(run_id))]["input_signature_hash"] == REAL_SIG_A


# --------------------------------------------------------------------------------------- #
# Behavioural: neighbouring monotonicity rules this chunk was warned not to break.
# --------------------------------------------------------------------------------------- #


def test_started_at_is_filled_once_and_then_kept() -> None:
    repo, pool = _repo()
    run_id = mint_run_id()
    principal = PrincipalId(uuid.uuid4())

    repo.upsert_trace_index(
        PROJECT,
        _upsert(run_id=run_id, principal=principal, signature=REAL_SIG_A, started_at=EPOCH),
    )
    later = datetime(2026, 6, 1, tzinfo=UTC)
    repo.upsert_trace_index(
        PROJECT,
        _upsert(run_id=run_id, principal=principal, signature=REAL_SIG_A, started_at=later),
    )

    assert pool.table[(str(PROJECT), str(run_id))]["started_at"] == EPOCH


def test_started_at_is_filled_by_a_later_batch_when_the_first_had_none() -> None:
    """The mirror of the test above, and the reason `started_at`'s COALESCE is correct on a
    NULLABLE column while the same idiom is wrong on `input_signature_hash`.
    """
    repo, pool = _repo()
    run_id = mint_run_id()
    principal = PrincipalId(uuid.uuid4())

    repo.upsert_trace_index(
        PROJECT,
        _upsert(run_id=run_id, principal=principal, signature=ABSENT_SIGNATURE, started_at=None),
    )
    repo.upsert_trace_index(
        PROJECT,
        _upsert(run_id=run_id, principal=principal, signature=REAL_SIG_A, started_at=EPOCH),
    )

    assert pool.table[(str(PROJECT), str(run_id))]["started_at"] == EPOCH


def test_outcome_status_never_regresses_to_pending() -> None:
    repo, pool = _repo()
    run_id = mint_run_id()
    principal = PrincipalId(uuid.uuid4())

    repo.upsert_trace_index(
        PROJECT,
        _upsert(
            run_id=run_id,
            principal=principal,
            signature=REAL_SIG_A,
            outcome_status=TraceOutcomeStatus.OK,
        ),
    )
    # A late partial batch carrying no run_end reports the TraceIndexUpsert default 'pending'.
    repo.upsert_trace_index(
        PROJECT,
        _upsert(
            run_id=run_id,
            principal=principal,
            signature=REAL_SIG_A,
            outcome_status=TraceOutcomeStatus.PENDING,
        ),
    )

    assert pool.table[(str(PROJECT), str(run_id))]["outcome_status"] == TraceOutcomeStatus.OK.value


# --------------------------------------------------------------------------------------- #
# Behavioural: the differing-claim signal (logged, not raised, not silent, not spurious).
# --------------------------------------------------------------------------------------- #


def _warnings(caplog: pytest.LogCaptureFixture) -> list[logging.LogRecord]:
    return [r for r in caplog.records if r.name == repo_module.__name__]


def test_differing_later_claim_is_logged_as_a_signal(caplog: pytest.LogCaptureFixture) -> None:
    """Two different principals (or signature clusters) claiming the same run_id is either a
    retry bug or a Sybil/spoofing attempt against D-020 corroboration -- first-write-wins keeps
    the evidence intact, but the collision itself must be observable, not silently dropped.
    """
    repo, _ = _repo()
    run_id = mint_run_id()
    principal_a = PrincipalId(uuid.uuid4())
    principal_b = PrincipalId(uuid.uuid4())

    repo.upsert_trace_index(
        PROJECT, _upsert(run_id=run_id, principal=principal_a, signature=REAL_SIG_A)
    )
    with caplog.at_level(logging.WARNING, logger=repo_module.__name__):
        repo.upsert_trace_index(
            PROJECT, _upsert(run_id=run_id, principal=principal_b, signature=REAL_SIG_A)
        )

    warnings = _warnings(caplog)
    assert warnings, "a conflicting later identity claim was not logged anywhere"
    message = warnings[0].getMessage()
    assert str(run_id) in message
    assert str(principal_a) in message
    assert str(principal_b) in message


def test_a_second_real_signature_on_the_same_run_is_logged(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The signature leg of the same signal: same principal, a DIFFERENT real input signature.
    The merge keeps the first; the attempt must still be visible.
    """
    repo, _ = _repo()
    run_id = mint_run_id()
    principal = PrincipalId(uuid.uuid4())

    repo.upsert_trace_index(
        PROJECT, _upsert(run_id=run_id, principal=principal, signature=REAL_SIG_A)
    )
    with caplog.at_level(logging.WARNING, logger=repo_module.__name__):
        repo.upsert_trace_index(
            PROJECT, _upsert(run_id=run_id, principal=principal, signature=REAL_SIG_B)
        )

    warnings = _warnings(caplog)
    assert warnings, "a second, different real signature for one run was not logged"
    assert REAL_SIG_B.hex() in warnings[0].getMessage()


def test_matching_later_claim_is_not_logged(caplog: pytest.LogCaptureFixture) -> None:
    """The ordinary at-least-once retry (same identity resubmitted) is not a signal and must
    not spam the log on every duplicate delivery.
    """
    repo, _ = _repo()
    run_id = mint_run_id()
    principal = PrincipalId(uuid.uuid4())

    repo.upsert_trace_index(
        PROJECT, _upsert(run_id=run_id, principal=principal, signature=REAL_SIG_A)
    )
    with caplog.at_level(logging.WARNING, logger=repo_module.__name__):
        repo.upsert_trace_index(
            PROJECT, _upsert(run_id=run_id, principal=principal, signature=REAL_SIG_A)
        )

    assert not _warnings(caplog), "a matching retry must not be logged as a conflict"


def test_an_ordinary_out_of_order_batch_is_not_logged_as_a_conflict(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A batch with no `run_start` supplies ABSENT_SIGNATURE, which is the absence of a claim,
    not a rival one. Warning on it would fire the Sybil signal on the single most common shape
    of at-least-once delivery -- and an alarm that fires on the normal path is one nobody reads.
    """
    repo, _ = _repo()
    run_id = mint_run_id()
    principal = PrincipalId(uuid.uuid4())

    repo.upsert_trace_index(
        PROJECT, _upsert(run_id=run_id, principal=principal, signature=REAL_SIG_A)
    )
    with caplog.at_level(logging.WARNING, logger=repo_module.__name__):
        repo.upsert_trace_index(
            PROJECT, _upsert(run_id=run_id, principal=principal, signature=ABSENT_SIGNATURE)
        )

    assert not _warnings(caplog)


def test_the_late_run_start_upgrade_is_not_logged_as_a_conflict(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The other direction: the sentinel is upgraded to the real signature, so the kept value
    now EQUALS what this call claimed and there is nothing anomalous to report.
    """
    repo, _ = _repo()
    run_id = mint_run_id()
    principal = PrincipalId(uuid.uuid4())

    repo.upsert_trace_index(
        PROJECT, _upsert(run_id=run_id, principal=principal, signature=ABSENT_SIGNATURE)
    )
    with caplog.at_level(logging.WARNING, logger=repo_module.__name__):
        repo.upsert_trace_index(
            PROJECT, _upsert(run_id=run_id, principal=principal, signature=REAL_SIG_A)
        )

    assert not _warnings(caplog)


# --------------------------------------------------------------------------------------- #
# Structural: the generated SQL itself, parsed rather than assumed.
# --------------------------------------------------------------------------------------- #


def _upsert_sql_body() -> str:
    return " ".join(repo_module._TRACE_INDEX_UPSERT_SQL.split())


def test_identity_columns_have_no_unconditional_excluded_assignment() -> None:
    """The exact defect this chunk fixes: `submitter_principal`/`input_signature_hash` bound
    straight from `EXCLUDED` with no merge rule at all.
    """
    body = _upsert_sql_body()
    assert "submitter_principal = EXCLUDED.submitter_principal" not in body
    assert "input_signature_hash = EXCLUDED.input_signature_hash" not in body
    assert "agent_type_id = EXCLUDED.agent_type_id" not in body
    assert (
        "submitter_principal = COALESCE(trace_index.submitter_principal, "
        "EXCLUDED.submitter_principal)" in body
    )
    assert (
        "agent_type_id = COALESCE(trace_index.agent_type_id, EXCLUDED.agent_type_id)" in body
    )


def test_the_signature_sentinel_literal_comes_from_domain_signatures() -> None:
    """Hand-typing 80 zeros here would let the SQL's idea of "absent" drift from
    `domain.signatures.ABSENT_SIGNATURE`, and the drift would be invisible: the CASE would
    simply stop matching and the upgrade branch would never fire again.
    """
    body = _upsert_sql_body()
    assert f"decode('{ABSENT_SIGNATURE.hex()}', 'hex')" in body
    assert (
        "input_signature_hash = CASE WHEN trace_index.input_signature_hash = "
        f"decode('{ABSENT_SIGNATURE.hex()}', 'hex') THEN EXCLUDED.input_signature_hash "
        "ELSE trace_index.input_signature_hash END" in body
    )


def test_every_conflict_target_has_a_deliberate_rule() -> None:
    """No column may be added to the DO UPDATE SET list without a merge rule this file
    recognises. `arm` is the one exception -- its expression is a server-side subquery against
    `retrieval_event`, checked separately below.
    """
    rules = _MergeRules(repo_module._TRACE_INDEX_UPSERT_SQL)
    insert_columns = {
        c.strip()
        for c in _upsert_sql_body()
        .split("INSERT INTO trace_index (", 1)[1]
        .split(")", 1)[0]
        .split(",")
    }
    # The conflict key itself is never reassigned; everything else must have a rule.
    assert set(rules.expressions) == insert_columns - {"project_id", "run_id"}
    for column, expr in rules.expressions.items():
        if column == "arm":
            assert "SELECT re.arm FROM retrieval_event re" in " ".join(expr.split())
            continue
        assert "EXCLUDED" in expr or "trace_index." in expr, (
            f"{column} has no merge rule referencing either row: {expr!r}"
        )


def test_neighbouring_monotonicity_rules_are_unchanged() -> None:
    """This chunk touches the identity columns only -- `arm`, `started_at`, and
    `outcome_status`'s pre-existing merge rules must survive untouched.
    """
    body = _upsert_sql_body()
    assert "started_at = COALESCE(trace_index.started_at, EXCLUDED.started_at)" in body
    assert "ended_at = COALESCE(EXCLUDED.ended_at, trace_index.ended_at)" in body
    assert (
        f"outcome_status = CASE WHEN EXCLUDED.outcome_status = "
        f"'{TraceOutcomeStatus.PENDING.value}' THEN trace_index.outcome_status "
        "ELSE EXCLUDED.outcome_status END" in body
    )
    assert "arm = COALESCE(" in body
    assert body.rstrip().endswith("), trace_index.arm)")
    assert "SELECT re.arm FROM retrieval_event re" in body
    assert "%(arm)s" not in body
    # Postgres rejects two assignments to the same column in one DO UPDATE SET -- a duplicate
    # SET target here would fail every upsert outright, not just this chunk's two columns.
    targets = list(_MergeRules(repo_module._TRACE_INDEX_UPSERT_SQL).expressions)
    assert len(targets) == len(set(targets)), f"duplicate SET targets: {targets}"


def test_upsert_template_has_no_unsubstituted_placeholder() -> None:
    """Guards the same invariant `repo.py`'s own import-time assertion does -- if that guard
    is ever weakened, this test still catches a literal `@TOKEN@` reaching the SQL psycopg
    would actually execute.
    """
    assert "@" not in repo_module._TRACE_INDEX_UPSERT_SQL
