"""Exact Compose-v1 HBA profile and live-attestation regressions."""

from __future__ import annotations

from collections import deque
from collections.abc import Iterator
from contextlib import contextmanager

import pytest

from tracebed.domain.errors import ConfigError
from tracebed.stores.pg import hba

pytestmark = pytest.mark.phase1


class _Cursor:
    def __init__(self, connection: _Connection) -> None:
        self._connection = connection

    def execute(self, query: str) -> None:
        self._connection.queries.append(query)

    def fetchone(self) -> tuple[object, ...] | None:
        return self._connection.rows.popleft()

    def fetchall(self) -> list[tuple[object, ...]]:
        return self._connection.rules


class _Connection:
    def __init__(self, rows: list[tuple[object, ...]], rules: list[tuple[object, ...]]) -> None:
        self.rows = deque(rows)
        self.rules = rules
        self.queries: list[str] = []

    @contextmanager
    def cursor(self) -> Iterator[_Cursor]:
        yield _Cursor(self)


def _actual_rows() -> list[tuple[object, ...]]:
    return [
        (
            rule.line_number,
            rule.type,
            list(rule.database),
            list(rule.user_name),
            rule.address,
            rule.netmask,
            rule.auth_method,
            list(rule.options),
            rule.error,
        )
        for rule in hba.COMPOSE_V1_RULES
    ]


def test_checked_compose_hba_has_the_exact_closed_ordered_profile() -> None:
    lines = hba.checked_hba_text().splitlines()
    assert len(lines) == 12
    assert all(line and not line.lstrip().startswith("#") for line in lines)
    assert "tracebed_owner" in lines[3]
    assert "tracebed_api" in lines[4]
    assert "tracebed_worker" in lines[5]
    assert "tracebed_erasure" in lines[6] and "10.77.16.0/29" in lines[6]
    assert "tracebed_bootstrap_probe_" in lines[7]
    assert "0.0.0.0/0" in lines[8] and lines[8].endswith("reject")
    assert "::/0" in lines[9] and lines[9].endswith("reject")
    assert "0.0.0.0/0" in lines[10] and lines[10].endswith("reject")
    assert "::/0" in lines[11] and lines[11].endswith("reject")


def test_attestation_requires_reloaded_exact_file_content_and_all_live_rows() -> None:
    connection = _Connection(
        [(True,), (hba.COMPOSE_HBA_FILE,), (hba.checked_hba_text(),)], _actual_rows()
    )

    hba.attest_compose_v1_hba(connection, reload=True)

    assert connection.queries == [
        hba._RELOAD_SQL,
        hba._HBA_FILE_SQL,
        hba._HBA_CONTENT_SQL,
        hba._HBA_RULES_SQL,
    ]


@pytest.mark.parametrize(
    "rows,rules",
    (
        ([(True,), ("/unsafe/hba.conf",), (hba.checked_hba_text(),)], _actual_rows()),
        ([(True,), (hba.COMPOSE_HBA_FILE,), ("include extra.conf\n",)], _actual_rows()),
        (
            [(True,), (hba.COMPOSE_HBA_FILE,), (hba.checked_hba_text(),)],
            [*_actual_rows()[1:], _actual_rows()[0]],
        ),
        (
            [(True,), (hba.COMPOSE_HBA_FILE,), (hba.checked_hba_text(),)],
            _actual_rows()[:-1],
        ),
        (
            [(True,), (hba.COMPOSE_HBA_FILE,), (hba.checked_hba_text(),)],
            [*_actual_rows(), _actual_rows()[-1]],
        ),
        (
            [(True,), (hba.COMPOSE_HBA_FILE,), (hba.checked_hba_text(),)],
            [
                *_actual_rows()[:-1],
                (*_actual_rows()[-1][:-1], "invalid HBA syntax"),
            ],
        ),
    ),
)
def test_attestation_rejects_wrong_path_content_reorder_or_missing_rule(
    rows: list[tuple[object, ...]], rules: list[tuple[object, ...]]
) -> None:
    with pytest.raises(ConfigError, match="compose-v1 HBA attestation failed"):
        hba.attest_compose_v1_hba(_Connection(rows, rules), reload=True)


@pytest.mark.parametrize(
    "environment",
    (
        {},
        {hba.HBA_PROFILE_ENV: "other"},
        {hba.HBA_PROFILE_ENV: hba.COMPOSE_V1_PROFILE, hba.LEGACY_INGRESS_ENV: "true"},
    ),
)
def test_profile_requires_only_exact_compose_v1_without_legacy_override(
    environment: dict[str, str]
) -> None:
    with pytest.raises(ConfigError, match="compose-v1 HBA profile is required"):
        hba.require_compose_v1_profile(environment)


def test_profile_accepts_the_one_supported_value() -> None:
    hba.require_compose_v1_profile({hba.HBA_PROFILE_ENV: hba.COMPOSE_V1_PROFILE})


def test_attestation_fails_closed_when_postgres_reports_reload_failure() -> None:
    with pytest.raises(ConfigError, match="compose-v1 HBA attestation failed"):
        hba.attest_compose_v1_hba(
            _Connection(
                [(False,), (hba.COMPOSE_HBA_FILE,), (hba.checked_hba_text(),)], _actual_rows()
            ),
            reload=True,
        )
