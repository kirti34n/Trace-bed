"""The one supported PostgreSQL HBA profile for the Compose-v1 topology.

The profile is deliberately a closed deployment contract, not a generic HBA
parser.  Bootstrap uses it to prove the checked-in file was loaded before it
can publish a runtime LOGIN, and again before active retries or rollback.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from tracebed.domain.errors import ConfigError

COMPOSE_V1_PROFILE: Final = "compose-v1"
HBA_PROFILE_ENV: Final = "TB_PG_HBA_PROFILE"
LEGACY_INGRESS_ENV: Final = "TB_0011_INGRESS_QUARANTINED"
COMPOSE_HBA_FILE: Final = "/etc/postgresql/pg_hba.conf"
_CHECKED_HBA_FILE: Final = Path(__file__).resolve().parents[4] / "docker/postgres/pg_hba.conf"
_COMPOSE_V1_HBA_TEXT: Final = """local   replication     all                                         reject
local   all             tracebed_owner                             scram-sha-256
local   all             all                                         reject
host    tracebed        tracebed_owner                             10.77.10.0/29          scram-sha-256
host    tracebed        tracebed_api                               10.77.11.0/29          scram-sha-256
host    tracebed        tracebed_worker                            10.77.12.0/29          scram-sha-256
host    tracebed        tracebed_erasure                           10.77.16.0/29          scram-sha-256
host    tracebed        "/^tracebed_bootstrap_probe_[0-9a-f]{32}$" 10.77.13.0/29         scram-sha-256
host    replication     all                                         0.0.0.0/0               reject
host    replication     all                                         ::/0                    reject
host    all             all                                         0.0.0.0/0               reject
host    all             all                                         ::/0                    reject
"""


@dataclass(frozen=True, slots=True)
class HbaRule:
    """One normalized ``pg_hba_file_rules`` row in its required order."""

    line_number: int
    type: str
    database: tuple[str, ...]
    user_name: tuple[str, ...]
    address: str | None
    netmask: str | None
    auth_method: str
    options: tuple[str, ...]
    error: str | None


COMPOSE_V1_RULES: Final[tuple[HbaRule, ...]] = (
    HbaRule(1, "local", ("replication",), ("all",), None, None, "reject", (), None),
    HbaRule(2, "local", ("all",), ("tracebed_owner",), None, None, "scram-sha-256", (), None),
    HbaRule(3, "local", ("all",), ("all",), None, None, "reject", (), None),
    HbaRule(
        4,
        "host",
        ("tracebed",),
        ("tracebed_owner",),
        "10.77.10.0",
        "255.255.255.248",
        "scram-sha-256",
        (),
        None,
    ),
    HbaRule(
        5,
        "host",
        ("tracebed",),
        ("tracebed_api",),
        "10.77.11.0",
        "255.255.255.248",
        "scram-sha-256",
        (),
        None,
    ),
    HbaRule(
        6,
        "host",
        ("tracebed",),
        ("tracebed_worker",),
        "10.77.12.0",
        "255.255.255.248",
        "scram-sha-256",
        (),
        None,
    ),
    HbaRule(
        7,
        "host",
        ("tracebed",),
        ("tracebed_erasure",),
        "10.77.16.0",
        "255.255.255.248",
        "scram-sha-256",
        (),
        None,
    ),
    HbaRule(
        8,
        "host",
        ("tracebed",),
        ("/^tracebed_bootstrap_probe_[0-9a-f]{32}$",),
        "10.77.13.0",
        "255.255.255.248",
        "scram-sha-256",
        (),
        None,
    ),
    HbaRule(
        9, "host", ("replication",), ("all",), "0.0.0.0", "0.0.0.0", "reject", (), None  # noqa: S104 - exact HBA reject fence
    ),
    HbaRule(10, "host", ("replication",), ("all",), "::", "::", "reject", (), None),
    HbaRule(
        11, "host", ("all",), ("all",), "0.0.0.0", "0.0.0.0", "reject", (), None  # noqa: S104 - exact HBA reject fence
    ),
    HbaRule(12, "host", ("all",), ("all",), "::", "::", "reject", (), None),
)

_HBA_RULES_SQL: Final = """
SELECT line_number, type, database, user_name, address, netmask, auth_method, options, error
FROM pg_hba_file_rules
ORDER BY line_number
"""
_RELOAD_SQL: Final = "SELECT pg_reload_conf()"
_HBA_FILE_SQL: Final = "SHOW hba_file"
_HBA_CONTENT_SQL: Final = "SELECT pg_read_file(current_setting('hba_file'))"


def checked_hba_text() -> str:
    """Return the canonical profile and detect source-tree drift when present.

    Runtime wheels intentionally do not package Docker deployment files.  The
    canonical bytes therefore live with the attestor, while a source checkout
    must have the checked mount file byte-identical to those bytes.
    """

    if _CHECKED_HBA_FILE.exists():
        try:
            if _CHECKED_HBA_FILE.read_text(encoding="utf-8") != _COMPOSE_V1_HBA_TEXT:
                raise ConfigError("compose-v1 HBA profile is unavailable")
        except OSError:
            raise ConfigError("compose-v1 HBA profile is unavailable") from None
    return _COMPOSE_V1_HBA_TEXT


def require_compose_v1_profile(environment: Mapping[str, str] | None = None) -> None:
    """Reject every ambient replacement for the one supported profile."""

    values = os.environ if environment is None else environment
    try:
        legacy_present = LEGACY_INGRESS_ENV in values
        profile = values.get(HBA_PROFILE_ENV)
    except Exception:
        raise ConfigError("compose-v1 HBA profile is required") from None
    if legacy_present or profile != COMPOSE_V1_PROFILE:
        raise ConfigError("compose-v1 HBA profile is required")


def _array(value: object) -> tuple[str, ...] | None:
    if value is None:
        return ()
    if not isinstance(value, (list, tuple)) or not all(isinstance(item, str) for item in value):
        return None
    return tuple(value)


def _text(value: object) -> str | None:
    return value if isinstance(value, str) else None


def _rule_from_row(row: object) -> HbaRule | None:
    if not isinstance(row, (list, tuple)) or len(row) != 9:
        return None
    line_number, rule_type, database, user_name, address, netmask, auth_method, options, error = row
    normalized_database = _array(database)
    normalized_user_name = _array(user_name)
    normalized_options = _array(options)
    if (
        not isinstance(line_number, int)
        or not isinstance(rule_type, str)
        or normalized_database is None
        or normalized_user_name is None
        or (address is not None and not isinstance(address, str))
        or (netmask is not None and not isinstance(netmask, str))
        or not isinstance(auth_method, str)
        or normalized_options is None
        or (error is not None and not isinstance(error, str))
    ):
        return None
    return HbaRule(
        line_number,
        rule_type,
        normalized_database,
        normalized_user_name,
        address,
        netmask,
        auth_method,
        normalized_options,
        error,
    )


def attest_compose_v1_hba(connection: Any, *, reload: bool) -> None:
    """Prove the loaded server HBA is the committed Compose-v1 profile."""

    try:
        with connection.cursor() as cursor:
            if reload:
                cursor.execute(_RELOAD_SQL)
                if cursor.fetchone() != (True,):
                    raise RuntimeError("HBA reload failed")
            cursor.execute(_HBA_FILE_SQL)
            hba_file = cursor.fetchone()
            cursor.execute(_HBA_CONTENT_SQL)
            hba_content = cursor.fetchone()
            cursor.execute(_HBA_RULES_SQL)
            rows = cursor.fetchall()
    except ConfigError:
        raise
    except Exception:
        raise ConfigError("compose-v1 HBA attestation failed") from None
    if hba_file != (COMPOSE_HBA_FILE,) or hba_content != (checked_hba_text(),):
        raise ConfigError("compose-v1 HBA attestation failed")
    actual = tuple(_rule_from_row(row) for row in rows)
    if actual != COMPOSE_V1_RULES:
        raise ConfigError("compose-v1 HBA attestation failed")
