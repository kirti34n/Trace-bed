"""Unambiguous PostgreSQL URL contract for authority migration work.

The authority/bootstrap path opens both psycopg and yoyo connections.  They
must derive the endpoint and identity from exactly the same URL authority and
database path; a query key that can override libpq coordinates would make
that statement false. Runtime validation additionally asks libpq's parser of
record for its no-connection interpretation before a pool is constructed.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from ipaddress import IPv6Address
from typing import Final
from urllib.parse import SplitResult, parse_qsl, unquote, unquote_to_bytes, urlsplit

from psycopg.conninfo import conninfo_to_dict

_POSTGRES_SCHEMES = frozenset(("postgresql", "postgres"))
_FORBIDDEN_QUERY_KEYS = frozenset(
    (
        "user",
        "password",
        "host",
        "hostaddr",
        "port",
        "dbname",
        "database",
        "service",
        "servicefile",
        "passfile",
        "options",
    )
)

API_DB_DSN_ENV: Final = "TB_API_DB_DSN"
WORKER_DB_DSN_ENV: Final = "TB_WORKER_DB_DSN"
ERASURE_DB_DSN_ENV: Final = "TB_ERASURE_DB_DSN"
_RUNTIME_DSN_ENV_BY_ROLE: Final = {
    "tracebed_api": API_DB_DSN_ENV,
    "tracebed_worker": WORKER_DB_DSN_ENV,
    "tracebed_erasure": ERASURE_DB_DSN_ENV,
}
_RUNTIME_FORBIDDEN_ENV: Final = frozenset(
    (
        "TB_STORAGE__PG_DSN",
        "TB_STORAGE__ADMIN_PG_DSN",
        "TB_STORAGE__OWNER_PG_DSN",
        "TB_BOOTSTRAP_PG_DSN",
        "TB_BOOTSTRAP_DB_DSN",
        "TB_BOOTSTRAP_DSN",
        "TB_ONBOARDING_PG_DSN",
        "TB_ONBOARDING_DB_DSN",
        "TB_OWNER_DB_DSN",
        "TB_OWNER_PG_DSN",
        "TB_ADMIN_DB_DSN",
        "TB_ADMIN_PG_DSN",
        "TB_ADMIN_DSN",
        "TB_APP_DB_DSN",
        "TB_APP_PG_DSN",
        "TB_APP_PASSWORD",
        "TB_APP_ROLE_PASSWORD",
        "TB_PG_PASSWORD",
        "TB_M4_ADMIN_PG_DSN",
        "DATABASE_URL",
        "POSTGRES_URL",
        "POSTGRESQL_URL",
        "POSTGRES_DSN",
        "DB_URL",
        "DB_DSN",
    )
)
_RUNTIME_FORBIDDEN_ENV_CASEFOLD: Final = frozenset(
    key.casefold() for key in _RUNTIME_FORBIDDEN_ENV
)
_RUNTIME_TRANSPORT_QUERY_KEYS: Final = frozenset(
    (
        "channel_binding",
        "connect_timeout",
        "gssencmode",
        "keepalives",
        "keepalives_count",
        "keepalives_idle",
        "keepalives_interval",
        "require_auth",
        "sslcert",
        "sslcrl",
        "sslcrldir",
        "sslkey",
        "sslmode",
        "sslnegotiation",
        "sslrootcert",
        "target_session_attrs",
        "tcp_user_timeout",
    )
)


@dataclass(frozen=True, slots=True, repr=False)
class RuntimeDsn:
    """One validated, process-private runtime database credential.

    The URL is intentionally not rendered by ``repr``.  Startup diagnostics
    report only the identity class, never a URL, password, host, or database.
    """

    value: str
    role: str


class RuntimeDsnError(ValueError):
    """Opaque runtime credential configuration failure."""


def _runtime_dsn_error() -> RuntimeDsnError:
    return RuntimeDsnError("runtime database credential configuration is invalid")


def parse_runtime_dsn(value: object, *, expected_role: str) -> RuntimeDsn:
    """Validate the one unambiguous URL allowed to a runtime identity.

    This is deliberately stricter than the migration parser: runtime clients
    may not use libpq indirection (``service``/``passfile``), caller options,
    coordinate query overrides, encoded identity/host/database fields, or a
    URL whose credential names a different process identity.
    """

    if expected_role not in _RUNTIME_DSN_ENV_BY_ROLE:
        raise _runtime_dsn_error()
    if not isinstance(value, str) or not value or _invalid_coordinate_text(value):
        raise _runtime_dsn_error()
    try:
        parsed = urlsplit(value)
    except ValueError:
        raise _runtime_dsn_error() from None
    if parsed.scheme not in _POSTGRES_SCHEMES or not parsed.netloc or parsed.fragment:
        raise _runtime_dsn_error()
    if parsed.netloc.count("@") != 1:
        raise _runtime_dsn_error()
    try:
        hostname = parsed.hostname
        port = parsed.port
    except ValueError:
        raise _runtime_dsn_error() from None
    raw_userinfo, authority_host = parsed.netloc.rsplit("@", 1)
    if ":" not in raw_userinfo:
        raise _runtime_dsn_error()
    raw_username, raw_password = raw_userinfo.split(":", 1)
    username = _strict_runtime_decode(raw_username)
    password = _strict_runtime_decode(raw_password)
    raw_hostname, bracketed_ipv6 = _raw_authority_hostname(authority_host)
    database = parsed.path.removeprefix("/")
    if (
        raw_username != expected_role
        or username != expected_role
        or password is None
        or not password
        or not hostname
        or not _validate_hostname(raw_hostname, hostname, bracketed_ipv6)
        or authority_host.endswith(":")
        or (port is not None and not 1 <= port <= 65535)
        or not parsed.path
        or parsed.path == "/"
        or not parsed.path.startswith("/")
        or "%" in parsed.path
        or "/" in parsed.path[1:]
        or "," in parsed.path
        or _invalid_coordinate_text(parsed.path)
    ):
        raise _runtime_dsn_error()

    query = _runtime_transport_query(parsed.query)
    try:
        libpq = conninfo_to_dict(value)
    except Exception:
        raise _runtime_dsn_error() from None
    expected_coordinates = {
        "user": expected_role,
        "password": password,
        "host": hostname,
        "port": str(port) if port is not None else None,
        "dbname": database,
    }
    if any(libpq.get(key) != expected for key, expected in expected_coordinates.items()):
        raise _runtime_dsn_error()
    if any(libpq.get(key) != query_value for key, query_value in query.items()):
        raise _runtime_dsn_error()
    return RuntimeDsn(value=value, role=expected_role)


def _runtime_transport_query(raw_query: str) -> dict[str, str]:
    """Decode exactly the reviewed, non-coordinate libpq transport keys."""

    if not raw_query:
        return {}
    query: dict[str, str] = {}
    for raw_pair in raw_query.split("&"):
        if not raw_pair or "=" not in raw_pair:
            raise _runtime_dsn_error()
        raw_key, raw_value = raw_pair.split("=", 1)
        key = _strict_runtime_decode(raw_key)
        query_value = _strict_runtime_decode(raw_value)
        if (
            key is None
            or query_value is None
            or not key
            or not query_value
            or raw_key != key
            or key != key.casefold()
            or key not in _RUNTIME_TRANSPORT_QUERY_KEYS
            or key in query
        ):
            raise _runtime_dsn_error()
        query[key] = query_value
    return query


def _strict_runtime_decode(value: str) -> str | None:
    """Percent-decode one userinfo/query token without replacement semantics."""

    if not _valid_percent_escapes(value):
        return None
    try:
        decoded = unquote_to_bytes(value).decode("utf-8", "strict")
    except UnicodeDecodeError:
        return None
    if any(character == "\x00" or character.isprintable() is False for character in decoded):
        return None
    return decoded


def runtime_dsn_from_environment(
    expected_role: str, environment: Mapping[str, str]
) -> RuntimeDsn:
    """Load one exclusive runtime URL before parsing settings or opening a pool.

    A runtime process is deliberately not a general libpq environment.  It
    must inherit exactly one exact-cased URL for its own identity and no
    opposite, owner/bootstrap/onboarding, legacy or ``PG*`` input.  This
    process-environment exclusivity is intentional: clearing variables would
    leave an inherited configuration ambiguity hidden from operators.
    """

    if expected_role not in _RUNTIME_DSN_ENV_BY_ROLE:
        raise _runtime_dsn_error()
    own_key = _RUNTIME_DSN_ENV_BY_ROLE[expected_role]
    own_key_folded = own_key.casefold()
    try:
        environment_keys = tuple(environment)
    except Exception:
        raise _runtime_dsn_error() from None
    if not all(isinstance(key, str) for key in environment_keys):
        raise _runtime_dsn_error()
    own_matches = [key for key in environment_keys if key.casefold() == own_key_folded]
    if (
        own_matches != [own_key]
        or any(
            key.casefold() == dsn_key.casefold()
            for role, dsn_key in _RUNTIME_DSN_ENV_BY_ROLE.items()
            if role != expected_role
            for key in environment_keys
        )
        or any(
            key.casefold() in _RUNTIME_FORBIDDEN_ENV_CASEFOLD
            or key.casefold().startswith("pg")
            for key in environment_keys
        )
    ):
        raise _runtime_dsn_error()
    try:
        own_value = environment[own_key]
    except Exception:
        raise _runtime_dsn_error() from None
    return parse_runtime_dsn(own_value, expected_role=expected_role)


class TrustedAuthorityDsn(str):
    """A bootstrap-composed URL carrying one exact internal options value.

    This is an internal invocation receipt for preventing an accidental
    unsupported runner path, not an unforgeable capability or a security
    boundary against Python code or a database owner. Plain strings are never
    permitted to supply ``options``; only ``trusted_authority_dsn`` creates
    this type after bootstrap rejected all caller options.
    """

    _trusted_options: str

    def __new__(cls, value: str, trusted_options: str) -> TrustedAuthorityDsn:
        instance = super().__new__(cls, value)
        instance._trusted_options = trusted_options
        return instance


def trusted_authority_dsn(value: str, trusted_options: str) -> TrustedAuthorityDsn:
    """Mark a URL whose options were composed by the bootstrap fence."""

    return TrustedAuthorityDsn(value, trusted_options)


def _invalid_coordinate_text(value: str) -> bool:
    """Whether a host/database coordinate contains non-URL-safe text."""

    return any(ord(character) < 32 or character.isspace() for character in value)


def _valid_percent_escapes(value: str) -> bool:
    """Require user-info percent escapes to be unambiguous single-byte escapes."""

    index = 0
    while index < len(value):
        if value[index] != "%":
            index += 1
            continue
        if index + 2 >= len(value) or any(
            character not in "0123456789abcdefABCDEF" for character in value[index + 1 : index + 3]
        ):
            return False
        index += 3
    return True


def _raw_authority_hostname(authority_host: str) -> tuple[str, bool]:
    """Return the raw host token and whether it used bracketed IPv6 syntax."""

    if authority_host.startswith("["):
        closing = authority_host.find("]")
        if closing == -1:
            return "", True
        return authority_host[1:closing], True
    return authority_host.rsplit(":", 1)[0] if ":" in authority_host else authority_host, False


def _validate_hostname(raw_hostname: str, hostname: str, bracketed_ipv6: bool) -> bool:
    """Accept one lowercase, unescaped DNS host or canonical bracketed IPv6 host."""

    if (
        not raw_hostname
        or raw_hostname != hostname
        or "%" in raw_hostname
        or "," in raw_hostname
        or not raw_hostname.isascii()
        or _invalid_coordinate_text(raw_hostname)
    ):
        return False
    if bracketed_ipv6:
        try:
            return str(IPv6Address(raw_hostname)) == raw_hostname
        except ValueError:
            return False
    return all(character.islower() or character.isdigit() or character in ".-" for character in raw_hostname)


def authority_migration_coordinates(dsn: object) -> tuple[str, str | None, str, int | None, str]:
    """Return the validated URL coordinates common to libpq and yoyo 9.

    This function intentionally has no database-client imports. The contract
    test compares its result with both ``psycopg.conninfo_to_dict`` and
    ``yoyo.connections.parse_uri`` so future parser changes cannot silently
    make the bootstrap and migration clients select different identities.
    """

    _dsn, parsed = parse_authority_migration_url(dsn)
    assert parsed.username is not None  # guaranteed by the shared validator
    assert parsed.hostname is not None  # guaranteed by the shared validator
    return (
        unquote(parsed.username),
        unquote(parsed.password) if parsed.password is not None else None,
        parsed.hostname,
        parsed.port,
        parsed.path.removeprefix("/"),
    )


def parse_authority_migration_url(dsn: object) -> tuple[str, SplitResult]:
    """Validate one unambiguous URL before psycopg/yoyo backend selection.

    User, optional password, host, optional port, and database may appear
    only in URI authority/path. The host and database must be unescaped,
    single coordinates because yoyo 9 does not percent-decode those fields
    while libpq does. Percent-escaped user/password are retained only where
    both parsers decode them identically. Query keys are percent-decoded and
    case-normalized before duplicate and forbidden-coordinate checks. Normal
    transport parameters such as ``sslmode`` remain allowed and are retained
    unchanged when the migration runner rewrites only the backend scheme.
    """

    if not isinstance(dsn, str) or _invalid_coordinate_text(dsn):
        raise ValueError("Tracebed migration runner requires an unambiguous PostgreSQL URL DSN")
    try:
        parsed = urlsplit(dsn)
    except ValueError as exc:
        raise ValueError(
            "Tracebed migration runner requires an unambiguous PostgreSQL URL DSN"
        ) from exc
    if parsed.scheme not in _POSTGRES_SCHEMES or not parsed.netloc or parsed.fragment:
        raise ValueError("Tracebed migration runner requires an unambiguous PostgreSQL URL DSN")
    # Reject more than one raw @ separator. A literal @ in a password must be
    # percent-encoded, avoiding divergent authority parsing between clients.
    if parsed.netloc.count("@") != 1:
        raise ValueError("Tracebed migration runner requires an unambiguous PostgreSQL URL DSN")
    try:
        username = parsed.username
        hostname = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise ValueError(
            "Tracebed migration runner requires an unambiguous PostgreSQL URL DSN"
        ) from exc
    authority_host = parsed.netloc.rsplit("@", 1)[1]
    raw_hostname, bracketed_ipv6 = _raw_authority_hostname(authority_host)
    decoded_username = unquote(username) if username is not None else ""
    decoded_password = unquote(parsed.password) if parsed.password is not None else None
    if (
        not username
        or not decoded_username
        or not _valid_percent_escapes(username)
        or (parsed.password is not None and not _valid_percent_escapes(parsed.password))
        or (decoded_password is not None and _invalid_coordinate_text(decoded_password))
        or not hostname
        or not _validate_hostname(raw_hostname, hostname, bracketed_ipv6)
        or authority_host.endswith(":")
        or (port is not None and not 1 <= port <= 65535)
        or not parsed.path
        or parsed.path == "/"
        or "%" in parsed.path
        or "/" in parsed.path[1:]
        or "," in parsed.path
        or _invalid_coordinate_text(parsed.path)
    ):
        raise ValueError("Tracebed migration runner requires an unambiguous PostgreSQL URL DSN")

    try:
        query = parse_qsl(parsed.query, keep_blank_values=True, strict_parsing=True)
    except ValueError as exc:
        raise ValueError(
            "Tracebed migration runner requires an unambiguous PostgreSQL URL DSN"
        ) from exc
    seen: set[str] = set()
    trusted_options = dsn._trusted_options if isinstance(dsn, TrustedAuthorityDsn) else None
    for key, value in query:
        normalized_key = key.casefold()
        if not normalized_key or normalized_key in seen:
            raise ValueError("Tracebed migration runner requires an unambiguous PostgreSQL URL DSN")
        seen.add(normalized_key)
        if normalized_key in _FORBIDDEN_QUERY_KEYS:
            if normalized_key == "options" and trusted_options is not None and value == trusted_options:
                continue
            raise ValueError("Tracebed migration runner requires an unambiguous PostgreSQL URL DSN")
    return str(dsn), parsed
