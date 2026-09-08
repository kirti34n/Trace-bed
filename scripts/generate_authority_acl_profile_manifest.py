#!/usr/bin/env python3
"""Generate the immutable authority-profile fixture from a clean PG18 reference.

This program is deliberately release engineering, not a migration helper.  It
uses a disposable dedicated cluster, applies the real source through 0009,
then runs *generation-only copies* of 0010/0011/rollback. Those copies omit
the checked-in profile literal and their final epoch append, collect the
public normalized actual tuple functions before a profile is accepted, and
seed only those generated rows to permit the next reference transition.

No production migration imports this file, executes its transforms, or has a
runtime switch for this path. The emitted values must be reviewed and are
inserted as literal immutable contract data in 0010.
"""

from __future__ import annotations

import argparse
import contextlib
import sys
from collections.abc import Iterable, Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import psycopg

from tracebed.stores.pg import bootstrap
from tracebed.stores.pg.migrate import apply_migrations, migration_directory

_PROFILES = ("genuine_0010", "cutover_0011", "cutover_0012", "hardened_0010")
_CLASSES = ("acl", "schema")
_FOUNDATION = "0010_authority_foundation.sql"
_CUTOVER = "0011_authority_cutover.sql"
_CUTOVER_ROLLBACK = "0011_authority_cutover.rollback.sql"
_ERASURE = "0012_erasure_saga.sql"
_ERASURE_ROLLBACK = "0012_erasure_saga.rollback.sql"
_MANIFEST_BEGIN = "-- GENERATED_AUTHORITY_ACL_PROFILE_TUPLES_BEGIN"
_MANIFEST_END = "-- GENERATED_AUTHORITY_ACL_PROFILE_TUPLES_END"
_FOUNDATION_SOURCE_PATH = Path(__file__).resolve().parents[1] / "migrations" / _FOUNDATION


def render_manifest(rows: Iterable[tuple[str, str, str]]) -> str:
    """Render sorted normalized tuple hashes as deterministic SQL literals."""

    normalized = tuple(sorted(rows))
    if not normalized or any(
        profile not in _PROFILES
        or tuple_class not in _CLASSES
        or len(digest) != 64
        or any(character not in "0123456789abcdef" for character in digest)
        for profile, tuple_class, digest in normalized
    ):
        raise ValueError("authority profile rows are not canonical")
    if len(set(normalized)) != len(normalized):
        raise ValueError("authority profile rows are not unique")

    lines = [
        "-- Fixture format: tracebed.authority-acl-profile-manifest/v1. Regenerate",
        "-- only from a clean dedicated PG18 reference and review every tuple.",
        "-- Generated from the pinned clean PG18 authority baseline by",
        "-- scripts/generate_authority_acl_profile_manifest.py. These are contract",
        "-- values, not a runtime catalog capture.",
        "INSERT INTO public.authority_acl_profile_tuple (profile, tuple_class, tuple_digest) VALUES",
    ]
    for index, (profile, tuple_class, digest) in enumerate(normalized):
        terminal = ";" if index + 1 == len(normalized) else ","
        lines.append(
            "    "
            f"('{profile}'::public.authority_acl_profile, '{tuple_class}', "
            f"decode('{digest}', 'hex')){terminal}"
        )
    return "\n".join(lines) + "\n"


def _checked_in_manifest_block(source: str) -> str:
    """Return the one literal block, refusing ambiguous source markers."""

    if source.count(_MANIFEST_BEGIN) != 1 or source.count(_MANIFEST_END) != 1:
        raise ValueError("authority profile source must contain one marked fixture block")
    begin = source.index(_MANIFEST_BEGIN) + len(_MANIFEST_BEGIN)
    end = source.index(_MANIFEST_END)
    if end <= begin:
        raise ValueError("authority profile fixture markers are misordered")
    return source[begin:end].strip() + "\n"


def _replace_manifest_block(source: str, rendered: str) -> str:
    """Return one mechanically regenerated source fixture block.

    This is deliberately the only writer for the generated literal.  It
    refuses missing, duplicate, or reordered markers rather than performing a
    broad source rewrite, and callers still need a separately reviewed clean
    PG18 reference to obtain ``rendered``.
    """

    if source.count(_MANIFEST_BEGIN) != 1 or source.count(_MANIFEST_END) != 1:
        raise ValueError("authority profile source must contain one marked fixture block")
    begin = source.index(_MANIFEST_BEGIN) + len(_MANIFEST_BEGIN)
    end = source.index(_MANIFEST_END)
    if end <= begin:
        raise ValueError("authority profile fixture markers are misordered")
    return source[:begin] + "\n" + rendered + source[end:]


def _apply_through_0009(dsn: str) -> None:
    """Apply only real 0001..0009 through Tracebed's atomic runner."""

    apply_migrations(dsn, through="0009_trace_index_terminal_freeze")


def _source(name: str) -> str:
    """Read one checked-in source migration without using profile data."""

    with migration_directory() as directory:
        return directory.joinpath(name).read_text(encoding="utf-8")


def _without_profile_literal_and_epoch(source: str) -> str:
    """Make a private 0010 copy which cannot accept its literal fixture."""

    marker = source.index(_MANIFEST_BEGIN)
    insert_start = source.index("INSERT INTO public.authority_acl_profile_tuple", marker)
    insert_end = source.index(";", insert_start) + 1
    no_literal = (
        source[:insert_start]
        + "INSERT INTO public.authority_acl_profile_tuple (profile, tuple_class, tuple_digest) "
        + "SELECT 'genuine_0010'::public.authority_acl_profile, 'acl', "
        + "decode(repeat('00', 32), 'hex') WHERE false;"
        + source[insert_end:]
    )
    epoch_append = no_literal.rfind("INSERT INTO public.authority_acl_epoch (")
    if epoch_append < 0:
        raise ValueError("foundation source has no final authority epoch append")
    return no_literal[:epoch_append]


def _without_final_epoch_append(source: str, *, rollback: bool) -> str:
    """Remove only a transition's final append from a private source copy."""

    epoch_append = source.rfind("INSERT INTO public.authority_acl_epoch (")
    if epoch_append < 0:
        raise ValueError("authority transition source has no final epoch append")
    if not rollback:
        return source[:epoch_append]
    end = source.find("\nEND\n$$;", epoch_append)
    if end < 0:
        # 0012's final receipt is a top-level INSERT (the schema teardown is
        # already complete); 0011's is inside a final DO block.  Generation
        # removes only the append in either shape, never a preceding gate.
        return source[:epoch_append]
    return source[:epoch_append] + "\nEND\n$$;\n"


def _execute_source(connection: psycopg.Connection[Any], source: str) -> None:
    """Execute one private complete source copy in its own transaction."""

    connection.execute(source, prepare=False)
    connection.commit()


def _actual_rows(
    connection: psycopg.Connection[Any], profile: str
) -> tuple[tuple[str, str, str], ...]:
    """Read normalized collectors directly; never read profile_tuple here."""

    rows = connection.execute(
        "WITH actual AS ("
        "  SELECT 'acl'::text AS tuple_class, tuple_digest "
        "  FROM public.authority_acl_profile_actual_tuples(%s::public.authority_acl_profile) "
        "  AS acl(tuple_digest) "
        "  UNION ALL "
        "  SELECT 'schema'::text AS tuple_class, tuple_digest "
        "  FROM public.authority_schema_profile_actual_tuples(%s::public.authority_acl_profile) "
        "  AS schema_profile(tuple_digest)"
        ") "
        "SELECT %s::text, tuple_class, encode(tuple_digest, 'hex') "
        "FROM actual ORDER BY tuple_class, tuple_digest",
        (profile, profile, profile),
    ).fetchall()
    return tuple((str(row[0]), str(row[1]), str(row[2])) for row in rows)


def _install_generated_profile(
    connection: psycopg.Connection[Any], rows: Iterable[tuple[str, str, str]]
) -> None:
    """Seed only independently generated rows to enable the next transition."""

    connection.execute(
        "ALTER TABLE public.authority_acl_profile_tuple "
        "DISABLE TRIGGER authority_acl_profile_tuple_immutable"
    )
    with connection.cursor() as cursor:
        cursor.executemany(
            "INSERT INTO public.authority_acl_profile_tuple (profile, tuple_class, tuple_digest) "
            "VALUES (%s::public.authority_acl_profile, %s, decode(%s, 'hex'))",
            tuple(rows),
        )
    connection.execute(
        "ALTER TABLE public.authority_acl_profile_tuple "
        "ENABLE TRIGGER authority_acl_profile_tuple_immutable"
    )
    connection.commit()


def _append_generated_epoch(connection: psycopg.Connection[Any], profile: str) -> None:
    """Append one receipt after generated rows can validate this state."""

    if profile == "genuine_0010":
        connection.execute(
            "INSERT INTO public.authority_acl_epoch ("
            "epoch, profile, profile_version, source_acl_digest, result_acl_digest, "
            "source_schema_digest, result_schema_digest, yoyo_lock_repair"
            ") VALUES ("
            "0, 'genuine_0010', 2, "
            "public.authority_acl_security_assert('genuine_0010'), "
            "public.authority_acl_security_assert('genuine_0010'), "
            "public.authority_schema_security_assert('genuine_0010'), "
            "public.authority_schema_security_assert('genuine_0010'), "
            "'not_required'"
            ")"
        )
    else:
        repair = "revoked" if profile == "cutover_0011" else "not_required"
        connection.execute(
            "INSERT INTO public.authority_acl_epoch ("
            "epoch, profile, profile_version, source_acl_digest, result_acl_digest, "
            "source_schema_digest, result_schema_digest, yoyo_lock_repair"
            ") SELECT "
            "(SELECT max(epoch) + 1 FROM public.authority_acl_epoch), "
            "%s::public.authority_acl_profile, 2, "
            "(SELECT result_acl_digest FROM public.authority_acl_epoch ORDER BY epoch DESC LIMIT 1), "
            "public.authority_acl_security_assert(%s::public.authority_acl_profile), "
            "(SELECT result_schema_digest FROM public.authority_acl_epoch ORDER BY epoch DESC LIMIT 1), "
            "public.authority_schema_security_assert(%s::public.authority_acl_profile), "
            "%s::public.authority_yoyo_lock_repair",
            (profile, profile, profile, repair),
        )
    connection.commit()


def _prepare_direct_rollback(
    connection: psycopg.Connection[Any], *, history: tuple[tuple[str, str], ...]
) -> None:
    """Install the committed pre-activity rollback quarantine in the reference.

    The generator executes private 0010/0011 source copies directly so it can
    collect tuples before accepting their immutable fixture. yoyo would have
    recorded those two transitions in ``_yoyo_migration`` in a production
    rollback; seed exactly those normal bookkeeping rows here so the real
    rollback's locked history fence is exercised rather than bypassed.
    """

    applied_at = datetime.now(UTC).replace(tzinfo=None)
    with connection.cursor() as cursor:
        cursor.executemany(
            "INSERT INTO public._yoyo_migration (migration_hash, migration_id, applied_at_utc) "
            "VALUES (%s, %s, %s) ON CONFLICT (migration_hash) DO NOTHING",
            tuple(
                (migration_hash, migration_id, applied_at + timedelta(microseconds=index))
                for index, (migration_id, migration_hash) in enumerate(history, start=1)
            ),
        )

    connection.execute("SET password_encryption = 'scram-sha-256'")
    connection.execute("ALTER ROLE tracebed_api NOLOGIN PASSWORD 'reference-api-password'")
    connection.execute("ALTER ROLE tracebed_worker NOLOGIN PASSWORD 'reference-worker-password'")
    connection.execute(
        "UPDATE public.authority_cutover_state "
        "SET activated_at = clock_timestamp(), rollback_quarantined_at = clock_timestamp() "
        "WHERE singleton AND first_activity_at IS NULL"
    )
    connection.execute(
        "UPDATE public.authority_admission_state "
        "SET admissions_open = false, changed_at = clock_timestamp() WHERE singleton"
    )
    connection.commit()


def _prepare_direct_erasure_forward(connection: psycopg.Connection[Any]) -> None:
    """Model the c11 closed-and-active state required by E1's forward gate."""

    # The private source copies used by this generator deliberately omit
    # yoyo's runner bookkeeping while deriving their profile roots.  E1's
    # real forward preflight authenticates the committed 0010+0011 history,
    # so model those two exact records here rather than weakening that gate
    # for generation-only execution.
    applied_at = datetime.now(UTC).replace(tzinfo=None)
    with connection.cursor() as cursor:
        cursor.executemany(
            "INSERT INTO public._yoyo_migration (migration_hash, migration_id, applied_at_utc) "
            "VALUES (%s, %s, %s) ON CONFLICT (migration_hash) DO NOTHING",
            tuple(
                (migration_hash, migration_id, applied_at + timedelta(microseconds=index))
                for index, (migration_id, migration_hash) in enumerate(
                    bootstrap._YOYO_MIGRATION_HISTORY[-4:-2], start=1
                )
            ),
        )
    connection.execute(
        "UPDATE public.authority_cutover_state "
        "SET activated_at = COALESCE(activated_at, clock_timestamp()), "
        "rollback_quarantined_at = NULL "
        "WHERE singleton AND first_activity_at IS NULL"
    )
    connection.execute(
        "UPDATE public.authority_admission_state "
        "SET admissions_open = false, changed_at = clock_timestamp() WHERE singleton"
    )
    # A real c11 cluster has already published its API/worker runtime
    # identities before an operator closes admissions and drains it for the
    # c12 cutover.  Their LOGIN state is part of the profiled ACL catalog;
    # generating c12 from the pre-publication NOLOGIN state would produce a
    # fixture that passes only a synthetic direct-source path and fails the
    # normal bootstrap lifecycle.
    connection.execute("SET password_encryption = 'scram-sha-256'")
    connection.execute("ALTER ROLE tracebed_api LOGIN PASSWORD 'reference-api-password'")
    connection.execute("ALTER ROLE tracebed_worker LOGIN PASSWORD 'reference-worker-password'")
    connection.commit()


def collect_clean_reference(dsn: str) -> tuple[tuple[str, str, str], ...]:
    """Build independent genuine/cutover/hardened tuples on an empty cluster.

    The caller supplies a disposable dedicated four-database cluster. Returned
    rows come from collectors before checked-in profile literals are present.
    """

    _apply_through_0009(dsn)
    attested = bootstrap._dedicated_cluster_dsn(dsn, "dedicated", ingress_quarantined=True)
    foundation = _without_profile_literal_and_epoch(_source(_FOUNDATION))
    cutover = _without_final_epoch_append(_source(_CUTOVER), rollback=False)
    rollback = _without_final_epoch_append(_source(_CUTOVER_ROLLBACK), rollback=True)
    erasure = _without_final_epoch_append(_source(_ERASURE), rollback=False)
    erasure_rollback = _without_final_epoch_append(_source(_ERASURE_ROLLBACK), rollback=True)

    with psycopg.connect(attested) as connection:
        # This release-engineering direct execution is not a public runner.
        # The GUC records that it is intentionally using the same trusted
        # source set while deriving the immutable fixture. It is not a DB
        # owner-proof security boundary.
        connection.execute("SET tracebed.atomic_migration_runner = 'on'")
        _execute_source(connection, foundation)
        genuine = _actual_rows(connection, "genuine_0010")
        _install_generated_profile(connection, genuine)
        _append_generated_epoch(connection, "genuine_0010")

        connection.execute("SET password_encryption = 'scram-sha-256'")
        connection.execute("ALTER ROLE tracebed_app NOINHERIT PASSWORD 'reference-legacy-password'")
        connection.commit()
        _execute_source(connection, cutover)
        cutover_rows = _actual_rows(connection, "cutover_0011")
        _install_generated_profile(connection, cutover_rows)
        _append_generated_epoch(connection, "cutover_0011")

        _prepare_direct_rollback(connection, history=bootstrap._YOYO_MIGRATION_HISTORY[-4:-2])
        _execute_source(connection, rollback)
        hardened = _actual_rows(connection, "hardened_0010")
        _install_generated_profile(connection, hardened)
        _append_generated_epoch(connection, "hardened_0010")

        _execute_source(connection, cutover)
        reapply = _actual_rows(connection, "cutover_0011")
        if reapply != cutover_rows:
            raise RuntimeError("clean cutover reapply did not reproduce normalized tuple rows")
        _append_generated_epoch(connection, "cutover_0011")

        _prepare_direct_erasure_forward(connection)
        _execute_source(connection, erasure)
        erasure_rows = _actual_rows(connection, "cutover_0012")
        _install_generated_profile(connection, erasure_rows)
        _append_generated_epoch(connection, "cutover_0012")

        _prepare_direct_rollback(connection, history=bootstrap._YOYO_MIGRATION_HISTORY[-3:-1])
        _execute_source(connection, erasure_rollback)
        # yoyo removes the reverted migration's receipt after a successful
        # rollback.  Private source execution deliberately models that
        # bookkeeping before proving c12 can be reapplied from c11.
        connection.execute(
            "DELETE FROM public._yoyo_migration "
            "WHERE migration_id = '0012_erasure_saga' "
            "AND migration_hash = %s",
            (bootstrap._YOYO_MIGRATION_HISTORY[-2][1],),
        )
        connection.commit()
        erasure_rollback_rows = _actual_rows(connection, "cutover_0011")
        if erasure_rollback_rows != cutover_rows:
            raise RuntimeError("clean erasure rollback did not reproduce cutover-0011 tuples")
        _append_generated_epoch(connection, "cutover_0011")

        _prepare_direct_erasure_forward(connection)
        _execute_source(connection, erasure)
        erasure_reapply = _actual_rows(connection, "cutover_0012")
        if erasure_reapply != erasure_rows:
            raise RuntimeError("clean erasure reapply did not reproduce normalized tuple rows")

    return tuple(sorted((*genuine, *cutover_rows, *erasure_rows, *hardened)))


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dsn", required=True, help="empty disposable dedicated-PG18 reference DSN")
    parser.add_argument(
        "--check",
        action="store_true",
        help="fail unless the independently regenerated fixture exactly matches 0010",
    )
    parser.add_argument(
        "--write",
        action="store_true",
        help="mechanically replace only the one marked fixture block after review",
    )
    args = parser.parse_args(argv)
    if args.check and args.write:
        raise SystemExit("--check and --write are mutually exclusive")
    # yoyo may print extension bootstrap result sets. Keep that diagnostic
    # output off stdout so stdout remains a byte-for-byte SQL fixture stream.
    with contextlib.redirect_stdout(sys.stderr):
        rows = collect_clean_reference(args.dsn)
    rendered = render_manifest(rows)
    if args.check:
        source = _FOUNDATION_SOURCE_PATH.read_text(encoding="utf-8")
        if _checked_in_manifest_block(source) != rendered:
            raise SystemExit("authority profile fixture is stale; regenerate and review the marked 0010 block")
        return 0
    if args.write:
        source = _FOUNDATION_SOURCE_PATH.read_text(encoding="utf-8")
        _FOUNDATION_SOURCE_PATH.write_text(
            _replace_manifest_block(source, rendered), encoding="utf-8"
        )
        return 0
    print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
