"""E4 external dependency readiness without touching actor-owned data."""

from __future__ import annotations

import os
import xml.etree.ElementTree as ET
from collections.abc import Mapping
from typing import Final, cast
from uuid import uuid4

from tracebed.domain.errors import ConfigError
from tracebed.erasure.composition import external_stores_from_environment
from tracebed.stores.tracestore.s3 import S3TraceStore
from tracebed.stores.tracestore.s3_erasure import S3TraceEraser
from tracebed.stores.valkey.erasure import FreshValkeyErasureCommands

__all__ = ["probe_erasure_readiness"]

_CANARY_TIMEOUT_SECONDS: Final = 10.0


def _enabled_versioning(store: S3TraceStore) -> bool:
    response = store.bucket_versioning()
    if response.status_code < 200 or response.status_code >= 300:
        return False
    try:
        root = ET.fromstring(response.content)  # noqa: S314 - signed deployment gateway response
    except ET.ParseError:
        return False
    namespace = root.tag.split("}", 1)[0] + "}" if root.tag.startswith("{") else ""
    status = root.findall(f"{namespace}Status")
    return (
        root.tag == f"{namespace}VersioningConfiguration"
        and not root.attrib
        and len(root) == 1
        and len(status) == 1
        and status[0] is root[0]
        and not status[0].attrib
        and len(status[0]) == 0
        and status[0].text == "Enabled"
    )


def _non_destructive_probe(environment: Mapping[str, str], store: S3TraceStore) -> None:
    """Prove only dependency reachability/capability for serving health."""

    if not _enabled_versioning(store):
        raise ConfigError("erasure readiness is unavailable")
    url = environment.get("TB_STORAGE__VALKEY_URL")
    if url != "valkey://valkey:6379/0":
        raise ConfigError("erasure readiness is unavailable")
    # A random match cannot enumerate or mutate a project namespace.  SCAN is
    # intentionally used rather than PING so the same deadline-bound command
    # wrapper that destructive work uses is exercised by serving readiness.
    # Redis/Valkey may return a nonzero cursor with no matching keys; follow
    # that cursor to completion rather than mistaking ordinary unrelated cache
    # contents for a failed serving dependency.
    client = FreshValkeyErasureCommands(url)
    pattern = "__tracebed_erasure_readiness_" + str(uuid4())
    cursor = 0
    seen_cursors: set[int] = set()
    monotonic_ms = store._clock.monotonic_ms
    deadline_ms = monotonic_ms() + _CANARY_TIMEOUT_SECONDS * 1000.0
    while True:
        remaining_ms = deadline_ms - monotonic_ms()
        if remaining_ms <= 0:
            raise ConfigError("erasure readiness is unavailable")
        try:
            raw_next, raw_keys = client.scan(
                cursor,
                match=pattern,
                count=1,
                timeout_seconds=remaining_ms / 1000.0,
            )
        except Exception as exc:
            raise ConfigError("erasure readiness is unavailable") from exc
        if (
            type(raw_next) is bool
            or not isinstance(raw_next, int)
            or raw_next < 0
            or type(raw_keys) not in {list, tuple}
        ):
            raise ConfigError("erasure readiness is unavailable")
        keys = cast(list[object] | tuple[object, ...], raw_keys)
        if (
            any(type(key) not in {str, bytes} for key in keys)
            or keys
            or monotonic_ms() > deadline_ms
        ):
            raise ConfigError("erasure readiness is unavailable")
        if raw_next == 0:
            return
        if raw_next == cursor or raw_next in seen_cursors:
            raise ConfigError("erasure readiness is unavailable")
        seen_cursors.add(cursor)
        cursor = raw_next


def probe_erasure_readiness(*, serving: bool) -> None:
    """Run serving or closed-controller E4 readiness using only erasure secrets.

    Serving health intentionally stops at non-destructive dependency checks.
    Prepublication is the one controller-only interval where an isolated S3
    version/delete-marker proof and an UNLINK of a random nonexistent Valkey
    key are permitted before admission opens.
    """

    environment = os.environ
    stores, trace_store = external_stores_from_environment(environment)
    try:
        _non_destructive_probe(environment, trace_store)
        if serving:
            return
        eraser = stores.get("trace_s3_v1")
        if not isinstance(eraser, S3TraceEraser):
            raise ConfigError("erasure readiness is unavailable")
        eraser.prepublication_canary(timeout_seconds=_CANARY_TIMEOUT_SECONDS)
        url = environment.get("TB_STORAGE__VALKEY_URL")
        if url != "valkey://valkey:6379/0":
            raise ConfigError("erasure readiness is unavailable")
        result = FreshValkeyErasureCommands(url).unlink(
            "__tracebed_erasure_prepublication_" + str(uuid4()),
            timeout_seconds=_CANARY_TIMEOUT_SECONDS,
        )
        if result != 0:
            raise ConfigError("erasure readiness is unavailable")
    finally:
        trace_store.close()
