"""Fresh-process readiness commands for the three Compose runtimes."""

from __future__ import annotations

import os
import sys
from typing import Literal

from tracebed.domain.config import TracebedSettings
from tracebed.stores.pg.authority_dsn import runtime_dsn_from_environment
from tracebed.stores.pg.pool import create_pool
from tracebed.stores.pg.runtime_identity import (
    probe_runtime_prepublication_readiness,
    probe_runtime_readiness,
    runtime_pool_configure,
)


def _main(
    role: Literal["tracebed_api", "tracebed_worker", "tracebed_erasure"], label: str, *, serving: bool
) -> int:
    try:
        dsn = runtime_dsn_from_environment(role, os.environ)
        settings = TracebedSettings() if role != "tracebed_erasure" else None
        pool = create_pool(
            dsn.value,
            min_size=1,
            max_size=1,
            connect_timeout_s=settings.storage.pg_connect_timeout_s if settings is not None else 5,
            checkout_timeout_s=settings.storage.pg_checkout_timeout_s if settings is not None else 5.0,
            configure=runtime_pool_configure(role),
        )
        try:
            probe = probe_runtime_readiness if serving else probe_runtime_prepublication_readiness
            probe(pool, expected_role=role)
            if role == "tracebed_erasure":
                from tracebed.erasure.readiness import probe_erasure_readiness

                probe_erasure_readiness(serving=serving)
        finally:
            pool.close()
    except Exception:
        print(f"{label} failed", file=sys.stderr)
        return 1
    return 0


def api_main() -> int:
    """Readiness for a fresh API-role physical connection."""

    return _main("tracebed_api", "tracebed-api-ready", serving=True)


def worker_main() -> int:
    """Readiness for a fresh worker-role physical connection."""

    return _main("tracebed_worker", "tracebed-worker-ready", serving=True)


def erasure_main() -> int:
    """Serving readiness for the separately credentialed erasure runtime."""

    return _main("tracebed_erasure", "tracebed-erasure-ready", serving=True)


def api_prepublication_main() -> int:
    """Closed-controller API identity/profile probe, not public readiness."""

    return _main("tracebed_api", "tracebed-api-prepublication-ready", serving=False)


def worker_prepublication_main() -> int:
    """Closed-controller worker identity/profile probe, not serving health."""

    return _main("tracebed_worker", "tracebed-worker-prepublication-ready", serving=False)


def erasure_prepublication_main() -> int:
    """Closed-controller erasure readiness, including bounded destructive canaries."""

    return _main("tracebed_erasure", "tracebed-erasure-prepublication-ready", serving=False)
