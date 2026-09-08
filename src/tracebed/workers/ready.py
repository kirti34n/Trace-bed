"""Fresh-process worker database readiness command for Compose-v1."""

from __future__ import annotations

from tracebed.runtime_ready import worker_main


def main() -> int:
    """Open a fresh worker-role connection and require database readiness."""

    return worker_main()
