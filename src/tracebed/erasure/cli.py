"""Bounded E3 command-line interface; arguments never name a target."""

from __future__ import annotations

import argparse
import json
from uuid import UUID

from tracebed.erasure.runner import resume, run_request, status

__all__ = ["once_main", "resume_main", "status_main"]


def _request_id(argv: list[str] | None, *, resume: bool = False) -> tuple[UUID, str | None]:
    parser = argparse.ArgumentParser(add_help=True)
    parser.add_argument("request_id")
    if resume:
        parser.add_argument("operator_code")
    parsed = parser.parse_args(argv)
    try:
        request_id = UUID(parsed.request_id)
    except ValueError as exc:
        raise SystemExit(2) from exc
    code = getattr(parsed, "operator_code", None)
    if code is not None and (not isinstance(code, str) or code != "operator_resumed"):
        raise SystemExit(2)
    return request_id, code


def once_main(argv: list[str] | None = None) -> None:
    request_id, _ = _request_id(argv)
    run_request(request_id)


def status_main(argv: list[str] | None = None) -> None:
    request_id, _ = _request_id(argv)
    value = status(request_id)
    if value is None:
        raise SystemExit(1)
    print(
        json.dumps(
            {
                "request_id": str(value.request_id),
                "scope": value.scope,
                "phase": value.phase,
                "disposition": value.disposition,
                "generation": value.generation,
                "retry_not_before": value.retry_not_before.isoformat()
                if value.retry_not_before is not None
                else None,
                "last_code": value.last_code,
                "closure_revision": value.closure_revision,
                "pending_work": value.pending_work,
                "verified_stores": value.verified_stores,
                "total_stores": value.total_stores,
            },
            separators=(",", ":"),
            sort_keys=True,
        )
    )


def resume_main(argv: list[str] | None = None) -> None:
    request_id, _ = _request_id(argv, resume=True)
    resume(request_id)
