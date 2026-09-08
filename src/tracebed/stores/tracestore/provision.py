"""Idempotent signed S3 bucket initialization for a Tracebed trace store."""

from __future__ import annotations

import os
import sys
import time
import xml.etree.ElementTree as ET
from typing import Final

import httpx

from tracebed.domain.clock import Clock
from tracebed.domain.config import TraceStoreConfig
from tracebed.domain.errors import ConfigError
from tracebed.stores.tracestore.s3 import S3TraceStore

__all__ = ["ensure_bucket", "main"]

_ENDPOINT_ENV: Final = "TB_STORAGE__TRACESTORE__ENDPOINT"
_BUCKET_ENV: Final = "TB_STORAGE__TRACESTORE__BUCKET"
_REGION_ENV: Final = "TB_STORAGE__TRACESTORE__REGION"
_ACCESS_KEY_ENV_NAME: Final = "TB_STORAGE__TRACESTORE__ACCESS_KEY_ENV"
_SECRET_KEY_ENV_NAME: Final = "TB_STORAGE__TRACESTORE__SECRET_KEY_ENV"  # noqa: S105
_S3_READY_ATTEMPTS: Final = 4
_S3_READY_RETRY_SECONDS: Final = 0.25


def _is_success(response: httpx.Response) -> bool:
    return 200 <= response.status_code < 300


def _ensure_bucket_once(store: S3TraceStore) -> None:
    """Perform one signed HEAD → PUT → re-HEAD bucket admission attempt."""

    initial = store.head_bucket()
    if _is_success(initial):
        return
    if initial.status_code != 404:
        initial.raise_for_status()
        raise RuntimeError("unexpected S3 bucket HEAD status")

    created = store.create_bucket()
    if _is_success(created):
        return
    if created.status_code == 409:
        after_conflict = store.head_bucket()
        if _is_success(after_conflict):
            return
        after_conflict.raise_for_status()
        raise RuntimeError("S3 bucket remained absent after create conflict")
    created.raise_for_status()
    raise RuntimeError("unexpected S3 bucket PUT status")


def _versioning_is_enabled(response: httpx.Response) -> bool:
    """Accept only an unambiguous S3 versioning ``Enabled`` state.

    Gateways legitimately include the S3 XML namespace (and occasionally an
    XML declaration), so byte equality would turn a correct enabled bucket
    into a false startup failure.  This accepts only one direct ``Status``
    leaf with the exact value, never ``Suspended`` or a decorated response.
    """

    if not _is_success(response):
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


def _ensure_versioning_once(store: S3TraceStore) -> None:
    """Enable bucket versioning idempotently and prove it is not suspended."""

    initial = store.bucket_versioning()
    if _versioning_is_enabled(initial):
        return
    if not _is_success(initial):
        initial.raise_for_status()
        raise RuntimeError("unexpected S3 versioning GET status")
    enabled = store.enable_bucket_versioning()
    if not _is_success(enabled):
        enabled.raise_for_status()
        raise RuntimeError("unexpected S3 versioning PUT status")
    verified = store.bucket_versioning()
    if not _versioning_is_enabled(verified):
        raise RuntimeError("S3 bucket versioning is not enabled")


def _is_transient_s3_failure(error: Exception) -> bool:
    """Retry transport failures and gateway 5xx only; auth/4xx never wait."""

    if isinstance(error, httpx.RequestError):
        return True
    return isinstance(error, httpx.HTTPStatusError) and 500 <= error.response.status_code < 600


def ensure_bucket(
    cfg: TraceStoreConfig,
    *,
    http: httpx.Client | None = None,
    clock: Clock | None = None,
) -> None:
    """Ensure ``cfg.bucket`` exists with signed HEAD → PUT → re-HEAD semantics.

    Only a first ``404`` means "attempt creation." A bounded retry absorbs
    only connection errors and 5xx gateway startup transients; authentication,
    authorization, redirects, and every 4xx response fail immediately.  A
    ``409`` from PUT is the one concurrent-create race we accept: re-HEAD
    proves whether another initializer actually created the bucket before
    treating the operation as successful.
    """
    owns_http = http is None
    client = http if http is not None else httpx.Client(timeout=10.0)
    store = S3TraceStore(cfg, http=client, clock=clock)
    try:
        for attempt in range(_S3_READY_ATTEMPTS):
            try:
                _ensure_bucket_once(store)
                _ensure_versioning_once(store)
                return
            except Exception as error:
                if not _is_transient_s3_failure(error) or attempt + 1 == _S3_READY_ATTEMPTS:
                    raise
                time.sleep(_S3_READY_RETRY_SECONDS)
    finally:
        if owns_http:
            client.close()


def _trace_store_config_from_env() -> TraceStoreConfig:
    endpoint = os.environ.get(_ENDPOINT_ENV)
    bucket = os.environ.get(_BUCKET_ENV)
    if not endpoint or not bucket:
        raise ConfigError(f"{_ENDPOINT_ENV} and {_BUCKET_ENV} must be set for S3 initialization")
    return TraceStoreConfig(
        driver="s3",
        endpoint=endpoint,
        bucket=bucket,
        region=os.environ.get(_REGION_ENV, "us-east-1"),
        access_key_env=os.environ.get(_ACCESS_KEY_ENV_NAME, "TB_S3_ACCESS_KEY"),
        secret_key_env=os.environ.get(_SECRET_KEY_ENV_NAME, "TB_S3_SECRET_KEY"),
    )


def main() -> int:
    """Installed ``tracebed-s3-init`` command; failures are non-zero and secret-free."""
    try:
        ensure_bucket(_trace_store_config_from_env())
    except Exception:
        print("tracebed-s3-init failed", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
