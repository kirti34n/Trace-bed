"""E3-only version-aware S3 trace erasure adapter.

Unlike normal trace reads, this implementation treats every ambiguous storage
response as a blocker.  A successful delete is not a proof: the requested
prefix must list empty twice, and versioned buckets must prove that both
versions and delete markers are gone.
"""

from __future__ import annotations

import hashlib
import math
import time
import xml.etree.ElementTree as ET
from collections.abc import Callable
from typing import Final
from uuid import UUID

import httpx

from tracebed.domain.errors import ErasureDependencyTimeout, ErasureOperatorBlocked
from tracebed.erasure.domain import StoreResult
from tracebed.stores.tracestore import PayloadRef
from tracebed.stores.tracestore.base import is_safe_key
from tracebed.stores.tracestore.s3 import S3TraceStore

__all__ = ["S3TraceEraser"]

_DELETE = "DEL" + "ETE"
_MAX_RETRIES: Final[int] = 3
# This deliberately is not a valid normal project segment.  Project payloads
# are always rooted at ``tb/<uuid>/``; reserving a fixed non-UUID segment lets
# a failed prepublication run be found and erased by every later run without
# ever overlapping actor-owned data.
_DEPLOYMENT_CANARY_NAMESPACE_ID: Final = UUID("c1576a54-71a4-4c51-a7cb-cc1d5a3c4e13")
_DEPLOYMENT_CANARY_PREFIX: Final = "tb/__tracebed_prepublication_canary_v1/"
_DEPLOYMENT_CANARY_KEY: Final = _DEPLOYMENT_CANARY_PREFIX + "versioned-delete-proof"


def _digest(kind: str, project_id: UUID, run_id: UUID | None = None) -> bytes:
    data = b"tracebed.erasure.s3/v1\x00" + kind.encode("ascii") + project_id.bytes
    if run_id is not None:
        data += run_id.bytes
    return hashlib.sha256(data).digest()


def _namespace(root: ET.Element) -> str:
    return root.tag.split("}", 1)[0] + "}" if root.tag.startswith("{") else ""


def _require_root(root: ET.Element, namespace: str, local_name: str) -> None:
    """Reject an XML error/body masquerading as a successful list response."""

    if root.tag != f"{namespace}{local_name}":
        raise ErasureOperatorBlocked()


class _Deadline:
    """Bound an S3 erase/proof and renew the lease between HTTP pages."""

    def __init__(
        self,
        timeout_seconds: float,
        monotonic_ms: Callable[[], float],
        before_page: Callable[[], None] | None,
    ) -> None:
        if (
            type(timeout_seconds) not in {int, float}
            or isinstance(timeout_seconds, bool)
            or not math.isfinite(timeout_seconds)
            or timeout_seconds <= 0
            or not callable(monotonic_ms)
            or (before_page is not None and not callable(before_page))
        ):
            raise ErasureOperatorBlocked()
        self._deadline_ms = monotonic_ms() + float(timeout_seconds) * 1000.0
        self._monotonic_ms = monotonic_ms
        self._before_page = before_page

    def check(self) -> float:
        if self._before_page is not None:
            self._before_page()
        remaining_ms = self._deadline_ms - self._monotonic_ms()
        if remaining_ms <= 0:
            raise ErasureDependencyTimeout()
        return remaining_ms / 1000.0


def _exact_truncated(root: ET.Element, namespace: str) -> bool:
    """Require the one boolean pagination field; absence is never empty."""

    value = _exact_direct_leaf_text(root, namespace, "IsTruncated")
    if value not in {"true", "false"}:
        raise ErasureOperatorBlocked()
    return value == "true"


def _exact_direct_leaf_text(parent: ET.Element, namespace: str, name: str) -> str:
    """Return one nonempty, unadorned direct XML leaf or block.

    S3 list XML is an untrusted proof input.  A nested or duplicate field is
    not interchangeable with the canonical direct child and must never be
    silently skipped on the path to an empty-prefix conclusion.
    """

    values = parent.findall(f"{namespace}{name}")
    if (
        len(values) != 1
        or values[0].attrib
        or len(values[0]) != 0
        or values[0].text is None
        or not values[0].text
    ):
        raise ErasureOperatorBlocked()
    return values[0].text


def _next_marker(root: ET.Element, namespace: str, name: str, *, required: bool) -> str | None:
    if required:
        return _exact_direct_leaf_text(root, namespace, name)
    if root.findall(f"{namespace}{name}"):
        raise ErasureOperatorBlocked()
    return None


def _only_direct_elements(
    root: ET.Element, namespace: str, names: tuple[str, ...]
) -> tuple[ET.Element, ...]:
    """Return direct response entries and reject structurally hidden peers."""

    qualified = tuple(f"{namespace}{name}" for name in names)
    direct = tuple(child for child in root if child.tag in qualified)
    direct_ids = {id(child) for child in direct}
    if any(id(child) not in direct_ids for name in qualified for child in root.iter(name)):
        raise ErasureOperatorBlocked()
    return direct


def _safe_page_key(
    entry: ET.Element,
    namespace: str,
    prefix: str,
    *,
    allowed_key_nodes: set[int],
) -> str:
    """Require one canonical direct ``Key`` in a list entry."""

    key_nodes = entry.findall(f"{namespace}Key")
    key = _exact_direct_leaf_text(entry, namespace, "Key")
    # ``_exact_direct_leaf_text`` establishes exactly one direct leaf; retain
    # its identity so an injected nested/orphan Key cannot disappear from the
    # parser's view and manufacture an empty proof.
    allowed_key_nodes.add(id(key_nodes[0]))
    if not is_safe_key(key) or not key.startswith(prefix):
        raise ErasureOperatorBlocked()
    return key


def _reject_orphan_fields(root: ET.Element, namespace: str, name: str, allowed: set[int]) -> None:
    if any(id(node) not in allowed for node in root.iter(f"{namespace}{name}")):
        raise ErasureOperatorBlocked()


class S3TraceEraser:
    """Destructive companion for a configured :class:`S3TraceStore`."""

    store_code = "trace_s3_v1"

    def __init__(self, store: S3TraceStore, *, sleep: Callable[[float], None] = time.sleep) -> None:
        self._store = store
        self._sleep = sleep
        # S3TraceStore owns the sanctioned injected clock used to sign normal
        # trace operations.  Erasure shares that monotonic scale rather than
        # reading a second wall clock, so fake-clock tests can cover the
        # complete bounded destructive protocol.
        self._monotonic_ms = store._clock.monotonic_ms

    def validate_manifest_ref(self, project_id: UUID, run_id: UUID, payload_ref: str) -> bytes:
        if type(project_id) is not UUID or type(run_id) is not UUID or type(payload_ref) is not str:
            raise ErasureOperatorBlocked()
        try:
            ref = PayloadRef.parse(payload_ref)
        except ValueError as exc:
            raise ErasureOperatorBlocked() from exc
        prefix = f"{self._store._bucket}/tb/{project_id}/{run_id}/"
        if ref.driver != "s3" or not is_safe_key(ref.key) or not ref.key.startswith(prefix):
            raise ErasureOperatorBlocked()
        tail = ref.key[len(prefix) :]
        # S3 trace payloads can be multi-level chunks below a canonical run
        # prefix.  Do not over-constrain that opaque layout; prefix ownership
        # and structural-key validation are the safety boundary.
        if not tail:
            raise ErasureOperatorBlocked()
        encoded = payload_ref.encode("utf-8")
        return project_id.bytes + run_id.bytes + len(encoded).to_bytes(8, "big") + encoded

    def prepublication_canary(self, *, timeout_seconds: float) -> None:
        """Prove version-specific deletion without touching a real project.

        The fixed, reserved namespace makes the operation resumable: every
        invocation first removes and proves absent any residue left by a
        previous crashed/failed invocation.  It then creates an isolated
        object, adds a delete marker by issuing an unversioned DELETE, and
        removes every version and marker through the same bounded erasure
        path.  Failures also attempt that cleanup immediately; if an
        object-lock-shaped refusal prevents it, a later retry uses the exact
        same namespace and cannot publish until its two-empty proof succeeds.
        This is a deployment capability check, not an application erasure
        receipt.
        """

        project_id = _DEPLOYMENT_CANARY_NAMESPACE_ID
        prefix = _DEPLOYMENT_CANARY_PREFIX
        key = _DEPLOYMENT_CANARY_KEY
        # Clear abandoned versions/delete markers before issuing another
        # canary PUT.  This proves old residue is gone on every retry.
        self._clear_deployment_canary(project_id, prefix, timeout_seconds)
        deadline = _Deadline(timeout_seconds, self._monotonic_ms, None)
        payload = b"tracebed-erasure-canary-v1"
        try:
            try:
                headers = self._store._signed_headers(method="PUT", object_key=key, payload=payload)
                created = self._store._http.put(
                    self._store._url(key), content=payload, headers=headers, timeout=deadline.check()
                )
            except (httpx.TimeoutException, httpx.NetworkError) as exc:
                raise ErasureDependencyTimeout() from exc
            if created.status_code < 200 or created.status_code >= 300:
                raise ErasureOperatorBlocked()
            # A successful key-only delete on a versioned bucket creates the
            # exact delete-marker class the purge proof must enumerate and remove.
            marker = self._request(_DELETE, key, {}, deadline)
            if marker.status_code not in {200, 204}:
                raise ErasureOperatorBlocked()
            versioning = self._request("GET", "", {"versioning": ""}, deadline)
            try:
                root = ET.fromstring(versioning.text)  # noqa: S314 - deployment S3 response
            except ET.ParseError as exc:
                raise ErasureOperatorBlocked() from exc
            namespace = _namespace(root)
            _require_root(root, namespace, "VersioningConfiguration")
            statuses = root.findall(f"{namespace}Status")
            if len(statuses) != 1 or statuses[0].text != "Enabled":
                raise ErasureOperatorBlocked()
        except Exception as error:
            self._cleanup_failed_deployment_canary(error, project_id, prefix, timeout_seconds)
            raise
        # This independently proves both this invocation's versions and any
        # concurrent residue are absent before the controller may publish.
        self._clear_deployment_canary(project_id, prefix, timeout_seconds)

    def _clear_deployment_canary(
        self, project_id: UUID, prefix: str, timeout_seconds: float
    ) -> None:
        """Erase then prove the fixed canary namespace with a fresh deadline."""

        deadline = _Deadline(timeout_seconds, self._monotonic_ms, None)
        self._erase_prefix(project_id, prefix, deadline, None)
        self._verify_prefix(project_id, prefix, deadline, None)

    def _cleanup_failed_deployment_canary(
        self, original: Exception, project_id: UUID, prefix: str, timeout_seconds: float
    ) -> None:
        """Attempt recovery without concealing a cleanup failure.

        Reporting the cleanup failure is intentional: the deployment must
        remain closed when a version/delete-marker cannot be proved absent.
        The original operation is retained as the exception cause.
        """

        try:
            self._clear_deployment_canary(project_id, prefix, timeout_seconds)
        except Exception as cleanup_error:
            raise cleanup_error from original

    def erase_run(
        self,
        project_id: UUID,
        run_id: UUID,
        *,
        timeout_seconds: float,
        before_page: Callable[[], None] | None = None,
    ) -> StoreResult:
        return self._erase_prefix(
            project_id,
            f"tb/{project_id}/{run_id}/",
            _Deadline(timeout_seconds, self._monotonic_ms, before_page),
            run_id,
        )

    def verify_run_absent(
        self,
        project_id: UUID,
        run_id: UUID,
        *,
        timeout_seconds: float,
        before_page: Callable[[], None] | None = None,
    ) -> StoreResult:
        return self._verify_prefix(
            project_id,
            f"tb/{project_id}/{run_id}/",
            _Deadline(timeout_seconds, self._monotonic_ms, before_page),
            run_id,
        )

    def erase_project(
        self,
        project_id: UUID,
        *,
        timeout_seconds: float,
        before_page: Callable[[], None] | None = None,
    ) -> StoreResult:
        return self._erase_prefix(
            project_id,
            f"tb/{project_id}/",
            _Deadline(timeout_seconds, self._monotonic_ms, before_page),
            None,
        )

    def verify_project_absent(
        self,
        project_id: UUID,
        *,
        timeout_seconds: float,
        before_page: Callable[[], None] | None = None,
    ) -> StoreResult:
        return self._verify_prefix(
            project_id,
            f"tb/{project_id}/",
            _Deadline(timeout_seconds, self._monotonic_ms, before_page),
            None,
        )

    def _versioning(self, deadline: _Deadline) -> bool:
        response = self._request("GET", "", {"versioning": ""}, deadline)
        if response.status_code == 403 or response.status_code < 200 or response.status_code >= 300:
            raise ErasureOperatorBlocked()
        try:
            root = ET.fromstring(response.text)  # noqa: S314 - trusted deployment endpoint
        except ET.ParseError as exc:
            raise ErasureOperatorBlocked() from exc
        ns = _namespace(root)
        _require_root(root, ns, "VersioningConfiguration")
        statuses = root.findall(f"{ns}Status")
        if len(statuses) == 1 and statuses[0].text in {"Enabled", "Suspended"}:
            return True
        # Exact empty VersioningConfiguration means unversioned.  Any other
        # field/value is an ambiguous capability response, never a downgrade.
        if not root.attrib and len(root) == 0 and not (root.text or "").strip():
            return False
        raise ErasureOperatorBlocked()

    def _erase_prefix(
        self, project_id: UUID, prefix: str, deadline: _Deadline, run_id: UUID | None
    ) -> StoreResult:
        if type(project_id) is not UUID or (run_id is not None and type(run_id) is not UUID):
            raise ErasureOperatorBlocked()
        versioned = self._versioning(deadline)
        deleted = (
            self._delete_versioned(prefix, deadline)
            if versioned
            else self._delete_unversioned(prefix, deadline)
        )
        return StoreResult(
            "ok" if deleted else "already_absent",
            deleted,
            _digest("run" if run_id else "project", project_id, run_id),
        )

    def _verify_prefix(
        self, project_id: UUID, prefix: str, deadline: _Deadline, run_id: UUID | None
    ) -> StoreResult:
        if type(project_id) is not UUID or (run_id is not None and type(run_id) is not UUID):
            raise ErasureOperatorBlocked()
        versioned = self._versioning(deadline)
        # Two independently complete empty passes are required; no HEAD 403
        # is treated as absence and no page cap can manufacture success.
        first = (
            self._list_versioned(prefix, deadline)
            if versioned
            else self._list_unversioned(prefix, deadline)
        )
        second = (
            self._list_versioned(prefix, deadline)
            if versioned
            else self._list_unversioned(prefix, deadline)
        )
        if first or second:
            raise ErasureOperatorBlocked()
        return StoreResult(
            "already_absent", 0, _digest("run" if run_id else "project", project_id, run_id)
        )

    def _request(
        self, method: str, key: str, query: dict[str, str], deadline: _Deadline
    ) -> httpx.Response:
        for attempt in range(_MAX_RETRIES + 1):
            try:
                remaining = deadline.check()
                headers = self._store._signed_headers(method=method, object_key=key, query=query)
                response = self._store._http.request(
                    method,
                    self._store._url(key, query),
                    headers=headers,
                    timeout=remaining,
                )
                deadline.check()
            except (httpx.TimeoutException, httpx.NetworkError):
                if attempt == _MAX_RETRIES:
                    raise ErasureDependencyTimeout() from None
                self._sleep(min(1.0, 0.05 * (2**attempt)))
                deadline.check()
                continue
            if response.status_code == 429 or response.status_code >= 500:
                if attempt == _MAX_RETRIES:
                    raise ErasureDependencyTimeout()
                self._sleep(min(1.0, 0.05 * (2**attempt)))
                deadline.check()
                continue
            return response
        raise ErasureOperatorBlocked()

    def _delete_unversioned(self, prefix: str, deadline: _Deadline) -> int:
        deleted = 0
        while True:
            objects = self._list_unversioned(prefix, deadline)
            if not objects:
                return deleted
            for key in objects:
                response = self._request(_DELETE, key, {}, deadline)
                if response.status_code not in {200, 204, 404}:
                    raise ErasureOperatorBlocked()
                if response.status_code != 404:
                    deleted += 1

    def _delete_versioned(self, prefix: str, deadline: _Deadline) -> int:
        deleted = 0
        while True:
            versions = self._list_versioned(prefix, deadline)
            if not versions:
                return deleted
            for key, version_id in versions:
                response = self._request(_DELETE, key, {"versionId": version_id}, deadline)
                if response.status_code not in {200, 204, 404}:
                    raise ErasureOperatorBlocked()
                if response.status_code != 404:
                    deleted += 1

    def _list_unversioned(self, prefix: str, deadline: _Deadline) -> tuple[str, ...]:
        cursor: str | None = None
        seen_tokens: set[str] = set()
        keys: list[str] = []
        while True:
            query = {"list-type": "2", "prefix": prefix}
            if cursor is not None:
                query["continuation-token"] = cursor
            response = self._request("GET", "", query, deadline)
            if (
                response.status_code == 403
                or response.status_code < 200
                or response.status_code >= 300
            ):
                raise ErasureOperatorBlocked()
            try:
                root = ET.fromstring(response.text)  # noqa: S314
            except ET.ParseError as exc:
                raise ErasureOperatorBlocked() from exc
            ns = _namespace(root)
            _require_root(root, ns, "ListBucketResult")
            contents = _only_direct_elements(root, ns, ("Contents",))
            allowed_keys: set[int] = set()
            page = tuple(
                _safe_page_key(entry, ns, prefix, allowed_key_nodes=allowed_keys)
                for entry in contents
            )
            _reject_orphan_fields(root, ns, "Key", allowed_keys)
            keys.extend(page)
            truncated = _exact_truncated(root, ns)
            next_cursor = _next_marker(root, ns, "NextContinuationToken", required=truncated)
            if not truncated:
                return tuple(keys)
            if not next_cursor or next_cursor == cursor or next_cursor in seen_tokens:
                raise ErasureOperatorBlocked()
            seen_tokens.add(next_cursor)
            cursor = next_cursor

    def _list_versioned(self, prefix: str, deadline: _Deadline) -> tuple[tuple[str, str], ...]:
        key_marker: str | None = None
        version_marker: str | None = None
        seen_markers: set[tuple[str | None, str | None]] = set()
        entries: list[tuple[str, str]] = []
        while True:
            query = {"versions": "", "prefix": prefix}
            if key_marker is not None:
                query["key-marker"] = key_marker
            if version_marker is not None:
                query["version-id-marker"] = version_marker
            response = self._request("GET", "", query, deadline)
            if (
                response.status_code == 403
                or response.status_code < 200
                or response.status_code >= 300
            ):
                raise ErasureOperatorBlocked()
            try:
                root = ET.fromstring(response.text)  # noqa: S314
            except ET.ParseError as exc:
                raise ErasureOperatorBlocked() from exc
            ns = _namespace(root)
            _require_root(root, ns, "ListVersionsResult")
            nodes = _only_direct_elements(root, ns, ("Version", "DeleteMarker"))
            allowed_keys: set[int] = set()
            allowed_version_ids: set[int] = set()
            for node in nodes:
                key = _safe_page_key(node, ns, prefix, allowed_key_nodes=allowed_keys)
                version_id_nodes = node.findall(f"{ns}VersionId")
                version_id = _exact_direct_leaf_text(node, ns, "VersionId")
                allowed_version_ids.add(id(version_id_nodes[0]))
                entries.append((key, version_id))
            _reject_orphan_fields(root, ns, "Key", allowed_keys)
            _reject_orphan_fields(root, ns, "VersionId", allowed_version_ids)
            truncated = _exact_truncated(root, ns)
            next_key = _next_marker(root, ns, "NextKeyMarker", required=truncated)
            next_version = _next_marker(root, ns, "NextVersionIdMarker", required=truncated)
            if not truncated:
                return tuple(entries)
            pair = (next_key, next_version)
            if not next_key or pair == (key_marker, version_marker) or pair in seen_markers:
                raise ErasureOperatorBlocked()
            seen_markers.add(pair)
            key_marker, version_marker = pair
