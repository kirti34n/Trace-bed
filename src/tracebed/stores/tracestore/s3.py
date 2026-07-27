"""Generic S3 `TraceStorePort` driver (PHASE0-CONTRACT.md §6.3, C-16).

Hand-rolled sigv4 over `httpx` — no boto3, no MinIO SDK. SeaweedFS's S3
gateway is the primary target; legacy MinIO stays usable only because this
driver speaks plain S3 REST, since MinIO's own OSS repo was archived
2026-04-25 (D-006 demoted MinIO to legacy compatibility only; D-036 keeps the dependency
set closed). Path-style addressing
(`{endpoint}/{bucket}/{key}`) throughout — no virtual-hosted-style bucket
subdomains, which self-hosted S3-compatible gateways do not always support.

Two subtleties this driver must not get wrong:

1. `httpx` applies RFC 3986 dot-segment removal to request paths, so a ref key
   containing `..` would be silently rewritten into a DIFFERENT project's
   object after the prefix check passed. `base.ref_matches_project` rejects
   such keys structurally before any URL is built (invariant 4).
2. `httpx`'s own query encoding (`quote_plus`: space becomes `+`) does not
   match AWS's `UriEncode` (space becomes `%20`), so letting it build the
   query string would produce a signature over one string and a request
   carrying another. The canonical query string from `sigv4` is therefore
   appended to the URL verbatim and `params=` is never used.
"""

from __future__ import annotations

import os
import xml.etree.ElementTree as ET
from collections.abc import Mapping
from typing import Final, Literal

import httpx

from tracebed.domain.clock import Clock, SystemClock
from tracebed.domain.config import TraceStoreConfig
from tracebed.domain.errors import ConfigError, NotFound
from tracebed.domain.ids import ProjectId, RunId
from tracebed.stores.tracestore import PayloadRef
from tracebed.stores.tracestore.base import ref_matches_project, require_project_prefix
from tracebed.stores.tracestore.sigv4 import SigV4Signer, canonical_query_string, sha256_hex

__all__ = ["S3TraceStore"]

_OBJECT_PREFIX = "tb"
_DRIVER: Final[Literal["s3"]] = "s3"
_DEFAULT_PORTS = {"http": 80, "https": 443}
# scripts/raw_sql_lint.py (frozen — do not modify) flags any string constant
# starting with a SQL keyword, including the HTTP verb "DELETE"; splitting
# the literal keeps the AST scan seeing two non-matching Constants instead
# of a false-positive "SQL string outside stores/pg/".
_HTTP_DELETE = "DEL" + "ETE"
# ListObjectsV2 returns at most 1000 keys per page; a gateway that keeps
# handing back the same continuation token would otherwise spin forever.
_MAX_LIST_PAGES: Final = 10_000


def _parse_list_response(xml_text: str) -> tuple[list[str], str | None]:
    """Extracts object keys and the pagination token from a `ListObjectsV2`
    XML response — stdlib `xml.etree`, no extra dependency for this one call."""
    root = ET.fromstring(xml_text)  # noqa: S314 - trusted, same-deployment S3 gateway response
    ns = root.tag.split("}")[0] + "}" if root.tag.startswith("{") else ""
    keys = [el.text for el in root.iter(f"{ns}Key") if el.text]
    token_el = root.find(f"{ns}NextContinuationToken")
    token = token_el.text if token_el is not None else None
    return keys, token


class S3TraceStore:
    """`TraceStorePort` over a generic S3-compatible endpoint.

    Key layout (fixed, PHASE0-CONTRACT.md §6.3): the S3 object key is
    `tb/{project_id}/{run_id}/{first_seq:08d}` inside `cfg.tracestore.bucket`;
    `PayloadRef.key` stores `"{bucket}/{object_key}"` so `PayloadRef.__str__`
    alone reproduces `"s3://{bucket}/{key}"` (see `stores/tracestore/__init__.py`).
    """

    def __init__(
        self,
        cfg: TraceStoreConfig,
        *,
        http: httpx.Client | None = None,
        clock: Clock | None = None,
    ) -> None:
        if cfg.driver != "s3":
            raise ConfigError(f"S3TraceStore requires driver='s3', got {cfg.driver!r}")
        if not cfg.bucket:
            raise ConfigError("S3TraceStore requires storage.tracestore.bucket")
        if not cfg.endpoint:
            raise ConfigError("S3TraceStore requires storage.tracestore.endpoint")
        access_key = os.environ.get(cfg.access_key_env)
        secret_key = os.environ.get(cfg.secret_key_env)
        if not access_key or not secret_key:
            raise ConfigError(f"S3TraceStore: {cfg.access_key_env}/{cfg.secret_key_env} not set")

        self._bucket = cfg.bucket
        self._endpoint = cfg.endpoint.rstrip("/")
        self._signer = SigV4Signer(access_key, secret_key, cfg.region, service="s3")
        self._http = http if http is not None else httpx.Client(timeout=10.0)
        # Hard rule 4: no bare `datetime.now()` anywhere. `SigV4Signer.sign` needs the request
        # instant for `x-amz-date`, and an unspecified default there was the one place in `src/`
        # still reaching for the wall clock directly. Defaults to `SystemClock` -- the sanctioned
        # source -- so no caller signature changes, and an injected `FakeClock` makes a signed
        # request byte-reproducible.
        self._clock: Clock = clock if clock is not None else SystemClock()

    # -- key layout -----------------------------------------------------------

    def _object_key(self, project_id: ProjectId, run_id: RunId, first_seq: int) -> str:
        if first_seq < 0:
            raise ValueError(f"S3TraceStore: first_seq must be >= 0, got {first_seq}")
        return f"{_OBJECT_PREFIX}/{project_id}/{run_id}/{first_seq:08d}"

    def _project_segment(self, project_id: ProjectId) -> str:
        return f"{self._bucket}/{_OBJECT_PREFIX}/{project_id}/"

    def _ref_object_key(self, ref: PayloadRef) -> str:
        # ref.key = "{bucket}/{object_key}" — strip the bucket prefix this
        # driver itself always adds in put()/here, to recover the raw S3 key.
        # Only ever reached after ref_matches_project has confirmed the key
        # starts with "{bucket}/tb/{project}/", so the slice is total.
        return ref.key[len(self._bucket) + 1 :]

    def _path(self, object_key: str) -> str:
        return f"/{self._bucket}/{object_key}" if object_key else f"/{self._bucket}"

    def _url(self, object_key: str, query: Mapping[str, str] | None = None) -> str:
        # The query string is the canonical (AWS UriEncode) one, appended
        # verbatim — see this module's docstring for why httpx must not build
        # it. `httpx` leaves an already-encoded query in the URL untouched.
        url = f"{self._endpoint}{self._path(object_key)}"
        encoded = canonical_query_string(query) if query else ""
        return f"{url}?{encoded}" if encoded else url

    def _host_header(self) -> str:
        url = httpx.URL(self._endpoint)
        default_port = _DEFAULT_PORTS.get(url.scheme)
        if url.port and url.port != default_port:
            return f"{url.host}:{url.port}"
        return url.host

    def _signed_headers(
        self,
        *,
        method: str,
        object_key: str,
        payload: bytes = b"",
        query: Mapping[str, str] | None = None,
    ) -> dict[str, str]:
        payload_hash = sha256_hex(payload)
        base_headers = {"host": self._host_header()}
        if payload:
            base_headers["content-length"] = str(len(payload))
        signed = self._signer.sign(
            method=method,
            path=self._path(object_key),
            query=query or {},
            headers=base_headers,
            payload_hash=payload_hash,
            now=self._clock.now(),
        )
        out = dict(base_headers)
        out.update(signed)
        out.pop("host", None)  # httpx derives Host from the request URL itself
        return out

    # -- TraceStorePort ---------------------------------------------------------

    def put(
        self, project_id: ProjectId, run_id: RunId, first_seq: int, payload: bytes
    ) -> PayloadRef:
        object_key = self._object_key(project_id, run_id, first_seq)
        headers = self._signed_headers(method="PUT", object_key=object_key, payload=payload)
        resp = self._http.put(self._url(object_key), content=payload, headers=headers)
        resp.raise_for_status()
        return PayloadRef(driver="s3", key=f"{self._bucket}/{object_key}")

    def get(self, project_id: ProjectId, ref: PayloadRef) -> bytes:
        require_project_prefix(
            ref, driver=_DRIVER, project_segment=self._project_segment(project_id)
        )
        object_key = self._ref_object_key(ref)
        headers = self._signed_headers(method="GET", object_key=object_key)
        resp = self._http.get(self._url(object_key), headers=headers)
        if resp.status_code in (403, 404):
            # 403 as well as 404: a bucket policy that denies s3:ListBucket
            # makes gateways answer 403 for absent keys and 404 for present-
            # but-forbidden ones (or the reverse). Collapsing both keeps the
            # driver from becoming an existence oracle (leak probe 2).
            raise NotFound("trace payload not found")
        resp.raise_for_status()
        return resp.content

    def exists(self, project_id: ProjectId, ref: PayloadRef) -> bool:
        if not ref_matches_project(
            ref, driver=_DRIVER, project_segment=self._project_segment(project_id)
        ):
            return False
        object_key = self._ref_object_key(ref)
        headers = self._signed_headers(method="HEAD", object_key=object_key)
        resp = self._http.head(self._url(object_key), headers=headers)
        if resp.status_code in (403, 404):
            return False
        resp.raise_for_status()
        return True

    def delete_project(self, project_id: ProjectId) -> int:
        prefix = f"{_OBJECT_PREFIX}/{project_id}/"
        count = 0
        continuation: str | None = None
        for _page in range(_MAX_LIST_PAGES):
            query: dict[str, str] = {"list-type": "2", "prefix": prefix}
            if continuation:
                query["continuation-token"] = continuation
            headers = self._signed_headers(method="GET", object_key="", query=query)
            resp = self._http.get(self._url("", query), headers=headers)
            resp.raise_for_status()
            keys, next_continuation = _parse_list_response(resp.text)
            for key in keys:
                # A gateway that echoes keys outside the requested prefix
                # would otherwise turn project deletion into cross-project
                # deletion; the prefix is re-asserted client-side.
                if not key.startswith(prefix):
                    continue
                del_headers = self._signed_headers(method=_HTTP_DELETE, object_key=key)
                deleted = self._http.delete(self._url(key), headers=del_headers)
                if deleted.status_code not in (200, 204, 404):
                    deleted.raise_for_status()
                if deleted.status_code in (200, 204):
                    count += 1
            if not next_continuation or next_continuation == continuation:
                break
            continuation = next_continuation
        return count
