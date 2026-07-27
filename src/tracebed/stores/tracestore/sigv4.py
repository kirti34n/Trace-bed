"""Hand-rolled AWS Signature Version 4 request signing.

PHASE0-CONTRACT.md §6.3/C-16: `stores/tracestore/s3.py` must sign requests
without boto3 or a MinIO SDK — legacy MinIO stays compatible only because a
generic S3-speaking driver works against it, and MinIO's own OSS repo was
archived 2026-04-25 (D-006 demoted MinIO to legacy compatibility only; D-036 keeps the
dependency set closed). This module implements
the canonical-request / string-to-sign / key-derivation algorithm exactly as
AWS specifies it, using nothing beyond stdlib `hashlib`/`hmac`.

Verified offline (`tests/phase0/test_tracestore.py`) against the
AWS-published test suite (`awslabs/aws-c-auth`,
`tests/aws-signing-test-suite/v4/{get-vanilla,
get-vanilla-query-order-key-case, post-x-www-form-urlencoded-parameters}`) —
fixed access key `AKIDEXAMPLE`, secret
`wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY`, timestamp `2015-08-30T12:36:00Z`,
region `us-east-1`, service `service`.
"""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Final
from urllib.parse import quote

__all__ = [
    "ALGORITHM",
    "UNSIGNED_PAYLOAD",
    "SigV4Signer",
    "build_canonical_request",
    "build_string_to_sign",
    "canonical_headers",
    "canonical_query_string",
    "canonical_uri",
    "credential_scope",
    "derive_signing_key",
    "sha256_hex",
    "uri_encode",
]

ALGORITHM: Final = "AWS4-HMAC-SHA256"
UNSIGNED_PAYLOAD: Final = "UNSIGNED-PAYLOAD"
_UNRESERVED_SAFE: Final = "-_.~"


def sha256_hex(data: bytes) -> str:
    """Hex digest used for both the payload hash and the canonical-request hash."""
    return hashlib.sha256(data).hexdigest()


def _hmac(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def uri_encode(value: str) -> str:
    """AWS's `UriEncode()`: percent-encode every byte except `A-Z a-z 0-9 - _ . ~`.
    Callers that need a `/`-preserving path encoding call `canonical_uri`
    instead, which encodes each segment with this function and rejoins."""
    return quote(value, safe=_UNRESERVED_SAFE)


def canonical_uri(path: str) -> str:
    """URI-encodes each path segment individually; never double-encodes `/`."""
    if not path:
        return "/"
    return "/".join(uri_encode(segment) for segment in path.split("/"))


def canonical_query_string(query: Mapping[str, str]) -> str:
    """Sorted, individually-encoded `k=v` pairs joined with `&`; sorting
    happens AFTER encoding, per the AWS spec. Empty query -> `""`."""
    encoded = sorted((uri_encode(k), uri_encode(v)) for k, v in query.items())
    return "&".join(f"{k}={v}" for k, v in encoded)


def canonical_headers(headers: Mapping[str, str]) -> tuple[str, str]:
    """Returns `(canonical_headers_block, signed_headers)`. Header values are
    trimmed and internal whitespace runs collapsed to one space, per spec;
    names lowercased and sorted; the block ends with a trailing newline
    after its last header (per AWS's `CanonicalHeaders` definition)."""
    normalized: dict[str, str] = {}
    for name, value in headers.items():
        normalized[name.lower()] = " ".join(str(value).split())
    names = sorted(normalized)
    block = "".join(f"{name}:{normalized[name]}\n" for name in names)
    return block, ";".join(names)


def build_canonical_request(
    *, method: str, path: str, query: Mapping[str, str], headers: Mapping[str, str], payload_hash: str
) -> str:
    """The six-line canonical request that both sides of a signature hash."""
    headers_block, signed_headers = canonical_headers(headers)
    return "\n".join(
        [
            method.upper(),
            canonical_uri(path),
            canonical_query_string(query),
            headers_block,
            signed_headers,
            payload_hash,
        ]
    )


def credential_scope(date_stamp: str, region: str, service: str) -> str:
    return f"{date_stamp}/{region}/{service}/aws4_request"


def build_string_to_sign(
    *, amz_date: str, date_stamp: str, region: str, service: str, canonical_request: str
) -> str:
    return "\n".join(
        [
            ALGORITHM,
            amz_date,
            credential_scope(date_stamp, region, service),
            sha256_hex(canonical_request.encode("utf-8")),
        ]
    )


def derive_signing_key(secret_key: str, date_stamp: str, region: str, service: str) -> bytes:
    """`DateKey -> DateRegionKey -> DateRegionServiceKey -> SigningKey`, the
    AWS docs' key-derivation chain, verbatim."""
    k_date = _hmac(("AWS4" + secret_key).encode("utf-8"), date_stamp)
    k_region = _hmac(k_date, region)
    k_service = _hmac(k_region, service)
    return _hmac(k_service, "aws4_request")


@dataclass(frozen=True, slots=True)
class SigV4Signer:
    """One `(access_key, secret_key, region, service)` credential set,
    reusable across many `sign()` calls."""

    access_key: str
    secret_key: str
    region: str
    service: str = "s3"

    def sign(
        self,
        *,
        method: str,
        path: str,
        query: Mapping[str, str],
        headers: Mapping[str, str],
        payload_hash: str,
        now: datetime,
        include_content_sha256: bool = True,
    ) -> dict[str, str]:
        """Returns the headers to ADD to the request: `x-amz-date`,
        `x-amz-content-sha256` (unless `include_content_sha256=False`),
        `Authorization`. `headers` must already include `host` (and
        `content-type`/`content-length` when present) — the canonical
        request is built from the union of `headers` and the `x-amz-*`
        headers this method adds, so anything the caller wants covered by
        the signature must already be in `headers`. `now` is REQUIRED, not defaulted: an
        optional wall-clock fallback here was the last bare `datetime.now()` on a request
        path in `src/` (hard rule 4). Callers pass `clock.now()`; the AWS test-suite
        timestamp reproduces exactly by passing its own instant.

        `include_content_sha256` defaults `True` because S3 requires the
        header on every request; it exists only so
        `tests/phase0/test_tracestore.py` can reproduce the AWS-published
        `service` (non-S3) test vectors verbatim, which predate S3's
        stricter requirement and omit it.
        """
        moment = now
        amz_date = moment.strftime("%Y%m%dT%H%M%SZ")
        date_stamp = moment.strftime("%Y%m%d")

        full_headers = dict(headers)
        full_headers["x-amz-date"] = amz_date
        if include_content_sha256:
            full_headers["x-amz-content-sha256"] = payload_hash

        creq = build_canonical_request(
            method=method, path=path, query=query, headers=full_headers, payload_hash=payload_hash
        )
        sts = build_string_to_sign(
            amz_date=amz_date,
            date_stamp=date_stamp,
            region=self.region,
            service=self.service,
            canonical_request=creq,
        )
        signing_key = derive_signing_key(self.secret_key, date_stamp, self.region, self.service)
        signature = hmac.new(signing_key, sts.encode("utf-8"), hashlib.sha256).hexdigest()
        _, signed_headers = canonical_headers(full_headers)
        scope = credential_scope(date_stamp, self.region, self.service)
        authorization = (
            f"{ALGORITHM} Credential={self.access_key}/{scope}, "
            f"SignedHeaders={signed_headers}, Signature={signature}"
        )
        result = {"x-amz-date": amz_date, "Authorization": authorization}
        if include_content_sha256:
            result["x-amz-content-sha256"] = payload_hash
        return result
