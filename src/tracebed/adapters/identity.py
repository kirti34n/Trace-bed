"""Caller identity (PHASE0-CONTRACT.md §9.1, PHASE-0 Task 8).

The service always verifies its own credentials. It never trusts a host's
asserted actor header, because that assertion is precisely what an attacker
would forge to cross a project wall — and `project_id` is derived from the
principal this module returns.

STATUS: `Principal`, `PrincipalRecord` and `PrincipalLookup` are final
(landed by an earlier chunk); this file is EXTENDED, not replaced, to add
the three verifiers api-auth owns: `ApiKeyVerifier`, `OidcJwksVerifier`,
`ChainVerifier`.
"""

from __future__ import annotations

import hmac
import json
import threading
from dataclasses import dataclass
from typing import Any, Final, Literal, Protocol, cast, runtime_checkable
from urllib.parse import urlsplit

import httpx
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt import PyJWTError
from jwt.algorithms import RSAAlgorithm

from tracebed.domain.canonical import sha256_hex
from tracebed.domain.clock import Clock, SystemClock
from tracebed.domain.deadline import RemainingBudget
from tracebed.domain.errors import AuthenticationFailed, RequestDeadlineExceeded
from tracebed.domain.ids import PrincipalId

__all__ = [
    "ApiKeyVerifier",
    "ChainVerifier",
    "OidcJwksVerifier",
    "Principal",
    "PrincipalLookup",
    "PrincipalRecord",
]

PrincipalKind = Literal["oidc_sub", "api_key"]


@dataclass(frozen=True, slots=True)
class Principal:
    """An authenticated caller. Produced only by a verifier, never by a route.

    Deliberately carries no project: scope derivation is a second, separate step
    (`Repo.resolve_project`) so that "who are you" and "what may you see" cannot
    be satisfied by one forged value.
    """

    principal_id: PrincipalId
    kind: PrincipalKind
    external_ref: str
    """The OIDC `sub`, or the public half of an API key. Never the secret."""


@dataclass(frozen=True, slots=True)
class PrincipalRecord:
    """The stored side of a principal, as the registry holds it."""

    principal_id: PrincipalId
    kind: PrincipalKind
    external_ref: str
    key_hash: str | None
    """sha256 hex of the API-key secret. None for OIDC principals."""
    revoked: bool


@runtime_checkable
class PrincipalLookup(Protocol):
    """How a verifier finds a stored principal.

    A Protocol rather than a Repo reference so `ApiKeyVerifier` can be tested
    with an in-memory dict on a machine with no database.
    """

    def get_principal_by_external_ref(
        self,
        kind: PrincipalKind,
        external_ref: str,
        *,
        deadline: RemainingBudget | None = None,
    ) -> PrincipalRecord | None:
        """Returns None for unknown or revoked. Must not raise on a miss —
        a distinguishable exception is a principal-enumeration oracle."""
        ...


# --------------------------------------------------------------------------- #
# API-key verification (contract §9.1 / C-19).
#
# Format: ``tb_sk_<key_id>.<secret>`` — key_id is a server-minted UUID hex
# (the public half, stored as `principal.external_ref`), secret is the
# high-entropy half whose sha256 is stored as `principal.key_hash`. Only the
# hash is ever persisted; the plaintext secret is returned exactly once by the
# owner-side onboarding/provisioning path, and never again. There is no HTTP
# agent-registration route in this runtime.
# --------------------------------------------------------------------------- #

_API_KEY_PREFIX: Literal["tb_sk_"] = "tb_sk_"

# A fixed dummy hash, hashed once at import (not derived from any real secret).
# Used to give the "principal not found" path the same shape of work as the
# "principal found, secret wrong" path: both end in exactly one
# `hmac.compare_digest` call against a 64-hex-char string. Without this, an
# unknown key_id returns before ever touching `compare_digest`, and the two
# paths are trivially distinguishable by an attacker measuring wall time —
# turning `ApiKeyVerifier` into a principal-enumeration oracle even though
# `PrincipalLookup.get_principal_by_external_ref` itself promises not to be one.
_DUMMY_KEY_HASH: Final = sha256_hex(b"tracebed-api-key-verifier-constant-time-decoy")


def _parse_api_key(raw: str) -> tuple[str, str]:
    """Splits ``tb_sk_<key_id>.<secret>``. Raises `AuthenticationFailed` on any
    shape that is not exactly that — a malformed key is not a lookup miss and
    must not reach `PrincipalLookup` at all (there is nothing to look up)."""
    if not raw.startswith(_API_KEY_PREFIX):
        raise AuthenticationFailed("malformed API key")
    key_id, sep, secret = raw[len(_API_KEY_PREFIX) :].partition(".")
    if not sep or not key_id or not secret:
        raise AuthenticationFailed("malformed API key")
    return key_id, secret


class ApiKeyVerifier:
    """Verifies `X-API-Key: tb_sk_<key_id>.<secret>` against a `PrincipalLookup`.

    Every rejection path — malformed key, unknown key_id, revoked principal,
    wrong secret — raises the exact same `AuthenticationFailed` with the exact
    same message (contract §3.1: "never distinguishes 'wrong key' from
    'unknown key'"). The unknown-key_id and wrong-secret paths are additionally
    balanced to cost the same wall-clock time (see `_DUMMY_KEY_HASH`).
    """

    def __init__(self, principals: PrincipalLookup) -> None:
        self._principals = principals

    def authenticate(
        self,
        *,
        authorization: str | None,
        api_key: str | None,
        deadline: RemainingBudget | None = None,
    ) -> Principal:
        if not api_key:
            raise AuthenticationFailed("missing API key")
        key_id, secret = _parse_api_key(api_key)
        presented_hash = sha256_hex(secret.encode("utf-8"))
        _require_remaining(deadline)
        if deadline is None:
            record = self._principals.get_principal_by_external_ref("api_key", key_id)
        else:
            record = self._principals.get_principal_by_external_ref(
                "api_key", key_id, deadline=deadline
            )
        if record is None or record.revoked or record.key_hash is None:
            # Miss (or a revoked/keyless row masquerading as one, to the caller):
            # still spend exactly one compare_digest against a same-length hash.
            hmac.compare_digest(presented_hash, _DUMMY_KEY_HASH)
            raise AuthenticationFailed("invalid API key")
        if not hmac.compare_digest(presented_hash, record.key_hash):
            raise AuthenticationFailed("invalid API key")
        return Principal(
            principal_id=record.principal_id, kind="api_key", external_ref=record.external_ref
        )


# --------------------------------------------------------------------------- #
# OIDC / JWKS verification (contract §9.1).
#
# CONTRACT_GAP: the contract's sketch says "RS256 via PyJWT + PyJWKClient", but
# `jwt.PyJWKClient` (installed pyjwt>=2.10) fetches its JWKS document over
# `urllib` internally and has no seam for injecting a transport — it cannot
# honour the `http: httpx.Client | None` constructor parameter the contract
# itself specifies (needed so `test_auth.py` can serve a *generated* JWKS
# without a live network, per the offline-first rule in §12). Implemented
# instead with the same verification semantics (RS256, iss/aud checked, keyed
# by `kid`) but fetching and parsing the JWKS document directly through the
# injected `httpx.Client`, converting each JWK to a public key with
# `jwt.algorithms.RSAAlgorithm.from_jwk`. Also CONTRACT_GAP: the sketch's
# constructor has no principal-lookup parameter even though "principal looked
# up by kind='oidc_sub'" is the described behaviour — added as a required
# keyword-only `principals: PrincipalLookup` argument. A `clock: Clock` was
# added for the same reason: the JWKS refetch cooldown below needs elapsed
# time, and the hard rules forbid reading a wall clock outside `SystemClock`.
# --------------------------------------------------------------------------- #

# The `kid` header of an UNVERIFIED token is fully attacker-controlled, and a
# cache miss on it is what triggers an outbound JWKS fetch. Without a floor on
# the refetch rate, one anonymous request per novel `kid` = one outbound HTTP
# request, i.e. the API is a request amplifier aimed at the IdP, and every one
# of those requests also pins a server worker thread for the client timeout.
# The cooldown makes JWKS fetches O(1) per window no matter how many distinct
# `kid`s an attacker invents, while still picking up a genuine IdP key rotation
# within one window without a restart.
_JWKS_REFRESH_COOLDOWN_MS: Final = 10_000.0
_MAX_BEARER_BYTES: Final = 16 * 1024
_MAX_JWKS_BYTES: Final = 256 * 1024
_MAX_JWKS_KEYS: Final = 16
_MAX_KID_CHARS: Final = 128
_MIN_RSA_BITS: Final = 2048


def _require_remaining(deadline: RemainingBudget | None) -> None:
    """Refuse a new request-bound stage after its shared budget expires."""

    if deadline is not None and deadline.remaining_ms() <= 0:
        raise RequestDeadlineExceeded()


def _clamp_timeout(timeout: httpx.Timeout, deadline: RemainingBudget | None) -> httpx.Timeout:
    """Return a per-request HTTPX timeout without changing the shared client.

    HTTPX applies these phase limits when a request starts.  It cannot safely replace an active
    stream's read timeout after that point, so callers also check ``deadline`` before every body
    iterator advance.
    """

    if deadline is None:
        # Passing ``timeout=None`` to ``Client.stream`` disables every timeout.  Keep the
        # configured object instead, without mutating the shared client.
        return timeout
    remaining_ms = deadline.remaining_ms()
    if remaining_ms <= 0:
        raise RequestDeadlineExceeded()
    remaining_s = remaining_ms / 1000.0

    def clamp(value: float | None) -> float:
        return remaining_s if value is None else min(value, remaining_s)

    return httpx.Timeout(
        connect=clamp(timeout.connect),
        read=clamp(timeout.read),
        write=clamp(timeout.write),
        pool=clamp(timeout.pool),
    )


class OidcJwksVerifier:
    """RS256 bearer-token verification against a fetched JWKS document."""

    def __init__(
        self,
        jwks_url: str,
        issuer: str,
        *,
        audience: str | None = "tracebed",
        http: httpx.Client | None = None,
        principals: PrincipalLookup,
        clock: Clock | None = None,
    ) -> None:
        _require_controlled_https_url(jwks_url)
        _require_controlled_https_url(issuer)
        if type(audience) is not str or not audience or len(audience) > 255:
            raise ValueError("OIDC audience is invalid")
        self._jwks_url = jwks_url
        self._issuer = issuer
        self._audience = audience
        self._http = (
            http
            if http is not None
            else httpx.Client(timeout=httpx.Timeout(2.0), follow_redirects=False, trust_env=False)
        )
        self._principals = principals
        self._clock: Clock = clock if clock is not None else SystemClock()
        self._jwk_cache: dict[str, Any] = {}
        # Serialises refetches: without it, N concurrent unknown-`kid` requests
        # each pass the cooldown check before any of them records a fetch, and
        # the amplification the cooldown exists to stop reappears under exactly
        # the concurrency an attacker would use.
        self._refresh_lock = threading.Lock()
        self._last_refresh_ms: float | None = None

    def authenticate(
        self,
        *,
        authorization: str | None,
        api_key: str | None,
        deadline: RemainingBudget | None = None,
    ) -> Principal:
        token = self._extract_bearer(authorization)
        # The private API consumes credentials, never browser identity
        # assertions.  Keycloak marks its access tokens with ``typ=Bearer``
        # and its ID tokens with ``typ=ID``; checking that authenticated claim
        # prevents a dashboard ID token from becoming an API bearer token.
        claims = self.verify_access_token(token, deadline=deadline)

        sub = claims.get("sub")
        if not isinstance(sub, str) or not sub or len(sub) > 255:
            raise AuthenticationFailed("bearer token has no subject")

        _require_remaining(deadline)
        if deadline is None:
            record = self._principals.get_principal_by_external_ref("oidc_sub", sub)
        else:
            record = self._principals.get_principal_by_external_ref(
                "oidc_sub", sub, deadline=deadline
            )
        if record is None or record.revoked:
            raise AuthenticationFailed("unknown principal")
        return Principal(
            principal_id=record.principal_id, kind="oidc_sub", external_ref=record.external_ref
        )

    def preflight(self) -> None:
        """Fetch and validate the configured JWKS before serving credentials."""
        if not self._refresh_jwks() or not self._jwk_cache:
            raise AuthenticationFailed("JWKS document unavailable")

    def verify_access_token(
        self, token: str, *, deadline: RemainingBudget | None = None
    ) -> dict[str, Any]:
        """Validate a Keycloak-compatible access token without assigning scope."""
        return self._verify_token(token, purpose="access", nonce=None, deadline=deadline)

    def verify_id_token(self, token: str, *, nonce: str) -> dict[str, Any]:
        """Validate an ID token for the browser authorization-code callback.

        An ID token is an authentication assertion for the OIDC client, not a
        bearer credential for this API.  The callback always has a freshly
        generated nonce, so make it mandatory here rather than leaving a
        second permissive verification entry point around.
        """
        if not isinstance(nonce, str) or not nonce:
            raise AuthenticationFailed("OIDC nonce is invalid")
        return self._verify_token(token, purpose="id", nonce=nonce)

    def verify_token(self, token: str, *, nonce: str | None = None) -> dict[str, Any]:
        """Backward-compatible explicit-ID-token entry point.

        New callers must use :meth:`verify_access_token` or
        :meth:`verify_id_token`; retaining this name avoids turning an upgrade
        into an accidental permissive path.  A nonce is required, therefore it
        can only validate an ID token and cannot authenticate an API request.
        """
        if nonce is None:
            raise AuthenticationFailed("OIDC nonce is invalid")
        return self.verify_id_token(token, nonce=nonce)

    def _verify_token(
        self,
        token: str,
        *,
        purpose: Literal["access", "id"],
        nonce: str | None,
        deadline: RemainingBudget | None = None,
    ) -> dict[str, Any]:
        if type(token) is not str or not token:
            raise AuthenticationFailed("malformed bearer token")
        try:
            if len(token.encode("ascii")) > _MAX_BEARER_BYTES:
                raise AuthenticationFailed("bearer token is too large")
        except UnicodeEncodeError as exc:
            raise AuthenticationFailed("malformed bearer token") from exc
        try:
            header = jwt.get_unverified_header(token)
        except PyJWTError as exc:
            raise AuthenticationFailed("malformed bearer token") from exc
        # RFC 9068 access-token JWTs use ``at+jwt``.  Keycloak's default
        # access and ID tokens both use ``JWT``.  No other presentation type is
        # accepted, and purpose is then separated by Keycloak's signed claim.
        allowed_headers = {"JWT", "at+jwt"} if purpose == "access" else {"JWT"}
        if header.get("alg") != "RS256" or header.get("typ") not in allowed_headers:
            raise AuthenticationFailed("bearer token failed verification")
        kid = header.get("kid")
        if not _valid_kid(kid):
            raise AuthenticationFailed("bearer token failed verification")
        claims = self._decode(token, self._candidate_keys(cast(str, kid), deadline=deadline))
        token_type = claims.get("typ")
        expected_type = "Bearer" if purpose == "access" else "ID"
        if not isinstance(token_type, str) or not hmac.compare_digest(token_type, expected_type):
            raise AuthenticationFailed("bearer token failed verification")
        if purpose == "id":
            assert nonce is not None
            received = claims.get("nonce")
            if not isinstance(received, str) or not hmac.compare_digest(received, nonce):
                raise AuthenticationFailed("OIDC nonce is invalid")
        return claims

    @staticmethod
    def _extract_bearer(authorization: str | None) -> str:
        if not authorization:
            raise AuthenticationFailed("missing bearer token")
        scheme, _, token = authorization.partition(" ")
        if scheme.lower() != "bearer" or not token:
            raise AuthenticationFailed("missing bearer token")
        if len(token.encode("ascii", errors="ignore")) > _MAX_BEARER_BYTES:
            raise AuthenticationFailed("bearer token is too large")
        return token

    def _decode(self, token: str, keys: list[Any]) -> dict[str, Any]:
        """Verifies against each candidate key and returns the claims.

        `require` carries `exp`: PyJWT only checks an expiry that is PRESENT,
        so without this an IdP (or a token minted by one) that omits `exp`
        yields a bearer credential that never stops being valid — a stolen
        token would be usable forever. `algorithms=["RS256"]` is what refuses
        `alg: none` and the HS256-keyed-by-the-public-key confusion.
        """
        for key in keys:
            try:
                claims = jwt.decode(
                    token,
                    key=key,
                    algorithms=["RS256"],
                    audience=self._audience,
                    issuer=self._issuer,
                    options={"require": ["sub", "iss", "aud", "exp", "iat"]},
                )
            except PyJWTError:
                continue
            return dict(claims)
        raise AuthenticationFailed("bearer token failed verification")

    def _candidate_keys(self, kid: str, *, deadline: RemainingBudget | None = None) -> list[Any]:
        """The keys this token may legitimately have been signed by.

        A named ``kid`` resolves to exactly one key.  Strict verification does
        not try every key when the attacker omits a key id: that turns one
        malformed token into a bounded-but-avoidable signature work multiplier
        and accepts an ambiguous issuer key selection policy.
        """
        _require_remaining(deadline)
        key = self._jwk_cache.get(kid)
        if key is None and self._refresh_jwks(deadline=deadline):
            key = self._jwk_cache.get(kid)
        return [] if key is None else [key]

    def _refresh_jwks(self, *, deadline: RemainingBudget | None = None) -> bool:
        """Returns True if a fetch actually happened, False if the cooldown
        suppressed it. Raises `AuthenticationFailed` if the fetch itself
        failed — a caller cannot be authenticated without a usable key set."""
        if deadline is None:
            self._refresh_lock.acquire()
            acquired = True
        else:
            remaining_ms = deadline.remaining_ms()
            if remaining_ms <= 0:
                raise RequestDeadlineExceeded()
            acquired = self._refresh_lock.acquire(timeout=remaining_ms / 1000.0)
            if not acquired:
                raise RequestDeadlineExceeded()
        try:
            _require_remaining(deadline)
            now_ms = self._clock.monotonic_ms()
            if (
                self._last_refresh_ms is not None
                and now_ms - self._last_refresh_ms < _JWKS_REFRESH_COOLDOWN_MS
            ):
                return False
            # Stamped BEFORE the fetch, so a hanging or erroring IdP cannot be
            # used to reopen the amplification window on every retry.
            self._last_refresh_ms = now_ms
            self._jwk_cache = self._fetch_jwks(deadline=deadline)
            return True
        finally:
            if acquired:
                self._refresh_lock.release()

    def _fetch_jwks(self, *, deadline: RemainingBudget | None = None) -> dict[str, Any]:
        try:
            _require_remaining(deadline)
            timeout = _clamp_timeout(self._http.timeout, deadline)
            with self._http.stream(
                "GET", self._jwks_url, headers={"Accept": "application/json"}, timeout=timeout
            ) as response:
                response.raise_for_status()
                if response.history:
                    raise ValueError
                body = _bounded_sync_body(response, _MAX_JWKS_BYTES, deadline=deadline)
            _require_remaining(deadline)
            document = json.loads(body)
            _require_remaining(deadline)
        except RequestDeadlineExceeded:
            raise
        except httpx.TimeoutException as exc:
            if deadline is not None and deadline.remaining_ms() <= 0:
                raise RequestDeadlineExceeded() from exc
            raise AuthenticationFailed("JWKS document unavailable") from exc
        except (httpx.HTTPError, UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
            raise AuthenticationFailed("JWKS document unavailable") from exc

        keys = document.get("keys") if isinstance(document, dict) else None
        if not isinstance(keys, list) or not keys or len(keys) > _MAX_JWKS_KEYS:
            raise AuthenticationFailed("JWKS document malformed")

        cache: dict[str, Any] = {}
        for jwk in keys:
            _require_remaining(deadline)
            if not isinstance(jwk, dict):
                raise AuthenticationFailed("JWKS document malformed")
            kid = jwk.get("kid")
            if not _valid_kid(kid) or kid in cache:
                raise AuthenticationFailed("JWKS document malformed")
            kid = cast(str, kid)
            if (
                jwk.get("kty") != "RSA"
                or jwk.get("use") != "sig"
                or jwk.get("alg") != "RS256"
                or (
                    "key_ops" in jwk
                    and (not isinstance(jwk["key_ops"], list) or jwk["key_ops"] != ["verify"])
                )
            ):
                continue
            try:
                key = RSAAlgorithm.from_jwk(json.dumps(jwk))
            except (ValueError, TypeError, KeyError, jwt.InvalidKeyError):
                continue
            if not isinstance(key, rsa.RSAPublicKey) or key.key_size < _MIN_RSA_BITS:
                continue
            cache[kid] = key
        if not cache:
            raise AuthenticationFailed("JWKS document malformed")
        _require_remaining(deadline)
        return cache


def _require_controlled_https_url(value: object) -> None:
    if type(value) is not str:
        raise ValueError("OIDC URL is invalid")
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("OIDC URL is invalid")


def _valid_kid(value: object) -> bool:
    return (
        type(value) is str
        and 0 < len(value) <= _MAX_KID_CHARS
        and all(
            character.isascii() and (character.isalnum() or character in "._-")
            for character in value
        )
    )


def _bounded_sync_body(
    response: httpx.Response, limit: int, *, deadline: RemainingBudget | None = None
) -> bytes:
    body = bytearray()
    chunks = iter(response.iter_bytes())
    while True:
        _require_remaining(deadline)
        try:
            chunk = next(chunks)
        except StopIteration:
            break
        body.extend(chunk)
        if len(body) > limit:
            raise ValueError("response exceeds the configured bound")
    return bytes(body)


class ChainVerifier:
    """Bearer -> OIDC (if configured); `X-API-Key` -> `ApiKeyVerifier` (if
    `api_key_mode`); neither present/valid -> `AuthenticationFailed` (contract
    §9.1). Satisfies `adapters.ports.PrincipalPort` structurally.
    """

    def __init__(
        self,
        *,
        oidc: OidcJwksVerifier | None,
        api_key: ApiKeyVerifier | None,
        api_key_mode: bool,
    ) -> None:
        self._oidc = oidc
        self._api_key = api_key
        self._api_key_mode = api_key_mode

    def authenticate(
        self,
        *,
        authorization: str | None,
        api_key: str | None,
        deadline: RemainingBudget | None = None,
    ) -> Principal:
        # Dispatch on the SCHEME, not on the header's mere presence: an empty
        # `Authorization:` header (proxies and some HTTP clients add one) or a
        # non-Bearer scheme would otherwise be routed to OIDC and rejected
        # there, denying a caller who also presented a perfectly valid
        # `X-API-Key`. Presence-based dispatch turns a stray header into an
        # outage, not into a security property.
        if self._oidc is not None and _is_bearer(authorization):
            if deadline is None:
                return self._oidc.authenticate(authorization=authorization, api_key=api_key)
            return self._oidc.authenticate(
                authorization=authorization, api_key=api_key, deadline=deadline
            )
        if api_key and self._api_key_mode and self._api_key is not None:
            if deadline is None:
                return self._api_key.authenticate(authorization=authorization, api_key=api_key)
            return self._api_key.authenticate(
                authorization=authorization, api_key=api_key, deadline=deadline
            )
        raise AuthenticationFailed("no credential presented")


def _is_bearer(authorization: str | None) -> bool:
    if not authorization:
        return False
    scheme, sep, token = authorization.partition(" ")
    return bool(sep) and scheme.lower() == "bearer" and bool(token.strip())
