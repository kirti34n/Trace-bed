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
from typing import Any, Final, Literal, Protocol, runtime_checkable

import httpx
import jwt
from jwt import PyJWTError
from jwt.algorithms import RSAAlgorithm

from tracebed.domain.canonical import sha256_hex
from tracebed.domain.clock import Clock, SystemClock
from tracebed.domain.errors import AuthenticationFailed
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
        self, kind: PrincipalKind, external_ref: str
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
# hash is ever persisted; the plaintext secret is returned exactly once, at
# mint time (`POST /admin/agents/register`), and never again.
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

    def authenticate(self, *, authorization: str | None, api_key: str | None) -> Principal:
        if not api_key:
            raise AuthenticationFailed("missing API key")
        key_id, secret = _parse_api_key(api_key)
        presented_hash = sha256_hex(secret.encode("utf-8"))
        record = self._principals.get_principal_by_external_ref("api_key", key_id)
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


class OidcJwksVerifier:
    """RS256 bearer-token verification against a fetched JWKS document."""

    def __init__(
        self,
        jwks_url: str,
        issuer: str,
        *,
        audience: str = "tracebed",
        http: httpx.Client | None = None,
        principals: PrincipalLookup,
        clock: Clock | None = None,
    ) -> None:
        self._jwks_url = jwks_url
        self._issuer = issuer
        self._audience = audience
        self._http = http if http is not None else httpx.Client(timeout=5.0)
        self._principals = principals
        self._clock: Clock = clock if clock is not None else SystemClock()
        self._jwk_cache: dict[str, Any] = {}
        # Serialises refetches: without it, N concurrent unknown-`kid` requests
        # each pass the cooldown check before any of them records a fetch, and
        # the amplification the cooldown exists to stop reappears under exactly
        # the concurrency an attacker would use.
        self._refresh_lock = threading.Lock()
        self._last_refresh_ms: float | None = None

    def authenticate(self, *, authorization: str | None, api_key: str | None) -> Principal:
        token = self._extract_bearer(authorization)
        try:
            header = jwt.get_unverified_header(token)
        except PyJWTError as exc:
            raise AuthenticationFailed("malformed bearer token") from exc

        claims = self._decode(token, self._candidate_keys(header.get("kid")))

        sub = claims.get("sub")
        if not isinstance(sub, str) or not sub:
            raise AuthenticationFailed("bearer token has no subject")

        record = self._principals.get_principal_by_external_ref("oidc_sub", sub)
        if record is None or record.revoked:
            raise AuthenticationFailed("unknown principal")
        return Principal(
            principal_id=record.principal_id, kind="oidc_sub", external_ref=record.external_ref
        )

    @staticmethod
    def _extract_bearer(authorization: str | None) -> str:
        if not authorization:
            raise AuthenticationFailed("missing bearer token")
        scheme, _, token = authorization.partition(" ")
        if scheme.lower() != "bearer" or not token:
            raise AuthenticationFailed("missing bearer token")
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
                    options={"require": ["sub", "iss", "aud", "exp"]},
                )
            except PyJWTError:
                continue
            return dict(claims)
        raise AuthenticationFailed("bearer token failed verification")

    def _candidate_keys(self, kid: object) -> list[Any]:
        """The keys this token may legitimately have been signed by.

        A named `kid` resolves to exactly one key. A token with NO `kid` is
        checked against every key the IdP currently advertises rather than an
        arbitrary one: picking `next(iter(cache))` silently rejects valid
        tokens whenever the IdP publishes more than one key (i.e. throughout
        every key rotation), and trying all of them is safe because every key
        in the set is one the configured issuer vouches for.
        """
        if isinstance(kid, str) and kid:
            key = self._jwk_cache.get(kid)
            if key is None and self._refresh_jwks():
                key = self._jwk_cache.get(kid)
            return [] if key is None else [key]
        if not self._jwk_cache:
            self._refresh_jwks()
        return list(self._jwk_cache.values())

    def _refresh_jwks(self) -> bool:
        """Returns True if a fetch actually happened, False if the cooldown
        suppressed it. Raises `AuthenticationFailed` if the fetch itself
        failed — a caller cannot be authenticated without a usable key set."""
        with self._refresh_lock:
            now_ms = self._clock.monotonic_ms()
            if (
                self._last_refresh_ms is not None
                and now_ms - self._last_refresh_ms < _JWKS_REFRESH_COOLDOWN_MS
            ):
                return False
            # Stamped BEFORE the fetch, so a hanging or erroring IdP cannot be
            # used to reopen the amplification window on every retry.
            self._last_refresh_ms = now_ms
            self._jwk_cache = self._fetch_jwks()
            return True

    def _fetch_jwks(self) -> dict[str, Any]:
        try:
            response = self._http.get(self._jwks_url)
            response.raise_for_status()
            document = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise AuthenticationFailed("JWKS document unavailable") from exc

        keys = document.get("keys") if isinstance(document, dict) else None
        if not isinstance(keys, list):
            raise AuthenticationFailed("JWKS document malformed")

        cache: dict[str, Any] = {}
        for jwk in keys:
            if not isinstance(jwk, dict):
                continue
            kid = jwk.get("kid")
            if not isinstance(kid, str) or not kid:
                continue
            try:
                cache[kid] = RSAAlgorithm.from_jwk(json.dumps(jwk))
            except (ValueError, TypeError, KeyError):
                # A malformed individual JWK must not blind the whole set —
                # skip it and keep the rest usable.
                continue
        return cache


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

    def authenticate(self, *, authorization: str | None, api_key: str | None) -> Principal:
        # Dispatch on the SCHEME, not on the header's mere presence: an empty
        # `Authorization:` header (proxies and some HTTP clients add one) or a
        # non-Bearer scheme would otherwise be routed to OIDC and rejected
        # there, denying a caller who also presented a perfectly valid
        # `X-API-Key`. Presence-based dispatch turns a stray header into an
        # outage, not into a security property.
        if self._oidc is not None and _is_bearer(authorization):
            return self._oidc.authenticate(authorization=authorization, api_key=api_key)
        if api_key and self._api_key_mode and self._api_key is not None:
            return self._api_key.authenticate(authorization=authorization, api_key=api_key)
        raise AuthenticationFailed("no credential presented")


def _is_bearer(authorization: str | None) -> bool:
    if not authorization:
        return False
    scheme, sep, token = authorization.partition(" ")
    return bool(sep) and scheme.lower() == "bearer" and bool(token.strip())
