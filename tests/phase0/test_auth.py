"""Identity verifiers (PHASE0-CONTRACT.md §9.1, §13.2 `test_auth.py`).

Proves: no-credential -> 401; a wrong API key -> 401 (with the same message
as an unknown key, never distinguishing "wrong" from "unknown"); a valid API
key resolves the principal the fake lookup holds; OIDC verification against a
locally generated RSA keypair and JWKS document (no network, per §12's
offline-first rule); `require_admin_key` rejects a missing/wrong/unconfigured
admin key and accepts the right one.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, cast
from uuid import uuid4

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import Depends, FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient
from jwt.algorithms import RSAAlgorithm

from tracebed.adapters.identity import (
    ApiKeyVerifier,
    ChainVerifier,
    OidcJwksVerifier,
    Principal,
    PrincipalRecord,
)
from tracebed.api.deps import require_admin_key
from tracebed.api.main import _RepoPrincipalLookup
from tracebed.domain.canonical import sha256_hex
from tracebed.domain.clock import FakeClock
from tracebed.domain.errors import AuthenticationFailed
from tracebed.domain.ids import PrincipalId
from tracebed.stores.pg.rows import PrincipalRow

if TYPE_CHECKING:
    from tracebed.adapters.identity import PrincipalKind

pytestmark = pytest.mark.phase0


# --------------------------------------------------------------------------- #
# Fakes.
# --------------------------------------------------------------------------- #


class FakePrincipalLookup:
    """In-memory `PrincipalLookup` — the offline stand-in every chunk's own
    tests build (contract §12: chunk-local fakes live in the chunk's tests)."""

    def __init__(self) -> None:
        self._by_key: dict[tuple[str, str], PrincipalRecord] = {}

    def put(self, kind: PrincipalKind, external_ref: str, record: PrincipalRecord) -> None:
        self._by_key[(kind, external_ref)] = record

    def get_principal_by_external_ref(
        self, kind: PrincipalKind, external_ref: str
    ) -> PrincipalRecord | None:
        return self._by_key.get((kind, external_ref))


def _api_key_record(*, key_hash: str, revoked: bool = False) -> PrincipalRecord:
    return PrincipalRecord(
        principal_id=PrincipalId(uuid4()),
        kind="api_key",
        external_ref="deadbeefdeadbeefdeadbeefdeadbeef",
        key_hash=key_hash,
        revoked=revoked,
    )


# --------------------------------------------------------------------------- #
# ApiKeyVerifier.
# --------------------------------------------------------------------------- #


class TestApiKeyVerifier:
    def test_missing_api_key_is_401(self) -> None:
        verifier = ApiKeyVerifier(FakePrincipalLookup())
        with pytest.raises(AuthenticationFailed):
            verifier.authenticate(authorization=None, api_key=None)

    def test_malformed_api_key_is_401(self) -> None:
        verifier = ApiKeyVerifier(FakePrincipalLookup())
        for bad in ("not-a-key", "tb_sk_", "tb_sk_onlyid", "tb_pk_deadbeef.secret"):
            with pytest.raises(AuthenticationFailed):
                verifier.authenticate(authorization=None, api_key=bad)

    def test_unknown_key_id_is_401(self) -> None:
        verifier = ApiKeyVerifier(FakePrincipalLookup())
        with pytest.raises(AuthenticationFailed):
            verifier.authenticate(authorization=None, api_key="tb_sk_deadbeefdeadbeef.somesecret")

    def test_valid_key_resolves_the_looked_up_principal(self) -> None:
        lookup = FakePrincipalLookup()
        secret = "s3cret-value-of-sufficient-length"
        record = _api_key_record(key_hash=sha256_hex(secret.encode("utf-8")))
        lookup.put("api_key", record.external_ref, record)
        verifier = ApiKeyVerifier(lookup)

        principal = verifier.authenticate(
            authorization=None, api_key=f"tb_sk_{record.external_ref}.{secret}"
        )

        assert principal == Principal(
            principal_id=record.principal_id, kind="api_key", external_ref=record.external_ref
        )

    def test_wrong_secret_is_401_same_message_as_unknown_key(self) -> None:
        lookup = FakePrincipalLookup()
        record = _api_key_record(key_hash=sha256_hex(b"the-real-secret"))
        lookup.put("api_key", record.external_ref, record)
        verifier = ApiKeyVerifier(lookup)

        with pytest.raises(AuthenticationFailed) as wrong_secret:
            verifier.authenticate(
                authorization=None, api_key=f"tb_sk_{record.external_ref}.totally-wrong"
            )
        with pytest.raises(AuthenticationFailed) as unknown_key:
            verifier.authenticate(authorization=None, api_key="tb_sk_0000000000000000.anything")

        # Never distinguishable (domain/errors.py's AuthenticationFailed docstring):
        # "wrong key" and "unknown key" must read identically to a caller.
        assert str(wrong_secret.value) == str(unknown_key.value)

    def test_revoked_principal_is_401(self) -> None:
        lookup = FakePrincipalLookup()
        secret = "still-the-right-secret"
        record = _api_key_record(key_hash=sha256_hex(secret.encode("utf-8")), revoked=True)
        lookup.put("api_key", record.external_ref, record)
        verifier = ApiKeyVerifier(lookup)

        with pytest.raises(AuthenticationFailed):
            verifier.authenticate(
                authorization=None, api_key=f"tb_sk_{record.external_ref}.{secret}"
            )

    def test_constant_time_compare_used_for_the_hash(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Not a timing measurement (flaky by nature) — proves the *mechanism*
        the CONSTANT TIME MATTERS instruction asks for: `hmac.compare_digest`
        is on the call path for both a miss and a wrong secret, not `==`."""
        calls: list[tuple[str, str]] = []
        import hmac as hmac_module

        real_compare = hmac_module.compare_digest

        def spy(a: str, b: str) -> bool:
            calls.append((a, b))
            return real_compare(a, b)

        monkeypatch.setattr("tracebed.adapters.identity.hmac.compare_digest", spy)

        lookup = FakePrincipalLookup()
        record = _api_key_record(key_hash=sha256_hex(b"the-real-secret"))
        lookup.put("api_key", record.external_ref, record)
        verifier = ApiKeyVerifier(lookup)

        with pytest.raises(AuthenticationFailed):
            verifier.authenticate(authorization=None, api_key="tb_sk_unknown0000000000.x")
        with pytest.raises(AuthenticationFailed):
            verifier.authenticate(
                authorization=None, api_key=f"tb_sk_{record.external_ref}.wrong-secret"
            )

        assert len(calls) == 2  # exactly one compare_digest call per rejection path


# --------------------------------------------------------------------------- #
# OidcJwksVerifier — RS256 against a locally generated JWKS (no network).
# --------------------------------------------------------------------------- #


def _generate_rsa_jwk(kid: str) -> tuple[bytes, dict[str, object]]:
    """Returns (private_key_pem, jwk_dict) for a fresh 2048-bit RSA keypair."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    jwk = RSAAlgorithm.to_jwk(private_key.public_key(), as_dict=True)
    jwk["kid"] = kid
    jwk["use"] = "sig"
    jwk["alg"] = "RS256"
    return pem, jwk


def _mock_jwks_client(jwks_documents: dict[str, dict[str, object]]) -> httpx.Client:
    """Serves `jwks_documents[url]` with zero real network I/O (httpx.MockTransport)."""

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if url not in jwks_documents:
            return httpx.Response(404)
        return httpx.Response(200, json=jwks_documents[url])

    return httpx.Client(transport=httpx.MockTransport(handler))


_ISSUER = "https://idp.example.test/"
_AUDIENCE = "tracebed"
_JWKS_URL = "https://idp.example.test/.well-known/jwks.json"


def _sign_token(
    private_key_pem: bytes,
    *,
    kid: str | None,
    sub: str = "user-42",
    issuer: str = _ISSUER,
    audience: str = _AUDIENCE,
    expires_in: timedelta | None = timedelta(minutes=5),
) -> str:
    now = datetime.now(UTC)
    claims: dict[str, object] = {"sub": sub, "iss": issuer, "aud": audience, "iat": now}
    if expires_in is not None:
        claims["exp"] = now + expires_in
    return jwt.encode(
        claims,
        private_key_pem,
        algorithm="RS256",
        headers={"kid": kid} if kid is not None else None,
    )


def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _forge_hs256(claims: dict[str, object], *, hmac_secret: bytes, kid: str) -> str:
    """The RSA->HMAC confusion token: `alg` says HS256 and the MAC key is the
    IdP's own PUBLIC key, which a verifier that trusts the header's `alg`
    would happily accept."""
    header = _b64u(json.dumps({"alg": "HS256", "typ": "JWT", "kid": kid}).encode("utf-8"))
    payload = _b64u(json.dumps(claims).encode("utf-8"))
    signing_input = f"{header}.{payload}".encode("ascii")
    mac = hmac.new(hmac_secret, signing_input, hashlib.sha256).digest()
    return f"{header}.{payload}.{_b64u(mac)}"


def _known_sub_lookup(sub: str = "user-42") -> FakePrincipalLookup:
    lookup = FakePrincipalLookup()
    lookup.put(
        "oidc_sub",
        sub,
        PrincipalRecord(
            principal_id=PrincipalId(uuid4()),
            kind="oidc_sub",
            external_ref=sub,
            key_hash=None,
            revoked=False,
        ),
    )
    return lookup


class TestOidcJwksVerifier:
    def test_missing_bearer_is_401(self) -> None:
        verifier = OidcJwksVerifier(
            _JWKS_URL, _ISSUER, http=_mock_jwks_client({}), principals=FakePrincipalLookup()
        )
        with pytest.raises(AuthenticationFailed):
            verifier.authenticate(authorization=None, api_key=None)
        with pytest.raises(AuthenticationFailed):
            verifier.authenticate(authorization="NotBearer xyz", api_key=None)

    def test_valid_token_resolves_known_sub(self) -> None:
        pem, jwk = _generate_rsa_jwk("kid-1")
        token = _sign_token(pem, kid="kid-1")
        lookup = FakePrincipalLookup()
        record = PrincipalRecord(
            principal_id=PrincipalId(uuid4()),
            kind="oidc_sub",
            external_ref="user-42",
            key_hash=None,
            revoked=False,
        )
        lookup.put("oidc_sub", "user-42", record)

        verifier = OidcJwksVerifier(
            _JWKS_URL,
            _ISSUER,
            audience=_AUDIENCE,
            http=_mock_jwks_client({_JWKS_URL: {"keys": [jwk]}}),
            principals=lookup,
        )

        principal = verifier.authenticate(authorization=f"Bearer {token}", api_key=None)

        assert principal == Principal(
            principal_id=record.principal_id, kind="oidc_sub", external_ref="user-42"
        )

    def test_unknown_sub_is_401(self) -> None:
        pem, jwk = _generate_rsa_jwk("kid-1")
        token = _sign_token(pem, kid="kid-1", sub="nobody-registered")
        verifier = OidcJwksVerifier(
            _JWKS_URL,
            _ISSUER,
            audience=_AUDIENCE,
            http=_mock_jwks_client({_JWKS_URL: {"keys": [jwk]}}),
            principals=FakePrincipalLookup(),
        )
        with pytest.raises(AuthenticationFailed):
            verifier.authenticate(authorization=f"Bearer {token}", api_key=None)

    def test_wrong_issuer_is_401(self) -> None:
        pem, jwk = _generate_rsa_jwk("kid-1")
        token = _sign_token(pem, kid="kid-1", issuer="https://not-the-configured-issuer/")
        verifier = OidcJwksVerifier(
            _JWKS_URL,
            _ISSUER,
            audience=_AUDIENCE,
            http=_mock_jwks_client({_JWKS_URL: {"keys": [jwk]}}),
            principals=FakePrincipalLookup(),
        )
        with pytest.raises(AuthenticationFailed):
            verifier.authenticate(authorization=f"Bearer {token}", api_key=None)

    def test_wrong_audience_is_401(self) -> None:
        pem, jwk = _generate_rsa_jwk("kid-1")
        token = _sign_token(pem, kid="kid-1", audience="some-other-service")
        verifier = OidcJwksVerifier(
            _JWKS_URL,
            _ISSUER,
            audience=_AUDIENCE,
            http=_mock_jwks_client({_JWKS_URL: {"keys": [jwk]}}),
            principals=FakePrincipalLookup(),
        )
        with pytest.raises(AuthenticationFailed):
            verifier.authenticate(authorization=f"Bearer {token}", api_key=None)

    def test_expired_token_is_401(self) -> None:
        pem, jwk = _generate_rsa_jwk("kid-1")
        token = _sign_token(pem, kid="kid-1", expires_in=timedelta(minutes=-5))
        verifier = OidcJwksVerifier(
            _JWKS_URL,
            _ISSUER,
            audience=_AUDIENCE,
            http=_mock_jwks_client({_JWKS_URL: {"keys": [jwk]}}),
            principals=FakePrincipalLookup(),
        )
        with pytest.raises(AuthenticationFailed):
            verifier.authenticate(authorization=f"Bearer {token}", api_key=None)

    def test_signed_by_a_different_key_than_the_jwks_advertises_is_401(self) -> None:
        pem_signer, _ = _generate_rsa_jwk("kid-1")
        _, jwk_advertised = _generate_rsa_jwk("kid-1")  # different keypair, same kid
        token = _sign_token(pem_signer, kid="kid-1")
        verifier = OidcJwksVerifier(
            _JWKS_URL,
            _ISSUER,
            audience=_AUDIENCE,
            http=_mock_jwks_client({_JWKS_URL: {"keys": [jwk_advertised]}}),
            principals=FakePrincipalLookup(),
        )
        with pytest.raises(AuthenticationFailed):
            verifier.authenticate(authorization=f"Bearer {token}", api_key=None)

    def test_unknown_kid_is_401(self) -> None:
        pem, jwk = _generate_rsa_jwk("kid-1")
        token = _sign_token(pem, kid="kid-does-not-appear-in-jwks")
        verifier = OidcJwksVerifier(
            _JWKS_URL,
            _ISSUER,
            audience=_AUDIENCE,
            http=_mock_jwks_client({_JWKS_URL: {"keys": [jwk]}}),
            principals=FakePrincipalLookup(),
        )
        with pytest.raises(AuthenticationFailed):
            verifier.authenticate(authorization=f"Bearer {token}", api_key=None)

    def test_token_without_exp_is_rejected(self) -> None:
        """PyJWT only enforces an expiry that is PRESENT. Without `exp` in the
        required-claims set, a token minted without one is a bearer credential
        that never stops working — a single leaked token is permanent access."""
        pem, jwk = _generate_rsa_jwk("kid-1")
        token = _sign_token(pem, kid="kid-1", expires_in=None)
        verifier = OidcJwksVerifier(
            _JWKS_URL,
            _ISSUER,
            audience=_AUDIENCE,
            http=_mock_jwks_client({_JWKS_URL: {"keys": [jwk]}}),
            principals=_known_sub_lookup(),
        )
        with pytest.raises(AuthenticationFailed):
            verifier.authenticate(authorization=f"Bearer {token}", api_key=None)

    def test_algorithm_confusion_is_rejected(self) -> None:
        """`alg: none`, and an HS256 token keyed by the IdP's PUBLIC key (the
        classic RSA->HMAC confusion), must both fail: only RS256 is accepted."""
        pem, jwk = _generate_rsa_jwk("kid-1")
        public_pem = (
            serialization.load_pem_private_key(pem, password=None)
            .public_key()
            .public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        now = datetime.now(UTC)
        claims: dict[str, object] = {
            "sub": "user-42",
            "iss": _ISSUER,
            "aud": _AUDIENCE,
            "exp": int((now + timedelta(minutes=5)).timestamp()),
        }
        # PyJWT refuses to *encode* HS256 with a PEM key, so the attacker's
        # token is assembled by hand — which is what an attacker would do.
        hs256 = _forge_hs256(claims, hmac_secret=public_pem, kid="kid-1")
        unsigned = jwt.encode(claims, key="", algorithm="none", headers={"kid": "kid-1"})

        verifier = OidcJwksVerifier(
            _JWKS_URL,
            _ISSUER,
            audience=_AUDIENCE,
            http=_mock_jwks_client({_JWKS_URL: {"keys": [jwk]}}),
            principals=_known_sub_lookup(),
        )
        for forged in (hs256, unsigned):
            with pytest.raises(AuthenticationFailed):
                verifier.authenticate(authorization=f"Bearer {forged}", api_key=None)

    def test_unknown_kids_do_not_amplify_into_one_jwks_fetch_each(self) -> None:
        """The `kid` of an unverified token is attacker-controlled. One
        outbound JWKS GET per novel `kid` makes an anonymous caller a request
        amplifier aimed at the IdP, and pins a worker thread per request for
        the client timeout. The cooldown must hold the fetch count at 1 for a
        burst, and the FakeClock must be the only thing that reopens it.
        """
        pem, jwk = _generate_rsa_jwk("kid-1")
        fetches: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            fetches.append(str(request.url))
            return httpx.Response(200, json={"keys": [jwk]})

        clock = FakeClock(datetime(2026, 1, 1, tzinfo=UTC))
        verifier = OidcJwksVerifier(
            _JWKS_URL,
            _ISSUER,
            audience=_AUDIENCE,
            http=httpx.Client(transport=httpx.MockTransport(handler)),
            principals=_known_sub_lookup(),
            clock=clock,
        )

        for i in range(50):
            token = _sign_token(pem, kid=f"attacker-invented-{i}")
            with pytest.raises(AuthenticationFailed):
                verifier.authenticate(authorization=f"Bearer {token}", api_key=None)
        assert len(fetches) == 1

        # A genuine rotation is still picked up once the window elapses.
        clock.advance(seconds=30)
        with pytest.raises(AuthenticationFailed):
            verifier.authenticate(
                authorization=f"Bearer {_sign_token(pem, kid='rotated')}", api_key=None
            )
        assert len(fetches) == 2

    def test_failed_jwks_fetch_does_not_reopen_the_window(self) -> None:
        """A hanging or erroring IdP must not let an attacker retry the fetch
        on every request — the cooldown is stamped before the fetch, not after
        a successful one."""
        fetches: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            fetches.append(str(request.url))
            return httpx.Response(503)

        pem, _ = _generate_rsa_jwk("kid-1")
        verifier = OidcJwksVerifier(
            _JWKS_URL,
            _ISSUER,
            audience=_AUDIENCE,
            http=httpx.Client(transport=httpx.MockTransport(handler)),
            principals=_known_sub_lookup(),
            clock=FakeClock(datetime(2026, 1, 1, tzinfo=UTC)),
        )
        for i in range(10):
            with pytest.raises(AuthenticationFailed):
                verifier.authenticate(
                    authorization=f"Bearer {_sign_token(pem, kid=f'k{i}')}", api_key=None
                )
        assert len(fetches) == 1

    def test_kidless_token_verifies_against_every_advertised_key(self) -> None:
        """During a rotation the IdP advertises two keys. A `kid`-less token
        signed by either must verify; picking one arbitrary key out of the set
        would reject perfectly valid tokens depending on JWKS ordering."""
        _pem_old, jwk_old = _generate_rsa_jwk("kid-old")
        pem_new, jwk_new = _generate_rsa_jwk("kid-new")
        token = _sign_token(pem_new, kid=None)  # signed by the SECOND key

        verifier = OidcJwksVerifier(
            _JWKS_URL,
            _ISSUER,
            audience=_AUDIENCE,
            http=_mock_jwks_client({_JWKS_URL: {"keys": [jwk_old, jwk_new]}}),
            principals=_known_sub_lookup(),
            clock=FakeClock(datetime(2026, 1, 1, tzinfo=UTC)),
        )
        assert verifier.authenticate(
            authorization=f"Bearer {token}", api_key=None
        ).external_ref == "user-42"

    def test_kidless_token_signed_by_a_stranger_is_still_401(self) -> None:
        """Trying every advertised key must not become "accept anything": a
        key the IdP does not advertise stays rejected."""
        pem_stranger, _ = _generate_rsa_jwk("stranger")
        _pem, jwk = _generate_rsa_jwk("kid-1")
        token = _sign_token(pem_stranger, kid=None)
        verifier = OidcJwksVerifier(
            _JWKS_URL,
            _ISSUER,
            audience=_AUDIENCE,
            http=_mock_jwks_client({_JWKS_URL: {"keys": [jwk]}}),
            principals=_known_sub_lookup(),
            clock=FakeClock(datetime(2026, 1, 1, tzinfo=UTC)),
        )
        with pytest.raises(AuthenticationFailed):
            verifier.authenticate(authorization=f"Bearer {token}", api_key=None)


# --------------------------------------------------------------------------- #
# ChainVerifier.
# --------------------------------------------------------------------------- #


class TestChainVerifier:
    def test_no_credential_is_401(self) -> None:
        chain = ChainVerifier(oidc=None, api_key=None, api_key_mode=True)
        with pytest.raises(AuthenticationFailed):
            chain.authenticate(authorization=None, api_key=None)

    def test_bearer_routes_to_oidc_when_configured(self) -> None:
        pem, jwk = _generate_rsa_jwk("kid-1")
        token = _sign_token(pem, kid="kid-1")
        lookup = FakePrincipalLookup()
        record = PrincipalRecord(
            principal_id=PrincipalId(uuid4()),
            kind="oidc_sub",
            external_ref="user-42",
            key_hash=None,
            revoked=False,
        )
        lookup.put("oidc_sub", "user-42", record)
        oidc = OidcJwksVerifier(
            _JWKS_URL,
            _ISSUER,
            audience=_AUDIENCE,
            http=_mock_jwks_client({_JWKS_URL: {"keys": [jwk]}}),
            principals=lookup,
        )
        chain = ChainVerifier(oidc=oidc, api_key=None, api_key_mode=False)

        principal = chain.authenticate(authorization=f"Bearer {token}", api_key=None)
        assert principal.external_ref == "user-42"

    def test_api_key_routes_to_api_key_verifier_when_mode_enabled(self) -> None:
        lookup = FakePrincipalLookup()
        secret = "chain-verifier-secret"
        record = _api_key_record(key_hash=sha256_hex(secret.encode("utf-8")))
        lookup.put("api_key", record.external_ref, record)
        chain = ChainVerifier(
            oidc=None, api_key=ApiKeyVerifier(lookup), api_key_mode=True
        )

        principal = chain.authenticate(
            authorization=None, api_key=f"tb_sk_{record.external_ref}.{secret}"
        )
        assert principal.principal_id == record.principal_id

    def test_api_key_ignored_when_mode_disabled(self) -> None:
        lookup = FakePrincipalLookup()
        secret = "chain-verifier-secret"
        record = _api_key_record(key_hash=sha256_hex(secret.encode("utf-8")))
        lookup.put("api_key", record.external_ref, record)
        chain = ChainVerifier(
            oidc=None, api_key=ApiKeyVerifier(lookup), api_key_mode=False
        )

        with pytest.raises(AuthenticationFailed):
            chain.authenticate(authorization=None, api_key=f"tb_sk_{record.external_ref}.{secret}")

    @pytest.mark.parametrize("authorization", ["", "   ", "Basic dXNlcjpwdw==", "Bearer "])
    def test_a_non_bearer_authorization_header_does_not_shadow_a_valid_api_key(
        self, authorization: str
    ) -> None:
        """Dispatch is on the SCHEME, not on the header being present. A
        proxy-injected empty `Authorization:` (or any non-Bearer scheme) must
        not route an API-key caller into the OIDC verifier and 401 them."""
        pem, jwk = _generate_rsa_jwk("kid-1")
        del pem
        lookup = FakePrincipalLookup()
        secret = "chain-verifier-secret"
        record = _api_key_record(key_hash=sha256_hex(secret.encode("utf-8")))
        lookup.put("api_key", record.external_ref, record)
        chain = ChainVerifier(
            oidc=OidcJwksVerifier(
                _JWKS_URL,
                _ISSUER,
                audience=_AUDIENCE,
                http=_mock_jwks_client({_JWKS_URL: {"keys": [jwk]}}),
                principals=lookup,
                clock=FakeClock(datetime(2026, 1, 1, tzinfo=UTC)),
            ),
            api_key=ApiKeyVerifier(lookup),
            api_key_mode=True,
        )

        principal = chain.authenticate(
            authorization=authorization, api_key=f"tb_sk_{record.external_ref}.{secret}"
        )
        assert principal.principal_id == record.principal_id


# --------------------------------------------------------------------------- #
# require_admin_key (contract §9.1/§9.2 bootstrap admin auth, C-20).
# --------------------------------------------------------------------------- #


def _admin_app(admin_key_hash: str | None) -> FastAPI:
    """A minimal app exercising `require_admin_key` exactly as `api/main.py`
    wires it: same `app.state.admin_key_hash` contract, same §9.4
    `AuthenticationFailed` -> 401 mapping (registered separately here so this
    test does not depend on `api.main.create_app`, which needs a full
    `AppDeps`)."""
    app = FastAPI()
    app.state.admin_key_hash = admin_key_hash

    @app.exception_handler(AuthenticationFailed)
    async def _auth_failed(request: Request, exc: AuthenticationFailed) -> JSONResponse:
        del request, exc
        return JSONResponse(status_code=401, content={"detail": "authentication failed"})

    @app.get("/gated", dependencies=[Depends(require_admin_key)])
    def gated() -> dict[str, bool]:
        return {"ok": True}

    return app


class TestRequireAdminKey:
    def test_missing_header_is_401(self) -> None:
        app = _admin_app(admin_key_hash=hashlib.sha256(b"real-admin-key").hexdigest())
        client = TestClient(app)
        r = client.get("/gated")
        assert r.status_code == 401

    def test_wrong_key_is_401(self) -> None:
        app = _admin_app(admin_key_hash=hashlib.sha256(b"real-admin-key").hexdigest())
        client = TestClient(app)
        r = client.get("/gated", headers={"x-admin-key": "not-the-real-key"})
        assert r.status_code == 401

    def test_unconfigured_admin_key_always_rejects(self) -> None:
        app = _admin_app(admin_key_hash=None)
        client = TestClient(app)
        r = client.get("/gated", headers={"x-admin-key": "anything"})
        assert r.status_code == 401

    def test_correct_key_passes(self) -> None:
        app = _admin_app(admin_key_hash=hashlib.sha256(b"real-admin-key").hexdigest())
        client = TestClient(app)
        r = client.get("/gated", headers={"x-admin-key": "real-admin-key"})
        assert r.status_code == 200
        assert r.json() == {"ok": True}


# --------------------------------------------------------------------------- #
# `api.main._RepoPrincipalLookup` — the adapter that stands between
# `Repo.get_principal_by_external_ref(external_ref, *, kind=None)` (contract
# §5.1 + C-29) and `PrincipalLookup` (kind first, positionally). It decides
# which principal_id an authentication resolves to, and principal_id decides
# project_id: getting the kind wrong here IS invariant 4's failure mode.
# --------------------------------------------------------------------------- #


@dataclass
class _FakeRepo:
    """Mirrors `Repo.get_principal_by_external_ref`'s real signature exactly,
    including C-29's keyword-only `kind` — a fake with the old one-argument
    shape would let the adapter silently stop forwarding `kind` (and fall back
    to the ambiguous cross-kind query) with every test still green."""

    row: PrincipalRow | None
    seen_kind: str | None = None
    """What the adapter actually passed, so `test_kind_is_pushed_into_the_query`
    can prove the filter is the query's, not a post-hoc comparison."""

    def get_principal_by_external_ref(
        self, external_ref: str, *, kind: str | None = None
    ) -> PrincipalRow | None:
        del external_ref
        self.seen_kind = kind
        if self.row is not None and kind is not None and self.row.kind != kind:
            # A real Postgres UNIQUE(kind, external_ref) lookup returns nothing
            # for the wrong kind; the fake must not be more permissive than the
            # index it stands in for.
            return None
        return self.row


def _principal_row(*, kind: str, revoked_at: datetime | None = None) -> PrincipalRow:
    return PrincipalRow(
        principal_id=PrincipalId(uuid4()),
        kind=kind,
        external_ref="ambiguous-ref",
        key_hash=sha256_hex(b"secret"),
        revoked_at=revoked_at,
    )


class TestRepoPrincipalLookup:
    def test_matching_kind_is_returned(self) -> None:
        row = _principal_row(kind="api_key")
        lookup = _RepoPrincipalLookup(cast(Any, _FakeRepo(row)))

        record = lookup.get_principal_by_external_ref("api_key", "ambiguous-ref")

        assert record is not None
        assert record.principal_id == row.principal_id
        assert record.key_hash == row.key_hash
        assert record.revoked is False

    def test_wrong_kind_is_not_returned(self) -> None:
        """An IdP controls its `sub` values; an api_key `external_ref` is a
        server-minted key_id. A `sub` that collides with a key_id must NOT
        authenticate an OIDC caller as that api_key principal (and vice
        versa) — that is authenticating as one identity and being scoped into
        another's project."""
        oidc_row = _principal_row(kind="oidc_sub")
        lookup = _RepoPrincipalLookup(cast(Any, _FakeRepo(oidc_row)))

        assert lookup.get_principal_by_external_ref("api_key", "ambiguous-ref") is None

    def test_revoked_row_is_reported_as_revoked(self) -> None:
        row = _principal_row(kind="api_key", revoked_at=datetime(2026, 1, 1, tzinfo=UTC))
        lookup = _RepoPrincipalLookup(cast(Any, _FakeRepo(row)))

        record = lookup.get_principal_by_external_ref("api_key", "ambiguous-ref")

        assert record is not None
        assert record.revoked is True
        # ...and a revoked record is refused by the verifier that consumes it.
        verifier = ApiKeyVerifier(lookup)
        with pytest.raises(AuthenticationFailed):
            verifier.authenticate(authorization=None, api_key="tb_sk_ambiguous-ref.secret")

    def test_ambiguous_lookup_miss_is_a_miss(self) -> None:
        """`Repo` fails closed (returns None) when one `external_ref` matches
        two kinds; the adapter must not invent a principal from that."""
        lookup = _RepoPrincipalLookup(cast(Any, _FakeRepo(None)))
        assert lookup.get_principal_by_external_ref("api_key", "ambiguous-ref") is None

    def test_kind_is_pushed_into_the_query_not_filtered_afterwards(self) -> None:
        """C-29. Post-filtering was correct but not sufficient: with the bare
        one-argument query, an IdP `sub` colliding with a server-minted key_id
        made `Repo` return None for BOTH identities, so an IdP could disable a
        tenant's api_key auth by minting one `sub`. Forwarding `kind` makes the
        collision unrepresentable in the query."""
        repo = _FakeRepo(_principal_row(kind="api_key"))
        lookup = _RepoPrincipalLookup(cast(Any, repo))

        lookup.get_principal_by_external_ref("oidc_sub", "ambiguous-ref")

        assert repo.seen_kind == "oidc_sub"
