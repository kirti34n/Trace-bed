"""Strict deployment settings for the browser-only OIDC BFF."""

from __future__ import annotations

from ipaddress import ip_address
from urllib.parse import SplitResult, urlsplit

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class EdgeSettings(BaseSettings):
    """The edge is disabled until its complete OIDC group is configured."""

    model_config = SettingsConfigDict(env_prefix="TB_EDGE_", extra="forbid", frozen=True)

    oidc_issuer: str | None = None
    # Must agree with API auth's configured JWKS URL; discovery is still used
    # for the authorization/token endpoints and checked against this pin.
    oidc_jwks_url: str | None = None
    oidc_client_id: str | None = None
    # This is deliberately separate from the dashboard client id.  An ID
    # token minted for the browser client must never become an API credential.
    oidc_api_audience: str | None = None
    redirect_uri: str | None = None
    allowed_origin: str | None = None
    api_base_url: str = "http://api:8110"
    # The dashboard/nginx container's fixed private address.  Only this direct
    # peer may supply the browser-address header used for login admission.
    trusted_ingress_host: str | None = None
    session_idle_seconds: int = Field(default=1_800, ge=60, le=86_400)
    session_absolute_seconds: int = Field(default=28_800, ge=300, le=86_400)
    secure_cookie: bool = True

    @field_validator(
        "oidc_issuer", "oidc_jwks_url", "oidc_client_id", "oidc_api_audience", "redirect_uri", "allowed_origin", mode="before"
    )
    @classmethod
    def _empty_optional_oidc_value_is_unset(cls, value: object) -> object:
        """Compose can pass an absent optional deployment value as an empty string."""

        return None if value == "" else value

    @property
    def enabled(self) -> bool:
        return self.oidc_issuer is not None

    @model_validator(mode="after")
    def _validate_boundary(self) -> EdgeSettings:
        values = (
            self.oidc_issuer,
            self.oidc_jwks_url,
            self.oidc_client_id,
            self.oidc_api_audience,
            self.redirect_uri,
            self.allowed_origin,
        )
        if any(value is not None for value in values) and not all(values):
            raise ValueError("edge OIDC issuer, JWKS URL, client id, API audience, redirect URI, and origin are all required")
        _require_private_api_url(self.api_base_url)
        if not self.enabled:
            return self
        if self.trusted_ingress_host is None:
            raise ValueError("enabled edge requires a trusted private ingress host")
        try:
            ingress = ip_address(self.trusted_ingress_host)
        except ValueError as exc:
            raise ValueError("edge trusted ingress host is invalid") from exc
        if not ingress.is_private:
            raise ValueError("edge trusted ingress host must be private")
        issuer = _require_https_url(self.oidc_issuer)
        _require_https_url(self.oidc_jwks_url)
        redirect = _require_https_or_local_url(self.redirect_uri, self.secure_cookie)
        origin = _require_https_or_local_url(self.allowed_origin, self.secure_cookie)
        if redirect.scheme != origin.scheme or redirect.netloc != origin.netloc or redirect.path != "/auth/callback":
            raise ValueError("edge redirect URI must be the configured origin's /auth/callback")
        if not self.oidc_client_id or len(self.oidc_client_id) > 255:
            raise ValueError("edge OIDC client id is invalid")
        if not self.oidc_api_audience or len(self.oidc_api_audience) > 255:
            raise ValueError("edge OIDC API audience is invalid")
        # The issuer is not used as an open redirect base: discovery endpoints
        # must remain at this exact HTTPS origin (checked again at fetch time).
        if not issuer.netloc:
            raise ValueError("edge OIDC issuer is invalid")
        return self


def _require_https_url(value: str | None) -> SplitResult:
    if value is None:
        raise ValueError("edge URL is absent")
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("edge URL must be controlled HTTPS")
    return parsed


def _require_https_or_local_url(value: str | None, secure_cookie: bool) -> SplitResult:
    if value is None:
        raise ValueError("edge URL is absent")
    parsed = urlsplit(value)
    secure = (
        parsed.scheme == "https"
        and parsed.netloc
        and parsed.username is None
        and parsed.password is None
        and not parsed.query
        and not parsed.fragment
    )
    local = (
        not secure_cookie
        and parsed.scheme == "http"
        and parsed.hostname in {"localhost", "127.0.0.1", "::1"}
        and parsed.username is None
        and parsed.password is None
        and not parsed.query
        and not parsed.fragment
    )
    if not secure and not local:
        raise ValueError("edge insecure cookies are permitted only for exact local development origins")
    return parsed


def _require_private_api_url(value: str) -> None:
    parsed = urlsplit(value)
    if (
        parsed.scheme != "http"
        or parsed.hostname != "api"
        or parsed.port != 8110
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("edge API URL must name the private api service")
