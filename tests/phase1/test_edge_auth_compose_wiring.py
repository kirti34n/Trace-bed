"""Executable preflight for the deliberately externally-run OIDC acceptance path.

The stack cannot safely embed an IdP user, signing key, callback hostname, or
principal grant in its normal Compose file.  A deployment acceptance therefore
supplies all seven OIDC values, starts the unchanged topology, completes the
browser Code+PKCE login, and proves `/admin/whoami` through the dashboard
origin.  This test prevents a future Compose change from silently severing
either the BFF or API half of that independently configured path.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from tracebed.edge.config import EdgeSettings


def test_compose_keeps_the_complete_external_oidc_to_edge_to_api_wiring() -> None:
    root = Path(__file__).parents[2]
    compose = yaml.safe_load((root / "docker" / "compose.yaml").read_text(encoding="utf-8"))
    services = compose["services"]
    api_environment = services["api"]["environment"]
    edge_environment = services["edge"]["environment"]

    assert api_environment["TB_AUTH__OIDC_ISSUER"] == "${TB_AUTH__OIDC_ISSUER:-}"
    assert api_environment["TB_AUTH__OIDC_JWKS_URL"] == "${TB_AUTH__OIDC_JWKS_URL:-}"
    assert api_environment["TB_AUTH__OIDC_AUDIENCE"] == "${TB_AUTH__OIDC_AUDIENCE:-}"
    assert edge_environment == {
        "TB_EDGE_OIDC_ISSUER": "${TB_AUTH__OIDC_ISSUER:-}",
        "TB_EDGE_OIDC_JWKS_URL": "${TB_AUTH__OIDC_JWKS_URL:-}",
        "TB_EDGE_OIDC_CLIENT_ID": "${TB_EDGE_OIDC_CLIENT_ID:-}",
        "TB_EDGE_OIDC_API_AUDIENCE": "${TB_AUTH__OIDC_AUDIENCE:-}",
        "TB_EDGE_REDIRECT_URI": "${TB_EDGE_REDIRECT_URI:-}",
        "TB_EDGE_ALLOWED_ORIGIN": "${TB_EDGE_ALLOWED_ORIGIN:-}",
        "TB_EDGE_TRUSTED_INGRESS_HOST": "10.77.15.3",
        "TB_EDGE_SECURE_COOKIE": "${TB_EDGE_SECURE_COOKIE:-true}",
    }

    # The BFF's API destination is deliberately code-validated, not a
    # deployment override that an IdP acceptance environment could redirect.
    assert EdgeSettings().api_base_url == "http://api:8110"
    assert set(services["edge"]["networks"]) == {"ingress"}
    assert "edge" in services["dashboard"]["depends_on"]


def test_local_demo_is_an_explicit_overlay_with_its_own_single_secret() -> None:
    root = Path(__file__).parents[2]
    base = yaml.safe_load((root / "docker" / "compose.yaml").read_text(encoding="utf-8"))
    overlay = yaml.safe_load((root / "docker" / "compose.demo.yaml").read_text(encoding="utf-8"))

    # The normal production file neither loads a demo entrypoint nor knows the
    # demo API-key secret. Operators must consciously select this overlay.
    assert base["services"]["edge"].get("secrets") is None
    assert "demo_api_key_secret" not in base.get("secrets", {})
    assert overlay["services"]["edge"] == {
        "entrypoint": ["tracebed-local-demo-edge"],
        "environment": {
            "TB_LOCAL_DEMO_ORIGIN": "${TB_LOCAL_DEMO_ORIGIN:?TB_LOCAL_DEMO_ORIGIN must be exact http://127.0.0.1:<port>}"
        },
        "secrets": ["demo_api_key_secret"],
    }
    assert overlay["secrets"] == {
        "demo_api_key_secret": {
            "file": "${TB_DEMO_API_KEY_SECRET_FILE:?TB_DEMO_API_KEY_SECRET_FILE must name the dedicated local demo secret}"
        }
    }
