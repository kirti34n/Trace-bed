"""Compatibility import for the packaged Compose-v1 HBA attestation."""

from tracebed.stores.pg.hba import (
    COMPOSE_HBA_FILE,
    COMPOSE_V1_PROFILE,
    COMPOSE_V1_RULES,
    HBA_PROFILE_ENV,
    LEGACY_INGRESS_ENV,
    HbaRule,
    attest_compose_v1_hba,
    checked_hba_text,
    require_compose_v1_profile,
)

__all__ = [
    "COMPOSE_HBA_FILE",
    "COMPOSE_V1_PROFILE",
    "COMPOSE_V1_RULES",
    "HBA_PROFILE_ENV",
    "LEGACY_INGRESS_ENV",
    "HbaRule",
    "attest_compose_v1_hba",
    "checked_hba_text",
    "require_compose_v1_profile",
]
