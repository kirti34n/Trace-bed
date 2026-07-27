"""Credential/secret rule set (PHASE-0 Task 9, PHASE0-CONTRACT.md §4).

Regex rules for identifiable credential shapes (AWS, GCP, private key
blocks, bearer tokens, JWTs, connection strings with embedded passwords,
generic `key = value` assignments), plus a high-entropy-string heuristic for
opaque secrets that have no fixed shape. Like `patterns.py`, this module has
no import from `tracebed.domain` — content-in, hits-out.

The entropy heuristic is base64/hex-aware specifically so it does NOT flag
ordinary hex digests (content_hash, scan_verdict_id-adjacent hashes, etc.)
that legitimately appear in provenance fields: a sha256/sha1/md5-shaped pure
hex token at a common digest length is skipped outright (`_COMMON_HASH_HEX_LENGTHS`),
and any other pure-hex token needs entropy close to hex's own ceiling
(log2(16) = 4.0 bits/char) before it is even considered — a deterministic
hash digest and a random hex secret are statistically identical, so length is
the only lever that distinguishes "this is probably a provenance hash" from
"this is probably a secret."
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass
from enum import StrEnum
from typing import Final

from tracebed.core.scans.patterns import RuleSeverity

__all__ = [
    "SECRETS_SUITE_VERSION",
    "SecretHit",
    "scan_secrets",
    "shannon_entropy",
]

SECRETS_SUITE_VERSION: Final[str] = "scans-secrets/1.0.0"


class _TokenAlphabet(StrEnum):
    HEX = "hex"
    GENERIC = "generic"


@dataclass(frozen=True, slots=True)
class SecretHit:
    rule_id: str
    severity: RuleSeverity
    rationale: str
    reason: str


@dataclass(frozen=True, slots=True)
class _Rule:
    id: str
    severity: RuleSeverity
    rationale: str
    pattern: re.Pattern[str]


def _rule(id_: str, severity: RuleSeverity, rationale: str, pattern: str, *, flags: int = re.IGNORECASE) -> _Rule:
    return _Rule(id=id_, severity=severity, rationale=rationale, pattern=re.compile(pattern, flags))


_RULES: Final[tuple[_Rule, ...]] = (
    _rule(
        "aws-access-key-id",
        RuleSeverity.STRONG,
        "AWS access key id shape (AKIA + 16 uppercase-alnum)",
        r"\bAKIA[0-9A-Z]{16}\b",
        flags=0,
    ),
    _rule(
        "aws-secret-access-key-context",
        RuleSeverity.STRONG,
        "AWS secret access key assigned by name, 40-char base64-ish value",
        r"aws_secret_access_key\s*[:=]\s*['\"]?[A-Za-z0-9/+]{40}['\"]?",
    ),
    _rule(
        "gcp-api-key",
        RuleSeverity.STRONG,
        "GCP API key shape (AIza + 35 chars)",
        r"\bAIza[0-9A-Za-z\-_]{35}\b",
        flags=0,
    ),
    _rule(
        "private-key-block",
        RuleSeverity.STRONG,
        "PEM private key block header — full asymmetric key material",
        r"-----BEGIN\s+(?:RSA|EC|OPENSSH|DSA|ENCRYPTED|PGP)?\s*PRIVATE KEY-----",
    ),
    _rule(
        "jwt-shape",
        RuleSeverity.STRONG,
        "three dot-separated base64url segments starting with a JWT header shape (eyJ...)",
        r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b",
        flags=0,
    ),
    _rule(
        "bearer-token",
        RuleSeverity.STRONG,
        "Authorization: Bearer header carrying an opaque long token",
        r"\bbearer\s+[A-Za-z0-9\-_.]{20,}\b",
    ),
    _rule(
        "slack-token",
        RuleSeverity.STRONG,
        "Slack API token shape (xox[baprs]-...)",
        r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b",
        flags=0,
    ),
    _rule(
        "github-token",
        RuleSeverity.STRONG,
        "GitHub personal/OAuth/app token shape (gh[pousr]_...)",
        r"\bgh[pousr]_[A-Za-z0-9]{36}\b",
        flags=0,
    ),
    _rule(
        "db-connection-string-with-password",
        RuleSeverity.STRONG,
        "database/queue connection URI with an embedded plaintext password",
        r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^:\s/@]+:[^@\s]+@[^\s'\"]+",
    ),
    _rule(
        "generic-credential-assignment",
        RuleSeverity.WEAK,
        "key/token/password assigned a long opaque value — context-based, more false-positive prone",
        r"\b(api[_-]?key|secret[_-]?key|access[_-]?token|client[_-]?secret|passwd|password)\b\s*[:=]\s*"
        r"['\"]?[A-Za-z0-9/+_\-]{12,}['\"]?",
    ),
)

# -- high-entropy heuristic --------------------------------------------------

_TOKEN_RE: Final[re.Pattern[str]] = re.compile(r"[A-Za-z0-9+/_=\-]{20,}")
_HEX_RE: Final[re.Pattern[str]] = re.compile(r"^[0-9a-fA-F]+$")

# md5=32, sha1=40, sha224=56, sha256=64, sha384=96, sha512=128 hex chars —
# the digest lengths that legitimately show up in provenance/content_hash
# fields and must never be treated as a leaked secret by entropy alone.
_COMMON_HASH_HEX_LENGTHS: Final[frozenset[int]] = frozenset({32, 40, 56, 64, 96, 128})

_MIN_ENTROPY_TOKEN_LEN: Final[int] = 20
# hex alphabet ceiling is log2(16) = 4.0 bits/char; only near-ceiling,
# non-hash-length hex is treated as suspicious.
_HEX_ENTROPY_THRESHOLD: Final[float] = 3.8
# generic (base64-ish) alphabet ceiling is log2(64) = 6.0 bits/char; ordinary
# identifiers/words sit well below ~4.3, random secrets sit at/above it.
_GENERIC_ENTROPY_THRESHOLD: Final[float] = 4.3


def shannon_entropy(s: str) -> float:
    """Bits of entropy per character. Empty string is defined as 0.0."""
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((n / length) * math.log2(n / length) for n in counts.values())


def _classify_alphabet(token: str) -> _TokenAlphabet:
    return _TokenAlphabet.HEX if _HEX_RE.match(token) is not None else _TokenAlphabet.GENERIC


def find_high_entropy_tokens(text: str) -> tuple[SecretHit, ...]:
    """Scans whitespace-delimited long tokens for high-entropy opaque
    secrets, skipping ordinary hex digests at common hash lengths."""
    hits: list[SecretHit] = []
    seen: set[str] = set()
    for match in _TOKEN_RE.finditer(text):
        token = match.group(0)
        if token in seen or len(token) < _MIN_ENTROPY_TOKEN_LEN:
            continue
        seen.add(token)
        alphabet = _classify_alphabet(token)
        entropy = shannon_entropy(token)
        if alphabet is _TokenAlphabet.HEX:
            if len(token) in _COMMON_HASH_HEX_LENGTHS:
                continue  # ordinary provenance-field digest — never a secret signal
            if entropy < _HEX_ENTROPY_THRESHOLD:
                continue
        elif entropy < _GENERIC_ENTROPY_THRESHOLD:
            continue
        hits.append(
            SecretHit(
                rule_id="high-entropy-token",
                severity=RuleSeverity.WEAK,
                rationale=(
                    f"opaque {alphabet.value} token (len={len(token)}, entropy={entropy:.2f} bits/char) "
                    "consistent with an unlabelled secret"
                ),
                reason="secret:high-entropy-token",
            )
        )
    return tuple(hits)


def scan_secrets(text: str) -> tuple[SecretHit, ...]:
    """Runs every named-shape rule, then the high-entropy fallback."""
    hits: list[SecretHit] = []
    for rule in _RULES:
        if rule.pattern.search(text) is not None:
            hits.append(
                SecretHit(
                    rule_id=rule.id,
                    severity=rule.severity,
                    rationale=rule.rationale,
                    reason=f"secret:{rule.id}",
                )
            )
    hits.extend(find_high_entropy_tokens(text))
    return tuple(hits)
