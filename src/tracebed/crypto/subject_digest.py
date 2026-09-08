"""Opaque, project-scoped subject identifiers for erasure envelopes.

The archived ``tb-env/2`` format must not retain a caller's subject tag.  A
digest is deliberately scoped to its project, length framed, and byte exact:
normalising Unicode here would make two distinct retained key identities
indistinguishable.  This module is pure and does not perform any key-store or
database access.
"""

from __future__ import annotations

from hashlib import sha256
from typing import Final

from tracebed.domain.ids import ProjectId
from tracebed.domain.subject_tags import PROJECT_SUBJECT_TAG, validate_subject_tag

__all__ = [
    "PROJECT_SUBJECT_TAG",
    "SUBJECT_DIGEST_DOMAIN",
    "subject_digest",
    "subject_digest_pairs",
    "validate_subject_tag",
]


SUBJECT_DIGEST_DOMAIN: Final = b"tracebed.subject-digest/v1\0"
def subject_digest(project_id: ProjectId, subject_tag: str) -> bytes:
    """Return the fixed 32-byte opaque identifier for ``subject_tag``.

    Tags are encoded as strict UTF-8 with no case-folding, trimming, or
    Unicode normalisation.  Error messages intentionally contain no caller
    value: these values can be personal data and this primitive is commonly
    used on an archive/error boundary.
    """

    if not isinstance(subject_tag, str):
        raise TypeError("subject tag must be a string")
    try:
        encoded = subject_tag.encode("utf-8", "strict")
    except UnicodeEncodeError:
        raise ValueError("subject tag is invalid") from None
    return sha256(
        SUBJECT_DIGEST_DOMAIN
        + project_id.value.bytes
        + len(encoded).to_bytes(4, byteorder="big", signed=False)
        + encoded
    ).digest()


def subject_digest_pairs(
    project_id: ProjectId, subject_tags: tuple[str, ...]
) -> tuple[tuple[bytes, str], ...]:
    """Validate an ingress tag set and return it sorted by opaque digest.

    This is the writer-side bridge from caller tags to v2 envelope ordering.
    No raw tag appears in an error; a digest collision is refused even though
    it is computationally implausible, rather than collapsing authority.
    """

    if len(subject_tags) > 64:
        raise ValueError("too many subject tags")
    if len(set(subject_tags)) != len(subject_tags):
        raise ValueError("duplicate subject tag")
    pairs = tuple(
        (subject_digest(project_id, validate_subject_tag(tag)), tag) for tag in subject_tags
    )
    digests = tuple(digest for digest, _tag in pairs)
    if len(set(digests)) != len(digests):
        raise ValueError("subject digest collision")
    return tuple(sorted(pairs))
