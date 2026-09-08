"""Pure subject-tag identity validation shared by ingress and crypto.

This is domain policy rather than cryptographic work: callers need to reject
invalid raw identifiers before they reach either the retrieval hot path or the
archive writer.  Keeping it here prevents a hot-path wire model from importing
the write-path crypto package merely to validate a string.
"""

from __future__ import annotations

from typing import Final

__all__ = [
    "MAX_SUBJECT_TAG_SCALARS",
    "MAX_SUBJECT_TAG_UTF8_BYTES",
    "PROJECT_SUBJECT_TAG",
    "validate_subject_tag",
]


PROJECT_SUBJECT_TAG: Final = "__project__"
MAX_SUBJECT_TAG_SCALARS: Final = 128
MAX_SUBJECT_TAG_UTF8_BYTES: Final = 512


def validate_subject_tag(subject_tag: str, *, allow_reserved: bool = False) -> str:
    """Validate a new ingress tag without normalizing its byte identity."""

    if not isinstance(subject_tag, str):
        raise TypeError("subject tag must be a string")
    try:
        encoded = subject_tag.encode("utf-8", "strict")
    except UnicodeEncodeError:
        # Raw tags can be personal data; error text must not echo them.
        raise ValueError("subject tag is invalid") from None
    if (
        not 1 <= len(subject_tag) <= MAX_SUBJECT_TAG_SCALARS
        or not 1 <= len(encoded) <= MAX_SUBJECT_TAG_UTF8_BYTES
        or subject_tag.isspace()
        or any(
            0x00 <= ord(character) <= 0x1F or 0x7F <= ord(character) <= 0x9F
            for character in subject_tag
        )
    ):
        raise ValueError("subject tag is invalid")
    if not allow_reserved and subject_tag == PROJECT_SUBJECT_TAG:
        raise ValueError("subject tag is reserved")
    return subject_tag
