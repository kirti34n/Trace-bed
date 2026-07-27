"""PHASE0-CONTRACT.md §3.7/C-06 and PHASE-0 Task 3 — `ScanVerdict`'s own defences.

Task 3's gate assertion is literally "`ScanVerdict` cannot be constructed from
test code". That is one half of forgery resistance; the other half is the HMAC,
which lives with the minting authority in `core/scans` and is proved by
`tests/phase0/test_scans.py` (chunk `scans`, §13.2). This file proves the half
that lives in `domain.scan`: the caller-module guard and the token's shape.

The guard is defence in depth, not a security boundary — anything that can
`exec` with a chosen `__name__` can satisfy it, as
`test_guard_is_satisfiable_by_a_fabricated_module_name` records deliberately.
Its job is to make an accidental or careless `ScanVerdict(...)` in `stores/pg`,
`api`, or a test impossible, so that "every insert is scanned" cannot quietly
become "every insert claims to be scanned".
"""

from __future__ import annotations

import sys
import types
from typing import Any
from uuid import uuid4

import pytest

from tracebed.domain.errors import ScanVerdictForgery, TracebedError
from tracebed.domain.scan import CONTENT_HASH_HEX_LEN, SIG_LEN, ScanVerdict

pytestmark = pytest.mark.phase0

_VALID_HASH = "a" * CONTENT_HASH_HEX_LEN
_VALID_SIG = b"\x00" * SIG_LEN


def _verdict_kwargs(**overrides: object) -> dict[str, Any]:
    base: dict[str, Any] = {
        "verdict_id": uuid4(),
        "content_hash": _VALID_HASH,
        "suite_version": "scans/1.0.0",
        "issued_at_ms": 1_753_000_000_000,
        "sig": _VALID_SIG,
    }
    base.update(overrides)
    return base


def _build_in_module(mod_name: str, **overrides: object) -> ScanVerdict:
    """Construct a ScanVerdict from inside a module named `mod_name`.

    The guard reads the instantiating frame's `__name__`, so exercising it
    requires a real frame whose globals carry the name under test. Used for
    both the positive control and the near-miss rejections below.
    """
    mod = types.ModuleType(mod_name)
    sys.modules[mod_name] = mod
    try:
        code = (
            "from tracebed.domain.scan import ScanVerdict\n"
            "def build(kwargs):\n"
            "    return ScanVerdict(**kwargs)\n"
        )
        exec(compile(code, mod_name, "exec"), mod.__dict__)  # noqa: S102
        built: ScanVerdict = mod.build(_verdict_kwargs(**overrides))
        return built
    finally:
        del sys.modules[mod_name]


# --------------------------------------------------------------------------- #
# The caller-module guard
# --------------------------------------------------------------------------- #


def test_scanverdict_cannot_be_constructed_from_test_code() -> None:
    # This module's __name__ is under `tests.phase0` — the exact case named by
    # PHASE-0 Task 3's gate assertion.
    with pytest.raises(ScanVerdictForgery):
        ScanVerdict(**_verdict_kwargs())


def test_scanverdict_forgery_message_names_the_offending_module() -> None:
    with pytest.raises(ScanVerdictForgery, match=__name__):
        ScanVerdict(**_verdict_kwargs())


def test_scan_verdict_forgery_is_a_tracebed_error() -> None:
    # §3.1: every deliberate raise derives from TracebedError, which is what
    # the API error mapping (§9.4) keys off.
    assert issubclass(ScanVerdictForgery, TracebedError)


@pytest.mark.parametrize(
    "mod_name",
    [
        # THE case that matters: the repository is the module that consumes a
        # verdict, so it is the module most likely to be "fixed" by minting one.
        "tracebed.stores.pg.repo",
        "tracebed.api.routes_v1",
        "tracebed.ingest.trace_writer",
        "tracebed.workers.distiller",
        # Near misses on the allowed prefix.
        "tracebed.core",  # the parent package is not the scan suite
        "tracebed.core.scan",  # singular
        "tracebed.core.scans_evil",  # shares a character prefix, different package
        "tracebed.core.scansomething",  # a bare str.startswith would accept this
        "evil.tracebed.core.scans",  # allowed name as a suffix, not a prefix
        "tracebed_core_scans",
        "",  # a frame with no module name at all
    ],
)
def test_scanverdict_rejects_construction_from_every_other_module(mod_name: str) -> None:
    with pytest.raises(ScanVerdictForgery):
        _build_in_module(mod_name)


def test_scanverdict_is_constructible_from_the_scan_suite_package() -> None:
    # Positive control: without this, a guard that rejected everything
    # unconditionally would pass every test above.
    verdict = _build_in_module("tracebed.core.scans")
    assert verdict.suite_version == "scans/1.0.0"


def test_scanverdict_is_constructible_from_a_scan_suite_submodule() -> None:
    verdict = _build_in_module("tracebed.core.scans.patterns")
    assert verdict.content_hash == _VALID_HASH


def test_guard_is_satisfiable_by_a_fabricated_module_name() -> None:
    # Recorded, not lamented: the guard is a mistake-catcher, not a security
    # boundary. Anything with code execution can name itself whatever it likes,
    # which is exactly why the contract puts the real defence in the HMAC
    # (§3.7 step 3) and has `Repo.insert_memory_item` call `verify_verdict`.
    # This test exists so nobody upgrades the guard's status by accident.
    verdict = _build_in_module("tracebed.core.scans._not_a_real_module")
    assert isinstance(verdict, ScanVerdict)


def test_indirection_through_a_helper_does_not_launder_the_caller() -> None:
    # The guard walks out of `domain.scan`'s own frames only. A disallowed
    # module calling through its own helper must still be caught — otherwise
    # one level of indirection would be a bypass.
    mod_name = "tracebed.stores.pg.launderer"
    mod = types.ModuleType(mod_name)
    sys.modules[mod_name] = mod
    try:
        code = (
            "from tracebed.domain.scan import ScanVerdict\n"
            "def _inner(kwargs):\n"
            "    return ScanVerdict(**kwargs)\n"
            "def build(kwargs):\n"
            "    return _inner(kwargs)\n"
        )
        exec(compile(code, mod_name, "exec"), mod.__dict__)  # noqa: S102
        with pytest.raises(ScanVerdictForgery):
            mod.build(_verdict_kwargs())
    finally:
        del sys.modules[mod_name]


def test_dataclasses_replace_cannot_retarget_a_legitimate_verdict() -> None:
    # The highest-value forgery: take a verdict minted for benign content and
    # point it at poisoned content. `dataclasses.replace` re-runs __init__, so
    # the guard sees `dataclasses` as the caller and refuses.
    import dataclasses

    verdict = _build_in_module("tracebed.core.scans")
    with pytest.raises(ScanVerdictForgery):
        dataclasses.replace(verdict, content_hash="b" * CONTENT_HASH_HEX_LEN)


# --------------------------------------------------------------------------- #
# Token shape and immutability
# --------------------------------------------------------------------------- #


def test_scanverdict_is_frozen() -> None:
    verdict = _build_in_module("tracebed.core.scans")
    with pytest.raises(AttributeError):
        verdict.content_hash = "b" * CONTENT_HASH_HEX_LEN  # type: ignore[misc]


def test_scanverdict_has_no_instance_dict() -> None:
    # slots=True: an attacker who gets hold of a verdict cannot bolt extra
    # attributes onto it for a downstream consumer to read.
    verdict = _build_in_module("tracebed.core.scans")
    assert not hasattr(verdict, "__dict__")


@pytest.mark.parametrize(
    "bad_hash",
    [
        "a" * (CONTENT_HASH_HEX_LEN - 1),
        "a" * (CONTENT_HASH_HEX_LEN + 1),
        "A" * CONTENT_HASH_HEX_LEN,  # uppercase never matches content_hash()'s output
        "g" * CONTENT_HASH_HEX_LEN,  # not hex
        "",
        "always retry with backoff",  # raw content where a digest belongs
    ],
)
def test_scanverdict_rejects_a_content_hash_that_is_not_a_sha256_hex_digest(bad_hash: str) -> None:
    # `Repo.insert_memory_item` compares this field for string equality against
    # `content_hash(item.content)`. A non-canonical form here would surface as
    # an unexplained forgery error in the write path instead of at the mistake.
    with pytest.raises(ScanVerdictForgery, match="content_hash"):
        _build_in_module("tracebed.core.scans", content_hash=bad_hash)


@pytest.mark.parametrize("bad_sig", [b"", b"x", b"\x00" * (SIG_LEN - 1), b"\x00" * (SIG_LEN + 1)])
def test_scanverdict_rejects_a_signature_that_is_not_hmac_sha256_sized(bad_sig: bytes) -> None:
    # A degenerate `sig` must not be constructible at all: an empty signature
    # is the one input to `hmac.compare_digest` nobody wants to reason about.
    with pytest.raises(ScanVerdictForgery, match="sig"):
        _build_in_module("tracebed.core.scans", sig=bad_sig)


def test_scanverdict_rejects_an_empty_suite_version() -> None:
    # suite_version is signed and stored; an empty one makes a stored verdict
    # unattributable to a rule set.
    with pytest.raises(ScanVerdictForgery, match="suite_version"):
        _build_in_module("tracebed.core.scans", suite_version="")


def test_scanverdict_rejects_a_negative_issued_at() -> None:
    with pytest.raises(ScanVerdictForgery, match="issued_at_ms"):
        _build_in_module("tracebed.core.scans", issued_at_ms=-1)


def test_valid_verdict_survives_every_shape_check() -> None:
    # Positive control for the shape checks as a group.
    verdict = _build_in_module("tracebed.core.scans")
    assert len(verdict.content_hash) == CONTENT_HASH_HEX_LEN
    assert len(verdict.sig) == SIG_LEN
    assert verdict.issued_at_ms >= 0
