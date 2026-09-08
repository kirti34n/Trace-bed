"""The capability contract must be valid and its generated view must not drift."""

from __future__ import annotations

import importlib.util
import re
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import pytest

pytestmark = pytest.mark.phase0
REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "capability_check.py"


def _load_checker() -> ModuleType:
    spec = importlib.util.spec_from_file_location("capability_check", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_generated_capabilities_are_current() -> None:
    result = subprocess.run(  # noqa: S603 -- invokes this repository's fixed local checker
        [sys.executable, str(SCRIPT), "--check"],
        cwd=REPO_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "docs/CAPABILITIES.md is current"


def test_contract_has_an_explicit_non_ready_release_state() -> None:
    checker = _load_checker()
    contract = checker.load_contract()
    states = {item["state"] for item in contract["capabilities"]}
    assert "not_ready" in states
    assert any(
        item["id"] == "production-readiness" and item["state"] == "not_ready"
        for item in contract["capabilities"]
    )


def test_contract_cannot_omit_a_required_blocker(tmp_path: Path) -> None:
    checker = _load_checker()
    source = (REPO_ROOT / "docs" / "capabilities.toml").read_text(encoding="utf-8")
    omitted_id = "rbac-and-authorization"
    marker = f'[[capability]]\nid = "{omitted_id}"'
    before, removed_and_after = source.split(marker, maxsplit=1)
    _, after = removed_and_after.split("[[capability]]", maxsplit=1)
    contract_path = tmp_path / "capabilities.toml"
    contract_path.write_text(before + "[[capability]]" + after, encoding="utf-8")

    with pytest.raises(ValueError, match="missing required capability IDs"):
        checker.load_contract(contract_path)


def test_generated_view_has_the_exact_required_capability_ids() -> None:
    checker = _load_checker()
    generated = (REPO_ROOT / "docs" / "CAPABILITIES.md").read_text(encoding="utf-8")
    rendered_ids = re.findall(r"^### `([^`]+)`", generated, flags=re.MULTILINE)

    assert len(rendered_ids) == len(set(rendered_ids))
    assert frozenset(rendered_ids) == checker.REQUIRED_CAPABILITY_IDS
