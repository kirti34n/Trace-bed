#!/usr/bin/env python3
"""Validate and render the source-controlled Tracebed capability contract.

The contract is intentionally a presence-and-state inventory.  It never turns
source files or passing local checks into a production-readiness assertion.
"""

from __future__ import annotations

import argparse
import sys
import tomllib
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
CONTRACT_PATH = ROOT / "docs" / "capabilities.toml"
OUTPUT_PATH = ROOT / "docs" / "CAPABILITIES.md"
SCHEMA_VERSION = 1
REQUIRED_CAPABILITY_KEYS = frozenset(
    {"id", "name", "state", "summary", "limits", "future_gates", "evidence_class", "evidence"}
)
# This inventory is deliberately exact rather than open-ended.  Adding a new
# capability requires an intentional checker update, and deleting a blocker
# from the source contract cannot silently make the generated view look safer.
REQUIRED_CAPABILITY_IDS = frozenset(
    {
        "audit-sink",
        "background-learning",
        "backup-restore-and-high-availability",
        "dependency-sbom-provenance-and-release",
        "edge-and-dashboard-authentication",
        "erasure-and-project-deletion",
        "execution-trace-intake",
        "export-authorization-and-completeness",
        "feedback-authenticity-and-poisoning",
        "host-integration",
        "project-scoped-memory",
        "provisioning-atomicity",
        "production-readiness",
        "rbac-and-authorization",
        "retention-policy",
        "runtime-and-worker-operation",
        "security-assurance",
    }
)


def _error(message: str) -> ValueError:
    return ValueError(f"capability contract: {message}")


def _require_string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise _error(f"{label} must be a non-empty string")
    return value.strip()


def _require_string_list(value: object, label: str) -> list[str]:
    if not isinstance(value, list) or not value:
        raise _error(f"{label} must be a non-empty list of strings")
    result: list[str] = []
    for index, item in enumerate(value):
        result.append(_require_string(item, f"{label}[{index}]"))
    return result


def _validate_evidence_path(value: str, capability_id: str) -> None:
    path = Path(value)
    if path.is_absolute() or ".." in path.parts:
        raise _error(f"{capability_id}.evidence contains a non-repository path: {value!r}")
    if not (ROOT / path).is_file():
        raise _error(f"{capability_id}.evidence references a missing file: {value!r}")


def load_contract(path: Path = CONTRACT_PATH) -> dict[str, Any]:
    """Load and validate the contract, returning normalized deterministic data."""
    try:
        with path.open("rb") as handle:
            raw = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise _error(f"cannot read {path.relative_to(ROOT)}: {exc}") from exc

    if raw.get("schema_version") != SCHEMA_VERSION:
        raise _error(f"schema_version must be {SCHEMA_VERSION}")
    title = _require_string(raw.get("title"), "title")

    states_raw = raw.get("states")
    if not isinstance(states_raw, dict) or not states_raw:
        raise _error("states must be a non-empty table")
    states = {
        _require_string(name, "state name"): _require_string(description, f"states.{name}")
        for name, description in states_raw.items()
    }

    evidence_classes_raw = raw.get("evidence_classes")
    if not isinstance(evidence_classes_raw, dict) or not evidence_classes_raw:
        raise _error("evidence_classes must be a non-empty table")
    evidence_classes = {
        _require_string(name, "evidence class name"): _require_string(
            description, f"evidence_classes.{name}"
        )
        for name, description in evidence_classes_raw.items()
    }

    capabilities_raw = raw.get("capability")
    if not isinstance(capabilities_raw, list) or not capabilities_raw:
        raise _error("at least one [[capability]] entry is required")

    capabilities: list[dict[str, Any]] = []
    ids: set[str] = set()
    for index, item in enumerate(capabilities_raw):
        if not isinstance(item, dict):
            raise _error(f"capability[{index}] must be a table")
        extra = set(item) - REQUIRED_CAPABILITY_KEYS
        missing_keys = REQUIRED_CAPABILITY_KEYS - set(item)
        if missing_keys or extra:
            details = []
            if missing_keys:
                details.append(f"missing {sorted(missing_keys)}")
            if extra:
                details.append(f"unknown {sorted(extra)}")
            raise _error(f"capability[{index}] has {'; '.join(details)}")

        capability_id = _require_string(item["id"], f"capability[{index}].id")
        if not capability_id.replace("-", "").isalnum() or capability_id != capability_id.lower():
            raise _error(f"capability id must be lowercase kebab-case: {capability_id!r}")
        if capability_id in ids:
            raise _error(f"duplicate capability id: {capability_id!r}")
        ids.add(capability_id)

        state = _require_string(item["state"], f"{capability_id}.state")
        if state not in states:
            raise _error(f"{capability_id}.state is not defined in [states]: {state!r}")
        evidence_class = _require_string(
            item["evidence_class"], f"{capability_id}.evidence_class"
        )
        if evidence_class not in evidence_classes:
            raise _error(
                f"{capability_id}.evidence_class is not defined in [evidence_classes]: "
                f"{evidence_class!r}"
            )
        evidence = _require_string_list(item["evidence"], f"{capability_id}.evidence")
        for evidence_path in evidence:
            _validate_evidence_path(evidence_path, capability_id)
        capabilities.append(
            {
                "id": capability_id,
                "name": _require_string(item["name"], f"{capability_id}.name"),
                "state": state,
                "summary": _require_string(item["summary"], f"{capability_id}.summary"),
                "limits": _require_string_list(item["limits"], f"{capability_id}.limits"),
                "future_gates": _require_string_list(
                    item["future_gates"], f"{capability_id}.future_gates"
                ),
                "evidence_class": evidence_class,
                "evidence": evidence,
            }
        )

    if ids != REQUIRED_CAPABILITY_IDS:
        missing_ids = sorted(REQUIRED_CAPABILITY_IDS - ids)
        unexpected_ids = sorted(ids - REQUIRED_CAPABILITY_IDS)
        details = []
        if missing_ids:
            details.append(f"missing required capability IDs {missing_ids}")
        if unexpected_ids:
            details.append(f"unregistered capability IDs {unexpected_ids}")
        raise _error("; ".join(details))

    return {
        "title": title,
        "states": dict(sorted(states.items())),
        "evidence_classes": dict(sorted(evidence_classes.items())),
        "capabilities": sorted(capabilities, key=lambda capability: str(capability["id"])),
    }


def render_document(contract: Mapping[str, Any]) -> str:
    """Render the Markdown view without timestamps or environment-dependent output."""
    title = _require_string(contract["title"], "title")
    states = contract["states"]
    evidence_classes = contract["evidence_classes"]
    capabilities = contract["capabilities"]
    if (
        not isinstance(states, Mapping)
        or not isinstance(evidence_classes, Mapping)
        or not isinstance(capabilities, Sequence)
    ):
        raise _error("invalid normalized contract")

    lines = [
        "<!-- Generated by `uv run python scripts/capability_check.py --write` from `docs/capabilities.toml`; do not edit directly. -->",
        "",
        f"# {title}",
        "",
        "> This is a source inventory, not a release approval or a deployment attestation. "
        "The stated capability state is the only claim this document makes.",
        "",
        "## State definitions",
        "",
        "| State | Meaning |",
        "|---|---|",
    ]
    for name, description in states.items():
        lines.append(f"| `{name}` | {description} |")

    lines.extend(["", "## Evidence classes", "", "| Class | Meaning |", "|---|---|"])
    for name, description in evidence_classes.items():
        lines.append(f"| `{name}` | {description} |")

    lines.extend(["", "## Capabilities"])
    for capability in capabilities:
        capability_id = _require_string(capability["id"], "capability.id")
        lines.extend(
            [
                "",
                f"### `{capability_id}` — {_require_string(capability['name'], f'{capability_id}.name')}",
                "",
                f"**State:** `{_require_string(capability['state'], f'{capability_id}.state')}`",
                "",
                f"**Evidence class:** `{_require_string(capability['evidence_class'], f'{capability_id}.evidence_class')}`",
                "",
                _require_string(capability["summary"], f"{capability_id}.summary"),
                "",
                "**Scope and limits**",
                "",
            ]
        )
        for limit in _require_string_list(capability["limits"], f"{capability_id}.limits"):
            lines.append(f"- {limit}")
        lines.extend(["", "**Future gates before this state can improve**", ""])
        for gate in _require_string_list(capability["future_gates"], f"{capability_id}.future_gates"):
            lines.append(f"- {gate}")
        lines.extend(
            ["", "**Code/evidence locations (presence only, not deployment validation):**", ""]
        )
        for evidence in sorted(
            _require_string_list(capability["evidence"], f"{capability_id}.evidence")
        ):
            lines.append(f"- [`{evidence}`](../{evidence})")

    lines.extend(
        [
            "",
            "## Maintaining this contract",
            "",
            "Edit `docs/capabilities.toml`, run `uv run python scripts/capability_check.py --write`, and include the regenerated file in the same change. `--check` is deterministic and fails when the generated view is stale.",
            "",
        ]
    )
    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="validate or render docs/capabilities.toml")
    actions = parser.add_mutually_exclusive_group()
    actions.add_argument(
        "--check", action="store_true", help="fail if the generated Markdown is stale"
    )
    actions.add_argument("--write", action="store_true", help="write the generated Markdown")
    actions.add_argument("--print", action="store_true", help="print the generated Markdown")
    args = parser.parse_args(argv)

    try:
        rendered = render_document(load_contract())
    except ValueError as exc:
        print(f"capability_check: {exc}", file=sys.stderr)
        return 1

    if args.print:
        print(rendered, end="")
        return 0
    if args.write:
        OUTPUT_PATH.write_text(rendered, encoding="utf-8")
        print(f"wrote {OUTPUT_PATH.relative_to(ROOT)}")
        return 0
    if not OUTPUT_PATH.is_file() or OUTPUT_PATH.read_text(encoding="utf-8") != rendered:
        print(
            "docs/CAPABILITIES.md is stale; run `uv run python scripts/capability_check.py --write`",
            file=sys.stderr,
        )
        return 1
    print("docs/CAPABILITIES.md is current")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
