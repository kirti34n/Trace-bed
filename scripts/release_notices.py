#!/usr/bin/env python3
"""Materialize resolved Python and npm licence metadata for a release candidate."""

from __future__ import annotations

import argparse
import json
import sys
from importlib import metadata
from pathlib import Path


def _license_text(directory: Path) -> str:
    candidates = sorted(
        path
        for path in directory.rglob("*")
        if path.is_file() and path.name.lower().startswith(("license", "copying", "notice"))
    )
    if not candidates:
        raise ValueError(f"no LICENSE/COPYING/NOTICE file in {directory}")
    return "\n\n".join(
        f"--- {path.name} ---\n{path.read_text(encoding='utf-8', errors='replace')}"
        for path in candidates
    )


def _python_entries(site_packages: Path) -> list[str]:
    entries: list[str] = []
    for distribution in metadata.distributions(path=[str(site_packages)]):
        name = distribution.metadata.get("Name")
        if not name:
            continue
        license_text = distribution.metadata.get("License-Expression") or distribution.metadata.get(
            "License", "(no machine-readable license)"
        )
        files = distribution.files or []
        metadata_file = next((file for file in files if str(file).endswith("METADATA")), None)
        directory = (
            Path(str(distribution.locate_file(metadata_file))).parent
            if metadata_file
            else site_packages
        )
        entries.append(
            f"Python: {name} {distribution.version}\nLicense: {license_text}\n\n"
            f"{_license_text(directory)}\n"
        )
    return sorted(entries, key=str.lower)


def _npm_entries(node_modules: Path) -> list[str]:
    entries: list[str] = []
    for package_json in sorted(node_modules.rglob("package.json")):
        if "node_modules" not in package_json.parts:
            continue
        raw = json.loads(package_json.read_text(encoding="utf-8"))
        name, version = raw.get("name"), raw.get("version")
        if isinstance(name, str) and isinstance(version, str):
            entries.append(
                f"npm: {name} {version}\nLicense: {raw.get('license', '(no machine-readable license)')}\n\n"
                f"{_license_text(package_json.parent)}\n"
            )
    return sorted(set(entries), key=str.lower)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--site-packages", type=Path, required=True)
    parser.add_argument("--node-modules", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        entries = _python_entries(args.site_packages) + _npm_entries(args.node_modules)
        if not entries or not any(
            "psycopg" in entry.lower() and "lgpl" in entry.lower() for entry in entries
        ):
            raise ValueError(
                "resolved notices are incomplete or omit conditional psycopg LGPL metadata"
            )
        args.output.write_text(
            "# Resolved third-party notices\n\n" + "\n".join(entries), encoding="utf-8"
        )
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"release notices: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
