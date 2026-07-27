"""CI step 1 — dependency licence gate (PHASE-0 Task 1).

Walks the *resolved* dependency tree via importlib.metadata (not the declared
one — transitive pulls are exactly what this is meant to catch), classifies each
distribution against scripts/license_policy.toml, and exits non-zero on anything
unknown or denied.

Usage:
    python scripts/license_check.py [--root tracebed] [--policy scripts/license_policy.toml]
    python scripts/license_check.py --self-test    # proves the gate actually fails
"""

from __future__ import annotations

import argparse
import re
import sys
import tomllib
from dataclasses import dataclass, field
from importlib import metadata
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# A gate that crashes while PRINTING its own (passing) result is a false red.
# Windows consoles default to cp1252; these reports use box drawing and em
# dashes, and `print` raised UnicodeEncodeError AFTER the gate had already
# decided its verdict -- so a PASS run looked like a gate failure. Force
# UTF-8 on the streams rather than downgrading the output, and fall back to
# replacement characters if even that is refused: the verdict must survive the
# terminal it is printed to.
for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        _stream.reconfigure(encoding="utf-8", errors="replace")


# Distributions that are part of the toolchain rather than the shipped artefact.
# They are still reported, but a denial here is a warning, not a gate failure.
DEV_ONLY = {
    "pytest",
    "pytest-asyncio",
    "mypy",
    "mypy-extensions",
    "ruff",
    "iniconfig",
    "pluggy",
    "coverage",
    "hatchling",
    "pathspec",
    "trove-classifiers",
    "editables",
}


@dataclass
class Policy:
    allow: set[str]
    conditional: set[str]
    deny: set[str]
    lgpl_rationale: dict[str, str]
    manual_overrides: dict[str, str]

    @staticmethod
    def load(path: Path) -> Policy:
        raw = tomllib.loads(path.read_text(encoding="utf-8"))
        return Policy(
            allow={_norm_licence(x) for x in raw.get("allow", [])},
            conditional={_norm_licence(x) for x in raw.get("conditional", [])},
            deny={_norm_licence(x) for x in raw.get("deny", [])},
            lgpl_rationale={_norm_dist(k): v for k, v in raw.get("lgpl_rationale", {}).items()},
            manual_overrides={_norm_dist(k): v for k, v in raw.get("manual_overrides", {}).items()},
        )


@dataclass
class Finding:
    dist: str
    version: str
    licence: str
    status: str  # allowed | conditional-ok | denied | unknown
    detail: str = ""


@dataclass
class Report:
    findings: list[Finding] = field(default_factory=list)

    @property
    def failures(self) -> list[Finding]:
        return [
            f
            for f in self.findings
            if f.status in {"denied", "unknown"} and _norm_dist(f.dist) not in DEV_ONLY
        ]


def _norm_licence(value: str) -> str:
    # Parentheses are dropped rather than stripped from the edges: classifier strings
    # like "Mozilla Public License 2.0 (MPL 2.0)" carry them mid-string, where an
    # edge-strip leaves an unbalanced atom that can never match the policy.
    return re.sub(r"[\s_]+", "-", re.sub(r"[()]", " ", value).strip().lower())


def _norm_dist(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value.strip().lower())


_CLASSIFIER_LICENCE = re.compile(r"^License\s*::\s*(?:OSI Approved\s*::\s*)?(.+)$")


def read_licence(dist: metadata.Distribution) -> str:
    """Best-effort licence extraction across the three metadata conventions."""
    meta = dist.metadata

    # PEP 639: License-Expression is authoritative when present.
    expr = meta.get("License-Expression")
    if expr:
        return str(expr).strip()

    classifiers = [str(c) for c in meta.get_all("Classifier") or []]
    from_classifiers = [
        m.group(1).strip() for c in classifiers if (m := _CLASSIFIER_LICENCE.match(c))
    ]
    # "OSI Approved" alone carries no information; drop it.
    from_classifiers = [c for c in from_classifiers if c.lower() != "osi approved"]
    if from_classifiers:
        return " OR ".join(from_classifiers)

    legacy = meta.get("License")
    if legacy:
        text = str(legacy).strip()
        # Some projects dump the whole licence text into this field.
        return text if len(text) < 120 else text.splitlines()[0][:120]

    return ""


def split_expression(expr: str) -> list[str]:
    """Split an SPDX-ish expression into its atoms. `A OR B` passes if any atom passes."""
    parts = re.split(r"\s+(?:OR|AND)\s+|\s*;\s*", expr, flags=re.IGNORECASE)
    return [p.strip(" ()") for p in parts if p.strip(" ()")]


def classify(dist_name: str, licence: str, policy: Policy) -> Finding:
    key = _norm_dist(dist_name)
    version = _version_of(dist_name)

    if key in policy.manual_overrides:
        return Finding(dist_name, version, licence or "(none)", "allowed",
                       f"manual override: {policy.manual_overrides[key]}")

    if not licence:
        return Finding(dist_name, version, "(none)", "unknown",
                       "no License-Expression, no License:: classifier, no License field")

    atoms = [_norm_licence(a) for a in split_expression(licence)]

    if any(a in policy.deny for a in atoms):
        denied = next(a for a in atoms if a in policy.deny)
        return Finding(dist_name, version, licence, "denied", f"denylisted licence: {denied}")

    if any(a in policy.allow for a in atoms):
        return Finding(dist_name, version, licence, "allowed")

    if any(a in policy.conditional for a in atoms):
        if key in policy.lgpl_rationale:
            return Finding(dist_name, version, licence, "conditional-ok",
                           policy.lgpl_rationale[key])
        return Finding(dist_name, version, licence, "denied",
                       "conditional licence with no entry in [lgpl_rationale]")

    return Finding(dist_name, version, licence, "unknown",
                   "licence not present in allow, conditional, or deny lists")


def _version_of(dist_name: str) -> str:
    try:
        return metadata.version(dist_name)
    except metadata.PackageNotFoundError:
        return "?"


def resolve_tree(root: str) -> set[str]:
    """Transitive closure of Requires-Dist starting at `root`, extras included."""
    seen: set[str] = set()
    queue = [root]
    while queue:
        name = queue.pop()
        key = _norm_dist(name)
        if key in seen:
            continue
        try:
            dist = metadata.distribution(name)
        except metadata.PackageNotFoundError:
            continue
        seen.add(key)
        for req in dist.requires or []:
            dep = re.split(r"[\s\[;(<>=!~]", req.strip(), maxsplit=1)[0]
            if dep:
                queue.append(dep)
    return seen


def collect(root: str | None, policy: Policy) -> Report:
    if root:
        wanted = resolve_tree(root)
        if not wanted:
            print(f"warning: '{root}' is not installed; falling back to the full environment",
                  file=sys.stderr)
    else:
        wanted = set()

    report = Report()
    for dist in metadata.distributions():
        name = dist.metadata.get("Name")
        if not name:
            continue
        if wanted and _norm_dist(name) not in wanted:
            continue
        report.findings.append(classify(str(name), read_licence(dist), policy))
    report.findings.sort(key=lambda f: (f.status != "denied", f.status != "unknown", f.dist.lower()))
    return report


def render(report: Report) -> str:
    lines = ["dist                           version      status          licence"]
    lines.append("-" * 96)
    for f in report.findings:
        lines.append(f"{f.dist[:30]:<30} {f.version[:12]:<12} {f.status:<15} {f.licence[:40]}")
        if f.detail and f.status != "allowed":
            lines.append(f"{'':<30} {'':<12} └─ {f.detail}")
    return "\n".join(lines)


def self_test(policy: Policy) -> int:
    """Prove the gate bites: a fake SSPL distribution must be rejected."""
    cases = [
        ("fake-sspl-db", "SSPL-1.0", "denied"),
        ("fake-agpl-cache", "AGPL-3.0-only", "denied"),
        ("psycopg", "LGPL-3.0-only", "conditional-ok"),
        ("some-other-lgpl", "LGPL-3.0-only", "denied"),
        ("fastapi", "MIT", "allowed"),
        ("mystery-lib", "", "unknown"),
        ("dual-licensed", "Apache-2.0 OR MIT", "allowed"),
    ]
    ok = True
    for name, licence, expected in cases:
        got = classify(name, licence, policy).status
        mark = "ok " if got == expected else "FAIL"
        if got != expected:
            ok = False
        print(f"[{mark}] {name:<20} {licence or '(none)':<22} expected={expected:<15} got={got}")
    return 0 if ok else 1


# Names that appear in `pyproject.toml` but are exempt from the DECISIONS.md audit below,
# with the reason. Deliberately tiny: the point of the audit is that an addition is a
# reviewable event, and an exemption list that grows is the audit failing quietly.
_DEPENDENCY_AUDIT_EXEMPT: dict[str, str] = {
    # Build backend, not a runtime or test dependency of the service.
    "hatchling": "build backend, declared in [build-system]",
}


def _declared_dependencies() -> set[str]:
    """Every distribution name in `pyproject.toml`'s runtime and dev dependency lists."""
    import re
    import tomllib

    raw = (REPO_ROOT / "pyproject.toml").read_bytes()
    data = tomllib.loads(raw.decode("utf-8"))
    project = data.get("project", {})
    specs: list[str] = list(project.get("dependencies", []))
    for extra in project.get("optional-dependencies", {}).values():
        specs.extend(extra)
    names: set[str] = set()
    for spec in specs:
        # "psycopg[binary,pool]>=3.2" -> "psycopg"
        name = re.split(r"[\[<>=!~;\s]", spec, maxsplit=1)[0].strip()
        if name:
            names.add(_norm_dist(name))
    return names


def dependency_audit() -> int:
    """Hard rule 10 / D-036: every declared dependency carries a DECISIONS.md entry.

    Three dependencies (`prometheus-client`, `pytest-asyncio`, `types-pyyaml`) reached this
    tree with no entry, while D-036's own inventory named a package (`onnxruntime`) that was
    never installed — the inventory was wrong in both directions at once. A grep is a weak
    check and it is the right strength here: the question is "did a human write this down",
    not "is the prose correct".
    """
    decisions = (REPO_ROOT / "DECISIONS.md").read_text(encoding="utf-8").lower()
    missing = sorted(
        name
        for name in _declared_dependencies()
        if name not in _DEPENDENCY_AUDIT_EXEMPT
        and name not in decisions
        and name.replace("-", "_") not in decisions
    )
    for name in missing:
        print(f"undeclared dependency (no DECISIONS.md entry): {name}")
    print()
    if missing:
        print(f"DEPENDENCY AUDIT: FAIL — {len(missing)} dependency(ies) with no decision record")
        return 1
    print("DEPENDENCY AUDIT: PASS — every declared dependency is named in DECISIONS.md")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--dependency-audit",
        action="store_true",
        help="check that every pyproject dependency is named in DECISIONS.md (hard rule 10)",
    )
    ap.add_argument("--root", default="tracebed",
                    help="walk only this distribution's dependency closure (default: tracebed)")
    ap.add_argument("--all", action="store_true", help="check every installed distribution")
    ap.add_argument("--policy", type=Path, default=REPO_ROOT / "scripts" / "license_policy.toml")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args(argv)

    if args.dependency_audit:
        return dependency_audit()

    policy = Policy.load(args.policy)
    if args.self_test:
        return self_test(policy)

    report = collect(None if args.all else args.root, policy)
    print(render(report))

    failures = report.failures
    print()
    if failures:
        print(f"LICENCE GATE: FAIL — {len(failures)} distribution(s) blocked")
        for f in failures:
            print(f"  - {f.dist} {f.version}: {f.licence or '(none)'} — {f.detail}")
        return 1
    print(f"LICENCE GATE: PASS — {len(report.findings)} distribution(s) cleared")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
