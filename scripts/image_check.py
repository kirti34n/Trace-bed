"""Container-image gate (D-109) — the half of hard rule 9 the Python licence gate cannot reach.

`scripts/license_check.py` walks `importlib.metadata.distributions()`, so it audits the Python
tree and nothing else. Every container image this repository runs — the database that holds the
vault, the cache, the object store — sat outside every gate, including one (`tensorchord/
vchord-suite:pg18-latest`) that appeared in no plan and no decision, on a floating tag. Rule 9's
three named AGPL hazards (pg_search, MinIO, Redis) are all infrastructure: exactly the category
the Python audit cannot see.

What this checks, and deliberately only this:

  1. every `image:` in `docker/compose.yaml` and `.github/workflows/ci.yml` is declared in
     `scripts/image_policy.toml`, with a licence and a purpose;
  2. every declared image's tag matches what the file actually uses (a policy that has drifted
     from the compose file is worse than none);
  3. a floating tag (`latest` / `*-latest`) is declared as such.

What it does NOT check: whether the declared licence is true. Verifying an image's licence needs
a registry pull and a filesystem walk; claiming otherwise would be exactly the kind of
adjacent-measurement the gate reports were audited for. The value here is that adding an image
without writing it down fails the build.

Usage:
    python scripts/image_check.py
    python scripts/image_check.py --self-test
"""

from __future__ import annotations

import argparse
import re
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path

for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        _stream.reconfigure(encoding="utf-8", errors="replace")

REPO_ROOT = Path(__file__).resolve().parent.parent
POLICY_PATH = REPO_ROOT / "scripts" / "image_policy.toml"
SCANNED_FILES = (
    REPO_ROOT / "docker" / "compose.yaml",
    REPO_ROOT / ".github" / "workflows" / "ci.yml",
)

# `image: repo/name:tag` in YAML. Quotes optional; a digest pin (`@sha256:...`) is captured as
# part of the tag so a digest-pinned image is never mistaken for a floating one.
_IMAGE_RE = re.compile(r"^\s*image:\s*[\"']?([^\s\"'#]+)[\"']?", re.MULTILINE)


def is_floating(tag: str) -> bool:
    """`latest`, `pg18-latest`, or no tag at all. A digest pin is never floating."""
    if tag.startswith("sha256:") or "@sha256:" in tag:
        return False
    return tag == "" or tag == "latest" or tag.endswith("-latest")


@dataclass(frozen=True, slots=True)
class ImageRef:
    repository: str
    tag: str
    source: str

    @property
    def full(self) -> str:
        return f"{self.repository}:{self.tag}" if self.tag else self.repository


def parse_image(raw: str, source: str) -> ImageRef:
    """Split `repo[:tag]`, tolerating a registry host with its own port (`host:5000/img:tag`)."""
    if "@" in raw:
        repository, _, digest = raw.partition("@")
        return ImageRef(repository, digest, source)
    head, sep, tail = raw.rpartition(":")
    if sep and "/" not in tail:
        return ImageRef(head, tail, source)
    return ImageRef(raw, "", source)


def scan_files(paths: tuple[Path, ...] = SCANNED_FILES) -> list[ImageRef]:
    found: list[ImageRef] = []
    for path in paths:
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8")
        for raw in _IMAGE_RE.findall(text):
            found.append(parse_image(raw, str(path.relative_to(REPO_ROOT)).replace("\\", "/")))
    return found


def load_policy(path: Path = POLICY_PATH) -> dict[str, dict[str, object]]:
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    entries = data.get("image", [])
    return {str(e["repository"]): e for e in entries}


def check(images: list[ImageRef], policy: dict[str, dict[str, object]]) -> list[str]:
    problems: list[str] = []
    for ref in images:
        entry = policy.get(ref.repository)
        if entry is None:
            problems.append(
                f"{ref.source}: image {ref.full} is not declared in scripts/image_policy.toml"
            )
            continue
        declared_tag = str(entry.get("tag", ""))
        if declared_tag != ref.tag:
            problems.append(
                f"{ref.source}: image {ref.full} does not match the policy's declared tag "
                f"{declared_tag!r} — the policy has drifted from what actually runs"
            )
        if not str(entry.get("licence", "")).strip():
            problems.append(f"policy entry for {ref.repository} declares no licence")
        if not str(entry.get("purpose", "")).strip():
            problems.append(f"policy entry for {ref.repository} declares no purpose")
        if is_floating(ref.tag) and not bool(entry.get("floating_tag", False)):
            problems.append(
                f"{ref.source}: image {ref.full} uses a floating tag that the policy does not "
                "acknowledge (set floating_tag = true, with a note naming the owner action)"
            )
    return problems


def self_test() -> int:
    policy = {
        "acme/db": {"tag": "1.2", "licence": "Apache-2.0", "purpose": "x", "floating_tag": False},
        "acme/store": {
            "tag": "latest",
            "licence": "Apache-2.0",
            "purpose": "x",
            "floating_tag": True,
        },
    }
    clean = check(
        [ImageRef("acme/db", "1.2", "t"), ImageRef("acme/store", "latest", "t")], policy
    )
    undeclared = check([ImageRef("acme/other", "1.0", "t")], policy)
    drifted = check([ImageRef("acme/db", "9.9", "t")], policy)
    unacknowledged = check(
        [ImageRef("acme/db", "latest", "t")],
        {"acme/db": {"tag": "latest", "licence": "L", "purpose": "p", "floating_tag": False}},
    )
    parsed = parse_image("registry.example.com:5000/team/img:2.1", "t")
    parse_ok = parsed.repository == "registry.example.com:5000/team/img" and parsed.tag == "2.1"
    floating_ok = (
        is_floating("latest")
        and is_floating("pg18-latest")
        and not is_floating("8-alpine")
        and not is_floating("sha256:abc")
    )

    checks = (
        ("clean policy -> 0 problems", not clean),
        ("undeclared image rejected", len(undeclared) == 1),
        ("tag drift rejected", len(drifted) == 1),
        ("unacknowledged floating tag rejected", len(unacknowledged) == 1),
        ("registry host with a port parses", parse_ok),
        ("floating-tag detection", floating_ok),
    )
    for label, ok in checks:
        print(f"[{'ok ' if ok else 'FAIL'}] {label}")
    return 0 if all(ok for _, ok in checks) else 1


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args(argv)
    if args.self_test:
        return self_test()

    images = scan_files()
    policy = load_policy()
    problems = check(images, policy)
    for ref in images:
        print(f"  {ref.source}: {ref.full}")
    for problem in problems:
        print(problem)
    print()
    if not images:
        print("IMAGE GATE: FAIL — no images found to check; the scanner or the paths are wrong")
        return 1
    if problems:
        print(f"IMAGE GATE: FAIL — {len(problems)} problem(s)")
        return 1
    print(f"IMAGE GATE: PASS — {len(images)} image reference(s), all declared")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
