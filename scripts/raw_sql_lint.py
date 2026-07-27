"""CI step 2 — raw-SQL containment lint (PHASE-0 Task 7).

Invariant 4 (project isolation) rests on every query being built by the typed
repository, which requires a ProjectId and sets the RLS GUC. A stray
`conn.execute("SELECT ...")` in api/ or workers/ bypasses both. This walks the
AST of src/ and fails on SQL execution outside the permitted packages.

Also enforced here (cheap, same walk):
  - No `tb:` Valkey key literal outside stores/valkey/keys.py (PHASE-0 Task 17).

Usage:
    python scripts/raw_sql_lint.py [--src src/tracebed]
    python scripts/raw_sql_lint.py --self-test
"""

from __future__ import annotations

import argparse
import ast
import re
import sys
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# Only these packages may execute SQL. Paths are relative to the src root.
SQL_ALLOWED_PREFIXES = (
    "stores/pg/",
    # Migrations are plain .sql applied by yoyo; the runner lives here.
    "stores/pg/migrate.py",
)

# Only this module may construct Valkey key strings.
KEY_ALLOWED = "stores/valkey/keys.py"

EXEC_ATTRS = {"execute", "executemany", "execute_batch", "executescript", "copy"}

SQL_START = re.compile(
    r"^\s*(SELECT|INSERT|UPDATE|DELETE|WITH|CREATE|ALTER|DROP|TRUNCATE|GRANT|REVOKE|SET\s+LOCAL|COPY)\b",
    re.IGNORECASE,
)

KEY_LITERAL = re.compile(r"(^|[^A-Za-z0-9_])tb:")


@dataclass(frozen=True)
class Violation:
    path: str
    line: int
    rule: str
    detail: str

    def __str__(self) -> str:
        return f"{self.path}:{self.line}: [{self.rule}] {self.detail}"


class Walker(ast.NodeVisitor):
    def __init__(self, rel_path: str) -> None:
        self.rel = rel_path
        self.sql_allowed = any(rel_path.startswith(p) for p in SQL_ALLOWED_PREFIXES)
        self.key_allowed = rel_path == KEY_ALLOWED
        self.violations: list[Violation] = []

    def visit_Call(self, node: ast.Call) -> None:
        if (
            not self.sql_allowed
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in EXEC_ATTRS
        ):
            self.violations.append(
                Violation(
                    self.rel,
                    node.lineno,
                    "raw-sql",
                    f".{node.func.attr}(...) outside stores/pg/ — use the typed Repo",
                )
            )
        self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant) -> None:
        if isinstance(node.value, str):
            text = node.value
            if not self.sql_allowed and SQL_START.match(text):
                head = " ".join(text.split())[:60]
                self.violations.append(
                    Violation(self.rel, node.lineno, "sql-literal",
                              f"SQL string outside stores/pg/: {head!r}")
                )
            if not self.key_allowed and KEY_LITERAL.search(text):
                self.violations.append(
                    Violation(self.rel, node.lineno, "valkey-key",
                              "'tb:' key literal outside stores/valkey/keys.py")
                )
        self.generic_visit(node)


def check_tree(src_root: Path) -> list[Violation]:
    violations: list[Violation] = []
    for path in sorted(src_root.rglob("*.py")):
        rel = path.relative_to(src_root).as_posix()
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except SyntaxError as exc:  # a parse failure is itself a gate failure
            violations.append(Violation(rel, exc.lineno or 0, "parse-error", str(exc.msg)))
            continue
        walker = Walker(rel)
        walker.visit(tree)
        violations.extend(walker.violations)
    return violations


def check_source(rel_path: str, source: str) -> list[Violation]:
    """Single-buffer variant used by the self-test and by unit tests."""
    walker = Walker(rel_path)
    walker.visit(ast.parse(source))
    return walker.violations


def self_test() -> int:
    cases: list[tuple[str, str, str, int]] = [
        ("api/routes.py", 'conn.execute("SELECT 1")', "must flag execute + literal", 2),
        ("api/routes.py", "await conn.execute(query)", "must flag execute", 1),
        ("stores/pg/repo.py", 'cur.execute("SELECT 1")', "repo is exempt", 0),
        ("hotpath/retriever.py", 'key = f"tb:{pid}:wm"', "key literal outside keys.py", 1),
        ("stores/valkey/keys.py", 'key = f"tb:{pid}:wm"', "keys.py is exempt", 0),
        ("workers/scorer.py", "repo.update_q(project_id, mid, q)", "repo call is fine", 0),
    ]
    ok = True
    for rel, src, why, expected in cases:
        got = len(check_source(rel, src))
        mark = "ok " if got == expected else "FAIL"
        if got != expected:
            ok = False
        print(f"[{mark}] {rel:<26} {why:<32} expected={expected} got={got}")
    return 0 if ok else 1


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--src", type=Path, default=REPO_ROOT / "src" / "tracebed")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args(argv)

    if args.self_test:
        return self_test()

    if not args.src.exists():
        print(f"raw-sql lint: source root {args.src} does not exist", file=sys.stderr)
        return 1

    violations = check_tree(args.src)
    for v in violations:
        print(str(v))
    print()
    if violations:
        print(f"RAW-SQL LINT: FAIL — {len(violations)} violation(s)")
        return 1
    print("RAW-SQL LINT: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
