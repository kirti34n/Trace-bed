"""CI step 3 — hot-path purity gate (PLAN.md §2 invariant 1, CI-blocking from Phase 1).

Walks the *static import graph* rooted at `tracebed.hotpath` and asserts that no
generative LLM client and no background worker is reachable. Query embedding is
permitted, but only through `tracebed.adapters.embedding` — a vector endpoint, not
a generative client.

This is a reachability test over the module graph, not a grep: an indirect import
three modules deep fails exactly like a direct one.

`--root` may be repeated and defaults to every root in `DEFAULT_ROOTS` -- which is
`tracebed.hotpath` PLUS the retrieval-adjacent surfaces that are not inside it
(`tracebed.workflow.prefetch` runs on the retrieval path). The flag used to be parsed and
then ignored: the gate iterated a hardcoded `hotpath` glob, so no other surface could be
checked by the gate that exists to check it.

Third-party imports are governed by an ALLOWLIST (`ALLOWED_EXTERNAL` + the standard
library), not by a denylist of provider SDKs. A denylist of eleven names let `import groq`
or `from ollama import chat` through unchallenged; an allowlist makes any new third-party
dependency on the hot path a gate failure that a human has to look at. `FORBIDDEN_EXTERNAL`
survives only to make the message for a known generative client say so explicitly.

Usage:
    python scripts/purity_check.py [--src src/tracebed] [--root tracebed.hotpath ...]
    python scripts/purity_check.py --self-test
"""

from __future__ import annotations

import argparse
import ast
import sys
from dataclasses import dataclass, field
from pathlib import Path

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



REPO_ROOT = Path(__file__).resolve().parent.parent
PACKAGE = "tracebed"

# Reaching any of these from hotpath/ is a gate failure.
FORBIDDEN_INTERNAL = (
    "tracebed.workers",
    "tracebed.ingest",
    "tracebed.adapters.llm",
    "tracebed.crypto",  # trace-payload crypto belongs to the write path
)

# Third-party generative clients. Import of any of these anywhere under hotpath/
# is a failure regardless of how it is reached.
FORBIDDEN_EXTERNAL = (
    "openai",
    "anthropic",
    "google.generativeai",
    "google.genai",
    "litellm",
    "vertexai",
    "cohere",
    "mistralai",
    "transformers",
    "langchain",
    "llama_index",
)

# The ONLY third-party top-level packages any checked root may reach, on top of the standard
# library. Deliberately tiny and deliberately an allowlist: the invariant is "no generative LLM
# client is reachable", and the set of things that are a generative LLM client is open-ended
# (groq, ollama, together, replicate, a vendored wrapper, a package published tomorrow) while
# the set of things the hot path legitimately needs is closed and short. Adding a name here is a
# reviewable one-line diff; adding a provider SDK without touching this file is impossible.
#
#   psycopg / psycopg_pool -- the store driver (D-036)
#   pydantic / pydantic_settings -- the wire and config models
ALLOWED_EXTERNAL = frozenset(
    {
        "psycopg",
        "psycopg_pool",
        "pydantic",
        "pydantic_settings",
    }
)

# Roots checked when `--root` is not given. `workflow.prefetch` is here because it sits on the
# retrieval path while living outside `hotpath/`.
DEFAULT_ROOTS = (
    f"{PACKAGE}.hotpath",
    f"{PACKAGE}.workflow.prefetch",
)

# Explicitly permitted despite living outside hotpath/.
ALLOWED_INTERNAL = (
    "tracebed.domain",
    "tracebed.stores",
    "tracebed.adapters.embedding",
    "tracebed.adapters.ports",
    "tracebed.core",
    "tracebed.hotpath",
)


@dataclass
class Graph:
    edges: dict[str, set[str]] = field(default_factory=dict)

    def add(self, src: str, dst: str) -> None:
        self.edges.setdefault(src, set()).add(dst)

    def reachable(self, root: str) -> dict[str, list[str]]:
        """module -> shortest import path from root (inclusive)."""
        paths: dict[str, list[str]] = {root: [root]}
        queue = [root]
        while queue:
            cur = queue.pop(0)
            for nxt in sorted(self.edges.get(cur, ())):
                if nxt not in paths:
                    paths[nxt] = [*paths[cur], nxt]
                    queue.append(nxt)
        return paths


def module_name(src_root: Path, path: Path) -> str:
    rel = path.relative_to(src_root).with_suffix("")
    parts = list(rel.parts)
    if parts and parts[-1] == "__init__":
        parts.pop()
    return ".".join([PACKAGE, *parts]) if parts else PACKAGE


def _is_type_checking_test(test: ast.expr) -> bool:
    """`TYPE_CHECKING` or `typing.TYPE_CHECKING` as the whole condition.

    Deliberately narrow: only the two spellings whose truth value is *known* to
    be False at runtime. `not TYPE_CHECKING`, `TYPE_CHECKING and X`, and any
    other expression are NOT recognised, so an unfamiliar guard keeps being
    walked — over-approximating reachability is a false red, under-approximating
    it is a hole, and only one of those two is safe to get wrong.
    """
    if isinstance(test, ast.Name):
        return test.id == "TYPE_CHECKING"
    if isinstance(test, ast.Attribute):
        return test.attr == "TYPE_CHECKING" and isinstance(test.value, ast.Name)
    return False


def _runtime_nodes(tree: ast.AST) -> list[ast.AST]:
    """Every node except those inside an `if TYPE_CHECKING:` body.

    An import nested under that guard emits no runtime import at all, so it
    cannot reach a generative client, a worker, or anything else this gate
    exists to keep out of the hot path — counting it is a false positive, and a
    gate that is red for a reason no edit to the hot path can fix stops being
    read. Four Phase 1 modules independently declared duplicate local Protocols
    purely to route around this (D-055/D-057), which is the cost of the false
    positive: the duplication itself is now the drift risk.

    The `orelse` branch IS walked — that is the runtime branch of the guard, and
    the whole point of the idiom is that it executes.
    """
    out: list[ast.AST] = []
    stack: list[ast.AST] = [tree]
    while stack:
        node = stack.pop()
        out.append(node)
        if isinstance(node, ast.If) and _is_type_checking_test(node.test):
            stack.extend(node.orelse)
            continue
        stack.extend(ast.iter_child_nodes(node))
    return out


def imports_in_source(source: str, this_module: str, filename: str = "<string>") -> set[str]:
    """The runtime import targets of one module's source (see `_runtime_nodes`)."""
    out: set[str] = set()
    tree = ast.parse(source, filename=filename)
    pkg_parts = this_module.split(".")
    for node in _runtime_nodes(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                out.add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                # Resolve a relative import against the *package* of this module.
                base = pkg_parts[: len(pkg_parts) - node.level + 1]
                target = ".".join([*base, node.module]) if node.module else ".".join(base)
            else:
                target = node.module or ""
            if target:
                out.add(target)
                for alias in node.names:
                    out.add(f"{target}.{alias.name}")
    return out


def imports_of(path: Path, this_module: str) -> set[str]:
    return imports_in_source(path.read_text(encoding="utf-8"), this_module, str(path))


def build_graph(src_root: Path) -> Graph:
    graph = Graph()
    by_module: dict[str, Path] = {}
    for path in sorted(src_root.rglob("*.py")):
        by_module[module_name(src_root, path)] = path
    for mod, path in by_module.items():
        for imported in imports_of(path, mod):
            # Normalise `from x import y` where y is a symbol, not a module.
            target = imported if imported in by_module else imported.rsplit(".", 1)[0]
            graph.add(mod, target if target in by_module else imported)
    return graph


def violations_for(
    graph: Graph, root: str, *, allowed_internal: tuple[str, ...] = ALLOWED_INTERNAL
) -> list[str]:
    problems: list[str] = []
    for mod, path in sorted(graph.reachable(root).items()):
        chain = " -> ".join(path)
        if mod.startswith(f"{PACKAGE}."):
            if mod.startswith(allowed_internal):
                continue
            if mod.startswith(FORBIDDEN_INTERNAL):
                problems.append(f"forbidden internal module reachable: {chain}")
            else:
                problems.append(f"module outside the hot-path allowlist reachable: {chain}")
        else:
            head = mod.split(".")[0]
            if head in {m.split(".")[0] for m in FORBIDDEN_EXTERNAL} or mod.startswith(
                FORBIDDEN_EXTERNAL
            ):
                problems.append(f"generative client reachable: {chain}")
            elif head in ALLOWED_EXTERNAL or head in sys.stdlib_module_names or head == "":
                continue
            else:
                # The allowlist half. An unknown third-party package on the hot path is a
                # failure even when nobody has ever heard of it -- which is the whole point,
                # because the denylist this replaced could only ever refuse the SDKs someone
                # had thought of in advance.
                problems.append(f"third-party module not on the hot-path allowlist: {chain}")
    return problems


def self_test() -> int:
    g = Graph()
    g.add("tracebed.hotpath.retriever", "tracebed.stores.pg.repo")
    g.add("tracebed.hotpath.retriever", "tracebed.adapters.embedding")
    clean = violations_for(g, "tracebed.hotpath.retriever")

    g2 = Graph()
    g2.add("tracebed.hotpath.assembler", "tracebed.workers.distiller")
    g2.add("tracebed.workers.distiller", "openai")
    dirty = violations_for(g2, "tracebed.hotpath.assembler")

    guarded = imports_in_source(
        "from typing import TYPE_CHECKING\n"
        "if TYPE_CHECKING:\n"
        "    import openai\n"
        "else:\n"
        "    import json\n"
        "import hashlib\n",
        "tracebed.hotpath.probe",
    )
    guard_ok = "openai" not in guarded and {"json", "hashlib"} <= guarded

    runtime = imports_in_source(
        "def f():\n    import openai\n    return openai\n", "tracebed.hotpath.probe"
    )
    runtime_ok = "openai" in runtime

    # The allowlist half, proved by mutation: a provider SDK nobody put on the denylist.
    g3 = Graph()
    g3.add("tracebed.hotpath.assembler", "groq")
    unlisted = violations_for(g3, "tracebed.hotpath.assembler")
    unlisted_ok = len(unlisted) == 1 and "not on the hot-path allowlist" in unlisted[0]

    # ... and the stdlib/allowlisted third party it must NOT flag.
    g4 = Graph()
    g4.add("tracebed.hotpath.assembler", "psycopg")
    g4.add("tracebed.hotpath.assembler", "hashlib")
    permitted_ok = not violations_for(g4, "tracebed.hotpath.assembler")

    # `--root` actually selects something (it used to be parsed and ignored).
    src = REPO_ROOT / "src" / PACKAGE
    root_ok = bool(modules_under(src, f"{PACKAGE}.hotpath")) and modules_under(
        src, f"{PACKAGE}.does_not_exist"
    ) == []

    print(f"[{'ok ' if unlisted_ok else 'FAIL'}] unlisted third-party import (groq) rejected")
    print(f"[{'ok ' if permitted_ok else 'FAIL'}] allowlisted + stdlib imports accepted")
    print(f"[{'ok ' if root_ok else 'FAIL'}] --root resolves to real modules")

    ok = (
        not clean
        and len(dirty) == 2
        and guard_ok
        and runtime_ok
        and unlisted_ok
        and permitted_ok
        and root_ok
    )
    print(f"[{'ok ' if not clean else 'FAIL'}] clean graph -> {len(clean)} violations (expected 0)")
    print(f"[{'ok ' if len(dirty) == 2 else 'FAIL'}] dirty graph -> {len(dirty)} violations (expected 2)")
    for d in dirty:
        print(f"        {d}")
    print(f"[{'ok ' if guard_ok else 'FAIL'}] `if TYPE_CHECKING:` import skipped, `else:` branch kept")
    print(f"[{'ok ' if runtime_ok else 'FAIL'}] function-local runtime import still counted")
    return 0 if ok else 1


def modules_under(src_root: Path, root: str) -> list[str]:
    """Every module at or under a dotted root, resolved through the filesystem.

    A root may name a package (`tracebed.hotpath` -> every file under `hotpath/`) or a single
    module (`tracebed.workflow.prefetch` -> just that file). Returns `[]` for a root that does
    not exist, which is how a not-yet-built surface SKIPs rather than failing.
    """
    if not root.startswith(f"{PACKAGE}."):
        return []
    rel = Path(*root.split(".")[1:])
    package_dir = src_root / rel
    if package_dir.is_dir():
        return [module_name(src_root, p) for p in sorted(package_dir.rglob("*.py"))]
    single = src_root / rel.with_suffix(".py")
    if single.is_file():
        return [module_name(src_root, single)]
    return []


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--src", type=Path, default=REPO_ROOT / "src" / PACKAGE)
    ap.add_argument(
        "--root",
        action="append",
        dest="roots",
        help=f"dotted module or package to check; repeatable. Default: {', '.join(DEFAULT_ROOTS)}",
    )
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args(argv)

    if args.self_test:
        return self_test()

    roots: list[str] = list(args.roots) if args.roots else list(DEFAULT_ROOTS)
    graph = build_graph(args.src)
    problems: list[str] = []
    checked: list[str] = []
    skipped: list[str] = []
    for root in roots:
        modules = modules_under(args.src, root)
        if not modules:
            skipped.append(root)
            continue
        checked.append(root)
        # The root's own package is necessarily allowed to import itself; everything else is
        # judged against the same allowlist the hot path is.
        allowed = (*ALLOWED_INTERNAL, root)
        for mod in modules:
            problems.extend(violations_for(graph, mod, allowed_internal=allowed))

    seen: set[str] = set()
    unique = [p for p in problems if not (p in seen or seen.add(p))]
    for p in unique:
        print(p)
    print()
    for root in skipped:
        print(f"PURITY GATE: SKIP — {root} does not exist in this tree")
    if not checked:
        print("PURITY GATE: SKIP — no requested root exists yet")
        return 0
    if unique:
        print(f"PURITY GATE: FAIL — {len(unique)} reachability violation(s)")
        return 1
    print(
        "PURITY GATE: PASS — no generative client, worker or unlisted third-party package "
        f"reachable from: {', '.join(checked)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
