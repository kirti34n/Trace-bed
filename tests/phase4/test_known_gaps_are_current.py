"""Every gate report's "Known gaps" section is a hardcoded tuple. This makes it lie back.

`_KNOWN_GAPS` in each `harness/phaseN_gate.py` is a literal constant derived from nothing and
pinned by no test, so re-running a gate reproduces its text verbatim whether or not the text is
still true. The audit found three entries that had become false — `abstention
.target_abstention_pct` described as absent from `AbstentionConfig` (D-089 added it), and the
blackboard column types plus three `AgentControlRepoPort` methods described as missing (D-087 /
D-088 added them). A reviewer trusts that section *instead of* reading the code, so a stale gap
list is worse than no gap list.

This file pins the claims that CAN be checked mechanically, in BOTH directions:

  * if the claim string is present, the condition it describes must still hold;
  * if the condition no longer holds, the string must be gone.

The second direction is what stops the next stale entry: fixing the underlying defect turns
this red until someone deletes the sentence that says it is broken. Claims that are judgements
("this needs a human decision at the STOP") are deliberately not listed — they cannot be
mechanically falsified and pretending otherwise would be its own dishonesty.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from pathlib import Path

import pytest
from harness import phase1_gate, phase2_gate, phase4_gate

pytestmark = pytest.mark.phase4

REPO_ROOT = Path(__file__).resolve().parents[2]


def _abstention_target_is_absent_from_config() -> bool:
    from tracebed.domain.config import AbstentionConfig

    return "target_abstention_pct" not in AbstentionConfig.model_fields


def _blackboard_columns_are_nullable() -> bool:
    ddl = (REPO_ROOT / "migrations" / "0002_partitioned.sql").read_text(encoding="utf-8")
    body = ddl.split("CREATE TABLE blackboard_entry", 1)[-1].split(";", 1)[0]
    return "value_ref     text NOT NULL" not in body or "author_agent  uuid NOT NULL" not in body


def _agent_control_repo_methods_are_missing() -> bool:
    from tracebed.stores.pg.repo import Repo

    return not all(
        hasattr(Repo, name)
        for name in ("count_proposals_in_run", "count_proposals_in_project_day", "find_proposal_in_run")
    )


def _no_embedding_write_path_exists() -> bool:
    """Was: "`repo.py` never mentions embedding". That predicate went STALE the moment the
    embedding writer landed in a SIBLING module (`stores/pg/learning.py`, D-128) -- it kept
    answering True while the gap it stood for had closed, which is precisely the failure this
    file exists to catch, reproduced inside the catcher.

    Now scans the whole of `stores/pg/` for a statement that assigns the embedding column, so
    the answer tracks the claim rather than one file's contents.
    """
    package = REPO_ROOT / "src" / "tracebed" / "stores" / "pg"
    return not any(
        "SET embedding" in path.read_text(encoding="utf-8") for path in package.glob("*.py")
    )


def _latency_bench_still_seeds_without_embeddings() -> bool:
    """The half of that gap which is still true, and the reason the phase-1 entry was rewritten
    rather than deleted: the bench seeds through `Repo.insert_memory_item`, which writes no
    embedding, so its vector arm measures zero rows however well the writer works.

    Reads the INSERT's own column list rather than searching the whole of `repo.py` for the
    string `"embedding"`. The file-wide search was a proxy that any unrelated mention of the
    column could falsify, and one did: D-133's `_EXPORT_EXCLUDED_COLUMNS` names `embedding` in
    order to keep it OUT of `/export/project`, which flipped this predicate to False and made
    the gate report a still-live gap as fixed. The narrow read cannot be fooled that way --
    only `INSERT INTO memory_item` actually gaining the column moves it.
    """
    bench = (REPO_ROOT / "harness" / "latency_bench.py").read_text(encoding="utf-8")
    repo_src = (REPO_ROOT / "src" / "tracebed" / "stores" / "pg" / "repo.py").read_text(
        encoding="utf-8"
    )
    match = re.search(r"INSERT INTO memory_item\s*\((?P<cols>[^)]*)\)", repo_src)
    assert match is not None, "repo.py no longer contains an `INSERT INTO memory_item` statement"
    insert_columns = {token.strip() for token in match.group("cols").split(",")}
    return "insert_memory_item" in bench and "embedding" not in insert_columns


def _routing_record_table_is_undefined() -> bool:
    migrations = (REPO_ROOT / "migrations").glob("*.sql")
    return not any("routing_record" in p.read_text(encoding="utf-8") for p in migrations)


# (gate module, a substring that appears in that gate's _KNOWN_GAPS iff the claim is made,
#  a predicate that is True iff the claim is still true)
_CLAIMS: tuple[tuple[object, str, Callable[[], bool]], ...] = (
    (phase1_gate, "absent from AbstentionConfig", _abstention_target_is_absent_from_config),
    (phase4_gate, "value_ref/status being NULLable", _blackboard_columns_are_nullable),
    (phase4_gate, "three missing AgentControlRepoPort", _agent_control_repo_methods_are_missing),
    (phase1_gate, "no write path for memory_item.embedding", _no_embedding_write_path_exists),
    (
        phase1_gate,
        "latency_bench.py still seeds through Repo.insert_memory_item",
        _latency_bench_still_seeds_without_embeddings,
    ),
    (phase4_gate, "routing_record table", _routing_record_table_is_undefined),
)


def _gaps(module: object) -> str:
    return " ".join(module._KNOWN_GAPS)


@pytest.mark.parametrize(
    ("module", "claim", "still_true"),
    _CLAIMS,
    ids=[f"{m.__name__.split('.')[-1]}:{c[:32]}" for m, c, _ in _CLAIMS],  # type: ignore[attr-defined]
)
def test_a_declared_gap_is_still_a_real_gap(
    module: object, claim: str, still_true: Callable[[], bool]
) -> None:
    """Direction 1: the report does not describe a problem that has been fixed."""
    if claim in _gaps(module):
        assert still_true(), (
            f"{module.__name__} still declares the known gap {claim!r}, but the code no longer "  # type: ignore[attr-defined]
            "has that defect. Delete the sentence — a stale gap list is trusted instead of the "
            "code it describes."
        )


@pytest.mark.parametrize(
    ("module", "claim", "still_true"),
    _CLAIMS,
    ids=[f"{m.__name__.split('.')[-1]}:{c[:32]}" for m, c, _ in _CLAIMS],  # type: ignore[attr-defined]
)
def test_a_real_gap_is_still_declared(
    module: object, claim: str, still_true: Callable[[], bool]
) -> None:
    """Direction 2: a gap that is still real has not been quietly dropped from the report."""
    if still_true():
        assert claim in _gaps(module), (
            f"{module.__name__} no longer declares {claim!r}, but the defect is still present. "  # type: ignore[attr-defined]
            "A gap that disappears from the report without being fixed is the failure mode this "
            "test exists to prevent."
        )


def test_every_gate_known_gaps_tuple_is_reachable() -> None:
    """The tuples themselves must exist and be non-empty — a gate that quietly stopped
    reporting gaps at all would pass every assertion above vacuously."""
    for module in (phase1_gate, phase2_gate, phase4_gate):
        gaps = module._KNOWN_GAPS
        assert isinstance(gaps, tuple) and gaps, f"{module.__name__} declares no known gaps"
