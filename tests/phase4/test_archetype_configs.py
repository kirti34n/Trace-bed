"""`docs/archetypes/*.toml` — the per-archetype starting configurations documented in
`docs/ARCHETYPE-CONFIGS.md` (PLAN.md §7 Phase 4: "operator docs, per-archetype configs,
adapter-port authoring guide"). Chunk `docs-adapters`.

This is what stops the docs drifting from the code (the chunk's own task description, verbatim):
a `.toml` file that still documents a field `domain.config.TracebedSettings` no longer has is
worse than no file at all, because an operator copying it into a real deployment gets a
config-loading failure with no indication which line is stale.

Every check below is driven by the REAL `TracebedSettings`/`ConfigResolver` shape, imported
from `tracebed.domain.config` — nothing here hardcodes a parallel list of "known fields" that
could itself drift from the settings model. `TestUnknownKeyIsCaught` is the one test that
proves the harness would actually catch drift rather than merely happening to pass today: it
mutates a loaded, valid archetype and asserts the mutation is rejected.

The same principle is applied to the two prose documents this chunk ships, because a doc that
lies is worse than a doc that is missing — it gets trusted:

  * `TestArchetypeDocTableMatchesFiles` parses the markdown tables in
    `docs/ARCHETYPE-CONFIGS.md` and binds every cell to reality: the "Default" column against
    the shipped `TracebedSettings` default, the archetype column against the loaded `.toml`,
    and the row set against the `.toml`'s own override set in both directions.
  * `TestAdapterGuideMatchesPorts` parses the ```python blocks in `docs/ADAPTER-GUIDE.md` and
    compares each documented `Protocol` method against the live source by AST, so a port
    whose signature changes fails CI here rather than misleading an integrator.
  * `TestAtomStubs` does the same for `adapters/atom/stubs.py`, and additionally asserts the
    stubs stay inert (construction raises) — a documentation artifact that can be constructed
    and satisfies a `@runtime_checkable` Protocol is integration code by accident.
"""

from __future__ import annotations

import ast
import inspect
import re
import textwrap
import tomllib
from collections.abc import Mapping
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest
from pydantic import ValidationError

from tracebed.domain.config import (
    OVERRIDABLE_SECTIONS,
    ConfigResolver,
    EffectiveConfig,
    TracebedSettings,
)
from tracebed.domain.errors import ConfigError
from tracebed.domain.ids import AgentTypeId, ProjectId

pytestmark = pytest.mark.phase4

REPO_ROOT: Path = Path(__file__).resolve().parents[2]
ARCHETYPES_DIR: Path = REPO_ROOT / "docs" / "archetypes"
ARCHETYPE_DOC: Path = REPO_ROOT / "docs" / "ARCHETYPE-CONFIGS.md"
ADAPTER_GUIDE: Path = REPO_ROOT / "docs" / "ADAPTER-GUIDE.md"
ATOM_README: Path = REPO_ROOT / "src" / "tracebed" / "adapters" / "atom" / "README.md"

# The three archetypes this chunk ships (docs/ARCHETYPE-CONFIGS.md). Listed explicitly,
# not discovered by glob, so a stray or misnamed file in the directory fails loudly as
# "not one of the documented three" instead of silently being skipped or silently being
# picked up as a fourth undocumented archetype.
ARCHETYPE_NAMES: tuple[str, ...] = ("general_purpose", "bfsi_soc", "high_volume")

# Business-invariant floors an archetype must never undercut, even though nothing in
# `domain/config.py` enforces them at the `pydantic.Field` level (see docs/ARCHETYPE-
# CONFIGS.md's "Invariant floors this test enforces" section for why each one is a floor
# and not merely a default):
_MIN_PROMOTION_DISTINCT_PRINCIPALS = 2   # Sybil resistance: invariant 7's own corroboration
                                          # floor is "2 distinct runs from distinct principals"
_MIN_RETIREMENT_DISTINCT_PRINCIPALS = 2  # K < 2 defeats D-021's entire point: one principal
                                          # could retire a memory unilaterally either way
_MIN_KILLSWITCH_CELL_N = 200             # PLAN.md's own stated statistical floor; undercutting
                                          # it reintroduces "thin data agreeing with itself"
                                          # (workers.killswitch's own docstring)

# The two sections every archetype must fill in for the file to load at all. They are
# deployment placeholders, not tuning, so the "does this override actually differ from the
# default?" and "is this row documented?" checks below exclude them.
_PLACEHOLDER_SECTIONS: frozenset[str] = frozenset({"storage", "embedding"})


def _archetype_path(name: str) -> Path:
    path = ARCHETYPES_DIR / f"{name}.toml"
    assert path.is_file(), f"{path} is listed in ARCHETYPE_NAMES but does not exist"
    return path


def _load_toml(path: Path) -> dict[str, Any]:
    with path.open("rb") as fh:
        return tomllib.load(fh)


def _build_settings(raw: Mapping[str, Any]) -> TracebedSettings:
    """Constructs `TracebedSettings` from a TOML-parsed mapping with the ambient `TB_`
    environment suppressed, exactly like `tests/conftest.py`'s `settings` fixture — an
    archetype's meaning must not depend on which environment variables happen to be set on
    whatever machine runs this test.

    `extra="forbid"` at every nested level (`domain.config._StrictModel`) is what makes an
    unknown or stale key a `ValidationError` here, not a silently-ignored dict entry — this
    function does no additional key-existence bookkeeping of its own because that check
    already lives in the settings model this repository ships, and duplicating it here would
    be exactly the second copy that could itself drift.
    """
    import os

    saved = {k: v for k, v in os.environ.items() if k.startswith("TB_")}
    for k in saved:
        del os.environ[k]
    try:
        return TracebedSettings(**raw)
    finally:
        os.environ.update(saved)


class _NoOverridesConfigStore:
    """A `ConfigStorePort` that never overrides anything.

    Used to resolve each archetype's `TracebedSettings` all the way through
    `ConfigResolver.effective()` — the same path a real project's first request takes before
    any `project_config`/`agent_type_config` row exists — so this suite exercises the full
    resolution path an operator's deployment actually uses, not merely construction of the
    process-defaults layer in isolation.
    """

    def get_project_config(self, project_id: ProjectId) -> Mapping[str, object]:
        return {}

    def get_agent_type_config(
        self, project_id: ProjectId, agent_type_id: AgentTypeId
    ) -> Mapping[str, object]:
        return {}

    def get_killswitch_overlay(
        self, project_id: ProjectId, agent_type_id: AgentTypeId | None
    ) -> Mapping[str, bool]:
        return {}


def _resolve_effective(settings: TracebedSettings) -> EffectiveConfig:
    resolver = ConfigResolver(settings, _NoOverridesConfigStore())
    project_id = ProjectId(str(uuid4()))
    agent_type_id = AgentTypeId(str(uuid4()))
    return resolver.effective(project_id, agent_type_id)


def _shipped_defaults() -> TracebedSettings:
    """`general_purpose` IS the shipped defaults by definition (and
    `test_general_purpose_only_overrides_deployment_placeholders` holds it to that), so it is
    the honest source for "what does this field default to" — reading `config.py`'s literals a
    second time here would be the parallel copy this module refuses to keep."""
    return _build_settings(_load_toml(_archetype_path("general_purpose")))


def _dotted(settings: TracebedSettings, path: str) -> object:
    """`"retrieval.total_budget_ms"` -> the live value. Raises `AttributeError` naming the
    exact missing component, which is what makes a stale doc row fail readably."""
    current: object = settings
    for part in path.split("."):
        current = getattr(current, part)
    return current


def _override_paths(raw: Mapping[str, Any]) -> set[str]:
    """Every `section.field` an archetype actually sets, minus the deployment placeholders."""
    return {
        f"{section}.{field}"
        for section, body in raw.items()
        if section not in _PLACEHOLDER_SECTIONS
        for field in body
    }


_TABLE_ROW = re.compile(r"^\|(?P<cells>.+)\|\s*$")


def _parse_doc_tables(text: str) -> dict[str, dict[str, tuple[str, str]]]:
    """`docs/ARCHETYPE-CONFIGS.md`'s per-archetype tables -> {archetype: {field: (default,
    value)}}.

    Deliberately dumb about markdown: a row is a line starting and ending with `|`, inside a
    `### \\`name\\`` section. Anything the parser cannot make sense of raises rather than being
    skipped — a table row silently dropped by the parser is a doc row nobody is checking, and
    that is precisely the state this test exists to make impossible.
    """
    tables: dict[str, dict[str, tuple[str, str]]] = {}
    current: str | None = None
    for line in text.splitlines():
        heading = re.match(r"^### `(?P<name>[a-z_]+)`", line)
        if heading:
            current = heading.group("name")
            tables.setdefault(current, {})
            continue
        if current is None:
            continue
        match = _TABLE_ROW.match(line)
        if not match:
            continue
        cells = [c.strip() for c in match.group("cells").split("|")]
        if len(cells) < 3 or set(cells[0]) <= {"-", ":"}:
            continue
        field = cells[0].strip("`")
        if field in {"Field", ""}:
            continue
        tables[current][field] = (cells[1].strip("`"), cells[2].strip("`"))
    return tables


def _sig_from_ast(node: ast.FunctionDef) -> str:
    returns = ast.unparse(node.returns) if node.returns is not None else "<none>"
    return f"({ast.unparse(node.args)}) -> {returns}"


def _signatures_of_source(source: str, class_name: str) -> dict[str, str]:
    """{method name: normalised signature} for one class in a source string."""
    module = ast.parse(textwrap.dedent(source))
    for node in ast.walk(module):
        if isinstance(node, ast.ClassDef) and node.name == class_name:
            return {
                item.name: _sig_from_ast(item)
                for item in node.body
                if isinstance(item, ast.FunctionDef)
            }
    raise AssertionError(f"class {class_name} not found in the parsed source")


def _live_signatures(cls: type) -> dict[str, str]:
    return _signatures_of_source(inspect.getsource(cls), cls.__name__)


def _python_blocks(text: str) -> list[str]:
    return re.findall(r"^```python\n(.*?)^```", text, flags=re.MULTILINE | re.DOTALL)


@pytest.fixture(params=ARCHETYPE_NAMES)
def archetype_name(request: pytest.FixtureRequest) -> str:
    return str(request.param)


@pytest.fixture
def archetype_raw(archetype_name: str) -> dict[str, Any]:
    return _load_toml(_archetype_path(archetype_name))


@pytest.fixture
def archetype_settings(archetype_raw: dict[str, Any]) -> TracebedSettings:
    return _build_settings(archetype_raw)


class TestEveryArchetypeLoadsAndValidates:
    """The chunk's headline requirement: every `.toml` LOADS into `TracebedSettings` and
    validates, all the way through `ConfigResolver.effective()`."""

    def test_toml_parses(self, archetype_name: str) -> None:
        raw = _load_toml(_archetype_path(archetype_name))
        assert isinstance(raw, dict)
        assert raw, f"{archetype_name}.toml parsed to an empty mapping"

    def test_constructs_tracebed_settings(self, archetype_raw: dict[str, Any]) -> None:
        # A ValidationError here IS the failure this whole test file exists to catch: a
        # documented field that no longer exists in the settings model, or a value that no
        # longer satisfies a Field constraint (e.g. `retrieval.total_budget_ms` must be
        # `ge=1`). Let it propagate with pydantic's own message rather than swallowing it —
        # that message names the exact offending path.
        settings = _build_settings(archetype_raw)
        assert isinstance(settings, TracebedSettings)

    def test_resolves_through_config_resolver(self, archetype_settings: TracebedSettings) -> None:
        # Exercises EffectiveConfig's cross-section validator too (scoring.q_start must sit
        # strictly above lifecycle.archive_floor) — a ConfigError here means this archetype
        # would fail on a real deployment's very first request, not merely at process start.
        effective = _resolve_effective(archetype_settings)
        assert isinstance(effective, EffectiveConfig)

    def test_every_overridable_section_present_in_effective_config(
        self, archetype_settings: TracebedSettings
    ) -> None:
        # OVERRIDABLE_SECTIONS is read from the settings model, not hardcoded here — if a
        # future chunk adds a new tunable section, this loop covers it for free.
        effective = _resolve_effective(archetype_settings)
        for section in OVERRIDABLE_SECTIONS:
            assert getattr(effective, section) is not None


class TestUnknownKeyIsCaught:
    """Proves the harness above would actually catch doc/code drift, not merely that today's
    three files happen to satisfy today's settings model.

    Takes each archetype's OWN parsed content, injects one field no `TracebedSettings`
    section has ever declared, and asserts construction is rejected. If this test ever
    started passing with the injected key silently accepted, `_StrictModel.model_config`
    would have quietly lost `extra="forbid"` somewhere in `domain/config.py`, and every other
    test in this file would still be green while genuinely stale archetype files sailed
    through unnoticed — which is exactly the failure mode this task exists to prevent.
    """

    def test_stale_field_in_existing_section_is_rejected(
        self, archetype_raw: dict[str, Any]
    ) -> None:
        mutated = dict(archetype_raw)
        mutated["retrieval"] = {
            **mutated.get("retrieval", {}),
            "this_field_was_removed_in_a_refactor": 123,
        }
        with pytest.raises(ValidationError):
            _build_settings(mutated)

    def test_unknown_top_level_section_is_rejected(self, archetype_raw: dict[str, Any]) -> None:
        mutated = dict(archetype_raw)
        mutated["not_a_real_section"] = {"anything": True}
        with pytest.raises(ValidationError):
            _build_settings(mutated)


class TestInvariantFloors:
    """`docs/ARCHETYPE-CONFIGS.md`'s "invariant floors" — business-level minimums that no
    archetype may undercut, even where `domain/config.py` itself declares no `Field`
    constraint (a gap that config.py's own docstrings report rather than paper over — see
    e.g. `ScoringConfig.updates_per_memory_per_day`'s "deliberately no ceiling" note). These
    assertions exist precisely because pydantic construction succeeding is NOT sufficient
    proof an archetype is sane; it only proves the archetype is well-typed.
    """

    def test_promotion_distinct_principals_floor(self, archetype_settings: TracebedSettings) -> None:
        assert (
            archetype_settings.promotion.min_distinct_principals
            >= _MIN_PROMOTION_DISTINCT_PRINCIPALS
        )

    def test_retirement_distinct_principals_floor(self, archetype_settings: TracebedSettings) -> None:
        assert (
            archetype_settings.retirement.min_distinct_principals
            >= _MIN_RETIREMENT_DISTINCT_PRINCIPALS
        )

    def test_promotion_requires_at_least_one_outcome(
        self, archetype_settings: TracebedSettings
    ) -> None:
        assert archetype_settings.promotion.min_outcomes >= 1
        assert archetype_settings.promotion.failure_lesson_outcomes >= 1

    def test_retirement_requires_at_least_one_scored_use(
        self, archetype_settings: TracebedSettings
    ) -> None:
        assert archetype_settings.retirement.min_scored_uses >= 1

    def test_killswitch_min_cell_n_floor(self, archetype_settings: TracebedSettings) -> None:
        assert archetype_settings.killswitch.min_cell_n >= _MIN_KILLSWITCH_CELL_N

    def test_the_token_budget_sums_close(self, archetype_settings: TracebedSettings) -> None:
        """`budget` is five numbers with two arithmetic relations between them, and
        `domain/config.py` enforces neither.

        `hotpath.assembler` (and `workers.prefix_builder`, identically) treats
        `total_tokens` as the OUTER bound and clamps every pool into what is left --
        `_clamp(budget.static_prefix, budget.total_tokens)`, then
        `_clamp(budget.static_prefix_lessons, static_pool - prefs_used)`. So an
        over-subscribed split never raises: it silently makes the per-slot caps an operator
        reads in `docs/ARCHETYPE-CONFIGS.md` unreachable, and the shortfall lands on whichever
        pool is filled last (lessons, then the dynamic block) rather than being shared.

        Asserted as `<=` rather than `==` because under-subscription is merely wasteful
        headroom, while over-subscription is a documented cap the code cannot honour.
        """
        budget = archetype_settings.budget
        assert budget.static_prefix_prefs + budget.static_prefix_lessons <= budget.static_prefix
        assert budget.static_prefix + budget.dynamic <= budget.total_tokens

    def test_derived_keep_versions_is_never_lowered(
        self, archetype_settings: TracebedSettings
    ) -> None:
        """`derived.keep_versions` looks like a storage-retention knob and is not one.

        `workers.derived_state` seeds the divergence alarm's SLOW reference from the earliest
        still-retained version (D-075(a)/(d)) -- so retention IS the reach of the only
        watchdog that catches a patient baseline-poisoning walk, and its own module docstring
        says the seeded history "reaches back `keep_versions` updates, not necessarily 30
        days". Lowering it shortens that window with nothing anywhere reporting the reduced
        coverage: `DerivedConfig`'s `ge=1` constraint stops only the total-disablement case.

        `high_volume.toml` really did ship `keep_versions = 10`, justified as trading away
        "debugging depth" alone -- at the archetype where a key updates most often per day,
        i.e. where the same version count buys the least wall-clock history. This assertion is
        what makes that unrepeatable.
        """
        assert (
            archetype_settings.derived.keep_versions >= _shipped_defaults().derived.keep_versions
        )

    def test_q_start_strictly_above_archive_floor(
        self, archetype_settings: TracebedSettings
    ) -> None:
        # Restated directly (in addition to being exercised indirectly through
        # `ConfigResolver.effective()` above) so a regression here fails with a message
        # naming exactly this pair, not pydantic's cross-section validator's generic text.
        assert archetype_settings.scoring.q_start > archetype_settings.lifecycle.archive_floor

    def test_config_resolution_never_raises_config_error(
        self, archetype_settings: TracebedSettings
    ) -> None:
        try:
            _resolve_effective(archetype_settings)
        except ConfigError as exc:  # pragma: no cover - failure path, not the happy path
            pytest.fail(f"archetype fails ConfigResolver.effective(): {exc}")


class TestArchetypeSpecificShape:
    """Ties each archetype's documented intent (docs/ARCHETYPE-CONFIGS.md) to its actual
    field values, relative to the shipped `TracebedSettings` defaults — proving
    `bfsi_soc.toml` really is more conservative than the defaults, and `high_volume.toml`
    really is tuned for throughput, rather than merely being well-typed."""

    @pytest.fixture
    def default_settings(self) -> TracebedSettings:
        return _build_settings(_load_toml(_archetype_path("general_purpose")))

    def test_general_purpose_only_overrides_deployment_placeholders(self) -> None:
        raw = _load_toml(_archetype_path("general_purpose"))
        # general_purpose IS the shipped defaults (docs/ARCHETYPE-CONFIGS.md) — it must not
        # silently grow a tunable-section override that would then diverge from
        # `domain/config.py`'s defaults without a corresponding doc explaining why.
        assert set(raw) <= {"storage", "embedding"}

    def test_bfsi_soc_is_more_conservative_than_default(
        self, default_settings: TracebedSettings
    ) -> None:
        bfsi = _build_settings(_load_toml(_archetype_path("bfsi_soc")))
        # High abstention: a stricter (higher) similarity bar means fewer injections.
        assert bfsi.abstention.cos_threshold > default_settings.abstention.cos_threshold
        # Strict promotion: more corroboration required before candidate -> validated.
        assert bfsi.promotion.min_outcomes > default_settings.promotion.min_outcomes
        assert (
            bfsi.promotion.min_distinct_principals
            > default_settings.promotion.min_distinct_principals
        )
        # Low spend: a materially lower daily cap than the general-purpose default.
        assert bfsi.spend.daily_llm_cap_usd < default_settings.spend.daily_llm_cap_usd

    def test_high_volume_is_tuned_for_throughput(self, default_settings: TracebedSettings) -> None:
        hv = _build_settings(_load_toml(_archetype_path("high_volume")))
        # Tighter budgets: retrieval must degrade to cheaper rungs sooner at this volume.
        assert hv.retrieval.total_budget_ms < default_settings.retrieval.total_budget_ms
        assert hv.retrieval.embed_timeout_ms < default_settings.retrieval.embed_timeout_ms
        # Bigger batches: ingest amortises fixed per-claim overhead across more items.
        assert hv.queue.batch_size > default_settings.queue.batch_size
        # More aggressive sweeps: shorter quarantine/candidate windows, faster idle decay.
        assert hv.lifecycle.quarantine_ttl_days < default_settings.lifecycle.quarantine_ttl_days
        assert hv.lifecycle.candidate_ttl_days < default_settings.lifecycle.candidate_ttl_days
        assert (
            hv.lifecycle.decay_pct_per_idle_week > default_settings.lifecycle.decay_pct_per_idle_week
        )


class TestSettingsSourcePrecedence:
    """Binds `docs/ARCHETYPE-CONFIGS.md`'s "Read this before deciding how to supply them" to
    the installed `pydantic-settings`.

    The document previously claimed the inverse ("env vars are read on top of whatever this
    file supplies"), which is false: `init_settings` outranks `env_settings`, so a placeholder
    left in the file wins over the environment variable an operator set instead. For
    `pg_dsn` that fails loudly; for `embedding.model_version` it fails SILENTLY, stamping
    `"CHANGEME"` onto `memory_item.embedding_model_id`/`embedding_model_version` for every row
    embedded under it -- recoverable only through the explicit re-embedding migration PLAN.md
    §10 describes.
    """

    def test_a_key_present_in_the_file_wins_over_the_environment(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("TB_STORAGE__PG_DSN", "postgresql://from-env/from-env")
        monkeypatch.setenv("TB_EMBEDDING__MODEL_VERSION", "from-env")
        raw = _load_toml(_archetype_path("general_purpose"))

        settings = TracebedSettings(**raw)

        assert settings.storage.pg_dsn == raw["storage"]["pg_dsn"]
        assert settings.embedding.model_version == raw["embedding"]["model_version"]

    def test_a_key_absent_from_the_file_is_supplied_by_the_environment(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # The document's option 2: delete the block, set the variable. Asserted so that the
        # advice cannot become wrong without this failing.
        monkeypatch.setenv("TB_STORAGE__PG_DSN", "postgresql://from-env/from-env")
        monkeypatch.setenv("TB_EMBEDDING__MODEL_VERSION", "from-env")
        raw = {
            k: v
            for k, v in _load_toml(_archetype_path("general_purpose")).items()
            if k not in _PLACEHOLDER_SECTIONS
        }

        settings = TracebedSettings(**raw)

        assert settings.storage.pg_dsn == "postgresql://from-env/from-env"
        assert settings.embedding.model_version == "from-env"


class TestArchetypeDocTableMatchesFiles:
    """`docs/ARCHETYPE-CONFIGS.md`'s tables, checked cell by cell against reality.

    A table that has drifted from the `.toml` beside it is worse than no table: an operator
    reads the table, deploys the file, and gets a third thing. Every direction is covered --
    a documented row that no longer matches the file, a documented default that no longer
    matches `config.py`, a file override with no row, and a row naming a field the settings
    model no longer has (which surfaces as `AttributeError` from `_dotted`).
    """

    @staticmethod
    @pytest.fixture(scope="class")
    def tables() -> dict[str, dict[str, tuple[str, str]]]:
        return _parse_doc_tables(ARCHETYPE_DOC.read_text(encoding="utf-8"))

    @pytest.mark.parametrize("name", ["bfsi_soc", "high_volume"])
    def test_documented_default_column_matches_the_shipped_default(
        self, tables: dict[str, dict[str, tuple[str, str]]], name: str
    ) -> None:
        defaults = _shipped_defaults()
        rows = tables[name]
        assert rows, f"no table parsed for archetype {name}"
        for field, (documented_default, _) in rows.items():
            assert float(documented_default) == float(_dotted(defaults, field)), (  # type: ignore[arg-type]
                f"{name} table: `{field}` documents default {documented_default}, "
                f"config.py ships {_dotted(defaults, field)}"
            )

    @pytest.mark.parametrize("name", ["bfsi_soc", "high_volume"])
    def test_documented_archetype_column_matches_the_toml(
        self, tables: dict[str, dict[str, tuple[str, str]]], name: str
    ) -> None:
        settings = _build_settings(_load_toml(_archetype_path(name)))
        for field, (_, documented_value) in tables[name].items():
            assert float(documented_value) == float(_dotted(settings, field)), (  # type: ignore[arg-type]
                f"{name} table: `{field}` documents {documented_value}, "
                f"{name}.toml sets {_dotted(settings, field)}"
            )

    @pytest.mark.parametrize("name", ["bfsi_soc", "high_volume"])
    def test_every_override_is_documented_and_every_documented_row_is_overridden(
        self, tables: dict[str, dict[str, tuple[str, str]]], name: str
    ) -> None:
        assert _override_paths(_load_toml(_archetype_path(name))) == set(tables[name])


class TestArchetypeOverridesActuallyDiffer:
    """Each archetype file states, in its own header, that every field it sets differs from
    the shipped default -- and gives the reason: a field restated at its default value
    silently pins the old number the day the default moves. `high_volume.toml` really did
    carry `scoring.updates_per_memory_per_day = 1` under that header."""

    @pytest.mark.parametrize("name", ["bfsi_soc", "high_volume"])
    def test_no_override_equals_the_shipped_default(self, name: str) -> None:
        defaults = _shipped_defaults()
        settings = _build_settings(_load_toml(_archetype_path(name)))
        for field in _override_paths(_load_toml(_archetype_path(name))):
            assert _dotted(settings, field) != _dotted(defaults, field), (
                f"{name}.toml sets `{field}` to the shipped default; remove the line "
                f"(a restated default pins the old value when the default moves)"
            )


class TestArchetypeDirectoryIsExactlyTheDocumentedThree:
    """Guards the inverse drift direction: a file added to `docs/archetypes/` that nobody
    added to `ARCHETYPE_NAMES` (and, per `docs/ARCHETYPE-CONFIGS.md`, to the table there)
    would otherwise never be exercised by this suite at all."""

    def test_directory_contains_exactly_the_documented_archetypes(self) -> None:
        on_disk = {p.stem for p in ARCHETYPES_DIR.glob("*.toml")}
        assert on_disk == set(ARCHETYPE_NAMES)


# --------------------------------------------------------------------------- #
# docs/ADAPTER-GUIDE.md and adapters/atom/ — the other half of this chunk.
#
# Both documents quote code. A quoted signature that has drifted from the source is the
# worst kind of documentation defect, because the integrator who trusts it writes an adapter
# that type-checks against a shape nothing calls.
# --------------------------------------------------------------------------- #

# stub class -> the ONE `adapters.ports` Protocol it claims to satisfy. Hardcoded here on
# purpose: this is the mapping `adapters/atom/README.md` publishes to an integrator, so a
# test that derived it from the stubs themselves could only ever prove the stubs agree with
# themselves. `test_readme_table_matches_the_exported_stubs` binds the README to this table.
_ATOM_STUB_PORTS: dict[str, str] = {
    "AtomKeycloakPrincipalPort": "PrincipalPort",
    "AtomGateLLMProvider": "LLMProviderPort",
    "AtomGateEmbeddingProvider": "EmbeddingPort",
    "AtomBuilderInvalidationSource": "InvalidationPort",
    "AtomWorkflowFeedbackAdapter": "FeedbackPort",
    "AtomAgentArmorFeedbackAdapter": "FeedbackPort",
    "AtomPolicyExecutorVerdictAdapter": "FeedbackPort",
    "AtomMinioAuditSink": "AuditSinkPort",
}


class TestAdapterGuideMatchesPorts:
    """Every ```python block in `docs/ADAPTER-GUIDE.md` is compared to the live source.

    The guide's own "How to read this document" promises the protocol blocks are "copied
    verbatim ... not paraphrased". This is that promise, executed: method name sets must match
    exactly (an omitted method is the sneakier drift -- it makes a partial implementation look
    complete), and each signature is compared after AST normalisation so whitespace and line
    wrapping are not what this test is about.
    """

    @staticmethod
    @pytest.fixture(scope="class")
    def documented() -> dict[str, dict[str, str]]:
        blocks = _python_blocks(ADAPTER_GUIDE.read_text(encoding="utf-8"))
        assert blocks, "no ```python blocks found in docs/ADAPTER-GUIDE.md"
        out: dict[str, dict[str, str]] = {}
        for block in blocks:
            for node in ast.parse(textwrap.dedent(block)).body:
                if isinstance(node, ast.ClassDef):
                    out[node.name] = {
                        item.name: _sig_from_ast(item)
                        for item in node.body
                        if isinstance(item, ast.FunctionDef)
                    }
        return out

    def test_every_port_in_ports_dunder_all_is_documented(
        self, documented: dict[str, dict[str, str]]
    ) -> None:
        from tracebed.adapters import ports

        # The guide is the host-implements contract, so it covers the eight PLAN.md §3 ports.
        # `QueueProducerPort`/`QueueConsumerPort`/`TelemetryPort` are internal seams, not
        # host-implements ports, and are deliberately out of scope -- named here rather than
        # silently subtracted.
        internal = {"QueueProducerPort", "QueueConsumerPort", "TelemetryPort"}
        assert set(ports.__all__) - internal == set(documented)

    def test_documented_signatures_match_the_live_protocols(
        self, documented: dict[str, dict[str, str]]
    ) -> None:
        from tracebed.adapters import ports

        for class_name, methods in documented.items():
            live = _live_signatures(getattr(ports, class_name))
            assert set(methods) == set(live), (
                f"ADAPTER-GUIDE.md's `{class_name}` block lists {sorted(methods)}, "
                f"the Protocol declares {sorted(live)}"
            )
            for method, signature in methods.items():
                assert signature == live[method], (
                    f"ADAPTER-GUIDE.md's `{class_name}.{method}` is documented as "
                    f"{signature}, source says {live[method]}"
                )


class TestAtomStubs:
    """`adapters/atom/` is documentation with type signatures attached (PLAN.md §4:
    "documented interface stubs ONLY -- the human writes the integration").

    Two properties have to hold for that to stay true, and neither is self-evident from
    reading the file: nothing is constructible, and every declared method still matches the
    port it documents. The first was genuinely broken -- the three `FeedbackPort` stubs
    declared no `__init__`, so they inherited `object.__init__`, constructed silently, and
    (because `FeedbackPort` is `@runtime_checkable`) passed an `isinstance` wiring check,
    deferring the failure to the first real outcome event.
    """

    @staticmethod
    @pytest.fixture(scope="class")
    def exported() -> dict[str, type]:
        from tracebed.adapters import atom

        return {name: getattr(atom, name) for name in atom.__all__}

    def test_the_export_set_is_exactly_the_documented_mapping(
        self, exported: dict[str, type]
    ) -> None:
        assert set(exported) == set(_ATOM_STUB_PORTS)

    def test_every_stub_refuses_construction(self, exported: dict[str, type]) -> None:
        for name, cls in exported.items():
            signature = inspect.signature(cls.__init__)
            kwargs = {
                param.name: "x"
                for param in signature.parameters.values()
                if param.name != "self" and param.kind is not inspect.Parameter.VAR_KEYWORD
            }
            with pytest.raises(NotImplementedError) as excinfo:
                cls(**kwargs)
            # The message must name the port, or an integrator reading a traceback learns
            # nothing about what to implement instead.
            assert _ATOM_STUB_PORTS[name] in str(excinfo.value)
            assert "ADAPTER-GUIDE.md" in str(excinfo.value)

    def test_every_stub_declares_its_ports_methods_with_the_ports_signature(
        self, exported: dict[str, type]
    ) -> None:
        from tracebed.adapters import ports

        for name, cls in exported.items():
            port = getattr(ports, _ATOM_STUB_PORTS[name])
            stub_sigs = _live_signatures(cls)
            for method, signature in _live_signatures(port).items():
                assert method in stub_sigs, f"{name} does not declare {port.__name__}.{method}"
                assert stub_sigs[method] == signature, (
                    f"{name}.{method} is {stub_sigs[method]}, "
                    f"{port.__name__}.{method} is {signature}"
                )

    def test_readme_table_matches_the_exported_stubs(self, exported: dict[str, type]) -> None:
        """The README's "What is stubbed, and what is not" table is what an integrator reads
        to decide which port they have to write themselves.

        Parsed as a TABLE, not by scanning the whole file for backticked `Atom*` names: the
        first version of this assertion did the latter and survived its own mutation, because
        renaming a row's class still left the correct name mentioned in the prose two sections
        down. The mapping column is checked too, so a row cannot point at the wrong port.
        """
        rows: dict[str, str] = {}
        for line in ATOM_README.read_text(encoding="utf-8").splitlines():
            match = _TABLE_ROW.match(line)
            if not match:
                continue
            cells = [c.strip().strip("`") for c in match.group("cells").split("|")]
            if len(cells) != 3 or cells[0] in {"Atom component", ""} or set(cells[0]) <= {"-"}:
                continue
            rows[cells[2]] = cells[1]
        assert set(rows) == set(exported)
        # "`FeedbackPort` (downstream)" / "`FeedbackPort` (verdict)": the Protocol is the
        # first token, and the qualifier after it is the adapter CLASS, not a second port.
        assert {
            stub: port.split()[0].strip("`") for stub, port in rows.items()
        } == _ATOM_STUB_PORTS

    def test_the_audit_sink_gap_is_still_real(self) -> None:
        """`docs/ADAPTER-GUIDE.md` and `adapters/atom/README.md` both state, as a reported
        contract gap, that no concrete `AuditSinkPort` implementation exists anywhere in
        `src/tracebed/`. That claim ages: the day someone writes one, both documents become
        wrong in the direction that matters (an integrator re-implements a port that ships).

        So the claim is pinned. A failure here is not a defect in the sink -- it means the gap
        closed and the two documents need updating.
        """
        implementors: list[str] = []
        for path in (REPO_ROOT / "src" / "tracebed").rglob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if not isinstance(node, ast.ClassDef):
                    continue
                bases = {ast.unparse(base) for base in node.bases}
                if "Protocol" in bases:  # the port itself, or a locally-declared twin
                    continue
                if path.parts[-2:] == ("atom", "stubs.py"):  # the documented stub
                    continue
                if any(
                    isinstance(item, ast.FunctionDef) and item.name == "emit"
                    for item in node.body
                ):
                    implementors.append(f"{path.relative_to(REPO_ROOT)}::{node.name}")
        assert not implementors, (
            "an AuditSinkPort-shaped implementation now exists "
            f"({implementors}); update docs/ADAPTER-GUIDE.md and adapters/atom/README.md, "
            "both of which still report this as an open contract gap"
        )
