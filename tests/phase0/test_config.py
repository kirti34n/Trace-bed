"""Typed config + resolver + error hierarchy (PHASE-0 Task 2).

CONTRACT NOTE (contract_gap): PHASE0-CONTRACT.md §13.2 assigns three
separate files to chunk domain-config — `test_config.py`,
`test_config_resolver.py`, `test_errors.py` — but this task's explicit FILE
LIST names only `test_config.py` and `test_clock.py`. Per hard rule 6
("write ONLY the files in your file list"), the resolver-precedence tests
and the error-hierarchy shape tests are folded into this file's
`TestConfigResolver` and `TestErrorHierarchy` classes rather than split into
their own files. If strict file-per-file separation matters at merge time,
these two classes are the pre-split content for
`test_config_resolver.py` / `test_errors.py`.
"""

from __future__ import annotations

import copy
import inspect
import os
from typing import TYPE_CHECKING, Any, cast

import pytest
from pydantic import ValidationError

from tracebed.domain import errors as errors_module
from tracebed.domain.config import (
    OVERRIDABLE_SECTIONS,
    ConfigResolver,
    ConfigStorePort,
    EffectiveConfig,
    EmbeddingConfig,
    StorageConfig,
    TracebedSettings,
)
from tracebed.domain.errors import (
    ConfigError,
    GuardNotSatisfied,
    IllegalTransition,
    NotFound,
    ScanRejected,
    TracebedError,
)
from tracebed.domain.ids import AgentTypeId, ProjectId

if TYPE_CHECKING:
    # errors.py annotates the two state-machine exceptions with `Status` under
    # TYPE_CHECKING only (§3.1: errors.py must never import state_machine).
    # Mirror that here so these tests stay type-checked against the real enum
    # without importing another chunk's module at runtime — `cast` is a no-op
    # at runtime, so this file still collects if state_machine.py is absent.
    from tracebed.domain.state_machine import Status


def _status(name: str) -> Status:
    return cast("Status", name)


REQUIRED_ENV = {
    "TB_STORAGE__PG_DSN": "postgresql://user:pass@localhost:5432/tracebed",
    "TB_EMBEDDING__MODEL_VERSION": "2026-01-01",
}

# `workers` joined this list with the scheduler wiring (D-128): one `Scheduler` serves every
# project in the process, so a per-project sweep cadence is a knob that silently does nothing.
DEPLOYMENT_SECTIONS = ("api", "dashboard", "auth", "storage", "embedding", "llm", "workers")
"""Sections §3.4 declares deployment-level: no project/agent_type override may reach them."""


@pytest.fixture(autouse=True)
def _isolated_tb_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Strip every ambient `TB_` env var before each test in this module.

    `TracebedSettings()` reads the real environment. Without this, a runner
    that exports `TB_API__PORT` turns "defaults load with only the two
    required env vars" into a claim about that machine, and the assertions
    below would be measuring the shell rather than the code. monkeypatch
    (rather than a raw `os.environ` edit) so restoration is pytest's problem
    and cannot be skipped by a failing assertion.
    """
    for key in [k for k in os.environ if k.startswith("TB_")]:
        monkeypatch.delenv(key, raising=False)


def _set_required_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for key, value in REQUIRED_ENV.items():
        monkeypatch.setenv(key, value)


# --------------------------------------------------------------------------- #
# TracebedSettings: defaults, env override, unknown-key rejection.
# --------------------------------------------------------------------------- #


class TestTracebedSettingsDefaults:
    """`extra="forbid"` rejection is proved at the two levels pydantic-settings
    can actually observe it: a nested-model key that IS read from the
    environment (`TB_STORAGE__NOT_A_REAL_FIELD`), and direct kwarg
    construction. A wholly unrelated top-level env var under the `TB_`
    prefix (e.g. `TB_MASTER_KEY`) cannot be caught this way —
    pydantic-settings' `EnvSettingsSource` walks the model's *declared*
    fields and looks up each one's env var; it never enumerates the actual
    environment, so an env var with no matching field is simply never read,
    not "extra" data the model ever sees. That is not merely a limitation:
    §3.4/C-02/C-15 *require* `TB_MASTER_KEY`, `TB_ADMIN_KEY`,
    `TB_HOLDOUT_SALT`, `TB_LLM_API_KEY` and the S3 key vars to live in the
    same `TB_` namespace while deliberately not being settings fields, so
    the ignore behaviour is pinned by a test below."""

    @pytest.mark.phase0
    def test_defaults_load_with_only_the_two_required_env_vars(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _set_required_env(monkeypatch)

        settings = TracebedSettings()

        assert settings.storage.pg_dsn == REQUIRED_ENV["TB_STORAGE__PG_DSN"]
        assert settings.embedding.model_version == REQUIRED_ENV["TB_EMBEDDING__MODEL_VERSION"]

        # Spot-check defaults across sections per PHASE-0.md Task 2 / contract §3.4.
        assert settings.api.port == 8110
        assert settings.api.workers == 2
        assert settings.dashboard.port == 8111
        assert settings.auth.api_key_mode is True
        assert settings.auth.admin_key_env == "TB_ADMIN_KEY"
        assert settings.storage.valkey_url == "valkey://localhost:6379/0"
        assert settings.storage.tracestore.driver == "fs"
        assert settings.embedding.model_id == "gemini-embedding-2"
        assert settings.embedding.dim == 768
        assert settings.llm.judge_model == "gemini-3.1-pro"
        assert settings.retrieval.total_budget_ms == 300
        assert settings.retrieval.rrf_k == 60
        assert settings.abstention.cos_threshold == 0.60
        assert settings.score.w_sim == 0.40
        assert settings.budget.total_tokens == 1200
        assert settings.budget.slot_caps == {
            "fact": 250,
            "exemplar": 150,
            "pitfall": 100,
            "candidate_note": 100,
            "jit_lesson": 150,
        }
        assert settings.scoring.adapter_weights == {
            "verdict": 1.0,
            "correction_adapter": 0.8,
            "downstream": 0.3,
            "implicit": 0.0,
        }
        assert settings.promotion.min_outcomes == 2
        assert settings.retirement.min_distinct_principals == 3
        assert settings.lifecycle.quarantine_ttl_days == 30
        assert settings.derived.baseline_max_delta_pct == 10
        assert settings.proposals.per_run_cap == 2
        assert settings.tier_a.candidate_cap_per_run == 1
        assert settings.killswitch.holdout_pct == 5
        assert settings.spend.daily_llm_cap_usd == 25.0
        assert settings.cache.ttl_class == {"intel": "24h", "registry": "14d"}
        assert settings.session.idle_ttl_min == 60
        assert settings.queue.lease_seconds == 30
        assert settings.queue.max_attempts == 5
        assert settings.queue.batch_size == 100

    @pytest.mark.phase0
    def test_missing_required_storage_env_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("TB_STORAGE__PG_DSN", raising=False)
        monkeypatch.setenv("TB_EMBEDDING__MODEL_VERSION", "2026-01-01")

        with pytest.raises(ValidationError):
            TracebedSettings()

    @pytest.mark.phase0
    def test_missing_required_embedding_env_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("TB_STORAGE__PG_DSN", "postgresql://x/y")
        monkeypatch.delenv("TB_EMBEDDING__MODEL_VERSION", raising=False)

        with pytest.raises(ValidationError):
            TracebedSettings()

    @pytest.mark.phase0
    def test_env_override_works(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _set_required_env(monkeypatch)
        monkeypatch.setenv("TB_API__PORT", "9999")
        monkeypatch.setenv("TB_RETRIEVAL__TOTAL_BUDGET_MS", "150")
        monkeypatch.setenv("TB_ABSTENTION__COS_THRESHOLD", "0.75")

        settings = TracebedSettings()

        assert settings.api.port == 9999
        assert settings.retrieval.total_budget_ms == 150
        assert settings.abstention.cos_threshold == 0.75
        # Untouched fields keep their defaults.
        assert settings.api.workers == 2

    @pytest.mark.phase0
    def test_unknown_nested_key_rejected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _set_required_env(monkeypatch)
        monkeypatch.setenv("TB_STORAGE__NOT_A_REAL_FIELD", "x")

        with pytest.raises(ValidationError):
            TracebedSettings()

    @pytest.mark.phase0
    def test_direct_construction_also_forbids_extra_keys(self) -> None:
        with pytest.raises(ValidationError):
            TracebedSettings(
                storage=StorageConfig(pg_dsn="postgresql://x/y"),
                embedding=EmbeddingConfig(model_version="v1"),
                not_a_field="boom",  # type: ignore[call-arg]
            )

    @pytest.mark.phase0
    def test_secret_env_vars_in_the_tb_namespace_do_not_break_startup(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The `TB_` namespace holds credentials that are deliberately NOT fields.

        C-15 keeps `TB_MASTER_KEY` out of `TracebedSettings` so key material
        never sits in the settings object; C-02 and the `*_env` fields name
        `TB_ADMIN_KEY` / `TB_LLM_API_KEY` / `TB_HOLDOUT_SALT` / the S3 pair
        as env vars read elsewhere. `extra="forbid"` must therefore NOT be
        interpreted as "reject unknown TB_ env vars" — if a pydantic-settings
        upgrade ever made that true, every correctly configured deployment
        would fail to boot. This test is that canary.
        """
        _set_required_env(monkeypatch)
        for name in (
            "TB_MASTER_KEY",
            "TB_ADMIN_KEY",
            "TB_LLM_API_KEY",
            "TB_HOLDOUT_SALT",
            "TB_S3_ACCESS_KEY",
            "TB_S3_SECRET_KEY",
        ):
            monkeypatch.setenv(name, "value-that-is-not-a-settings-field")

        settings = TracebedSettings()

        # Read, not merely constructed: the vars are inert, not absorbed.
        assert settings.auth.admin_key_env == "TB_ADMIN_KEY"
        assert settings.llm.api_key_env == "TB_LLM_API_KEY"
        assert settings.killswitch.salt_env == "TB_HOLDOUT_SALT"

    @pytest.mark.phase0
    def test_config_sections_are_frozen(self, settings: TracebedSettings) -> None:
        """A section is a snapshot, not a mutable global.

        `TracebedSettings` is a process-wide singleton in every deployment;
        `ConfigResolver.effective()` starts from `settings.<section>` on every
        request. An in-place write here would silently repoint every project
        at once, with no audit row — the exact shape of the admin bypass
        invariant 7 forbids.
        """
        with pytest.raises(ValidationError):
            settings.retrieval.total_budget_ms = 1  # type: ignore[misc]
        assert settings.retrieval.total_budget_ms == 300


# --------------------------------------------------------------------------- #
# ConfigResolver: layered precedence, killswitch overlay, ConfigError cases.
# --------------------------------------------------------------------------- #


class _FakeConfigStore:
    """In-memory `ConfigStorePort` — the offline test double every chunk hand-rolls (§13.1).

    Returns copies, like the real `Repo` does (each call decodes fresh jsonb).
    `_AliasingConfigStore` below is the adversarial variant that does not.
    """

    def __init__(self) -> None:
        self._project: dict[ProjectId, dict[str, object]] = {}
        self._agent_type: dict[tuple[ProjectId, AgentTypeId], dict[str, object]] = {}
        self._overlay: dict[tuple[ProjectId, AgentTypeId | None], dict[str, bool]] = {}

    def set_project_config(self, project_id: ProjectId, overrides: dict[str, object]) -> None:
        self._project[project_id] = overrides

    def set_agent_type_config(
        self, project_id: ProjectId, agent_type_id: AgentTypeId, overrides: dict[str, object]
    ) -> None:
        self._agent_type[(project_id, agent_type_id)] = overrides

    def set_killswitch_overlay(
        self,
        project_id: ProjectId,
        agent_type_id: AgentTypeId | None,
        overlay: dict[str, bool],
    ) -> None:
        self._overlay[(project_id, agent_type_id)] = overlay

    def get_project_config(self, project_id: ProjectId) -> dict[str, object]:
        return dict(self._project.get(project_id, {}))

    def get_agent_type_config(
        self, project_id: ProjectId, agent_type_id: AgentTypeId
    ) -> dict[str, object]:
        return dict(self._agent_type.get((project_id, agent_type_id), {}))

    def get_killswitch_overlay(
        self, project_id: ProjectId, agent_type_id: AgentTypeId | None
    ) -> dict[str, bool]:
        return dict(self._overlay.get((project_id, agent_type_id), {}))


class _AliasingConfigStore:
    """A store that hands out its own live dicts instead of copies.

    `ConfigStorePort` promises a `Mapping`, not a fresh one. This double
    proves the resolver defends itself: nothing it returns may alias store
    state, or a caller mutating an `EffectiveConfig` would be editing the
    killswitch table for the next request.
    """

    def __init__(self, overlay: dict[str, bool]) -> None:
        self.overlay = overlay

    def get_project_config(self, project_id: ProjectId) -> dict[str, object]:
        return {}

    def get_agent_type_config(
        self, project_id: ProjectId, agent_type_id: AgentTypeId
    ) -> dict[str, object]:
        return {}

    def get_killswitch_overlay(
        self, project_id: ProjectId, agent_type_id: AgentTypeId | None
    ) -> dict[str, bool]:
        return self.overlay


@pytest.fixture
def project_id() -> ProjectId:
    return ProjectId("00000000-0000-0000-0000-000000000001")


@pytest.fixture
def other_project_id() -> ProjectId:
    return ProjectId("00000000-0000-0000-0000-000000000002")


@pytest.fixture
def agent_type_id() -> AgentTypeId:
    return AgentTypeId("00000000-0000-0000-0000-0000000000a1")


@pytest.fixture
def other_agent_type_id() -> AgentTypeId:
    return AgentTypeId("00000000-0000-0000-0000-0000000000a2")


def _mutated(value: object) -> object | None:
    """A different-but-valid value for a scalar, or None if `value` is not scalar."""
    if isinstance(value, bool):
        return not value
    if isinstance(value, int):
        return value + 7
    if isinstance(value, float):
        return value + 0.5
    if isinstance(value, str):
        return value + "-overridden"
    return None


def _an_override_for(section_dump: dict[str, Any]) -> tuple[str, object, dict[str, Any]]:
    """Pick one overridable leaf in a dumped section.

    Returns (dotted suffix, new value, the expected post-override dump).
    Written generically so the parametrised round-trip below covers all
    sixteen sections without sixteen hand-written cases going stale the day
    a field is added.
    """
    expected = copy.deepcopy(section_dump)
    for name, value in section_dump.items():
        new = _mutated(value)
        if new is not None:
            expected[name] = new
            return name, new, expected
    for name, value in section_dump.items():
        if isinstance(value, dict) and value:
            leaf_key, leaf_value = next(iter(value.items()))
            new = _mutated(leaf_value)
            if new is not None:
                expected[name][leaf_key] = new
                return f"{name}.{leaf_key}", new, expected
    raise AssertionError(f"no overridable leaf found in {section_dump!r}")


class TestConfigResolver:
    @pytest.mark.phase0
    def test_fake_store_satisfies_config_store_port(self) -> None:
        assert isinstance(_FakeConfigStore(), ConfigStorePort)

    @pytest.mark.phase0
    def test_defaults_only_when_store_is_empty(
        self, settings: TracebedSettings, project_id: ProjectId
    ) -> None:
        resolver = ConfigResolver(settings, _FakeConfigStore())

        effective = resolver.effective(project_id)

        assert isinstance(effective, EffectiveConfig)
        assert effective.retrieval.total_budget_ms == settings.retrieval.total_budget_ms
        assert effective.budget.slot_caps == settings.budget.slot_caps
        assert effective.killswitch_overlay == {}

    @pytest.mark.phase0
    def test_project_config_overrides_defaults(
        self, settings: TracebedSettings, project_id: ProjectId
    ) -> None:
        store = _FakeConfigStore()
        store.set_project_config(project_id, {"retrieval.total_budget_ms": 250})
        resolver = ConfigResolver(settings, store)

        effective = resolver.effective(project_id)

        assert effective.retrieval.total_budget_ms == 250
        # Untouched fields in the same section keep the process default.
        assert effective.retrieval.rrf_k == settings.retrieval.rrf_k

    @pytest.mark.phase0
    @pytest.mark.parametrize("section", sorted(OVERRIDABLE_SECTIONS))
    def test_every_overridable_section_round_trips_an_override(
        self, settings: TracebedSettings, project_id: ProjectId, section: str
    ) -> None:
        """Each of the sixteen sections is genuinely reachable and rebuilt.

        Guards the two-map wiring (`_SECTION_MODELS` / `EffectiveConfig`
        fields): a section present in one and absent from the other would
        either silently drop overrides or blow up at construction, and the
        set-equality test alone would not notice a section wired to the
        wrong model class.
        """
        base = getattr(settings, section).model_dump()
        suffix, value, expected = _an_override_for(base)

        store = _FakeConfigStore()
        store.set_project_config(project_id, {f"{section}.{suffix}": value})
        effective = ConfigResolver(settings, store).effective(project_id)

        assert getattr(effective, section).model_dump() == expected

    @pytest.mark.phase0
    def test_agent_type_config_overrides_project_config(
        self,
        settings: TracebedSettings,
        project_id: ProjectId,
        agent_type_id: AgentTypeId,
    ) -> None:
        store = _FakeConfigStore()
        store.set_project_config(project_id, {"retrieval.total_budget_ms": 250})
        store.set_agent_type_config(
            project_id, agent_type_id, {"retrieval.total_budget_ms": 111}
        )
        resolver = ConfigResolver(settings, store)

        by_agent_type = resolver.effective(project_id, agent_type_id)
        assert by_agent_type.retrieval.total_budget_ms == 111

        # Without an agent_type_id, only the project-level override applies —
        # proves agent_type_config is layered ON TOP of, not instead of,
        # project_config.
        project_only = resolver.effective(project_id)
        assert project_only.retrieval.total_budget_ms == 250

    @pytest.mark.phase0
    def test_agent_type_layer_does_not_erase_untouched_project_keys(
        self,
        settings: TracebedSettings,
        project_id: ProjectId,
        agent_type_id: AgentTypeId,
    ) -> None:
        """Layering is a merge, not a replacement, at every level.

        A resolver that rebuilt `merged` from defaults before applying the
        agent-type layer would pass the precedence test above and still lose
        every project-level key the agent type did not restate.
        """
        store = _FakeConfigStore()
        store.set_project_config(
            project_id,
            {"retrieval.total_budget_ms": 250, "retrieval.rrf_k": 33, "budget.total_tokens": 900},
        )
        store.set_agent_type_config(
            project_id, agent_type_id, {"retrieval.total_budget_ms": 111}
        )

        effective = ConfigResolver(settings, store).effective(project_id, agent_type_id)

        assert effective.retrieval.total_budget_ms == 111
        assert effective.retrieval.rrf_k == 33
        assert effective.budget.total_tokens == 900

    @pytest.mark.phase0
    def test_agent_type_config_is_scoped_per_agent_type(
        self,
        settings: TracebedSettings,
        project_id: ProjectId,
        agent_type_id: AgentTypeId,
        other_agent_type_id: AgentTypeId,
    ) -> None:
        store = _FakeConfigStore()
        store.set_agent_type_config(
            project_id, agent_type_id, {"retrieval.total_budget_ms": 111}
        )
        resolver = ConfigResolver(settings, store)

        # Resolve the overridden agent type FIRST: if the resolver leaked its
        # working copy into the settings object, the second call would inherit
        # 111 and this would go red.
        assert resolver.effective(project_id, agent_type_id).retrieval.total_budget_ms == 111
        other = resolver.effective(project_id, other_agent_type_id)
        assert other.retrieval.total_budget_ms == settings.retrieval.total_budget_ms

    @pytest.mark.phase0
    def test_override_for_one_project_does_not_bleed_into_another(
        self,
        settings: TracebedSettings,
        project_id: ProjectId,
        other_project_id: ProjectId,
    ) -> None:
        """Invariant 4, config edition: project A's tuning is not project B's.

        `effective()` builds its working copy with `model_dump()`. Swapping
        that for a plain `getattr(...).__dict__` or a shallow `dict(...)` —
        an easy "optimisation" — would make `_apply_override` write straight
        through into the shared settings object, and every later project
        would inherit project A's values. Both the nested-dict path
        (`budget.slot_caps.fact`, the one that mutates a container rather
        than rebinding a key) and the scalar path are checked, then the
        settings object itself.
        """
        store = _FakeConfigStore()
        store.set_project_config(
            project_id,
            {"budget.slot_caps.fact": 999, "retrieval.total_budget_ms": 42},
        )
        resolver = ConfigResolver(settings, store)

        a = resolver.effective(project_id)
        assert a.budget.slot_caps["fact"] == 999
        assert a.retrieval.total_budget_ms == 42

        b = resolver.effective(other_project_id)
        assert b.budget.slot_caps["fact"] == 250
        assert b.retrieval.total_budget_ms == 300

        assert settings.budget.slot_caps["fact"] == 250
        assert settings.retrieval.total_budget_ms == 300

    @pytest.mark.phase0
    def test_mutating_a_snapshot_does_not_reach_the_next_snapshot(
        self, settings: TracebedSettings, project_id: ProjectId
    ) -> None:
        """A caller editing a returned dict field must not poison later calls.

        `frozen=True` blocks `cfg.budget.total_tokens = ...` but cannot deep
        -freeze `slot_caps` (see `_StrictModel`); the containment guarantee is
        that each snapshot owns its own containers.
        """
        resolver = ConfigResolver(settings, _FakeConfigStore())

        first = resolver.effective(project_id)
        first.budget.slot_caps["fact"] = 1

        second = resolver.effective(project_id)
        assert second.budget.slot_caps["fact"] == 250
        assert settings.budget.slot_caps["fact"] == 250

    @pytest.mark.phase0
    def test_killswitch_overlay_applies_last_and_is_not_writable_via_override(
        self,
        settings: TracebedSettings,
        project_id: ProjectId,
        agent_type_id: AgentTypeId,
    ) -> None:
        store = _FakeConfigStore()
        store.set_project_config(project_id, {"killswitch.holdout_pct": 10})
        store.set_killswitch_overlay(project_id, agent_type_id, {"lesson": True, "fact": False})
        resolver = ConfigResolver(settings, store)

        effective = resolver.effective(project_id, agent_type_id)

        # The `killswitch` *section* is overridable (tunes holdout_pct etc.)...
        assert effective.killswitch.holdout_pct == 10
        # ...while `killswitch_overlay` comes ONLY from get_killswitch_overlay.
        assert effective.killswitch_overlay == {"lesson": True, "fact": False}

        # An attempt to reach killswitch_overlay through a dotted override
        # is rejected outright — it is not a section, so it is unknown.
        store.set_project_config(project_id, {"killswitch_overlay.lesson": False})
        with pytest.raises(ConfigError):
            resolver.effective(project_id, agent_type_id)

    @pytest.mark.phase0
    def test_killswitch_overlay_snapshot_does_not_alias_the_store(
        self, settings: TracebedSettings, project_id: ProjectId
    ) -> None:
        """The overlay is "read-only" in the sense that matters: no write-back.

        A resolver that passed the store's mapping straight through would let
        anything holding an `EffectiveConfig` re-enable a memory type the
        kill switch disabled, for every subsequent request in the process.
        """
        live = {"lesson": True}
        store = _AliasingConfigStore(live)

        effective = ConfigResolver(settings, store).effective(project_id)
        assert effective.killswitch_overlay == {"lesson": True}

        effective.killswitch_overlay["lesson"] = False  # type: ignore[index]
        assert live == {"lesson": True}

        live["semantic"] = True
        assert "semantic" not in effective.killswitch_overlay

    @pytest.mark.phase0
    def test_nested_dict_field_override(
        self, settings: TracebedSettings, project_id: ProjectId
    ) -> None:
        store = _FakeConfigStore()
        store.set_project_config(project_id, {"budget.slot_caps.fact": 999})
        resolver = ConfigResolver(settings, store)

        effective = resolver.effective(project_id)

        assert effective.budget.slot_caps["fact"] == 999
        # Sibling keys in the same nested dict are untouched.
        assert effective.budget.slot_caps["exemplar"] == 150

    @pytest.mark.phase0
    def test_unknown_dotted_key_raises_config_error(
        self, settings: TracebedSettings, project_id: ProjectId
    ) -> None:
        store = _FakeConfigStore()
        store.set_project_config(project_id, {"not_a_section.field": 1})
        resolver = ConfigResolver(settings, store)

        with pytest.raises(ConfigError):
            resolver.effective(project_id)

    @pytest.mark.phase0
    @pytest.mark.parametrize(
        ("section", "field", "value"),
        [
            ("api", "port", 1),
            ("dashboard", "port", 1),
            ("auth", "api_key_mode", False),
            ("auth", "oidc_jwks_url", "https://attacker.example/jwks.json"),
            ("storage", "pg_dsn", "postgresql://attacker@elsewhere/other_tenant"),
            ("storage", "valkey_url", "valkey://attacker/0"),
            ("embedding", "model_version", "sneaky"),
            ("llm", "api_key_env", "PATH"),
        ],
    )
    def test_deployment_level_section_is_not_overridable(
        self,
        settings: TracebedSettings,
        project_id: ProjectId,
        section: str,
        field: str,
        value: object,
    ) -> None:
        """Project-scoped config must not reach the wiring layer.

        `project_config` rows are the closest thing to caller-influenced data
        in the resolution path. If `storage.pg_dsn` or `auth.*` were
        overridable, one project's config row would repoint the process at
        another tenant's database or disable credential verification —
        invariant 4 collapses on a config write instead of a code change.
        The refusal must be per-section, not per-field, so every deployment
        section is exercised.
        """
        store = _FakeConfigStore()
        store.set_project_config(project_id, {f"{section}.{field}": value})
        resolver = ConfigResolver(settings, store)

        with pytest.raises(ConfigError):
            resolver.effective(project_id)

    @pytest.mark.phase0
    def test_deployment_sections_are_absent_from_the_overridable_set(self) -> None:
        assert OVERRIDABLE_SECTIONS.isdisjoint(DEPLOYMENT_SECTIONS)
        assert set(TracebedSettings.model_fields) == OVERRIDABLE_SECTIONS | set(
            DEPLOYMENT_SECTIONS
        )

    @pytest.mark.phase0
    def test_dotted_key_without_a_field_component_raises(
        self, settings: TracebedSettings, project_id: ProjectId
    ) -> None:
        store = _FakeConfigStore()
        store.set_project_config(project_id, {"retrieval": 1})
        resolver = ConfigResolver(settings, store)

        with pytest.raises(ConfigError):
            resolver.effective(project_id)

    @pytest.mark.phase0
    @pytest.mark.parametrize("key", ["", ".", "retrieval.", ".rrf_k", "retrieval..rrf_k"])
    def test_malformed_dotted_keys_raise_config_error(
        self, settings: TracebedSettings, project_id: ProjectId, key: str
    ) -> None:
        store = _FakeConfigStore()
        store.set_project_config(project_id, {key: 1})
        resolver = ConfigResolver(settings, store)

        with pytest.raises(ConfigError):
            resolver.effective(project_id)

    @pytest.mark.phase0
    def test_override_traversing_a_scalar_raises_config_error(
        self, settings: TracebedSettings, project_id: ProjectId
    ) -> None:
        store = _FakeConfigStore()
        store.set_project_config(project_id, {"budget.slot_caps.fact.deeper": 1})
        resolver = ConfigResolver(settings, store)

        with pytest.raises(ConfigError):
            resolver.effective(project_id)

    @pytest.mark.phase0
    def test_unknown_leaf_field_raises_config_error(
        self, settings: TracebedSettings, project_id: ProjectId
    ) -> None:
        store = _FakeConfigStore()
        store.set_project_config(project_id, {"retrieval.not_a_real_field": 1})
        resolver = ConfigResolver(settings, store)

        with pytest.raises(ConfigError):
            resolver.effective(project_id)

    @pytest.mark.phase0
    def test_unknown_leaf_field_in_agent_type_layer_also_raises(
        self,
        settings: TracebedSettings,
        project_id: ProjectId,
        agent_type_id: AgentTypeId,
    ) -> None:
        """Both layers go through the same validation — no second, laxer path."""
        store = _FakeConfigStore()
        store.set_agent_type_config(
            project_id, agent_type_id, {"retrieval.not_a_real_field": 1}
        )
        resolver = ConfigResolver(settings, store)

        with pytest.raises(ConfigError):
            resolver.effective(project_id, agent_type_id)

    @pytest.mark.phase0
    def test_wrong_typed_value_raises_config_error(
        self, settings: TracebedSettings, project_id: ProjectId
    ) -> None:
        store = _FakeConfigStore()
        store.set_project_config(project_id, {"retrieval.total_budget_ms": "not-an-int"})
        resolver = ConfigResolver(settings, store)

        with pytest.raises(ConfigError):
            resolver.effective(project_id)

    @pytest.mark.phase0
    def test_config_error_is_the_only_failure_mode_of_a_bad_override(
        self, settings: TracebedSettings, project_id: ProjectId
    ) -> None:
        """C-03 says ConfigError, and callers catch exactly that.

        Override keys arrive from a jsonb column, so they are arbitrary
        strings — including ones that collide with Python/pydantic internals.
        Any of these escaping as a raw TypeError/AttributeError would bypass
        every `except ConfigError` handler in the service.
        """
        hostile_keys = [
            "retrieval.self",
            "retrieval.__class__",
            "retrieval.model_config",
            "retrieval.model_fields",
            "__class__.__init__",
            "budget.slot_caps.fact.__class__",
        ]
        for key in hostile_keys:
            store = _FakeConfigStore()
            store.set_project_config(project_id, {key: 1})
            resolver = ConfigResolver(settings, store)
            with pytest.raises(ConfigError):
                resolver.effective(project_id)

    @pytest.mark.phase0
    @pytest.mark.parametrize(
        "overrides",
        [
            {"lifecycle.archive_floor": 0.5},  # floor raised above the 0.5 seed
            {"lifecycle.archive_floor": 0.9},
            {"scoring.q_start": 0.15},  # seed lowered onto the 0.15 floor
            {"scoring.q_start": 0.1},
            {"lifecycle.archive_floor": 0.3, "scoring.q_start": 0.3},  # both moved
        ],
    )
    def test_a_q_seed_at_or_below_the_archive_floor_is_refused(
        self,
        settings: TracebedSettings,
        project_id: ProjectId,
        overrides: dict[str, object],
    ) -> None:
        """`scoring` and `lifecycle` are separately overridable sections, so no
        single-field constraint can see this pair.

        `workers.sweeps._decayed_q_value` seeds the idle-decay curve at
        `scoring.q_start` and archives at `lifecycle.archive_floor`. A seed at
        or below the floor archives EVERY idle `validated` memory on its first
        idle sweep — the whole vault emptied by two individually plausible
        override rows, each of which passes its own section's validation.
        """
        store = _FakeConfigStore()
        store.set_project_config(project_id, overrides)
        resolver = ConfigResolver(settings, store)

        with pytest.raises(ConfigError):
            resolver.effective(project_id)

    @pytest.mark.phase0
    def test_a_coherent_seed_and_floor_pair_still_resolves(
        self, settings: TracebedSettings, project_id: ProjectId
    ) -> None:
        """Guard the guard: the cross-section check must not be satisfiable by
        refusing everything. A floor genuinely below the seed resolves."""
        store = _FakeConfigStore()
        store.set_project_config(
            project_id, {"lifecycle.archive_floor": 0.4, "scoring.q_start": 0.45}
        )

        effective = ConfigResolver(settings, store).effective(project_id)

        assert effective.lifecycle.archive_floor == 0.4
        assert effective.scoring.q_start == 0.45

    @pytest.mark.phase0
    def test_effective_config_is_frozen(
        self, settings: TracebedSettings, project_id: ProjectId
    ) -> None:
        resolver = ConfigResolver(settings, _FakeConfigStore())
        effective = resolver.effective(project_id)

        with pytest.raises(ValidationError):
            effective.retrieval = effective.retrieval  # type: ignore[misc]

    @pytest.mark.phase0
    def test_effective_config_sections_are_frozen(
        self, settings: TracebedSettings, project_id: ProjectId
    ) -> None:
        """The thresholds the state machine reads cannot be rewritten in place.

        `TransitionLimits.from_config(cfg)` (§3.9) sources retirement and
        promotion thresholds from this object. Top-level `frozen=True` alone
        left `cfg.retirement.q_threshold = 0.0` legal, which is a governance
        bypass reachable from any module holding a snapshot (invariant 7).
        """
        effective = ConfigResolver(settings, _FakeConfigStore()).effective(project_id)

        with pytest.raises(ValidationError):
            effective.retirement.q_threshold = 0.0  # type: ignore[misc]
        with pytest.raises(ValidationError):
            effective.promotion.min_distinct_principals = 0  # type: ignore[misc]
        with pytest.raises(ValidationError):
            effective.lifecycle.quarantine_ttl_days = 0  # type: ignore[misc]

        assert effective.retirement.q_threshold == 0.25
        assert effective.promotion.min_distinct_principals == 2

    @pytest.mark.phase0
    def test_overridable_sections_matches_effective_config_fields(self) -> None:
        # Every overridable section must have a same-named field on
        # EffectiveConfig, and vice versa (minus killswitch_overlay, which
        # is not a section at all — see the test above).
        effective_fields = set(EffectiveConfig.model_fields) - {"killswitch_overlay"}
        assert effective_fields == OVERRIDABLE_SECTIONS

    @pytest.mark.phase0
    def test_effective_section_types_match_the_settings_section_types(
        self, settings: TracebedSettings, project_id: ProjectId
    ) -> None:
        """A section wired to the wrong model class would still validate.

        `_SECTION_MODELS` maps names to classes by hand; nothing else checks
        that `EffectiveConfig.promotion` is built from `PromotionConfig` and
        not, say, `RetirementConfig`.
        """
        effective = ConfigResolver(settings, _FakeConfigStore()).effective(project_id)

        for section in OVERRIDABLE_SECTIONS:
            assert type(getattr(effective, section)) is type(getattr(settings, section)), section


# --------------------------------------------------------------------------- #
# Error hierarchy shape (PHASE0-CONTRACT.md §3.1).
#
# See the module docstring's contract_gap note: this is test_errors.py's
# content, folded in here because this chunk's file list has no separate
# test_errors.py.
# --------------------------------------------------------------------------- #


CONTRACT_ERROR_NAMES = frozenset(
    {
        "TracebedError",
        "ConfigError",
        "AuthenticationFailed",
        "ScopeResolutionFailed",
        "DuplicateRegistration",
        "NotFound",
        "ProvenanceIncomplete",
        "ScanRejected",
        "ScanVerdictForgery",
        "IllegalTransition",
        "GuardNotSatisfied",
        "QueueFull",
        "Tombstoned",
        "MasterKeyMissing",
        "EmbeddingTimeout",
        "BudgetExceeded",
        "CapExceeded",
        "CrossEpochComparison",
    }
)
"""Transcribed from PHASE0-CONTRACT.md §3.1. Deliberately a literal, not
derived from the module: a test that reads its expectation out of the code
under test proves nothing about the contract."""


def _defined_exception_classes() -> dict[str, type[BaseException]]:
    """Every exception class *defined in* `domain.errors` (not merely imported)."""
    return {
        name: obj
        for name, obj in vars(errors_module).items()
        if inspect.isclass(obj)
        and issubclass(obj, BaseException)
        and obj.__module__ == errors_module.__name__
    }


class TestErrorHierarchy:
    @pytest.mark.phase0
    def test_module_defines_exactly_the_contract_error_set(self) -> None:
        """Drift in either direction is a finding.

        A hand-maintained parametrise list can only check the classes someone
        remembered to add to it; introspecting the module catches the new
        exception that quietly subclasses `Exception` instead of
        `TracebedError` and so escapes §9.4's handler as an opaque 500.
        """
        assert set(_defined_exception_classes()) == CONTRACT_ERROR_NAMES

    @pytest.mark.phase0
    def test_all_exports_exactly_the_defined_classes(self) -> None:
        assert set(errors_module.__all__) == CONTRACT_ERROR_NAMES

    @pytest.mark.phase0
    def test_every_defined_exception_subclasses_tracebed_error(self) -> None:
        for name, exc_cls in _defined_exception_classes().items():
            if name == "TracebedError":
                continue
            assert issubclass(exc_cls, TracebedError), name
        # Exception, never BaseException: a Tracebed error must be catchable by
        # `except Exception` and must not masquerade as a cancellation.
        assert TracebedError.__bases__ == (Exception,)

    @pytest.mark.phase0
    def test_scan_rejected_carries_all_reasons(self) -> None:
        exc = ScanRejected(["injection:imperative", "secret:aws-key"])
        assert exc.reasons == ("injection:imperative", "secret:aws-key")
        assert "injection:imperative" in str(exc)
        assert "secret:aws-key" in str(exc)

    @pytest.mark.phase0
    def test_scan_rejected_accepts_a_one_shot_iterable(self) -> None:
        """`reasons` drives the review_queue row; consuming them to build the
        message would leave the queue entry blank."""
        # A generator is not a Sequence; the annotation says so and mypy would
        # stop it. The runtime hardening exists because the scan suite builds
        # reasons by comprehension and one dropped `list(...)` is silent.
        exc = ScanRejected(f"secret:rule-{i}" for i in range(3))  # type: ignore[arg-type]
        assert exc.reasons == ("secret:rule-0", "secret:rule-1", "secret:rule-2")
        assert "secret:rule-2" in str(exc)

    @pytest.mark.phase0
    def test_scan_rejected_with_no_reasons_still_constructs(self) -> None:
        exc = ScanRejected([])
        assert exc.reasons == ()
        assert str(exc) == "scan rejected"

    @pytest.mark.phase0
    def test_illegal_transition_carries_current_and_target(self) -> None:
        exc = IllegalTransition(_status("quarantined"), _status("validated"))
        assert exc.current == "quarantined"
        assert exc.target == "validated"
        assert "quarantined" in str(exc)
        assert "validated" in str(exc)

    @pytest.mark.phase0
    def test_illegal_transition_accepts_none_current(self) -> None:
        exc = IllegalTransition(None, _status("candidate"))
        assert exc.current is None

    @pytest.mark.phase0
    def test_guard_not_satisfied_carries_reason(self) -> None:
        exc = GuardNotSatisfied(
            _status("quarantined"),
            _status("candidate"),
            "only 1 of 2 required independent confirmations",
        )
        assert exc.current == "quarantined"
        assert exc.target == "candidate"
        assert exc.reason == "only 1 of 2 required independent confirmations"
        assert exc.reason in str(exc)

    @pytest.mark.phase0
    def test_not_found_cannot_carry_a_distinguishing_reason(self) -> None:
        """Invariant 4 / leak probe 2: 404 must not become an existence oracle.

        The uniformity is structural, not a convention the call sites are
        trusted to keep: `NotFound` defines no `__init__`, so there is no
        parameter in which "wrong project" could differ from "no such row",
        and a bare instance renders as the empty string. Adding
        `def __init__(self, reason)` here — the natural thing to do while
        debugging — turns every raise site into a potential leak, and this
        test is what stops it landing.
        """
        assert "__init__" not in vars(NotFound)
        assert "__init__" not in vars(TracebedError)
        assert NotFound.__init__ is Exception.__init__

        absent = NotFound()
        not_yours = NotFound()
        assert str(absent) == "" and str(not_yours) == ""
        assert absent.args == () == not_yours.args
        assert repr(absent) == repr(not_yours)

    @pytest.mark.phase0
    def test_config_error_is_a_plain_message_exception(self) -> None:
        exc = ConfigError("unknown override key 'foo.bar'")
        assert "foo.bar" in str(exc)


# --------------------------------------------------------------------------------------- #
# Hard rule 12 — the numbers live in config, and the workers READ them.
#
# Three governed thresholds used to be module constants in `workers/`: the Benjamini-Hochberg
# alpha, the confidence level, and the contribution rubric (plus its temperature). Each had a
# CONTRACT GAP comment saying PLAN.md §6 named no field for it, which is how a governed number
# becomes a magic number with an explanation attached. The fields now exist; these tests are
# what stops a worker from quietly going back to a literal, because a literal that happens to
# equal the default today would pass every other test in this suite forever.
# --------------------------------------------------------------------------------------- #


def test_the_bh_alpha_and_confidence_level_come_from_killswitch_config() -> None:
    from tracebed.domain.config import KillswitchConfig
    from tracebed.workers.lift import DEFAULT_BH_ALPHA, DEFAULT_CONFIDENCE

    cfg = KillswitchConfig()
    assert cfg.fdr_alpha == DEFAULT_BH_ALPHA
    assert cfg.confidence_level == DEFAULT_CONFIDENCE
    # D-027's own numbers, pinned so "read from config" cannot become "read a config field
    # somebody changed to 0.5 and nobody noticed".
    assert (cfg.fdr_alpha, cfg.confidence_level) == (0.05, 0.95)


def test_the_contribution_rubric_and_temperature_come_from_scoring_config() -> None:
    from tracebed.domain.config import ScoringConfig
    from tracebed.workers.contribution_judge import _RUBRIC, RUBRIC_FACTORS, TEMPERATURE

    cfg = ScoringConfig()
    assert dict(_RUBRIC) == cfg.contribution_rubric
    assert cfg.contribution_judge_temperature == TEMPERATURE
    # PLAN.md §6: "judge ∈ {0, 0.5, 1.0}, temperature 0".
    assert set(cfg.contribution_rubric.values()) == RUBRIC_FACTORS == {0.0, 0.5, 1.0}
    assert cfg.contribution_judge_temperature == 0.0


def test_the_rubric_the_judge_uses_cannot_be_mutated_at_runtime() -> None:
    """A governed threshold with a public setter is not a governed threshold."""
    from tracebed.workers.contribution_judge import _RUBRIC

    with pytest.raises(TypeError):
        _RUBRIC["FULL"] = 0.0  # type: ignore[index]
