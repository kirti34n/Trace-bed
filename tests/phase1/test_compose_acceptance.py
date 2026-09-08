"""Adversarial isolation proofs for the destructive Compose-v1 acceptance harness."""

from __future__ import annotations

import inspect
import subprocess

import pytest
from scripts import compose_acceptance

from tracebed.erasure import runner as erasure_runner

pytestmark = pytest.mark.phase1

_PROJECT = "tracebed-acceptance-0123456789abcdef0123456789abcdef"


def _completed(
    *arguments: str, stdout: str = "", stderr: str = "", returncode: int = 0
) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(arguments, returncode, stdout=stdout, stderr=stderr)


def test_external_default_project_is_rejected_before_any_docker_operation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("COMPOSE_PROJECT_NAME", "tracebed")
    monkeypatch.setattr(
        compose_acceptance,
        "_docker_capture",
        lambda *_args, **_kwargs: pytest.fail("must not inspect or mutate Docker"),
    )

    with pytest.raises(compose_acceptance.AcceptanceError):
        compose_acceptance._acceptance_environment()


def test_generated_project_and_compose_commands_never_target_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(compose_acceptance.secrets, "token_hex", lambda _: "a" * 32)
    environment, project = compose_acceptance._acceptance_environment()

    assert project == "tracebed-acceptance-" + "a" * 32
    assert environment["COMPOSE_PROJECT_NAME"] == project
    assert environment[compose_acceptance._API_HOST_PORT_ENV] != "8110"
    assert environment[compose_acceptance._DASHBOARD_HOST_PORT_ENV] != "8111"
    command = compose_acceptance._compose_command(environment, "ps")
    assert command[:4] == ("docker", "compose", "--project-name", project)
    assert compose_acceptance._DEFAULT_PROJECT not in command


def test_exact_label_preflight_refuses_collision_without_touching_default_or_prefix(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, ...]] = []

    def fake_docker(*arguments: str, check: bool = True) -> subprocess.CompletedProcess[str]:
        del check
        calls.append(arguments)
        assert f"label=com.docker.compose.project={_PROJECT}" in arguments
        # Docker filtering is exact: fake default and a same-prefix project are
        # deliberately absent from this result, while the exact label collides.
        return _completed(*arguments, stdout="owned-by-another-run\n")

    monkeypatch.setattr(compose_acceptance, "_docker_capture", fake_docker)
    tracker = compose_acceptance._AcceptanceResources(_PROJECT)

    with pytest.raises(compose_acceptance.AcceptanceError):
        tracker.preflight()

    assert all("rm" not in call for call in calls)


def test_cleanup_removes_only_recorded_exact_label_resources(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, ...]] = []
    tracker = compose_acceptance._AcceptanceResources(_PROJECT)
    tracker.containers.update({"created-container", "foreign-default", "foreign-prefix"})
    tracker.volumes.update({"created-volume", "foreign-volume"})
    tracker.networks.update({"created-network", "foreign-network"})

    labels = {
        "created-container": _PROJECT,
        "created-volume": _PROJECT,
        "created-network": _PROJECT,
        "foreign-default": "tracebed",
        "foreign-prefix": "tracebed-acceptance-deadbeefdeadbeefdeadbeefdeadbeef",
        "foreign-volume": "tracebed",
        "foreign-network": "tracebed-acceptance-deadbeefdeadbeefdeadbeefdeadbeef",
    }

    def fake_docker(*arguments: str, check: bool = True) -> subprocess.CompletedProcess[str]:
        del check
        calls.append(arguments)
        if "inspect" in arguments:
            return _completed(*arguments, stdout=labels[arguments[-1]] + "\n")
        return _completed(*arguments)

    monkeypatch.setattr(compose_acceptance, "_docker_capture", fake_docker)
    tracker.cleanup()

    destructive = [
        call
        for call in calls
        if call[:2] in {("rm", "--force"), ("volume", "rm"), ("network", "rm")}
    ]
    assert destructive == [
        ("rm", "--force", "created-container"),
        ("volume", "rm", "created-volume"),
        ("network", "rm", "created-network"),
    ]
    assert all("foreign" not in item for call in destructive for item in call)


def test_cleanup_attempts_every_recorded_removal_and_rejects_a_failed_remove(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tracker = compose_acceptance._AcceptanceResources(_PROJECT)
    tracker.containers.add("created-container")
    tracker.volumes.add("created-volume")
    tracker.networks.add("created-network")
    destructive: list[tuple[str, ...]] = []

    def fake_docker(*arguments: str, check: bool = True) -> subprocess.CompletedProcess[str]:
        del check
        if "inspect" in arguments:
            return _completed(*arguments, stdout=_PROJECT + "\n")
        if arguments[:2] in {("rm", "--force"), ("volume", "rm"), ("network", "rm")}:
            destructive.append(arguments)
            return _completed(*arguments, returncode=1 if arguments[0] == "rm" else 0)
        return _completed(*arguments)

    monkeypatch.setattr(compose_acceptance, "_docker_capture", fake_docker)

    with pytest.raises(compose_acceptance.AcceptanceError):
        tracker.cleanup()

    assert destructive == [
        ("rm", "--force", "created-container"),
        ("volume", "rm", "created-volume"),
        ("network", "rm", "created-network"),
    ]


def test_cleanup_rejects_remaining_exact_label_resources(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tracker = compose_acceptance._AcceptanceResources(_PROJECT)
    tracker.containers.add("created-container")

    def fake_docker(*arguments: str, check: bool = True) -> subprocess.CompletedProcess[str]:
        del check
        if "inspect" in arguments:
            return _completed(*arguments, stdout=_PROJECT + "\n")
        if arguments[:3] == ("ps", "--all", "--quiet"):
            # This was not in the tracker, so cleanup has no authority to
            # remove it.  A passing harness must still reject the residue.
            return _completed(*arguments, stdout="unrecorded-container\n")
        return _completed(*arguments)

    monkeypatch.setattr(compose_acceptance, "_docker_capture", fake_docker)

    with pytest.raises(compose_acceptance.AcceptanceError):
        tracker.cleanup()


def test_active_tracker_captures_only_the_exact_acceptance_label(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tracker = compose_acceptance._AcceptanceResources(_PROJECT)
    monkeypatch.setattr(compose_acceptance, "_ACTIVE_RESOURCES", tracker)
    environment = {"COMPOSE_PROJECT_NAME": _PROJECT}

    def fake_docker(*arguments: str, check: bool = True) -> subprocess.CompletedProcess[str]:
        del check
        assert arguments[-1] == f"label=com.docker.compose.project={_PROJECT}"
        kind = arguments[0]
        values = {"ps": "created-container\n", "volume": "created-volume\n", "network": "created-network\n"}
        return _completed(*arguments, stdout=values[kind])

    monkeypatch.setattr(compose_acceptance, "_docker_capture", fake_docker)
    compose_acceptance._capture_resources(environment)

    assert tracker.containers == {"created-container"}
    assert tracker.volumes == {"created-volume"}
    assert tracker.networks == {"created-network"}


def test_e4_lease_blocker_removal_requires_exact_labeled_container(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    container = "a" * 64
    tracker = compose_acceptance._AcceptanceResources(_PROJECT)
    tracker.containers.add(container)
    calls: list[tuple[str, ...]] = []
    monkeypatch.setattr(compose_acceptance, "_ACTIVE_RESOURCES", tracker)

    def fake_docker(*arguments: str, check: bool = True) -> subprocess.CompletedProcess[str]:
        del check
        calls.append(arguments)
        if arguments[:2] == ("container", "inspect"):
            return _completed(*arguments, stdout=_PROJECT + "\ndb-bootstrap\n")
        return _completed(*arguments)

    monkeypatch.setattr(compose_acceptance, "_docker_capture", fake_docker)
    compose_acceptance._stop_e4_lease_blocker({"COMPOSE_PROJECT_NAME": _PROJECT}, container)

    assert calls == [
        (
            "container",
            "inspect",
            "--format",
            '{{ index .Config.Labels "com.docker.compose.project" }}\n'
            '{{ index .Config.Labels "com.docker.compose.service" }}',
            container,
        ),
        ("rm", "--force", container),
    ]


def test_e4_live_lease_observation_execs_inside_the_exact_holder(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    container = "b" * 64
    request_id = "00000000-0000-0000-0000-000000000001"
    tracker = compose_acceptance._AcceptanceResources(_PROJECT)
    tracker.containers.add(container)
    calls: list[tuple[str, ...]] = []
    monkeypatch.setattr(compose_acceptance, "_ACTIVE_RESOURCES", tracker)

    def fake_docker(*arguments: str, check: bool = True) -> subprocess.CompletedProcess[str]:
        del check
        calls.append(arguments)
        if arguments[:2] == ("container", "inspect"):
            return _completed(*arguments, stdout=_PROJECT + "\ndb-bootstrap\n")
        return _completed(*arguments, stdout="e4-lease: generation-1\n")

    monkeypatch.setattr(compose_acceptance, "_docker_capture", fake_docker)
    assert (
        compose_acceptance._owner_python_in_e4_lease_blocker(
            {"COMPOSE_PROJECT_NAME": _PROJECT},
            container,
            compose_acceptance._OWNER_E4_LEASE_GENERATION,
            values={"B4_REQUEST_ID": request_id, "B4_EXPECTED_GENERATION": "1"},
        )
        == "e4-lease: generation-1"
    )

    assert calls[-1] == (
        "exec",
        "-e",
        "B4_EXPECTED_GENERATION=1",
        "-e",
        "B4_REQUEST_ID=" + request_id,
        container,
        "python",
        "-c",
        compose_acceptance._OWNER_E4_LEASE_GENERATION,
    )


def test_e4_lease_timeout_diagnostic_is_bounded_to_fixed_state_codes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    container = "f" * 64
    request_id = "00000000-0000-0000-0000-000000000001"
    observed: list[tuple[str, dict[str, str]]] = []

    def owner_probe(
        _environment: dict[str, str], _container: str, code: str, *, values: dict[str, str]
    ) -> str:
        observed.append((code, values))
        return "e4-lease-observation:unclaimed"

    monkeypatch.setattr(compose_acceptance, "_owner_python_in_e4_lease_blocker", owner_probe)

    assert (
        compose_acceptance._e4_lease_timeout_diagnostic(
            {"COMPOSE_PROJECT_NAME": _PROJECT}, container, request_id
        )
        == "e4-lease-unclaimed"
    )
    assert observed == [
        (
            compose_acceptance._OWNER_E4_LEASE_OBSERVATION,
            {"B4_REQUEST_ID": request_id},
        )
    ]


def test_e4_lease_timeout_diagnostic_rejects_unstructured_owner_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        compose_acceptance,
        "_owner_python_in_e4_lease_blocker",
        lambda *_args, **_kwargs: "e4-lease-observation:secret-or-hostile-text",
    )

    assert (
        compose_acceptance._e4_lease_timeout_diagnostic(
            {"COMPOSE_PROJECT_NAME": _PROJECT}, "f" * 64, "00000000-0000-0000-0000-000000000001"
        )
        == "e4-lease-observation-unavailable"
    )


def test_e4_lease_blocker_outlives_the_real_lease_window() -> None:
    """The holder must not hit PostgreSQL's 60-second idle transaction timeout."""

    assert "idle_in_transaction_session_timeout" in compose_acceptance._OWNER_E4_LEASE_BLOCKER
    assert "conn.execute('SELECT 1')" in compose_acceptance._OWNER_E4_LEASE_BLOCKER
    assert "FOR UPDATE OF key_row" in compose_acceptance._OWNER_E4_LEASE_BLOCKER
    assert "LOCK TABLE public.subject_key" not in compose_acceptance._OWNER_E4_LEASE_BLOCKER


def test_e4_lease_blocker_receives_only_the_canonical_fenced_request_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    container = "9" * 64
    request_id = "00000000-0000-0000-0000-000000000001"
    tracker = compose_acceptance._AcceptanceResources(_PROJECT)
    tracker.containers.add(container)
    observed: dict[str, object] = {}
    listed = iter((set(), {container}))
    monkeypatch.setattr(compose_acceptance, "_ACTIVE_RESOURCES", tracker)
    monkeypatch.setattr(
        compose_acceptance,
        "_labelled_service_containers",
        lambda _environment, _service: next(listed),
    )

    def fake_compose(
        *arguments: str, environment: dict[str, str]
    ) -> subprocess.CompletedProcess[str]:
        observed["arguments"] = arguments
        observed["environment"] = environment
        return _completed(*arguments)

    def fake_docker(*arguments: str, check: bool = True) -> subprocess.CompletedProcess[str]:
        del check
        if arguments[:2] == ("container", "inspect"):
            return _completed(*arguments, stdout=_PROJECT + "\ndb-bootstrap\n")
        if arguments[0] == "logs":
            return _completed(*arguments, stdout="e4-lease-blocker: locked\n")
        pytest.fail("unexpected Docker operation")

    monkeypatch.setattr(compose_acceptance, "_compose", fake_compose)
    monkeypatch.setattr(compose_acceptance, "_docker_capture", fake_docker)

    assert (
        compose_acceptance._start_e4_lease_blocker(
            {"COMPOSE_PROJECT_NAME": _PROJECT}, request_id
        )
        == container
    )
    assert observed == {
        "arguments": (
            "run",
            "--detach",
            "--no-deps",
            "-e",
            "B4_REQUEST_ID",
            "--entrypoint",
            "python",
            "db-bootstrap",
            "-c",
            compose_acceptance._OWNER_E4_LEASE_BLOCKER,
        ),
        "environment": {"COMPOSE_PROJECT_NAME": _PROJECT, "B4_REQUEST_ID": request_id},
    }


def test_e4_lease_reclaim_pauses_before_request_and_releases_daemon_after_row_lock() -> None:
    source = inspect.getsource(compose_acceptance._run_e4_erasure_acceptance)
    reclaim = source[
        source.index("lease_blocker: str | None = None") : source.index(
            '_CURRENT_STEP = "e4-lease-reclaim-complete-status"'
        )
    ]

    assert reclaim.index("_pause_erasure_daemon") < reclaim.index("_request_e4_erasure")
    assert reclaim.index("_request_e4_erasure") < reclaim.index("_start_e4_lease_blocker")
    assert reclaim.index("_start_e4_lease_blocker") < reclaim.index("_resume_erasure_daemon")
    assert reclaim.index("_resume_erasure_daemon") < reclaim.index("_wait_for_e4_lease_generation")


def test_e4_lease_reclaim_recreates_only_the_erasure_daemon(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A PID-1 restart is not enough to prove the old claimant disappeared."""

    old_id, new_id = "c" * 64, "d" * 64
    states = iter(((old_id, 0, "old"), (new_id, 0, "new")))
    calls: list[tuple[str, ...]] = []

    def fake_state(_environment: dict[str, str]) -> tuple[str, int, str]:
        return next(states)

    def fake_compose(*arguments: str, environment: dict[str, str]) -> subprocess.CompletedProcess[str]:
        assert environment == {"COMPOSE_PROJECT_NAME": _PROJECT}
        calls.append(arguments)
        return _completed(*arguments)

    monkeypatch.setattr(compose_acceptance, "_erasure_restart_state", fake_state)
    monkeypatch.setattr(compose_acceptance, "_compose", fake_compose)
    monkeypatch.setattr(compose_acceptance, "_wait_for_erasure_serving_readiness", lambda _environment: None)

    compose_acceptance._restart_erasure_and_wait({"COMPOSE_PROJECT_NAME": _PROJECT})

    assert calls == [("up", "--detach", "--no-deps", "--force-recreate", "erasure")]


def test_e4_fault_once_requires_the_fixed_executor_command_to_fail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request_id = "00000000-0000-0000-0000-000000000001"
    calls: list[tuple[str, ...]] = []

    def must_fail(*arguments: str, environment: dict[str, str]) -> None:
        assert environment == {"COMPOSE_PROJECT_NAME": _PROJECT}
        calls.append(arguments)

    monkeypatch.setattr(compose_acceptance, "_compose_must_fail", must_fail)
    monkeypatch.setattr(
        compose_acceptance,
        "_compose",
        lambda *_arguments, **_kwargs: pytest.fail("the fault path must require a nonzero one-shot"),
    )

    compose_acceptance._run_e4_once(
        {"COMPOSE_PROJECT_NAME": _PROJECT},
        request_id,
        through_proxy=True,
        expects_block=True,
    )

    assert calls == [
        (
            "exec",
            "-T",
            "-e",
            "HTTP_PROXY=http://127.0.0.1:19876",
            "-e",
            "http_proxy=http://127.0.0.1:19876",
            "-e",
            "HTTPS_PROXY=",
            "-e",
            "https_proxy=",
            "-e",
            "ALL_PROXY=",
            "-e",
            "all_proxy=",
            "-e",
            "NO_PROXY=",
            "-e",
            "no_proxy=",
            "erasure",
            "tracebed-compose-erasure-once",
            request_id,
        )
    ]


def test_e4_fault_daemon_pause_uses_only_the_exact_labeled_container(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Each cycle externally stops only after an ack and owner cleanliness proof."""

    container = "e" * 64
    tracker = compose_acceptance._AcceptanceResources(_PROJECT)
    calls: list[tuple[str, ...]] = []
    phases: list[str] = []

    monkeypatch.setattr(compose_acceptance, "_ACTIVE_RESOURCES", tracker)

    def fake_compose(*arguments: str, environment: dict[str, str]) -> subprocess.CompletedProcess[str]:
        assert environment == {"COMPOSE_PROJECT_NAME": _PROJECT}
        if arguments == ("ps", "-q", "erasure"):
            return _completed(*arguments, stdout=container + "\n")
        raise AssertionError(arguments)

    def fake_docker(*arguments: str, check: bool = True) -> subprocess.CompletedProcess[str]:
        del check
        calls.append(arguments)
        if arguments[:2] == ("container", "inspect"):
            return _completed(*arguments, stdout=_PROJECT + "\n")
        return _completed(*arguments)

    monkeypatch.setattr(compose_acceptance, "_compose", fake_compose)
    monkeypatch.setattr(compose_acceptance, "_docker_capture", fake_docker)

    monkeypatch.setattr(
        compose_acceptance,
        "_assert_erasure_quiesce_ack_absent",
        lambda _environment: phases.append("ack-absent"),
    )
    monkeypatch.setattr(
        compose_acceptance,
        "_wait_for_erasure_quiesce_ack",
        lambda _environment, _deadline: phases.append("ack-valid"),
    )

    def owner_clean(
        _environment: dict[str, str], code: str, *, values: dict[str, str], timeout_seconds: float = 45.0
    ) -> None:
        assert code == compose_acceptance._OWNER_E4_PAUSED_DAEMON_CLEAN
        assert values == {}
        assert timeout_seconds > 0
        phases.append("owner-clean")

    monkeypatch.setattr(compose_acceptance, "_wait_for_owner_assertion", owner_clean)
    monkeypatch.setattr(
        compose_acceptance,
        "_wait_for_erasure_daemon_stopped",
        lambda _environment, _deadline: phases.append("stopped"),
    )
    monkeypatch.setattr(compose_acceptance, "_erasure_daemon_state", lambda _environment: "S")

    for _ in range(2):
        compose_acceptance._pause_erasure_daemon({"COMPOSE_PROJECT_NAME": _PROJECT})
        compose_acceptance._resume_erasure_daemon({"COMPOSE_PROJECT_NAME": _PROJECT})

    assert [call for call in calls if call[0] == "kill"] == [
        ("kill", "--signal", "USR1", container),
        ("kill", "--signal", "STOP", container),
        ("kill", "--signal", "CONT", container),
        ("kill", "--signal", "USR1", container),
        ("kill", "--signal", "STOP", container),
        ("kill", "--signal", "CONT", container),
    ]
    assert phases == [
        "ack-absent",
        "ack-valid",
        "owner-clean",
        "stopped",
        "ack-absent",
        "ack-absent",
        "ack-valid",
        "owner-clean",
        "stopped",
        "ack-absent",
    ]


def test_e4_quiesce_ack_timeout_fails_without_an_external_stop(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    container = "d" * 64
    tracker = compose_acceptance._AcceptanceResources(_PROJECT)
    calls: list[tuple[str, ...]] = []
    monkeypatch.setattr(compose_acceptance, "_ACTIVE_RESOURCES", tracker)

    def fake_compose(*arguments: str, environment: dict[str, str]) -> subprocess.CompletedProcess[str]:
        assert environment == {"COMPOSE_PROJECT_NAME": _PROJECT}
        if arguments == ("ps", "-q", "erasure"):
            return _completed(*arguments, stdout=container + "\n")
        raise AssertionError(arguments)

    def fake_docker(*arguments: str, check: bool = True) -> subprocess.CompletedProcess[str]:
        del check
        calls.append(arguments)
        if arguments[:2] == ("container", "inspect"):
            return _completed(*arguments, stdout=_PROJECT + "\n")
        return _completed(*arguments)

    monkeypatch.setattr(compose_acceptance, "_compose", fake_compose)
    monkeypatch.setattr(compose_acceptance, "_docker_capture", fake_docker)
    monkeypatch.setattr(compose_acceptance, "_assert_erasure_quiesce_ack_absent", lambda _environment: None)

    def ack_timeout(_environment: dict[str, str], _deadline: float) -> None:
        raise compose_acceptance.AcceptanceError("Compose-v1 acceptance check failed")

    monkeypatch.setattr(compose_acceptance, "_wait_for_erasure_quiesce_ack", ack_timeout)

    with pytest.raises(compose_acceptance.AcceptanceError):
        compose_acceptance._pause_erasure_daemon({"COMPOSE_PROJECT_NAME": _PROJECT})

    assert [call for call in calls if call[0] == "kill"] == [
        ("kill", "--signal", "USR1", container),
    ]


def test_e4_fault_proxy_proof_requires_the_version_delete_refusal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, ...]] = []

    def fake_compose(*arguments: str, environment: dict[str, str]) -> subprocess.CompletedProcess[str]:
        assert environment == {"COMPOSE_PROJECT_NAME": _PROJECT}
        calls.append(arguments)
        return _completed(*arguments, stdout="e4-object-fault: proxy-refused\n")

    monkeypatch.setattr(compose_acceptance, "_compose", fake_compose)
    compose_acceptance._assert_version_delete_proxy_refusal(
        {"COMPOSE_PROJECT_NAME": _PROJECT}
    )

    assert calls[0][:5] == ("exec", "-T", "erasure", "python", "-c")
    assert "events.count('version-delete-refused') != 1" in calls[0][-1]


def test_e4_fault_registers_the_request_only_after_pausing_the_daemon() -> None:
    """The normal poller must never win the fault-injection race."""

    source = inspect.getsource(compose_acceptance._run_e4_erasure_acceptance)
    fault_setup = source[source.index('subject_request = ""') : source.index('e4-object-fault-once')]

    assert fault_setup.index("_pause_erasure_daemon") < fault_setup.index("_request_e4_erasure")
    assert source.index("_run_e4_once(environment, subject_request, through_proxy=True, expects_block=True)") < source.index(
        "_assert_version_delete_proxy_refusal"
    )


def test_e4_project_request_requires_live_safe_boundary_quiesce() -> None:
    """The project one-shot proves a blocked admission returns before PID 1 stops."""

    source = inspect.getsource(compose_acceptance._run_e4_erasure_acceptance)
    project_setup = source[
        source.index('project_request = ""') : source.index("_run_e4_once(environment, project_request)")
    ]

    assert project_setup.index("_start_e4_admission_blocker") < project_setup.index(
        "_wait_for_e4_daemon_admission_wait"
    )
    assert project_setup.index("_wait_for_e4_daemon_admission_wait") < project_setup.index(
        "_request_erasure_daemon_quiesce"
    )
    assert project_setup.index("_request_erasure_daemon_quiesce") < project_setup.index(
        "_assert_erasure_daemon_not_quiesced"
    )
    assert project_setup.index("_assert_erasure_daemon_not_quiesced") < project_setup.index(
        "_stop_e4_admission_blocker"
    )
    assert project_setup.index("_stop_e4_admission_blocker") < project_setup.index(
        "_wait_for_erasure_daemon_quiesced"
    )
    assert project_setup.index("_wait_for_erasure_daemon_quiesced") < project_setup.index("_request_e4_erasure")

    quiesce = inspect.getsource(compose_acceptance._wait_for_erasure_daemon_quiesced)
    assert quiesce.index("_wait_for_erasure_quiesce_ack") < quiesce.index("_wait_for_owner_assertion")
    assert quiesce.index("_wait_for_owner_assertion") < quiesce.index(
        "_stop_erasure_daemon_after_quiesce_ack"
    )
    assert quiesce.index("_stop_erasure_daemon_after_quiesce_ack") < quiesce.index(
        "_wait_for_erasure_daemon_stopped"
    )


def test_e4_project_quiesce_observation_is_narrow_and_never_terminates_a_backend() -> None:
    assertion = compose_acceptance._OWNER_E4_PAUSED_DAEMON_CLEAN
    assert "pg_terminate_backend" not in assertion
    assert "tracebed_erasure" in assertion
    assert "10.77.16.3" in assertion
    assert "idle in transaction" in assertion
    assert "AccessShareLock" in assertion
    assert "PARTITIONED_TABLES" in assertion
    # The receipt proves that *all* idle E4-role sessions from the fixed
    # daemon IP have cleared, rather than trusting their previous query text.
    assert "query = %s" not in assertion
    assert "activity.query = %s" not in assertion


def test_e4_quiesce_ack_contract_matches_the_daemon_and_is_fail_closed() -> None:
    assert compose_acceptance._ERASURE_QUIESCE_ACK_PATH == erasure_runner._QUIESCE_ACK_PATH
    assert compose_acceptance._ERASURE_QUIESCE_ACK_CONTENT == erasure_runner._QUIESCE_ACK_CONTENT
    assert compose_acceptance._ERASURE_QUIESCE_ACK_MODE == erasure_runner._QUIESCE_ACK_MODE
    assert "os.O_NOFOLLOW" in compose_acceptance._ERASURE_QUIESCE_ACK_VALID
    assert "stat.S_ISREG" in compose_acceptance._ERASURE_QUIESCE_ACK_VALID
    assert "0o600" in compose_acceptance._ERASURE_QUIESCE_ACK_VALID
    assert "held.st_nlink != 1" in compose_acceptance._ERASURE_QUIESCE_ACK_VALID
    assert "named.st_nlink != 1" in compose_acceptance._ERASURE_QUIESCE_ACK_VALID
    assert "tracebed-erasure-quiesced-v1" in compose_acceptance._ERASURE_QUIESCE_ACK_ABSENT

    daemon = inspect.getsource(erasure_runner)
    assert "os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW" in daemon
    park = inspect.getsource(erasure_runner._park_at_safe_boundary)
    assert park.index("_quiesce_parked = True") < park.index("descriptor = _publish_quiesce_ack()")
    assert park.index("while not _quiesce_resume_requested") < park.index("_remove_quiesce_ack")


def test_worker_restart_requires_a_fixed_fresh_serving_readiness_probe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, ...]] = []

    def fake_compose(*arguments: str, environment: dict[str, str]) -> subprocess.CompletedProcess[str]:
        assert environment == {"COMPOSE_PROJECT_NAME": _PROJECT}
        calls.append(arguments)
        return _completed(
            *arguments,
            stdout="a" * 64 + "\n" if arguments == ("ps", "-q", "worker") else "",
        )

    monkeypatch.setattr(compose_acceptance, "_compose", fake_compose)
    monkeypatch.setattr(
        compose_acceptance.subprocess,
        "run",
        lambda arguments, **_kwargs: _completed(*arguments),
    )
    compose_acceptance._start_worker_and_require_serving_health(
        {"COMPOSE_PROJECT_NAME": _PROJECT}
    )

    assert calls == [
        (
            "up",
            "--detach",
            "worker",
        ),
        ("ps", "-q", "worker"),
    ]


def test_controller_sets_the_fixed_network_diagnostic_only_on_its_subprocess(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    environment = {"COMPOSE_PROJECT_NAME": _PROJECT}
    observed: dict[str, str] = {}

    def invoke(arguments: tuple[str, ...], **kwargs: object) -> subprocess.CompletedProcess[str]:
        del arguments
        value = kwargs.get("env")
        assert isinstance(value, dict)
        observed.update(value)
        return _completed("controller")

    monkeypatch.setattr(compose_acceptance, "_capture_resources", lambda _environment: None)
    monkeypatch.setattr(compose_acceptance.subprocess, "run", invoke)
    compose_acceptance._controller("upgrade", environment, succeeds=True)

    assert environment == {"COMPOSE_PROJECT_NAME": _PROJECT}
    assert observed == {
        "COMPOSE_PROJECT_NAME": _PROJECT,
        "TRACEBED_COMPOSE_NETWORK_DIAGNOSTIC": "1",
    }


def test_controller_records_only_fixed_lifecycle_diagnostics(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    sentinel = "secret-or-hostile-text"
    monkeypatch.setattr(compose_acceptance, "_capture_resources", lambda _environment: None)
    monkeypatch.setattr(compose_acceptance, "_CURRENT_DIAGNOSTIC", "")
    monkeypatch.setattr(
        compose_acceptance.subprocess,
        "run",
        lambda *_args, **_kwargs: _completed(
            "controller",
            returncode=1,
            stderr=(
                'Compose-v1 diagnostic {"code":"publish-one-shot-residue",'
                '"kind":"compose-v1-lifecycle"}\n' + sentinel
            ),
        ),
    )

    with pytest.raises(compose_acceptance.AcceptanceError):
        compose_acceptance._controller("upgrade", {"COMPOSE_PROJECT_NAME": _PROJECT}, succeeds=True)

    assert compose_acceptance._CURRENT_DIAGNOSTIC == "controller-upgrade-publish-one-shot-residue"
    assert sentinel not in capsys.readouterr().err


def test_controller_records_fixed_rollback_restore_diagnostic(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    sentinel = "secret-or-hostile-text"
    monkeypatch.setattr(compose_acceptance, "_capture_resources", lambda _environment: None)
    monkeypatch.setattr(compose_acceptance, "_CURRENT_DIAGNOSTIC", "")
    monkeypatch.setattr(
        compose_acceptance.subprocess,
        "run",
        lambda *_args, **_kwargs: _completed(
            "controller",
            returncode=1,
            stderr=(
                'Compose-v1 diagnostic {"code":"rollback-restore-closed-worker",'
                '"kind":"compose-v1-lifecycle"}\n' + sentinel
            ),
        ),
    )

    with pytest.raises(compose_acceptance.AcceptanceError):
        compose_acceptance._controller("rollback", {"COMPOSE_PROJECT_NAME": _PROJECT}, succeeds=True)

    assert compose_acceptance._CURRENT_DIAGNOSTIC == "controller-rollback-rollback-restore-closed-worker"
    assert sentinel not in capsys.readouterr().err


def test_controller_records_only_fixed_network_preflight_diagnostics(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    sentinel = "secret-or-hostile-text"
    monkeypatch.setattr(compose_acceptance, "_capture_resources", lambda _environment: None)
    monkeypatch.setattr(compose_acceptance, "_CURRENT_DIAGNOSTIC", "")
    monkeypatch.setattr(
        compose_acceptance.subprocess,
        "run",
        lambda *_args, **_kwargs: _completed(
            "controller",
            returncode=1,
            stderr=(
                'Compose-v1 diagnostic {"kind":"compose-v1-network-preflight",'
                '"reason":"owned-attachment-stage"}\n' + sentinel
            ),
        ),
    )

    with pytest.raises(compose_acceptance.AcceptanceError):
        compose_acceptance._controller("rollback", {"COMPOSE_PROJECT_NAME": _PROJECT}, succeeds=True)

    assert compose_acceptance._CURRENT_DIAGNOSTIC == "controller-rollback-network-owned-attachment-stage"
    assert sentinel not in capsys.readouterr().err
