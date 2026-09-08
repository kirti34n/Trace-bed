"""The supported Compose controller has a deliberately closed action surface."""

from __future__ import annotations

import json
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest
from scripts import compose_stack

pytestmark = pytest.mark.phase1
_ORIGINAL_HOST_NETWORK_ISOLATION = compose_stack._validate_host_network_isolation
_ORIGINAL_REQUIRE_WORKER_RUNNING = compose_stack._require_worker_running_for_drain
_ORIGINAL_PREPUBLICATION_PROBE = compose_stack._probe_closed_runtime_publication


@pytest.fixture(autouse=True)
def _bypass_host_secret_fixture(monkeypatch: pytest.MonkeyPatch) -> None:
    """Controller ordering tests use synthetic Compose output, not real files."""

    monkeypatch.setattr(compose_stack, "validate_compose_secret_source", lambda environment: None)
    monkeypatch.setattr(compose_stack, "_validate_host_network_isolation", lambda *_: None)
    monkeypatch.setattr(compose_stack, "_require_worker_running_for_drain", lambda: None)
    monkeypatch.setattr(compose_stack, "_probe_closed_runtime_publication", lambda: None)


def _rendered_topology() -> str:
    return json.dumps(
        {
            "name": "tracebed",
            "networks": {
                name: {
                    "ipam": {"config": [{"subnet": subnet}]},
                    **({"internal": True} if name in compose_stack._INTERNAL_NETWORKS else {}),
                }
                for name, subnet in compose_stack._NETWORK_SUBNETS.items()
            },
            "services": {
                service: {
                    "networks": {
                        network: {"ipv4_address": address}
                        for network, address in attachments.items()
                    }
                }
                for service, attachments in compose_stack._STATIC_ATTACHMENTS.items()
            },
        }
    )


def _completed(arguments: tuple[str, ...]) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(
        arguments,
        0,
        stdout=(
            _rendered_topology()
            if arguments == ("config", "--format", "json")
            else "0\n"
            if arguments == ("exec", "-T", "worker", "tracebed-compose-worker-drain")
            else ""
        ),
        stderr="",
    )


def _owned_network_inventory(
    project: str = "tracebed",
    *,
    attachments_by_service: dict[str, dict[str, str]] | None = None,
) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    """A complete authenticated six-network stack, including stopped runtime.

    The inventory mirrors Docker's network/container inspect shape closely so
    the controller tests exercise ownership proof, rather than a label-only
    shortcut.
    """

    network_entries: list[dict[str, object]] = []
    expected = (
        compose_stack._SUSTAINED_ATTACHMENTS
        if attachments_by_service is None
        else attachments_by_service
    )
    container_ids = {service: f"{index:064x}" for index, service in enumerate(expected, 1)}
    by_network = compose_stack._expected_stage_attachments(expected)
    for index, (logical, subnet) in enumerate(compose_stack._NETWORK_SUBNETS.items(), 1):
        network = compose_stack._parsed_network(subnet)
        endpoints = {
            container_ids[service]: {"IPv4Address": f"{address}/{network.prefixlen}"}
            for service, address in by_network[logical].items()
        }
        network_entries.append(
            {
                "Name": compose_stack._expected_network_name(project, logical),
                "Id": f"{index + 100:064x}",
                "Labels": {
                    "com.docker.compose.config-hash": "0" * 64,
                    "com.docker.compose.project": project,
                    "com.docker.compose.network": logical,
                    "com.docker.compose.version": "5.3.1",
                },
                "Driver": "bridge",
                "Scope": "local",
                "Internal": logical in compose_stack._INTERNAL_NETWORKS,
                "EnableIPv4": True,
                "EnableIPv6": False,
                "Attachable": False,
                "Ingress": False,
                "ConfigOnly": False,
                "Options": {},
                "IPAM": {
                    "Driver": "default",
                    "Options": None,
                    "Config": [{"Subnet": subnet, "Gateway": compose_stack._expected_gateway(network)}],
                },
                "Containers": endpoints,
            }
        )
    containers: list[dict[str, object]] = []
    for service, identifier in container_ids.items():
        attachments = expected[service]
        containers.append(
            {
                "Id": identifier,
                "Name": f"/{project}-{service}-1",
                "Config": {
                    "Labels": {
                        "com.docker.compose.project": project,
                        "com.docker.compose.service": service,
                        "com.docker.compose.container-number": "1",
                    }
                },
                "State": {
                    "Running": service in compose_stack._CORE_SERVICES,
                    "Status": "running" if service in compose_stack._CORE_SERVICES else "exited",
                },
                "NetworkSettings": {
                    "Networks": {
                        compose_stack._expected_network_name(project, logical): {"IPAddress": address}
                        for logical, address in attachments.items()
                    }
                },
            }
        )
    return network_entries, containers


def _install_owned_network_inventory(
    monkeypatch: pytest.MonkeyPatch, networks: list[dict[str, object]], containers: list[dict[str, object]]
) -> None:
    """Install only the closed Docker inspect protocol used by ownership proof."""

    def readonly(*arguments: str) -> subprocess.CompletedProcess[str]:
        if arguments[:2] == ("network", "ls"):
            return subprocess.CompletedProcess(arguments, 0, stdout="\n".join(str(item["Id"]) for item in networks), stderr="")
        if arguments[:2] == ("network", "inspect"):
            return subprocess.CompletedProcess(arguments, 0, stdout=json.dumps(networks), stderr="")
        if arguments[:2] == ("container", "inspect"):
            return subprocess.CompletedProcess(arguments, 0, stdout=json.dumps(containers), stderr="")
        raise AssertionError(arguments)

    monkeypatch.setattr(compose_stack, "_docker_readonly", readonly)


def test_start_has_fixed_core_bootstrap_init_and_publication_order(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, ...]] = []

    def fake_run(*arguments: str) -> subprocess.CompletedProcess[str]:
        calls.append(arguments)
        return _completed(arguments)

    monkeypatch.setattr(compose_stack, "_run", fake_run)
    compose_stack.start()
    actions = [call[5] for call in calls if call[:5] == ("run", "--build", "--rm", "--no-deps", "-e")]
    assert calls[:4] == [
        ("config", "--quiet"),
        ("config", "--format", "json"),
        ("ps", "--all", "--services"),
        ("up", "--detach", "--wait", "postgres"),
    ]
    assert ("build", *compose_stack._BUILT_SERVICES) in calls
    assert actions == [
        "TB_DB_BOOTSTRAP_ACTION=start-preflight",
        "TB_DB_BOOTSTRAP_ACTION=apply",
        "TB_DB_BOOTSTRAP_ACTION=cutover-0012-closed",
        "TB_DB_BOOTSTRAP_ACTION=cutover-0013",
        "TB_DB_BOOTSTRAP_ACTION=admission-open",
    ]
    assert ("up", "--detach", "api", "edge", "worker", "erasure", "dashboard") in calls


def test_upgrade_and_rollback_close_admission_drain_then_stop_worker_before_owner_action(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, ...]] = []

    def fake_run(*arguments: str) -> subprocess.CompletedProcess[str]:
        calls.append(arguments)
        return _completed(arguments)

    monkeypatch.setattr(compose_stack, "_run", fake_run)
    monkeypatch.setattr(compose_stack, "_restore_closed_worker_after_rollback", lambda: None)
    compose_stack.rollback()
    assert calls[:5] == [
        ("config", "--quiet"),
        ("config", "--format", "json"),
        ("stop", "--timeout", "30", "dashboard", "edge", "api"),
        ("ps", "--status", "running", "--services"),
        ("stop", "--timeout", "30", "erasure"),
    ]
    erasure_drain = calls.index(
        ("run", "--build", "--rm", "--no-deps", "-e", "TB_DB_BOOTSTRAP_ACTION=erasure-drain-assert", "db-bootstrap")
    )
    admission_close = calls.index(
        ("run", "--build", "--rm", "--no-deps", "-e", "TB_DB_BOOTSTRAP_ACTION=admission-close", "db-bootstrap")
    )
    worker_stop = calls.index(("stop", "--timeout", "30", "worker"))
    rollback = calls.index(
        ("run", "--build", "--rm", "--no-deps", "-e", "TB_DB_BOOTSTRAP_ACTION=rollback", "db-bootstrap")
    )
    assert erasure_drain < admission_close < worker_stop < rollback


def test_successful_rollback_restores_closed_worker_for_the_next_upgrade(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A rollback never strands the controller without its drain consumer."""

    calls: list[tuple[str, ...]] = []
    bootstrap_actions: list[str] = []
    events: list[str] = []
    worker_running = False

    def fake_run(*arguments: str) -> subprocess.CompletedProcess[str]:
        nonlocal worker_running
        calls.append(arguments)
        if arguments == ("up", "--detach", "worker"):
            events.append("worker-up")
        elif arguments == ("exec", "-T", "worker", "tracebed-compose-worker-prepublication-ready"):
            events.append("worker-closed-ready")
        if arguments == ("up", "--detach", "worker"):
            worker_running = True
        elif arguments in {
            ("stop", "--timeout", "30", "worker"),
            ("rm", "--force", "worker"),
        }:
            worker_running = False
        if arguments == ("ps", "--status", "running", "--services"):
            return subprocess.CompletedProcess(
                arguments,
                0,
                stdout="worker\n" if worker_running else "",
                stderr="",
            )
        if arguments == ("exec", "-T", "worker", "tracebed-compose-worker-drain"):
            return subprocess.CompletedProcess(arguments, 0, stdout="0\n", stderr="")
        return _completed(arguments)

    monkeypatch.setattr(compose_stack, "_validate_rendered_configuration", lambda: None)
    monkeypatch.setattr(compose_stack, "_run", fake_run)
    monkeypatch.setattr(
        compose_stack,
        "_run_bootstrap",
        lambda action, **_kwargs: (bootstrap_actions.append(action), events.append("bootstrap-" + action)),
    )
    monkeypatch.setattr(compose_stack, "_build_local_images", lambda: None)
    monkeypatch.setattr(compose_stack, "_recreate_postgres_for_upgrade", lambda: None)
    monkeypatch.setattr(compose_stack, "_publish_runtime", lambda: None)

    compose_stack.rollback()

    rollback_index = events.index("bootstrap-rollback")
    assert events[rollback_index + 1 : rollback_index + 3] == [
        "bootstrap-admission-assert-closed",
        "worker-up",
    ]
    assert ("exec", "-T", "worker", "tracebed-compose-worker-prepublication-ready") in calls
    assert bootstrap_actions[-1] == "admission-assert-closed"

    # This is the actual next supported lifecycle action, not a direct
    # Compose repair: the restored closed worker satisfies upgrade's drain
    # prerequisite and is removed again only by the controller.
    compose_stack.upgrade()
    assert calls.count(("stop", "--timeout", "30", "worker")) >= 2
    assert bootstrap_actions.count("runtime-drain-assert") >= 2


def test_active_0013_rollback_refusal_restores_closed_worker_for_supported_upgrade(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The defined post-activity refusal is recoverable without raw Compose."""

    calls: list[tuple[str, ...]] = []
    bootstrap_actions: list[str] = []
    events: list[str] = []
    worker_running = False

    def fake_run(*arguments: str) -> subprocess.CompletedProcess[str]:
        nonlocal worker_running
        calls.append(arguments)
        if arguments == ("up", "--detach", "worker"):
            worker_running = True
            events.append("worker-up")
        elif arguments in {
            ("stop", "--timeout", "30", "worker"),
            ("rm", "--force", "worker"),
        }:
            worker_running = False
        elif arguments == ("exec", "-T", "worker", "tracebed-compose-worker-prepublication-ready"):
            events.append("worker-closed-ready")
        if arguments == ("ps", "--status", "running", "--services"):
            return subprocess.CompletedProcess(
                arguments, 0, stdout="worker\n" if worker_running else "", stderr=""
            )
        if arguments == ("exec", "-T", "worker", "tracebed-compose-worker-drain"):
            return subprocess.CompletedProcess(arguments, 0, stdout="0\n", stderr="")
        return _completed(arguments)

    def fake_bootstrap(action: str, **_kwargs: object) -> None:
        bootstrap_actions.append(action)
        events.append("bootstrap-" + action)
        if action == "rollback":
            raise compose_stack.ComposeStackError("Compose-v1 lifecycle operation failed")

    monkeypatch.setattr(compose_stack, "_validate_rendered_configuration", lambda: None)
    monkeypatch.setattr(compose_stack, "_run", fake_run)
    monkeypatch.setattr(compose_stack, "_run_bootstrap", fake_bootstrap)
    monkeypatch.setattr(compose_stack, "_build_local_images", lambda: None)
    monkeypatch.setattr(compose_stack, "_recreate_postgres_for_upgrade", lambda: None)
    monkeypatch.setattr(compose_stack, "_publish_runtime", lambda: None)

    with pytest.raises(compose_stack.ComposeStackError):
        compose_stack.rollback()

    refusal = events.index("bootstrap-rollback")
    assert events[refusal + 1 : refusal + 4] == [
        "bootstrap-rollback-refusal-recovery-preflight",
        "bootstrap-admission-assert-closed",
        "worker-up",
    ]
    assert "worker-closed-ready" in events

    # The worker was restored only through the authenticated controller
    # bridge; the actual next supported action can therefore drain it.
    compose_stack.upgrade()
    assert calls.count(("stop", "--timeout", "30", "worker")) >= 2
    assert bootstrap_actions.count("runtime-drain-assert") >= 2


def test_ambiguous_rollback_failure_never_restores_a_worker(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Only the explicit active-0013 proof may recover a refused rollback."""

    actions: list[str] = []
    restored: list[bool] = []

    monkeypatch.setattr(compose_stack, "_validate_rendered_configuration", lambda: None)
    monkeypatch.setattr(compose_stack, "_fence_and_drain_runtime", lambda: None)

    def failed_bootstrap(action: str, **_kwargs: object) -> None:
        actions.append(action)
        raise compose_stack.ComposeStackError("Compose-v1 lifecycle operation failed")

    monkeypatch.setattr(compose_stack, "_run_bootstrap", failed_bootstrap)
    monkeypatch.setattr(
        compose_stack,
        "_restore_closed_worker_after_rollback",
        lambda: restored.append(True),
    )

    with pytest.raises(compose_stack.ComposeStackError):
        compose_stack.rollback()

    assert actions == ["rollback", "rollback-refusal-recovery-preflight"]
    assert restored == []


@pytest.mark.parametrize(
    ("failing_phase", "expected_diagnostic"),
    [
        ("rendered", "rollback-rendered-preflight"),
        ("fence", "rollback-fence-drain"),
        ("bootstrap", "rollback-bootstrap"),
        ("restore", "rollback-restore-closed-worker"),
    ],
)
def test_rollback_emits_only_fixed_phase_diagnostics(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    failing_phase: str,
    expected_diagnostic: str,
) -> None:
    monkeypatch.setenv("TRACEBED_COMPOSE_NETWORK_DIAGNOSTIC", "1")
    monkeypatch.setattr(compose_stack, "_validate_rendered_configuration", lambda: None)
    monkeypatch.setattr(compose_stack, "_fence_and_drain_runtime", lambda: None)
    monkeypatch.setattr(compose_stack, "_run_bootstrap", lambda _action, **_kwargs: None)
    monkeypatch.setattr(compose_stack, "_restore_closed_worker_after_rollback", lambda: None)

    if failing_phase == "rendered":
        monkeypatch.setattr(
            compose_stack,
            "_validate_rendered_configuration",
            lambda: (_ for _ in ()).throw(compose_stack.ComposeStackError("opaque")),
        )
    elif failing_phase == "fence":
        monkeypatch.setattr(
            compose_stack,
            "_fence_and_drain_runtime",
            lambda: (_ for _ in ()).throw(compose_stack.ComposeStackError("opaque")),
        )
    elif failing_phase == "bootstrap":
        def fail_only_rollback(action: str, **_kwargs: object) -> None:
            if action == "rollback":
                raise compose_stack.ComposeStackError("opaque")

        monkeypatch.setattr(
            compose_stack,
            "_run_bootstrap",
            fail_only_rollback,
        )
    else:
        monkeypatch.setattr(
            compose_stack,
            "_restore_closed_worker_after_rollback",
            lambda: (_ for _ in ()).throw(compose_stack.ComposeStackError("opaque")),
        )

    with pytest.raises(compose_stack.ComposeStackError):
        compose_stack.rollback()

    assert capsys.readouterr().err == (
        "Compose-v1 diagnostic "
        + '{"code":"'
        + expected_diagnostic
        + '","kind":"compose-v1-lifecycle"}\n'
    )


def test_rendered_preflight_emits_fixed_config_diagnostic(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("TRACEBED_COMPOSE_NETWORK_DIAGNOSTIC", "1")
    monkeypatch.setattr(
        compose_stack,
        "_run",
        lambda *_arguments: (_ for _ in ()).throw(compose_stack.ComposeStackError("opaque")),
    )

    with pytest.raises(compose_stack.ComposeStackError):
        compose_stack._validate_rendered_configuration()

    assert capsys.readouterr().err == (
        'Compose-v1 diagnostic {"code":"rendered-compose-config",'
        '"kind":"compose-v1-lifecycle"}\n'
    )


def test_controller_builds_every_local_runtime_image_before_publication(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, ...]] = []

    def fake_run(*arguments: str) -> subprocess.CompletedProcess[str]:
        calls.append(arguments)
        return _completed(arguments)

    monkeypatch.setattr(compose_stack, "_run", fake_run)
    compose_stack.upgrade()
    build_index = calls.index(("build", *compose_stack._BUILT_SERVICES))
    assert calls[build_index + 1] == ("up", "--detach", "--wait", "--force-recreate", "postgres")
    assert ("run", "--build", "--rm", "--no-deps", "s3-volume-init") not in calls


def test_start_refuses_existing_runtime_containers_before_any_build(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, ...]] = []
    monkeypatch.setattr(compose_stack, "_validate_rendered_configuration", lambda: None)

    def fake_run(*arguments: str) -> subprocess.CompletedProcess[str]:
        calls.append(arguments)
        return subprocess.CompletedProcess(arguments, 0, stdout="api\n", stderr="")

    monkeypatch.setattr(compose_stack, "_run", fake_run)
    with pytest.raises(compose_stack.ComposeStackError, match="use upgrade"):
        compose_stack.start()
    assert calls == [("ps", "--all", "--services")]


@pytest.mark.parametrize("runtime_state", ("api\n", "edge\n", "worker\n", "dashboard\n"))
def test_start_refuses_each_partial_runtime_container(
    monkeypatch: pytest.MonkeyPatch, runtime_state: str
) -> None:
    monkeypatch.setattr(compose_stack, "_validate_rendered_configuration", lambda: None)
    monkeypatch.setattr(
        compose_stack,
        "_run",
        lambda *arguments: subprocess.CompletedProcess(arguments, 0, stdout=runtime_state, stderr=""),
    )
    with pytest.raises(compose_stack.ComposeStackError, match="use upgrade"):
        compose_stack.start()


def test_start_refuses_existing_core_when_owner_cannot_prove_drained_closed_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, ...]] = []
    monkeypatch.setattr(compose_stack, "_validate_rendered_configuration", lambda: None)

    def fake_run(*arguments: str) -> subprocess.CompletedProcess[str]:
        calls.append(arguments)
        output = (
            "postgres\nvalkey\nseaweedfs\n"
            if arguments
            in {
                ("ps", "--all", "--services"),
                ("ps", "--status", "running", "--services"),
            }
            else ""
        )
        return subprocess.CompletedProcess(arguments, 0, stdout=output, stderr="")

    monkeypatch.setattr(compose_stack, "_run", fake_run)
    monkeypatch.setattr(
        compose_stack,
        "_run_bootstrap",
        lambda action, **_kwargs: (_ for _ in ()).throw(compose_stack.ComposeStackError(action)),
    )
    with pytest.raises(compose_stack.ComposeStackError, match="use upgrade"):
        compose_stack.start()
    assert calls == [
        ("ps", "--all", "--services"),
        ("ps", "--status", "running", "--services"),
    ]


@pytest.mark.parametrize("state", ("stopped", "restarting", "created", "dead"))
def test_start_rejects_every_nonrunning_postgres_partial_state(
    monkeypatch: pytest.MonkeyPatch, state: str
) -> None:
    """`ps -q` must not make a retained but non-running cluster look empty."""

    del state  # The Compose status query exposes each as absent from `running`.
    monkeypatch.setattr(compose_stack, "_validate_rendered_configuration", lambda: None)

    def fake_run(*arguments: str) -> subprocess.CompletedProcess[str]:
        output = (
            "postgres\nvalkey\nseaweedfs\n"
            if arguments == ("ps", "--all", "--services")
            else "valkey\nseaweedfs\n"
            if arguments == ("ps", "--status", "running", "--services")
            else ""
        )
        return subprocess.CompletedProcess(arguments, 0, stdout=output, stderr="")

    monkeypatch.setattr(compose_stack, "_run", fake_run)
    with pytest.raises(compose_stack.ComposeStackError, match="use upgrade"):
        compose_stack.start()


def test_start_with_no_postgres_container_starts_isolated_pg_then_owner_preflights(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A retained volume cannot bypass the owner check merely by lacking a container."""

    calls: list[tuple[str, ...]] = []
    actions: list[str] = []
    monkeypatch.setattr(compose_stack, "_validate_rendered_configuration", lambda: None)
    monkeypatch.setattr(
        compose_stack,
        "_run",
        lambda *arguments: calls.append(arguments) or _completed(arguments),
    )
    monkeypatch.setattr(
        compose_stack,
        "_run_bootstrap",
        lambda action, **_kwargs: actions.append(action),
    )
    monkeypatch.setattr(compose_stack, "_build_local_images", lambda: None)
    monkeypatch.setattr(compose_stack, "_prepare_s3_volume", lambda: None)
    monkeypatch.setattr(compose_stack, "_publish_runtime", lambda: None)

    compose_stack.start()

    assert calls == [
        ("ps", "--all", "--services"),
        ("up", "--detach", "--wait", "postgres"),
        ("up", "--detach", "--wait", "valkey", "seaweedfs"),
    ]
    assert actions == ["start-preflight"]


@pytest.mark.parametrize("failure", ("apply", "s3", "runtime-up", "prepublication-probe", "residue-precheck"))
def test_every_prepublication_failure_stops_runtime_and_never_opens_admission(
    monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    actions: list[str] = []
    stops: list[str] = []

    def bootstrap(action: str, **_kwargs: object) -> None:
        actions.append(action)
        if failure == "apply" and action == "apply":
            raise compose_stack.ComposeStackError("apply")

    monkeypatch.setattr(compose_stack, "_run_bootstrap", bootstrap)
    monkeypatch.setattr(
        compose_stack,
        "_run_s3_init",
        lambda: (_ for _ in ()).throw(compose_stack.ComposeStackError("s3"))
        if failure == "s3"
        else None,
    )
    monkeypatch.setattr(
        compose_stack,
        "_run",
        lambda *arguments: (_ for _ in ()).throw(compose_stack.ComposeStackError("up"))
        if failure == "runtime-up"
        else subprocess.CompletedProcess(arguments, 0, stdout="", stderr=""),
    )
    monkeypatch.setattr(
        compose_stack,
        "_probe_closed_runtime_publication",
        lambda: (_ for _ in ()).throw(compose_stack.ComposeStackError("probe"))
        if failure == "prepublication-probe"
        else None,
    )
    monkeypatch.setattr(
        compose_stack,
        "_assert_no_one_shot_container",
        lambda: (_ for _ in ()).throw(compose_stack.ComposeStackError("residue"))
        if failure == "residue-precheck"
        else None,
    )
    monkeypatch.setattr(compose_stack, "_stop_runtime", lambda: stops.append("stopped"))

    with pytest.raises(compose_stack.ComposeStackError):
        compose_stack._publish_runtime()
    assert "admission-open" not in actions
    assert stops == ["stopped"]
    if failure != "apply":
        assert actions[-1] == "admission-assert-closed"


def test_admission_open_is_final_publication_mutation_after_closed_probes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    monkeypatch.setattr(
        compose_stack,
        "_run_bootstrap",
        lambda action, **kwargs: events.append(action + ("-terminal" if kwargs else "")),
    )
    monkeypatch.setattr(compose_stack, "_run_s3_init", lambda: events.append("s3"))
    monkeypatch.setattr(compose_stack, "_run", lambda *_: events.append("runtime-up") or _completed(()))
    monkeypatch.setattr(compose_stack, "_probe_closed_runtime_publication", lambda: events.append("probe"))
    monkeypatch.setattr(compose_stack, "_assert_no_one_shot_container", lambda: events.append("residue-precheck"))
    compose_stack._publish_runtime()
    assert events == [
        "apply",
        "cutover-0012-closed",
        "cutover-0013",
        "s3",
        "runtime-up",
        "probe",
        "residue-precheck",
        "admission-open-terminal",
    ]


def test_residue_precheck_diagnostic_is_fixed_and_secret_safe(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("TRACEBED_COMPOSE_NETWORK_DIAGNOSTIC", "1")
    monkeypatch.setattr(compose_stack, "_run_bootstrap", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(compose_stack, "_run_s3_init", lambda: None)
    monkeypatch.setattr(compose_stack, "_run", lambda *_args: _completed(()))
    monkeypatch.setattr(compose_stack, "_probe_closed_runtime_publication", lambda: None)
    monkeypatch.setattr(
        compose_stack,
        "_assert_no_one_shot_container",
        lambda: (_ for _ in ()).throw(compose_stack.ComposeStackError("secret-or-hostile-text")),
    )
    monkeypatch.setattr(compose_stack, "_stop_runtime", lambda: None)

    with pytest.raises(compose_stack.ComposeStackError):
        compose_stack._publish_runtime()

    diagnostic = capsys.readouterr().err
    assert "secret-or-hostile-text" not in diagnostic
    assert json.loads(diagnostic.removeprefix("Compose-v1 diagnostic ")) == {
        "code": "publish-one-shot-residue",
        "kind": "compose-v1-lifecycle",
    }


def test_ambiguous_admission_open_stops_runtime_closes_and_proves_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []

    def bootstrap(action: str, **_kwargs: object) -> None:
        events.append(action)
        if action == "admission-open":
            raise compose_stack.ComposeStackError("ambiguous-open")

    monkeypatch.setattr(compose_stack, "_run_bootstrap", bootstrap)
    monkeypatch.setattr(compose_stack, "_run_s3_init", lambda: events.append("s3"))
    monkeypatch.setattr(compose_stack, "_run", lambda *_: _completed(()))
    monkeypatch.setattr(compose_stack, "_probe_closed_runtime_publication", lambda: events.append("probe"))
    monkeypatch.setattr(compose_stack, "_assert_no_one_shot_container", lambda: events.append("residue"))
    monkeypatch.setattr(compose_stack, "_stop_runtime", lambda: events.append("stop-runtime"))

    with pytest.raises(compose_stack.ComposeStackError, match="ambiguous-open"):
        compose_stack._publish_runtime()
    assert events == [
        "apply",
        "cutover-0012-closed",
        "cutover-0013",
        "s3",
        "probe",
        "residue",
        "admission-open",
        "stop-runtime",
        "admission-close",
        "admission-assert-closed",
    ]


def test_controller_lifecycle_lock_serializes_complete_actions(monkeypatch: pytest.MonkeyPatch) -> None:
    """Two callers cannot interleave validation and final publication."""

    entered = threading.Event()
    release = threading.Event()
    events: list[str] = []

    def action() -> None:
        events.append("entered")
        if len(events) == 1:
            entered.set()
            assert release.wait(timeout=2)
        events.append("finished")

    monkeypatch.setattr(compose_stack, "_start", action)
    first = threading.Thread(target=compose_stack.start)
    second = threading.Thread(target=compose_stack.start)
    first.start()
    assert entered.wait(timeout=2)
    second.start()
    time.sleep(0.05)
    assert events == ["entered"]
    release.set()
    first.join(timeout=2)
    second.join(timeout=2)
    assert not first.is_alive() and not second.is_alive()
    assert events == ["entered", "finished", "entered", "finished"]


def test_controller_lifecycle_lock_blocks_a_second_process_until_action_completion() -> None:
    """The lock is not merely a same-process/thread convention."""

    program = (
        "from scripts.compose_stack import _controller_lifecycle_lock\n"
        "with _controller_lifecycle_lock():\n"
        "    print('acquired', flush=True)\n"
    )
    root = Path(__file__).resolve().parents[2]
    with compose_stack._controller_lifecycle_lock():
        contender = subprocess.Popen(  # noqa: S603 - fixed interpreter and self-contained probe
            (sys.executable, "-c", program),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=root,
        )
        time.sleep(0.05)
        assert contender.poll() is None
    stdout, stderr = contender.communicate(timeout=2)
    assert contender.returncode == 0, stderr
    assert stdout == "acquired\n"


def test_topology_preflight_rejects_a_static_address_collision() -> None:
    document = json.loads(_rendered_topology())
    document["services"]["api"]["networks"]["pg-api"]["ipv4_address"] = "10.77.11.2"
    with pytest.raises(compose_stack.ComposeStackError):
        compose_stack._validate_fixed_topology(document)


def test_host_ipam_overlap_is_refused_before_any_compose_mutation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    outputs = iter(
        (
            subprocess.CompletedProcess(("docker", "network", "ls"), 0, stdout="foreign\n", stderr=""),
            subprocess.CompletedProcess(
                ("docker", "network", "inspect", "foreign"),
                0,
                stdout=json.dumps([{"IPAM": {"Config": [{"Subnet": "10.77.11.0/29"}]}}]),
                stderr="",
            ),
        )
    )
    monkeypatch.setattr(compose_stack, "_docker_readonly", lambda *_: next(outputs))
    monkeypatch.setattr(compose_stack.sys, "platform", "darwin")
    with pytest.raises(compose_stack.ComposeStackError):
        _ORIGINAL_HOST_NETWORK_ISOLATION()


def test_same_prefix_nonoverlap_docker_network_is_allowed_on_nonlinux(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    outputs = iter(
        (
            subprocess.CompletedProcess(("docker", "network", "ls"), 0, stdout="foreign\n", stderr=""),
            subprocess.CompletedProcess(
                ("docker", "network", "inspect", "foreign"),
                0,
                stdout=json.dumps([{"IPAM": {"Config": [{"Subnet": "10.76.0.0/16"}]}}]),
                stderr="",
            ),
        )
    )
    monkeypatch.setattr(compose_stack, "_docker_readonly", lambda *_: next(outputs))
    monkeypatch.setattr(compose_stack.sys, "platform", "darwin")
    _ORIGINAL_HOST_NETWORK_ISOLATION()


def test_builtin_host_and_none_without_ipam_are_not_treated_as_overlap(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    outputs = iter(
        (
            subprocess.CompletedProcess(("docker", "network", "ls"), 0, stdout="host\nnone\n", stderr=""),
            subprocess.CompletedProcess(
                ("docker", "network", "inspect", "host", "none"),
                0,
                stdout=json.dumps(
                    [
                        {"Name": "host", "IPAM": {"Config": None}},
                        {"Name": "none", "IPAM": {"Config": None}},
                    ]
                ),
                stderr="",
            ),
        )
    )
    monkeypatch.setattr(compose_stack, "_docker_readonly", lambda *_: next(outputs))
    monkeypatch.setattr(compose_stack.sys, "platform", "darwin")
    _ORIGINAL_HOST_NETWORK_ISOLATION()


def test_only_a_complete_exact_owned_network_set_receives_an_overlap_exemption(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    networks, containers = _owned_network_inventory()
    _install_owned_network_inventory(monkeypatch, networks, containers)
    monkeypatch.setattr(compose_stack.sys, "platform", "darwin")
    _ORIGINAL_HOST_NETWORK_ISOLATION("tracebed")


def test_complete_core_only_stage_is_authenticated_without_accepting_foreign_attachments(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    networks, containers = _owned_network_inventory()
    core_ids = {
        str(container["Id"])
        for container in containers
        if container["Config"]["Labels"]["com.docker.compose.service"] in compose_stack._CORE_SERVICES  # type: ignore[index]
    }
    for network in networks:
        network["Containers"] = {  # type: ignore[index]
            identifier: endpoint
            for identifier, endpoint in network["Containers"].items()  # type: ignore[index]
            if identifier in core_ids
        }
    containers = [container for container in containers if str(container["Id"]) in core_ids]
    _install_owned_network_inventory(monkeypatch, networks, containers)
    monkeypatch.setattr(compose_stack.sys, "platform", "darwin")
    _ORIGINAL_HOST_NETWORK_ISOLATION("tracebed")


def test_forged_or_partial_current_project_networks_fail_before_any_exemption(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Regression matrix for the former label-only ownership bypass."""

    for mutate in (
        lambda networks, containers: networks.pop(),
        lambda networks, containers: networks[0].__setitem__("Name", "tracebed_forged"),
        lambda networks, containers: networks[0]["Labels"].__setitem__("com.docker.compose.network", "pg-api"),  # type: ignore[index]
        lambda networks, containers: networks[0]["IPAM"].__setitem__(  # type: ignore[index]
            "Config", [{"Subnet": "10.77.10.0/28", "Gateway": "10.77.10.1"}]
        ),
        lambda networks, containers: networks[0].__setitem__("Driver", "overlay"),
        lambda networks, containers: networks[0].__setitem__("Internal", False),
        lambda networks, containers: networks[0].__setitem__("Options", {"forged": "1"}),
        lambda networks, containers: networks.append(dict(networks[0])),
        lambda networks, containers: networks[0]["Containers"].__setitem__(  # type: ignore[index]
            "f" * 64, {"IPv4Address": "10.77.10.6/29"}
        ),
    ):
        networks, containers = _owned_network_inventory()
        mutate(networks, containers)
        _install_owned_network_inventory(monkeypatch, networks, containers)
        monkeypatch.setattr(compose_stack.sys, "platform", "darwin")
        with pytest.raises(compose_stack.ComposeStackError):
            _ORIGINAL_HOST_NETWORK_ISOLATION("tracebed")


def test_owned_route_requires_exact_bridge_device_and_main_table(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    networks, containers = _owned_network_inventory()
    _install_owned_network_inventory(monkeypatch, networks, containers)
    pg_api = next(network for network in networks if network["Name"] == "tracebed_pg-api")
    route = {
        "dst": "10.77.11.0/29",
        "table": "main",
        "dev": "br-" + str(pg_api["Id"])[:12],
        "protocol": "kernel",
        "scope": "link",
        "flags": [],
    }
    monkeypatch.setattr(compose_stack.sys, "platform", "linux")
    monkeypatch.setattr(compose_stack.shutil, "which", lambda _: "/usr/sbin/ip")

    def ip_run(arguments: tuple[str, ...], **_: object) -> subprocess.CompletedProcess[str]:
        if arguments == ("ip", "-j", "rule", "show"):
            return subprocess.CompletedProcess(arguments, 0, stdout="[]", stderr="")
        return subprocess.CompletedProcess(arguments, 0, stdout=json.dumps([route]), stderr="")

    monkeypatch.setattr(compose_stack.subprocess, "run", ip_run)
    _ORIGINAL_HOST_NETWORK_ISOLATION("tracebed")
    route["table"] = "52"
    with pytest.raises(compose_stack.ComposeStackError):
        _ORIGINAL_HOST_NETWORK_ISOLATION("tracebed")


def test_owned_bridge_local_route_companions_require_the_complete_kernel_shape(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    networks, containers = _owned_network_inventory()
    _install_owned_network_inventory(monkeypatch, networks, containers)
    pg_api = next(network for network in networks if network["Name"] == "tracebed_pg-api")
    device = "br-" + str(pg_api["Id"])[:12]
    routes = [
        {
            "type": "local",
            "dst": "10.77.11.1",
            "dev": device,
            "table": "local",
            "protocol": "kernel",
            "scope": "host",
            "prefsrc": "10.77.11.1",
            "flags": [],
        },
        {
            "type": "broadcast",
            "dst": "10.77.11.7",
            "dev": device,
            "table": "local",
            "protocol": "kernel",
            "scope": "link",
            "prefsrc": "10.77.11.1",
            "flags": [],
        },
    ]
    monkeypatch.setattr(compose_stack.sys, "platform", "linux")
    monkeypatch.setattr(compose_stack.shutil, "which", lambda _: "/usr/sbin/ip")

    def ip_run(arguments: tuple[str, ...], **_: object) -> subprocess.CompletedProcess[str]:
        if arguments == ("ip", "-j", "rule", "show"):
            return subprocess.CompletedProcess(arguments, 0, stdout="[]", stderr="")
        return subprocess.CompletedProcess(arguments, 0, stdout=json.dumps(routes), stderr="")

    monkeypatch.setattr(compose_stack.subprocess, "run", ip_run)
    _ORIGINAL_HOST_NETWORK_ISOLATION("tracebed")
    routes[0]["scope"] = "link"
    with pytest.raises(compose_stack.ComposeStackError):
        _ORIGINAL_HOST_NETWORK_ISOLATION("tracebed")


def test_core_only_ingress_routes_allow_only_dockers_linkdown_kernel_records(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    networks, containers = _owned_network_inventory()
    core_ids = {
        str(container["Id"])
        for container in containers
        if container["Config"]["Labels"]["com.docker.compose.service"] in compose_stack._CORE_SERVICES  # type: ignore[index]
    }
    for network in networks:
        network["Containers"] = {  # type: ignore[index]
            identifier: endpoint
            for identifier, endpoint in network["Containers"].items()  # type: ignore[index]
            if identifier in core_ids
        }
    containers = [container for container in containers if str(container["Id"]) in core_ids]
    _install_owned_network_inventory(monkeypatch, networks, containers)
    ingress = next(network for network in networks if network["Name"] == "tracebed_ingress")
    device = "br-" + str(ingress["Id"])[:12]
    routes = [
        {
            "dst": "10.77.15.0/29",
            "dev": device,
            "protocol": "kernel",
            "scope": "link",
            "prefsrc": "10.77.15.1",
            "flags": ["linkdown"],
        },
        {
            "type": "local",
            "dst": "10.77.15.1",
            "dev": device,
            "table": "local",
            "protocol": "kernel",
            "scope": "host",
            "prefsrc": "10.77.15.1",
            "flags": [],
        },
        {
            "type": "broadcast",
            "dst": "10.77.15.7",
            "dev": device,
            "table": "local",
            "protocol": "kernel",
            "scope": "link",
            "prefsrc": "10.77.15.1",
            "flags": ["linkdown"],
        },
    ]
    monkeypatch.setattr(compose_stack.sys, "platform", "linux")
    monkeypatch.setattr(compose_stack.shutil, "which", lambda _: "/usr/sbin/ip")

    def ip_run(arguments: tuple[str, ...], **_: object) -> subprocess.CompletedProcess[str]:
        if arguments == ("ip", "-j", "rule", "show"):
            return subprocess.CompletedProcess(arguments, 0, stdout="[]", stderr="")
        return subprocess.CompletedProcess(arguments, 0, stdout=json.dumps(routes), stderr="")

    monkeypatch.setattr(compose_stack.subprocess, "run", ip_run)
    _ORIGINAL_HOST_NETWORK_ISOLATION("tracebed")
    # A detached bridge must carry Docker's exact linkdown marker.  Do not
    # accept the attached-bridge shape merely because the remaining fields
    # look plausible.
    routes[2]["flags"] = []
    with pytest.raises(compose_stack._NetworkPreflightError) as failure:
        _ORIGINAL_HOST_NETWORK_ISOLATION("tracebed")
    assert failure.value.reason == "owned-bridge-companion-shape"


def test_exact_drained_stage_authenticates_stopped_public_ingress_without_worker(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The controller's post-drain state is neither full nor core-only."""

    networks, containers = _owned_network_inventory()
    worker_ids = {
        str(container["Id"])
        for container in containers
        if container["Config"]["Labels"]["com.docker.compose.service"] == "worker"  # type: ignore[index]
    }
    for network in networks:
        network["Containers"] = {  # type: ignore[index]
            identifier: endpoint
            for identifier, endpoint in network["Containers"].items()  # type: ignore[index]
            if identifier not in worker_ids
        }
    containers = [container for container in containers if str(container["Id"]) not in worker_ids]
    _install_owned_network_inventory(monkeypatch, networks, containers)
    monkeypatch.setattr(compose_stack.sys, "platform", "darwin")
    _ORIGINAL_HOST_NETWORK_ISOLATION("tracebed")

    # A partial stopped-public state remains a hard refusal: only the exact
    # two detached worker endpoints may distinguish the drained stage.
    dashboard_id = next(
        str(container["Id"])
        for container in containers
        if container["Config"]["Labels"]["com.docker.compose.service"] == "dashboard"  # type: ignore[index]
    )
    for network in networks:
        network["Containers"] = {  # type: ignore[index]
            identifier: endpoint
            for identifier, endpoint in network["Containers"].items()  # type: ignore[index]
            if identifier != dashboard_id
        }
    containers = [container for container in containers if str(container["Id"]) != dashboard_id]
    _install_owned_network_inventory(monkeypatch, networks, containers)
    with pytest.raises(compose_stack._NetworkPreflightError) as failure:
        _ORIGINAL_HOST_NETWORK_ISOLATION("tracebed")
    assert failure.value.reason == "owned-attachment-stage"


def test_exact_rollback_recovery_stage_authenticates_only_closed_core_and_worker(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A successful rollback's restored worker is a controller-owned stage."""

    networks, containers = _owned_network_inventory(
        attachments_by_service=compose_stack._ROLLBACK_RECOVERY_ATTACHMENTS
    )
    _install_owned_network_inventory(monkeypatch, networks, containers)
    monkeypatch.setattr(compose_stack.sys, "platform", "darwin")
    _ORIGINAL_HOST_NETWORK_ISOLATION("tracebed")

    # The exact worker routes are essential.  Removing just one route must
    # not collapse into a tolerated core-only stage.
    worker_id = next(
        str(container["Id"])
        for container in containers
        if container["Config"]["Labels"]["com.docker.compose.service"] == "worker"  # type: ignore[index]
    )
    pg_worker = next(network for network in networks if network["Name"] == "tracebed_pg-worker")
    pg_worker["Containers"] = {  # type: ignore[index]
        identifier: endpoint
        for identifier, endpoint in pg_worker["Containers"].items()  # type: ignore[index]
        if identifier != worker_id
    }
    _install_owned_network_inventory(monkeypatch, networks, containers)
    with pytest.raises(compose_stack._NetworkPreflightError) as failure:
        _ORIGINAL_HOST_NETWORK_ISOLATION("tracebed")
    assert failure.value.reason == "owned-attachment-stage"


def test_network_preflight_diagnostic_emits_only_fixed_shape_and_count_evidence(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Controller diagnostics never copy hostile Docker/route text to stderr."""

    sentinel = "secret-or-hostile-text-must-not-escape"

    def readonly(*arguments: str) -> subprocess.CompletedProcess[str]:
        if arguments[:2] == ("network", "ls"):
            return subprocess.CompletedProcess(arguments, 0, stdout="a" * 64 + "\n", stderr=sentinel)
        if arguments[:2] == ("network", "inspect"):
            return subprocess.CompletedProcess(
                arguments,
                0,
                stdout=json.dumps([{"Name": sentinel, "Labels": {}}]),
                stderr=sentinel,
            )
        raise AssertionError(arguments)

    def ip_run(arguments: tuple[str, ...], **_: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(arguments, 0, stdout="[]", stderr=sentinel)

    monkeypatch.setattr(compose_stack, "_docker_readonly", readonly)
    monkeypatch.setattr(compose_stack.sys, "platform", "linux")
    monkeypatch.setattr(compose_stack.shutil, "which", lambda _: "/usr/sbin/ip")
    monkeypatch.setattr(compose_stack.subprocess, "run", ip_run)
    monkeypatch.setenv("COMPOSE_PROJECT_NAME", "tracebed")
    compose_stack._emit_network_preflight_diagnostic("tracebed", "owned-bridge-route-shape")

    diagnostic = capsys.readouterr().err
    assert sentinel not in diagnostic
    prefix = "Compose-v1 diagnostic "
    assert diagnostic.startswith(prefix)
    record = json.loads(diagnostic.removeprefix(prefix))
    assert record == {
        "all_table_route_record_count": 0,
        "host_route_inventory": "read",
        "host_route_inventory_shape": "lists",
        "kind": "compose-v1-network-preflight",
        "expected_core_attachment_count": sum(map(len, compose_stack._CORE_ATTACHMENTS.values())),
        "expected_drained_attachment_count": sum(map(len, compose_stack._DRAINED_ATTACHMENTS.values())),
        "expected_rollback_recovery_attachment_count": sum(
            map(len, compose_stack._ROLLBACK_RECOVERY_ATTACHMENTS.values())
        ),
        "expected_sustained_attachment_count": sum(map(len, compose_stack._SUSTAINED_ATTACHMENTS.values())),
        "network_count": 1,
        "network_inventory": "read",
        "network_inventory_shape": "list-of-objects",
        "project_environment": "match",
        "project_network_attachment_count": 0,
        "project_network_attachment_counts": dict.fromkeys(compose_stack._NETWORK_SUBNETS, -1),
        "project_network_attachment_shape": "objects",
        "project_network_claim_count": 0,
        "reason": "owned-bridge-route-shape",
        "rendered_topology": "validated",
        "rule_record_count": 0,
    }


def test_linux_host_route_overlap_and_missing_ip_utility_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        compose_stack,
        "_docker_readonly",
        lambda *_: subprocess.CompletedProcess(("docker",), 0, stdout="", stderr=""),
    )
    monkeypatch.setattr(compose_stack.sys, "platform", "linux")
    monkeypatch.setattr(compose_stack.shutil, "which", lambda _: None)
    with pytest.raises(compose_stack.ComposeStackError):
        _ORIGINAL_HOST_NETWORK_ISOLATION()


def test_linux_host_route_overlap_is_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        compose_stack,
        "_docker_readonly",
        lambda *_: subprocess.CompletedProcess(("docker",), 0, stdout="", stderr=""),
    )
    monkeypatch.setattr(compose_stack.sys, "platform", "linux")
    monkeypatch.setattr(compose_stack.shutil, "which", lambda _: "/usr/sbin/ip")
    monkeypatch.setattr(
        compose_stack.subprocess,
        "run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess(
            ("ip", "-j", "route", "show"), 0, stdout='[{"dst":"10.77.14.0/28"}]', stderr=""
        ),
    )
    with pytest.raises(compose_stack.ComposeStackError):
        _ORIGINAL_HOST_NETWORK_ISOLATION()


@pytest.mark.parametrize(
    "rule",
    (
        {"priority": 100, "src": "all", "table": "100"},
        {"priority": 100, "src": "10.77.11.0/29", "table": "100"},
        {"priority": 100, "src": "all", "fwmark": "0x1", "fwmask": "0xff", "table": "100"},
        {"priority": 100, "src": "all", "iif": "eth0", "table": "100"},
    ),
    ids=("catch-all", "source", "fwmark", "ingress-interface"),
)
def test_custom_policy_table_default_is_refused_for_every_selector(
    monkeypatch: pytest.MonkeyPatch, rule: dict[str, object]
) -> None:
    """A custom-table default can steer a fixed subnet even when selected."""

    monkeypatch.setattr(
        compose_stack,
        "_docker_readonly",
        lambda *_: subprocess.CompletedProcess(("docker",), 0, stdout="", stderr=""),
    )
    monkeypatch.setattr(compose_stack.sys, "platform", "linux")
    monkeypatch.setattr(compose_stack.shutil, "which", lambda _: "/usr/sbin/ip")

    def ip_run(arguments: tuple[str, ...], **_: object) -> subprocess.CompletedProcess[str]:
        stdout = json.dumps([rule]) if arguments == ("ip", "-j", "rule", "show") else json.dumps(
            [{"dst": "default", "table": "100", "dev": "eth0"}]
        )
        return subprocess.CompletedProcess(arguments, 0, stdout=stdout, stderr="")

    monkeypatch.setattr(compose_stack.subprocess, "run", ip_run)
    with pytest.raises(compose_stack._NetworkPreflightError) as failure:
        _ORIGINAL_HOST_NETWORK_ISOLATION()
    assert failure.value.reason == "policy-custom-default"


@pytest.mark.parametrize(
    "rule",
    (
        {"priority": 100, "src": "all"},
        {"priority": 100, "src": "10.77.11.0/29"},
        {"priority": 100, "src": "all", "fwmark": "0x1", "fwmask": "0xff"},
        {"priority": 100, "src": "all", "iif": "eth0"},
    ),
    ids=("catch-all", "source", "fwmark", "ingress-interface"),
)
@pytest.mark.parametrize("table", ("local", 255, "default", 253), ids=("local", "local-id", "default", "default-id"))
def test_reserved_policy_table_default_is_refused_for_every_selector(
    monkeypatch: pytest.MonkeyPatch, rule: dict[str, object], table: str | int
) -> None:
    """Aliases for local/default cannot hide a selected default route."""

    monkeypatch.setattr(
        compose_stack,
        "_docker_readonly",
        lambda *_: subprocess.CompletedProcess(("docker",), 0, stdout="", stderr=""),
    )
    monkeypatch.setattr(compose_stack.sys, "platform", "linux")
    monkeypatch.setattr(compose_stack.shutil, "which", lambda _: "/usr/sbin/ip")
    selected_rule = {**rule, "table": table}

    def ip_run(arguments: tuple[str, ...], **_: object) -> subprocess.CompletedProcess[str]:
        stdout = json.dumps([selected_rule]) if arguments == ("ip", "-j", "rule", "show") else json.dumps(
            [{"dst": "default", "table": table, "dev": "eth0"}]
        )
        return subprocess.CompletedProcess(arguments, 0, stdout=stdout, stderr="")

    monkeypatch.setattr(compose_stack.subprocess, "run", ip_run)
    with pytest.raises(compose_stack._NetworkPreflightError) as failure:
        _ORIGINAL_HOST_NETWORK_ISOLATION()
    assert failure.value.reason == "policy-reserved-default"


def test_main_policy_table_default_route_remains_supported(monkeypatch: pytest.MonkeyPatch) -> None:
    """The host's normal main-table default route remains a supported shape."""

    monkeypatch.setattr(
        compose_stack,
        "_docker_readonly",
        lambda *_: subprocess.CompletedProcess(("docker",), 0, stdout="", stderr=""),
    )
    monkeypatch.setattr(compose_stack.sys, "platform", "linux")
    monkeypatch.setattr(compose_stack.shutil, "which", lambda _: "/usr/sbin/ip")

    def ip_run(arguments: tuple[str, ...], **_: object) -> subprocess.CompletedProcess[str]:
        stdout = (
            json.dumps([{"priority": 100, "src": "all", "table": "main"}])
            if arguments == ("ip", "-j", "rule", "show")
            else json.dumps([{"dst": "default", "table": "main", "dev": "eth0"}])
        )
        return subprocess.CompletedProcess(arguments, 0, stdout=stdout, stderr="")

    monkeypatch.setattr(compose_stack.subprocess, "run", ip_run)
    _ORIGINAL_HOST_NETWORK_ISOLATION()


def test_nonstandard_policy_table_is_allowed_only_when_its_routes_are_disjoint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        compose_stack,
        "_docker_readonly",
        lambda *_: subprocess.CompletedProcess(("docker",), 0, stdout="", stderr=""),
    )
    monkeypatch.setattr(compose_stack.sys, "platform", "linux")
    monkeypatch.setattr(compose_stack.shutil, "which", lambda _: "/usr/sbin/ip")

    def ip_run(arguments: tuple[str, ...], **_: object) -> subprocess.CompletedProcess[str]:
        stdout = (
            json.dumps([{"priority": 5270, "src": "all", "table": "52"}])
            if arguments == ("ip", "-j", "rule", "show")
            else json.dumps([{"dst": "100.64.0.0/10", "table": "52", "dev": "tailscale0"}])
        )
        return subprocess.CompletedProcess(arguments, 0, stdout=stdout, stderr="")

    monkeypatch.setattr(compose_stack.subprocess, "run", ip_run)
    _ORIGINAL_HOST_NETWORK_ISOLATION()


def test_drain_refuses_a_stopped_worker_instead_of_claiming_zero_work(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        compose_stack,
        "_run",
        lambda *_: subprocess.CompletedProcess(("docker",), 0, stdout="api\n", stderr=""),
    )
    with pytest.raises(compose_stack.ComposeStackError):
        _ORIGINAL_REQUIRE_WORKER_RUNNING()


def test_controller_rejects_leftover_privileged_one_shot_container(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        compose_stack,
        "_run",
        lambda *_: subprocess.CompletedProcess((), 0, stdout="db-bootstrap\n", stderr=""),
    )
    with pytest.raises(compose_stack.ComposeStackError):
        compose_stack._assert_no_one_shot_container()


def test_controller_does_not_accept_free_form_docker_or_endpoint_arguments() -> None:
    with pytest.raises(SystemExit, match="2"):
        compose_stack.main(["unexpected"])
    assert compose_stack._RUNTIME_SERVICES == ("api", "edge", "worker", "erasure", "dashboard")
    assert "/var/run/docker.sock" not in (
        (compose_stack._ROOT / "docker" / "compose.yaml").read_text(encoding="utf-8")
    )
