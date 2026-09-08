#!/usr/bin/env python3
"""The only supported Compose-v1 stack lifecycle controller.

This is deliberately a small, closed command surface rather than a wrapper
for arbitrary ``docker compose`` arguments.  It never receives a DSN,
password, endpoint, service name, or host from the command line: Compose
resolves named secret *files* itself and the service entrypoints construct
their fixed in-network credentials.  Arbitrary external HBA/topologies are
not supported by this controller.
"""

from __future__ import annotations

import argparse
import fcntl
import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from pathlib import Path
from typing import Final, Literal, cast

from tracebed.compose_secrets import validate_compose_secret_source
from tracebed.domain.errors import ConfigError

_ROOT: Final = Path(__file__).resolve().parents[1]
_COMPOSE_FILE: Final = _ROOT / "docker" / "compose.yaml"
_BASE: Final = ("docker", "compose", "--project-directory", str(_ROOT), "--file", str(_COMPOSE_FILE))
_RUNTIME_SERVICES: Final = ("api", "edge", "worker", "erasure", "dashboard")
_CORE_SERVICES: Final = ("postgres", "valkey", "seaweedfs")
_ONE_SHOTS: Final = ("db-bootstrap", "s3-init", "s3-volume-init")
# `docker compose run --build db-bootstrap` builds only the bootstrap image;
# it does not refresh the separately tagged API and worker images that share
# the Dockerfile.  Publication must therefore build every local image before
# a clean stack can make claims about the checked source revision.
_BUILT_SERVICES: Final = (*_RUNTIME_SERVICES, *_ONE_SHOTS, "seaweedfs")
_NETWORK_SUBNETS: Final = {
    "pg-admin": "10.77.10.0/29",
    "pg-api": "10.77.11.0/29",
    "pg-worker": "10.77.12.0/29",
    "pg-probe": "10.77.13.0/29",
    "runtime-data": "10.77.14.0/28",
    "ingress": "10.77.15.0/29",
    "pg-erasure": "10.77.16.0/29",
}
_STATIC_ATTACHMENTS: Final = {
    "postgres": {
        "pg-admin": "10.77.10.2",
        "pg-api": "10.77.11.2",
        "pg-worker": "10.77.12.2",
        "pg-probe": "10.77.13.2",
        "pg-erasure": "10.77.16.2",
    },
    "db-bootstrap": {
        "pg-admin": "10.77.10.3",
        "pg-api": "10.77.11.4",
        "pg-worker": "10.77.12.4",
        "pg-probe": "10.77.13.3",
        "pg-erasure": "10.77.16.4",
    },
    "valkey": {"runtime-data": "10.77.14.2"},
    "seaweedfs": {"runtime-data": "10.77.14.3"},
    "s3-init": {"runtime-data": "10.77.14.4"},
    "api": {"pg-api": "10.77.11.3", "runtime-data": "10.77.14.5", "ingress": "10.77.15.2"},
    "edge": {"ingress": "10.77.15.4"},
    "worker": {"pg-worker": "10.77.12.3", "runtime-data": "10.77.14.6"},
    "erasure": {"pg-erasure": "10.77.16.3", "runtime-data": "10.77.14.7"},
    "dashboard": {"ingress": "10.77.15.3"},
}
_INTERNAL_NETWORKS: Final = frozenset(_NETWORK_SUBNETS) - {"ingress"}
_SUSTAINED_ATTACHMENTS: Final = {
    service: attachments
    for service, attachments in _STATIC_ATTACHMENTS.items()
    if service not in {"db-bootstrap", "s3-init"}
}
_CORE_ATTACHMENTS: Final = {
    service: _SUSTAINED_ATTACHMENTS[service] for service in _CORE_SERVICES
}
# ``upgrade``/``rollback`` first stop public ingress, retain the worker to
# drain, then stop the worker immediately before the owner mutation. Docker
# retains the stopped API/edge/dashboard endpoints but detaches the stopped worker
# from its two bridges.  This is a distinct, exact controller-owned state;
# accepting it requires the same seven authenticated networks and static
# addresses as every other stage, never a partial topology exemption.
_DRAINED_ATTACHMENTS: Final = {
    service: attachments for service, attachments in _SUSTAINED_ATTACHMENTS.items() if service != "worker"
}
# A successful E4 rollback is a distinct authenticated c12 recovery state:
# public runtime endpoints remain stopped while the controller recreates just
# the ordinary worker, closed, so its next ``upgrade`` can drain it.  Docker
# detaches the stopped public containers on supported engines, leaving this
# exact core-plus-worker attachment set.  Treat no other partial stage as
# equivalent.
_ROLLBACK_RECOVERY_ATTACHMENTS: Final = {
    **_CORE_ATTACHMENTS,
    "worker": _SUSTAINED_ATTACHMENTS["worker"],
}
_NETWORK_ID_RE: Final = re.compile(r"\A[0-9a-f]{64}\Z")
_COMPOSE_CONFIG_HASH_RE: Final = re.compile(r"\A[0-9a-f]{64}\Z")
_DRAIN_TIMEOUT_SECONDS: Final = 180.0
_DRAIN_POLL_SECONDS: Final = 1.0
_PREPUBLICATION_TIMEOUT_SECONDS: Final = 45.0
_PREPUBLICATION_POLL_SECONDS: Final = 0.5
_NETWORK_DIAGNOSTIC_ENV: Final = "TRACEBED_COMPOSE_NETWORK_DIAGNOSTIC"
_CONTROLLER_LOCK_FILE: Final = _COMPOSE_FILE
_CONTROLLER_THREAD_LOCK = threading.Lock()
# ``main`` is the only standard table whose default route may remain in a
# supported host configuration.  The reserved ``local`` and ``default``
# tables are otherwise harmless for the fixed Compose subnets, but a default
# route in either can be selected by a nonstandard RPDB rule and must be a
# fail-closed preflight refusal.
_MAIN_ROUTE_TABLES: Final = frozenset({"main", "254", 254})
_LOCAL_OR_DEFAULT_ROUTE_TABLES: Final = frozenset({"local", "255", 255, "default", "253", 253})


class ComposeStackError(RuntimeError):
    """An opaque lifecycle failure; Docker output carries non-secret detail."""


class _NetworkPreflightError(ComposeStackError):
    """A fixed-code network refusal used only for diagnostic evidence.

    The public controller error deliberately remains opaque.  The acceptance
    harness can opt into the closed, fixed-code record below; it never copies
    Docker, route, configuration, or environment text into its receipt.
    """

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__("Compose-v1 lifecycle operation failed")


def _emit_lifecycle_diagnostic(code: str) -> None:
    """Emit one fixed controller checkpoint when acceptance opted in.

    This complements the topology diagnostic without copying Compose output,
    service logs, paths, credentials, or attacker-controlled text.  The
    caller supplies only controller literals, and the acceptance harness uses
    the record to distinguish a deterministic lifecycle refusal from a
    transient Docker failure.
    """

    if os.environ.get(_NETWORK_DIAGNOSTIC_ENV) != "1":
        return
    print(
        "Compose-v1 diagnostic "
        + json.dumps(
            {"kind": "compose-v1-lifecycle", "code": code},
            sort_keys=True,
            separators=(",", ":"),
        ),
        file=sys.stderr,
    )


@contextmanager
def _controller_lifecycle_lock() -> Iterator[None]:
    """Serialize a complete authenticated controller action on this checkout.

    The lock is taken before secret/topology validation and is held until the
    action returns, so two trusted controller invocations cannot interleave a
    fence, image build, closed probe, or the final owner publication.  It uses
    the checked Compose artifact as a stable, read-only lock inode: no
    deployment state or secret-source directory is modified.  The in-process
    lock covers thread concurrency; ``flock`` covers independently launched
    controller processes on the supported Linux host.
    """

    try:
        with _CONTROLLER_THREAD_LOCK, _CONTROLLER_LOCK_FILE.open("rb") as handle:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
    except OSError:
        raise ComposeStackError("Compose-v1 lifecycle controller lock failed") from None


def _run(*arguments: str) -> subprocess.CompletedProcess[str]:
    """Run a fixed Docker Compose subcommand without accepting caller fragments."""

    try:
        return subprocess.run(  # noqa: S603 - arguments are closed literals selected above
            (*_BASE, *arguments),
            check=True,
            text=True,
            capture_output=True,
        )
    except (OSError, subprocess.CalledProcessError):
        # The operation is selected exclusively by this controller, so this
        # label is useful failure evidence without copying Compose output (or
        # ever risking a secret-bearing environment value in a log).
        operation = arguments[0] if arguments else "unknown"
        if operation == "run" and arguments:
            # All controller ``run`` targets are closed literals.  Naming the
            # one-shot distinguishes the bootstrap, S3 initializer, and
            # volume preparation in an opaque acceptance receipt.
            operation = f"run-{arguments[-1]}"
        raise ComposeStackError(f"Compose-v1 lifecycle {operation} failed") from None


def _validate_rendered_configuration() -> None:
    """Fail before a pull/start if required secret file references are absent."""

    try:
        validate_compose_secret_source(os.environ)
    except ConfigError:
        _emit_lifecycle_diagnostic("rendered-secret-source-preflight")
        raise ComposeStackError("Compose-v1 lifecycle secret-source preflight failed") from None
    try:
        _run("config", "--quiet")
        rendered = _run("config", "--format", "json").stdout
    except ComposeStackError:
        _emit_lifecycle_diagnostic("rendered-compose-config")
        raise
    try:
        document = json.loads(rendered)
    except (TypeError, json.JSONDecodeError):
        _emit_lifecycle_diagnostic("rendered-json")
        raise ComposeStackError("Compose-v1 lifecycle rendered-topology preflight failed") from None
    try:
        _validate_fixed_topology(document)
    except ComposeStackError:
        _emit_lifecycle_diagnostic("rendered-topology")
        raise ComposeStackError("Compose-v1 lifecycle rendered-topology preflight failed") from None
    project = document.get("name") if isinstance(document, dict) else None
    if not isinstance(project, str) or not project:
        _emit_lifecycle_diagnostic("rendered-project")
        raise ComposeStackError("Compose-v1 lifecycle rendered-topology preflight failed")
    try:
        _validate_host_network_isolation(project)
    except _NetworkPreflightError as error:
        if os.environ.get(_NETWORK_DIAGNOSTIC_ENV) == "1":
            _emit_network_preflight_diagnostic(project, error.reason)
        _emit_lifecycle_diagnostic("rendered-network-preflight")
        raise ComposeStackError("Compose-v1 lifecycle network preflight failed") from None
    except ComposeStackError:
        _emit_lifecycle_diagnostic("rendered-network-preflight")
        raise ComposeStackError("Compose-v1 lifecycle network preflight failed") from None


def _validate_fixed_topology(document: object) -> None:
    """Reject every topology/IP drift before any Compose mutation occurs."""

    if not isinstance(document, dict):
        raise ComposeStackError("Compose-v1 lifecycle operation failed")
    networks = document.get("networks")
    services = document.get("services")
    if not isinstance(networks, dict) or not isinstance(services, dict):
        raise ComposeStackError("Compose-v1 lifecycle operation failed")
    if set(networks) != set(_NETWORK_SUBNETS) or not set(_STATIC_ATTACHMENTS).issubset(services):
        raise ComposeStackError("Compose-v1 lifecycle operation failed")
    for name, subnet in _NETWORK_SUBNETS.items():
        network = networks.get(name)
        if not isinstance(network, dict):
            raise ComposeStackError("Compose-v1 lifecycle operation failed")
        ipam = network.get("ipam")
        if not isinstance(ipam, dict) or ipam.get("config") != [{"subnet": subnet}]:
            raise ComposeStackError("Compose-v1 lifecycle operation failed")
        if (network.get("internal") is True) != (name in _INTERNAL_NETWORKS):
            raise ComposeStackError("Compose-v1 lifecycle operation failed")

    seen_addresses: set[tuple[str, str]] = set()
    for service_name, expected_networks in _STATIC_ATTACHMENTS.items():
        service = services.get(service_name)
        if not isinstance(service, dict) or not isinstance(service.get("networks"), dict):
            raise ComposeStackError("Compose-v1 lifecycle operation failed")
        actual_networks = cast("dict[object, object]", service["networks"])
        if set(actual_networks) != set(expected_networks):
            raise ComposeStackError("Compose-v1 lifecycle operation failed")
        for network_name, expected_ip in expected_networks.items():
            attachment = actual_networks.get(network_name)
            if not isinstance(attachment, dict) or attachment.get("ipv4_address") != expected_ip:
                raise ComposeStackError("Compose-v1 lifecycle operation failed")
            unique = (network_name, expected_ip)
            if unique in seen_addresses:
                raise ComposeStackError("Compose-v1 lifecycle operation failed")
            seen_addresses.add(unique)


def _docker_readonly(*arguments: str) -> subprocess.CompletedProcess[str]:
    """Run only a closed read-only Docker inspection command."""

    try:
        return subprocess.run(  # noqa: S603 - fixed Docker inspection protocol
            ("docker", *arguments),  # noqa: S607 - fixed Docker executable
            check=True,
            text=True,
            capture_output=True,
        )
    except (OSError, subprocess.CalledProcessError):
        raise ComposeStackError("Compose-v1 lifecycle operation failed") from None


def _parsed_network(value: object) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    if not isinstance(value, str):
        raise ComposeStackError("Compose-v1 lifecycle operation failed")
    try:
        return ipaddress.ip_network(value, strict=True)
    except ValueError:
        raise ComposeStackError("Compose-v1 lifecycle operation failed") from None


def _expected_network_name(project: str, logical_name: str) -> str:
    return f"{project}_{logical_name}"


def _expected_gateway(network: ipaddress.IPv4Network | ipaddress.IPv6Network) -> str:
    return str(network.network_address + 1)


def _network_candidates_for_project(
    networks: list[dict[object, object]], project: str | None
) -> list[dict[object, object]]:
    """Return every resource that claims this project's namespace.

    A name-prefix or project-label claim is enough to require complete
    authentication, never enough to receive an overlap exemption by itself.
    """

    if project is None:
        return []
    prefix = project + "_"
    candidates: list[dict[object, object]] = []
    for network in networks:
        name = network.get("Name")
        labels = network.get("Labels")
        claimed_project = labels.get("com.docker.compose.project") if isinstance(labels, dict) else None
        if (isinstance(name, str) and name.startswith(prefix)) or claimed_project == project:
            candidates.append(network)
    return candidates


def _expected_stage_attachments(
    attachments_by_service: dict[str, dict[str, str]]
) -> dict[str, dict[str, str]]:
    by_network: dict[str, dict[str, str]] = {logical: {} for logical in _NETWORK_SUBNETS}
    for service, attachments in attachments_by_service.items():
        for logical, address in attachments.items():
            by_network[logical][service] = address
    return by_network


def _authenticate_current_project_attachments(
    networks: dict[str, dict[object, object]],
    project: str,
    *,
    expected_by_service: dict[str, dict[str, str]],
) -> None:
    """Authenticate exact static Compose attachments for every lifecycle stage.

    Runtime containers may be either running or stopped while a controller is
    fenced; core dependencies must remain running.  No foreign container,
    duplicate service, additional network, or dynamic address is accepted.
    """

    expected_by_network = _expected_stage_attachments(expected_by_service)
    endpoint_ids: set[str] = set()
    endpoint_expectations: dict[str, dict[str, str]] = {}
    for logical, network in networks.items():
        containers = network.get("Containers")
        expected = expected_by_network[logical]
        if not isinstance(containers, dict) or len(containers) != len(expected):
            raise _NetworkPreflightError("owned-attachment-count")
        observed_addresses: set[str] = set()
        for identifier, endpoint in containers.items():
            if not isinstance(identifier, str) or not _NETWORK_ID_RE.fullmatch(identifier):
                raise _NetworkPreflightError("owned-attachment-id")
            if not isinstance(endpoint, dict):
                raise _NetworkPreflightError("owned-attachment-shape")
            address = endpoint.get("IPv4Address")
            expected_addresses = set(expected.values())
            network_size = _parsed_network(_NETWORK_SUBNETS[logical]).prefixlen
            if (
                not isinstance(address, str)
                or address not in {f"{expected_address}/{network_size}" for expected_address in expected_addresses}
                or address in observed_addresses
            ):
                raise _NetworkPreflightError("owned-attachment-address")
            observed_addresses.add(address)
            endpoint_ids.add(identifier)
            if identifier in endpoint_expectations:
                endpoint_expectations[identifier][logical] = address
            else:
                endpoint_expectations[identifier] = {logical: address}
        if observed_addresses != {
            f"{expected_address}/{_parsed_network(_NETWORK_SUBNETS[logical]).prefixlen}"
            for expected_address in expected.values()
        }:
            raise _NetworkPreflightError("owned-attachment-address-set")

    if not endpoint_ids:
        raise _NetworkPreflightError("owned-attachment-empty")
    try:
        raw_containers = _docker_readonly("container", "inspect", *sorted(endpoint_ids)).stdout
    except ComposeStackError:
        raise _NetworkPreflightError("owned-container-inspect") from None
    try:
        containers = json.loads(raw_containers)
    except (TypeError, json.JSONDecodeError):
        raise _NetworkPreflightError("owned-container-json") from None
    if not isinstance(containers, list) or len(containers) != len(endpoint_ids):
        raise _NetworkPreflightError("owned-container-count")

    expected_services = set(expected_by_service)
    seen_services: set[str] = set()
    for container in containers:
        if not isinstance(container, dict):
            raise _NetworkPreflightError("owned-container-shape")
        identifier = container.get("Id")
        name = container.get("Name")
        labels = container.get("Config", {}).get("Labels") if isinstance(container.get("Config"), dict) else None
        state = container.get("State")
        networks_state = (
            container.get("NetworkSettings", {}).get("Networks")
            if isinstance(container.get("NetworkSettings"), dict)
            else None
        )
        if (
            not isinstance(identifier, str)
            or identifier not in endpoint_expectations
            or not isinstance(labels, dict)
            or labels.get("com.docker.compose.project") != project
            or not isinstance(labels.get("com.docker.compose.service"), str)
            or not isinstance(name, str)
            or not isinstance(state, dict)
            or not isinstance(networks_state, dict)
        ):
            raise _NetworkPreflightError("owned-container-identity")
        service = labels["com.docker.compose.service"]
        if (
            service not in expected_services
            or service in seen_services
            or name != f"/{project}-{service}-1"
            or labels.get("com.docker.compose.container-number") != "1"
        ):
            raise _NetworkPreflightError("owned-container-label")
        running = state.get("Running")
        status = state.get("Status")
        if service in _CORE_SERVICES:
            if running is not True or status != "running":
                raise _NetworkPreflightError("owned-core-state")
        elif running is not True and status not in {"exited", "created"}:
            raise _NetworkPreflightError("owned-runtime-state")
        expected_attachments = expected_by_service[service]
        if set(networks_state) != {
            _expected_network_name(project, logical) for logical in expected_attachments
        }:
            raise _NetworkPreflightError("owned-container-networks")
        for logical, address in expected_attachments.items():
            observed = networks_state.get(_expected_network_name(project, logical))
            if not isinstance(observed, dict) or observed.get("IPAddress") != address:
                raise _NetworkPreflightError("owned-container-address")
        seen_services.add(service)
    if seen_services != expected_services:
        raise _NetworkPreflightError("owned-service-set")


def _authenticated_current_project_networks(
    networks: list[dict[object, object]], expected_project: str | None
) -> dict[ipaddress.IPv4Network | ipaddress.IPv6Network, tuple[str, bool]]:
    """Return exact bridge-route ownership only after full topology proof."""

    candidates = _network_candidates_for_project(networks, expected_project)
    if not candidates:
        return {}
    if expected_project is None or len(candidates) != len(_NETWORK_SUBNETS):
        raise _NetworkPreflightError("owned-network-count")
    by_logical: dict[str, dict[object, object]] = {}
    expected_names = {_expected_network_name(expected_project, logical) for logical in _NETWORK_SUBNETS}
    if {network.get("Name") for network in candidates} != expected_names:
        raise _NetworkPreflightError("owned-network-name-set")
    for network in candidates:
        name = network.get("Name")
        labels = network.get("Labels")
        identifier = network.get("Id")
        if not isinstance(name, str) or not isinstance(labels, dict) or not isinstance(identifier, str):
            raise _NetworkPreflightError("owned-network-identity")
        logical = labels.get("com.docker.compose.network")
        permitted_labels = {
            "com.docker.compose.config-hash",
            "com.docker.compose.project",
            "com.docker.compose.network",
            "com.docker.compose.version",
        }
        if (
            not isinstance(logical, str)
            or logical not in _NETWORK_SUBNETS
            or labels.get("com.docker.compose.project") != expected_project
            or name != _expected_network_name(expected_project, logical)
            or not set(labels).issubset(permitted_labels)
            or not _NETWORK_ID_RE.fullmatch(identifier)
            or logical in by_logical
        ):
            raise _NetworkPreflightError("owned-network-label")
        config_hash = labels.get("com.docker.compose.config-hash")
        compose_version = labels.get("com.docker.compose.version")
        if (
            not isinstance(config_hash, str)
            or _COMPOSE_CONFIG_HASH_RE.fullmatch(config_hash) is None
            or not isinstance(compose_version, str)
            or not compose_version
        ):
            raise _NetworkPreflightError("owned-network-compose-label")
        try:
            desired = _parsed_network(_NETWORK_SUBNETS[logical])
        except ComposeStackError:
            raise _NetworkPreflightError("owned-network-subnet") from None
        ipam = network.get("IPAM")
        if (
            network.get("Driver") != "bridge"
            or network.get("Scope") != "local"
            or network.get("Internal") != (logical in _INTERNAL_NETWORKS)
            or network.get("EnableIPv4") is not True
            or network.get("EnableIPv6") is not False
            or network.get("Attachable") is not False
            or network.get("Ingress") is not False
            or network.get("ConfigOnly") is not False
            or network.get("Options") != {}
            or not isinstance(ipam, dict)
            or ipam.get("Driver") != "default"
            or ipam.get("Options") is not None
            or ipam.get("Config")
            != [{"Subnet": str(desired), "Gateway": _expected_gateway(desired)}]
        ):
            raise _NetworkPreflightError("owned-network-shape")
        by_logical[logical] = network
    if set(by_logical) != set(_NETWORK_SUBNETS):
        raise _NetworkPreflightError("owned-network-logical-set")
    attachment_count = 0
    for network in by_logical.values():
        containers = network.get("Containers")
        if not isinstance(containers, dict):
            raise _NetworkPreflightError("owned-network-containers")
        attachment_count += len(containers)
    full_count = sum(len(attachments) for attachments in _SUSTAINED_ATTACHMENTS.values())
    drained_count = sum(len(attachments) for attachments in _DRAINED_ATTACHMENTS.values())
    core_count = sum(len(attachments) for attachments in _CORE_ATTACHMENTS.values())
    rollback_recovery_count = sum(
        len(attachments) for attachments in _ROLLBACK_RECOVERY_ATTACHMENTS.values()
    )
    if attachment_count == full_count:
        expected_by_service = _SUSTAINED_ATTACHMENTS
    elif attachment_count == drained_count:
        expected_by_service = _DRAINED_ATTACHMENTS
    elif attachment_count == rollback_recovery_count:
        expected_by_service = _ROLLBACK_RECOVERY_ATTACHMENTS
    elif attachment_count == core_count:
        expected_by_service = _CORE_ATTACHMENTS
    else:
        raise _NetworkPreflightError("owned-attachment-stage")
    _authenticate_current_project_attachments(
        by_logical, expected_project, expected_by_service=expected_by_service
    )
    return {
        _parsed_network(_NETWORK_SUBNETS[logical]): (
            "br-" + str(network["Id"])[:12],
            bool(network["Containers"]),
        )
        for logical, network in by_logical.items()
    }


def _emit_network_preflight_diagnostic(expected_project: str, reason: str) -> None:
    """Emit a bounded, secret-safe snapshot at the controller boundary.

    This is deliberately diagnostic-only: it reuses closed read-only Docker
    and Linux inspection commands, serializes no resource names, addresses,
    labels, paths, or command output, and cannot change a preflight result.
    Counts and JSON-shape state make a transient topology mismatch
    reproducible without turning the acceptance receipt into a host inventory.
    """

    record: dict[str, object] = {
        "kind": "compose-v1-network-preflight",
        "reason": reason,
        "rendered_topology": "validated",
        "project_environment": (
            "match"
            if os.environ.get("COMPOSE_PROJECT_NAME") == expected_project
            else "missing"
            if os.environ.get("COMPOSE_PROJECT_NAME") is None
            else "mismatch"
        ),
    }
    try:
        identifiers = tuple(
            identifier
            for identifier in _docker_readonly("network", "ls", "--quiet").stdout.splitlines()
            if identifier
        )
        record["network_inventory"] = "read"
        record["network_count"] = len(identifiers)
        if identifiers:
            networks = json.loads(_docker_readonly("network", "inspect", *identifiers).stdout)
            if isinstance(networks, list) and all(isinstance(network, dict) for network in networks):
                typed_networks = cast("list[dict[object, object]]", networks)
                candidates = _network_candidates_for_project(typed_networks, expected_project)
                record["project_network_claim_count"] = len(candidates)
                attachment_counts = [
                    len(containers)
                    for network in candidates
                    if isinstance((containers := network.get("Containers")), dict)
                ]
                record["project_network_attachment_count"] = sum(attachment_counts)
                record["project_network_attachment_shape"] = (
                    "objects" if len(attachment_counts) == len(candidates) else "invalid"
                )
                by_logical_count: dict[str, int] = {}
                for network in candidates:
                    labels = network.get("Labels")
                    containers = network.get("Containers")
                    logical = labels.get("com.docker.compose.network") if isinstance(labels, dict) else None
                    if logical in _NETWORK_SUBNETS and isinstance(containers, dict):
                        by_logical_count[logical] = len(containers)
                record["project_network_attachment_counts"] = {
                    logical: by_logical_count.get(logical, -1) for logical in sorted(_NETWORK_SUBNETS)
                }
                record["expected_core_attachment_count"] = sum(
                    len(attachments) for attachments in _CORE_ATTACHMENTS.values()
                )
                record["expected_drained_attachment_count"] = sum(
                    len(attachments) for attachments in _DRAINED_ATTACHMENTS.values()
                )
                record["expected_rollback_recovery_attachment_count"] = sum(
                    len(attachments) for attachments in _ROLLBACK_RECOVERY_ATTACHMENTS.values()
                )
                record["expected_sustained_attachment_count"] = sum(
                    len(attachments) for attachments in _SUSTAINED_ATTACHMENTS.values()
                )
                record["network_inventory_shape"] = "list-of-objects"
            else:
                record["network_inventory_shape"] = "invalid"
        else:
            record["project_network_claim_count"] = 0
            record["network_inventory_shape"] = "list-of-objects"
    except (ComposeStackError, TypeError, json.JSONDecodeError):
        record["network_inventory"] = "unavailable"

    if sys.platform == "linux":
        if shutil.which("ip") is None:
            record["host_route_inventory"] = "ip-unavailable"
        else:
            try:
                rules = subprocess.run(
                    ("ip", "-j", "rule", "show"),  # noqa: S607 - closed diagnostic command
                    check=True,
                    text=True,
                    capture_output=True,
                )
                routes = subprocess.run(
                    ("ip", "-j", "route", "show", "table", "all"),  # noqa: S607 - closed diagnostic command
                    check=True,
                    text=True,
                    capture_output=True,
                )
                decoded_rules = json.loads(rules.stdout)
                decoded_routes = json.loads(routes.stdout)
                record["host_route_inventory"] = "read"
                record["rule_record_count"] = len(decoded_rules) if isinstance(decoded_rules, list) else -1
                record["all_table_route_record_count"] = len(decoded_routes) if isinstance(decoded_routes, list) else -1
                record["host_route_inventory_shape"] = (
                    "lists"
                    if isinstance(decoded_rules, list) and isinstance(decoded_routes, list)
                    else "invalid"
                )
            except (OSError, subprocess.CalledProcessError, TypeError, json.JSONDecodeError):
                record["host_route_inventory"] = "unavailable"
    else:
        record["host_route_inventory"] = "unsupported-platform"
    print("Compose-v1 diagnostic " + json.dumps(record, sort_keys=True, separators=(",", ":")), file=sys.stderr)


def _policy_table(value: object) -> str | int:
    """Return one exact Linux RPDB table identifier, defaulting to main."""

    if value is None:
        return "main"
    if type(value) in {str, int}:
        return cast("str | int", value)
    raise _NetworkPreflightError("policy-table-shape")


def _validate_policy_selector(value: object) -> None:
    """Reject malformed source/destination selectors without logging them."""

    if value == "all":
        return
    if not isinstance(value, str):
        raise _NetworkPreflightError("policy-selector-shape")
    try:
        ipaddress.ip_network(value, strict=False)
    except ValueError:
        raise _NetworkPreflightError("policy-selector-shape") from None


def _validate_policy_routing(
    rules: list[object],
    routes: list[object],
    *,
    expected: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...],
) -> None:
    """Prove nonstandard RPDB tables cannot steer a fixed Compose subnet.

    Hosts commonly carry Tailscale/VPN policy tables.  They remain supported
    only when every custom route is non-default and disjoint from the seven
    checked subnets.  A catch-all, source-, mark-, or interface-selected rule
    to a custom table with a default/overlapping route is therefore rejected
    before Compose can publish a login.
    """

    for route in routes:
        if not isinstance(route, dict):
            raise _NetworkPreflightError("host-route-shape")
        table = _policy_table(route.get("table"))
        destination = route.get("dst")
        if table in _MAIN_ROUTE_TABLES:
            continue
        if table in _LOCAL_OR_DEFAULT_ROUTE_TABLES:
            if destination in (None, "default"):
                raise _NetworkPreflightError("policy-reserved-default")
            # Docker's local companion routes are expected to overlap the
            # checked bridges.  They cannot steer traffic through a default
            # route, so leave their concrete destinations to the kernel's
            # reserved-table semantics rather than treating them as foreign
            # routes.
            continue
        if destination in (None, "default"):
            raise _NetworkPreflightError("policy-custom-default")
        if not isinstance(destination, str):
            raise _NetworkPreflightError("policy-custom-route-shape")
        try:
            network = _parsed_network(destination)
        except ComposeStackError:
            raise _NetworkPreflightError("policy-custom-route-shape") from None
        if any(network.version == desired.version and network.overlaps(desired) for desired in expected):
            raise _NetworkPreflightError("policy-custom-route-overlap")

    allowed_rule_fields = {
        "priority",
        "src",
        "dst",
        "iif",
        "oif",
        "ipproto",
        "fwmark",
        "fwmask",
        "table",
        "action",
    }
    for rule in rules:
        if not isinstance(rule, dict) or not set(rule).issubset(allowed_rule_fields):
            raise _NetworkPreflightError("policy-rule-shape")
        if "src" in rule:
            _validate_policy_selector(rule["src"])
        if "dst" in rule:
            _validate_policy_selector(rule["dst"])
        for key in ("iif", "oif", "ipproto", "fwmark", "fwmask"):
            value = rule.get(key)
            if value is not None and (not isinstance(value, str) or not value):
                raise _NetworkPreflightError("policy-rule-selector")
        table_value = rule.get("table")
        action = rule.get("action")
        if table_value is None:
            if action != "unreachable":
                raise _NetworkPreflightError("policy-rule-action")
            continue
        if action is not None:
            raise _NetworkPreflightError("policy-rule-action")
        _policy_table(table_value)


def _validate_host_network_isolation(expected_project: str | None = None) -> None:
    """Reject foreign Docker IPAM or Linux route overlap before mutation.

    An already-running instance of this exact checked Compose project owns the
    seven fixed subnets itself.  Its exact, label-authenticated networks are
    therefore not a foreign collision during an upgrade/rollback preflight;
    an extra, relabelled, reordered, or wrong-subnet network remains a hard
    refusal.
    """

    try:
        expected = tuple(_parsed_network(subnet) for subnet in _NETWORK_SUBNETS.values())
    except ComposeStackError:
        raise _NetworkPreflightError("checked-subnet") from None
    owned_routes: dict[ipaddress.IPv4Network | ipaddress.IPv6Network, tuple[str, bool]] = {}
    try:
        identifiers = tuple(
            identifier for identifier in _docker_readonly("network", "ls", "--quiet").stdout.splitlines() if identifier
        )
    except ComposeStackError:
        raise _NetworkPreflightError("docker-network-list") from None
    if identifiers:
        try:
            raw_networks = _docker_readonly("network", "inspect", *identifiers).stdout
        except ComposeStackError:
            raise _NetworkPreflightError("docker-network-inspect") from None
        try:
            networks = json.loads(raw_networks)
        except (TypeError, json.JSONDecodeError):
            raise _NetworkPreflightError("docker-network-json") from None
        if not isinstance(networks, list):
            raise _NetworkPreflightError("docker-network-shape")
        validated_networks: list[dict[object, object]] = []
        for network in networks:
            if not isinstance(network, dict):
                raise _NetworkPreflightError("docker-network-shape")
            validated_networks.append(network)
        try:
            owned_routes = _authenticated_current_project_networks(validated_networks, expected_project)
        except _NetworkPreflightError:
            raise
        except ComposeStackError:
            raise _NetworkPreflightError("owned-topology") from None
        for network in validated_networks:
            ipam = network.get("IPAM")
            if not isinstance(ipam, dict):
                raise _NetworkPreflightError("docker-ipam-shape")
            configurations = ipam.get("Config")
            # Docker's two built-in non-routable networks expose a literal
            # null IPAM Config.  They cannot collide with bridge subnets and
            # are not Compose-created resources; accept only those exact
            # names, while keeping every other malformed/no-IPAM network a
            # fail-closed preflight error.
            if configurations is None and network.get("Name") in {"host", "none"}:
                continue
            if not isinstance(configurations, list):
                raise _NetworkPreflightError("docker-ipam-shape")
            for configuration in configurations:
                if not isinstance(configuration, dict) or "Subnet" not in configuration:
                    raise _NetworkPreflightError("docker-ipam-shape")
                try:
                    actual = _parsed_network(configuration["Subnet"])
                except ComposeStackError:
                    raise _NetworkPreflightError("docker-ipam-subnet") from None
                if actual in owned_routes:
                    continue
                if any(actual.version == desired.version and actual.overlaps(desired) for desired in expected):
                    raise _NetworkPreflightError("docker-ipam-overlap")

    if sys.platform != "linux":
        return
    if shutil.which("ip") is None:
        # Compose-v1 is intentionally Linux-host constrained until this
        # process can inspect host routes; guessing would be unsafe.
        raise _NetworkPreflightError("ip-command-unavailable")
    try:
        rules_result = subprocess.run(
            ("ip", "-j", "rule", "show"),  # noqa: S607 - fixed Linux route executable
            check=True,
            text=True,
            capture_output=True,
        )
        routes_result = subprocess.run(
            ("ip", "-j", "route", "show", "table", "all"),  # noqa: S607 - fixed Linux route executable
            check=True,
            text=True,
            capture_output=True,
        )
        rules = json.loads(rules_result.stdout)
        routes = json.loads(routes_result.stdout)
    except (OSError, subprocess.CalledProcessError, TypeError, json.JSONDecodeError):
        raise _NetworkPreflightError("host-route-read") from None
    if not isinstance(rules, list) or not isinstance(routes, list):
        raise _NetworkPreflightError("host-route-json-shape")
    _validate_policy_routing(rules, routes, expected=expected)
    for route in routes:
        if not isinstance(route, dict):
            raise _NetworkPreflightError("host-route-shape")
        destination = route.get("dst")
        if destination in (None, "default"):
            continue
        if not isinstance(destination, str):
            raise _NetworkPreflightError("host-route-shape")
        try:
            actual = _parsed_network(destination)
        except ComposeStackError:
            raise _NetworkPreflightError("host-route-destination") from None
        # Docker installs an exact host route for each of this project's
        # already-attested bridge networks.  It is a consequence of the
        # exact labelled IPAM record checked above, not an external route
        # collision.  Never waive a supernet/subnet or an unlabelled route.
        expected_route = owned_routes.get(actual)
        if expected_route is not None:
            expected_device, has_attachment = expected_route
            table = route.get("table", "main")
            if (
                table != "main"
                or route.get("dev") != expected_device
                or route.get("protocol") != "kernel"
                or route.get("scope") != "link"
                or route.get("flags") != ([] if has_attachment else ["linkdown"])
            ):
                raise _NetworkPreflightError("owned-bridge-route-shape")
            continue
        # A bridge also registers two local-table kernel companions for its
        # exact, authenticated gateway and directed broadcast address.  They
        # are not alternative routes and cannot be a policy-table bypass, but
        # ``table all`` must still inspect them.  Waive only Docker's complete
        # fixed records; an extra route, a different interface, or an
        # arbitrary address in the subnet remains an overlap refusal below.
        companion_network = next(
            (
                network
                for network in owned_routes
                if actual.version == network.version
                and actual.network_address in network
                and actual.broadcast_address in network
            ),
            None,
        )
        if companion_network is not None and _is_owned_bridge_local_companion(
            route,
            network=companion_network,
            device=owned_routes[companion_network][0],
            has_attachment=owned_routes[companion_network][1],
        ):
            continue
        if any(actual.version == desired.version and actual.overlaps(desired) for desired in expected):
            if companion_network is not None:
                raise _NetworkPreflightError("owned-bridge-companion-shape")
            raise _NetworkPreflightError("host-route-overlap")


def _is_owned_bridge_local_companion(
    route: dict[object, object],
    *,
    network: ipaddress.IPv4Network | ipaddress.IPv6Network,
    device: str,
    has_attachment: bool,
) -> bool:
    """Recognize only the exact local/broadcast records of one owned bridge."""

    if network.version != 4 or route.get("dev") != device or route.get("table") != "local":
        return False
    gateway = str(_expected_gateway(network))
    broadcast = str(network.broadcast_address)
    common = {
        "dev": device,
        "table": "local",
        "protocol": "kernel",
        "prefsrc": gateway,
    }
    if route.get("type") == "local":
        expected = {**common, "type": "local", "dst": gateway, "scope": "host", "flags": []}
    elif route.get("type") == "broadcast":
        expected = {
            **common,
            "type": "broadcast",
            "dst": broadcast,
            "scope": "link",
            "flags": [] if has_attachment else ["linkdown"],
        }
    else:
        return False
    return route == expected


def _assert_no_one_shot_container() -> None:
    """A completed bootstrap/init container is not a persistent privileged service."""

    completed = _run("ps", "--all", "--services").stdout.splitlines()
    if any(service.strip() in _ONE_SHOTS for service in completed):
        raise ComposeStackError("Compose-v1 lifecycle operation failed")


def _run_bootstrap(
    action: Literal[
        "apply",
        "rollback",
        "rollback-0011",
        "cutover-0012",
        "rollback-0013",
        "admission-close",
        "admission-open",
        "runtime-drain-assert",
        "admission-assert-closed",
        "erasure-drain-assert",
        "start-preflight",
        "rollback-recovery-preflight",
        "rollback-refusal-recovery-preflight",
        "cutover-0012-closed",
        "cutover-0013",
    ],
    *,
    assert_no_one_shot_container: bool = True,
) -> None:
    """Run the owner-side action once, under only the fixed profile/route."""

    _run(
        "run",
        "--build",
        "--rm",
        "--no-deps",
        "-e",
        f"TB_DB_BOOTSTRAP_ACTION={action}",
        "db-bootstrap",
    )
    if assert_no_one_shot_container:
        _assert_no_one_shot_container()


def _run_s3_init() -> None:
    _run("run", "--build", "--rm", "--no-deps", "s3-init")
    try:
        _assert_no_one_shot_container()
    except Exception:
        _compensate_failed_prepublication(admission_exists=True)
        raise


def _prepare_s3_volume() -> None:
    """Grant the named data volume to Seaweed's fixed non-root UID offline."""

    _run("run", "--build", "--rm", "--no-deps", "s3-volume-init")
    _assert_no_one_shot_container()


def _build_local_images() -> None:
    """Build every local image before it is eligible for publication."""

    _run("build", *_BUILT_SERVICES)


def _recreate_postgres_for_upgrade() -> None:
    """Recreate only PostgreSQL after the closed/drained receipt.

    The named ``pgdata`` volume remains the durable cluster, but a normal
    ``up`` would leave the old postmaster (and therefore its previously read
    HBA bytes) in place.  This explicit recreation is the controller's
    upgrade boundary: the subsequent owner bootstrap must attest the freshly
    loaded read-only Compose-v1 profile before it can republish either login.
    """

    _run("up", "--detach", "--wait", "--force-recreate", "postgres")


def _stop_runtime() -> None:
    """Stop every long-running runtime service in its safe public order."""

    _run("stop", "--timeout", "30", "dashboard", "edge", "api")
    _run("stop", "--timeout", "30", "erasure")
    _run("stop", "--timeout", "30", "worker")


def _start_preflight(*, present: set[str] | None = None) -> bool:
    """Refuse ``start`` unless it is an idle closed publication state.

    A zero-state first launch has no PostgreSQL container.  ``start`` launches
    its isolated PostgreSQL core and runs the owner preflight before any
    publication.  Once a core already exists, every core service must be
    running and the owner preflight is run immediately; stopped/restarting,
    created, or dead PostgreSQL is an unsupported partial state.  A
    running/stopped runtime container is not silently repurposed by ``start``:
    operators must use ``upgrade``.
    """

    if present is None:
        present = {
            service.strip() for service in _run("ps", "--all", "--services").stdout.splitlines()
        }
    if present.intersection(_RUNTIME_SERVICES):
        raise ComposeStackError("Compose-v1 start requires an idle closed state; use upgrade")
    present_core = present.intersection(_CORE_SERVICES)
    if not present_core:
        return False
    running = {
        service.strip()
        for service in _run("ps", "--status", "running", "--services").stdout.splitlines()
    }
    if present_core != set(_CORE_SERVICES) or not set(_CORE_SERVICES).issubset(running):
        raise ComposeStackError("Compose-v1 start requires an idle closed state; use upgrade")
    return True


def _is_rollback_recovery_state(present: set[str]) -> bool:
    """Recognize only the controller's closed c12 rollback handoff shape.

    The independent bootstrap preflight below authenticates the c12 history,
    profile, role absence, and closed admission receipt.  This local shape
    check merely decides whether ``start`` may enter that fixed recovery
    protocol instead of treating an arbitrary stopped runtime as idle.
    """

    known = set(_CORE_SERVICES).union(_RUNTIME_SERVICES)
    if (
        not set(_CORE_SERVICES).issubset(present)
        or "worker" not in present
        or not present.issubset(known)
    ):
        return False
    running = {
        service.strip()
        for service in _run("ps", "--status", "running", "--services").stdout.splitlines()
    }
    return (
        set(_CORE_SERVICES).issubset(present)
        and set(_CORE_SERVICES).issubset(running)
        and present.issubset(known)
        and "worker" in present
        and "worker" in running
        and not running.intersection({"api", "edge", "erasure", "dashboard"})
    )


def _recover_rollback_state_for_start() -> None:
    """Drain the exact c12 rollback state before a fresh E4 publication.

    This keeps all mutation inside the lifecycle controller.  The preflight
    rejects any active E4 login/receipt or open admission before it can stop
    the retained worker; normal unknown partial runtime states never reach
    this branch.
    """

    _run_bootstrap("rollback-recovery-preflight")
    _fence_and_drain_runtime()
    # ``_fence_and_drain_runtime`` removes the worker but deliberately keeps
    # stopped public containers for the normal upgrade topology proof.  A
    # recovered ``start`` needs the same idle core state as a first launch,
    # so remove exactly those controller-owned stopped containers here.
    _run("rm", "--force", "api", "edge", "erasure", "dashboard")
    present = {service.strip() for service in _run("ps", "--all", "--services").stdout.splitlines()}
    if present.intersection(_RUNTIME_SERVICES):
        raise ComposeStackError("Compose-v1 lifecycle operation failed")


def _runtime_processes_are_live() -> bool:
    running = {
        service.strip()
        for service in _run("ps", "--status", "running", "--services").stdout.splitlines()
    }
    return set(_RUNTIME_SERVICES).issubset(running)


def _probe_closed_runtime_publication() -> None:
    """Poll fixed process/listener/identity probes while admission is closed."""

    deadline = time.monotonic() + _PREPUBLICATION_TIMEOUT_SECONDS
    while True:
        try:
            if not _runtime_processes_are_live():
                raise ComposeStackError("Compose-v1 lifecycle operation failed")
            _run("exec", "-T", "api", "tracebed-compose-api-prepublication-ready")
            _run("exec", "-T", "worker", "tracebed-compose-worker-prepublication-ready")
            _run(
                "exec",
                "-T",
                "erasure",
                "tracebed-compose-erasure-prepublication-ready",
            )
            _run(
                "exec",
                "-T",
                "api",
                "python",
                "-c",
                "import urllib.request; "
                "response = urllib.request.urlopen('http://127.0.0.1:8110/healthz', timeout=2); "
                "assert response.status == 200",
            )
            _run(
                "exec",
                "-T",
                "edge",
                "python",
                "-c",
                "import urllib.request; "
                "response = urllib.request.urlopen('http://127.0.0.1:8120/healthz', timeout=2); "
                "assert response.status == 200",
            )
            return
        except ComposeStackError:
            if time.monotonic() >= deadline:
                raise ComposeStackError("Compose-v1 lifecycle operation failed") from None
            time.sleep(_PREPUBLICATION_POLL_SECONDS)


def _compensate_failed_prepublication(*, admission_exists: bool) -> None:
    """Stop partial runtime and prove its durable authority gate stayed closed."""

    with suppress(ComposeStackError):
        _stop_runtime()
    if admission_exists:
        _run_bootstrap("admission-assert-closed")


def _compensate_ambiguous_admission_open() -> None:
    """Fence a possibly committed owner-open before reporting its failure.

    Docker can lose the one-shot result after PostgreSQL commits the owner
    transition.  Never infer that an exception means admission remained
    closed: stop all runtime processes, request a fresh owner close, and use
    an independent owner assertion as the only success condition.
    """

    with suppress(ComposeStackError):
        _stop_runtime()
    with suppress(ComposeStackError):
        _run_bootstrap("admission-close")
    _run_bootstrap("admission-assert-closed")


def _stop_public_ingress() -> None:
    """Stop dashboard, edge, and API before closing public admission."""

    _run("stop", "--timeout", "30", "dashboard", "edge", "api")
    running = {service.strip() for service in _run("ps", "--status", "running", "--services").stdout.splitlines()}
    if running.intersection({"api", "edge", "dashboard"}):
        raise ComposeStackError("Compose-v1 lifecycle operation failed")


def _stop_erasure_for_drain() -> None:
    """Stop the only erasure executor before waiting for its lease to expire."""

    _run("stop", "--timeout", "30", "erasure")
    running = {service.strip() for service in _run("ps", "--status", "running", "--services").stdout.splitlines()}
    if "erasure" in running:
        raise ComposeStackError("Compose-v1 lifecycle operation failed")


def _wait_erasure_drain() -> None:
    """Bound the owner-side E4 no-session/no-live-lease proof."""

    deadline = time.monotonic() + _DRAIN_TIMEOUT_SECONDS
    while True:
        try:
            _run_bootstrap("erasure-drain-assert")
            return
        except ComposeStackError:
            if time.monotonic() >= deadline:
                raise ComposeStackError("Compose-v1 lifecycle operation failed") from None
            time.sleep(_DRAIN_POLL_SECONDS)


def _stop_worker_after_drain() -> None:
    """Gracefully stop then remove the drained sole queue consumer.

    Docker can retain one of an exited worker's bridge endpoints for an
    implementation-dependent interval.  Removing only this stopped service
    makes the authenticated drained topology deterministic before the owner
    verifies sessions and recreates PostgreSQL.
    """

    _run("stop", "--timeout", "30", "worker")
    running = {service.strip() for service in _run("ps", "--status", "running", "--services").stdout.splitlines()}
    if "worker" in running:
        raise ComposeStackError("Compose-v1 lifecycle operation failed")
    _run("rm", "--force", "worker")
    present = {service.strip() for service in _run("ps", "--all", "--services").stdout.splitlines()}
    if "worker" in present:
        raise ComposeStackError("Compose-v1 lifecycle operation failed")


def _require_worker_running_for_drain() -> None:
    """Refuse an upgrade/rollback that would silently skip queued work."""

    running = {service.strip() for service in _run("ps", "--status", "running", "--services").stdout.splitlines()}
    if "worker" not in running:
        raise ComposeStackError("Compose-v1 lifecycle operation failed")


def _worker_pending_count() -> int:
    """Ask the running worker container for all v1 queued/leased work.

    A Compose ``run`` would create a second container with the worker
    service's fixed ``10.77.12.3`` address, colliding with the only permitted
    consumer.  ``exec`` instead starts the closed drain entrypoint inside the
    already-authenticated worker container, where it reconstructs only that
    role's DSN from its mounted worker secret.
    """

    output = _run(
        "exec",
        "-T",
        "worker",
        "tracebed-compose-worker-drain",
    ).stdout.strip()
    if not output.isdecimal():
        raise ComposeStackError("Compose-v1 lifecycle operation failed")
    count = int(output)
    if count < 0:
        raise ComposeStackError("Compose-v1 lifecycle operation failed")
    return count


def _drain_worker_queue() -> None:
    """Wait for worker-owned v1 work to reach exactly zero before stopping it."""

    deadline = time.monotonic() + _DRAIN_TIMEOUT_SECONDS
    while True:
        if _worker_pending_count() == 0:
            return
        if time.monotonic() >= deadline:
            raise ComposeStackError("Compose-v1 lifecycle operation failed")
        time.sleep(_DRAIN_POLL_SECONDS)


def _fence_and_drain_runtime() -> None:
    """Stop erasure first, prove lease closure, then close and drain worker."""

    _stop_public_ingress()
    _stop_erasure_for_drain()
    try:
        _wait_erasure_drain()
        # The owner routine holds the singleton UPDATE lock and refuses
        # lingering API sessions.  E4 has already released/expired every
        # executor lease before this final write fence commits.
        _run_bootstrap("admission-close")
        _require_worker_running_for_drain()
        _drain_worker_queue()
        _stop_worker_after_drain()
        _run_bootstrap("runtime-drain-assert")
    except Exception:
        # A drain failure can occur before the normal close mutation.  Fence
        # every runtime, then independently close *and assert* the durable
        # gate rather than merely assuming the interrupted lifecycle left it
        # closed.  If either proof cannot be made, that safety failure is the
        # actionable result.
        with suppress(ComposeStackError):
            _run("stop", "--timeout", "30", "dashboard", "edge", "api", "erasure", "worker")
        with suppress(ComposeStackError):
            _run_bootstrap("admission-close")
        _run_bootstrap("admission-assert-closed")
        raise


def _restore_closed_worker_after_rollback() -> None:
    """Recreate the sole ordinary consumer in the canonical rollback state.

    A successful rollback deliberately leaves API, edge, dashboard, and the E4
    executor stopped, but the next supported controller action still has to
    drain ordinary queued work.  ``_fence_and_drain_runtime`` removes the
    worker to eliminate its retained bridge endpoints before the catalog
    rollback; leaving it absent would make both ``upgrade`` and a subsequent
    c12 rollback impossible without an out-of-band Compose command.

    The replacement is started only after the rollback has committed and the
    owner has independently proved admission remains closed.  Its *closed*
    readiness command authenticates the c12 profile without requiring public
    serving readiness (which correctly stays false while admissions are
    closed).  Any failure stops the replacement and re-proves the durable
    fence before returning an opaque controller failure.
    """

    try:
        _run_bootstrap("admission-assert-closed")
        _run("up", "--detach", "worker")
        deadline = time.monotonic() + _PREPUBLICATION_TIMEOUT_SECONDS
        while True:
            try:
                running = {
                    service.strip()
                    for service in _run("ps", "--status", "running", "--services").stdout.splitlines()
                }
                if "worker" not in running:
                    raise ComposeStackError("Compose-v1 lifecycle operation failed")
                _run("exec", "-T", "worker", "tracebed-compose-worker-prepublication-ready")
                return
            except ComposeStackError:
                if time.monotonic() >= deadline:
                    raise
                time.sleep(_PREPUBLICATION_POLL_SECONDS)
    except Exception:
        with suppress(ComposeStackError):
            _run("stop", "--timeout", "30", "worker")
        _run_bootstrap("admission-assert-closed")
        raise


def _publish_runtime() -> None:
    """Start services closed; the owner open is the final publication mutation."""

    applied = False
    phase = "publish-bootstrap-apply"
    try:
        _run_bootstrap("apply")
        applied = True
        phase = "publish-cutover-0012-closed"
        _run_bootstrap("cutover-0012-closed")
        phase = "publish-cutover-0013"
        _run_bootstrap("cutover-0013")
        phase = "publish-s3-init"
        _run_s3_init()
        # Do not wait here: public health intentionally fails until the final
        # admission transition below.  Dashboard depends on API process start,
        # not on public readiness, for this closed prepublication stage.
        phase = "publish-runtime-start"
        _run("up", "--detach", *_RUNTIME_SERVICES)
        phase = "publish-closed-probe"
        _probe_closed_runtime_publication()
        # This must remain inside the prepublication compensation scope: a
        # residue discovery is a fallible closed-state check, not a mutation
        # permitted after the terminal owner-open below.
        phase = "publish-one-shot-residue"
        _assert_no_one_shot_container()
    except Exception:
        _emit_lifecycle_diagnostic(phase)
        _compensate_failed_prepublication(admission_exists=applied)
        raise
    # Check one-shot residue *before* the owner-open and omit the normal
    # post-run assertion from this terminal call.  A successful owner-open is
    # the final controller mutation; serving health becomes healthy naturally
    # after it commits and no fallible command follows it.
    try:
        _run_bootstrap("admission-open", assert_no_one_shot_container=False)
    except Exception:
        _emit_lifecycle_diagnostic("publish-admission-open")
        _compensate_ambiguous_admission_open()
        raise


def _start() -> None:
    """Create a fresh/idle Compose-v1 stack in its required publication order."""

    try:
        _validate_rendered_configuration()
    except Exception:
        _emit_lifecycle_diagnostic("start-rendered-preflight")
        raise
    initial_present = {
        service.strip() for service in _run("ps", "--all", "--services").stdout.splitlines()
    }
    if _is_rollback_recovery_state(initial_present):
        try:
            _recover_rollback_state_for_start()
        except Exception:
            _emit_lifecycle_diagnostic("start-rollback-recovery")
            raise
        present: set[str] | None = None
    else:
        present = initial_present
    try:
        core_already_running = _start_preflight(present=present)
    except Exception:
        _emit_lifecycle_diagnostic("start-preflight")
        raise
    if core_already_running:
        try:
            _run_bootstrap("start-preflight")
        except ComposeStackError:
            _emit_lifecycle_diagnostic("start-bootstrap-preflight")
            raise ComposeStackError("Compose-v1 start requires an idle closed state; use upgrade") from None
    else:
        # A retained pgdata volume with no container is not treated as a new
        # cluster.  Start only PostgreSQL, authenticate its actual authority
        # state through the owner route, then start the remaining core.
        _run("up", "--detach", "--wait", "postgres")
        try:
            _run_bootstrap("start-preflight")
        except ComposeStackError:
            _emit_lifecycle_diagnostic("start-bootstrap-preflight")
            raise ComposeStackError("Compose-v1 start requires an idle closed state; use upgrade") from None
    try:
        _build_local_images()
    except Exception:
        _emit_lifecycle_diagnostic("start-image-build")
        raise
    try:
        _prepare_s3_volume()
    except Exception:
        _emit_lifecycle_diagnostic("start-s3-volume")
        raise
    try:
        if core_already_running:
            _run("up", "--detach", "--wait", *_CORE_SERVICES)
        else:
            _run("up", "--detach", "--wait", "valkey", "seaweedfs")
    except Exception:
        _emit_lifecycle_diagnostic("start-core-start")
        raise
    _publish_runtime()


def _upgrade() -> None:
    """Fence/drain, recreate PostgreSQL, then attest and re-publish runtime."""

    try:
        _validate_rendered_configuration()
    except Exception:
        _emit_lifecycle_diagnostic("upgrade-rendered-preflight")
        raise
    try:
        _fence_and_drain_runtime()
    except Exception:
        _emit_lifecycle_diagnostic("upgrade-fence-drain")
        raise
    try:
        _build_local_images()
    except Exception:
        _emit_lifecycle_diagnostic("upgrade-image-build")
        raise
    # ``s3-volume-init`` belongs to fresh volume creation only.  Re-running a
    # recursive root chown while Seaweed is serving an existing volume would
    # add an unnecessary mutable data-plane operation to an upgrade.
    try:
        _recreate_postgres_for_upgrade()
    except Exception:
        _emit_lifecycle_diagnostic("upgrade-postgres-recreate")
        raise
    _publish_runtime()


def _rollback() -> None:
    """Rollback the authenticated newest epoch after runtime drain/stop.

    The database refuses after first activity.  This controller intentionally
    leaves the core containers and named data volumes intact on that refusal;
    an operator must investigate rather than receiving a destructive cleanup.
    """

    try:
        _validate_rendered_configuration()
    except Exception:
        _emit_lifecycle_diagnostic("rollback-rendered-preflight")
        raise
    try:
        _fence_and_drain_runtime()
    except Exception:
        _emit_lifecycle_diagnostic("rollback-fence-drain")
        raise
    try:
        _run_bootstrap("rollback")
    except Exception as rollback_failure:
        _emit_lifecycle_diagnostic("rollback-bootstrap")
        # A failed owner call is deliberately treated as ambiguous until the
        # owner independently certifies the one non-mutating outcome that is
        # safe to recover: active 0013 with recorded executor activity and a
        # durable closed admission fence.  A successful certification restores
        # the closed ordinary worker so the documented next ``upgrade`` can
        # drain it.  Any failure of that certification (including an owner
        # call which might have committed a rollback before failing) leaves
        # the worker absent and preserves the original opaque rollback error.
        try:
            _run_bootstrap("rollback-refusal-recovery-preflight")
        except Exception:
            _emit_lifecycle_diagnostic("rollback-refusal-recovery-preflight")
            raise rollback_failure from None
        try:
            _restore_closed_worker_after_rollback()
        except Exception:
            _emit_lifecycle_diagnostic("rollback-refusal-restore-closed-worker")
            raise rollback_failure from None
        raise
    try:
        _restore_closed_worker_after_rollback()
    except Exception:
        _emit_lifecycle_diagnostic("rollback-restore-closed-worker")
        raise


def start() -> None:
    """Run the complete ``start`` lifecycle under one controller-wide lock."""

    with _controller_lifecycle_lock():
        _start()


def upgrade() -> None:
    """Run the complete ``upgrade`` lifecycle under one controller-wide lock."""

    with _controller_lifecycle_lock():
        _upgrade()


def rollback() -> None:
    """Run the complete ``rollback`` lifecycle under one controller-wide lock."""

    with _controller_lifecycle_lock():
        _rollback()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("start", "upgrade", "rollback"))
    arguments = parser.parse_args(argv)
    try:
        {"start": start, "upgrade": upgrade, "rollback": rollback}[arguments.action]()
    except ComposeStackError as error:
        print(str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
