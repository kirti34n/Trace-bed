"""Real-socket nginx streaming contract used by the edge export acceptance path."""

# ruff: noqa: S104, S603, S607

from __future__ import annotations

import shutil
import socket
import socketserver
import subprocess
import tempfile
import threading
import time
from pathlib import Path

import httpx
import pytest

pytestmark = pytest.mark.phase1


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def _wait_for(port: int) -> None:
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                return
        except OSError:
            time.sleep(0.05)
    raise AssertionError(f"socket {port} did not start")


@pytest.mark.skipif(shutil.which("docker") is None, reason="real nginx transport needs Docker")
def test_nginx_real_socket_keeps_clean_export_complete_and_breaks_over_limit() -> None:
    """Exercise a real nginx hop, not TestClient's in-memory response buffer.

    The edge's generator uses this same response shape: an under-cap unknown
    length stream ends cleanly, while an over-cap generator raises after a
    partial chunk and nginx must not manufacture a clean EOF.
    """
    backend_port = _free_port()
    nginx_port = _free_port()
    container_name = f"tracebed-edge-socket-{nginx_port}"
    class Upstream(socketserver.BaseRequestHandler):
        def handle(self) -> None:
            request = self.request.recv(4_096)
            path = request.split(b" ", 2)[1]
            self.request.sendall(
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n"
                b"X-Tracebed-Export-Completeness: complete\r\n\r\n"
            )
            chunks = (b"a" * 600_000, b"b" * 600_000, b"c" * 400_000)
            if path == b"/under":
                for chunk in chunks:
                    self.request.sendall(f"{len(chunk):x}\r\n".encode("ascii") + chunk + b"\r\n")
                self.request.sendall(b"0\r\n\r\n")
            else:
                # Equivalent to edge cancelling the upstream as soon as the
                # next chunk would cross its 16MiB cap: no terminal chunk.
                chunk = b"x" * (9 * 1_024 * 1_024)
                self.request.sendall(f"{len(chunk):x}\r\n".encode("ascii") + chunk + b"\r\n")

    server = socketserver.ThreadingTCPServer(("0.0.0.0", backend_port), Upstream)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    _wait_for(backend_port)

    nginx: subprocess.Popen[str] | None = None
    try:
        with tempfile.TemporaryDirectory() as temporary:
            config = Path(temporary) / "nginx.conf"
            config.write_text(
                "events {}\nhttp { server { listen "
                + str(nginx_port)
                + "; location / { proxy_buffering off; proxy_request_buffering off; "
                + "proxy_pass http://host.docker.internal:"
                + str(backend_port)
                + "; } } }\n",
                encoding="utf-8",
            )
            nginx = subprocess.Popen(
                [
                    "docker",
                    "run",
                    "--rm",
                    "--name",
                    container_name,
                    "--add-host",
                    "host.docker.internal:host-gateway",
                    "-p",
                    f"127.0.0.1:{nginx_port}:{nginx_port}",
                    "-v",
                    f"{config}:/etc/nginx/nginx.conf:ro",
                    "nginx:1.27-alpine",
                ],
                text=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            _wait_for(nginx_port)
            # A TCP listener can precede nginx's first successful upstream
            # connect; let its worker finish initialising before reading.
            time.sleep(0.25)
            with httpx.Client(timeout=10) as client:
                under = client.get(f"http://127.0.0.1:{nginx_port}/under")
                assert under.status_code == 200
                assert under.content == b"a" * 600_000 + b"b" * 600_000 + b"c" * 400_000
                assert under.headers["x-tracebed-export-completeness"] == "complete"
                with pytest.raises(httpx.TransportError):
                    client.get(f"http://127.0.0.1:{nginx_port}/over")
    finally:
        if nginx is not None:
            subprocess.run(
                ["docker", "rm", "-f", container_name],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            nginx.wait(timeout=10)
        server.shutdown()
        server.server_close()
        thread.join(timeout=10)
