"""Bounded local-demo owner/data utility contract."""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from tracebed import local_demo_provision as demo

pytestmark = pytest.mark.phase1


def test_seed_manifest_is_fixed_unique_uuid_evidence() -> None:
    runs = demo.load_seed_manifest()
    assert len(runs) == 5
    assert len({run.run_id for run in runs}) == 5
    assert runs[0].facts == "5,230 passed; 311 skipped."


def test_fixed_secret_reader_rejects_writable_or_linked_leaves(tmp_path: Path) -> None:
    secret_dir = tmp_path / "secrets"
    secret_dir.mkdir()
    secret_dir.chmod(0o700)
    secret = secret_dir / "demo_api_key_secret"
    secret.write_text("value", encoding="utf-8")
    secret.chmod(0o644)
    assert demo._read_fixed_secret(secret, expected_name="demo_api_key_secret") == "value"
    secret.chmod(0o666)
    with pytest.raises(demo.DemoProvisionError):
        demo._read_fixed_secret(secret, expected_name="demo_api_key_secret")
    secret.unlink()
    secret.symlink_to(tmp_path / "missing")
    with pytest.raises(demo.DemoProvisionError):
        demo._read_fixed_secret(secret, expected_name="demo_api_key_secret")


def test_public_seed_uses_only_api_key_batch_and_export_poll() -> None:
    requests: list[httpx.Request] = []
    runs = demo.load_seed_manifest()

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.url.path == "/v1/trace/batch":
            return httpx.Response(202, json={"status": "accepted"})
        payload = "".join(
            '{"table":"trace_index","row":{"run_id":"'
            + str(run.run_id)
            + '","outcome_status":"ok"}}\n'
            for run in runs
        )
        return httpx.Response(200, text=payload)

    with httpx.Client(base_url="http://api:8110", transport=httpx.MockTransport(handler)) as client:
        demo.seed_public_api(
            "tb_sk_demo-key1.abcdefghijklmnop", runs, client=client, sleep=lambda _: None
        )

    assert [request.url.path for request in requests] == ["/v1/trace/batch", "/export/project"]
    assert all(request.headers["x-api-key"].startswith("tb_sk_") for request in requests)
    assert all("authorization" not in request.headers for request in requests)
    batch = requests[0]
    assert batch.content.count(b'"type":"run_end"') == len(runs)


def test_public_seed_requires_each_manifest_terminal_outcome() -> None:
    original = demo.load_seed_manifest()
    runs = (
        demo.SeedRun(original[0].run_id, original[0].label, "failed", original[0].facts),
        *original[1:],
    )

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/trace/batch":
            return httpx.Response(202, json={"status": "accepted"})
        return httpx.Response(
            200,
            text="".join(
                '{"table":"trace_index","row":{"run_id":"'
                + str(run.run_id)
                + '","outcome_status":"'
                + ("error" if run.status == "failed" else "ok")
                + '"}}\n'
                for run in runs
            ),
        )

    with httpx.Client(base_url="http://api:8110", transport=httpx.MockTransport(handler)) as client:
        demo.seed_public_api(
            "tb_sk_demo-key1.abcdefghijklmnop", runs, client=client, sleep=lambda _: None
        )
