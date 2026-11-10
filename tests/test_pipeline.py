"""End to end test of the whole pipeline against a local mock network.

The mock provides a real SOCKS5 proxy and a real HTTP server, so sing-box
actually opens a tunnel and the measurement code really transfers bytes.
"""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path

import pytest

from tunnelbench.models import BenchSettings
from tunnelbench.pipeline import run_benchmark


@pytest.fixture(autouse=True)
def _allow_private_urls():
    os.environ["TUNNELBENCH_ALLOW_PRIVATE_URLS"] = "1"
    yield
    os.environ.pop("TUNNELBENCH_ALLOW_PRIVATE_URLS", None)


def _socks_uri(port: int, name: str, credentials: str | None = None) -> str:
    if credentials is None:
        return f"socks://127.0.0.1:{port}#{name}"
    encoded = base64.b64encode(credentials.encode()).decode()
    return f"socks://{encoded}@127.0.0.1:{port}#{name}"


def test_pipeline_end_to_end(mock_network, sing_box_binary, tmp_path):
    mock_network.config_text = "\n".join(
        [
            _socks_uri(mock_network.socks_port, "Mock A", "user:pass"),
            _socks_uri(mock_network.socks_port, "Mock B"),
            "trojan://dead@127.0.0.1:1?sni=dead.example#Dead",
            "this-is-not-a-configuration",
        ]
    )

    settings = BenchSettings(
        source_url=f"{mock_network.base_url}/configs.txt",
        output_dir=str(tmp_path / "out"),
        max_configs=10,
        concurrency=4,
        speed_test_bytes=64 * 1024,
        latency_url=f"{mock_network.base_url}/generate_204",
        speed_test_url=f"{mock_network.base_url}/speed",
        exit_ip_url=f"{mock_network.base_url}/ip-api",
        iran_probe="off",
        geo_lookup=False,
        core_path=sing_box_binary,
        latency_samples=2,
    )

    report = run_benchmark(settings)

    assert report.parsed == 3
    assert report.rejected == 1
    assert report.tested == 3
    assert report.alive == 2
    assert report.best_mbps > 0
    assert report.median_latency_ms > 0

    output = Path(settings.output_dir)
    for name in (
        "working_configs.txt",
        "working_configs_plain.txt",
        "alive_configs.txt",
        "configs_ranked.csv",
        "results.json",
        "summary.md",
        "report.pdf",
    ):
        assert (output / name).exists(), name
        assert (output / name).stat().st_size > 0, name

    plain = (output / "working_configs_plain.txt").read_text(encoding="utf-8")
    assert "Mock A" in plain

    subscription = (output / "working_configs.txt").read_text(encoding="utf-8").strip()
    decoded = base64.b64decode(subscription).decode("utf-8")
    assert "Mock B" in decoded

    payload = json.loads((output / "results.json").read_text(encoding="utf-8"))
    assert payload["counts"]["alive"] == 2
    assert payload["results"][0]["download_mbps"] > 0
    assert payload["results"][0]["exit_ip"] == "203.0.113.7"

    pdf = (output / "report.pdf").read_bytes()
    assert pdf.startswith(b"%PDF")
    assert len(pdf) > 5000


def test_dry_run_only_parses(mock_network, tmp_path):
    mock_network.config_text = _socks_uri(mock_network.socks_port, "Mock A")
    settings = BenchSettings(
        source_url=f"{mock_network.base_url}/configs.txt",
        output_dir=str(tmp_path / "out"),
        dry_run=True,
    )
    report = run_benchmark(settings)
    assert report.parsed == 1
    assert report.tested == 0
    assert (Path(settings.output_dir) / "summary.md").exists()
