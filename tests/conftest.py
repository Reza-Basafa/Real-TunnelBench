"""Shared pytest fixtures."""

from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from tests.mocknet import MockNetwork  # noqa: E402


@pytest.fixture(scope="session")
def mock_network():
    network = MockNetwork(config_text="", payload_size=256 * 1024)
    yield network
    network.stop()


def _find_core() -> str:
    explicit = os.environ.get("SING_BOX_BINARY", "")
    if explicit and Path(explicit).exists():
        return explicit
    return shutil.which("sing-box") or ""


@pytest.fixture(scope="session")
def sing_box_binary() -> str:
    binary = _find_core()
    if not binary:
        pytest.skip("no sing-box binary available (set SING_BOX_BINARY)")
    return binary
