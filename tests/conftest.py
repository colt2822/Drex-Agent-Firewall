"""Pytest configuration and shared fixtures for hermetic test execution."""

import os
import shutil
import tempfile
import pytest

from drex_agent_firewall import DrexFirewall
from drex_agent_firewall.schemas.config import FirewallConfig


@pytest.fixture
def temp_workspace(tmp_path):
    """Provides a temporary, hermetic directory for filesystem and shell tests."""
    ws = tmp_path / "workspace"
    ws.mkdir()
    # Create sample files
    (ws / "README.md").write_text("# Test Workspace\n")
    src = ws / "src"
    src.mkdir()
    (src / "app.py").write_text("print('hello world')\n")
    return ws


@pytest.fixture
def hermetic_config(temp_workspace, tmp_path):
    """Firewall configuration confined strictly to temp_workspace and a temporary database."""
    cfg = FirewallConfig.load_default()
    cfg.provider.type = "replay"
    cfg.filesystem.allowed_roots = [str(temp_workspace)]
    cfg.filesystem.blocked_paths = [str(temp_workspace / "forbidden")]
    cfg.database_path = str(tmp_path / "test_firewall.db")
    return cfg


@pytest.fixture
def hermetic_firewall(hermetic_config):
    """Firewall instance isolated to disposable temporary resources."""
    return DrexFirewall(config=hermetic_config)
