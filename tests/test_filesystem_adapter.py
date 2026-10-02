"""Hermetic tests for FilesystemAdapter."""

import os
from drex_agent_firewall.adapters.filesystem_adapter import FilesystemAdapter
from drex_agent_firewall.policy.engine import DeterministicPolicyEngine
from drex_agent_firewall.schemas.config import FirewallConfig


def test_fs_create_and_read_file(temp_workspace):
    cfg = FirewallConfig.load_default()
    cfg.filesystem.allowed_roots = [str(temp_workspace)]
    engine = DeterministicPolicyEngine(config=cfg)
    adapter = FilesystemAdapter(engine)

    # 1. Create file inside hermetic workspace
    create_res = adapter.create_file(str(temp_workspace / "demo.txt"), "hello firewall")
    assert create_res.allowed is True
    assert create_res.new_hash is not None

    # 2. Read file back
    read_res = adapter.read_file(str(temp_workspace / "demo.txt"))
    assert read_res.allowed is True
    assert read_res.content == "hello firewall"


def test_fs_rejects_path_traversal(temp_workspace):
    cfg = FirewallConfig.load_default()
    cfg.filesystem.allowed_roots = [str(temp_workspace)]
    engine = DeterministicPolicyEngine(config=cfg)
    adapter = FilesystemAdapter(engine)

    res = adapter.create_file(str(temp_workspace / "../../escape.txt"), "forbidden")
    assert res.allowed is False
    assert "Blocked by firewall" in res.error
