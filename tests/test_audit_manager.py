"""MCP config file safety and agent launch integration regressions."""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from drex_agent_firewall.sandbox.backend import SandboxStatus
from drex_agent_firewall.sandbox.manager import SandboxManager


def test_session_mcp_config_does_not_follow_workspace_symlink(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    outside = tmp_path / "host-canary.txt"
    outside.write_text("unchanged host canary", encoding="utf-8")
    link = workspace / ".drex_mcp_config.json"
    link.symlink_to(outside)

    manager = SandboxManager.__new__(SandboxManager)
    config_path = manager._generate_mcp_config(str(workspace), "safe-local-coding", "symlink-canary", "claude")

    assert outside.read_text(encoding="utf-8") == "unchanged host canary"
    assert config_path != str(link)
    assert not (workspace / config_path).is_symlink()


class _CaptureBackend:
    name = "bubblewrap"

    def __init__(self):
        self.command = None

    def status(self, _session_id):
        return SandboxStatus.RUNNING

    def exec_agent(self, _session_id, command, **_kwargs):
        self.command = command
        return SimpleNamespace(returncode=0, stdout="", stderr="")


class _SessionRepository:
    def __init__(self, agent_type, mcp_config_path):
        self.agent_type = agent_type
        self.mcp_config_path = mcp_config_path

    def get_sandbox_session(self, _session_id):
        return {
            "agent": self.agent_type,
            "network_mode": "controlled-online",
            "metadata_json": {"mcp_config_path": self.mcp_config_path},
        }


@pytest.mark.parametrize("agent_type", ["claude", "codex"])
def test_run_agent_loads_the_generated_firewall_mcp_server(tmp_path, agent_type):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    manager = SandboxManager.__new__(SandboxManager)
    manager.backend = _CaptureBackend()
    manager._mcp_config_paths = {}
    config_path = workspace / "mcp.json"
    config_path.write_text(
        json.dumps({
            "mcpServers": {
                "drex_firewall": {
                    "command": "python3",
                    "args": ["-m", "drex_agent_firewall.mcp.server", "--session-id", "mcp-canary"],
                    "env": {"DREX_DATABASE_PATH": "/workspace/.drex_firewall.db"},
                }
            }
        }),
        encoding="utf-8",
    )
    manager.repository = _SessionRepository(agent_type, str(config_path))

    manager.run_agent("mcp-canary", "synthetic prompt")

    command = manager.backend.command
    if agent_type == "claude":
        assert "--mcp-config" in command
        assert command[command.index("--mcp-config") + 1] == f"/workspace/{config_path.name}"
        assert "--strict-mcp-config" in command
    else:
        serialized = " ".join(command)
        assert "mcp_servers.drex_firewall.command" in serialized
        assert "mcp_servers.drex_firewall.args" in serialized
        assert "drex_agent_firewall.mcp.server" in serialized
