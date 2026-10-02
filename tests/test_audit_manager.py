"""MCP config file safety and agent launch integration regressions."""

from __future__ import annotations

import json
import os
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
    assert not str(config_path).startswith(str(workspace) + "/")
    assert (workspace / link.name).is_symlink()
    assert os.stat(config_path).st_mode & 0o777 == 0o600
    assert os.stat(os.path.dirname(config_path)).st_mode & 0o777 == 0o700


def test_session_mounts_private_mcp_config_read_only(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    class _CaptureSessionBackend:
        name = "bubblewrap"

        def prepare(self, spec):
            self.spec = spec

        def launch(self, _spec):
            return SimpleNamespace(status=SandboxStatus.RUNNING)

    class _CaptureRepository:
        def record_sandbox_session(self, **_kwargs):
            pass

    manager = SandboxManager.__new__(SandboxManager)
    manager.backend = _CaptureSessionBackend()
    manager.repository = _CaptureRepository()
    manager.db_path = str(tmp_path / "audit.db")
    manager._mcp_config_paths = {}
    manager.create_session(str(workspace), session_id="mcp-mount-canary")

    mount = next(m for m in manager.backend.spec.extra_mounts if m.container_path == "/tmp/.drex_mcp_config.json")
    assert mount.mode == "ro"
    assert not mount.host_path.startswith(str(workspace) + "/")
    manager._remove_mcp_config("mcp-mount-canary")


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
    private_dir = tmp_path / "private"
    private_dir.mkdir(mode=0o700)
    config_path = private_dir / "mcp.json"
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

    # An untrusted workspace replacement does not alter the private host copy.
    workspace_config = workspace / ".drex_mcp_config.json"
    workspace_config.symlink_to(tmp_path / "attacker.json")
    (tmp_path / "attacker.json").write_text("{}", encoding="utf-8")

    manager.run_agent("mcp-canary", "synthetic prompt")

    command = manager.backend.command
    if agent_type == "claude":
        assert "--mcp-config" in command
        assert command[command.index("--mcp-config") + 1] == "/tmp/.drex_mcp_config.json"
        assert "--strict-mcp-config" in command
    else:
        serialized = " ".join(command)
        assert "mcp_servers.drex_firewall.command" in serialized
        assert "mcp_servers.drex_firewall.args" in serialized
        assert "drex_agent_firewall.mcp.server" in serialized
