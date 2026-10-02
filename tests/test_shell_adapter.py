"""Hermetic tests for ShellAdapter."""

import os
from drex_agent_firewall.adapters.shell_adapter import ShellAdapter
from drex_agent_firewall.policy.engine import DeterministicPolicyEngine
from drex_agent_firewall.schemas.config import FirewallConfig


def test_shell_execute_safe_command(temp_workspace):
    cfg = FirewallConfig.load_default()
    cfg.filesystem.allowed_roots = [str(temp_workspace)]
    engine = DeterministicPolicyEngine(config=cfg)
    adapter = ShellAdapter(engine)

    result = adapter.execute("echo 'hello hermetic test'", cwd=str(temp_workspace))
    assert result.allowed is True
    assert result.exit_code == 0
    assert "hello hermetic test" in result.stdout


def test_shell_blocks_dangerous_command(temp_workspace):
    cfg = FirewallConfig.load_default()
    cfg.filesystem.allowed_roots = [str(temp_workspace)]
    engine = DeterministicPolicyEngine(config=cfg)
    adapter = ShellAdapter(engine)

    result = adapter.execute("rm -rf /", cwd=str(temp_workspace))
    assert result.allowed is False
    assert "Blocked by firewall" in result.error


def test_shell_timeout_enforcement(temp_workspace):
    cfg = FirewallConfig.load_default()
    cfg.filesystem.allowed_roots = [str(temp_workspace)]
    cfg.shell.max_runtime_seconds = 1.0
    engine = DeterministicPolicyEngine(config=cfg)
    adapter = ShellAdapter(engine)

    result = adapter.execute("sleep 5", cwd=str(temp_workspace), timeout=0.5)
    assert result.allowed is True
    assert result.exit_code == -9
    assert "timeout" in (result.error or "").lower()

