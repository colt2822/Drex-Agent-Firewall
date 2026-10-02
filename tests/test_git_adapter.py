"""Hermetic tests for GitAdapter."""

import subprocess
from drex_agent_firewall.adapters.git_adapter import GitAdapter
from drex_agent_firewall.policy.engine import DeterministicPolicyEngine
from drex_agent_firewall.schemas.config import FirewallConfig


def test_git_status_and_commit(temp_workspace):
    # Initialize a hermetic git repo inside temp_workspace
    subprocess.run(["git", "init"], cwd=str(temp_workspace), check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=str(temp_workspace), check=True)
    subprocess.run(["git", "config", "user.email", "test@test.local"], cwd=str(temp_workspace), check=True)

    cfg = FirewallConfig.load_default()
    cfg.filesystem.allowed_roots = [str(temp_workspace)]
    engine = DeterministicPolicyEngine(config=cfg)
    adapter = GitAdapter(engine)

    # Status check (read-only -> ALLOW)
    status_res = adapter.status(repo_dir=str(temp_workspace))
    assert status_res.allowed is True

    # Commit check (write -> ALLOW_WITH_CONSTRAINTS)
    adapter.add(["README.md"], repo_dir=str(temp_workspace))
    commit_res = adapter.commit("Initial commit", repo_dir=str(temp_workspace))
    assert commit_res.allowed is True


def test_git_force_push_blocked(temp_workspace):
    cfg = FirewallConfig.load_default()
    cfg.filesystem.allowed_roots = [str(temp_workspace)]
    engine = DeterministicPolicyEngine(config=cfg)
    adapter = GitAdapter(engine)

    push_res = adapter.push(branch="main", force=True, repo_dir=str(temp_workspace))
    assert push_res.allowed is False
    assert "Blocked by firewall" in push_res.error
