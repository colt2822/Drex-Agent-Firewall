"""Tests for GitHubAdapter."""

from drex_agent_firewall.adapters.github_adapter import GitHubAdapter
from drex_agent_firewall.policy.engine import DeterministicPolicyEngine


def test_github_read_issue():
    engine = DeterministicPolicyEngine()
    adapter = GitHubAdapter(engine)
    res = adapter.read_issue("org/repo", 42)
    assert res.allowed is True
    assert res.firewall_decision.decision.value == "ALLOW"


def test_github_mutation_escalation():
    engine = DeterministicPolicyEngine()
    adapter = GitHubAdapter(engine)
    res = adapter.create_pr("org/repo", "Fix bug", "feat", "main", "body")
    assert res.allowed is False
    assert res.firewall_decision.decision.value == "ESCALATE"
    assert res.idempotency_key is not None
