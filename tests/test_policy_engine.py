"""Tests for DeterministicPolicyEngine confidence thresholds and dispositions."""

from drex_agent_firewall.normalizers.context_normalizer import ContextNormalizer
from drex_agent_firewall.policy.engine import DeterministicPolicyEngine
from drex_agent_firewall.providers.replay_provider import ReplayProvider
from drex_agent_firewall.schemas.config import FirewallConfig
from drex_agent_firewall.schemas.decision import FinalDecision


def test_benign_read_allows():
    engine = DeterministicPolicyEngine()
    normalizer = ContextNormalizer()
    env = normalizer.normalize(
        tool="shell",
        operation="execute",
        arguments={"command": "cat README.md"},
    )
    decision = engine.evaluate(env)
    assert decision.decision == FinalDecision.ALLOW
    assert decision.allowed is True


def test_filesystem_write_returns_constraints():
    engine = DeterministicPolicyEngine()
    normalizer = ContextNormalizer()
    env = normalizer.normalize(
        tool="filesystem",
        operation="modify",
        arguments={"path": "src/app.py", "content": "print(1)"},
    )
    decision = engine.evaluate(env)
    assert decision.decision == FinalDecision.ALLOW_WITH_CONSTRAINTS
    assert decision.allowed is True
    assert decision.constraints.max_runtime_seconds is not None
    assert decision.constraints.no_force_push is True


def test_fail_disposition_on_provider_error(monkeypatch):
    config = FirewallConfig.load_default()
    engine = DeterministicPolicyEngine(config=config)

    # Force provider to throw
    def _mock_eval(env):
        raise TimeoutError("Provider timed out")

    monkeypatch.setattr(engine.provider, "evaluate", _mock_eval)

    normalizer = ContextNormalizer()
    # Read should fail-open (ALLOW)
    env_read = normalizer.normalize(tool="shell", operation="execute", arguments={"command": "cat README.md"})
    dec_read = engine.evaluate(env_read)
    assert dec_read.decision == FinalDecision.ALLOW

    # Delete should fail-closed (BLOCK)
    env_del = normalizer.normalize(tool="filesystem", operation="delete", arguments={"path": "data.db"})
    dec_del = engine.evaluate(env_del)
    assert dec_del.decision == FinalDecision.BLOCK
