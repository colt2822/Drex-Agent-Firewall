"""Tests for Deterministic hard invariants."""

from drex_agent_firewall.normalizers.context_normalizer import ContextNormalizer
from drex_agent_firewall.policy.deterministic_rules import DeterministicRulesEngine
from drex_agent_firewall.schemas.config import FirewallConfig
from drex_agent_firewall.schemas.decision import FinalDecision


def test_hard_rule_forbidden_shell_command():
    config = FirewallConfig.load_default()
    engine = DeterministicRulesEngine(config)
    normalizer = ContextNormalizer()

    env = normalizer.normalize(
        tool="shell",
        operation="execute",
        arguments={"command": "rm -rf /"},
    )
    result = engine.evaluate(env)
    assert result is not None
    assert result.triggered is True
    assert result.decision == FinalDecision.BLOCK
    assert result.rule_name == "HARD_RULE_FORBIDDEN_SHELL_COMMAND"


def test_hard_rule_ssrf_blocked():
    config = FirewallConfig.load_default()
    engine = DeterministicRulesEngine(config)
    normalizer = ContextNormalizer()

    env = normalizer.normalize(
        tool="http",
        operation="GET",
        arguments={"url": "http://169.254.169.254/latest/meta-data/"},
    )
    result = engine.evaluate(env)
    assert result is not None
    assert result.decision == FinalDecision.BLOCK
    assert result.rule_name == "HARD_RULE_BLOCKED_NETWORK_TARGET"


def test_hard_rule_git_force_push():
    config = FirewallConfig.load_default()
    engine = DeterministicRulesEngine(config)
    normalizer = ContextNormalizer()

    env = normalizer.normalize(
        tool="git",
        operation="push",
        arguments={"remote": "origin", "branch": "main", "force": True},
    )
    result = engine.evaluate(env)
    assert result is not None
    assert result.decision == FinalDecision.BLOCK
    assert result.rule_name == "HARD_RULE_GIT_FORCE_PUSH_FORBIDDEN"
