"""Tests for decision providers: ReplayProvider, DrexProvider, and failure modes."""

import pytest
import httpx
from drex_agent_firewall.normalizers.context_normalizer import ContextNormalizer
from drex_agent_firewall.providers.drex_provider import DrexProvider
from drex_agent_firewall.providers.replay_provider import ReplayProvider
from drex_agent_firewall.schemas.decision import ActionRisk, FinalDecision


def test_replay_provider_labeling_and_probabilities():
    provider = ReplayProvider(requested_model="drex-latest")
    assert provider.provider_name == "REPLAY"

    normalizer = ContextNormalizer()
    env = normalizer.normalize(
        tool="shell",
        operation="execute",
        arguments={"command": "cat README.md"},
    )

    result = provider.evaluate(env)
    assert result.provider == "REPLAY"
    assert result.requested_model == "drex-latest"
    assert result.resolved_model == "replay-deterministic-v1"
    assert result.risk == ActionRisk.LOW

    # Verify probability distributions are preserved across dimensions
    dist = result.distributions
    assert "LOW" in dist.risk
    assert "READ" in dist.action_class
    assert "IN_SCOPE" in dist.scope_match
    assert sum(dist.risk.values()) == pytest.approx(1.0, abs=0.01)
    assert sum(dist.action_class.values()) == pytest.approx(1.0, abs=0.01)


def test_drex_provider_connection_error_handling():
    # Target an invalid/unreachable URL to verify clean error propagation
    provider = DrexProvider(api_url="http://127.0.0.1:54321", api_key="fake-key", timeout_seconds=0.5)

    normalizer = ContextNormalizer()
    env = normalizer.normalize(
        tool="shell",
        operation="execute",
        arguments={"command": "ls"},
    )

    with pytest.raises(httpx.RequestError):
        provider.evaluate(env)
