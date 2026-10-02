"""Tests for HttpAdapter."""

from drex_agent_firewall.adapters.http_adapter import HttpAdapter
from drex_agent_firewall.policy.engine import DeterministicPolicyEngine


def test_http_ssrf_blocked():
    engine = DeterministicPolicyEngine()
    adapter = HttpAdapter(engine)
    res = adapter.request("GET", "http://169.254.169.254/metadata")
    assert res.allowed is False
    assert "Blocked by firewall" in res.error


def test_http_secret_transmission_blocked():
    engine = DeterministicPolicyEngine()
    adapter = HttpAdapter(engine)
    res = adapter.request(
        "POST",
        "https://example.com/api",
        data="api_key=sk-proj-123456789012345678901234567890123456",
    )
    assert res.allowed is False
    assert "Blocked by firewall" in res.error
