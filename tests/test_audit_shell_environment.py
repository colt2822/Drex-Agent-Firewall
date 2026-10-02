"""Ambient and explicit environment credential filtering regression."""

from drex_agent_firewall.adapters.shell_adapter import ShellAdapter
from drex_agent_firewall.policy.engine import DeterministicPolicyEngine
from drex_agent_firewall.schemas.config import FirewallConfig


def test_shell_adapter_does_not_inherit_secret_environment_variants(monkeypatch):
    values = {
        "openai_api_key": "DREX_SYNTHETIC_OPENAI_CANARY",
        "aws_secret_access_key": "DREX_SYNTHETIC_AWS_CANARY",
        "custom_db_password": "DREX_SYNTHETIC_PASSWORD_CANARY",
        "custom_service_key": "DREX_SYNTHETIC_CUSTOM_KEY_CANARY",
        "session_cookie": "DREX_SYNTHETIC_COOKIE_CANARY",
        "custom_authorization": "DREX_SYNTHETIC_AUTHORIZATION_CANARY",
        "http_proxy": "DREX_SYNTHETIC_PROXY_CANARY",
    }
    for name, value in values.items():
        monkeypatch.setenv(name, value)

    config = FirewallConfig.from_pack("safe-local-coding")
    config.provider.type = "replay"
    config.thresholds.EXECUTE = 0.80
    result = ShellAdapter(DeterministicPolicyEngine(config=config)).execute(
        "env",
        env={"github_token": "DREX_SYNTHETIC_EXPLICIT_TOKEN_CANARY"},
    )

    assert result.allowed
    assert all(value not in result.stdout for value in values.values())
    assert "DREX_SYNTHETIC_EXPLICIT_TOKEN_CANARY" not in result.stdout
