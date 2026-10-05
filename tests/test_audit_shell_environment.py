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
    )

    assert result.allowed
    assert all(value not in result.stdout for value in values.values())
    blocked = ShellAdapter(DeterministicPolicyEngine(config=config)).execute("env", env={"PYTHONPATH": "/tmp/evil"})
    assert not blocked.allowed


def test_execution_environment_filter_blocks_code_loading_controls():
    from drex_agent_firewall.security.environment import filter_environment
    hostile = {"PYTHONPATH": "/tmp/evil", "LD_PRELOAD": "/tmp/evil.so", "BASH_ENV": "/tmp/evil.sh", "PATH": "/usr/bin"}
    assert filter_environment(hostile) == {"PATH": "/usr/bin"}


def test_audit_text_escapes_terminal_control_characters():
    from drex_agent_firewall.persistence.repository import _safe_audit_text
    rendered = _safe_audit_text("ok\n[FAKE_AUDIT]\x1b[31m")
    assert "\n" not in rendered
    assert "\x1b" not in rendered
    assert "\\u000a" in rendered
    assert "\\u001b" in rendered
