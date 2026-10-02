"""Tests for ActionEnvelope normalization and validation."""

from drex_agent_firewall.normalizers.context_normalizer import ContextNormalizer
from drex_agent_firewall.schemas.envelope import ActionEnvelope


def test_normalize_shell_action():
    normalizer = ContextNormalizer()
    env = normalizer.normalize(
        tool="shell",
        operation="execute",
        arguments={"command": "cat README.md"},
        context={"cwd": "/workspace"},
    )
    assert env.tool == "shell"
    assert env.operation == "execute"
    assert env.read_only is True
    assert env.process_execution is True
    assert env.resource_target == "cat README.md"


def test_normalize_destructive_action():
    normalizer = ContextNormalizer()
    env = normalizer.normalize(
        tool="shell",
        operation="execute",
        arguments={"command": "rm -rf /tmp/data"},
    )
    assert env.destructive is True
    assert env.reversible is False


def test_normalize_git_push():
    normalizer = ContextNormalizer()
    env = normalizer.normalize(
        tool="git",
        operation="push",
        arguments={"remote": "origin", "branch": "main", "force": True},
    )
    assert env.external_write is True
    assert env.network_access is True
    assert env.destructive is True
