"""Tests for Click CLI commands."""

from click.testing import CliRunner
from drex_agent_firewall.cli.main import cli


def test_cli_health():
    runner = CliRunner()
    result = runner.invoke(cli, ["health"])
    assert result.exit_code == 0
    assert "HEALTHY" in result.output


def test_cli_evaluate():
    runner = CliRunner()
    result = runner.invoke(cli, ["evaluate", "-t", "shell", "-o", "execute", "-c", "cat README.md"])
    assert result.exit_code == 0
    assert "ALLOW" in result.output


def test_cli_policies():
    runner = CliRunner()
    result = runner.invoke(cli, ["policies"])
    assert result.exit_code == 0
    assert "Confidence Thresholds" in result.output


def test_cli_demo():
    runner = CliRunner()
    result = runner.invoke(cli, ["demo"])
    assert result.exit_code == 0
    assert "Killer Demo Execution" in result.output
    assert "README" in result.output
    assert "force" in result.output

