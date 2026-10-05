import json
import stat
from pathlib import Path

from click.testing import CliRunner

from drex_agent_firewall.cli.main import cli


def test_init_is_idempotent_and_uses_xdg_paths(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    runner = CliRunner()
    first = runner.invoke(cli, ["init"])
    second = runner.invoke(cli, ["init"])
    assert first.exit_code == second.exit_code == 0
    config = tmp_path / "config/drex-firewall"
    data = tmp_path / "data/drex-firewall"
    assert (config / "policy.yaml").exists()
    assert (data / "audit.db").exists()
    from drex_agent_firewall.schemas.config import FirewallConfig
    assert FirewallConfig.load_default().database_path == str(data / "audit.db")
    assert stat.S_IMODE((config / "policy.yaml").stat().st_mode) == 0o600
    original = (config / "policy.yaml").read_text()
    (config / "policy.yaml").write_text(original + "# keep my edits\n")
    assert runner.invoke(cli, ["init"]).exit_code == 0
    assert (config / "policy.yaml").read_text() == original + "# keep my edits\n"


def test_claude_config_preserves_entries_and_undoes_only_drex(tmp_path, monkeypatch):
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    monkeypatch.setattr("drex_agent_firewall.cli.main.shutil.which", lambda _cmd: "/bin/claude")
    config = tmp_path / ".claude.json"
    config.write_text(json.dumps({"theme": "dark", "mcpServers": {"existing": {"command": "old"}}}))
    runner = CliRunner()
    dry = runner.invoke(cli, ["configure", "claude", "--upstream", "fixture-server", "--dry-run"])
    assert dry.exit_code == 0
    assert json.loads(config.read_text())["mcpServers"].keys() == {"existing"}
    installed = runner.invoke(cli, ["configure", "claude", "--upstream", "fixture-server"])
    assert installed.exit_code == 0
    payload = json.loads(config.read_text())
    assert payload["theme"] == "dark"
    assert payload["mcpServers"]["existing"] == {"command": "old"}
    assert payload["mcpServers"]["drex-alpha"]["args"] == ["mcp-proxy", "--upstream", "fixture-server"]
    assert list(tmp_path.glob(".claude.json.bak-*"))
    undone = runner.invoke(cli, ["configure", "claude", "--undo"])
    assert undone.exit_code == 0
    payload = json.loads(config.read_text())
    assert payload == {"theme": "dark", "mcpServers": {"existing": {"command": "old"}}}


def test_claude_undo_refuses_to_remove_user_edited_entry(tmp_path, monkeypatch):
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    monkeypatch.setattr("drex_agent_firewall.cli.main.shutil.which", lambda _cmd: "/bin/claude")
    runner = CliRunner()
    assert runner.invoke(cli, ["configure", "claude", "--upstream", "fixture-server"]).exit_code == 0
    config = tmp_path / ".claude.json"
    payload = json.loads(config.read_text())
    payload["mcpServers"]["drex-alpha"]["args"].append("user-edit")
    config.write_text(json.dumps(payload))
    undone = runner.invoke(cli, ["configure", "claude", "--undo"])
    assert undone.exit_code != 0
    assert "refusing to remove" in undone.output
    assert json.loads(config.read_text())["mcpServers"]["drex-alpha"]["args"][-1] == "user-edit"


def test_packaged_canary_allows_safe_blocks_destructive_and_prints_trace(tmp_path, monkeypatch):
    db = tmp_path / "canary-audit.db"
    monkeypatch.setenv("DREX_DATABASE_PATH", str(db))
    result = CliRunner().invoke(cli, ["canary"])
    assert result.exit_code == 0, result.output
    assert "SAFE CALL -> ALLOW" in result.output
    assert "SAFE_UPSTREAM_EXECUTIONS=1" in result.output
    assert "DESTRUCTIVE CALL -> BLOCK" in result.output
    assert "BLOCKED_UPSTREAM_EXECUTIONS=0" in result.output
    assert "$ drex-firewall trace" in result.output
    import sqlite3
    conn = sqlite3.connect(db)
    try:
        rows = conn.execute("SELECT operation, final_decision, executed FROM audit_actions WHERE tool='mcp'").fetchall()
    finally:
        conn.close()
    assert ("read_safe_fixture", "ALLOW", 1) in rows
    assert ("delete_test_workspace", "BLOCK", 0) in rows


def test_invalid_policy_is_reported_without_starting_upstream(tmp_path, monkeypatch):
    config = tmp_path / "config/drex-firewall"
    config.mkdir(parents=True)
    (config / "policy.yaml").write_text("default_policy: definitely-not-a-decision\n")
    marker = tmp_path / "upstream-started"
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("DREX_DATABASE_PATH", str(tmp_path / "audit.db"))
    result = CliRunner().invoke(cli, ["mcp-proxy", "--upstream", f"touch {marker}"])
    assert result.exit_code != 0
    assert "Invalid Drex policy" in result.output
    assert "Traceback" not in result.output
    assert not marker.exists()


def test_audit_database_unavailable_does_not_start_upstream(tmp_path, monkeypatch):
    occupied = tmp_path / "database-is-a-directory"
    occupied.mkdir()
    marker = tmp_path / "upstream-started"
    monkeypatch.setenv("DREX_DATABASE_PATH", str(occupied))
    result = CliRunner().invoke(cli, ["mcp-proxy", "--upstream", f"touch {marker}"])
    assert result.exit_code != 0
    assert "Audit database startup failed" in result.output
    assert "no action executed" in result.output
    assert "Traceback" not in result.output
    assert not marker.exists()


def test_init_honors_explicit_audit_database_path(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    override = tmp_path / "custom/audit.db"
    monkeypatch.setenv("DREX_DATABASE_PATH", str(override))
    result = CliRunner().invoke(cli, ["init"])
    assert result.exit_code == 0
    assert override.exists()
    assert f"AUDIT_DB={override}" in result.output
