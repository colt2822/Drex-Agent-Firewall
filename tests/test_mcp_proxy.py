"""Tests for MCP proxy interception and enforcement."""

from drex_agent_firewall.adapters.mcp_proxy import McpFirewallProxy
from drex_agent_firewall.policy.engine import DeterministicPolicyEngine
import os
from drex_agent_firewall.schemas.config import FirewallConfig


def test_mcp_proxy_allows_benign_call():
    config = FirewallConfig()
    config.filesystem.allowed_roots = [os.getcwd()]
    engine = DeterministicPolicyEngine(config=config)
    proxy = McpFirewallProxy(engine)

    msg = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "read_file",
            "arguments": {"path": "README.md"},
        },
    }

    resp = proxy.handle_jsonrpc_message(msg)
    assert resp["id"] == 1
    assert "result" in resp
    assert resp.get("error") is None


def test_mcp_proxy_blocks_dangerous_call():
    config = FirewallConfig()
    config.filesystem.allowed_roots = [os.getcwd()]
    engine = DeterministicPolicyEngine(config=config)
    proxy = McpFirewallProxy(engine)

    msg = {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {
            "name": "shell_exec",
            "arguments": {"command": "rm -rf /"},
        },
    }

    resp = proxy.handle_jsonrpc_message(msg)
    assert resp["id"] == 2
    assert "error" in resp
    assert resp["error"]["code"] == -32003
    assert resp["error"]["data"]["decision"] == "BLOCK"


def test_mcp_proxy_rejects_unknown_state_changing_method_without_forwarding():
    proxy = McpFirewallProxy(DeterministicPolicyEngine())
    calls = []
    response = proxy.handle_jsonrpc_message(
        {"jsonrpc": "2.0", "id": 9, "method": "resources/write", "params": {"uri": "file:///tmp/x"}},
        forward_handler=lambda request: calls.append(request) or {"jsonrpc": "2.0", "id": 9, "result": {}},
    )
    assert response["error"]["code"] == -32601
    assert calls == []


def test_mcp_proxy_rejects_invalid_arguments_without_forwarding():
    proxy = McpFirewallProxy(DeterministicPolicyEngine())
    calls = []
    response = proxy.handle_jsonrpc_message(
        {"jsonrpc": "2.0", "id": 90, "method": "tools/call", "params": {"name": "read_file", "arguments": ["not", "an", "object"]}},
        forward_handler=lambda request: calls.append(request),
    )
    assert response["error"]["code"] == -32602
    assert "no policy-approved action was sent upstream" in response["error"]["message"]
    assert calls == []


def test_mcp_proxy_missing_upstream_error_has_recovery_and_no_bypass():
    from drex_agent_firewall.adapters.mcp_proxy import UpstreamForwardError
    proxy = McpFirewallProxy(DeterministicPolicyEngine())
    calls = []
    def missing(_request):
        calls.append("attempted")
        raise UpstreamForwardError("FileNotFoundError", False)
    response = proxy.handle_jsonrpc_message(
        {"jsonrpc": "2.0", "id": 91, "method": "tools/call", "params": {"name": "read_file", "arguments": {"path": "/workspace/ok"}}},
        forward_handler=missing,
    )
    assert "action was not sent" in response["error"]["message"]
    assert "restart the MCP session" in response["error"]["message"]
    assert calls == ["attempted"]


def test_mcp_proxy_inventory_rejects_malformed_upstream_response():
    proxy = McpFirewallProxy(DeterministicPolicyEngine())
    response = proxy.handle_jsonrpc_message(
        {"jsonrpc": "2.0", "id": 10, "method": "tools/list", "params": {}},
        forward_handler=lambda request: {"not_jsonrpc": True},
    )
    assert response["error"]["code"] == -32603


def test_mcp_notification_is_forwarded_without_jsonrpc_response():
    proxy = McpFirewallProxy(DeterministicPolicyEngine())
    calls = []
    response = proxy.handle_jsonrpc_message(
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        forward_handler=lambda request: calls.append(request),
    )
    assert response is None
    assert len(calls) == 1


def test_mcp_destructive_verb_with_test_suffix_is_not_misclassified_as_read():
    config = FirewallConfig()
    config.filesystem.allowed_roots = [os.getcwd()]
    proxy = McpFirewallProxy(DeterministicPolicyEngine(config=config))
    calls = []
    response = proxy.handle_jsonrpc_message(
        {"jsonrpc": "2.0", "id": 11, "method": "tools/call", "params": {
            "name": "delete_test_workspace", "arguments": {"path": "/tmp/disposable-fixture"}}},
        forward_handler=lambda request: calls.append(request) or {"jsonrpc": "2.0", "id": 11, "result": {}},
    )
    assert response["error"]["data"]["decision"] == "BLOCK"
    assert calls == []


def test_mcp_provider_failure_does_not_forward_destructive_call(monkeypatch, tmp_path):
    from drex_agent_firewall import DrexFirewall
    from drex_agent_firewall.schemas.config import FirewallConfig
    config = FirewallConfig()
    config.filesystem.allowed_roots = ["/workspace"]
    firewall = DrexFirewall(config=config, database_path=str(tmp_path / "provider-failure.db"))
    def unavailable(_envelope):
        raise ConnectionError("synthetic provider outage")
    monkeypatch.setattr(firewall.engine.provider, "evaluate", unavailable)
    proxy = McpFirewallProxy(firewall.engine, firewall.repository, firewall.normalizer)
    calls = []
    response = proxy.handle_jsonrpc_message(
        {"jsonrpc": "2.0", "id": 12, "method": "tools/call", "params": {
            "name": "delete_test_workspace", "arguments": {"path": "/workspace/disposable-fixture"}}},
        forward_handler=lambda request: calls.append(request) or {"jsonrpc": "2.0", "id": 12, "result": {}},
    )
    assert response["error"]["data"]["decision"] == "BLOCK"
    assert calls == []


def test_mcp_audit_decision_failure_blocks_before_forwarding():
    class BrokenAudit:
        def record_decision(self, *_args):
            raise OSError("synthetic audit unavailable")
        def record_execution(self, **_kwargs):
            return None
    config = FirewallConfig()
    config.filesystem.allowed_roots = [os.getcwd()]
    proxy = McpFirewallProxy(DeterministicPolicyEngine(config=config), repository=BrokenAudit())
    calls = []
    response = proxy.handle_jsonrpc_message(
        {"jsonrpc": "2.0", "id": 13, "method": "tools/call", "params": {
            "name": "read_file", "arguments": {"path": "README.md"}}},
        forward_handler=lambda request: calls.append(request) or {"jsonrpc": "2.0", "id": 13, "result": {}},
    )
    assert response["error"]["data"]["decision"] == "BLOCK"
    assert calls == []


def test_mcp_upstream_exception_returns_error_without_fallback():
    proxy = McpFirewallProxy(DeterministicPolicyEngine())
    calls = []
    def dead_upstream(request):
        calls.append(request)
        raise BrokenPipeError("synthetic upstream death")
    response = proxy.handle_jsonrpc_message(
        {"jsonrpc": "2.0", "id": 14, "method": "tools/list", "params": {}},
        forward_handler=dead_upstream,
    )
    assert response["error"]["code"] == -32603
    assert len(calls) == 1


def test_mcp_audit_records_initialized_client_identity(tmp_path):
    from drex_agent_firewall import DrexFirewall
    config = FirewallConfig()
    config.filesystem.allowed_roots = [os.getcwd()]
    firewall = DrexFirewall(config=config, database_path=str(tmp_path / "client-id.db"))
    proxy = McpFirewallProxy(firewall.engine, firewall.repository, firewall.normalizer)
    proxy.handle_jsonrpc_message({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
        "clientInfo": {"name": "Claude Code", "version": "2.1.289"}}},
        forward_handler=lambda request: {"jsonrpc": "2.0", "id": 1, "result": {}})
    proxy.handle_jsonrpc_message({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {
        "name": "read_file", "arguments": {"path": "README.md"}}},
        forward_handler=lambda request: {"jsonrpc": "2.0", "id": 2, "result": {"content": []}})
    assert firewall.repository.list_actions()[0]["agent"] == "Claude Code/2.1.289"


def test_real_subprocess_timeout_kills_upstream_and_proxy_returns_deterministic_errors(tmp_path, monkeypatch):
    """Exercise the CLI proxy process and a live stdio child that hangs on tools/call."""
    import json
    import os
    import subprocess
    import sys
    import shlex
    from pathlib import Path

    log = tmp_path / "upstream.jsonl"
    db = tmp_path / "audit.db"
    fixture = "\n".join([
        "import json,sys,time",
        "for line in sys.stdin:",
        " r=json.loads(line)",
        " if r.get('method') == 'tools/call':",
        "  with open(sys.argv[1], 'a') as f: f.write(json.dumps(r)+'\\n')",
        "  time.sleep(5)",
        " print(json.dumps({'jsonrpc':'2.0','id':r.get('id'),'result':{'content':[]}}), flush=True)",
    ])
    upstream = " ".join([shlex.quote(sys.executable), "-c", shlex.quote(fixture), shlex.quote(str(log))])
    env = os.environ.copy()
    env["DREX_DATABASE_PATH"] = str(db)
    env["DREX_MCP_UPSTREAM_TIMEOUT"] = "0.2"
    env["PYTHONPATH"] = str(Path(__file__).parents[1] / "src")
    proc = subprocess.Popen(
        [sys.executable, "-c", "from drex_agent_firewall.cli.main import cli; cli()", "mcp-proxy", "--upstream", upstream],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env,
    )
    try:
        proc.stdin.write(json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}) + "\n")
        proc.stdin.flush()
        assert json.loads(proc.stdout.readline())["id"] == 1
        proc.stdin.write(json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "read_file", "arguments": {"path": "/workspace/safe.txt"}}}) + "\n")
        proc.stdin.flush()
        timed_out = json.loads(proc.stdout.readline())
        assert timed_out["error"]["code"] == -32603
        assert "timed out" in timed_out["error"]["message"]
        # A later request is answered deterministically despite the dead upstream.
        proc.stdin.write(json.dumps({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "read_file", "arguments": {"path": "/workspace/safe.txt"}}}) + "\n")
        proc.stdin.flush()
        later = json.loads(proc.stdout.readline())
        assert later["id"] == 3 and "error" in later
    finally:
        proc.stdin.close()
        proc.wait(timeout=4)
        proc.stderr.close()
    rows = [json.loads(line) for line in log.read_text().splitlines()]
    assert len(rows) == 1
    import sqlite3
    conn = sqlite3.connect(db)
    try:
        audits = conn.execute("SELECT error_class, executed FROM audit_actions ORDER BY timestamp").fetchall()
        result = conn.execute("SELECT execution_result FROM audit_actions ORDER BY timestamp LIMIT 1").fetchone()[0]
    finally:
        conn.close()
    assert audits[0][0] == "TimeoutError"
    assert audits[0][1] == 1  # invocation was sent; the side effect is unknown
    assert result == '{"status": "upstream_invoked_outcome_unknown"}'
    from click.testing import CliRunner
    from drex_agent_firewall.cli.main import cli
    monkeypatch.setenv("DREX_DATABASE_PATH", str(db))
    trace = CliRunner().invoke(cli, ["trace"])
    assert trace.exit_code == 0, trace.output
    assert "UPSTREAM RECEIVED REQUEST; FINAL OUTCOME UNKNOWN" in trace.output
