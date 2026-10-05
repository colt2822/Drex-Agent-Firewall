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
