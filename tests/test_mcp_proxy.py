"""Tests for MCP proxy interception and enforcement."""

from drex_agent_firewall.adapters.mcp_proxy import McpFirewallProxy
from drex_agent_firewall.policy.engine import DeterministicPolicyEngine


def test_mcp_proxy_allows_benign_call():
    engine = DeterministicPolicyEngine()
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
    engine = DeterministicPolicyEngine()
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
