"""MCP Compatibility Matrix test suite validating firewall interception across realistic configurations."""

from typing import Any, Dict
import pytest
import os
from drex_agent_firewall.schemas.config import FirewallConfig
from drex_agent_firewall.adapters.mcp_proxy import McpFirewallProxy
from drex_agent_firewall.adapters.mcp_servers import (
    FilesystemMcpServer,
    GenericToolMcpServer,
    GitGitHubMcpServer,
)
from drex_agent_firewall.policy.engine import DeterministicPolicyEngine


@pytest.fixture
def proxy() -> McpFirewallProxy:
    config = FirewallConfig()
    config.filesystem.allowed_roots = [os.getcwd(), "/workspace"]
    engine = DeterministicPolicyEngine(config=config)
    return McpFirewallProxy(engine)


def test_filesystem_mcp_compatibility(proxy: McpFirewallProxy):
    """Test filesystem-style MCP server with tools, resources, and policy enforcement."""
    server = FilesystemMcpServer()

    # 1. tools/list pass-through
    list_req = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
    resp = proxy.handle_jsonrpc_message(list_req, forward_handler=server.handle_request)
    assert resp["id"] == 1
    assert "tools" in resp["result"]
    assert len(resp["result"]["tools"]) == 3

    # 2. tools/call benign read
    call_req = {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "read_file", "arguments": {"path": "src/main.py"}}}
    resp = proxy.handle_jsonrpc_message(call_req, forward_handler=server.handle_request)
    assert resp["id"] == 2
    assert "result" in resp
    assert not resp.get("error")

    # 3. tools/call path traversal escape attempt (must be intercepted and blocked)
    bad_req = {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "read_file", "arguments": {"path": "../../etc/shadow"}}}
    resp = proxy.handle_jsonrpc_message(bad_req, forward_handler=server.handle_request)
    assert resp["id"] == 3
    assert "error" in resp
    assert resp["error"]["code"] == -32003
    assert resp["error"]["data"]["decision"] == "BLOCK"

    # 4. resources/read benign
    res_req = {"jsonrpc": "2.0", "id": 4, "method": "resources/read", "params": {"uri": "file:///workspace/schema.json"}}
    resp = proxy.handle_jsonrpc_message(res_req, forward_handler=server.handle_request)
    assert resp["id"] == 4
    assert "result" in resp

    # 5. resources/read blocked credential target
    bad_res = {"jsonrpc": "2.0", "id": 5, "method": "resources/read", "params": {"uri": "file:///etc/shadow"}}
    resp = proxy.handle_jsonrpc_message(bad_res, forward_handler=server.handle_request)
    assert resp["id"] == 5
    assert "error" in resp
    assert resp["error"]["code"] == -32003


def test_git_github_mcp_compatibility(proxy: McpFirewallProxy):
    """Test Git/GitHub-style MCP server with read inspection and write escalation."""
    server = GitGitHubMcpServer()

    # 1. tools/list pass-through
    list_req = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
    resp = proxy.handle_jsonrpc_message(list_req, forward_handler=server.handle_request)
    assert resp["id"] == 1
    assert len(resp["result"]["tools"]) == 4

    # 2. tools/call git_status (benign read-only -> ALLOW)
    call_req = {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "git_status", "arguments": {}}}
    resp = proxy.handle_jsonrpc_message(call_req, forward_handler=server.handle_request)
    assert resp["id"] == 2
    assert "result" in resp

    # 3. tools/call git_push with force=True (must be intercepted and blocked)
    force_req = {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "git_push", "arguments": {"branch": "main", "force": True}}}
    resp = proxy.handle_jsonrpc_message(force_req, forward_handler=server.handle_request)
    assert resp["id"] == 3
    assert "error" in resp
    assert resp["error"]["code"] == -32003

    # 4. tools/call create_pull_request (external publish -> ESCALATE, allowed=False without human approval)
    pr_req = {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "create_pull_request", "arguments": {"title": "Update deps", "body": "Release"}}}
    resp = proxy.handle_jsonrpc_message(pr_req, forward_handler=server.handle_request)
    assert resp["id"] == 4
    assert resp["error"]["data"]["decision"] in {"ESCALATE", "BLOCK"}


def test_generic_tool_mcp_compatibility(proxy: McpFirewallProxy):
    """Test generic tool MCP server with calculations and execution protection."""
    server = GenericToolMcpServer()

    # 1. tools/list pass-through
    list_req = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
    resp = proxy.handle_jsonrpc_message(list_req, forward_handler=server.handle_request)
    assert resp["id"] == 1
    assert len(resp["result"]["tools"]) == 3

    # 2. tools/call calculate (benign utility -> ALLOW)
    calc_req = {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "calculate", "arguments": {"expression": "2 + 2"}}}
    resp = proxy.handle_jsonrpc_message(calc_req, forward_handler=server.handle_request)
    assert resp["id"] == 2
    assert "result" in resp

    # 3. tools/call execute_shell with destructive command (must be blocked)
    danger_req = {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "execute_shell", "arguments": {"command": "rm -rf /"}}}
    resp = proxy.handle_jsonrpc_message(danger_req, forward_handler=server.handle_request)
    assert resp["id"] == 3
    assert "error" in resp
    assert resp["error"]["code"] == -32003

    # 4. Error propagation from upstream server (e.g. invalid tool name)
    unknown_req = {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "non_existent_tool", "arguments": {}}}
    resp = proxy.handle_jsonrpc_message(unknown_req, forward_handler=server.handle_request)
    assert resp["id"] == 4
    assert "error" in resp
