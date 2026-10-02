"""Example demonstrating MCP firewall interception of tools/call requests."""

import json
from drex_agent_firewall import DrexFirewall
from drex_agent_firewall.adapters.mcp_proxy import McpFirewallProxy

fw = DrexFirewall()
proxy = McpFirewallProxy(fw.engine, fw.repository, fw.normalizer)

# 1. Benign tool call passing through proxy
benign_rpc = {
    "jsonrpc": "2.0",
    "id": "req-1",
    "method": "tools/call",
    "params": {
        "name": "read_file",
        "arguments": {"path": "README.md"}
    }
}

resp1 = proxy.handle_jsonrpc_message(benign_rpc)
print("Benign Tool Call Response:")
print(json.dumps(resp1, indent=2))

# 2. Blocked tool call intercepted by firewall
malicious_rpc = {
    "jsonrpc": "2.0",
    "id": "req-2",
    "method": "tools/call",
    "params": {
        "name": "execute_command",
        "arguments": {"command": "rm -rf /"}
    }
}

resp2 = proxy.handle_jsonrpc_message(malicious_rpc)
print("\nBlocked Tool Call Response (Intercepted by Firewall):")
print(json.dumps(resp2, indent=2))
