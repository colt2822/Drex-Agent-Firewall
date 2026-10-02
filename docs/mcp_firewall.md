# MCP (Model Context Protocol) Firewall Proxy

Drex Agent Firewall functions as a transparent JSON-RPC 2.0 proxy between autonomous MCP clients (such as Claude Code, Codex, OpenHands) and upstream MCP servers.

## Architecture

```text
MCP Client (Claude Code / OpenHands)
             ↓ JSON-RPC 2.0 (stdio or SSE)
Drex Firewall MCP Proxy
             ↓
       1. Intercept tools/call, tools/list, resources/read
       2. Normalize to ActionEnvelope
       3. Evaluate with Drex & Deterministic Policy
       4. If ALLOW or ALLOW_WITH_CONSTRAINTS:
             Forward to upstream MCP Server
          If BLOCK or ESCALATE:
             Return JSON-RPC Error (-32003 Policy Rejection)
             ↓
Upstream MCP Server (Unmodified)
```

## Running the Proxy

Start the MCP proxy over an arbitrary upstream command:

```bash
drex-firewall mcp-proxy --upstream "node /path/to/server.js"
```

## Rejection Protocol

When an action is blocked, the proxy returns a structured error:

```json
{
  "jsonrpc": "2.0",
  "id": "call-1",
  "error": {
    "code": -32003,
    "message": "Drex Agent Firewall blocked tool 'execute_command': Command matches forbidden pattern: rm -rf /",
    "data": {
      "decision": "BLOCK",
      "trace_id": "c596e1b7-...",
      "action_id": "f8a02c81-..."
    }
  }
}
```
