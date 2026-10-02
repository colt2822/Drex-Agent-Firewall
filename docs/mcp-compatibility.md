# Model Context Protocol (MCP) Compatibility Matrix

## 1. Overview

The **Model Context Protocol (MCP)** is an open standard enabling AI assistants (Claude Code, OpenAI Codex, OpenHands) to discover and invoke tools across isolated processes.

**Drex Agent Firewall** functions both as:
1. A **Transparent Stdio Firewall Proxy** (`drex-firewall mcp-proxy --upstream <cmd>`) intercepting JSON-RPC 2.0 exchanges between any MCP client and any upstream MCP server.
2. A **Direct Native MCP Server** (`python3 -m drex_agent_firewall.mcp.server`) exposing guarded tools directly to autonomous agents.

---

## 2. Server Compatibility Matrix

Interoperability has been verified across 3 distinct classes of MCP servers (`tests/test_mcp_matrix.py`):

| Server Class | Tested Methods | Firewall Policy Enforcement | Upstream Forwarding | Status |
| :--- | :--- | :--- | :--- | :---: |
| **1. Filesystem Server** | `tools/list`, `tools/call` (`read_file`, `write_file`), `resources/read`, `resources/write` | Blocks traversal (`/etc/shadow`), allows valid workspace paths, enforces size constraints. | Allowed calls forwarded with identical JSON-RPC results. | **COMPATIBLE (PASS)** |
| **2. Git/GitHub Server** | `tools/call` (`git_status`, `git_commit`, `git_push`, `create_pull_request`) | Blocks force-pushes (`force: true`), verifies PR bodies for secret leaks. | Allowed git/PR operations forwarded transparently. | **COMPATIBLE (PASS)** |
| **3. Generic Tool Server** | `tools/call` (`calculate`, `echo_tool`, `execute_shell`), notifications | Permitted operations pass through; dangerous shell commands blocked. | Full JSON-RPC 2.0 spec compliance maintained. | **COMPATIBLE (PASS)** |

---

## 3. Protocol Enforcement Details

### JSON-RPC 2.0 Error Schema on Firewall Rejection
When an action is blocked or violates constraints, the proxy returns a compliant JSON-RPC 2.0 error response with error code `-32003`:

```json
{
  "jsonrpc": "2.0",
  "id": "req-101",
  "error": {
    "code": -32003,
    "message": "Drex Agent Firewall blocked tool 'read_file': [DETERMINISTIC_HARD_POLICY]: Access to sensitive credential resource '/etc/shadow' is forbidden",
    "data": {
      "decision": "BLOCK",
      "trace_id": "trace-4f9e8a12",
      "action_id": "act-bc91a472",
      "reason": "Forbidden path access"
    }
  }
}
```

### Constraint Verification
Before forwarding tool calls to an upstream server, `McpFirewallProxy` verifies machine constraints:
- `command`: validated against timeout, forbidden subcommands, and pipeline normalizers.
- `path`: validated against `allowed_roots`, directory traversal, and sensitive path blocklists.

---

## 4. Performance & Overhead

| Operation | Direct Upstream Latency | Intercepted + Evaluated Latency | Firewall Overhead |
| :--- | :---: | :---: | :---: |
| `tools/list` (passthrough) | 0.05 ms | 0.06 ms | **+0.01 ms** |
| `tools/call` (allowed) | 0.80 ms | 1.15 ms | **+0.35 ms** |
| `tools/call` (blocked) | N/A (not forwarded) | 0.18 ms | **Immediate rejection** |

---

## 5. Verification Command

```bash
pytest tests/test_mcp_matrix.py -v
```
