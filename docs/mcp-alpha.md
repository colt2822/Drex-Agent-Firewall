# Local MCP alpha: scope and setup

## Install from a checkout

Requires Linux or macOS, Python 3.10+, `pipx`, and one stdio MCP server. Claude Code must be installed separately.

```bash
git clone https://github.com/colt2822/Drex-Agent-Firewall.git
cd Drex-Agent-Firewall
pipx install .
```

Configure Claude Code to launch the upstream MCP server through Drex:

```bash
claude mcp add --scope user drex -- drex-firewall mcp-proxy --upstream "YOUR_UPSTREAM_MCP_COMMAND"
```

Use the actual upstream command and arguments in place of the quoted placeholder. The upstream process is spawned by Drex. For local audit persistence, `DREX_DATABASE_PATH` may be set to a user-writable SQLite path before Claude Code starts. The default is `drex_firewall.db` in the process working directory.

After an action, find the `action_id` or `trace_id` in Drex's audit database through the existing local API or SDK, then inspect it with:

```bash
drex-firewall trace ACTION_OR_TRACE_ID
```

## MCP contract

| Method | Supported | Policy evaluated | Audited | Forwarded | Blockable / fail closed |
|---|---|---|---|---|---|
| `initialize` | Yes | No | No | Yes | Upstream failure becomes JSON-RPC error |
| `notifications/initialized`, `notifications/cancelled` | Yes | No | No | Yes, no response expected | Upstream failure does not create a direct path |
| `ping` | Yes | No | No | Yes | Upstream failure becomes JSON-RPC error |
| `tools/list` | Yes | Inventory action only | Yes, metadata validated and inventory count recorded | Yes | Malformed upstream response returns error; metadata is not policy filtered |
| `tools/call` | Yes | Yes | Yes | Only if allowed | Yes; policy/audit failure prevents forwarding |
| `resources/list` | Yes | Inventory action only | Yes, metadata validated and count recorded | Yes | Malformed upstream response returns error; metadata is not policy filtered |
| `resources/read` | Yes | Yes | Yes | Only if allowed | Yes; policy/audit failure prevents forwarding |
| `prompts/list` | Yes | Inventory action only | Yes, metadata validated and count recorded | Yes | Malformed upstream response returns error; metadata is not policy filtered |
| `prompts/get` | No | No | No | No | Rejected as unsupported |
| `resources/write`, `tools/execute`, and unknown methods | No | No | No | No | Rejected as unsupported |

Provider errors use configured fallback dispositions. The default READ and WRITE dispositions are `ESCALATE`, DELETE is `BLOCK`, and EXECUTE is `ESCALATE`. Deterministic hard rules run independently of provider availability. Unknown methods are rejected rather than passed to upstream.

The proxy currently handles one upstream stdio process and synchronous request/response calls. Do not claim coverage for MCP extensions or transports that are not listed above.

## Canary evidence (2026-10-04)

Claude Code `2.1.289` was run against Drex installed into a fresh Python virtual environment from the checkout. The MCP upstream was a synthetic stdio fixture that only appends invoked tool names to a temporary log; its destructive tool never deletes files.

- `read_safe_fixture` returned `safe fixture result`; audit decision `ALLOW`; the fixture log contains exactly one invocation.
- `delete_test_workspace` on `/workspace/disposable-fixture` received a deterministic `BLOCK` (high destructive classification, confidence 0.99); audit `error_class=FIREWALL_POLICY_BLOCKED`; the fixture log contains zero invocations of this tool.
- `drex-firewall trace ACTION_ID` showed both the safe and blocked decisions with tool, target, and reason.
- MCP `initialize` client identity is retained in audit actions as `claude-code/2.1.289`.
- A read-only inspection of the temporary SQLite audit showed timestamp, tool, operation, redacted arguments, decision, reason, constraints, policy latency, provider (`REPLAY`), model (`replay-deterministic-v1`), and blocked execution status.
- Elapsed time from starting the fresh virtualenv install through the protected Claude calls was 16.369 seconds, under the 5-minute stretch target. This run used an already-installed Claude Code client and existing user authentication; it measures Drex installation plus MCP setup and actions, not installing Claude Code or creating an account.

This proves one local Claude Code MCP workflow through one local stdio fixture. It does not prove arbitrary upstream compatibility, complete MCP coverage, or general host mediation.
