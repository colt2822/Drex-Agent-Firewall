# Drex external alpha quickstart (Linux)

This alpha protects MCP calls configured to run through Drex. It does not intercept arbitrary host activity; read [SECURITY_BOUNDARY.md](../SECURITY_BOUNDARY.md) first.

## Install and initialize

With Python 3.10+ and pipx installed, install the wheel from the Drex alpha release bundle:

```bash
pipx install ./drex_agent_firewall-0.1.3rc1-py3-none-any.whl
drex-firewall init
```

To see the packaged harmless canary before connecting an MCP server:

```bash
drex-firewall canary
```

It calls `read_safe_fixture` and a destructive test operation using disposable data, then prints the audit trace.

## Protect a local MCP server in Claude Code

Preview the change, then apply it. Replace the example command with the MCP server command you already use:

```bash
drex-firewall configure claude --upstream 'npx -y your-mcp-server' --dry-run
drex-firewall configure claude --upstream 'npx -y your-mcp-server'
```

The helper adds a user-scoped `drex-alpha` server entry in `~/.claude.json`, preserving other entries and backing up the file. Restart Claude Code and invoke one of the configured server's tools. Calls made through this entry are evaluated and audited by Drex.

## Inspect and disconnect

```bash
drex-firewall trace
drex-firewall configure claude --undo
pipx uninstall drex-agent-firewall
```

Undo removes only the Drex entry and leaves the audit database intact. Remove audit data manually only if you explicitly want to discard history.

This alpha does not install Claude Code, sign in to Claude, or change your upstream server's own permissions.
