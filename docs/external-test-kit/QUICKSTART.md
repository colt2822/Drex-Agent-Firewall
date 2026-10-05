# Drex external alpha quickstart (Linux)

This alpha evaluates supported MCP operations routed through Drex. It does not intercept arbitrary host activity. Read [security boundary](../../SECURITY_BOUNDARY.md), [limitations](KNOWN_LIMITATIONS.md), and [privacy](../PRIVACY_EXTERNAL_ALPHA.md) first. Requirements: Linux, Python 3.10+, pipx, Claude Code, and an existing stdio MCP server.

## Install and initialize

Requirements: Linux, Python 3.10+, pipx, and Claude Code installed and authenticated. Install pipx using your Linux distribution's package manager (for Debian/Ubuntu, `sudo apt install pipx`), then run `pipx ensurepath` and open a new terminal if requested. Drex itself installs into pipx without root access. Claude installation/authentication is separate from Drex setup.

From the extracted tester bundle directory, install the included wheel:

```bash
pipx install ./drex_agent_firewall-0.1.3rc1-py3-none-any.whl
drex-firewall init
drex-firewall doctor
```

To see the packaged harmless canary before connecting an MCP server:

```bash
drex-firewall canary
```

It calls a harmless fixture read and attempts a named destructive test against a disposable local MCP fixture. The fixture never deletes files. Expect one ALLOW/one upstream execution and one BLOCK/zero upstream executions.

## Prove both decisions through Claude using the bundled fixture

This fixture is local, makes no external requests, and never deletes files. Configure it and restart Claude Code:

```bash
drex-firewall configure claude --upstream 'drex-firewall-canary-server --counter /tmp/drex-alpha-fixture-count' --dry-run
drex-firewall configure claude --upstream 'drex-firewall-canary-server --counter /tmp/drex-alpha-fixture-count'
claude -p "Use the drex-alpha read_safe_fixture tool exactly once and report its returned text."
claude -p "Use the drex-alpha delete_test_workspace tool exactly once with path /workspace/disposable-fixture. This is the documented synthetic test fixture; report the tool response."
cat /tmp/drex-alpha-fixture-count
drex-firewall trace --limit 4
drex-firewall configure claude --undo
```

The fixture log should contain `read_safe_fixture` and not `delete_test_workspace`. Do not use these calls with a different upstream.

## Protect a local MCP server in Claude Code

Replace the example with the exact existing stdio server command, check it, preview the change, then apply:

```bash
drex-firewall doctor --claude --upstream 'npx -y your-mcp-server'
drex-firewall configure claude --upstream 'npx -y your-mcp-server' --dry-run
drex-firewall configure claude --upstream 'npx -y your-mcp-server'
```

The helper adds a user-scoped `drex-alpha` server entry in `~/.claude.json`, preserving other entries and backing up the file. Restart Claude Code. Try a harmless read/list tool first. Only attempt a BLOCK test if your server offers a documented disposable/reversible test operation. Never use valuable data. Inventory calls are not policy filtered.

## Inspect and disconnect

```bash
drex-firewall trace
drex-firewall configure claude --undo
pipx uninstall drex-agent-firewall
```

Undo removes only the Drex entry and leaves the audit database intact. Remove audit data manually only if you explicitly want to discard history.

Use [the checklist](../EXTERNAL_ALPHA_CHECKLIST.md) and [feedback form](ALPHA_FEEDBACK.md) to record results. Read [privacy and data handling](../PRIVACY_EXTERNAL_ALPHA.md) before sharing logs or traces.

This alpha does not install Claude Code, sign in to Claude, or change your upstream server's own permissions.
