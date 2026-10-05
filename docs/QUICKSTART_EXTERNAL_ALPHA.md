# Drex external alpha quickstart (Linux)

This alpha evaluates supported MCP operations routed through Drex. It does not intercept arbitrary host activity. Before installation, read [SECURITY_BOUNDARY.md](../SECURITY_BOUNDARY.md), [known limitations](external-test-kit/KNOWN_LIMITATIONS.md), and [privacy/data handling](PRIVACY_EXTERNAL_ALPHA.md). The external tester target is Linux, Python 3.10+, pipx, Claude Code, and an existing stdio MCP server command.

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

It calls a harmless fixture read and attempts a named destructive test against a disposable local MCP fixture. The fixture never deletes files. Expected output is one ALLOW with one upstream execution and one BLOCK with zero upstream executions.

## Prove the decisions through Claude with the bundled fixture

This optional local MCP fixture makes no external requests and never deletes files. It records each tool invocation in the named temporary log. Configure it, then restart Claude Code:

```bash
drex-firewall configure claude --upstream 'drex-firewall-canary-server --counter /tmp/drex-alpha-fixture-count' --dry-run
drex-firewall configure claude --upstream 'drex-firewall-canary-server --counter /tmp/drex-alpha-fixture-count'
```

Use Claude Code to invoke exactly one safe tool call and one synthetic blocked call:

```bash
claude -p "Use the drex-alpha read_safe_fixture tool exactly once and report its returned text."
claude -p "Use the drex-alpha delete_test_workspace tool exactly once with path /workspace/disposable-fixture. This is the documented synthetic test fixture; report the tool response."
```

Then inspect evidence and undo the fixture integration:

```bash
cat /tmp/drex-alpha-fixture-count
drex-firewall trace --limit 4
drex-firewall configure claude --undo
```

The log should contain `read_safe_fixture` and not `delete_test_workspace`. Use only these exact synthetic calls for the bundled fixture.

## Protect a local MCP server in Claude Code

Replace the example with the exact stdio MCP server command you already use. Check it, preview the change, then apply it:

```bash
drex-firewall doctor --claude --upstream 'npx -y your-mcp-server'
drex-firewall configure claude --upstream 'npx -y your-mcp-server' --dry-run
drex-firewall configure claude --upstream 'npx -y your-mcp-server'
```

The helper adds a user-scoped `drex-alpha` server entry in `~/.claude.json`, preserving other entries and backing up the file. Restart Claude Code. Invoke a harmless read/list tool first. Only attempt a BLOCK test if your server has a documented disposable or reversible test operation; never test on valuable data. Inventory calls are not policy filtered. Supported calls through this entry are evaluated and audited by Drex.

## Inspect and disconnect

```bash
drex-firewall trace
drex-firewall configure claude --undo
pipx uninstall drex-agent-firewall
```

Undo removes only the Drex entry and leaves the audit database intact. Remove audit data manually only if you explicitly want to discard history.

After the fixture check, optionally configure your existing MCP command using the steps above and test only harmless operations. Use `docs/EXTERNAL_ALPHA_CHECKLIST.md` and `docs/external-test-kit/ALPHA_FEEDBACK.md` to record results. Review `docs/PRIVACY_EXTERNAL_ALPHA.md` before sharing any trace or logs. Claude authentication is separate and is not part of Drex setup time.

This alpha does not install Claude Code, sign in to Claude, or change your upstream server's own permissions.
