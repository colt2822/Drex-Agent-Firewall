# External alpha tester checklist

For Linux with Python 3.10+ and Claude Code already installed. Allow about 10–20 minutes. Read `SECURITY_BOUNDARY.md` and `docs/external-test-kit/KNOWN_LIMITATIONS.md` first.

From the extracted tester bundle directory:

```bash
pipx install ./drex_agent_firewall-0.1.3rc1-py3-none-any.whl
drex-firewall init
drex-firewall doctor --claude
drex-firewall canary
```

Configure the bundled deterministic fixture. Preview the change, then apply it:

```bash
drex-firewall configure claude --upstream 'drex-firewall-canary-server --counter /tmp/drex-alpha-fixture-count' --dry-run
drex-firewall configure claude --upstream 'drex-firewall-canary-server --counter /tmp/drex-alpha-fixture-count'
```

Restart Claude Code and use the two exact fixture prompts in `docs/QUICKSTART_EXTERNAL_ALPHA.md` to observe a fixture ALLOW and BLOCK through Claude. Check the fixture count and trace, then undo the fixture integration. To assess compatibility, you may then configure your own existing MCP command and make harmless calls. Never test destructive operations on valuable data. If your server has no safe disposable block test, do not improvise.

```bash
drex-firewall trace
drex-firewall configure claude --undo
```

Record answers (no secrets or private content):

```text
INSTALL_PASS=
INIT_PASS=
CANARY_PASS=
CLAUDE_CONFIG_PASS=
SAFE_CALL_PASS=
BLOCK_CALL_PASS=
TRACE_UNDERSTOOD=
UNDO_PASS=
NORMAL_USAGE_BROKEN=
WOULD_KEEP_INSTALLED=
```

The packaged fixture has no real destructive behavior; its destructive-named tool only records invocation. For your own server, only test a block if it offers a safe disposable operation. Otherwise leave that compatibility-specific check untested; do not improvise with real data.
