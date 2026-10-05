# 60-second local alpha demo

This is a screen-recording script, not a claim of recorded evidence. Use an already authenticated Claude Code session and the bundled local MCP fixture. Do not show secrets, private prompts, or private source. The fixture is deterministic and requires no external service.

## Prepare once before recording

Install the wheel and initialize Drex. Configure Claude to use the bundled fixture, then restart Claude Code:

```bash
drex-firewall init
drex-firewall configure claude --upstream 'drex-firewall-canary-server --counter /tmp/drex-alpha-demo-count' --dry-run
drex-firewall configure claude --upstream 'drex-firewall-canary-server --counter /tmp/drex-alpha-demo-count'
claude --version
```

Confirm Claude shows the `drex-alpha` tools. Authenticate before recording. During recording:

**0–10 sec — show Claude and the boundary**

Show the Claude session with `drex-alpha` connected. Briefly show the scope statement:

```bash
drex-firewall doctor --claude --upstream 'drex-firewall-canary-server --counter /tmp/drex-alpha-demo-count'
```

Say: “Drex evaluates supported MCP requests routed through its proxy. It does not mediate arbitrary host activity.”

**10–20 sec — safe MCP action**

```bash
claude -p "Use the drex-alpha read_safe_fixture tool exactly once and report its returned text."
```

Point to the successful result, then run `drex-firewall trace --limit 4` and show the ALLOW.

**20–35 sec — destructive test attempt**

```bash
claude -p "Use the drex-alpha delete_test_workspace tool exactly once with path /workspace/disposable-fixture. This is the documented synthetic test fixture; report the tool response."
```

The fixture does not delete files. Point to the BLOCK response.

**35–45 sec — show no blocked upstream execution**

```bash
wc -l /tmp/drex-alpha-demo-count
cat /tmp/drex-alpha-demo-count
```

Point out the fixture log contains `read_safe_fixture` and not `delete_test_workspace`.

**45–60 sec — inspect decisions**

```bash
drex-firewall trace --limit 4
```

Show the tool, redacted arguments, decision reason, and execution status. Explain that a timeout after dispatch is recorded as `UPSTREAM RECEIVED REQUEST; FINAL OUTCOME UNKNOWN`; it is not the same as a block before upstream.

Finish with `drex-firewall configure claude --undo`. Never demonstrate against valuable or real data.
