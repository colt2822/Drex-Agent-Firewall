# Drex Agent Firewall v0.1.3rc1

This release candidate consolidates the K3 host-boundary hardening and adds a bounded local MCP alpha path.

## Included

- Closes confirmed shell constraint smuggling, execution-environment injection, API exposure, audit text forging, URI path confusion, and broad default-root issues; tightens process-group cleanup, provider failure defaults, and shell egress rules.
- Pins tests to the source tree under test and records the tested Git HEAD, preventing an older editable installation from silently satisfying or failing the suite.
- Defines a fail-closed MCP subset: `tools/call` and `resources/read` are policy evaluated and audited; inventory methods are validated and recorded; unsupported methods are rejected.
- Adds a Claude Code stdio MCP canary fixture and shows CLI audit inspection through `drex-firewall trace`.
- Adds user-scoped `drex-firewall init`, Claude MCP configuration with dry-run/backup/undo, recent human-readable trace output, and XDG audit paths.
- On a real upstream response timeout, terminates the upstream process group, records that invocation occurred with an unknown outcome, and never retries. Restart the MCP session to reconnect.
- Adds an external alpha quickstart and test kit. See [docs/QUICKSTART_EXTERNAL_ALPHA.md](docs/QUICKSTART_EXTERNAL_ALPHA.md).
- Documents the local MCP boundary in [SECURITY_BOUNDARY.md](SECURITY_BOUNDARY.md) and the method contract and install flow in [docs/mcp-alpha.md](docs/mcp-alpha.md).

## Verification

- Source-pinned suite: 213 passed, zero failed, zero skipped on the release commit.
- Clean virtualenv install plus Claude Code 2.1.289 MCP canary: safe fixture call allowed; destructive fixture call blocked; zero blocked calls reached upstream.
- Measured install through first protected call: 16.369 seconds in this environment.
- Updated source-pinned suite: 223 passed, zero failed, zero skipped.
- A wheel installed into a new virtual environment and ran with Claude Code 2.1.289: harmless fixture call `ALLOW`; destructive fixture call `BLOCK`; blocked upstream invocation count 0; generated user config was undone.

## Known limits

This build does not automatically mediate arbitrary host shell, filesystem, Git, HTTP, or socket activity. It covers only actions routed through supported Drex paths. Aggregate workspace quotas, complete native path-policy mediation, global/OCI containment, and protection for unknown MCP extensions remain outside this release claim. See the security boundary for details.
