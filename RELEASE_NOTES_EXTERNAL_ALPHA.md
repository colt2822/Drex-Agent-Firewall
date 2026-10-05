# Drex Agent Firewall 0.1.3rc1 — external alpha

## What this alpha does

Drex is a local security gateway for supported MCP operations. It evaluates supported tool/resource requests before execution, applies deterministic policy, and creates an inspectable audit trail.

## What it does not do

It does not provide whole-machine protection or transparently intercept arbitrary processes. Native host bypass remains possible. This is an external alpha, not production-grade software.

## Supported client and MCP boundary

The external tester path supports Linux, Python 3.10+, and Claude Code with a configured stdio MCP server routed through Drex. Supported methods: `initialize`, `notifications/initialized`, `notifications/cancelled`, `ping`, `tools/list`, `tools/call`, `resources/list`, `resources/read`, and `prompts/list`. Policy is evaluated for `tools/call` and `resources/read`; inventory methods are not policy-filtered. `prompts/get`, unsupported write/execute extensions, and unknown methods are rejected.

## Install and test

Install the included wheel with `pipx install ./drex_agent_firewall-0.1.3rc1-py3-none-any.whl`, then run `drex-firewall init`, `drex-firewall doctor`, and `drex-firewall canary`. Follow `docs/QUICKSTART_EXTERNAL_ALPHA.md` and read `SECURITY_BOUNDARY.md`, `docs/external-test-kit/KNOWN_LIMITATIONS.md`, and `docs/PRIVACY_EXTERNAL_ALPHA.md` before routing real work.

## Known limitations

Native host bypass exists; only listed MCP operations are supported; inventory methods are not policy-filtered; timeouts after upstream receives a request leave final outcome unknown and may require an MCP session restart. Linux and Claude Code are the alpha tester targets. There are no cloud/fleet features or billing. No production readiness is claimed.

## Report bugs

Use `docs/external-test-kit/BUG_REPORT_TEMPLATE.md` and share it through the alpha distributor who supplied this bundle. Review and sanitize all details before sharing. For security vulnerabilities, do not open a public issue; use the repository's private vulnerability reporting feature if enabled, or contact maintainers privately as described in `SECURITY.md`.
