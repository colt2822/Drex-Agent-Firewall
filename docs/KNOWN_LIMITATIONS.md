# Known limitations

- Linux and Claude Code are the only external quickstart target in this alpha.
- Drex covers documented MCP stdio methods routed through the proxy. Inventory listings are audited but are not policy filtered.
- A timed-out upstream is terminated. Restart the Claude MCP session to reconnect; Drex does not retry an ambiguous tool call.
- Edit the generated `policy.yaml` only using the documented configuration fields; malformed policy stops proxy startup before the upstream is started.
- Native Claude shell, filesystem, Git, HTTP, socket, and process activity can bypass Drex unless a supported containment mechanism is explicitly used.
- No SaaS, billing, multi-tenancy, SSO, fleet control, remote kill, whole-host mediation, Gemini, Kimi, Windows, or macOS support is included.
- Provider and audit failures can prevent tool execution. An audit update failure after a completed upstream call cannot undo that call.
