# Known limitations

## Read before testing

- **Native host bypass exists.** Drex does not mediate arbitrary host commands, files, processes, sockets, or network activity.
- Only the supported MCP methods listed in `SECURITY_BOUNDARY.md` are handled. Only `tools/call` and `resources/read` receive policy evaluation.
- `tools/list`, `resources/list`, and `prompts/list` are inventory operations: validated/audited but not policy filtered.
- `prompts/get`, unsupported write/execute extensions, and unknown methods are rejected.
- If a timeout happens after upstream receives a request, the final side-effect outcome is unknown. Drex does not retry or fall back directly; check upstream state and restart the MCP session.
- Linux, Python 3.10+, and Claude Code are the supported external alpha target.
- This is not production-grade. There is no billing, cloud policy sync, SaaS, or fleet management.

## Additional limitations

- Edit generated `policy.yaml` only using documented configuration fields; malformed policy stops proxy startup before upstream is started.
- Other Claude shell, filesystem, Git, HTTP, socket, and process activity can bypass Drex unless separately routed through a supported guarded path.
- Windows and macOS are not supported by this alpha path.
- Provider and audit failures can prevent tool execution. An audit update failure after a completed upstream call cannot undo that call.
