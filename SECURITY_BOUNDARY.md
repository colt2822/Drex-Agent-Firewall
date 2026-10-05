# Security boundary

Drex evaluates, enforces, and audits supported actions that an agent routes through the Drex MCP stdio proxy or a guarded adapter. It does not automatically intercept arbitrary host shell commands, filesystem access, Git, `curl`, or sockets. Those actions can bypass Drex unless they are invoked through a guarded path or the agent runs inside an appropriately configured Drex controlled sandbox.

The MCP proxy currently supports `initialize`, `notifications/initialized`, `notifications/cancelled`, `ping`, `tools/list`, `tools/call`, `resources/list`, `resources/read`, and `prompts/list`. Session setup methods are forwarded. Inventory methods are forwarded, validated as JSON-RPC responses, and recorded as audit actions; metadata is recorded but not policy filtered. `tools/call` and `resources/read` are policy evaluated before forwarding and their outcomes are audited. Unknown methods, including unimplemented write methods and `prompts/get`, are rejected with `-32601`.

If upstream transport or protocol handling fails, the proxy returns a JSON-RPC error and never connects the client directly to the upstream. If SQLite cannot persist the policy decision, the adapter blocks the operation before forwarding. Audit update failures after execution are surfaced as errors; the upstream operation may already have completed in that case.

Provider errors follow the configured deterministic fallback. The default READ fallback is `ESCALATE`; WRITE defaults to `ESCALATE`, DELETE to `BLOCK`, and EXECUTE to `ESCALATE`. Explicit policy configuration can change these choices and must be reviewed accordingly.

This release does not claim complete MCP coverage, complete host mediation, protection from kernel/privileged compromise, or protection for actions taken outside routed Drex paths.
