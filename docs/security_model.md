# Security & Defense-in-Depth Model

## Security Principles

1. **Deterministic Hard Invariants Precede Models**: Probabilistic model judgments are never trusted to override absolute security invariants. If an action breaches a hard boundary (such as path traversal, forbidden shell patterns, or credential exfiltration), it is immediately blocked without consulting Drex.
2. **Secret Redaction by Default**: All arguments, payloads, and command strings pass through `SecretRedactor` prior to persistence, telemetry logging, or Drex API transmission.
3. **No Unbounded Retentions**: Process execution and network responses are strictly bounded by byte limits and execution timeouts.
4. **Machine-Enforceable Constraints**: `ALLOW_WITH_CONSTRAINTS` produces concrete parameters (canonical paths, command prefixes, read-only flags) that are actively enforced by adapters at execution time.
5. **Fail-Closed Strategy**: On provider errors, timeouts, or unexpected failure dispositions, non-read actions default to `BLOCK` or `ESCALATE`.
6. **Constrained Commands Are Direct Executables**: When a command allowlist or prefix is active, shell syntax is rejected and the parsed executable is launched directly. Unconstrained shell commands retain shell semantics.
7. **Shell Egress Uses a Broker**: Direct shell network access is blocked because shell clients cannot be reliably pinned to policy-checked DNS answers. Use the guarded HTTP adapter or a sandbox configured with controlled egress.
8. **API Exposure**: Every route except `/healthz` requires bearer authentication. Set `DREX_API_TOKEN` for a stable operator token; otherwise the application generates an ephemeral token, which the CLI prints at startup. Binding `drex-firewall serve` beyond loopback requires an operator token.

The default filesystem roots contain only `/workspace`; policy packs do not implicitly grant the firewall process working directory. Configure explicit roots for other workspaces. Provider failure defaults READ to `ESCALATE`; a deployment that deliberately configures READ as `ALLOW` is opting into fail-open behavior.
