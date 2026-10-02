# Security & Defense-in-Depth Model

## Security Principles

1. **Deterministic Hard Invariants Precede Models**: Probabilistic model judgments are never trusted to override absolute security invariants. If an action breaches a hard boundary (such as path traversal, forbidden shell patterns, or credential exfiltration), it is immediately blocked without consulting Drex.
2. **Secret Redaction by Default**: All arguments, payloads, and command strings pass through `SecretRedactor` prior to persistence, telemetry logging, or Drex API transmission.
3. **No Unbounded Retentions**: Process execution and network responses are strictly bounded by byte limits and execution timeouts.
4. **Machine-Enforceable Constraints**: `ALLOW_WITH_CONSTRAINTS` produces concrete parameters (canonical paths, command prefixes, read-only flags) that are actively enforced by adapters at execution time.
5. **Fail-Closed Strategy**: On provider errors, timeouts, or unexpected failure dispositions, non-read actions default to `BLOCK` or `ESCALATE`.
