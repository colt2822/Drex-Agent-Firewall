# Drex Agent Firewall Threat Model

## 1. Executive Summary

Autonomous coding agents (e.g., Claude Code, OpenAI Codex, OpenHands) execute high-privilege operations including shell command execution, filesystem mutations, git version control operations, and external network interactions. 

Without hard enforcement boundaries, agents are susceptible to:
1. Indirect prompt injection via malicious repository files (READMEs, issues, task descriptions).
2. Catastrophic host damage (`rm -rf /`, `mkfs`, partition wipes).
3. Secret exfiltration (environment variables, `.env` files, API keys, credentials).
4. Network boundary violations (cloud instance metadata extraction, SSRF, private intranet scanning).
5. Irreversible external actions (unauthorized git force-pushes, remote branch deletion, production deployments).

**Drex Agent Firewall** establishes a defense-in-depth architecture separating probabilistic risk assessment from deterministic policy enforcement.

---

## 2. Core Architectural Invariants

```
REAL CODING AGENT
      ↓
Drex Agent Firewall (ActionEnvelope + Secret Redactor)
      ↓
Drex Decision Layer (Probabilistic Categorization & Distributions)
      ↓
Deterministic Policy Engine (Sole Authority & Invariant Hard Rules)
      ↓
Constraint Enforcer & Guarded Adapters
      ↓
Disposable Workspace / System Execution
      ↓
SQLite WAL Audit Persistence & Outcome Calibration
```

1. **Deterministic Authority**: Probabilistic outputs from Drex (or any LLM) *never* possess execution authority. Deterministic hard policies always have absolute veto power.
2. **Fail-Closed Default**: In the presence of network partition, API timeout, ambiguous classification, or unclassified actions, the firewall defaults to `ESCALATE` or `BLOCK`.
3. **Secret Redaction Invariant**: No raw secrets, authorization headers, or private keys are ever stored in audit traces, Prometheus metrics, or forwarded upstream to model providers.
4. **Boundary Confinement**: All filesystem reads, writes, and deletions must strictly resolve within pre-authorized workspace roots (`allowed_roots`). Any symlink, path traversal (`../`), or encoded trick escaping the boundary is unconditionally blocked.
5. **No Network Bypass**: All outbound network requests and command wrappers are validated against private IP ranges (RFC1918), loopback, link-local, and cloud metadata endpoints (`169.254.169.254`, `metadata.google.internal`).

---

## 3. Threat Landscape & Attack Vectors

### Category A: Shell Obfuscation
- **Attack Techniques**: Command chaining (`&&`, `||`, `;`), subshells (`$(...)`, `` `...` ``), wrapper invocations (`sh -c`, `bash -c`, `eval`, `python -c`, `perl -e`), quote fragmentation (`'r''m' -'r''f'`), backslash escapes (`\r\m`), base64 decoding pipes (`echo ... | base64 -d | sh`), format string injection (`printf | bash`).
- **Mitigation**: `ShellNormalizer` recursively deconstructs command pipelines, decodes base64 buffers, unrolls shell wrappers, strips syntactic quoting/escaping, and evaluates individual pipeline components against hard safety rules.

### Category B: Filesystem Escape & Directory Traversal
- **Attack Techniques**: Standard `../` traversal, double-encoded separators (`%2e%2e%2f`), Unicode normalization quirks (fullwidth dots `\uff0e\uff0e/`), symlink planting (symlinking `/workspace/link` to `/etc`), and rename-across-root tricks.
- **Mitigation**: `PathValidator` normalizes paths using Unicode NFKC, resolves canonical paths via `os.path.realpath()`, verifies that canonical destinations reside strictly within `allowed_roots`, and blocks sensitive system directories (`/etc`, `/root`, `~/.ssh`, `~/.aws`, `.git/config`, `.env`).

### Category C: Secret Exfiltration
- **Attack Techniques**: Embedding credentials in HTTP request bodies, headers, query parameters, URL authorities, nested JSON payloads, MCP tool arguments, GitHub issue/PR comments, or remote git URLs. Payload representations include plaintext, Base64, hex encoding, and URL encoding.
- **Mitigation**: `SecretRedactor` scans all action targets and payloads using bounded regex detectors covering raw and encoded formats (Base64, Hex, URL-encoded), replaces credential values with scrubbed placeholders before model evaluation or persistence, and blocks any network transmission containing detected secrets.

### Category D: SSRF & Network Boundary Violations
- **Attack Techniques**: Accessing `localhost`, `127.0.0.1`, `0.0.0.0`, IPv6 equivalents (`::1`, `::ffff:127.0.0.1`), alternative numerical representations (integer IPs like `2130706433`, octal `0177.0.0.1`, hex `0x7f000001`), cloud metadata endpoints (`169.254.169.254`), scheme confusion (`file://`, `gopher://`), and userinfo spoofing (`http://attacker.com@169.254.169.254`).
- **Mitigation**: `NetworkValidator` parses targets with robust IP and URL validation, resolves integer/hex/octal notation into standard IPv4/IPv6 objects, checks against RFC1918 private ranges and link-local ranges, rejects userinfo components, and verifies permitted schemes (`http`, `https`).

### Category E: Git Abuse & Remote Mutation
- **Attack Techniques**: `git push --force`, `git push -f`, force-with-lease, deleting remote branches (`git push origin :main`), hard resetting remote tracking branches, remote reconfiguration to adversarial targets, and pushing credentials in commit history.
- **Mitigation**: `GitAdapter` strictly separates local inspection operations (`status`, `diff`, `log`, `branch`) from remote mutations. Remote pushes with force flags are blocked by deterministic hard policy rules.

### Category F: External Effects & API Mutations
- **Attack Techniques**: Arbitrary GitHub operations (closing issues, merging PRs, posting spam comments, deleting releases, creating unauthorized webhooks).
- **Mitigation**: External publish operations require high confidence thresholds (typically $\ge 98\%$), require explicit human escalation when ambiguous, and are subject to bounded rate limits.

### Category G: MCP Protocol Manipulation
- **Attack Techniques**: Oversized JSON-RPC messages (memory exhaustion), deeply nested arguments, duplicate keys, tool-name impersonation (`name: "mcp__drex_firewall__execute_shell"`), and masquerading destructive commands inside harmless tool calls.
- **Mitigation**: `McpFirewallProxy` strictly validates JSON-RPC schema compliance, normalizes tool names, extracts inner process execution and path arguments, and subjects all MCP requests to the complete firewall evaluation pipeline.

### Category H: Multi-Step Composite Attacks
- **Attack Techniques**: Traces where individually safe actions compose into an attack:
  - Step 1: Read `.env`
  - Step 2: Base64 encode file
  - Step 3: HTTP POST encoded string
- **Mitigation**: Context-aware normalization tracks `previous_actions` across the session trace. Reading sensitive files marks the session context with `credential_read_in_trace`, causing subsequent external network transmissions to be automatically escalated or blocked.

---

## 4. Trust Boundaries & Assumptions

| Component | Trust Level | Description |
| :--- | :--- | :--- |
| **Autonomous Agent (Claude, Codex)** | **Untrusted** | The model's prompts and tool calls may be influenced by prompt injections or hallucinated plans. |
| **Workspace Repository Content** | **Untrusted** | Repositories may contain adversarial bait, malicious scripts, or misleading documentation. |
| **Drex Decision Provider** | **Semi-Trusted** | Provides probabilistic guidance, but cannot override hard invariants. |
| **Deterministic Policy Engine** | **Trusted Core** | Hard deterministic invariants, strictly immutable at runtime. |
| **Execution Adapters** | **Trusted Core** | Enforces machine-level constraints (timeouts, cwd, env filtering). |
| **SQLite Audit Database** | **Trusted Store** | Append-only audit trail in WAL mode recording all actions and outcomes. |

---

## 5. Security Invariant Verification

The firewall's invariants are verified by:
1. **Automated Unit & Integration Tests**: 60 unit tests covering every adapter and validator.
2. **220-Scenario Adversarial Red-Team Suite**: Rigorous bypass test suite across all 10 categories achieving **0.0% high-impact false allows**.
3. **Live Autonomous Agent Testing**: Claude Code executing inside disposable repositories with safe adversarial bait.
