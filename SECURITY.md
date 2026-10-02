# Security Policy

## Scope and Disclaimer

**Drex Agent Firewall** is an independent open-source project designed to provide policy and decision controls between autonomous AI agents and execution environments.

> **Notice**: This is an independent open-source project. It is not an official Nace or Drex SDK or certified security appliance. It does not provide formal security certification or mathematical proofs of non-interference. It should be deployed as defense-in-depth alongside containerization, sandboxing, least privilege IAM, and network isolation.

## Reporting a Vulnerability

If you discover a security vulnerability in Drex Agent Firewall, please report it responsibly:

1. **Do not open a public GitHub issue.**
2. Send an email to the security maintainers at `security@drex-agent-firewall.local` (or submit a private security advisory on GitHub).
3. Include details regarding:
   - The type of vulnerability (e.g., path traversal bypass, secret leak, prompt injection causing policy bypass)
   - Step-by-step reproduction instructions or code
   - Environment and version details
   - Potential impact

We will acknowledge receipt within 48 hours and work with you on a coordinated disclosure schedule.

## Defense-in-Depth Model

1. **Deterministic Hard Policies First**: Drex Agent Firewall enforces hard policies (absolute path containment, forbidden command execution, forbidden IP/domain blocks) strictly before or overriding probabilistic Drex judgments.
2. **Secret Redaction**: Raw secret values and detected API keys, passwords, and private keys are redacted prior to persistence or provider communication.
3. **Bounded Execution**: Subprocess execution and output retrieval are strictly bounded by timeout and byte limit guards.
