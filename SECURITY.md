# Security Policy

## Scope and Disclaimer

**Drex Agent Firewall** is an independent open-source project designed to provide policy and decision controls between autonomous AI agents and execution environments.

> **Notice**: This is an independent open-source project. It is not an official Nace or Drex SDK or certified security appliance. It does not provide formal security certification or mathematical proofs of non-interference. It should be deployed as defense-in-depth alongside containerization, sandboxing, least privilege IAM, and network isolation.

The HTTP API has no built-in authentication. Its CLI binds to loopback by default, and browser cross-origin access is disabled unless exact origins are configured through `DREX_FIREWALL_CORS_ORIGINS`. Deployments that bind to a network interface must provide independent authentication and access controls. Native agent effects are not all mediated by MCP, and MCP audit records remain writable from the agent workspace; see the documented limitations.

## Reporting a Vulnerability

If you discover a security vulnerability in Drex Agent Firewall, please report it responsibly:

1. **Do not open a public GitHub issue.**
2. Use GitHub's private vulnerability reporting feature for this repository if it is enabled. If it is unavailable, contact the maintainers privately through the contact options on their GitHub profiles.
3. Include, without sharing live credentials or personal data:
   - The type of vulnerability (e.g., path traversal bypass, secret leak, prompt injection causing policy bypass)
   - Step-by-step reproduction instructions or code
   - Environment and version details
   - Potential impact

The maintainers will assess reports and coordinate any disclosure with the reporter. No response-time commitment is currently published.

## Defense-in-Depth Model

1. **Deterministic Hard Policies First**: Drex Agent Firewall enforces hard policies (absolute path containment, forbidden command execution, forbidden IP/domain blocks) strictly before or overriding probabilistic Drex judgments.
2. **Secret Redaction**: Raw secret values and detected API keys, passwords, and private keys are redacted prior to persistence or provider communication.
3. **Bounded Execution**: Subprocess execution and output retrieval are strictly bounded by timeout and byte limit guards.
