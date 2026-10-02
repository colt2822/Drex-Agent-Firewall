# Drex Agent Firewall v0.1.0 Release Notes

## What It Is

Drex Agent Firewall is an open-source, vendor-neutral policy and decision firewall for autonomous AI agents (Claude Code, OpenAI Codex, OpenHands, generic MCP clients). It sits between agents and tools that cause side effects (shell, filesystem, git, GitHub, HTTP, MCP) and enforces deterministic policy decisions on every proposed action.

## Why It Exists

Autonomous coding agents operating in real environments can inadvertently or adversarially:
- Execute destructive shell commands (`rm -rf /`, `mkfs`, fork bombs)
- Escape workspace boundaries via path traversal or symlinks
- Exfiltrate credentials (`.env`, SSH keys, API keys) to external endpoints
- Force-push to protected branches or delete remote references
- Access cloud metadata services (SSRF) or container runtime sockets

Drex Agent Firewall stops these failures **deterministically before side effects occur**, using a layered architecture of hard invariants, probabilistic classification, and machine-enforceable constraints.

## Architecture

1. **Action Envelope Normalization**: Every tool call is converted to a strongly-typed `ActionEnvelope` with secret redaction
2. **Deterministic Hard Invariants**: Absolute rules (path confinement, forbidden commands, SSRF blocks) override all model outputs
3. **Drex Decision Engine**: Structured probabilistic classification across 8 dimensions with full probability distributions
4. **Policy Interpretation**: Configurable confidence thresholds and fail dispositions per action class
5. **Constraint Synthesis**: `ALLOW_WITH_CONSTRAINTS` returns concrete, machine-enforceable constraints

## Isolated Runtime

The optional **Drex Isolated Agent Runtime** (`drex-firewall sandbox`) provides an outer OS boundary using Bubblewrap (bwrap) unprivileged rootless container namespaces:

- **Namespace Isolation**: user, PID, IPC, UTS, and network namespaces are unshared
- **Writable `/workspace` only**: All other host paths are read-only or absent
- **Ambient environment cleared**: `--clearenv` wipes host environment; only safe defaults are injected
- **All capabilities dropped**: `--cap-drop ALL` removes all 38 Linux capabilities
- **Die-with-parent**: Sandbox processes terminate when the parent exits
- **Host home absent**: The host `$HOME` is never mounted; agent uses ephemeral `/home/agent`
- **Container sockets blocked**: Docker, Podman, containerd sockets are inaccessible

### Runtime Credential Model

When running Claude Code inside the sandbox, the agent's CLI authentication token is **narrowly injected** from the host's `~/.claude/` directory into the ephemeral sandbox home. This credential:
- Exists only because Claude Code requires it to function
- Is scoped to the Claude API (not arbitrary host secrets)
- Lives only for the duration of the sandbox session
- Is destroyed when the session tmpdir is cleaned up
- Is NOT persisted to SQLite, logs, or the UI
- Is only injected when `agent_type="claude"` is explicitly specified

**Ambient host secrets** (AWS, GitHub, OpenAI, SSH, Slack tokens) are **never inherited**.

## Benchmark Results

Benchmarks are run in deterministic replay mode (offline, no API calls). Results reflect the current threat model and test suite coverage.

| Suite | Scenarios | Accuracy | High-Impact False Allows |
|-------|-----------|----------|--------------------------|
| Standard | 105 | 100.0% | 0 |
| Adversarial Red-Team | 220 | 99.55% | 0 |
| Hostile Bypass | 186 | 98.39% | 0 |
| Isolation | 100 | 98.0% | 0 |

> **Note**: These results demonstrate that the firewall **prevented the tested bypasses in the current threat model and benchmark suites**. They do not constitute formal security certification, mathematical proofs of non-interference, or guarantees against novel attack vectors.

## Security Model

### What Bubblewrap Provides
- Linux namespace isolation (user, PID, IPC, UTS, network)
- Bind mount confinement with read-only system mounts
- Capability dropping and new-session isolation
- Environment cleansing

### What Bubblewrap Does NOT Provide
- **Kernel isolation**: Bubblewrap shares the host Linux kernel. It is not a microVM (Firecracker, gVisor) or hypervisor boundary.
- **Formal verification**: There are no mathematical proofs of non-interference or information flow control.
- **Kernel-level resource limits**: Bubblewrap alone does not enforce cgroup-based memory, CPU, or PID limits. Resource exhaustion is mitigated by timeout enforcement and output truncation, but a determined attacker can consume host resources.
- **Seccomp filtering**: No seccomp profile is applied; the full syscall surface is available within the namespace.
- **Fine-grained network egress**: The `allowlisted` network mode is not yet implemented with veth/iptables. Currently, it falls back to full network isolation.

### NoIsolationBackend

`NoIsolationBackend` is an **explicit unsafe/development compatibility mode** that executes directly on the host with no kernel-level isolation. It:
- Must be explicitly selected (`--backend none`)
- Is never automatically selected when sandbox mode is requested
- Prints a visible warning on use
- Is suitable only for benchmarking and development comparison

## Quickstart

```bash
# Install
git clone https://github.com/example/drex-agent-firewall.git
cd drex-agent-firewall
pip install -e .

# Verify
drex-firewall health
drex-firewall benchmark
drex-firewall sandbox test-escape

# Run agent in sandbox
drex-firewall sandbox demo --agent claude
```

## Known Limitations

1. **Shared kernel**: Bubblewrap namespaces share the host kernel. A kernel-level exploit could escape the sandbox.
2. **No cgroup limits**: Memory, CPU, and PID limits are not enforced by Bubblewrap. Use external cgroup configuration for production deployments.
3. **`~/.local` exposure**: The host's `~/.local` directory is mounted read-only as `/opt/agent_tools` to provide agent binaries. This may expose cached application data.
4. **DNS-based SSRF**: The network validator checks IP literals and known hostnames but does not resolve DNS. Wildcard DNS services (e.g., nip.io) that resolve to metadata IPs are not detected.
5. **Encoded secret detection**: Transformed secrets (base64, hex, chunked) have inherent false-negative limitations in string-based detection.
6. **Network allowlisting**: Fine-grained egress filtering via veth/iptables is planned but not yet implemented.
7. **MCP bypass within sandbox**: Inside the sandbox, the agent can execute raw commands directly rather than routing through the MCP firewall. The outer OS sandbox prevents host escape, but the MCP firewall is a defense-in-depth layer, not an enforcement boundary against an agent with shell access.

## License

MIT License. See [LICENSE](LICENSE) for details.
