# Drex Agent Firewall v0.1.0

## Overview

Drex Agent Firewall is an open-source policy and decision firewall for autonomous agents. It normalizes proposed tool actions, obtains structured Drex decisions when configured, applies deterministic policy rules, and enforces resulting decisions and constraints through guarded adapters. A decision is not itself executed.

This release is an independent project, not an official Drex SDK or a certified security product. Its results describe the listed tests and benchmark datasets; they are not a guarantee against untested attacks.

## Included

- Structured Drex decisions with probability distributions across action risk, class, scope, reversibility, external effect, credential risk, destructive risk, and approval need.
- Deterministic policy enforcement, hard invariants, fail dispositions, and machine-enforced constraints.
- Shell, filesystem, Git, GitHub, HTTP, and MCP proxy adapters. The MCP proxy handles JSON-RPC tool and resource operations.
- SQLite write-ahead-log audit traces, a FastAPI service, Prometheus metrics, and a web UI.
- Six reusable policy packs and replay-based calibration and benchmark tools.
- An optional Bubblewrap agent runtime with a writable workspace, isolated ephemeral home, cleared ambient environment, and dropped capabilities.
- Controlled-online mode for authenticated Claude and Codex calls through a loopback proxy and host broker.

## Runtime and Egress Scope

Bubblewrap keeps its network namespace unshared. In controlled-online mode, the broker accepts CONNECT requests only for the configured provider hostnames on TCP/443 and validates resolved destinations as globally routable. It does not inspect TLS SNI, encrypted HTTPS paths, or request bodies. This is hostname and destination control, not an HTTPS content filter.

The host home directory and user-local directories are not mounted. For an explicitly selected authenticated agent call, the runtime stages that agent's existing authentication data into its ephemeral sandbox home and removes the staged copy during cleanup. Host environment credentials are not inherited.

## Agent Validation Evidence

- **Claude Code:** A Claude Code v2.1.287 sandbox coding task and confinement audit are documented in [docs/agent-runtime.md](docs/agent-runtime.md). The report describes that run only.
- **Codex:** Sandbox tests exercise Codex CLI launch, controlled-online authentication staging and cleanup, and provider-host policy. These tests do not claim a successful live Codex coding task or prove behavior for every Codex version or account configuration.

## Benchmark Baselines

Recorded v0.1.0 deterministic replay results:

| Suite | Scenarios | Accuracy | False allows |
| --- | ---: | ---: | ---: |
| Standard | 105 | 100.0% | 0 high-impact |
| Adversarial red-team | 220 | 99.55% | 0 high-impact |
| Hostile bypass | 186 | 98.39% | 0 |
| Isolation | 100 | 98.0% | 0 |

Benchmark commands are `drex-firewall benchmark`, `drex-firewall benchmark --redteam`, `drex-firewall benchmark --bypass`, and `drex-firewall benchmark --isolation`. These finite datasets measure their encoded cases and should not be read as security certification or a prediction of performance against novel attacks.

## Quickstart

```bash
git clone https://github.com/colt2822/Drex-Agent-Firewall.git
cd Drex-Agent-Firewall
python3 -m pip install -e .
drex-firewall health
drex-firewall sandbox list
drex-firewall sandbox test-escape
```

## Known Limitations

- Bubblewrap shares the host Linux kernel; it is not a microVM or hypervisor boundary.
- Bubblewrap alone does not enforce cgroup CPU, memory, or process limits. No seccomp profile is applied.
- The CONNECT broker controls destination hostnames and ports. It cannot inspect encrypted HTTPS paths or bodies.
- Codex's inner workspace sandbox may be disabled for its CLI child where nested Bubblewrap cannot create a namespace. The outer Drex Bubblewrap remains the filesystem, process, and network enforcement boundary in that mode.
- The legacy `allowlisted` network mode remains isolated. Use `controlled-online` for supported authenticated Claude or Codex calls; other agents and arbitrary destinations are not supported by that path.
- `NoIsolationBackend` runs without an operating-system isolation boundary and is an explicit development/benchmark mode.
- Resource exhaustion, kernel vulnerabilities, application bugs, model mistakes, and attacks outside the tested cases remain possible. Use least privilege and additional host controls appropriate to the deployment.

## License

MIT. See [LICENSE](LICENSE).
