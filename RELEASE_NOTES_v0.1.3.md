# Drex Agent Firewall v0.1.3

Drex Agent Firewall v0.1.3 provides deterministic policy and bounded capability enforcement for autonomous AI coding agents.

## Overview

Drex Agent Firewall acts as an execution-control gatekeeper between AI agents and local developer systems. It evaluates proposed agent operations, executes absolute deterministic invariants and probabilistic policy rules, and provides guarded execution adapters and bounded runtime isolation.

## Capabilities & Features

- **Local Agent Firewall**: Runs entirely on the local machine without requiring external hosted services or registries.
- **Bounded Capability Enforcement**: Fine-grained capabilities scoped to tasks, workspaces, and strict resource paths.
- **Deterministic ALLOW / BLOCK / Escalate**: Absolute hard invariants (e.g. blocking destructive commands like `rm -rf /`, restricting paths to allowed roots, preventing credential exfiltration) take strict precedence.
- **Guarded Adapters**: Protected execution adapters for Shell, Filesystem, Git, GitHub, HTTP, and stdio MCP JSON-RPC 2.0 proxy.
- **Receipts & Audit Store**: Persistent audit history stored in SQLite (WAL mode) tracking action envelopes, probability distributions, decisions, reasons, and execution outcomes. Secrets are scrubbed prior to persistence.
- **Isolated Agent Runtime**: Unprivileged Bubblewrap-based rootless containment, cleared ambient environment, dropped Linux capabilities, and die-with-parent lifecycle supervision.
- **Zero Blocked Upstream Executions**: Forbidden actions are halted before reaching underlying shell, filesystem, or upstream MCP servers.

## Verification

- Test suite: 225 unit, integration, and security tests passing with zero failures.
- Zero high-impact false allows observed across benchmark and red-team suites.
- Verified clean GitHub-based git installation via `pip install "git+https://github.com/colt2822/Drex-Agent-Firewall.git@v0.1.3"`.

## Platform Support

- Linux (x86_64, aarch64) with Python 3.10+
- Optional unprivileged Bubblewrap (`bwrap`) support for kernel namespace isolation

## Known Limitations

- **Not a MicroVM / Hypervisor**: Bubblewrap shares the host Linux kernel; it does not provide formal cryptographic verification or VM-level boundary guarantees.
- **Mediation Scope**: Policy enforcement applies to actions routed through guarded adapters, the MCP proxy, or inside managed sandbox sessions. Unconfined host execution with same-UID privileges is outside the mediation boundary.
- **Resource Limits**: Kernel-level resource enforcement requires delegated cgroup-v2 controllers on the host system.
- **Model Advisory**: Probabilistic decision layer is advisory; deterministic policy rules govern final enforcement.
