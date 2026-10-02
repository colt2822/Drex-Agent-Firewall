# Changelog

All notable changes to the Drex Agent Firewall project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1] - 2026-10-02

### Security
- Apply audited network isolation, DNS/proxy controls, bounded HTTP and subprocess output, credential environment filtering, and secure MCP configuration wiring.
- Restrict cross-origin browser access to explicit exact origins and bind the unauthenticated HTTP API to loopback by default.
- Document unresolved resource quota, mandatory mediation, and audit database isolation limitations.
- Fix the `serve --policy` path to pass a configured firewall instance into the FastAPI app.

## [0.1.0] - 2026-10-02

### Added
- **Drex Isolated Agent Runtime**: Bubblewrap (bwrap) rootless unprivileged container sandbox
  - Linux namespace isolation (user, pid, ipc, uts, net)
  - Writable `/workspace` mount only; host home never exposed
  - Ambient host environment cleared (`--clearenv`)
  - All Linux capabilities dropped (`--cap-drop ALL`)
  - Die-with-parent lifecycle supervision
  - Ephemeral `/home/agent` with session-scoped cleanup
- **Sandbox CLI** (`drex-firewall sandbox`): run, shell, test-escape, demo, list, inspect, stop, destroy
- **Escape Probe Runner**: 18 automated adversarial host escape verification probes
- **100-Scenario Isolation Benchmark**: filesystem, credential, process, network, socket, privilege, mount, MCP, git, resource exhaustion
- **Real Agent Validation**: Claude Code v2.1.287 successfully completed coding tasks inside sandbox
- **Fail-Closed Backend Selection**: sandbox requests always fail with error if no isolation runtime available (never silently falls back to NoIsolationBackend)
- **105-Scenario Standard Benchmark**: 100.0% accuracy, 0 high-impact false allows
- **220-Scenario Adversarial Red-Team Benchmark**: 99.55% accuracy, 0 high-impact false allows
- **186-Scenario Hostile Bypass Benchmark**: 98.39% accuracy, 0 high-impact false allows
- **MCP Firewall Proxy**: JSON-RPC 2.0 stdio proxy intercepting tools/call, resources/read, resources/write
- **Guarded Adapters**: shell, filesystem, Git, GitHub, HTTP, and MCP proxy integrations
- **Controlled Online Mode**: Bubblewrap network isolation with an exact-host CONNECT broker for supported Claude and Codex calls
- **Prometheus Metrics & Web UI**: FastAPI service metrics and real-time dashboard
- **Codex Runtime Validation**: CLI launch, controlled-online authentication handling, cleanup, and provider-host policy are covered by sandbox tests; no successful live Codex coding-task result is claimed
- **6 Reusable Policy Packs**: safe-local-coding, github-contributor, read-only-research, autonomous-ci, production-ops, paranoid
- **Policy Simulator**: Compare audit traces across all policy packs without side effects
- **Calibration & Latency Benchmarks**: Brier score, ECE, risk-outcome correlation, P50/P95/P99 latency profiling
- **SQLite WAL Persistence**: Full decision traces with 8-dimensional probability distributions
- **FastAPI Server & Web UI**: REST API, Prometheus metrics, real-time dashboard
- **Python SDK**: sync/async evaluate, enforce, execute_shell, record_outcome
- **Secret Redactor**: Automatic scrubbing of API keys, tokens, private keys, URL credentials

### Security Hardening (v0.1.0-rc)
- Removed hardcoded developer-specific absolute paths from shipped examples
- Narrowed `/etc` mount from full directory to selective required files only (SSL certs, resolv.conf, ld.so, etc.)
- Made credential injection opt-in per agent_type with explicit logging
- Fixed network isolation to always unshare-net for `allowlisted` mode (veth/iptables not yet implemented; network is fully isolated)
- Removed false probe result override that hid network escapes in allowlisted/host mode
- Added workspace path canonicalization against symlinks to sensitive system paths
- Added host home directory rejection as workspace mount
- Fixed sandbox demo evaluation to report actual results instead of hardcoded PASSED values
- Added explicit visible warning when NoIsolationBackend is used
- Qualified README claims to be narrower than evidence

### Known Limitations
- Bubblewrap shares the host Linux kernel; it is not a microVM or formal verification boundary
- No kernel-level resource limits (cgroups) — Bubblewrap alone does not enforce memory/PID/CPU limits
- `allowlisted` network mode does not yet implement fine-grained veth/iptables egress filtering
- DNS-based SSRF bypasses (e.g., nip.io resolving to metadata IPs) are not detected by string-only validators
- No seccomp profile filtering — full syscall surface remains available within the namespace
- Transformed/encoded secret detection has inherent false-negative limitations
- Controlled-online agent execution requires system-installed agent binaries; no `~/.local` fallback is permitted
