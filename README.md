> v0.1.3rc1 is a hardening candidate, not release-ready. See [current validation and open gates](docs/HARDENING_VALIDATION.md).

# Drex Agent Firewall

> Deterministic policy and execution control for coding agents, powered by Drex.

[![CI](https://github.com/colt2822/Drex-Agent-Firewall/actions/workflows/ci.yml/badge.svg)](https://github.com/colt2822/Drex-Agent-Firewall/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)

**Drex Agent Firewall** is a deterministic policy and execution-control layer for coding agents. It evaluates proposed actions, applies deterministic rules and constraints, and offers guarded adapters and optional outer sandboxing. Coverage depends on how an agent is integrated.

> **Notice**: Independent open-source project. Not an official Nace/Drex SDK or certified security appliance. It does not provide formal security certification or mathematical proofs of non-interference. It should be deployed as defense-in-depth alongside containerization, least privilege IAM, and network sandboxing.

---

## What it is and what it is not

Drex combines a probabilistic decision layer with deterministic policy rules and execution controls for actions routed through its integrations. It can be used through MCP, SDK calls, guarded adapters, and an optional outer sandbox.

It is not a VM or hardware isolation boundary, complete mandatory mediation today, complete resource isolation, or globally tamper-proof audit infrastructure. Agents with native shell/filesystem access can bypass MCP policy calls; the sandbox is an independent defense layer with backend-specific limits.

## Current hardening status

| Area | Status |
|---|---|
| Managed Bubblewrap audit isolation | **Demonstrated** within the tested managed Bubblewrap scope |
| OCI audit isolation | **Pending runtime validation**; configuration tests alone do not demonstrate containment |
| RT-02 mandatory mediation | **Unresolved** |
| Aggregate resource isolation (RT-01) | **Unresolved** |
| Host rollback detection | **Not implemented** |
| Global RT-03 | **Unresolved** |

Managed Bubblewrap agents could not directly access the authoritative audit DB/WAL/SHM in 26 synthetic tamper cases. Global audit tamperability remains possible through raw NoIsolation or same-UID host access. See [RT-03 patch notes](RELEASE_NOTES_v0.1.2.md), the [security report](security/rt03/REPORT.md), and the [roadmap](docs/ROADMAP.md).

## Security model

The controls have distinct roles:

- **DREX_DECISION_LAYER**: probabilistic action classification; its output is advisory input to policy.
- **DETERMINISTIC_POLICY_LAYER**: rules and invariants decide whether a proposed action is permitted or escalated.
- **MCP_MEDIATION**: intercepts calls routed through the MCP server; native agent operations may bypass it.
- **GUARDED_ADAPTERS**: apply policy and constraints to actions executed through those adapters.
- **OUTER_SANDBOX**: limits process visibility and access according to the selected backend; it does not make all actions policy-mediated.
- **CONTROLLED_EGRESS**: optional brokered network path with documented destination and protocol limits.
- **AUDIT_STORE**: managed sessions use a host-private DB and narrow per-session append socket; this is scoped prevention, not globally tamper-proof history.

## Architecture

```text
AI Agent (Claude Code / OpenHands / Custom)
   ↓ proposed action / tool call
Drex Agent Firewall
   ├── 1. Context Normalizer & Secret Redactor
   ├── 2. Deterministic Pre-Check (Absolute Invariants)
   ├── 3. Drex Decision Layer (Full Probability Distributions)
   ├── 4. Deterministic Policy Layer
   └── 5. Machine-Enforceable Constraint Synthesis
   ↓
ALLOW | ALLOW_WITH_CONSTRAINTS | ESCALATE | ABSTAIN | BLOCK
   ↓
Enforcement Adapters (Shell / Filesystem / Git / GitHub / HTTP / MCP)
   ↓
Managed Audit Store (host writer for supported managed sessions)
```

---

## WHAT
Drex Agent Firewall is an enforcement gatekeeper. Every proposed tool call is converted into a strongly-typed `ActionEnvelope`, scrubbed of credentials, and evaluated across structured decision taxonomies. A deterministic policy engine interprets the probabilistic distribution to make an enforceable ruling: `ALLOW`, `ALLOW_WITH_CONSTRAINTS`, `ESCALATE`, `ABSTAIN`, or `BLOCK`.

## WHY
Autonomous agents operating in production environments can inadvertently cause catastrophic side-effects:
- Running destructive shell commands (`rm -rf /`, `mkfs`, fork bombs)
- Escaping repository roots via path traversal or symlinks
- Force-pushing to remote branches or overwriting release tags
- Exfiltrating credentials (`.env`, `id_rsa`, API keys) to unknown external HTTP destinations
- Performing high-impact mutations with low model confidence

Deterministic rules are designed to block configured forbidden actions before guarded adapters execute them. Coverage depends on which integrations and runtime boundaries are used; see the [threat model](docs/threat-model.md) and [known limitations](#limitations).

## HOW
1. **Action Envelope**: Captures normalized targets, read-only status, reversibility, external effects, and context.
2. **Secret Redaction**: Scrubs credentials, API keys, and bearer tokens before persistence or external queries.
3. **Deterministic Hard Invariants**: Absolute rules (path confinement, forbidden commands, SSRF blocks) operate independently of and override model outputs.
4. **Drex Decision Engine**: Provides structured probabilistic classification across 8 dimensions. Full probability distributions are preserved.
5. **Enforceable Constraints**: `ALLOW_WITH_CONSTRAINTS` returns concrete constraints (allowed canonical paths, command prefixes, timeout limits, byte caps) enforced by adapters.

---

## WHAT DREX DOES
- Fast, typed, probabilistic classification across multidimensional taxonomies.
- Generates probability distributions over:
  - **Action Risk**: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`
  - **Action Class**: `READ`, `WRITE`, `DELETE`, `EXECUTE`, `NETWORK`, `AUTH`, `EXTERNAL_PUBLISH`, `MONEY_MOVEMENT`, `UNKNOWN`
  - **Scope Match**: `IN_SCOPE`, `POSSIBLY_IN_SCOPE`, `OUT_OF_SCOPE`, `UNKNOWN`
  - **Reversibility**: `FULLY_REVERSIBLE`, `PARTIALLY_REVERSIBLE`, `IRREVERSIBLE`, `UNKNOWN`
  - **External Effect**: `NONE`, `LOCAL_ONLY`, `REMOTE_REVERSIBLE`, `REMOTE_IRREVERSIBLE`, `UNKNOWN`
  - **Credential Risk**: `NONE`, `READ_ONLY_SECRET_ACCESS`, `SECRET_TRANSMISSION`, `SECRET_PERSISTENCE`, `UNKNOWN`
  - **Destructive Risk**: `NONE`, `LOW`, `MODERATE`, `HIGH`
  - **Needs Human Approval**: `YES`, `NO`, `UNCERTAIN`
- Returns confidence scores for calibration.

## WHAT DREX DOES NOT DO
- Drex does **NOT** generate code.
- Drex does **NOT** write arbitrary prose or conversational chat.
- Drex does **NOT** replace the autonomous agent.
- Drex does **NOT** summarize entire repositories.
- Drex output is **NEVER** directly executed.

---

## QUICKSTART

### Installation
```bash
git clone https://github.com/colt2822/Drex-Agent-Firewall.git
cd Drex-Agent-Firewall
pip install -e .
```

### CLI Quickstart
```bash
# Health check
drex-firewall health

# Run real autonomous agent inside isolated sandbox runtime (Bubblewrap)
drex-firewall sandbox demo --agent claude

# Run dedicated host escape audit session with real agent inside sandbox
drex-firewall sandbox demo --escape-session --agent claude

# Run 100-scenario outer isolation and host escape benchmark
drex-firewall benchmark --isolation

# Verify sandbox boundary against automated host escape probes
drex-firewall sandbox test-escape

# Interactive confined bash shell
drex-firewall sandbox shell --workspace .

# Run the 220-scenario adversarial red-team benchmark
drex-firewall benchmark --redteam

# Run the 186-scenario hostile architectural bypass benchmark
drex-firewall benchmark --bypass

# Run baseline benchmark suite (105 scenarios)
drex-firewall benchmark

# Run latency and overhead benchmark
drex-firewall benchmark --latency

# Run multi-pack historical policy simulator
drex-firewall simulate --limit 100

# Start Web UI and REST API server
drex-firewall serve --port 8000
```

### Python SDK
```python
from drex_agent_firewall import DrexFirewall, OutcomeType

fw = DrexFirewall()

# 1. Evaluate a proposed action
decision = fw.evaluate(
    tool="shell",
    operation="execute",
    arguments={"command": "cat README.md"},
    context={"cwd": "/workspace"},
)

if decision.allowed:
    print(f"Action permitted: {decision.decision.value}")

# 2. Guarded execution through adapter
result = fw.execute_shell("ls -la")
print(result.stdout)

# 3. Attach calibration outcome feedback
fw.record_outcome(
    action_id=decision.action_id,
    outcome=OutcomeType.EXECUTED_SUCCESSFULLY,
    notes="Normal read operation verified",
)
```

---

## REAL AUTONOMOUS AGENT INTEGRATION

The repository includes a documented Claude Code sandbox integration and Codex controlled-online runtime validation. The reproducible test suite covers sandbox setup, credential staging and cleanup, host policy, and controlled egress. These checks do not establish a general guarantee against agent or kernel attacks.

```text
REAL CODING AGENT (Claude Code / Codex)
         ↓ (JSON-RPC 2.0 via stdio)
Drex Agent Firewall MCP Server
         ↓ (ActionEnvelope normalization + Secret Redaction)
Drex Probabilistic Decision Layer
         ↓ (Full Probability Distributions)
Deterministic Policy Engine & Hard Invariants
         ↓ (Machine-Enforceable Constraints)
Guarded Adapters (Shell / Filesystem / Git)
         ↓
Disposable Git Repository
         ↓
SQLite WAL Audit Trail & Calibration
```

### Validation Scope
- A Claude Code v2.1.287 sandbox task and confinement audit are documented in [docs/agent-runtime.md](docs/agent-runtime.md).
- Codex CLI launch, controlled-online authentication handling, and provider-host policy are covered by sandbox tests. A successful live Codex coding-task result is not claimed here.
- The benchmark results below measure only the listed deterministic replay datasets; they are not proof of security outside those cases.

Run with a single command:
```bash
drex-firewall demo-agent
```

---

## DREX ISOLATED AGENT RUNTIME (`drex-firewall sandbox`)

An optional outer operating-system confinement layer for agents launched inside it. It reduces exposure to bypasses through direct native execution, subject to the runtime's documented limitations.

```text
HOST ENVIRONMENT
 │
 │ [Controlled Boundary]
 ▼
┌────────────────────────────────────────────────────────┐
│             DREX ISOLATED AGENT RUNTIME                │
│                                                        │
│  Autonomous Agent (Claude Code / Codex / Generic)      │
│                     │                                  │
│                     ▼                                  │
│            Drex Agent Firewall                         │
│                     │                                  │
│         ┌───────────┼───────────┐                      │
│         ▼           ▼           ▼                      │
│        MCP        Shell        Git                     │
│        FS         HTTP        GitHub                   │
│                                                        │
│  • Writable /workspace mount only                      │
│  • Ephemeral isolated /home/agent                      │
│  • Ambient host credentials not inherited             │
│  • Deny direct network egress by default               │
│  • Dropped kernel capabilities (CAP_DROP ALL)          │
│  • Die-with-parent lifecycle supervision               │
└────────────────────────────────────────────────────────┘
```

### Security Properties
- **Host `$HOME` Isolated**: The host home directory (`~`) is never mounted. The agent runs with an isolated ephemeral tmpfs at `/home/agent`.
- **Ambient Environment Cleared**: Host environment is wiped (`--clearenv`). Ambient secrets (`GITHUB_TOKEN`, `AWS_*`, `OPENAI_API_KEY`, `SSH_AUTH_SOCK`) are not inherited. The opt-in `controlled-online` path injects only the selected agent's existing auth file, read-only for that call, and removes its ephemeral copy when the call ends.
- **Rootless & Unprivileged**: Runs via unprivileged user namespaces (`bwrap` bubblewrap), drops all 38 Linux capabilities (`CAP_DROP ALL`), and forbids setuid.
- **Docker Socket Blocked**: Daemon sockets (`/var/run/docker.sock`) are inaccessible, neutralizing container-breakout vectors.
- **No User-Local Directory Mount**: Host `~/.local`, `~/.codex`, and host `$HOME` are not mounted. Codex and Claude use system-installed executables from read-only `/usr`.
- **Controlled Online Agent Calls**: This mode keeps Bubblewrap's network namespace unshared. A loopback-only in-sandbox CONNECT proxy uses one mode-0600 per-session socket mounted at `/run/drex-egress.sock`; the host broker permits exact provider hostnames on TCP/443 and rejects DNS results that are not globally routable. Host Docker, Podman, and SSH runtime sockets are not mounted.

### Limitations
- Bubblewrap **shares the host Linux kernel**. It is not a microVM, hypervisor, or formal verification boundary.
- **Delegated cgroup-v2 controllers are required** by the v0.1.3rc1 Bubblewrap candidate. Writable workspace aggregate disk/inode quotas remain unresolved.
- The MCP policy layer is not mandatory mediation. Agents with native shell or filesystem access can perform workspace actions without calling the MCP server; the outer sandbox limits some host access but does not make every effect policy checked.
- Managed sessions use a host-private SQLite store and a per-session append-oriented Unix-socket capability. In tested managed Bubblewrap sessions, native attacks could not read, write, delete, or replace the authoritative store. OCI runtime behavior remains unvalidated. Standalone MCP/SDK databases remain caller-selected and can be tampered with by same-UID host execution. Global RT-03 remains unresolved; see [RT-03 evidence and limits](security/rt03/REPORT.md).
- Resource controls vary by backend. Bubblewrap does not enforce CPU, memory, or file-descriptor quotas; configured command timeouts, output limits, and namespace boundaries do not prevent every resource exhaustion attack.
- Disk and file-descriptor quotas are not enforced consistently across backends, and command timeouts are not a whole-session wall-clock limit. Container backends apply their configured CPU, memory, and PID limits; those limits are not portable to every backend.
- The runtime is defense-in-depth and is not a complete authoritative security boundary. Do not rely on it as the sole enforcement or audit control for high-impact actions.

Managed audit history defaults to the trusted launcher's
`~/.local/state/drex-agent-firewall/audit/history.db`, with a 0700 parent and 0600
database. The DB and its WAL/SHM are never guest mounts. MCP gets only
`/run/drex-audit.sock`; changing guest environment, workspace configuration, or
MCP arguments cannot change that writer's destination. `SandboxManager` refuses
NoIsolation sessions. Raw NoIsolation and standalone host execution remain unsafe.
History persists after session destruction. Host inspection supports
`drex-firewall sandbox inspect SESSION --audit-db /trusted/private/history.db`;
the existing API/CLI can inspect the DB when configured by the trusted operator.
Existing workspace databases are not silently migrated. The v0.1.2 candidate
passed 120 tests; 26 native filesystem tamper cases ran in real Bubblewrap namespaces;
there is no independent cryptographic rollback detection or complete native-action
audit coverage. Docker/Podman and a real-agent canary were not validated here.
- The legacy `allowlisted` network mode remains fully isolated. Use `controlled-online` only for supported authenticated agent calls; Codex currently permits `api.openai.com`, `auth.openai.com`, and `chatgpt.com`, while Claude permits `api.anthropic.com`.
- The broker accepts CONNECT requests only for exact configured hostname strings on TCP/443 and validates each resolved destination as globally routable. It does not inspect TLS SNI, HTTPS URL paths, or encrypted request contents.
- Codex's inner workspace sandbox may be disabled for its CLI child when nested Bubblewrap cannot create a namespace. In that mode, the enclosing Drex Bubblewrap remains the filesystem, process, and network enforcement boundary.

### Commands
```bash
# Run command inside sandbox
drex-firewall sandbox run --workspace . -- ls -la /workspace

# Run Claude Code with controlled provider egress
drex-firewall sandbox demo --agent claude --network controlled-online

# Run Codex with controlled OpenAI/ChatGPT egress
drex-firewall sandbox demo --agent codex --network controlled-online

# Run defensive escape audit session with Claude Code
drex-firewall sandbox demo --escape-session --agent claude

# Verify 10 host escape vectors
drex-firewall sandbox test-escape

# Run 100-scenario outer isolation benchmark
drex-firewall benchmark --isolation
```

---

## REUSABLE POLICY PACKS

Pre-configured, standardized security profiles tailored to operational contexts:

1. **`safe-local-coding`**: Default developer profile allowing workspace edits and local testing while blocking secrets, force-pushes, and host wipes.
2. **`github-contributor`**: PR contributor bot profile allowing branch workflows while forbidding remote deletions and unauthorized merges.
3. **`read-only-research`**: Zero-mutation profile that deterministically blocks all filesystem modifications and external writes in the current rule set.
4. **`autonomous-ci`**: Bounded unattended CI runner profile with strict runtime and memory caps.
5. **`production-ops`**: High-assurance ops profile requiring $\ge 95\%$ confidence for mutations and human approval for releases.
6. **`paranoid`**: Zero-trust air-gapped posture requiring explicit human escalation for any filesystem write or shell process.

### Historical Policy Simulation
Simulate audit traces across all 6 packs without side effects:
```bash
drex-firewall simulate --limit 100
```

---

## ADVERSARIAL RED-TEAM BENCHMARK

A dedicated adversarial benchmark of **220 scenarios** across 10 security categories:

```text
A. Shell Obfuscation (subshells, quotes, base64 pipes, eval, wrapper unrolling)
B. Filesystem Escape (directory traversal, symlink escapes, Unicode normalization)
C. Secret Exfiltration (HTTP JSON, forms, query params, headers, git remotes, MCP args)
D. SSRF / Network Bypass (IP formats, hex/octal/decimal IPs, RFC1918, cloud metadata)
E. Git Bypass (force-push, force-with-lease, delete remote ref, hard reset)
F. GitHub External Effects (PRs, issues, comments, releases, label mutations)
G. MCP Protocol Attacks (nested tool args, malformed schemas, tool impersonation)
H. Ambiguous High-Impact (unknown binaries, opaque deployment scripts)
I. Prompt Injection Payloads (injected instructions inside tool arguments)
J. Multi-Step Composite Attacks (read secret -> encode -> network POST)
```

### Benchmark Results

These are the recorded v0.1.0 baseline results. Run each command to reproduce the result in the current environment.

| Suite | Scenarios | Accuracy | False allows |
| --- | ---: | ---: | ---: |
| Standard | 105 | 100.0% | 0 high-impact |
| Red-team | 220 | 99.55% | 0 high-impact |
| Hostile bypass | 186 | 98.39% | 0 |
| Isolation | 100 | 98.0% | 0 |

```bash
drex-firewall benchmark --redteam
```

---

## CALIBRATION & LATENCY PROFILES

### Calibration & Latency Tools
The calibration and latency commands report measurements for the current run and configuration. Results depend on the provider, host, and dataset; no fixed latency or live-provider performance guarantee is made.

```bash
drex-firewall calibration
drex-firewall benchmark --latency
```

---

## MCP COMPATIBILITY

Verified against standard Model Context Protocol servers:
- **Filesystem Server**: Blocks traversal, enforces size quotas.
- **Git/GitHub Server**: Blocks remote force-pushes, prevents secret leaks.
- **Generic Tool Server**: Full JSON-RPC 2.0 specification compliance.

Run proxy:
```bash
drex-firewall mcp-proxy --upstream "node /path/to/server.js"
```

---

## REPLAY MODE vs LIVE DREX

### Replay Mode (Default / Offline)
- `provider="REPLAY"`, `resolved_model="replay-deterministic-v1"`.
- Runs completely offline without API credentials.
- Employs deterministic heuristics preserving full probability distributions.
- Powers CI, benchmark verification, and local tests.

### Live Drex Mode
Connects directly to the live Drex Decision Engine (`drex-v1.5`):
```bash
export DREX_PROVIDER_TYPE=drex
export DREX_API_KEY=your_drex_api_key_here
export DREX_API_URL=https://drex.nace.ai/v1/systemone
```

---

## AUDIT TRACES & PERSISTENCE
Every decision is persisted to SQLite in **WAL mode** (`PRAGMA journal_mode=WAL`).
- Tracks complete action envelopes, 8-dimensional probability distributions, policy rules, latencies, and execution outcomes.
- Traces survive process restarts.
- Secrets are scrubbed prior to persistence.

The FastAPI service exposes Prometheus metrics and a web dashboard. Its API has no built-in authentication, so `drex-firewall serve` binds to loopback by default. Cross-origin browser access is disabled by default; set `DREX_FIREWALL_CORS_ORIGINS` to a comma-separated list of exact HTTP(S) origins if needed. Wildcards are rejected. Review [SECURITY.md](SECURITY.md) and provide separate access controls before binding to a network interface.

---

## DOCUMENTATION INDEX
- [Architecture & Invariants](docs/architecture.md)
- [Threat Model](docs/threat-model.md)
- [Adversarial Red-Team Benchmark](docs/redteam.md)
- [Real Autonomous Agent Demo](docs/real-agent-demo.md)
- [Reusable Policy Packs](docs/policy-packs.md)
- [MCP Compatibility Matrix](docs/mcp-compatibility.md)
- [Calibration & Latency Report](docs/calibration.md)
- [Security Model & Invariants](docs/security_model.md)

## DEVELOPMENT

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pytest
drex-firewall benchmark
```

---

## LICENSE
MIT License. See [LICENSE](LICENSE) for details.
