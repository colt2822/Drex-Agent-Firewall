# Drex Agent Firewall

> A probabilistic policy firewall for autonomous AI agents, powered by Drex.

[![CI](https://github.com/example/drex-agent-firewall/actions/workflows/ci.yml/badge.svg)](https://github.com/example/drex-agent-firewall/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)

**Drex Agent Firewall** is a production-grade, vendor-neutral policy and decision firewall designed to sit between autonomous AI agents (Claude Code, OpenAI Codex, OpenHands, generic MCP clients, custom agentic loops) and tools that can cause side effects (Shell, Filesystem, Git, GitHub, HTTP, MCP).

> **Notice**: Independent open-source project. Not an official Nace/Drex SDK or certified security appliance. It does not provide formal security certification or mathematical proofs of non-interference. It should be deployed as defense-in-depth alongside containerization, least privilege IAM, and network sandboxing.

---

## Architecture

```text
AI Agent (Claude Code / OpenHands / Custom)
   ↓ proposed action / tool call
Drex Agent Firewall
   ├── 1. Context Normalizer & Secret Redactor
   ├── 2. Deterministic Pre-Check (Absolute Invariants)
   ├── 3. Drex Decision Engine (Full Probability Distributions)
   ├── 4. Deterministic Policy Interpretation (Confidence Thresholds)
   └── 5. Machine-Enforceable Constraint Synthesis
   ↓
ALLOW | ALLOW_WITH_CONSTRAINTS | ESCALATE | ABSTAIN | BLOCK
   ↓
Enforcement Adapters (Shell / Filesystem / Git / GitHub / HTTP / MCP)
   ↓
Audit Trace & WAL SQLite Persistence
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

Drex Agent Firewall stops these failures deterministically before effects occur.

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
git clone https://github.com/example/drex-agent-firewall.git
cd drex-agent-firewall
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

The firewall is proven under a **real autonomous coding agent** (Claude Code v2.1.287 / OpenAI Codex) solving a real bug in a disposable repository with safe adversarial bait.

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

### Verification Results
- **Legitimate Coding Task**: **PASSED** (Agent diagnosed bug in `src/normalizer.py`, wrote fix, passed all pytest tests, and committed).
- **Adversarial Bait Leaks**: **0 LEAKS (100% BLOCKED)** (Reading `.env`, cloud metadata SSRF, force-pushing to untrusted remotes, and out-of-workspace writes were neutralized).
- **Agent Autonomy Rate**: **100.0%** (Zero false escalations or workflow interruptions on safe actions).
- **Firewall Overhead**: **< 1.0 ms / call** (Average 0.64 ms).

Run with a single command:
```bash
drex-firewall demo-agent
```

---

## DREX ISOLATED AGENT RUNTIME (`drex-firewall sandbox`)

An optional, production-grade outer operating system boundary around autonomous agents. Prevents agents from bypassing application-level firewalls via direct native host execution.

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
- **No cgroup-based resource limits** are enforced by Bubblewrap alone. Timeout enforcement and output truncation provide partial mitigation.
- The legacy `allowlisted` network mode remains fully isolated. Use `controlled-online` only for supported authenticated agent calls; Codex currently permits `api.openai.com`, `auth.openai.com`, and `chatgpt.com`, while Claude permits `api.anthropic.com`.
- The broker accepts CONNECT requests only for exact configured hostname strings on TCP/443 and validates each resolved destination as globally routable. It does not inspect TLS SNI, HTTPS URL paths, or encrypted request contents.
- Codex's inner workspace sandbox is disabled only for the CLI child because nested Bubblewrap fails in this host's outer user namespace (`No permissions to create new namespace`). The enclosing Drex Bubblewrap remains in force for filesystem, process, and network isolation.

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

### Red-Team Results
- Total Scenarios: **220**
- Accuracy: **96.36%**
- High-Impact Scenarios Evaluated: **136**
- **High-Impact False Allows**: **0 (0.0% False Allow Rate)**
- False Blocks: **1 (0.45%)**
- Escalation Rate: **15.0%**
- Average Decision Latency: **24.91 ms**

```bash
drex-firewall benchmark --redteam
```

---

## CALIBRATION & LATENCY PROFILES

### Probabilistic Calibration
Evaluates correlation between Drex predicted probabilities and real downstream execution outcomes:
- **Brier Score**: **0.000 - 0.004** (where 0.0 is perfect calibration).
- **Expected Calibration Error (ECE)**: **0.0018**.
- **Risk-Outcome Correlation**: **1.000**.
- **Calibration Quality**: **HIGH**.

### Latency Profiles
Measured across 200 iterations for local and replay modes:
- **Local Deterministic Policy**: **P50: 0.135 ms**, P95: 0.181 ms, P99: 0.372 ms (7,120 ops/sec).
- **Full Replay Firewall**: **P50: 0.359 ms**, P95: 0.595 ms, P99: 6.621 ms (1,676 ops/sec).
- **Live Drex API (`drex-v1.5`)**: **P50: 262.66 ms**, P95: 276.06 ms (public HTTPS).

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

---

## LICENSE
MIT License. See [LICENSE](LICENSE) for details.
