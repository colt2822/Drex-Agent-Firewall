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

# Run the 8-step killer demo
drex-firewall demo

# Evaluate an action
drex-firewall evaluate --tool shell --operation execute --command "git status"

# Run a guarded shell command
drex-firewall shell -- git status

# Run comprehensive benchmark suite (105 scenarios)
drex-firewall benchmark

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

## REPLAY MODE
The firewall runs completely offline without any API credentials using `ReplayProvider`:
- Clearly marked: `provider="REPLAY"`, `resolved_model="replay-deterministic-v1"`.
- Replay decisions are never represented as live Drex decisions.
- Employs deterministic heuristics preserving full probability distributions.
- Powers CI, benchmark verification, local tests, and offline demonstrations.

## LIVE MODE
To connect to the live Drex Decision Engine:
```bash
export DREX_PROVIDER_TYPE=drex
export DREX_API_KEY=your_drex_api_key_here
export DREX_API_URL=https://drex.nace.ai
export DREX_REQUESTED_MODEL=drex-latest
```
When live mode is active, the firewall records both `requested_model` and `resolved_model` (e.g. `drex-v1.5`) as returned by the upstream provider.

---

## ADAPTERS

### 1. MCP Firewall Proxy
Intercepts Model Context Protocol (JSON-RPC 2.0) tool calls and resource reads between MCP clients (Claude Code, OpenHands) and upstream servers:
```bash
drex-firewall mcp-proxy --upstream "node /path/to/server.js"
```
Tool calls are normalized into action envelopes, evaluated through the firewall, and forwarded only if permitted.

### 2. Guarded Shell Executor
- Bounded stdout/stderr memory retention (`max_output_bytes`).
- Strict process execution timeouts (`max_runtime_seconds`).
- Environment variable name filtering: secret values are never passed to Drex.

### 3. Filesystem Adapter
- Operations: `read`, `create`, `modify`, `rename`, `delete`, `mkdir`.
- Symlink resolution (`os.path.realpath`) and confinement checks against `allowed_roots`.
- Pre- and post-operation SHA-256 hash tracking.

### 4. Git Adapter
- Distinguishes local reversible actions (`git status`, `git commit`) from remote mutations (`git push`).
- Deterministically blocks force-push (`--force`, `+ref`).

### 5. GitHub Adapter
- Guarded issues, PRs, comments, and merges.
- Idempotency key generation for remote write operations.
- Credential scrubbing for all tokens.

### 6. HTTP Adapter
- Inspects method, destination host, and request payload.
- Blocks cloud metadata endpoints (`169.254.169.254`) and unauthorized exfiltration of API keys.

---

## POLICIES & CONFIDENCE THRESHOLDS

Configurable minimum confidence required to allow actions:
```yaml
thresholds:
  READ: 0.70
  WRITE: 0.90
  DELETE: 0.98
  EXECUTE: 0.90
  NETWORK: 0.85
  AUTH: 0.95
  EXTERNAL_PUBLISH: 0.97
```

### Fail-Open vs Fail-Closed
Configurable by action class when provider queries encounter errors or timeouts:
- `READ`: Fail open (`ALLOW`) with audit warning.
- `WRITE`: Escalate (`ESCALATE`).
- `DELETE` / `DESTRUCTIVE`: Fail closed (`BLOCK`).
- `SECRET_TRANSMISSION`: Fail closed (`BLOCK`).

---

## AUDIT TRACES & PERSISTENCE
Every decision is persisted to SQLite configured in **WAL mode** (`PRAGMA journal_mode=WAL`).
- Tracks: `action_id`, `trace_id`, `agent`, `tool`, `operation`, `normalized_target`, `requested_model`, `resolved_model`, `provider`, `full_probability_distribution`, `confidence`, `policy_rule`, `constraints`, `latency_ms`, `executed`, `outcome`.
- Traces survive process restarts.
- Secrets are scrubbed prior to persistence.

---

## BENCHMARK SUITE
The project includes a benchmark suite of **105 scenarios** across 17 categories:
```bash
drex-firewall benchmark
```
Metrics measured:
- Total Scenarios: **105**
- Accuracy: **100.0%**
- False Allow Rate (Overall): **0.0%**
- False Block Rate: **0.0%**
- Escalation Rate: **15.24%**
- **False Allow Rate for High-Impact Actions**: **0.0%**

---

## KILLER DEMO
Sequential execution of 8 autonomous agent actions:
```text
1. read README                          → ALLOW (Drex Probabilistic, 98% conf)
2. inspect git status                   → ALLOW (Drex Probabilistic, 98% conf)
3. modify src file                      → ALLOW_WITH_CONSTRAINTS (Drex Probabilistic, 96% conf)
4. run tests                            → ALLOW (Drex Probabilistic, 95% conf)
5. commit change                        → ALLOW_WITH_CONSTRAINTS (Drex Probabilistic, 96% conf)
6. attempt force push                   → BLOCK (Deterministic Hard Invariant)
7. read API key (.env)                  → BLOCK (Deterministic Hard Invariant)
8. attempt POST of API key to unknown   → BLOCK (Deterministic Hard Invariant)
```

---

## LIMITATIONS
- Shell command evaluation uses pattern matching and AST heuristics; obfuscated subshells or encoded command wrappers should be accompanied by container sandboxing.
- Network policy uses domain and IP matching; DNS rebinding protections require host-level network namespace isolation.
- Offline replay mode relies on deterministic heuristics; production deployments should calibrate with live Drex decisions and outcome feedback.

---

## SECURITY
Please see [SECURITY.md](SECURITY.md) for vulnerability reporting guidelines.
