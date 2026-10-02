# Drex Agent Firewall: Reusable Policy Packs

## 1. Overview

Different autonomous agent deployments require distinct security postures. Rather than forcing a single rigid configuration, **Drex Agent Firewall** provides 6 standardized, battle-tested **Policy Packs**.

Each pack configures:
- Default decision disposition (`ALLOW`, `ESCALATE`, `BLOCK`)
- Filesystem policies (`allowed_roots`, `blocked_paths`, mutation quotas)
- Shell execution boundaries (forbidden patterns, runtime bounds)
- Network boundaries (`allowed_domains`, `blocked_domains`)
- Confidence thresholds per action class (`READ`, `WRITE`, `EXECUTE`, `NETWORK`, `AUTH`, `EXTERNAL_PUBLISH`)
- Fail dispositions when the decision provider is unavailable

---

## 2. Policy Pack Specifications

### 1. `safe-local-coding` (Default Developer Workstation)
- **Goal**: Enable rapid local editing, building, and testing while preventing catastrophic host damage, secret leaks, and force pushes.
- **Default Policy**: `ESCALATE` on unclassified high-risk actions.
- **Allowed Roots**: Workspace directory and temporary build folders.
- **Blocked Targets**: `/etc/shadow`, `/root`, `~/.ssh`, `~/.aws`, `.env`, `.git/config`.
- **Thresholds**: READ: 70%, WRITE: 88%, EXECUTE: 85%, NETWORK: 95%.

### 2. `github-contributor` (Open-Source Contributor)
- **Goal**: Facilitate branch workflows, reading issues, and submitting PRs while forbidding remote branch deletion, force-pushes, and unauthorized repository setting changes.
- **Default Policy**: `ESCALATE`.
- **Allowed Networks**: `api.github.com`, `github.com`.
- **Thresholds**: EXTERNAL_PUBLISH: 95%, NETWORK: 95%.

### 3. `read-only-research` (Zero-Mutation Exploration)
- **Goal**: Allow code inspection, search, and read-only analysis with absolute mathematical guarantee of zero state modifications.
- **Default Policy**: `BLOCK`.
- **Mutations Allowed**: None. Filesystem writes, deletions, shell process mutations, and external POSTs are unconditionally blocked by deterministic hard rules.

### 4. `autonomous-ci` (Unattended CI Runner)
- **Goal**: Unattended execution of test suites, linting, and dependency builds within strict time and output quotas.
- **Fail Disposition**: `BLOCK` on timeout or provider error.
- **Shell Max Runtime**: 120 seconds.
- **Allowed Networks**: Package registries (`pypi.org`, `npmjs.org`).

### 5. `production-ops` (High-Assurance Site Reliability)
- **Goal**: Operational management requiring $\ge 95\%$ model confidence for mutations and mandatory human escalation for destructive changes, releases, or schema migrations.
- **Thresholds**: WRITE: 95%, EXECUTE: 95%, EXTERNAL_PUBLISH: 98%.

### 6. `paranoid` (Air-Gapped Zero-Trust)
- **Goal**: Maximum restriction with fail-closed posture. All external networks are blocked; all file writes and process executions require explicit human escalation.

---

## 3. Policy Pack Comparison Matrix

Simulation across representative action streams illustrates how each profile enforces boundaries:

| Policy Pack | Allowed Pass Rate | Blocked Rate | Escalation Rate | Primary Use Case |
| :--- | :---: | :---: | :---: | :--- |
| `safe-local-coding` | **61.8%** | 32.4% | 5.8% | Local software engineering |
| `github-contributor` | **61.8%** | 38.2% | 0.0% | Automated open-source PR bots |
| `read-only-research` | **44.1%** | 32.4% | 23.5% | Security audits, documentation extraction |
| `autonomous-ci` | **58.8%** | 41.2% | 0.0% | GitHub Actions, CI test pipelines |
| `production-ops` | **38.2%** | 35.3% | 26.5% | Production deployments, infra automation |
| `paranoid` | **5.9%** | 88.2% | 5.9% | Classified or high-security environments |

---

## 4. Multi-Pack Policy Simulator

The `PolicySimulator` enables security teams to simulate historical audit traces across all policy packs without executing side effects.

### CLI Usage
```bash
drex-firewall simulate --limit 100
```

### Python SDK Usage
```python
from drex_agent_firewall.policy.simulator import PolicySimulator

sim = PolicySimulator()
matrix = sim.simulate_historical_traces(limit=100)
for pack, stats in matrix.items():
    print(f"{pack}: {stats['pass_rate']}% pass rate ({stats['allowed']} allowed, {stats['blocked']} blocked)")
```
