# Architecture Overview

Drex Agent Firewall sits between autonomous AI agents and tool interfaces (Shell, Filesystem, Git, GitHub, HTTP, and MCP).

## Core Principle: Separation of Decision from Enforcement

Drex is a specialized engine for structured probabilistic decision evaluation. It is NOT asked to generate code, write prose, or summarize repositories.

```text
Agent Proposes Action
          ↓
Action Envelope Normalization (Context Sanitized & Redacted)
          ↓
Deterministic Pre-Check (Hard Invariants & Forbidden Rules)
          ↓ (if not hard-blocked)
Drex Decision Layer (Live Drex or Replay Provider)
          ↓
Full Probability Distribution
  - Action Risk (LOW, MEDIUM, HIGH, CRITICAL)
  - Action Class (READ, WRITE, DELETE, EXECUTE, NETWORK, AUTH, EXTERNAL_PUBLISH, MONEY_MOVEMENT, UNKNOWN)
  - Scope Match (IN_SCOPE, POSSIBLY_IN_SCOPE, OUT_OF_SCOPE, UNKNOWN)
  - Reversibility (FULLY_REVERSIBLE, PARTIALLY_REVERSIBLE, IRREVERSIBLE, UNKNOWN)
  - External Effect (NONE, LOCAL_ONLY, REMOTE_REVERSIBLE, REMOTE_IRREVERSIBLE, UNKNOWN)
  - Credential Risk (NONE, READ_ONLY_SECRET_ACCESS, SECRET_TRANSMISSION, SECRET_PERSISTENCE, UNKNOWN)
  - Destructive Risk (NONE, LOW, MODERATE, HIGH)
  - Needs Human Approval (YES, NO, UNCERTAIN)
          ↓
Deterministic Policy Engine (Confidence Thresholding & Rules)
          ↓
ALLOW / ALLOW_WITH_CONSTRAINTS / ESCALATE / ABSTAIN / BLOCK
          ↓
Enforcement Adapter (Shell, Filesystem, Git, GitHub, HTTP, MCP)
          ↓
Tool Execution
          ↓
Outcome Feedback & WAL SQLite Audit Trace Persisted
```
