"""SQLite database initialization with WAL mode for audit and trace logging."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Optional


SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS audit_events (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    action_id TEXT NOT NULL,
    kind TEXT NOT NULL CHECK(kind IN ('decision','execution')),
    payload TEXT NOT NULL,
    UNIQUE(action_id, kind)
);
CREATE INDEX IF NOT EXISTS idx_events_session ON audit_events(session_id);
CREATE TABLE IF NOT EXISTS audit_actions (
    action_id TEXT PRIMARY KEY,
    trace_id TEXT NOT NULL,
    parent_action_id TEXT,
    timestamp REAL NOT NULL,
    agent TEXT NOT NULL,
    session_id TEXT,
    sandbox_session_id TEXT,
    tool TEXT NOT NULL,
    operation TEXT NOT NULL,
    normalized_target TEXT,
    arguments_json TEXT,
    requested_model TEXT,
    resolved_model TEXT,
    provider TEXT,
    decision_type TEXT NOT NULL,
    final_decision TEXT NOT NULL,
    allowed INTEGER NOT NULL,
    reason TEXT,
    hard_policy_triggered INTEGER NOT NULL,
    policy_rule TEXT,
    confidence REAL,
    full_probability_distribution TEXT,
    constraints_json TEXT,
    latency_ms REAL,
    provider_latency_ms REAL,
    error_class TEXT,
    failure_disposition TEXT,
    executed INTEGER DEFAULT 0,
    execution_result TEXT,
    outcome TEXT,
    outcome_notes TEXT,
    outcome_recorded_at REAL
);

CREATE TABLE IF NOT EXISTS native_runs (
    run_id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    policy_digest TEXT NOT NULL,
    started_at REAL NOT NULL,
    completed_at REAL,
    process_class TEXT NOT NULL,
    returncode INTEGER,
    timed_out INTEGER,
    error_class TEXT
);

CREATE TABLE IF NOT EXISTS sandbox_sessions (
    session_id TEXT PRIMARY KEY,
    runtime_backend TEXT NOT NULL,
    runtime_id TEXT,
    agent TEXT,
    policy_pack TEXT,
    workspace_path TEXT NOT NULL,
    network_mode TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at REAL NOT NULL,
    stopped_at REAL,
    duration_seconds REAL,
    total_actions INTEGER DEFAULT 0,
    allowed_actions INTEGER DEFAULT 0,
    blocked_actions INTEGER DEFAULT 0,
    escalated_actions INTEGER DEFAULT 0,
    escape_attempts INTEGER DEFAULT 0,
    escape_successes INTEGER DEFAULT 0,
    metadata_json TEXT
);

CREATE INDEX IF NOT EXISTS idx_actions_trace ON audit_actions(trace_id);
CREATE INDEX IF NOT EXISTS idx_actions_timestamp ON audit_actions(timestamp);
CREATE INDEX IF NOT EXISTS idx_actions_tool ON audit_actions(tool);
CREATE INDEX IF NOT EXISTS idx_actions_decision ON audit_actions(final_decision);
CREATE INDEX IF NOT EXISTS idx_sandbox_status ON sandbox_sessions(status);
"""


def init_db(db_path: str = "drex_firewall.db") -> sqlite3.Connection:
    """Initialize SQLite database with WAL mode and create tables if needed."""
    conn = sqlite3.connect(db_path, timeout=30.0, check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=FULL;")
    conn.execute("PRAGMA busy_timeout=5000;")
    conn.executescript(SCHEMA_SQL)

    # Safe migration: ensure sandbox_session_id column exists
    cursor = conn.execute("PRAGMA table_info(audit_actions);")
    cols = [r[1] for r in cursor.fetchall()]
    if "sandbox_session_id" not in cols:
        conn.execute("ALTER TABLE audit_actions ADD COLUMN sandbox_session_id TEXT;")

    conn.execute("CREATE INDEX IF NOT EXISTS idx_actions_sandbox ON audit_actions(sandbox_session_id);")
    conn.commit()
    return conn
