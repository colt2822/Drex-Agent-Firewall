"""SQLite database initialization with WAL mode for audit and trace logging."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Optional


SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS audit_actions (
    action_id TEXT PRIMARY KEY,
    trace_id TEXT NOT NULL,
    parent_action_id TEXT,
    timestamp REAL NOT NULL,
    agent TEXT NOT NULL,
    session_id TEXT,
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

CREATE INDEX IF NOT EXISTS idx_actions_trace ON audit_actions(trace_id);
CREATE INDEX IF NOT EXISTS idx_actions_timestamp ON audit_actions(timestamp);
CREATE INDEX IF NOT EXISTS idx_actions_tool ON audit_actions(tool);
CREATE INDEX IF NOT EXISTS idx_actions_decision ON audit_actions(final_decision);
"""


def init_db(db_path: str = "drex_firewall.db") -> sqlite3.Connection:
    """Initialize SQLite database with WAL mode and create tables if needed."""
    conn = sqlite3.connect(db_path, timeout=30.0, check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    conn.execute("PRAGMA busy_timeout=5000;")
    conn.executescript(SCHEMA_SQL)
    conn.commit()
    return conn
