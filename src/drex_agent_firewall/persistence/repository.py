"""Repository for storing, querying, and updating firewall audit traces and outcomes."""

from __future__ import annotations

import json
import sqlite3
import time
from typing import Any, Dict, List, Optional

from drex_agent_firewall.persistence.database import init_db
from drex_agent_firewall.schemas.decision import FirewallDecision
from drex_agent_firewall.schemas.envelope import ActionEnvelope
from drex_agent_firewall.schemas.outcome import ActionOutcome, OutcomeType
from drex_agent_firewall.security.redactor import SecretRedactor


import threading
import re


def _safe_audit_text(value: Any) -> Any:
    if isinstance(value, str):
        return re.sub(r"[\x00-\x1f\x7f]", lambda m: f"\\u{ord(m.group(0)):04x}", value)
    if isinstance(value, dict):
        return { _safe_audit_text(k): _safe_audit_text(v) for k, v in value.items() }
    if isinstance(value, list):
        return [_safe_audit_text(v) for v in value]
    return value


class ActionRepository:
    """Audit persistence repository using SQLite in WAL mode."""

    def __init__(self, db_path: str = "drex_firewall.db", redactor: Optional[SecretRedactor] = None):
        self.db_path = db_path
        self.redactor = redactor or SecretRedactor()
        self._lock = threading.Lock()
        self.conn = init_db(db_path)


    def record_decision(
        self,
        envelope: ActionEnvelope,
        decision: FirewallDecision,
    ) -> None:
        """Persist a complete firewall evaluation record."""
        # Sanitize arguments and target before storing
        clean_args = _safe_audit_text(self.redactor.sanitize(envelope.arguments))
        clean_target = _safe_audit_text(self.redactor.redact_text(envelope.resource_target))

        drex_eval = decision.drex_evaluation
        dist_json = None
        req_model = None
        res_model = None
        prov = None
        prov_lat = 0.0

        if drex_eval:
            req_model = drex_eval.requested_model
            res_model = drex_eval.resolved_model
            prov = drex_eval.provider
            prov_lat = drex_eval.provider_latency_ms
            dist_json = drex_eval.distributions.model_dump_json()

        constraints_json = decision.constraints.model_dump_json()

        with self._lock:
            with self.conn:
                self.conn.execute(

                """
                INSERT OR REPLACE INTO audit_actions (
                    action_id, trace_id, parent_action_id, timestamp,
                    agent, session_id, sandbox_session_id, tool, operation,
                    normalized_target, arguments_json, requested_model,
                    resolved_model, provider, decision_type, final_decision,
                    allowed, reason, hard_policy_triggered, policy_rule,
                    confidence, full_probability_distribution, constraints_json,
                    latency_ms, provider_latency_ms, error_class, failure_disposition
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    decision.action_id,
                    decision.trace_id,
                    envelope.parent_action_id,
                    decision.timestamp,
                    envelope.agent_id,
                    envelope.session_id,
                    envelope.sandbox_session_id,
                    envelope.tool,
                    envelope.operation,
                    clean_target,
                    json.dumps(clean_args),
                    req_model,
                    res_model,
                    prov,
                    "PROBABILISTIC_DREX" if not decision.hard_policy_triggered else "HARD_INVARIANT",
                    decision.decision.value,
                    1 if decision.allowed else 0,
                    _safe_audit_text(decision.reason),
                    1 if decision.hard_policy_triggered else 0,
                    decision.policy_rule,
                    drex_eval.confidence if drex_eval else 1.0,
                    dist_json,
                    constraints_json,
                    decision.latency_ms,
                    prov_lat,
                    None,
                    None,
                ),
            )

    def record_execution(
        self,
        action_id: str,
        executed: bool,
        result: Any = None,
        error_class: Optional[str] = None,
    ) -> None:
        """Record execution attempt and bounded result."""
        clean_result = self.redactor.sanitize(result)
        result_str = json.dumps(clean_result) if isinstance(clean_result, (dict, list)) else str(clean_result or "")
        # Bounded persistence to avoid ballooning DB
        if len(result_str) > 100_000:
            result_str = result_str[:100_000] + "... [TRUNCATED_PERSISTENCE]"

        with self._lock:
            with self.conn:
                self.conn.execute(
                    """
                    UPDATE audit_actions
                    SET executed = ?, execution_result = ?, error_class = ?
                    WHERE action_id = ?
                    """,
                    (1 if executed else 0, result_str, error_class, action_id),
                )

    def record_outcome(self, outcome: ActionOutcome) -> None:
        """Attach calibration/outcome feedback to an action."""
        with self._lock:
            with self.conn:
                self.conn.execute(
                    """
                    UPDATE audit_actions
                    SET outcome = ?, outcome_notes = ?, outcome_recorded_at = ?
                    WHERE action_id = ?
                    """,
                    (outcome.outcome.value, outcome.notes, outcome.recorded_at, outcome.action_id),
                )


    def get_action(self, action_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            cursor = self.conn.cursor()
            cursor.execute("SELECT * FROM audit_actions WHERE action_id = ?", (action_id,))
            row = cursor.fetchone()
            if not row:
                return None
            return self._row_to_dict(cursor, row)

    def get_trace(self, trace_id: str) -> List[Dict[str, Any]]:
        with self._lock:
            cursor = self.conn.cursor()
            cursor.execute(
                "SELECT * FROM audit_actions WHERE trace_id = ? ORDER BY timestamp ASC",
                (trace_id,),
            )
            rows = cursor.fetchall()
            return [self._row_to_dict(cursor, r) for r in rows]

    def get_actions_for_session(self, session_id: str) -> List[Dict[str, Any]]:
        with self._lock:
            cursor = self.conn.cursor()
            cursor.execute(
                "SELECT * FROM audit_actions WHERE session_id = ? ORDER BY timestamp ASC",
                (session_id,),
            )
            rows = cursor.fetchall()
            return [self._row_to_dict(cursor, r) for r in rows]

    def list_actions(
        self,
        limit: int = 50,
        offset: int = 0,
        decision: Optional[str] = None,
        tool: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        with self._lock:
            cursor = self.conn.cursor()
            query = "SELECT * FROM audit_actions"
            params: List[Any] = []
            conditions: List[str] = []

            if decision:
                conditions.append("final_decision = ?")
                params.append(decision.upper())
            if tool:
                conditions.append("tool = ?")
                params.append(tool.lower())

            if conditions:
                query += " WHERE " + " AND ".join(conditions)

            query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
            params.extend([limit, offset])

            cursor.execute(query, tuple(params))
            rows = cursor.fetchall()
            return [self._row_to_dict(cursor, r) for r in rows]

    def get_stats(self) -> Dict[str, Any]:
        with self._lock:
            cursor = self.conn.cursor()
            cursor.execute("""
                SELECT
                    COUNT(*) as total,
                    SUM(CASE WHEN final_decision = 'ALLOW' THEN 1 ELSE 0 END) as allowed,
                    SUM(CASE WHEN final_decision = 'ALLOW_WITH_CONSTRAINTS' THEN 1 ELSE 0 END) as constrained,
                    SUM(CASE WHEN final_decision = 'ESCALATE' THEN 1 ELSE 0 END) as escalated,
                    SUM(CASE WHEN final_decision = 'BLOCK' THEN 1 ELSE 0 END) as blocked,
                    SUM(CASE WHEN final_decision = 'ABSTAIN' THEN 1 ELSE 0 END) as abstained,
                    AVG(latency_ms) as avg_latency_ms,
                    AVG(provider_latency_ms) as avg_prov_latency_ms,
                    SUM(executed) as total_executed
                FROM audit_actions
            """)
            row = cursor.fetchone()

        if not row or row[0] == 0:
            return {
                "total": 0,
                "allowed": 0,
                "constrained": 0,
                "escalated": 0,
                "blocked": 0,
                "abstained": 0,
                "avg_latency_ms": 0.0,
                "avg_prov_latency_ms": 0.0,
                "total_executed": 0,
            }
        return {
            "total": row[0] or 0,
            "allowed": row[1] or 0,
            "constrained": row[2] or 0,
            "escalated": row[3] or 0,
            "blocked": row[4] or 0,
            "abstained": row[5] or 0,
            "avg_latency_ms": round(row[6] or 0.0, 2),
            "avg_prov_latency_ms": round(row[7] or 0.0, 2),
            "total_executed": row[8] or 0,
        }

    def _row_to_dict(self, cursor: sqlite3.Cursor, row: tuple) -> Dict[str, Any]:
        cols = [col[0] for col in cursor.description]
        d = dict(zip(cols, row))
        # Parse JSON columns if present
        for col in ("arguments_json", "full_probability_distribution", "constraints_json", "metadata_json"):
            if d.get(col):
                try:
                    d[col] = json.loads(d[col])
                except Exception:
                    pass
        return d

    def record_sandbox_session(
        self,
        session_id: str,
        runtime_backend: str,
        workspace_path: str,
        network_mode: str,
        status: str = "RUNNING",
        agent: Optional[str] = None,
        policy_pack: Optional[str] = None,
        runtime_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Record the creation/start of an isolated sandbox session."""
        now = time.time()
        meta_json = json.dumps(metadata) if metadata else None
        with self._lock:
            with self.conn:
                self.conn.execute(
                    """
                    INSERT OR REPLACE INTO sandbox_sessions (
                        session_id, runtime_backend, runtime_id, agent,
                        policy_pack, workspace_path, network_mode, status,
                        created_at, metadata_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        session_id, runtime_backend, runtime_id, agent,
                        policy_pack, workspace_path, network_mode, status,
                        now, meta_json
                    )
                )

    def update_sandbox_session(
        self,
        session_id: str,
        status: Optional[str] = None,
        duration_seconds: Optional[float] = None,
        total_actions: Optional[int] = None,
        allowed_actions: Optional[int] = None,
        blocked_actions: Optional[int] = None,
        escalated_actions: Optional[int] = None,
        escape_attempts: Optional[int] = None,
        escape_successes: Optional[int] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Update metrics and terminal state of a sandbox session."""
        updates: List[str] = []
        params: List[Any] = []

        if status is not None:
            updates.append("status = ?")
            params.append(status)
            if status in {"STOPPED", "FAILED", "DESTROYED"}:
                updates.append("stopped_at = ?")
                params.append(time.time())

        if duration_seconds is not None:
            updates.append("duration_seconds = ?")
            params.append(duration_seconds)
        if total_actions is not None:
            updates.append("total_actions = ?")
            params.append(total_actions)
        if allowed_actions is not None:
            updates.append("allowed_actions = ?")
            params.append(allowed_actions)
        if blocked_actions is not None:
            updates.append("blocked_actions = ?")
            params.append(blocked_actions)
        if escalated_actions is not None:
            updates.append("escalated_actions = ?")
            params.append(escalated_actions)
        if escape_attempts is not None:
            updates.append("escape_attempts = ?")
            params.append(escape_attempts)
        if escape_successes is not None:
            updates.append("escape_successes = ?")
            params.append(escape_successes)
        if metadata is not None:
            updates.append("metadata_json = ?")
            params.append(json.dumps(metadata))

        if not updates:
            return

        params.append(session_id)
        sql = f"UPDATE sandbox_sessions SET {', '.join(updates)} WHERE session_id = ?"
        with self._lock:
            with self.conn:
                self.conn.execute(sql, tuple(params))

    def get_sandbox_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a single sandbox session by its ID."""
        with self._lock:
            cursor = self.conn.cursor()
            cursor.execute("SELECT * FROM sandbox_sessions WHERE session_id = ?", (session_id,))
            row = cursor.fetchone()
            if not row:
                return None
            return self._row_to_dict(cursor, row)

    def list_sandbox_sessions(self, limit: int = 50) -> List[Dict[str, Any]]:
        """List recent sandbox sessions."""
        with self._lock:
            cursor = self.conn.cursor()
            cursor.execute(
                "SELECT * FROM sandbox_sessions ORDER BY created_at DESC LIMIT ?",
                (limit,)
            )
            rows = cursor.fetchall()
            return [self._row_to_dict(cursor, r) for r in rows]

    def get_actions_for_sandbox(self, sandbox_session_id: str) -> List[Dict[str, Any]]:
        """Query all audit actions tied to a sandbox session."""
        with self._lock:
            cursor = self.conn.cursor()
            cursor.execute(
                "SELECT * FROM audit_actions WHERE sandbox_session_id = ? ORDER BY timestamp ASC",
                (sandbox_session_id,)
            )
            rows = cursor.fetchall()
            return [self._row_to_dict(cursor, r) for r in rows]
