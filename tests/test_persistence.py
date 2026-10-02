"""Tests for SQLite audit persistence, WAL mode, outcomes, and restarts."""

import os
import sqlite3
import threading
from drex_agent_firewall import DrexFirewall, OutcomeType
from drex_agent_firewall.persistence.database import init_db
from drex_agent_firewall.persistence.repository import ActionRepository
from drex_agent_firewall.schemas.config import FirewallConfig


def test_sqlite_wal_mode_and_trace_persistence(tmp_path):
    db_file = str(tmp_path / "test_wal.db")
    cfg = FirewallConfig.load_default()
    cfg.database_path = db_file

    fw = DrexFirewall(config=cfg)

    dec = fw.evaluate(tool="shell", operation="execute", arguments={"command": "cat README.md"})
    assert dec.action_id is not None

    # Verify WAL mode in SQLite PRAGMA
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    cursor.execute("PRAGMA journal_mode;")
    mode = cursor.fetchone()[0]
    assert mode.lower() == "wal"

    # Verify action was persisted
    action = fw.get_action(dec.action_id)
    assert action is not None
    assert action["tool"] == "shell"
    assert action["final_decision"] == "ALLOW"


def test_sqlite_restart_preserves_traces(tmp_path):
    db_file = str(tmp_path / "test_restart.db")
    cfg = FirewallConfig.load_default()
    cfg.database_path = db_file

    # First instance creates record
    fw1 = DrexFirewall(config=cfg)
    dec = fw1.evaluate(tool="git", operation="status", arguments={})
    action_id = dec.action_id
    trace_id = dec.trace_id

    # Simulate restart by instantiating new firewall pointing to same DB
    fw2 = DrexFirewall(config=cfg)
    act = fw2.get_action(action_id)
    assert act is not None
    assert act["trace_id"] == trace_id

    # Record outcome feedback
    fw2.record_outcome(action_id, OutcomeType.EXECUTED_SUCCESSFULLY, notes="Restart verification")
    updated = fw2.get_action(action_id)
    assert updated["outcome"] == "EXECUTED_SUCCESSFULLY"
    assert updated["outcome_notes"] == "Restart verification"


def test_concurrent_reads_writes(tmp_path):
    db_file = str(tmp_path / "test_concurrent.db")
    cfg = FirewallConfig.load_default()
    cfg.database_path = db_file
    fw = DrexFirewall(config=cfg)

    def _worker(idx):
        for _ in range(10):
            fw.evaluate(tool="shell", operation="execute", arguments={"command": f"echo {idx}"})

    threads = [threading.Thread(target=_worker, args=(i,)) for i in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    stats = fw.get_stats()
    assert stats["total"] >= 40
