"""Measured native sandbox attack matrix, including live and closed SQLite.

Run before with PYTHONPATH pointing to the exact release; run after with candidate.
Each attack has an independent disposable sandbox/store. No provider calls.
"""
import argparse
import json
from pathlib import Path
import sqlite3
import tempfile

from attacks import ATTACKS, native_code
from drex_agent_firewall.persistence.repository import ActionRepository
from drex_agent_firewall.sandbox.backend import SandboxSpec
from drex_agent_firewall.sandbox.bubblewrap import BubblewrapBackend


def run(mode, only=None):
    results = []
    variants = [(name, False) for name in ATTACKS]
    variants += [(name, True) for name in ("zero_truncate", "partial_truncate", "valid_empty", "rollback", "inode_replace")]
    for attack, closed in variants:
        if only and attack not in only:
            continue
        with tempfile.TemporaryDirectory(prefix="drex-rt03-hostile-") as root:
            root = Path(root)
            workspace = root / "workspace"
            workspace.mkdir()
            private = root / "private"
            private.mkdir(mode=0o700)
            if mode == "before":
                path = workspace / ".drex_firewall.db"
                repo = ActionRepository(str(path))
                backend = BubblewrapBackend()
                spec = SandboxSpec(session_id="disposable", workspace_path=str(workspace), network_mode="none")
                backend.prepare(spec)
                backend.launch(spec)
                sid = spec.session_id
                manager = None
            else:
                from drex_agent_firewall.sandbox.manager import SandboxManager
                manager = SandboxManager("bubblewrap", str(private / "history.db"))
                sid = manager.create_session(str(workspace), agent_type="generic", network_mode="none").session_id
                backend = manager.backend
                repo = manager.repository
                path = Path(manager.db_path)
            repo.record_sandbox_session("old", "fixture", str(workspace), "none")
            old = workspace / "old.db"
            backup = sqlite3.connect(old)
            repo.conn.backup(backup)
            backup.close()
            repo.record_sandbox_session("new", "fixture", str(workspace), "none")
            with repo.conn:
                repo.conn.execute("INSERT INTO audit_actions(action_id,trace_id,timestamp,agent,tool,operation,decision_type,final_decision,allowed,hard_policy_triggered) VALUES('block','trace',1,'fixture','shell','execute','HARD_INVARIANT','BLOCK',0,1)")
            if closed:
                repo.conn.close()
            guest_db = "/workspace/.drex_firewall.db" if mode == "before" else str(path)
            res = backend.exec(sid, ["python3", "-c", native_code(attack, guest_db, "/workspace/old.db", "/workspace/replacement")])
            live_error = None
            if not closed:
                try:
                    repo.record_sandbox_session("subsequent", "fixture", str(workspace), "none")
                except Exception as exc:
                    live_error = type(exc).__name__
                repo.conn.close()
            reopen_error = None
            try:
                later = ActionRepository(str(path))
                new = later.get_sandbox_session("new")
                block = later.get_action("block")
                intact = new is not None and new["status"] != "FORGED" and block is not None and block["final_decision"] == "BLOCK" and block["timestamp"] == 1
                later.conn.close()
            except Exception as exc:
                reopen_error = type(exc).__name__
                intact = False
            results.append({"attack": attack + ("_closed" if closed else "_live"), "precondition": "native Python inside real Bubblewrap; writer closed" if closed else "native Python inside real Bubblewrap; live writer", "result": "native mutation succeeded" if res.returncode == 0 else "native operation denied", "native_returncode": res.returncode, "audit_history_changed": not intact, "detected": bool(live_error or reopen_error), "live_error": live_error, "reopen_error": reopen_error, "blocked": res.returncode != 0, "action_fails_closed": "N/A: native tamper action is not MCP-mediated", "security_impact": "committed history lost/forged" if not intact else "committed fixture intact"})
            backend.destroy(sid)
            if manager:
                manager._remove_mcp_config(sid)
                manager._remove_audit_broker(sid)
    return results


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=["before", "after"])
    args = parser.parse_args()
    print(json.dumps(run(args.mode), indent=2))
