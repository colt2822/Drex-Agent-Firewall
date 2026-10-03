"""Disposable native SQLite attacks; never opens a production database."""
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tempfile

from drex_agent_firewall.persistence.repository import ActionRepository


ATTACKS = {
    "unlink": "p.unlink()",
    "zero_truncate": "p.write_bytes(b'')",
    "partial_truncate": "os.truncate(p, 100)",
    "unlink_recreate": "p.unlink(); p.write_bytes(b'')",
    "rename_empty": "q.write_bytes(b''); os.replace(q,p)",
    "valid_empty": "c=sqlite3.connect(q); c.execute('CREATE TABLE empty(x)'); c.close(); os.replace(q,p)",
    "rollback": "shutil.copyfile(old,q); os.replace(q,p)",
    "delete_rows": "c=sqlite3.connect(p); c.execute('DELETE FROM sandbox_sessions'); c.commit()",
    "update_rows": "c=sqlite3.connect(p); c.execute(\"UPDATE sandbox_sessions SET status='FORGED', created_at=0\"); c.commit()",
    "update_decision_result": "c=sqlite3.connect(p); c.execute(\"UPDATE audit_actions SET final_decision='ALLOW',allowed=1,execution_result='FORGED',timestamp=0\"); c.commit()",
    "delete_block": "c=sqlite3.connect(p); c.execute(\"DELETE FROM audit_actions WHERE final_decision='BLOCK'\"); c.commit()",
    "wal_delete": "Path(str(p)+'-wal').unlink()",
    "wal_truncate": "Path(str(p)+'-wal').write_bytes(b'')",
    "wal_replace": "q.write_bytes(b''); os.replace(q,str(p)+'-wal')",
    "shm_remove": "Path(str(p)+'-shm').unlink()",
    "db_symlink": "p.unlink(); p.symlink_to(old)",
    "parent_symlink": "p.parent.rename(str(p.parent)+'-moved'); p.parent.symlink_to(old.parent)",
    "directory_replace": "p.unlink(); p.mkdir()",
    "unwritable": "os.chmod(p,0)",
    "rename_race": "from concurrent.futures import ThreadPoolExecutor; q.write_bytes(b''); pool=ThreadPoolExecutor(max_workers=1); pool.submit(os.replace,q,p).result(); pool.shutdown()",
    "inode_replace": "shutil.copyfile(old,q); os.replace(q,p)",
}


def native_code(attack, path, old, replacement):
    return "\n".join([
        "import os,sqlite3,shutil", "from pathlib import Path",
        f"p=Path({str(path)!r}); old=Path({str(old)!r}); q=Path({str(replacement)!r})",
        ATTACKS[attack],
    ])


def run_before():
    results = []
    for attack in ATTACKS:
        with tempfile.TemporaryDirectory(prefix="drex-rt03-before-") as root:
            root = Path(root)
            ws = root / "workspace"
            ws.mkdir()
            path = ws / ".drex_firewall.db"
            repo = ActionRepository(str(path))
            repo.record_sandbox_session("old", "fixture", str(ws), "none")
            old = root / "old.db"
            backup = sqlite3.connect(old)
            repo.conn.backup(backup)
            backup.close()
            repo.record_sandbox_session("new", "fixture", str(ws), "none")
            # A real committed BLOCK row, not an inferred replay result.
            with repo.conn:
                repo.conn.execute("INSERT INTO audit_actions(action_id,trace_id,timestamp,agent,tool,operation,decision_type,final_decision,allowed,hard_policy_triggered) VALUES('block','trace',1,'fixture','shell','execute','HARD_INVARIANT','BLOCK',0,1)")
            proc = subprocess.run([sys.executable, "-c", native_code(attack, path, old, root / "replacement")], capture_output=True, text=True)
            live_error = None
            try:
                repo.record_sandbox_session("subsequent", "fixture", str(ws), "none")
            except Exception as exc:
                live_error = type(exc).__name__
            repo.conn.close()
            reopen_error = None
            try:
                later = ActionRepository(str(path))
                intact = later.get_sandbox_session("new") is not None and later.get_action("block") is not None
                forged = (later.get_sandbox_session("new") or {}).get("status") == "FORGED"
                later.conn.close()
                intact = intact and not forged
            except Exception as exc:
                reopen_error = type(exc).__name__
                intact = False
            results.append({"attack": attack, "precondition": "native process shares writer UID and writable workspace; SQLite connection initially open", "native_returncode": proc.returncode, "audit_history_changed": not intact, "detected": bool(live_error or reopen_error), "live_error": live_error, "reopen_error": reopen_error, "action_fails_closed": "see adapter persistence-error regression; native execution unmediated", "security_impact": "history lost/forged" if not intact else "sidecar/path tamper possible; committed fixture survived"})
    return results


if __name__ == "__main__":
    print(json.dumps(run_before(), indent=2))
