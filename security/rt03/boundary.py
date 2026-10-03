"""Disposable before/after path ownership and native visibility measurements."""
import json
import os
from pathlib import Path
import stat
import tempfile

from drex_agent_firewall.persistence.repository import ActionRepository
from drex_agent_firewall.sandbox.manager import SandboxManager


def metadata(path):
    info = os.stat(path)
    return {"path": str(path), "uid": info.st_uid, "mode": oct(stat.S_IMODE(info.st_mode))}


if __name__ == "__main__":
    with tempfile.TemporaryDirectory(prefix="drex-rt03-boundary-") as root:
        root = Path(root)
        workspace = root / "workspace"
        workspace.mkdir()
        legacy = ActionRepository(str(workspace / ".drex_firewall.db"))
        before = {"db": metadata(legacy.db_path), "parent": metadata(workspace), "wal": metadata(legacy.db_path + "-wal"), "shm": metadata(legacy.db_path + "-shm")}
        legacy.conn.close()
        private = root / "private"
        private.mkdir(mode=0o700)
        manager = SandboxManager("bubblewrap", str(private / "history.db"))
        sid = manager.create_session(str(workspace), agent_type="generic", network_mode="none").session_id
        after = {"db": metadata(manager.db_path), "parent": metadata(private), "wal": metadata(manager.db_path + "-wal"), "shm": metadata(manager.db_path + "-shm"), "socket": metadata(manager._audit_brokers[sid].socket_path)}
        probe = "import os,json; p=" + repr(manager.db_path) + "; print(json.dumps({'uid':os.getuid(),'db_visible':os.path.exists(p),'wal_visible':os.path.exists(p+'-wal'),'shm_visible':os.path.exists(p+'-shm'),'db_writable':os.access(p,os.W_OK),'parent_visible':os.path.exists(os.path.dirname(p))}))"
        result = manager.exec_command(sid, ["python3", "-c", probe])
        assert result.returncode == 0, result.stderr
        after["native_guest"] = json.loads(result.stdout)
        after["sqlite_synchronous"] = manager.repository.conn.execute("PRAGMA synchronous").fetchone()[0]
        manager.destroy_session(sid)
        after["history_survives_destroy"] = Path(manager.db_path).exists()
        manager.repository.conn.close()
        print(json.dumps({"host_writer": {"uid": os.getuid(), "process": "host SandboxManager Python process, per-session serial writer thread", "pid_during_fixture": os.getpid()}, "before": before, "after": after}, indent=2))
