"""Native filesystem and append-capability attacks against disposable stores."""
import json
import os
from pathlib import Path
import sqlite3
import sys

import pytest

from drex_agent_firewall.mcp.server import DrexMcpServer
from drex_agent_firewall.persistence.audit_broker import AuditBroker, AuditClient, GUEST_SOCKET, private_database_path
from drex_agent_firewall.persistence.repository import ActionRepository
from drex_agent_firewall.sandbox.manager import SandboxManager
from drex_agent_firewall.schemas.config import FirewallConfig, SandboxMount
from drex_agent_firewall.schemas.envelope import ActionEnvelope
from drex_agent_firewall.schemas.decision import FirewallDecision


@pytest.fixture
def session(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    manager = SandboxManager("bubblewrap", str(private / "history.db"))
    info = manager.create_session(str(workspace), agent_type="generic", network_mode="none")
    yield manager, info.session_id, workspace
    manager.destroy_session(info.session_id)
    manager.repository.conn.close()


def mcp_call(manager, sid, request, env=None):
    return manager.exec_command(sid, ["python3", "-m", "drex_agent_firewall.mcp.server", "--workspace", "/workspace", "--host-audit", "--session-id", "attacker-selected"], input=json.dumps(request) + "\n", env=env)


def seed(manager, sid):
    result = mcp_call(manager, sid, {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "write_file", "arguments": {"path": "legitimate.txt", "content": "task intact"}}})
    assert result.returncode == 0, result.stderr
    assert not json.loads(result.stdout).get("error"), result.stdout
    actions = manager.repository.get_actions_for_sandbox(sid)
    assert len(actions) == 1
    assert actions[0]["session_id"] == sid
    assert actions[0]["executed"] == 1
    return actions[0]


@pytest.mark.parametrize("attack", ["read", "unlink", "truncate", "replace", "sql_delete", "sql_update", "wal", "shm", "parent", "symlink"])
def test_native_agent_cannot_touch_authoritative_history(session, attack):
    manager, sid, workspace = session
    action = seed(manager, sid)
    db = manager.db_path
    statements = {
        "read": "open(p,'rb').read()",
        "unlink": "os.unlink(p)",
        "truncate": "open(p,'wb').close()",
        "replace": "os.replace('/workspace/replacement',p)",
        "sql_delete": "c=sqlite3.connect(p); c.execute('DELETE FROM audit_actions'); c.commit()",
        "sql_update": "c=sqlite3.connect(p); c.execute(\"UPDATE audit_actions SET final_decision='FORGED'\"); c.commit()",
        "wal": "open(p+'-wal','wb').close()",
        "shm": "os.unlink(p+'-shm')",
        "parent": "os.rename(os.path.dirname(p),'/workspace/stolen')",
        "symlink": "os.symlink(p,'/workspace/link'); open('/workspace/link','wb').close()",
    }
    (workspace / "replacement").write_bytes(b"replacement")
    res = manager.exec_command(sid, ["python3", "-c", "import os,sqlite3\np=" + repr(db) + "\n" + statements[attack]])
    assert res.returncode != 0, res.stdout
    assert manager.repository.get_action(action["action_id"]) == action
    assert (workspace / "legitimate.txt").read_text() == "task intact"


def test_workspace_and_environment_redirect_only_decoys(session):
    manager, sid, workspace = session
    outside = workspace / "decoy.db"
    (workspace / ".drex_firewall.db").symlink_to(outside)
    result = mcp_call(manager, sid, {"id": 1, "method": "tools/call", "params": {"name": "write_file", "arguments": {"path": "good.txt", "content": "ok"}}}, {"DREX_DATABASE_PATH": "/workspace/decoy.db", "DREX_AUDIT_PATH": "/workspace/decoy.db"})
    assert not json.loads(result.stdout).get("error"), result.stdout
    assert not outside.exists()
    assert len(manager.repository.get_actions_for_sandbox(sid)) == 1
    # An attacker can start a different MCP server/config writing a decoy, but
    # has no authority to redirect/delete history in the fixed host broker.
    (workspace / "attacker-mcp.json").write_text('{"env":{"DREX_DATABASE_PATH":"/workspace/decoy.db"}}')
    res = manager.exec_command(sid, ["python3", "-c", "import sqlite3; c=sqlite3.connect('/workspace/decoy.db'); c.execute('CREATE TABLE fake(x)'); c.commit()"])
    assert res.returncode == 0
    assert len(manager.repository.get_actions_for_sandbox(sid)) == 1


def test_destroy_retains_history_and_authorized_inspection(session):
    manager, sid, workspace = session
    action = seed(manager, sid)
    assert manager.destroy_session(sid)
    assert Path(manager.db_path).exists()
    later = ActionRepository(manager.db_path)
    assert later.get_action(action["action_id"]) == action
    assert later.get_sandbox_session(sid)["status"] == "DESTROYED"
    assert later.conn.execute("SELECT count(*) FROM audit_events WHERE session_id=?", (sid,)).fetchone()[0] == 2
    later.conn.close()
    from drex_agent_firewall import DrexFirewall
    from drex_agent_firewall.server.app import create_app
    from fastapi.testclient import TestClient
    from click.testing import CliRunner
    from drex_agent_firewall.cli.main import cli
    fw = DrexFirewall(database_path=manager.db_path)
    app = create_app(firewall=fw)
    api = TestClient(app, headers={"Authorization": f"Bearer {app.state.api_token}"})
    assert api.get(f"/v1/actions/{action['action_id']}").status_code == 200
    inspected = CliRunner().invoke(cli, ["sandbox", "inspect", sid, "--audit-db", manager.db_path])
    assert inspected.exit_code == 0, inspected.output
    assert sid in inspected.output
    fw.repository.conn.close()
    with pytest.raises(ValueError, match="already exists"):
        manager.create_session(str(workspace), session_id=sid)


def test_persistence_failure_blocks_protected_write(session):
    manager, sid, workspace = session
    manager.repository.conn.execute("PRAGMA query_only=ON")
    try:
        result = manager.backend.exec(sid, ["python3", "-m", "drex_agent_firewall.mcp.server", "--workspace", "/workspace", "--host-audit"], input=json.dumps({"id": 1, "method": "tools/call", "params": {"name": "write_file", "arguments": {"path": "must-not-exist", "content": "unsafe"}}}) + "\n")
        assert result.returncode == 0, result.stderr
        assert not (workspace / "must-not-exist").exists()
        assert json.loads(result.stdout).get("error") or json.loads(result.stdout)["result"]["isError"]
    finally:
        manager.repository.conn.execute("PRAGMA query_only=OFF")


@pytest.mark.parametrize("mount_mode", ["ro", "rw"])
def test_mount_aliases_of_private_store_are_rejected(tmp_path, mount_mode):
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    manager = SandboxManager("none", str(private / "audit.db"))
    cfg = FirewallConfig.from_pack("safe-local-coding")
    cfg.sandbox.extra_mounts = [SandboxMount(host_path=str(tmp_path), container_path="/host-alias", mode=mount_mode)]
    with pytest.raises(ValueError, match="overlap"):
        manager.create_session(str(workspace), config=cfg)
    with pytest.raises(ValueError, match="overlap"):
        manager.create_session(str(private))
    manager.repository.conn.close()


def test_no_secret_mounts_or_database_mount(session):
    manager, sid, workspace = session
    data = manager.backend._sessions[sid]
    args = manager.backend._build_bwrap_args(data["spec"], data)
    assert manager.db_path not in args
    assert str(Path(manager.db_path).parent) not in args
    assert GUEST_SOCKET in args
    for secret in (".ssh", ".aws", ".codex/auth.json", ".claude/.credentials.json"):
        assert not any(secret in arg for arg in args)


def test_no_isolation_same_uid_is_explicitly_tamperable(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    manager = SandboxManager("none", str(private / "history.db"))
    with pytest.raises(RuntimeError, match="NoIsolation cannot protect"):
        manager.create_session(str(workspace), agent_type="generic")
    assert manager.backend._sessions == {}
    # Raw backend remains explicitly unsafe development-only execution; chmod
    # cannot distinguish the trusted owner from an unrestricted same-UID child.
    from drex_agent_firewall.sandbox.backend import SandboxSpec
    spec = SandboxSpec(session_id="raw-unsafe", workspace_path=str(workspace))
    manager.backend.prepare(spec)
    manager.backend.launch(spec)
    res = manager.backend.exec(spec.session_id, [sys.executable, "-c", f"import os; os.unlink({manager.db_path!r})"])
    assert res.returncode == 0
    assert not Path(manager.db_path).exists()
    # Do not let session metadata error hide the demonstrated unlink.
    manager.backend.destroy(spec.session_id)
    manager.repository.conn.close()


def test_private_path_rejects_symlinks_and_nonprivate_parent(tmp_path):
    other = tmp_path / "other"
    other.mkdir(mode=0o755)
    with pytest.raises(ValueError):
        private_database_path(other / "db")
    alias = tmp_path / "alias"
    alias.symlink_to(other)
    with pytest.raises(ValueError):
        private_database_path(alias / "db")


def test_broker_rejects_history_edits_and_cross_session_result(tmp_path):
    repo = ActionRepository(private_database_path(tmp_path / "db"))
    broker = AuditBroker(repo, "host-session", "host-agent")
    client = AuditClient(broker.socket_path)
    server = DrexMcpServer(str(tmp_path), config=FirewallConfig.from_pack("safe-local-coding"), host_audit=True)
    server.fs_adapter.repository = client
    try:
        server.fs_adapter.list_dir(str(tmp_path), cwd=str(tmp_path))
        row = repo.list_actions()[0]
        snapshots = repo.conn.execute("SELECT payload FROM audit_events ORDER BY sequence").fetchall()
        for request in ({"kind": "sql", "sql": "DELETE FROM audit_events"}, {"kind": "execution", "action_id": row["action_id"], "executed": False}, {"kind": "execution", "action_id": "unknown", "executed": False}):
            with pytest.raises(RuntimeError):
                client._append(request)
        original = json.loads(snapshots[0][0])
        assert isinstance(original["decision"]["constraints"]["no_secret_access"], bool)
        with pytest.raises(RuntimeError):
            client.record_decision(ActionEnvelope.model_validate(original["envelope"]), FirewallDecision.model_validate(original["decision"]))
        assert repo.conn.execute("SELECT payload FROM audit_events ORDER BY sequence").fetchall() == snapshots
        assert repo.get_action(row["action_id"]) == row
        assert row["sandbox_session_id"] == "host-session"
    finally:
        broker.close()
        repo.conn.close()


def test_broker_budget_and_missing_socket_fail_closed(tmp_path, monkeypatch):
    import drex_agent_firewall.persistence.audit_broker as audit
    repo = ActionRepository(private_database_path(tmp_path / "db"))
    broker = AuditBroker(repo, "budget-session", "agent")
    server = DrexMcpServer(str(tmp_path), config=FirewallConfig.from_pack("safe-local-coding"), host_audit=True)
    server.fs_adapter.repository = AuditClient(broker.socket_path)
    try:
        monkeypatch.setattr(audit, "SESSION_BYTE_LIMIT", 1)
        with pytest.raises(RuntimeError):
            server.fs_adapter.create_file(str(tmp_path / "budget-denied"), "unsafe", cwd=str(tmp_path))
        assert not (tmp_path / "budget-denied").exists()
        assert repo.conn.execute("SELECT count(*) FROM audit_events").fetchone()[0] == 0
        with pytest.raises(RuntimeError):
            AuditClient(broker.socket_path)._append({"kind": "execution", "result": "x" * (audit.MAX_FRAME + 1)})
    finally:
        broker.close()
        repo.conn.close()
    # Missing IPC has no database fallback and cannot execute a protected write.
    with pytest.raises(OSError):
        server.fs_adapter.create_file(str(tmp_path / "socket-denied"), "unsafe", cwd=str(tmp_path))
    assert not (tmp_path / "socket-denied").exists()


def test_native_broker_forgery_cannot_edit_committed_events(session):
    manager, sid, workspace = session
    action = seed(manager, sid)
    before = manager.repository.conn.execute("SELECT payload FROM audit_events WHERE session_id=? ORDER BY sequence", (sid,)).fetchall()
    script = "\n".join([
        "import json,socket", f"requests={repr([{'kind': 'sql', 'sql': 'DELETE FROM audit_events'}, {'kind': 'execution', 'action_id': action['action_id'], 'executed': False}])}",
        "for request in requests:",
        " s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)",
        f" s.connect({GUEST_SOCKET!r})",
        " s.sendall(json.dumps(request).encode()+b'\\n')",
        " response=json.loads(s.recv(4096))",
        " assert response['ok'] is False, response",
        " s.close()",
    ])
    result = manager.exec_command(sid, ["python3", "-c", script])
    assert result.returncode == 0, result.stderr
    assert manager.repository.conn.execute("SELECT payload FROM audit_events WHERE session_id=? ORDER BY sequence", (sid,)).fetchall() == before
    assert manager.repository.get_action(action["action_id"]) == action


def test_sqlite_full_before_action_fails_closed(session):
    manager, sid, workspace = session
    conn = manager.repository.conn
    pages = conn.execute("PRAGMA page_count").fetchone()[0]
    conn.execute(f"PRAGMA max_page_count={pages}")
    # Force SQLITE_FULL without filling the host disk. A decision larger than
    # available free pages must not reach the protected filesystem effect.
    result = manager.backend.exec(sid, ["python3", "-m", "drex_agent_firewall.mcp.server", "--workspace", "/workspace", "--host-audit"], input=json.dumps({"id": 1, "method": "tools/call", "params": {"name": "write_file", "arguments": {"path": "x" * 32000, "content": "unsafe"}}}) + "\n")
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout).get("error") or json.loads(result.stdout)["result"]["isError"]
    assert list(workspace.iterdir()) == []
    assert conn.execute("SELECT count(*) FROM audit_events").fetchone()[0] == 0
    conn.execute("PRAGMA max_page_count=1073741823")


def test_slow_sender_cannot_extend_frame_deadline(tmp_path, monkeypatch):
    import socket
    import threading
    import time
    import drex_agent_firewall.persistence.audit_broker as audit
    monkeypatch.setattr(audit, "TIMEOUT", 0.15)
    repo = ActionRepository(private_database_path(tmp_path / "db"))
    broker = AuditBroker(repo, "slow-frame", "agent")
    stop = threading.Event()
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect(broker.socket_path)
    sock.settimeout(1)
    def drip():
        while not stop.wait(0.02):
            try:
                sock.sendall(b" ")
            except OSError:
                return
    worker = threading.Thread(target=drip)
    worker.start()
    started = time.monotonic()
    try:
        response = json.loads(sock.recv(4096))
        assert response == {"ok": False, "error": "TimeoutError"}
        assert time.monotonic() - started < 1
        assert repo.conn.execute("SELECT count(*) FROM audit_events").fetchone()[0] == 0
    finally:
        stop.set()
        worker.join(timeout=1)
        sock.close()
        broker.close()
        repo.conn.close()
