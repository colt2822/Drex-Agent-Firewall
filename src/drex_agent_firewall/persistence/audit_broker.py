"""Host-only audit writer. The guest receives an append capability, never SQL.

The socket inode is the per-session capability. Its private parent and the
database directory must never be mounted into the guest. No TCP listener,
background queue, unbounded frame, or guest-selected storage destination exists.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import socket
import socketserver
import stat
import tempfile
import threading
import time

from drex_agent_firewall.persistence.repository import ActionRepository
from drex_agent_firewall.schemas.decision import FirewallDecision
from drex_agent_firewall.schemas.envelope import ActionEnvelope

MAX_FRAME = 131072
SESSION_BYTE_LIMIT = 16 * 1024 * 1024
TIMEOUT = 3.0
GUEST_SOCKET = "/run/drex-audit.sock"


def _typed_snapshot(value, redactor):
    """Scrub string values without destroying schema-defined boolean/enum fields."""
    if isinstance(value, str):
        return redactor.redact_text(value)
    if isinstance(value, dict):
        return {key: _typed_snapshot(item, redactor) for key, item in value.items()}
    if isinstance(value, list):
        return [_typed_snapshot(item, redactor) for item in value]
    return value


def private_database_path(db_path=None):
    """Resolve an operator path, refusing symlinks and non-private store parents.

    HOME is the trusted launcher environment, never the guest environment.
    Explicit paths are host operator inputs, not accepted on the IPC protocol.
    """
    path = Path(db_path).absolute() if db_path else Path.home() / ".local/state/drex-agent-firewall/audit/history.db"
    for component in [path, *path.parents]:
        if component.is_symlink():
            raise ValueError("Audit path must not contain symlinks")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    parent = path.parent.stat()
    if parent.st_uid != os.getuid() or stat.S_IMODE(parent.st_mode) != 0o700:
        raise ValueError("Audit parent must be host-owned and mode 0700")
    if path.exists():
        info = path.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1:
            raise ValueError("Audit database must be a host-owned regular file without hardlinks")
    else:
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        os.close(fd)
    os.chmod(path, 0o600)
    return str(path)


def validate_audit_mounts(db_path, workspace, mounts, code_root=None):
    """Reject any mount overlapping the store, including read-only aliases."""
    store = Path(db_path).resolve().parent
    sources = [workspace, *(m.host_path for m in mounts)]
    if code_root:
        sources.append(code_root)
    for source in sources:
        source = Path(source).resolve()
        if source == store or source in store.parents or store in source.parents:
            raise ValueError("Audit store must not overlap any sandbox mount")


def _receive(sock):
    data = bytearray()
    deadline = time.monotonic() + TIMEOUT
    while len(data) <= MAX_FRAME:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("Audit frame deadline exceeded")
        sock.settimeout(remaining)
        chunk = sock.recv(min(4096, MAX_FRAME + 1 - len(data)))
        if not chunk:
            raise ValueError("Incomplete audit frame")
        data.extend(chunk)
        if b"\n" in data:
            line, _, remainder = data.partition(b"\n")
            if remainder or len(line) > MAX_FRAME:
                raise ValueError("Invalid audit frame")
            return json.loads(line)
    raise ValueError("Audit frame too large")


class _Writer(socketserver.UnixStreamServer):
    request_queue_size = 2

    def handle_error(self, request, client_address):
        # Never print untrusted frames or secret-bearing request diagnostics.
        pass


class _Handler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(TIMEOUT)
        try:
            response = self.server.broker.append(_receive(self.request))
            result = {"ok": True, "action_id": response}
        except Exception as exc:
            result = {"ok": False, "error": type(exc).__name__}
        try:
            self.request.sendall(json.dumps(result).encode() + b"\n")
        except OSError:
            pass


class AuditBroker:
    """One serial writer per session with bounded frames and durable budget.

    audit_events is authoritative history; audit_actions remains the compatible
    reporting projection. All IPC snapshots append; no IPC edits past events.
    """
    def __init__(self, repository: ActionRepository, session_id: str, agent_id: str):
        self.repository = repository
        self.session_id = session_id
        self.agent_id = agent_id
        self.private_dir = tempfile.mkdtemp(prefix="drex-audit-ipc-")
        os.chmod(self.private_dir, 0o700)
        self.socket_path = os.path.join(self.private_dir, "writer.sock")
        self.server = _Writer(self.socket_path, _Handler)
        self.server.broker = self
        os.chmod(self.socket_path, 0o600)
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        self.thread.start()

    def append(self, request):
        if not isinstance(request, dict):
            raise ValueError("Invalid audit request")
        kind = request.get("kind")
        repo = self.repository
        if kind == "decision":
            envelope = ActionEnvelope.model_validate(request["envelope"])
            decision = FirewallDecision.model_validate(request["decision"])
            if decision.action_id != envelope.action_id:
                raise ValueError("Mismatched action identity")
            envelope.session_id = self.session_id
            envelope.sandbox_session_id = self.session_id
            envelope.agent_id = self.agent_id
            action_id = decision.action_id
            payload = _typed_snapshot({"envelope": envelope.model_dump(mode="json"), "decision": decision.model_dump(mode="json")}, repo.redactor)
            # Free-form agent maps still require sensitive-key redaction. Known
            # schema fields such as no_secret_access/credential_risk retain type.
            for key in ("arguments", "metadata", "previous_actions"):
                payload["envelope"][key] = repo.redactor.sanitize(payload["envelope"][key])
            evaluation = payload["decision"].get("drex_evaluation")
            if evaluation and evaluation.get("raw_response"):
                evaluation["raw_response"] = repo.redactor.sanitize(evaluation["raw_response"])
        elif kind == "execution":
            action_id = request["action_id"]
            if not isinstance(action_id, str) or type(request.get("executed")) is not bool:
                raise ValueError("Invalid execution event")
            payload = repo.redactor.sanitize({key: request.get(key) for key in ("action_id", "executed", "result", "error_class")})
        else:
            raise ValueError("Only decision/execution appends are supported")
        encoded = json.dumps(payload, separators=(",", ":"))
        if len(encoded.encode()) > MAX_FRAME:
            raise ValueError("Audit snapshot too large")
        # Serialize all brokers sharing this repository. Budget/duplicate checks
        # and immutable snapshot insertion happen in the same transaction.
        with repo._lock:
            with repo.conn:
                used = repo.conn.execute("SELECT COALESCE(SUM(length(CAST(payload AS BLOB))),0) FROM audit_events WHERE session_id=?", (self.session_id,)).fetchone()[0]
                if used + len(encoded.encode()) > SESSION_BYTE_LIMIT:
                    raise ValueError("Session audit budget exhausted")
                if kind == "decision":
                    if repo.conn.execute("SELECT 1 FROM audit_actions WHERE action_id=?", (action_id,)).fetchone():
                        raise ValueError("Action already committed")
                else:
                    if not repo.conn.execute("SELECT 1 FROM audit_events WHERE session_id=? AND action_id=? AND kind='decision'", (self.session_id, action_id)).fetchone():
                        raise ValueError("Unknown session action")
                repo.conn.execute("INSERT INTO audit_events(session_id,action_id,kind,payload) VALUES(?,?,?,?)", (self.session_id, action_id, kind, encoded))
        # No success acknowledgement until both durable event and projection
        # writes succeed. A failed projection cannot erase the committed event.
        if kind == "decision":
            repo.record_decision(envelope, decision)
        else:
            repo.record_execution(action_id, bool(payload["executed"]), payload["result"], payload["error_class"])
        return action_id

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=TIMEOUT + 1)
        os.unlink(self.socket_path)
        os.rmdir(self.private_dir)


class AuditClient:
    """Guest repository adapter. Never falls back to a guest-selected database."""
    def __init__(self, socket_path=GUEST_SOCKET):
        self.socket_path = socket_path

    def _append(self, request):
        frame = json.dumps(request, separators=(",", ":")).encode()
        if len(frame) > MAX_FRAME:
            raise RuntimeError("Audit frame too large")
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(TIMEOUT)
            sock.connect(self.socket_path)
            sock.sendall(frame + b"\n")
            response = _receive(sock)
        if not response.get("ok"):
            raise RuntimeError("Host audit persistence rejected request")

    def record_decision(self, envelope, decision):
        self._append({"kind": "decision", "envelope": envelope.model_dump(mode="json"), "decision": decision.model_dump(mode="json")})

    def record_execution(self, action_id, executed, result=None, error_class=None):
        self._append({"kind": "execution", "action_id": action_id, "executed": executed, "result": result, "error_class": error_class})
