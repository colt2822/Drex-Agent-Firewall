"""Disposable release persistence-suppression and session-reuse observations."""
import json
import os
from pathlib import Path
import tempfile

from drex_agent_firewall.mcp.server import DrexMcpServer
from drex_agent_firewall.schemas.config import FirewallConfig


if __name__ == "__main__":
    results = []
    for case in ("readonly_connection", "unwritable_path", "incompatible_directory", "valid_empty_session_reuse"):
        with tempfile.TemporaryDirectory(prefix="drex-rt03-suppress-") as root:
            workspace = Path(root)
            db = workspace / ".drex_firewall.db"
            target = workspace / "protected-effect"
            config = FirewallConfig.from_pack("safe-local-coding")
            config.database_path = str(db)
            config.filesystem.allowed_roots = [str(workspace)]
            error = None
            allowed = None
            first = DrexMcpServer(str(workspace), config=config)
            first.repository.record_sandbox_session("committed", "fixture", str(workspace), "none")
            if case == "readonly_connection":
                first.repository.conn.execute("PRAGMA query_only=ON")
                server = first
            else:
                first.repository.conn.close()
                if case == "unwritable_path":
                    os.chmod(db, 0)
                elif case == "incompatible_directory":
                    db.unlink()
                    db.mkdir()
                else:
                    db.write_bytes(b"")
                try:
                    server = DrexMcpServer(str(workspace), config=config)
                except Exception as exc:
                    error = type(exc).__name__
                    server = None
            history_changed = case in ("incompatible_directory", "valid_empty_session_reuse")
            if server:
                try:
                    history_changed = server.repository.get_sandbox_session("committed") is None
                    result = server.fs_adapter.create_file(str(target), "safe fixture", cwd=str(workspace))
                    allowed = result.allowed
                except Exception as exc:
                    error = type(exc).__name__
                server.repository.conn.close()
            results.append({"attack": case, "precondition": "disposable standalone release MCP store; same UID native path or SQLite failure", "result": error or ("allowed" if allowed else "blocked"), "audit_history_changed": history_changed, "detected": bool(error), "action_fails_closed": not target.exists(), "protected_effect_created": target.exists(), "security_impact": "fresh session silently accepts missing history" if case == "valid_empty_session_reuse" else "persistence error prevents effect; history may already be damaged"})
    print(json.dumps(results, indent=2))
