"""Sandbox Manager orchestrating isolated agent runtime lifecycles and Drex integration."""

from __future__ import annotations

import json
import logging
import os
import tempfile
import time
import uuid
from typing import Any, Dict, List, Optional

from drex_agent_firewall.persistence.repository import ActionRepository
from drex_agent_firewall.persistence.audit_broker import AuditBroker, GUEST_SOCKET, private_database_path, validate_audit_mounts
from drex_agent_firewall.policy.packs import get_policy_pack
from drex_agent_firewall.sandbox.backend import (
    IsolationBackend,
    SandboxLimits,
    SandboxResult,
    SandboxSessionInfo,
    SandboxSpec,
    SandboxStatus,
)
from drex_agent_firewall.sandbox.factory import get_isolation_backend
from drex_agent_firewall.sandbox.python_runtime import python_dependency_mounts
from drex_agent_firewall.schemas.config import FirewallConfig, SandboxMount

logger = logging.getLogger(__name__)


class SandboxManager:
    """Manages the full lifecycle of an isolated agent runtime session.
    
    Responsibilities:
    1. Resolve configuration and policy packs
    2. Instantiate and validate isolation backend (fail-closed if unavailable)
    3. Generate MCP configuration for firewall-mediated tool execution
    4. Confine agent within outer OS sandbox boundary
    5. Maintain correlated audit trace in SQLite repository
    6. Ensure clean teardown without corrupting user workspace
    """

    def __init__(
        self,
        backend_type: str = "auto",
        db_path: Optional[str] = None,
        repository: Optional[ActionRepository] = None,
    ):
        self.backend_type = backend_type
        self.db_path = private_database_path(repository.db_path if repository else db_path)
        self.repository = repository or ActionRepository(db_path=self.db_path)
        self.backend: IsolationBackend = get_isolation_backend(backend_type)
        self._mcp_config_paths: Dict[str, str] = {}
        self._audit_brokers: Dict[str, AuditBroker] = {}

    def create_session(
        self,
        workspace_path: str,
        policy_pack: str = "safe-local-coding",
        agent_type: str = "claude",
        network_mode: Optional[str] = None,
        workspace_mode: str = "rw",
        session_id: Optional[str] = None,
        limits: Optional[SandboxLimits] = None,
        config: Optional[FirewallConfig] = None,
        env_overrides: Optional[Dict[str, str]] = None,
    ) -> SandboxSessionInfo:
        """Create and launch a new isolated sandbox session."""
        sid = session_id or f"sbx-{uuid.uuid4().hex[:10]}"
        abs_workspace = os.path.abspath(workspace_path)

        if not os.path.exists(abs_workspace):
            raise FileNotFoundError(f"Target workspace does not exist: {abs_workspace}")

        # Load policy pack configuration
        cfg = config or get_policy_pack(policy_pack)
        net_mode = network_mode or cfg.sandbox.network_mode
        lims = limits or cfg.sandbox.limits

        if self.repository.get_sandbox_session(sid):
            raise ValueError("Sandbox session identity already exists; refusing history replacement")
        code_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
        runtime_mounts = python_dependency_mounts() if self.backend.name == "bubblewrap" else []
        validate_audit_mounts(self.db_path, abs_workspace, [*cfg.sandbox.extra_mounts, *runtime_mounts], code_root)
        if self.backend.name == "none":
            raise RuntimeError(
                "FAIL-CLOSED: NoIsolation cannot protect host audit history from same-UID native execution; "
                "audited sessions require an isolation backend"
            )
        broker = AuditBroker(self.repository, sid, f"{agent_type}-sandboxed")
        self._audit_brokers[sid] = broker
        try:
            validate_audit_mounts(broker.socket_path, abs_workspace, cfg.sandbox.extra_mounts, code_root)
        except Exception:
            self._remove_audit_broker(sid)
            raise

        if net_mode == "controlled-online" and self.backend.name != "bubblewrap":
            self._remove_audit_broker(sid)
            raise RuntimeError(
                "FAIL-CLOSED: controlled-online networking is implemented only by the Bubblewrap backend"
            )

        # Keep the generated MCP configuration outside agent-writable paths.
        try:
            mcp_cfg_path = self._generate_mcp_config(abs_workspace, policy_pack, sid, agent_type)
        except Exception:
            self._remove_audit_broker(sid)
            raise
        self._mcp_config_paths[sid] = mcp_cfg_path

        spec = SandboxSpec(
            session_id=sid,
            workspace_path=abs_workspace,
            policy_pack=policy_pack,
            agent_type=agent_type,
            config=cfg,
            network_mode=net_mode,
            workspace_mode=workspace_mode,
            limits=lims,
            mcp_config_path=mcp_cfg_path,
            drex_db_path=os.path.abspath(self.db_path),
            env_overrides=env_overrides or {},
            extra_mounts=[
                *cfg.sandbox.extra_mounts,
                *runtime_mounts,
                SandboxMount(
                    host_path=mcp_cfg_path,
                    container_path="/tmp/.drex_mcp_config.json",
                    mode="ro",
                ),
                SandboxMount(host_path=broker.socket_path, container_path=GUEST_SOCKET, mode="ro"),
            ],
        )

        try:
            # Prepare backend
            self.backend.prepare(spec)

            # Record session initiation in repository
            self.repository.record_sandbox_session(
                session_id=sid,
                runtime_backend=self.backend.name,
                workspace_path=abs_workspace,
                network_mode=net_mode,
                status="RUNNING",
                agent=agent_type,
                policy_pack=policy_pack,
                runtime_id=f"{self.backend.name}-{sid}",
                metadata={
                    "limits": lims.model_dump(),
                    "workspace_mode": workspace_mode,
                    "mcp_config_path": mcp_cfg_path,
                },
            )

            # Launch backend
            info = self.backend.launch(spec)
            return info

        except Exception as e:
            self.backend.destroy(sid)
            self._remove_audit_broker(sid)
            self._remove_mcp_config(sid)
            # Record failure in repository (fail-closed)
            self.repository.record_sandbox_session(
                session_id=sid,
                runtime_backend=self.backend.name,
                workspace_path=abs_workspace,
                network_mode=net_mode,
                status="FAILED",
                agent=agent_type,
                policy_pack=policy_pack,
                metadata={"error": str(e)},
            )
            raise RuntimeError(f"Sandbox session creation failed: {e}") from e

    def _generate_mcp_config(
        self,
        workspace_path: str,
        policy_pack: str,
        session_id: str,
        agent_type: str,
    ) -> str:
        """Create a private MCP config outside the agent-writable workspace."""
        mcp_cfg = {
            "mcpServers": {
                "drex_firewall": {
                    "command": "python3",
                    "args": [
                        "-m",
                        "drex_agent_firewall.mcp.server",
                        "--workspace",
                        "/workspace",
                        "--policy",
                        policy_pack,
                        "--session-id",
                        session_id,
                        "--agent-id",
                        f"{agent_type}-sandboxed",
                        "--host-audit",
                    ],
                    "env": {},
                }
            }
        }
        private_dir = tempfile.mkdtemp(prefix="drex-mcp-config-")
        os.chmod(private_dir, 0o700)
        fd, cfg_file = tempfile.mkstemp(
            prefix=".drex_mcp_config-",
            suffix=".json",
            dir=private_dir,
        )
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(mcp_cfg, f, indent=2)
                f.flush()
                os.fsync(f.fileno())
        except Exception:
            try:
                os.unlink(cfg_file)
            except OSError:
                pass
            try:
                os.rmdir(private_dir)
            except OSError:
                pass
            raise
        return cfg_file

    def _remove_mcp_config(self, session_id: str) -> None:
        path = self._mcp_config_paths.pop(session_id, None)
        if path:
            try:
                os.unlink(path)
            except FileNotFoundError:
                pass
            try:
                os.rmdir(os.path.dirname(path))
            except OSError:
                pass

    def _remove_audit_broker(self, session_id: str) -> None:
        broker = self._audit_brokers.pop(session_id, None)
        if broker:
            broker.close()

    def run_agent(
        self,
        session_id: str,
        prompt: str,
        timeout: Optional[float] = None,
    ) -> SandboxResult:
        """Execute autonomous coding agent inside the isolated runtime."""
        info = self.backend.status(session_id)
        if info != SandboxStatus.RUNNING:
            raise RuntimeError(f"Sandbox session {session_id} is not running (status: {info})")

        # Resolve session details from repository
        sess_record = self.repository.get_sandbox_session(session_id)
        agent_type = sess_record.get("agent", "claude") if sess_record else "claude"

        # Determine agent command vector
        if agent_type in ("claude", "codex"):
            metadata = sess_record.get("metadata_json", {}) if sess_record else {}
            mcp_config_path = self._mcp_config_paths.get(session_id) or (
                metadata.get("mcp_config_path") if isinstance(metadata, dict) else None
            )
            if not mcp_config_path or not os.path.isfile(mcp_config_path):
                raise RuntimeError("Drex MCP configuration is missing; refusing to launch the agent without firewall tools")
            guest_mcp_config_path = "/tmp/.drex_mcp_config.json"
            network_mode = sess_record.get("network_mode", "firewall-only") if sess_record else "firewall-only"
            if network_mode != "controlled-online":
                raise RuntimeError(
                    f"Authenticated {agent_type} task requires explicit network_mode='controlled-online'; "
                    "network=none remains isolated and receives no runtime auth"
                )
            exec_agent = getattr(self.backend, "exec_agent", None)
            if exec_agent is None:
                raise RuntimeError("Controlled online agent execution is available only on the Bubblewrap backend")

            if agent_type == "claude":
                cmd = [
                    "/usr/bin/claude",
                    "-p",
                    prompt,
                    "--dangerously-skip-permissions",
                    "--mcp-config",
                    guest_mcp_config_path,
                    "--strict-mcp-config",
                ]
            else:
                mcp_server = self._load_mcp_server_config(mcp_config_path)
                cmd = [
                    "/usr/bin/codex",
                    "exec",
                    "--cd",
                    "/workspace",
                    "--ephemeral",
                    "--ignore-user-config",
                    # Nested bwrap fails under this host's outer user namespace:
                    # "No permissions to create new namespace". The outer
                    # Bubblewrap boundary remains active around this process.
                    "--dangerously-bypass-approvals-and-sandbox",
                    "-c",
                    f'mcp_servers.drex_firewall.command={json.dumps(mcp_server["command"])}',
                    "-c",
                    f'mcp_servers.drex_firewall.args={json.dumps(mcp_server["args"])}',
                    "-c",
                    f'mcp_servers.drex_firewall.env={self._toml_inline_table(mcp_server.get("env", {}))}',
                    prompt,
                ]
            return exec_agent(session_id, cmd, timeout=timeout)
        else:
            cmd = ["bash", "-c", prompt]
            res = self.exec_command(session_id, cmd, timeout=timeout)
            return res

    @staticmethod
    def _load_mcp_server_config(config_path: str) -> Dict[str, Any]:
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                config = json.load(f)
            server = config["mcpServers"]["drex_firewall"]
            if not isinstance(server.get("command"), str) or not isinstance(server.get("args"), list):
                raise ValueError("invalid Drex MCP server declaration")
            return server
        except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
            raise RuntimeError("Drex MCP configuration is invalid; refusing unguarded agent launch") from exc

    @staticmethod
    def _toml_inline_table(value: Dict[str, Any]) -> str:
        pairs = []
        for key, item in value.items():
            if not isinstance(key, str) or not isinstance(item, str):
                raise RuntimeError("Drex MCP environment must contain string keys and values")
            pairs.append(f"{json.dumps(key)} = {json.dumps(item)}")
        return "{ " + ", ".join(pairs) + " }"

    def exec_command(
        self,
        session_id: str,
        command: List[str],
        cwd: Optional[str] = None,
        env: Optional[Dict[str, str]] = None,
        timeout: Optional[float] = None,
        input: Optional[str] = None,
    ) -> SandboxResult:
        """Run arbitrary command confined inside the active sandbox."""
        start_t = time.time()
        res = self.backend.exec(session_id, command, cwd=cwd, env=env, timeout=timeout, input=input)
        duration = time.time() - start_t

        # Update session metrics in repository
        actions = self.repository.get_actions_for_sandbox(session_id)
        total_a = len(actions)
        allowed_a = sum(1 for a in actions if a["allowed"])
        blocked_a = sum(1 for a in actions if not a["allowed"])
        escalate_a = sum(1 for a in actions if a["final_decision"] == "ESCALATE")

        self.repository.update_sandbox_session(
            session_id=session_id,
            duration_seconds=duration,
            total_actions=total_a,
            allowed_actions=allowed_a,
            blocked_actions=blocked_a,
            escalated_actions=escalate_a,
        )
        return res

    def stop_session(self, session_id: str) -> bool:
        """Stop sandbox execution and record terminal state."""
        ok = self.backend.stop(session_id)
        if ok:
            self.repository.update_sandbox_session(session_id=session_id, status="STOPPED")
        return ok

    def destroy_session(self, session_id: str) -> bool:
        """Clean up ephemeral mount points and sandbox resources."""
        ok = self.backend.destroy(session_id)
        if ok:
            try:
                self.repository.update_sandbox_session(session_id=session_id, status="DESTROYED")
            finally:
                self._remove_mcp_config(session_id)
                self._remove_audit_broker(session_id)
        return ok
