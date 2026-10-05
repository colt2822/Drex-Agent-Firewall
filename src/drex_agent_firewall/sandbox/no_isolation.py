"""Non-isolated direct host execution backend for Drex Agent Firewall (Baseline / Comparison)."""

from __future__ import annotations

import os
import signal
import shutil
import subprocess
import time
from typing import Any, Dict, List, Optional

from drex_agent_firewall.sandbox.backend import (
    IsolationBackend,
    SandboxResult,
    SandboxSessionInfo,
    SandboxSpec,
    SandboxStatus,
)
from drex_agent_firewall.utils.process_io import bounded_communicate
from drex_agent_firewall.sandbox.resource_guard import ResourceGuard


class NoIsolationBackend(IsolationBackend):
    """Null isolation backend executing directly on the host.
    
    WARNING: Does not prevent direct host POSIX bypasses. Provided exclusively
    for performance baseline benchmarking and comparison against isolated runtimes.
    This is NOT a sandbox. It must never be silently selected when sandbox mode
    is requested.
    """

    def __init__(self):
        self._sessions: Dict[str, Dict[str, Any]] = {}
        import logging
        self._logger = logging.getLogger(__name__)

    @property
    def name(self) -> str:
        return "none"

    def is_available(self) -> bool:
        return True

    def prepare(self, spec: SandboxSpec) -> bool:
        self._sessions[spec.session_id] = {
            "spec": spec,
            "status": SandboxStatus.CREATED,
            "pids": set(),
            "processes": set(),
            "pgids": set(),
            "resource_guards": set(),
        }
        return True

    def launch(self, spec: SandboxSpec) -> SandboxSessionInfo:
        if spec.session_id not in self._sessions:
            self.prepare(spec)
        self._sessions[spec.session_id]["status"] = SandboxStatus.RUNNING

        # Explicit visible warning — this is NOT isolated
        import sys
        warning_msg = (
            "\n⚠️  WARNING: NoIsolationBackend active — agent is executing directly on the host "
            "with NO kernel-level isolation. This mode is for development/benchmarking only. "
            "Do NOT use for untrusted agents or production workloads.\n"
        )
        self._logger.warning(warning_msg.strip())
        print(warning_msg, file=sys.stderr, flush=True)

        return SandboxSessionInfo(
            session_id=spec.session_id,
            backend_name=self.name,
            runtime_id="host-process",
            workspace_path=spec.workspace_path,
            policy_pack=spec.policy_pack,
            agent_type=spec.agent_type,
            network_mode="host",
            status=SandboxStatus.RUNNING,
            limits=spec.limits,
            metadata={"warning": "Unrestricted host execution; no kernel isolation active"},
        )

    def exec(
        self,
        session_id: str,
        command: List[str],
        cwd: Optional[str] = None,
        env: Optional[Dict[str, str]] = None,
        timeout: Optional[float] = None,
        input: Optional[str] = None,
    ) -> SandboxResult:
        if session_id not in self._sessions:
            raise KeyError(f"Unknown sandbox session: {session_id}")

        spec: SandboxSpec = self._sessions[session_id]["spec"]
        exec_timeout = timeout or spec.limits.timeout_seconds
        target_cwd = cwd or spec.workspace_path

        exec_env = os.environ.copy()
        if env:
            exec_env.update(env)

        start_t = time.perf_counter()
        guard = None
        try:
            guard = ResourceGuard(spec.limits)
            self._sessions[session_id]["resource_guards"].add(guard)
            guarded_command = list(command)
            if guarded_command:
                resolved = shutil.which(guarded_command[0], path=exec_env.get("PATH"))
                if resolved:
                    guarded_command[0] = resolved
            proc = subprocess.Popen(
                guard.wrap(guarded_command, spec.limits),
                cwd=target_cwd,
                env=exec_env,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
                pass_fds=(guard.fd,),
            )
            self._sessions[session_id]["processes"].add(proc)
            self._sessions[session_id]["pgids"].add(proc.pid)
            captured = bounded_communicate(
                proc,
                input=input,
                timeout=exec_timeout,
                max_output_bytes=spec.limits.max_output_bytes,
            )
            duration = time.perf_counter() - start_t
            return SandboxResult(
                returncode=124 if captured.timed_out else captured.returncode,
                stdout=captured.stdout,
                stderr=captured.stderr + (
                    f"\nExecution timed out after {exec_timeout}s" if captured.timed_out else ""
                ),
                duration_seconds=round(duration, 3),
                timed_out=captured.timed_out,
                limit_exceeded=captured.limit_exceeded,
            )
        except Exception as e:
            duration = time.perf_counter() - start_t
            return SandboxResult(
                returncode=-1,
                stdout="",
                stderr=str(e),
                duration_seconds=round(duration, 3),
                error=str(e),
            )
        finally:
            if guard is not None:
                guard.close()
                self._sessions.get(session_id, {}).get("resource_guards", set()).discard(guard)
            if 'proc' in locals():
                self._sessions.get(session_id, {}).get("processes", set()).discard(proc)
                try:
                    os.killpg(proc.pid, 0)
                except (ProcessLookupError, PermissionError, OSError):
                    self._sessions.get(session_id, {}).get("pgids", set()).discard(proc.pid)

    def stop(self, session_id: str) -> bool:
        if session_id in self._sessions:
            for guard in tuple(self._sessions[session_id].get("resource_guards", ())):
                guard.kill()
            for pgid in tuple(self._sessions[session_id].get("pgids", ())):
                try:
                    os.killpg(pgid, signal.SIGKILL)
                except (ProcessLookupError, PermissionError, OSError):
                    pass
            self._sessions[session_id].get("pgids", set()).clear()
            self._sessions[session_id]["status"] = SandboxStatus.STOPPED
            return True
        return False

    def destroy(self, session_id: str) -> bool:
        if session_id in self._sessions:
            self.stop(session_id)
            self._sessions.pop(session_id)
            return True
        return False

    def status(self, session_id: str) -> SandboxStatus:
        if session_id not in self._sessions:
            return SandboxStatus.DESTROYED
        return self._sessions[session_id]["status"]
