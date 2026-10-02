"""Container CLI isolation backends (Podman and Docker) for Drex Agent Firewall."""

from __future__ import annotations

import logging
import os
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

logger = logging.getLogger(__name__)


class ContainerCLIBackend(IsolationBackend):
    """Generic OCI container CLI backend base for Podman / Docker."""

    def __init__(self, cli_bin: str, name: str, default_image: str = "python:3.12-slim"):
        self.cli_bin = cli_bin
        self._name = name
        self.default_image = default_image
        self._sessions: Dict[str, Dict[str, Any]] = {}

    @property
    def name(self) -> str:
        return self._name

    def is_available(self) -> bool:
        bin_path = shutil.which(self.cli_bin)
        if not bin_path:
            return False
        try:
            res = subprocess.run([bin_path, "--version"], capture_output=True, timeout=2.0)
            return res.returncode == 0
        except Exception:
            return False

    def prepare(self, spec: SandboxSpec) -> bool:
        if not self.is_available():
            raise RuntimeError(f"Container runtime '{self.cli_bin}' is not installed or available on this host")
        if not os.path.exists(spec.workspace_path):
            raise FileNotFoundError(f"Workspace path does not exist: {spec.workspace_path}")
        if not spec.expose_host_root and os.path.realpath(spec.workspace_path) == "/":
            raise ValueError("Refusing to mount host root '/' into container")

        container_name = f"drex-sandbox-{spec.session_id}"
        self._sessions[spec.session_id] = {
            "spec": spec,
            "container_name": container_name,
            "status": SandboxStatus.CREATED,
        }
        return True

    def launch(self, spec: SandboxSpec) -> SandboxSessionInfo:
        if spec.session_id not in self._sessions:
            self.prepare(spec)

        session_data = self._sessions[spec.session_id]
        c_name = session_data["container_name"]

        # Build run arguments
        run_args = [
            self.cli_bin, "run", "-d",
            "--name", c_name,
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
        ]

        if spec.network_mode in ("none", "firewall-only"):
            run_args.extend(["--network", "none"])

        # Mount workspace
        rw_flag = "rw" if spec.workspace_mode == "rw" else "ro"
        run_args.extend(["-v", f"{os.path.abspath(spec.workspace_path)}:/workspace:{rw_flag}"])
        run_args.extend(["-w", "/workspace"])

        # Resource limits
        run_args.extend([
            f"--memory={spec.limits.memory_mb}m",
            f"--cpus={spec.limits.cpus}",
            f"--pids-limit={spec.limits.pids}",
        ])

        # Extra mounts
        for m in spec.extra_mounts:
            run_args.extend(["-v", f"{os.path.abspath(m.host_path)}:{m.container_path}:{m.mode}"])

        run_args.extend([self.default_image, "sleep", "infinity"])

        res = subprocess.run(run_args, capture_output=True, text=True)
        if res.returncode != 0:
            session_data["status"] = SandboxStatus.FAILED
            raise RuntimeError(f"Failed to start container '{c_name}': {res.stderr}")

        session_data["status"] = SandboxStatus.RUNNING
        session_data["container_id"] = res.stdout.strip()[:12]

        return SandboxSessionInfo(
            session_id=spec.session_id,
            backend_name=self.name,
            runtime_id=session_data["container_id"],
            workspace_path=spec.workspace_path,
            policy_pack=spec.policy_pack,
            agent_type=spec.agent_type,
            network_mode=spec.network_mode,
            status=SandboxStatus.RUNNING,
            limits=spec.limits,
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

        session_data = self._sessions[session_id]
        spec: SandboxSpec = session_data["spec"]
        c_name = session_data["container_name"]
        exec_timeout = timeout or spec.limits.timeout_seconds

        exec_args = [self.cli_bin, "exec"]
        if input is not None:
            exec_args.append("-i")
        if cwd:
            exec_args.extend(["-w", cwd])
        if env:
            for k, v in env.items():
                exec_args.extend(["-e", f"{k}={v}"])

        exec_args.append(c_name)
        exec_args.extend(command)

        start_t = time.perf_counter()
        try:
            res = subprocess.run(
                exec_args,
                input=input,
                capture_output=True,
                text=True,
                timeout=exec_timeout,
            )
            duration = time.perf_counter() - start_t
            return SandboxResult(
                returncode=res.returncode,
                stdout=res.stdout,
                stderr=res.stderr,
                duration_seconds=round(duration, 3),
            )
        except subprocess.TimeoutExpired:
            duration = time.perf_counter() - start_t
            return SandboxResult(
                returncode=124,
                stdout="",
                stderr=f"Execution timed out after {exec_timeout}s",
                duration_seconds=round(duration, 3),
                timed_out=True,
            )

    def stop(self, session_id: str) -> bool:
        if session_id not in self._sessions:
            return False
        c_name = self._sessions[session_id]["container_name"]
        subprocess.run([self.cli_bin, "stop", "-t", "2", c_name], capture_output=True)
        self._sessions[session_id]["status"] = SandboxStatus.STOPPED
        return True

    def destroy(self, session_id: str) -> bool:
        if session_id not in self._sessions:
            return False
        c_name = self._sessions[session_id]["container_name"]
        subprocess.run([self.cli_bin, "rm", "-f", c_name], capture_output=True)
        self._sessions.pop(session_id)
        return True

    def status(self, session_id: str) -> SandboxStatus:
        if session_id not in self._sessions:
            return SandboxStatus.DESTROYED
        return self._sessions[session_id]["status"]


class PodmanBackend(ContainerCLIBackend):
    def __init__(self, image: str = "python:3.12-slim"):
        super().__init__(cli_bin="podman", name="podman", default_image=image)


class DockerBackend(ContainerCLIBackend):
    def __init__(self, image: str = "python:3.12-slim"):
        super().__init__(cli_bin="docker", name="docker", default_image=image)
