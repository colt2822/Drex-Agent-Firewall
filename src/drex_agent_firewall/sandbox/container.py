"""Container CLI isolation backends (Podman and Docker) for Drex Agent Firewall."""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import time
import uuid
from typing import Any, Dict, List, Optional

from drex_agent_firewall.sandbox.backend import (
    IsolationBackend,
    SandboxResult,
    SandboxSessionInfo,
    SandboxSpec,
    SandboxStatus,
)
from drex_agent_firewall.security.environment import is_sensitive_environment_name
from drex_agent_firewall.utils.process_io import bounded_communicate
from drex_agent_firewall.security.safe_filesystem import parent_fd, validate_workspace_tree

logger = logging.getLogger(__name__)


class ContainerCLIBackend(IsolationBackend):
    """Generic OCI container CLI backend base for Podman / Docker."""

    def __init__(self, cli_bin: str, name: str, default_image: str = "drex-agent-firewall:validation"):
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
        if not os.path.isdir(spec.workspace_path):
            raise FileNotFoundError(f"Workspace path does not exist: {spec.workspace_path}")
        if not spec.expose_host_root and os.path.realpath(spec.workspace_path) == "/":
            raise ValueError("Refusing to mount host root '/' into container")

        real_workspace = os.path.realpath(spec.workspace_path)
        real_home = os.path.realpath(os.path.expanduser("~"))
        if os.path.commonpath([real_home, real_workspace]) == real_workspace:
            raise ValueError("Refusing host HOME or its ancestors as container workspace")
        for sensitive in ("/root", "/etc", "/run", "/var/run", "/proc", "/sys", "/dev"):
            if os.path.commonpath([real_workspace, sensitive]) == sensitive:
                raise ValueError("Refusing sensitive container workspace")
        with parent_fd(real_workspace, [real_workspace]) as (parent, leaf):
            fd = os.open(leaf, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            try:
                validate_workspace_tree(fd)
            finally:
                os.close(fd)
        if spec.session_id in self._sessions:
            raise ValueError("SESSION_ALREADY_EXISTS")
        container_name = f"drex-sandbox-{spec.session_id}"
        self._sessions[spec.session_id] = {
            "spec": spec,
            "container_name": container_name,
            "status": SandboxStatus.CREATED,
            "real_workspace": real_workspace,
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
            "--read-only",
            "--tmpfs", f"/tmp:rw,nosuid,nodev,size={spec.limits.tmp_mb}m",
            "--tmpfs", f"/home/agent:rw,nosuid,nodev,size={spec.limits.tmp_mb}m",
            "--ulimit", f"nofile={spec.limits.max_open_files}:{spec.limits.max_open_files}",
            "--ulimit", f"fsize={spec.limits.max_file_bytes}:{spec.limits.max_file_bytes}",
            "--ulimit", "core=0:0",
        ]
        # The private IPC socket is owned by the trusted host UID. Rootless
        # Podman must retain that mapping; Docker runs with the same numeric UID.
        if self.name == "podman":
            run_args.extend(["--userns", "keep-id"])
        run_args.extend(["--user", f"{os.getuid()}:{os.getgid()}"])

        # The OCI default is a bridged network with general egress. Every mode
        # except the explicit host opt-out must start network-isolated because
        # fine-grained allowlisted egress is not implemented by this backend.
        if spec.network_mode != "host":
            run_args.extend(["--network", "none"])

        # Mount workspace
        rw_flag = "rw" if spec.workspace_mode == "rw" else "ro"
        run_args.extend(["-v", f"{session_data['real_workspace']}:/workspace:{rw_flag}"])
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

        run_args.extend([self.default_image, "/usr/bin/env", "-i", "PATH=/usr/local/bin:/usr/bin:/bin", "HOME=/home/agent", "sleep", "infinity"])

        session_data["run_args"] = run_args
        res = subprocess.run(run_args, capture_output=True, text=True, timeout=60, env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": os.path.expanduser("~"), "XDG_RUNTIME_DIR": os.environ.get("XDG_RUNTIME_DIR", f"/run/user/{os.getuid()}")})
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
        if session_data["status"] != SandboxStatus.RUNNING:
            raise RuntimeError("SESSION_NOT_RUNNING")
        spec: SandboxSpec = session_data["spec"]
        c_name = session_data["container_name"]
        exec_timeout = timeout or spec.limits.timeout_seconds

        # Each command is PID 1 of a fresh container. On exit the runtime tears
        # down its whole PID namespace, including setsid/double-fork descendants.
        # A persistent `docker exec` would leave detached workers alive.
        exec_name = c_name + "-exec-" + uuid.uuid4().hex[:10]
        exec_args = list(session_data["run_args"])
        exec_args.remove("-d")
        exec_args.insert(2, "--rm")
        if input is not None:
            exec_args.insert(2, "-i")
        exec_args[exec_args.index("--name") + 1] = exec_name
        if cwd:
            exec_args[exec_args.index("-w") + 1] = cwd
        from drex_agent_firewall.sandbox.bubblewrap import BubblewrapBackend
        clean = BubblewrapBackend()._sanitize_environment(spec)
        clean["PATH"] = "/usr/local/bin:/usr/bin:/bin"
        clean["PYTHONPATH"] = "/opt/drex-python"
        if env:
            clean.update({k: v for k, v in env.items() if not is_sensitive_environment_name(k)})
        image_index = exec_args.index(self.default_image)
        exec_args[image_index + 1:] = ["/usr/bin/env", "-i", *[f"{k}={v}" for k,v in clean.items()], *command]
        session_data.setdefault("active_execs", set()).add(exec_name)

        start_t = time.perf_counter()
        try:
            proc = subprocess.Popen(
                exec_args,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
            )
            captured = bounded_communicate(
                proc,
                input=input,
                timeout=exec_timeout,
                max_output_bytes=spec.limits.max_output_bytes,
            )
            if captured.timed_out:
                # Killing the CLI does not kill container exec descendants.
                subprocess.run([self.cli_bin, "kill", exec_name], capture_output=True, timeout=10)
                session_data["status"] = SandboxStatus.FAILED
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
        except Exception as exc:
            duration = time.perf_counter() - start_t
            return SandboxResult(returncode=-1, stderr=f"Sandbox execution failed: {type(exc).__name__}", duration_seconds=round(duration, 3), error=type(exc).__name__)

        finally:
            # Only task-owned names are removed; never touch other containers.
            cleanup = subprocess.run([self.cli_bin, "rm", "-f", exec_name], capture_output=True, text=True, timeout=10)
            if cleanup.returncode != 0 and "no such container" not in cleanup.stderr.lower():
                session_data["status"] = SandboxStatus.FAILED
                raise RuntimeError("CLEANUP_FAILURE: task-owned OCI container removal unconfirmed")
            session_data["active_execs"].discard(exec_name)

    def stop(self, session_id: str) -> bool:
        if session_id not in self._sessions:
            return False
        c_name = self._sessions[session_id]["container_name"]
        for name in list(self._sessions[session_id].get("active_execs", set())):
            subprocess.run([self.cli_bin, "rm", "-f", name], capture_output=True, timeout=10)
        subprocess.run([self.cli_bin, "stop", "-t", "2", c_name], capture_output=True, timeout=10)
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
    def __init__(self, image: str = "drex-agent-firewall:validation"):
        super().__init__(cli_bin="podman", name="podman", default_image=image)


class DockerBackend(ContainerCLIBackend):
    def __init__(self, image: str = "drex-agent-firewall:validation"):
        super().__init__(cli_bin="docker", name="docker", default_image=image)
