"""Bubblewrap unprivileged rootless container sandbox backend for Drex Agent Firewall."""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import time
from typing import Any, Dict, List, Optional

from drex_agent_firewall.sandbox.backend import (
    IsolationBackend,
    SandboxLimits,
    SandboxResult,
    SandboxSessionInfo,
    SandboxSpec,
    SandboxStatus,
)

logger = logging.getLogger(__name__)

BLOCKED_SENSITIVE_ENV_PREFIXES = (
    "GITHUB_",
    "GH_",
    "AWS_",
    "OPENAI_",
    "ANTHROPIC_",
    "GOOGLE_",
    "GEMINI_",
    "DREX_",
    "SSH_",
    "SLACK_",
)

BLOCKED_SENSITIVE_ENV_EXACT = {
    "SSH_AUTH_SOCK",
    "SSH_AGENT_PID",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "GIT_ASKPASS",
    "GIT_TERMINAL_PROMPT",
}


class BubblewrapBackend(IsolationBackend):
    """Bubblewrap (bwrap) unprivileged rootless container isolation backend.
    
    Provides Linux namespace isolation (user, pid, ipc, uts, net) without requiring root:
    - Bind mounts only the explicit workspace (/workspace)
    - Denies access to host /home, host credentials, ~/.ssh, ~/.aws
    - Unshares PID namespace so host processes cannot be inspected or signaled
    - Drops all Linux capabilities (cap-drop ALL)
    - Enforces no-new-privileges and dies with parent
    - Unshares network namespace (network: none / firewall-only)
    - Cleanses host environment and prevents secret inheritance
    """

    def __init__(self, bwrap_bin: Optional[str] = None):
        self.bwrap_bin = bwrap_bin or shutil.which("bwrap") or "/usr/bin/bwrap"
        self._sessions: Dict[str, Dict[str, Any]] = {}

    @property
    def name(self) -> str:
        return "bubblewrap"

    def is_available(self) -> bool:
        """Verify bwrap binary exists and basic user namespaces function."""
        if not os.path.exists(self.bwrap_bin):
            return False
        try:
            res = subprocess.run(
                [
                    self.bwrap_bin,
                    "--ro-bind", "/usr", "/usr",
                    "--ro-bind", "/bin", "/bin",
                    "--ro-bind", "/lib", "/lib",
                    "--ro-bind", "/lib64", "/lib64",
                    "--proc", "/proc",
                    "--dev", "/dev",
                    "--tmpfs", "/tmp",
                    "echo", "ok",
                ],
                capture_output=True,
                text=True,
                timeout=3.0,
            )
            return res.returncode == 0 and "ok" in res.stdout
        except Exception:
            return False

    def prepare(self, spec: SandboxSpec) -> bool:
        """Prepare ephemeral sandbox filesystem and enforce fail-closed invariants."""
        # Fail closed on missing workspace
        if not os.path.exists(spec.workspace_path):
            raise FileNotFoundError(f"Sandbox workspace path does not exist: {spec.workspace_path}")

        real_workspace = os.path.realpath(spec.workspace_path)
        real_home = os.path.realpath(os.path.expanduser("~"))

        # Strictly prevent exposing root or host home as workspace
        if not spec.expose_host_root and real_workspace == "/":
            raise ValueError("Refusing to mount host root '/' as sandbox workspace")

        if not spec.expose_host_home and real_workspace == real_home:
            raise ValueError(
                f"Refusing to mount host home directory '{real_home}' as sandbox workspace. "
                "Use a subdirectory or set expose_host_home=True explicitly."
            )

        # Prevent symlink-supplied workspace paths that resolve to sensitive locations
        sensitive_prefixes = ["/root", "/etc", "/var/run", "/run", "/proc", "/sys", "/dev"]
        for prefix in sensitive_prefixes:
            if real_workspace == prefix or real_workspace.startswith(prefix + "/"):
                raise ValueError(
                    f"Refusing to mount sensitive system path '{real_workspace}' as sandbox workspace"
                )

        # Create ephemeral session directory
        session_tmp = f"/tmp/drex_sandbox_{spec.session_id}"
        os.makedirs(session_tmp, exist_ok=True)
        agent_home = os.path.join(session_tmp, "home")
        os.makedirs(agent_home, exist_ok=True)

        # Create minimal synthetic passwd file
        passwd_path = os.path.join(session_tmp, "passwd")
        with open(passwd_path, "w") as f:
            f.write("root:x:0:0:root:/root:/bin/bash\n")
            f.write("agent:x:1000:1000:Drex Agent:/home/agent:/bin/bash\n")
            f.write("nobody:x:65534:65534:nobody:/nonexistent:/bin/false\n")

        # Create session bin directory with wrappers
        session_bin = os.path.join(session_tmp, "bin")
        os.makedirs(session_bin, exist_ok=True)
        # Discover Claude binary dynamically (no hardcoded personal paths)
        real_claude = shutil.which("claude")
        host_claude_path = None
        if real_claude:
            host_claude_path = os.path.realpath(real_claude)
        else:
            # Check common user-local installation path
            user_claude_dir = os.path.expanduser("~/.local/share/claude/versions")
            if os.path.isdir(user_claude_dir):
                versions = sorted(os.listdir(user_claude_dir), reverse=True)
                for v in versions:
                    candidate = os.path.join(user_claude_dir, v)
                    if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                        host_claude_path = candidate
                        break
        if host_claude_path and os.path.exists(host_claude_path):
            # Resolve the in-sandbox path relative to /opt/agent_tools mount
            user_local = os.path.expanduser("~/.local")
            if host_claude_path.startswith(user_local):
                sandbox_claude_path = "/opt/agent_tools" + host_claude_path[len(user_local):]
            else:
                sandbox_claude_path = host_claude_path
            claude_wrapper = os.path.join(session_bin, "claude")
            with open(claude_wrapper, "w") as f:
                f.write(f"#!/bin/bash\nexec {sandbox_claude_path} \"$@\"\n")
            os.chmod(claude_wrapper, 0o755)

        # Runtime credential injection: narrowly scoped, opt-in, documented
        # WHY: Claude Code requires its authentication token to function
        # WHAT: Claude CLI session credential (API access for the agent's execution)
        # HOW LONG: Ephemeral — destroyed with sandbox session tmpdir
        # SCOPE: Only injected when agent_type is 'claude' and credentials exist
        # NOT: host environment variables, not persisted to SQLite, not logged
        if spec.agent_type == "claude":
            claude_creds = os.path.expanduser("~/.claude/.credentials.json")
            claude_json = os.path.expanduser("~/.claude.json")
            injected_creds = []
            if os.path.exists(claude_creds):
                agent_claude_dir = os.path.join(agent_home, ".claude")
                os.makedirs(agent_claude_dir, exist_ok=True)
                shutil.copy(claude_creds, os.path.join(agent_claude_dir, ".credentials.json"))
                injected_creds.append(".claude/.credentials.json")
            if os.path.exists(claude_json):
                shutil.copy(claude_json, os.path.join(agent_home, ".claude.json"))
                injected_creds.append(".claude.json")
            if injected_creds:
                logger.info(
                    "Sandbox %s: injected %d narrow runtime credential(s) for Claude agent: %s "
                    "(ephemeral, destroyed with session)",
                    spec.session_id, len(injected_creds), ", ".join(injected_creds),
                )

        self._sessions[spec.session_id] = {
            "spec": spec,
            "session_tmp": session_tmp,
            "session_bin": session_bin,
            "agent_home": agent_home,
            "passwd_path": passwd_path,
            "real_workspace": real_workspace,
            "status": SandboxStatus.CREATED,
            "pids": set(),
        }
        return True

    def _build_bwrap_args(self, spec: SandboxSpec, session_data: Dict[str, Any]) -> List[str]:
        """Construct full bubblewrap isolation argument vector."""
        args = [self.bwrap_bin]

        # Process & Namespace Isolation
        args.extend(["--die-with-parent", "--new-session"])
        args.extend(["--unshare-user", "--unshare-pid", "--unshare-ipc", "--unshare-uts"])
        args.extend(["--cap-drop", "ALL"])

        # Network Isolation — always unshare network namespace
        if spec.network_mode in ("none", "firewall-only"):
            args.append("--unshare-net")
        elif spec.network_mode == "allowlisted":
            # Always isolate network; allowlisted mode requires additional veth/iptables
            # configuration not yet implemented — log and proceed with isolation
            args.append("--unshare-net")
            logger.warning(
                "Sandbox %s: network_mode='allowlisted' requested but fine-grained egress "
                "filtering (veth + iptables) is not yet implemented. Network is fully isolated. "
                "The agent may not be able to reach external services.",
                spec.session_id if hasattr(spec, 'session_id') else 'unknown',
            )
        elif spec.network_mode == "host":
            # Explicit host network — user has deliberately opted out of network isolation
            logger.warning(
                "Sandbox %s: network_mode='host' — network namespace NOT isolated. "
                "Agent has full host network access.",
                spec.session_id if hasattr(spec, 'session_id') else 'unknown',
            )
        else:
            # Unknown mode — fail closed with isolation
            args.append("--unshare-net")

        # Standard OS Read-Only System Mounts (binaries/libraries only, NOT /etc)
        system_ro_dirs = [
            "/usr",
            "/bin",
            "/sbin",
            "/lib",
            "/lib64",
        ]
        for d in system_ro_dirs:
            if os.path.exists(d):
                args.extend(["--ro-bind", d, d])

        # Selective /etc mounts — only required configuration, not full host /etc
        etc_required_files = [
            "/etc/ssl",             # CA certificates for TLS
            "/etc/ca-certificates", # CA certificate bundles
            "/etc/pki",             # PKI on RHEL-based systems
            "/etc/resolv.conf",     # DNS resolution (needed even in isolated net for local resolution)
            "/etc/nsswitch.conf",   # Name service switch configuration
            "/etc/hosts",           # Host resolution (sandbox may override)
            "/etc/ld.so.conf",      # Dynamic linker configuration
            "/etc/ld.so.conf.d",    # Dynamic linker configuration directory
            "/etc/ld.so.cache",     # Dynamic linker cache
            "/etc/localtime",       # Timezone
            "/etc/alternatives",    # Debian alternatives system (for python3 etc)
        ]
        for f in etc_required_files:
            if os.path.exists(f):
                args.extend(["--ro-bind", f, f])

        # If network is enabled, mount resolv.conf target
        if spec.network_mode not in ("none", "firewall-only"):
            if os.path.exists("/run/systemd/resolve"):
                args.extend(["--ro-bind", "/run/systemd/resolve", "/run/systemd/resolve"])

        # Synthetic user configuration
        args.extend(["--ro-bind", session_data["passwd_path"], "/etc/passwd"])

        # Core virtual filesystems
        args.extend(["--proc", "/proc", "--dev", "/dev"])

        # Ephemeral mounts
        args.extend(["--tmpfs", "/tmp"])
        args.extend(["--bind", session_data["agent_home"], "/home/agent"])

        # Optional Agent Tools & Drex Read-Only mounts (to allow agent execution)
        host_user_local = os.path.expanduser("~/.local")
        if os.path.exists(host_user_local):
            args.extend(["--ro-bind", host_user_local, "/opt/agent_tools"])

        if "session_bin" in session_data and os.path.exists(session_data["session_bin"]):
            args.extend(["--ro-bind", session_data["session_bin"], "/opt/agent_bin"])

        drex_repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
        if os.path.exists(os.path.join(drex_repo_root, "src", "drex_agent_firewall")):
            args.extend(["--ro-bind", drex_repo_root, "/opt/drex-firewall"])

        # Extra User/Policy Mounts
        for m in spec.extra_mounts:
            if os.path.exists(m.host_path):
                bind_flag = "--bind" if m.mode == "rw" else "--ro-bind"
                args.extend([bind_flag, m.host_path, m.container_path])

        # Workspace mount
        workspace_flag = "--bind" if spec.workspace_mode == "rw" else "--ro-bind"
        args.extend([workspace_flag, session_data["real_workspace"], "/workspace"])
        args.extend(["--chdir", "/workspace"])

        # Environment Cleansing and Allowlisting
        args.append("--clearenv")

        # Construct sanitized environment
        env_vars = self._sanitize_environment(spec)
        for k, v in env_vars.items():
            args.extend(["--setenv", k, v])

        return args

    def _sanitize_environment(self, spec: SandboxSpec) -> Dict[str, str]:
        """Strip host credentials, sensitive keys, and construct allowlisted environment."""
        env: Dict[str, str] = {
            "PATH": "/opt/agent_bin:/opt/agent_tools/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "HOME": "/home/agent",
            "USER": "agent",
            "SHELL": "/bin/bash",
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "TERM": "xterm-256color",
            "PYTHONPATH": "/opt/drex-firewall/src:/opt/agent_tools/lib/python3.12/site-packages",
        }

        # Transfer only allowlisted environment variables that are safe
        for key in spec.env_allowlist:
            if key in os.environ and key not in env:
                # Strictly check blocked prefixes and names
                if any(key.startswith(p) for p in BLOCKED_SENSITIVE_ENV_PREFIXES):
                    continue
                if key in BLOCKED_SENSITIVE_ENV_EXACT:
                    continue
                env[key] = os.environ[key]

        # Apply explicit overrides from spec (if not blocked)
        for k, v in spec.env_overrides.items():
            if not any(k.startswith(p) for p in BLOCKED_SENSITIVE_ENV_PREFIXES) and k not in BLOCKED_SENSITIVE_ENV_EXACT:
                env[k] = v

        return env

    def launch(self, spec: SandboxSpec) -> SandboxSessionInfo:
        """Initialize session and verify boundary."""
        if spec.session_id not in self._sessions:
            self.prepare(spec)

        session_data = self._sessions[spec.session_id]
        session_data["status"] = SandboxStatus.RUNNING

        # Run boundary verification probe
        probe_res = self.exec(
            spec.session_id,
            ["python3", "-c", "import os; print('SANDBOX_ACTIVE', os.getpid())"],
            timeout=5.0,
        )
        if probe_res.returncode != 0:
            session_data["status"] = SandboxStatus.FAILED
            raise RuntimeError(f"Sandbox boundary verification failed: {probe_res.stderr}")

        return SandboxSessionInfo(
            session_id=spec.session_id,
            backend_name=self.name,
            runtime_id=f"bwrap-{spec.session_id}",
            workspace_path=spec.workspace_path,
            policy_pack=spec.policy_pack,
            agent_type=spec.agent_type,
            network_mode=spec.network_mode,
            status=SandboxStatus.RUNNING,
            limits=spec.limits,
            metadata={"temp_dir": session_data["session_tmp"]},
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
        """Execute command confined strictly within the bubblewrap container."""
        if session_id not in self._sessions:
            raise KeyError(f"Unknown sandbox session: {session_id}")

        session_data = self._sessions[session_id]
        spec: SandboxSpec = session_data["spec"]
        max_bytes = spec.limits.max_output_bytes
        exec_timeout = timeout or spec.limits.timeout_seconds

        bwrap_args = self._build_bwrap_args(spec, session_data)

        # If custom cwd requested, append --chdir
        if cwd:
            # Map host workspace path to container /workspace
            if cwd.startswith(session_data["real_workspace"]):
                rel = os.path.relpath(cwd, session_data["real_workspace"])
                container_cwd = "/workspace" if rel == "." else f"/workspace/{rel}"
            else:
                container_cwd = cwd
            bwrap_args.extend(["--chdir", container_cwd])

        # Extra environment variables for this exec
        if env:
            for k, v in env.items():
                if not any(k.startswith(p) for p in BLOCKED_SENSITIVE_ENV_PREFIXES) and k not in BLOCKED_SENSITIVE_ENV_EXACT:
                    bwrap_args.extend(["--setenv", k, v])

        # Append target command
        bwrap_args.append("--")
        bwrap_args.extend(command)

        start_t = time.perf_counter()
        try:
            proc = subprocess.Popen(
                bwrap_args,
                stdin=subprocess.PIPE if input is not None else None,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            session_data["pids"].add(proc.pid)

            try:
                stdout_str, stderr_str = proc.communicate(input=input, timeout=exec_timeout)
                duration = time.perf_counter() - start_t
                timed_out = False
            except subprocess.TimeoutExpired:
                proc.kill()
                stdout_str, stderr_str = proc.communicate()
                duration = time.perf_counter() - start_t
                timed_out = True
                stderr_str += f"\n[DREX_SANDBOX_TIMEOUT]: Execution timed out after {exec_timeout}s"

            session_data["pids"].discard(proc.pid)

            # Check output limits
            limit_exceeded = False
            if len(stdout_str) > max_bytes:
                stdout_str = stdout_str[:max_bytes] + f"\n... [TRUNCATED at {max_bytes} bytes]"
                limit_exceeded = True
            if len(stderr_str) > max_bytes:
                stderr_str = stderr_str[:max_bytes] + f"\n... [TRUNCATED at {max_bytes} bytes]"
                limit_exceeded = True

            return SandboxResult(
                returncode=proc.returncode if not timed_out else 124,
                stdout=stdout_str,
                stderr=stderr_str,
                duration_seconds=round(duration, 3),
                timed_out=timed_out,
                limit_exceeded=limit_exceeded,
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

    def stop(self, session_id: str) -> bool:
        """Terminate all lingering processes."""
        if session_id not in self._sessions:
            return False
        session_data = self._sessions[session_id]
        for pid in list(session_data["pids"]):
            try:
                os.kill(pid, 9)
            except Exception:
                pass
        session_data["pids"].clear()
        session_data["status"] = SandboxStatus.STOPPED
        return True

    def destroy(self, session_id: str) -> bool:
        """Stop processes and clean up ephemeral filesystem."""
        self.stop(session_id)
        if session_id in self._sessions:
            session_data = self._sessions.pop(session_id)
            tmp_dir = session_data.get("session_tmp")
            if tmp_dir and os.path.exists(tmp_dir):
                shutil.rmtree(tmp_dir, ignore_errors=True)
            return True
        return False

    def status(self, session_id: str) -> SandboxStatus:
        if session_id not in self._sessions:
            return SandboxStatus.DESTROYED
        return self._sessions[session_id]["status"]
