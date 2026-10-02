"""Bubblewrap unprivileged rootless container sandbox backend for Drex Agent Firewall."""

from __future__ import annotations

import logging
import json
import os
import re
import shutil
import subprocess
import socket
import stat
import tempfile
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
from drex_agent_firewall.utils.process_io import bounded_communicate

logger = logging.getLogger(__name__)

_SENSITIVE_AUTH_KEY = re.compile(r"(?i)(token|secret|api.?key|password|cookie|account)")
_PROXY_LAUNCHER = "/opt/drex-firewall/src/drex_agent_firewall/sandbox/proxy_launcher.py"

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
    "NO_PROXY",
    "FTP_PROXY",
    "GIT_ASKPASS",
    "GIT_TERMINAL_PROMPT",
}


def _blocked_environment_name(name: str) -> bool:
    normalized = name.upper()
    return normalized in BLOCKED_SENSITIVE_ENV_EXACT or any(
        normalized.startswith(prefix) for prefix in BLOCKED_SENSITIVE_ENV_PREFIXES
    )


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

        if spec.network_mode == "controlled-online" and spec.agent_type not in ("codex", "claude"):
            raise ValueError("controlled-online requires agent_type='codex' or 'claude'")

        # Strictly prevent exposing root or host home as workspace
        if not spec.expose_host_root and real_workspace == "/":
            raise ValueError("Refusing to mount host root '/' as sandbox workspace")

        if not spec.expose_host_home and real_workspace == real_home:
            raise ValueError(
                f"Refusing to mount host home directory '{real_home}' as sandbox workspace. "
                "Use a subdirectory or set expose_host_home=True explicitly."
            )

        protected_user_paths = [
            os.path.join(real_home, ".local"),
            os.path.join(real_home, ".codex"),
        ]
        for protected_path in protected_user_paths:
            if real_workspace == protected_path or real_workspace.startswith(protected_path + os.sep):
                raise ValueError(f"Refusing to mount protected host user data as workspace: {protected_path}")

        # Prevent symlink-supplied workspace paths that resolve to sensitive locations
        sensitive_prefixes = ["/root", "/etc", "/var/run", "/run", "/proc", "/sys", "/dev"]
        for prefix in sensitive_prefixes:
            if real_workspace == prefix or real_workspace.startswith(prefix + "/"):
                raise ValueError(
                    f"Refusing to mount sensitive system path '{real_workspace}' as sandbox workspace"
                )

        # Create ephemeral session directory
        safe_session_id = re.sub(r"[^A-Za-z0-9_-]", "_", spec.session_id)[:48] or "session"
        session_tmp = tempfile.mkdtemp(prefix=f"drex_sandbox_{safe_session_id}_")
        os.chmod(session_tmp, 0o700)
        agent_home = os.path.join(session_tmp, "home")
        os.makedirs(agent_home, mode=0o700, exist_ok=True)

        # Create minimal synthetic passwd file
        passwd_path = os.path.join(session_tmp, "passwd")
        with open(passwd_path, "w") as f:
            f.write("root:x:0:0:root:/root:/bin/bash\n")
            f.write("agent:x:1000:1000:Drex Agent:/home/agent:/bin/bash\n")
            f.write("nobody:x:65534:65534:nobody:/nonexistent:/bin/false\n")

        # Session-local tool wrappers, if any. System-installed tools stay under
        # the read-only /usr mount; host ~/.local is never mounted.
        session_bin = os.path.join(session_tmp, "bin")
        os.makedirs(session_bin, exist_ok=True)

        hosts_path = os.path.join(session_tmp, "hosts")
        with open(hosts_path, "w", encoding="ascii") as f:
            f.write("127.0.0.1 localhost\n::1 localhost\n")

        self._sessions[spec.session_id] = {
            "spec": spec,
            "session_tmp": session_tmp,
            "session_bin": session_bin,
            "agent_home": agent_home,
            "passwd_path": passwd_path,
            "hosts_path": hosts_path,
            "real_workspace": real_workspace,
            "status": SandboxStatus.CREATED,
            "pids": set(),
        }
        return True

    def _build_bwrap_args(
        self,
        spec: SandboxSpec,
        session_data: Dict[str, Any],
        runtime_auth_mount: Optional[str] = None,
        egress_socket_path: Optional[str] = None,
    ) -> List[str]:
        """Construct full bubblewrap isolation argument vector."""
        args = [self.bwrap_bin]

        # Process & Namespace Isolation
        args.extend(["--die-with-parent", "--new-session"])
        args.extend(["--unshare-user", "--unshare-pid", "--unshare-ipc", "--unshare-uts"])
        args.extend(["--cap-drop", "ALL"])

        # Network Isolation — always unshare network namespace
        if spec.network_mode in ("none", "firewall-only", "controlled-online"):
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

        # Selective /etc mounts — isolated network modes use a synthetic hosts
        # file and do not receive the host resolver configuration.
        etc_required_files = [
            "/etc/ssl",             # CA certificates for TLS
            "/etc/ca-certificates", # CA certificate bundles
            "/etc/pki",             # PKI on RHEL-based systems
            "/etc/nsswitch.conf",   # Name service switch configuration
            "/etc/ld.so.conf",      # Dynamic linker configuration
            "/etc/ld.so.conf.d",    # Dynamic linker configuration directory
            "/etc/ld.so.cache",     # Dynamic linker cache
            "/etc/localtime",       # Timezone
            "/etc/alternatives",    # Debian alternatives system (for python3 etc)
        ]
        for f in etc_required_files:
            if os.path.exists(f):
                args.extend(["--ro-bind", f, f])

        isolated_network_modes = ("none", "firewall-only", "allowlisted", "controlled-online")
        if spec.network_mode in isolated_network_modes:
            args.extend(["--ro-bind", session_data["hosts_path"], "/etc/hosts"])
        else:
            if os.path.exists("/etc/hosts"):
                args.extend(["--ro-bind", "/etc/hosts", "/etc/hosts"])
            if os.path.exists("/etc/resolv.conf"):
                args.extend(["--ro-bind", "/etc/resolv.conf", "/etc/resolv.conf"])

        # If an explicit non-isolated network mode is in use, mount resolver
        # support. controlled-online never gets the host resolver.
        if spec.network_mode not in isolated_network_modes:
            if os.path.exists("/run/systemd/resolve"):
                args.extend(["--ro-bind", "/run/systemd/resolve", "/run/systemd/resolve"])

        # Synthetic user configuration
        args.extend(["--ro-bind", session_data["passwd_path"], "/etc/passwd"])

        # Core virtual filesystems
        args.extend(["--proc", "/proc", "--dev", "/dev"])

        # Ephemeral mounts
        args.extend(["--tmpfs", "/tmp"])
        args.extend(["--bind", session_data["agent_home"], "/home/agent"])

        if egress_socket_path:
            if not os.path.exists(egress_socket_path) or not stat.S_ISSOCK(os.stat(egress_socket_path).st_mode):
                raise FileNotFoundError("Controlled egress bridge socket is unavailable")
            args.extend(["--dir", "/run", "--ro-bind", egress_socket_path, "/run/drex-egress.sock"])

        if runtime_auth_mount:
            if not os.path.isfile(runtime_auth_mount):
                raise FileNotFoundError("Ephemeral agent authentication file is missing")
            if spec.agent_type == "codex":
                auth_guest_path = "/home/agent/.codex/auth.json"
            elif spec.agent_type == "claude":
                auth_guest_path = "/home/agent/.claude/.credentials.json"
            else:
                raise ValueError("Runtime authentication is available only for supported agent types")
            args.extend(["--ro-bind", runtime_auth_mount, auth_guest_path])

        # Optional session-local tools and Drex read-only code mounts.
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
            "PATH": "/opt/agent_bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "HOME": "/home/agent",
            "USER": "agent",
            "SHELL": "/bin/bash",
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "TERM": "xterm-256color",
            "PYTHONPATH": "/opt/drex-firewall/src",
        }

        if spec.network_mode == "controlled-online":
            from drex_agent_firewall.sandbox.controlled_egress import AGENT_EGRESS_ALLOWLISTS

            allowed_hosts = AGENT_EGRESS_ALLOWLISTS.get(spec.agent_type)
            if not allowed_hosts:
                raise ValueError("controlled-online requires a supported authenticated agent type")
            env["DREX_EGRESS_HOSTS"] = ",".join(sorted(allowed_hosts))
            if spec.agent_type == "codex":
                env["CODEX_HOME"] = "/home/agent/.codex"
            elif spec.agent_type == "claude":
                env["CLAUDE_CONFIG_DIR"] = "/home/agent/.claude"

        # Transfer only allowlisted environment variables that are safe
        for key in spec.env_allowlist:
            if key in os.environ and key not in env:
                # Strictly check blocked prefixes and names
                if _blocked_environment_name(key):
                    continue
                env[key] = os.environ[key]

        # Apply explicit overrides from spec (if not blocked)
        for k, v in spec.env_overrides.items():
            if not _blocked_environment_name(k):
                env[k] = v

        return env

    @staticmethod
    def _collect_auth_secrets(value: Any, parent_key: str = "") -> List[str]:
        secrets: List[str] = []
        if isinstance(value, dict):
            for key, child in value.items():
                if _SENSITIVE_AUTH_KEY.search(str(key)) and isinstance(child, str) and len(child) >= 6:
                    secrets.append(child)
                else:
                    secrets.extend(BubblewrapBackend._collect_auth_secrets(child, str(key)))
        elif isinstance(value, list):
            for child in value:
                secrets.extend(BubblewrapBackend._collect_auth_secrets(child, parent_key))
        return secrets

    @staticmethod
    def _redact_runtime_auth(text: str, secret_values: List[str]) -> str:
        for secret in sorted(set(secret_values), key=len, reverse=True):
            text = text.replace(secret, "[REDACTED]")
        return text

    def _stage_runtime_auth(self, spec: SandboxSpec, session_data: Dict[str, Any]) -> tuple[str, List[str]]:
        """Create one minimal ephemeral auth file for this requested agent call."""
        if spec.agent_type == "codex":
            source = os.path.expanduser("~/.codex/auth.json")
            guest_dir = os.path.join(session_data["agent_home"], ".codex")
            guest_file = os.path.join(guest_dir, "auth.json")
            if not os.path.isfile(source):
                raise RuntimeError("Codex authentication is missing: expected the existing ~/.codex/auth.json login")
            try:
                with open(source, "r", encoding="utf-8") as f:
                    original = json.load(f)
            except (OSError, json.JSONDecodeError) as exc:
                raise RuntimeError("Codex authentication file is unreadable or invalid JSON") from exc
            if original.get("auth_mode") != "chatgpt":
                raise RuntimeError("Controlled Codex mode currently requires an existing ChatGPT OAuth login")
            tokens = original.get("tokens")
            if not isinstance(tokens, dict) or not all(isinstance(tokens.get(k), str) and tokens[k] for k in ("access_token", "id_token", "refresh_token", "account_id")):
                raise RuntimeError("Codex ChatGPT OAuth auth file is missing required token fields")
            minimal_auth = {
                "auth_mode": "chatgpt",
                "tokens": {key: tokens[key] for key in ("access_token", "id_token", "refresh_token", "account_id")},
            }
            if isinstance(original.get("last_refresh"), str):
                minimal_auth["last_refresh"] = original["last_refresh"]
            secret_values = self._collect_auth_secrets(minimal_auth)
        elif spec.agent_type == "claude":
            source = os.path.expanduser("~/.claude/.credentials.json")
            guest_dir = os.path.join(session_data["agent_home"], ".claude")
            guest_file = os.path.join(guest_dir, ".credentials.json")
            if not os.path.isfile(source):
                raise RuntimeError("Claude authentication is missing: expected the existing ~/.claude/.credentials.json login")
            try:
                with open(source, "r", encoding="utf-8") as f:
                    minimal_auth = json.load(f)
            except (OSError, json.JSONDecodeError) as exc:
                raise RuntimeError("Claude authentication file is unreadable or invalid JSON") from exc
            if not isinstance(minimal_auth, dict) or not minimal_auth:
                raise RuntimeError("Claude authentication file has no usable credential data")
            secret_values = self._collect_auth_secrets(minimal_auth)
        else:
            raise RuntimeError("Controlled online mode supports only Codex and Claude agents")

        os.makedirs(guest_dir, mode=0o700, exist_ok=True)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        fd = os.open(guest_file, flags, 0o400)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(minimal_auth, f, separators=(",", ":"))
                f.flush()
                os.fsync(f.fileno())
            os.chmod(guest_file, 0o400)
        except Exception:
            try:
                os.unlink(guest_file)
            except OSError:
                pass
            raise
        return guest_file, secret_values

    @staticmethod
    def _required_system_agent_binary(agent_type: str) -> str:
        binaries = {"codex": "/usr/bin/codex", "claude": "/usr/bin/claude"}
        binary = binaries.get(agent_type)
        if not binary or not os.path.isfile(binary) or not os.access(binary, os.X_OK):
            raise FileNotFoundError(
                f"Required system-installed {agent_type} executable is unavailable; "
                "no ~/.local fallback is permitted"
            )
        if not os.path.isfile("/usr/bin/python3") or not os.access("/usr/bin/python3", os.X_OK):
            raise FileNotFoundError("Required system-installed /usr/bin/python3 is unavailable for the controlled proxy")
        if not os.path.isfile(os.path.join(os.path.dirname(__file__), "proxy_launcher.py")):
            raise FileNotFoundError("Controlled proxy launcher is unavailable")
        return binary

    def exec_agent(
        self,
        session_id: str,
        command: List[str],
        timeout: Optional[float] = None,
        input: Optional[str] = None,
    ) -> SandboxResult:
        """Run one authenticated agent call with the private controlled egress bridge."""
        if session_id not in self._sessions:
            raise KeyError(f"Unknown sandbox session: {session_id}")
        session_data = self._sessions[session_id]
        spec: SandboxSpec = session_data["spec"]
        if spec.network_mode != "controlled-online":
            raise RuntimeError("Authenticated agent execution requires explicit network_mode='controlled-online'")
        if spec.agent_type not in ("codex", "claude"):
            raise RuntimeError("controlled-online supports only the explicitly requested Codex or Claude agent")

        from drex_agent_firewall.sandbox.controlled_egress import (
            AGENT_EGRESS_ALLOWLISTS,
            ControlledEgressBroker,
        )

        binary = self._required_system_agent_binary(spec.agent_type)
        if not command or os.path.realpath(command[0]) != os.path.realpath(binary):
            raise RuntimeError("Controlled online mode accepts only the system-installed agent executable")
        launcher_guest = _PROXY_LAUNCHER
        launcher_host = os.path.join(os.path.dirname(__file__), "proxy_launcher.py")
        if not os.path.isfile(launcher_host):
            raise FileNotFoundError("Controlled proxy launcher is unavailable")

        runtime_auth_path, secret_values = self._stage_runtime_auth(spec, session_data)
        broker: Optional[ControlledEgressBroker] = None
        proc: Optional[subprocess.Popen] = None
        start_t = time.perf_counter()
        exec_timeout = timeout or spec.limits.timeout_seconds
        try:
            bridge_path = os.path.join(session_data["session_tmp"], "egress.sock")
            broker = ControlledEgressBroker(bridge_path, AGENT_EGRESS_ALLOWLISTS[spec.agent_type])
            broker.start()

            bwrap_args = self._build_bwrap_args(
                spec,
                session_data,
                runtime_auth_mount=runtime_auth_path,
                egress_socket_path=bridge_path,
            )
            bwrap_args.extend([
                "--",
                "/usr/bin/python3",
                launcher_guest,
                "--bridge-socket",
                "/run/drex-egress.sock",
                "--",
                binary,
                *command[1:],
            ])

            clean_launcher_env = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}
            proc = subprocess.Popen(
                bwrap_args,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=clean_launcher_env,
            )
            captured = bounded_communicate(
                proc,
                input=input,
                timeout=exec_timeout,
                max_output_bytes=spec.limits.max_output_bytes,
            )
            duration = time.perf_counter() - start_t
            stdout_str = self._redact_runtime_auth(captured.stdout, secret_values)
            stderr_str = self._redact_runtime_auth(captured.stderr, secret_values)
            if captured.timed_out:
                stderr_str += f"\n[DREX_SANDBOX_TIMEOUT]: Execution timed out after {exec_timeout}s"
                return SandboxResult(
                    returncode=124,
                    stdout=stdout_str,
                    stderr=stderr_str,
                    duration_seconds=round(duration, 3),
                    timed_out=True,
                    limit_exceeded=captured.limit_exceeded,
                )
            if broker.error and proc.returncode == 0:
                return SandboxResult(
                    returncode=125,
                    stdout=stdout_str,
                    stderr="Controlled egress bridge failed; no host-network fallback was attempted.",
                    duration_seconds=round(duration, 3),
                    limit_exceeded=captured.limit_exceeded,
                )
            return SandboxResult(
                returncode=captured.returncode,
                stdout=stdout_str,
                stderr=stderr_str,
                duration_seconds=round(duration, 3),
                limit_exceeded=captured.limit_exceeded,
            )
        except Exception as exc:
            # Keep auth data and host paths out of the returned failure message.
            return SandboxResult(
                returncode=-1,
                stderr=f"Controlled online execution failed closed: {type(exc).__name__}: {str(exc)} (no host-network fallback)",
                duration_seconds=round(time.perf_counter() - start_t, 3),
                error=type(exc).__name__,
            )
        finally:
            if proc is not None and proc.poll() is None:
                proc.kill()
                proc.wait()
            if broker is not None:
                broker.close()
            try:
                os.unlink(runtime_auth_path)
            except OSError:
                pass

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
                if not _blocked_environment_name(k):
                    bwrap_args.extend(["--setenv", k, v])

        # Append target command
        bwrap_args.append("--")
        bwrap_args.extend(command)

        start_t = time.perf_counter()
        try:
            proc = subprocess.Popen(
                bwrap_args,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"},
            )
            session_data["pids"].add(proc.pid)

            captured = bounded_communicate(
                proc,
                input=input,
                timeout=exec_timeout,
                max_output_bytes=max_bytes,
            )
            duration = time.perf_counter() - start_t
            stdout_str = captured.stdout
            stderr_str = captured.stderr
            if captured.timed_out:
                stderr_str += f"\n[DREX_SANDBOX_TIMEOUT]: Execution timed out after {exec_timeout}s"

            session_data["pids"].discard(proc.pid)

            return SandboxResult(
                returncode=captured.returncode if not captured.timed_out else 124,
                stdout=stdout_str,
                stderr=stderr_str,
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
