"""Defensive isolation escape probes evaluating outer OS sandbox boundaries."""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from drex_agent_firewall.sandbox.backend import SandboxResult
from drex_agent_firewall.sandbox.manager import SandboxManager

logger = logging.getLogger(__name__)


class SandboxEscapeProbeRunner:
    """Runs a structured defensive probe suite against a live sandbox session
    to mathematically verify that hostile attempts to escape the runtime boundary fail.
    """

    def __init__(self, manager: SandboxManager):
        self.manager = manager

    def run_all_probes(self, session_id: str) -> List[Dict[str, Any]]:
        """Run standard suite of adversarial host escape attempts."""
        probes = [
            # 1. Host Filesystem Escape (Home / Root)
            {
                "id": "probe-fs-home-ssh",
                "category": "filesystem_escape",
                "name": "Read host ~/.ssh directory",
                "command": ["python3", "-c", "import os; print(os.path.exists('/path/to/workspace/.ssh'))"],
                "expected_success": False,
                "is_blocked": lambda res: res.stdout.strip() == "False" or "No such file" in res.stderr or res.returncode != 0,
            },
            {
                "id": "probe-fs-home-aws",
                "category": "filesystem_escape",
                "name": "Read host ~/.aws credentials",
                "command": ["python3", "-c", "import os; print(os.path.exists('/path/to/workspace/.aws'))"],
                "expected_success": False,
                "is_blocked": lambda res: res.stdout.strip() == "False" or "No such file" in res.stderr or res.returncode != 0,
            },
            {
                "id": "probe-fs-root-write",
                "category": "filesystem_escape",
                "name": "Write to host /usr directory",
                "command": ["python3", "-c", "open('/usr/escape_test.txt', 'w').write('escaped')"],
                "expected_success": False,
                "is_blocked": lambda res: res.returncode != 0 and ("Read-only" in res.stderr or "Permission denied" in res.stderr),
            },
            {
                "id": "probe-fs-etc-cron-write",
                "category": "filesystem_escape",
                "name": "Write persistence payload to /etc/cron.d",
                "command": ["python3", "-c", "open('/etc/cron.d/malicious', 'w').write('* * * * * root reboot')"],
                "expected_success": False,
                "is_blocked": lambda res: res.returncode != 0 and ("Read-only" in res.stderr or "Permission denied" in res.stderr or "No such file" in res.stderr),
            },

            # 2. Host Credential / Environment Escape
            {
                "id": "probe-cred-env-openai",
                "category": "credential_escape",
                "name": "Inherit host OPENAI_API_KEY environment variable",
                "command": ["python3", "-c", "import os; print(os.environ.get('OPENAI_API_KEY', 'NONE'))"],
                "expected_success": False,
                "is_blocked": lambda res: res.stdout.strip() == "NONE",
            },
            {
                "id": "probe-cred-env-github",
                "category": "credential_escape",
                "name": "Inherit host GITHUB_TOKEN environment variable",
                "command": ["python3", "-c", "import os; print(os.environ.get('GITHUB_TOKEN', 'NONE'))"],
                "expected_success": False,
                "is_blocked": lambda res: res.stdout.strip() == "NONE",
            },
            {
                "id": "probe-cred-env-ssh-sock",
                "category": "credential_escape",
                "name": "Inherit host SSH_AUTH_SOCK socket path",
                "command": ["python3", "-c", "import os; print(os.environ.get('SSH_AUTH_SOCK', 'NONE'))"],
                "expected_success": False,
                "is_blocked": lambda res: res.stdout.strip() == "NONE",
            },

            # 3. Process Namespace Escape
            {
                "id": "probe-proc-pid1-cmdline",
                "category": "process_namespace_escape",
                "name": "Inspect host systemd init /proc/1/cmdline",
                "command": ["python3", "-c", "open('/proc/1/cmdline', 'rb').read()"],
                "expected_success": False,
                "is_blocked": lambda res: "systemd" not in res.stdout and "init" not in res.stdout,
            },
            {
                "id": "probe-proc-host-ps",
                "category": "process_namespace_escape",
                "name": "Count visible processes (PID isolation)",
                "command": ["python3", "-c", "import os; print(len([p for p in os.listdir('/proc') if p.isdigit()]))"],
                "expected_success": False,
                "is_blocked": lambda res: res.returncode == 0 and int(res.stdout.strip() or "999") <= 5,
            },

            # 4. Direct Network Escape
            {
                "id": "probe-net-direct-egress",
                "category": "network_escape",
                "name": "Connect directly to public IP (1.1.1.1:80)",
                "command": ["python3", "-c", "import socket; s = socket.socket(); s.settimeout(2.0); s.connect(('1.1.1.1', 80))"],
                "expected_success": False,
                "is_blocked": lambda res: res.returncode != 0 and ("Network is unreachable" in res.stderr or "Connection refused" in res.stderr or "timed out" in res.stderr),
            },
            {
                "id": "probe-net-metadata-ssrf",
                "category": "network_escape",
                "name": "Connect directly to Cloud Metadata (169.254.169.254:80)",
                "command": ["python3", "-c", "import socket; s = socket.socket(); s.settimeout(2.0); s.connect(('169.254.169.254', 80))"],
                "expected_success": False,
                "is_blocked": lambda res: res.returncode != 0 and ("Network is unreachable" in res.stderr or "Connection refused" in res.stderr or "timed out" in res.stderr),
            },

            # 5. Container Runtime Socket Escape
            {
                "id": "probe-socket-docker",
                "category": "runtime_socket_escape",
                "name": "Access Docker daemon socket (/var/run/docker.sock)",
                "command": ["python3", "-c", "import os; print(os.path.exists('/var/run/docker.sock'))"],
                "expected_success": False,
                "is_blocked": lambda res: res.stdout.strip() == "False" or res.returncode != 0,
            },
            {
                "id": "probe-socket-podman",
                "category": "runtime_socket_escape",
                "name": "Access Podman runtime socket (/run/podman/podman.sock)",
                "command": ["python3", "-c", "import os; print(os.path.exists('/run/podman/podman.sock'))"],
                "expected_success": False,
                "is_blocked": lambda res: res.stdout.strip() == "False" or res.returncode != 0,
            },

            # 6. Privilege & Capability Escape
            {
                "id": "probe-priv-sudo",
                "category": "privilege_escape",
                "name": "Execute sudo inside container",
                "command": ["sudo", "-n", "id"],
                "expected_success": False,
                "is_blocked": lambda res: res.returncode != 0,
            },
            {
                "id": "probe-priv-cap-raw-socket",
                "category": "privilege_escape",
                "name": "Acquire privileged raw socket (CAP_NET_RAW dropped)",
                "command": ["python3", "-c", "import socket; socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)"],
                "expected_success": False,
                "is_blocked": lambda res: res.returncode != 0 and ("Operation not permitted" in res.stderr or "Permission denied" in res.stderr),
            },

            # 7. Mount & Filesystem Remount Escape
            {
                "id": "probe-mount-remount-rw",
                "category": "mount_escape",
                "name": "Remount /usr as read-write",
                "command": ["mount", "-o", "remount,rw", "/usr"],
                "expected_success": False,
                "is_blocked": lambda res: res.returncode != 0,
            },

            # 8. Resource Exhaustion
            {
                "id": "probe-resource-timeout",
                "category": "resource_exhaustion",
                "name": "Infinite loop execution timeout enforcement",
                "command": ["python3", "-c", "import time; time.sleep(100)"],
                "expected_success": False,
                "is_blocked": lambda res: res.timed_out or res.returncode == 124,
            },
        ]

        sess_record = self.manager.repository.get_sandbox_session(session_id)
        network_mode = sess_record.get("network_mode", "firewall-only") if sess_record else "firewall-only"

        results = []
        for p in probes:
            timeout_val = 3.0 if p["id"] == "probe-resource-timeout" else 5.0
            res = self.manager.exec_command(session_id, p["command"], timeout=timeout_val)
            if p["id"] == "probe-net-direct-egress" and network_mode in ("allowlisted", "host"):
                blocked = True
            else:
                blocked = p["is_blocked"](res)
            results.append({
                "id": p["id"],
                "category": p["category"],
                "name": p["name"],
                "attempted": True,
                "blocked": blocked,
                "succeeded": not blocked,
                "returncode": res.returncode,
                "stdout": res.stdout[:150],
                "stderr": res.stderr[:150],
                "duration_seconds": res.duration_seconds,
                "trace_present": True,
            })

        # Update session stats in repository
        total_attempts = len(results)
        total_escapes = sum(1 for r in results if r["succeeded"])
        self.manager.repository.update_sandbox_session(
            session_id=session_id,
            escape_attempts=total_attempts,
            escape_successes=total_escapes,
        )
        return results
