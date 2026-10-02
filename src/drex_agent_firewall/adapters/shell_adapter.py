"""Guarded shell executor adapter with bounded output, timeouts, and env filtering."""

from __future__ import annotations

import os
import subprocess
import time
from typing import Any, Dict, List, Optional

from drex_agent_firewall.adapters.base import BaseAdapter
from drex_agent_firewall.constraints.enforcer import ConstraintEnforcer, ConstraintViolation
from drex_agent_firewall.security.environment import filter_environment
from drex_agent_firewall.schemas.decision import FirewallDecision
from drex_agent_firewall.utils.process_io import bounded_communicate


class ShellExecutionResult:
    def __init__(
        self,
        command: str,
        stdout: str,
        stderr: str,
        exit_code: int,
        duration_seconds: float,
        allowed: bool,
        firewall_decision: FirewallDecision,
        error: Optional[str] = None,
    ):
        self.command = command
        self.stdout = stdout
        self.stderr = stderr
        self.exit_code = exit_code
        self.duration_seconds = duration_seconds
        self.allowed = allowed
        self.firewall_decision = firewall_decision
        self.error = error

    def to_dict(self) -> Dict[str, Any]:
        return {
            "command": self.command,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "exit_code": self.exit_code,
            "duration_seconds": round(self.duration_seconds, 4),
            "allowed": self.allowed,
            "decision": self.firewall_decision.decision.value,
            "error": self.error,
        }


class ShellAdapter(BaseAdapter):
    """Executes shell commands under active firewall policies and machine-enforced constraints."""

    def execute(
        self,
        command: str,
        cwd: Optional[str] = None,
        env: Optional[Dict[str, str]] = None,
        timeout: Optional[float] = None,
        agent_id: str = "agent",
        session_id: str = "default-session",
    ) -> ShellExecutionResult:
        # Extract environment variable names only (never pass secret values to Drex or logs!)
        env_keys = list((env or {}).keys())

        context = {
            "cwd": cwd or os.getcwd(),
            "env_names": env_keys,
            "timeout": timeout,
        }

        arguments = {
            "command": command,
            "cwd": cwd or os.getcwd(),
            "env_keys": env_keys,
        }

        # 1. Firewall Evaluation
        envelope, decision = self.evaluate_action(
            tool="shell",
            operation="execute",
            arguments=arguments,
            context=context,
            agent_id=agent_id,
            session_id=session_id,
        )

        if not decision.allowed:
            self.record_execution_result(
                action_id=envelope.action_id,
                tool="shell",
                executed=False,
                error_class="FIREWALL_POLICY_BLOCKED",
            )
            return ShellExecutionResult(
                command=command,
                stdout="",
                stderr="",
                exit_code=-1,
                duration_seconds=0.0,
                allowed=False,
                firewall_decision=decision,
                error=f"Blocked by firewall: {decision.reason}",
            )

        # 2. Verify Enforceable Constraints
        try:
            ConstraintEnforcer.verify_command(command, decision.constraints)
            if cwd:
                ConstraintEnforcer.verify_path(cwd, decision.constraints)
        except ConstraintViolation as cv:
            self.record_execution_result(
                action_id=envelope.action_id,
                tool="shell",
                executed=False,
                error_class="CONSTRAINT_VIOLATION",
            )
            return ShellExecutionResult(
                command=command,
                stdout="",
                stderr="",
                exit_code=-2,
                duration_seconds=0.0,
                allowed=False,
                firewall_decision=decision,
                error=f"Constraint violation: {str(cv)}",
            )

        # 3. Determine Execution Bounds
        runtime_timeout = timeout or decision.constraints.max_runtime_seconds or 30.0
        max_bytes = decision.constraints.max_output_bytes or (1024 * 1024)

        # Prepare sanitized runtime environment
        exec_env = filter_environment(os.environ)
        if env:
            exec_env.update(filter_environment(env))

        # 4. Guarded Subprocess Execution
        start_t = time.perf_counter()
        try:
            proc = subprocess.Popen(
                command,
                shell=True,
                cwd=cwd or os.getcwd(),
                env=exec_env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.PIPE,
            )

            captured = bounded_communicate(
                proc,
                timeout=runtime_timeout,
                max_output_bytes=max_bytes,
            )
            duration = time.perf_counter() - start_t
            if captured.timed_out:
                self.record_execution_result(
                    action_id=envelope.action_id,
                    tool="shell",
                    executed=True,
                    error_class="TIMEOUT_EXPIRED",
                )
                return ShellExecutionResult(
                    command=command,
                    stdout=captured.stdout,
                    stderr=captured.stderr + f"\nExecution exceeded timeout limit of {runtime_timeout}s",
                    exit_code=-9,
                    duration_seconds=duration,
                    allowed=True,
                    firewall_decision=decision,
                    error=f"Process killed after {runtime_timeout}s timeout constraint",
                )

            result = ShellExecutionResult(
                command=command,
                stdout=captured.stdout,
                stderr=captured.stderr,
                exit_code=captured.returncode,
                duration_seconds=duration,
                allowed=True,
                firewall_decision=decision,
            )

            self.record_execution_result(
                action_id=envelope.action_id,
                tool="shell",
                executed=True,
                result={"exit_code": captured.returncode, "duration_seconds": duration},
                error_class=None if captured.returncode == 0 else f"EXIT_{captured.returncode}",
            )
            return result

        except Exception as e:
            duration = time.perf_counter() - start_t
            self.record_execution_result(
                action_id=envelope.action_id,
                tool="shell",
                executed=False,
                error_class=type(e).__name__,
            )
            return ShellExecutionResult(
                command=command,
                stdout="",
                stderr=str(e),
                exit_code=-1,
                duration_seconds=duration,
                allowed=True,
                firewall_decision=decision,
                error=f"Subprocess spawn failure: {str(e)}",
            )
