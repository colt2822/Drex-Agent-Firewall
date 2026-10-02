"""Policy-aware Git adapter differentiating local reversible operations from remote writes."""

from __future__ import annotations

import os
import subprocess
from typing import Any, Dict, List, Optional

from drex_agent_firewall.adapters.base import BaseAdapter
from drex_agent_firewall.constraints.enforcer import ConstraintEnforcer, ConstraintViolation
from drex_agent_firewall.security.environment import filter_environment
from drex_agent_firewall.schemas.decision import FirewallDecision
from drex_agent_firewall.utils.process_io import bounded_communicate


class GitResult:
    def __init__(
        self,
        operation: str,
        allowed: bool,
        firewall_decision: FirewallDecision,
        stdout: str = "",
        stderr: str = "",
        exit_code: int = 0,
        error: Optional[str] = None,
    ):
        self.operation = operation
        self.allowed = allowed
        self.firewall_decision = firewall_decision
        self.stdout = stdout
        self.stderr = stderr
        self.exit_code = exit_code
        self.error = error

    def to_dict(self) -> Dict[str, Any]:
        return {
            "operation": self.operation,
            "allowed": self.allowed,
            "decision": self.firewall_decision.decision.value,
            "exit_code": self.exit_code,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "error": self.error,
        }


class GitAdapter(BaseAdapter):
    """Guarded Git adapter with strict differentiation between local inspections and remote pushes."""

    def status(self, repo_dir: Optional[str] = None) -> GitResult:
        return self._run_git("status", ["status", "--porcelain"], repo_dir=repo_dir)

    def diff(self, repo_dir: Optional[str] = None) -> GitResult:
        return self._run_git("diff", ["diff"], repo_dir=repo_dir)

    def branch(self, repo_dir: Optional[str] = None) -> GitResult:
        return self._run_git("branch", ["branch", "-a"], repo_dir=repo_dir)

    def add(self, files: List[str], repo_dir: Optional[str] = None) -> GitResult:
        return self._run_git("add", ["add"] + files, repo_dir=repo_dir, extra_args={"files": files})

    def commit(self, message: str, repo_dir: Optional[str] = None) -> GitResult:
        return self._run_git("commit", ["commit", "-m", message], repo_dir=repo_dir, extra_args={"message": message})

    def checkout(self, target: str, create_branch: bool = False, repo_dir: Optional[str] = None) -> GitResult:
        args = ["checkout", "-b", target] if create_branch else ["checkout", target]
        return self._run_git("checkout", args, repo_dir=repo_dir, extra_args={"target": target})

    def push(
        self,
        remote: str = "origin",
        branch: str = "main",
        force: bool = False,
        repo_dir: Optional[str] = None,
    ) -> GitResult:
        args = ["push", remote, branch]
        if force:
            args.append("--force")
        return self._run_git(
            "push",
            args,
            repo_dir=repo_dir,
            extra_args={"remote": remote, "branch": branch, "force": force},
        )

    def reset(self, target: str = "HEAD", hard: bool = False, repo_dir: Optional[str] = None) -> GitResult:
        args = ["reset", "--hard", target] if hard else ["reset", target]
        return self._run_git("reset", args, repo_dir=repo_dir, extra_args={"target": target, "hard": hard})

    def clean(self, force: bool = False, repo_dir: Optional[str] = None) -> GitResult:
        args = ["clean", "-fd"] if force else ["clean", "-n"]
        return self._run_git("clean", args, repo_dir=repo_dir, extra_args={"force": force})

    def _run_git(
        self,
        operation: str,
        git_cmd_args: List[str],
        repo_dir: Optional[str] = None,
        extra_args: Optional[Dict[str, Any]] = None,
    ) -> GitResult:
        working_dir = repo_dir or os.getcwd()
        args_payload = {"operation": operation, "repo_dir": working_dir, "command": f"git {' '.join(git_cmd_args)}"}
        if extra_args:
            args_payload.update(extra_args)

        context = {"cwd": working_dir, "git_branch": extra_args.get("branch") if extra_args else None}

        envelope, decision = self.evaluate_action(
            tool="git",
            operation=operation,
            arguments=args_payload,
            context=context,
        )

        if not decision.allowed:
            self.record_execution_result(
                action_id=envelope.action_id,
                tool="git",
                executed=False,
                error_class="FIREWALL_POLICY_BLOCKED",
            )
            return GitResult(
                operation=operation,
                allowed=False,
                firewall_decision=decision,
                exit_code=-1,
                error=f"Blocked by firewall: {decision.reason}",
            )

        # Enforce git specific constraints
        try:
            if operation == "push":
                is_force = bool(extra_args and extra_args.get("force"))
                branch_name = extra_args.get("branch") if extra_args else None
                ConstraintEnforcer.verify_git_push(is_force, branch_name, decision.constraints)
        except ConstraintViolation as cv:
            self.record_execution_result(
                action_id=envelope.action_id,
                tool="git",
                executed=False,
                error_class="CONSTRAINT_VIOLATION",
            )
            return GitResult(
                operation=operation,
                allowed=False,
                firewall_decision=decision,
                exit_code=-2,
                error=f"Constraint violation: {str(cv)}",
            )

        # Run git command
        try:
            cmd = ["git"] + git_cmd_args
            proc = subprocess.Popen(
                cmd,
                cwd=working_dir,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=filter_environment(os.environ),
            )
            captured = bounded_communicate(
                proc,
                timeout=decision.constraints.max_runtime_seconds or 30.0,
                max_output_bytes=decision.constraints.max_output_bytes or (1024 * 1024),
            )
            res = GitResult(
                operation=operation,
                allowed=True,
                firewall_decision=decision,
                stdout=captured.stdout,
                stderr=captured.stderr,
                exit_code=124 if captured.timed_out else captured.returncode,
                error="Git command timed out" if captured.timed_out else None,
            )
            self.record_execution_result(
                action_id=envelope.action_id,
                tool="git",
                executed=True,
                result=res.to_dict(),
                error_class=(
                    "TIMEOUT_EXPIRED"
                    if captured.timed_out
                    else None if captured.returncode == 0 else f"EXIT_{captured.returncode}"
                ),
            )
            return res
        except Exception as e:
            self.record_execution_result(
                action_id=envelope.action_id,
                tool="git",
                executed=False,
                error_class=type(e).__name__,
            )
            return GitResult(
                operation=operation,
                allowed=True,
                firewall_decision=decision,
                exit_code=-1,
                error=f"Git command failed: {str(e)}",
            )
