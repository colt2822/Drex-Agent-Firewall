"""Filesystem adapter enforcing root confinement, symlink resolution, and hash tracking."""

from __future__ import annotations

import hashlib
import os
import shutil
from pathlib import Path
from typing import Any, Dict, List, Optional

from drex_agent_firewall.adapters.base import BaseAdapter
from drex_agent_firewall.constraints.enforcer import ConstraintEnforcer, ConstraintViolation
from drex_agent_firewall.schemas.decision import FirewallDecision


def _compute_sha256(filepath: str) -> Optional[str]:
    """Compute SHA-256 of file if exists, else None."""
    if not os.path.isfile(filepath):
        return None
    try:
        h = hashlib.sha256()
        with open(filepath, "rb") as f:
            while chunk := f.read(65536):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None


class FilesystemResult:
    def __init__(
        self,
        operation: str,
        path: str,
        allowed: bool,
        firewall_decision: FirewallDecision,
        content: Optional[str] = None,
        previous_hash: Optional[str] = None,
        new_hash: Optional[str] = None,
        size_bytes: Optional[int] = None,
        error: Optional[str] = None,
    ):
        self.operation = operation
        self.path = path
        self.allowed = allowed
        self.firewall_decision = firewall_decision
        self.content = content
        self.previous_hash = previous_hash
        self.new_hash = new_hash
        self.size_bytes = size_bytes
        self.error = error

    def to_dict(self) -> Dict[str, Any]:
        return {
            "operation": self.operation,
            "path": self.path,
            "allowed": self.allowed,
            "decision": self.firewall_decision.decision.value,
            "previous_hash": self.previous_hash,
            "new_hash": self.new_hash,
            "size_bytes": self.size_bytes,
            "error": self.error,
        }


class FilesystemAdapter(BaseAdapter):
    """Guarded filesystem adapter with canonical symlink resolution and hash audit tracking."""

    def read_file(self, path: str, cwd: Optional[str] = None) -> FilesystemResult:
        return self._guarded_fs_op("read", path, cwd=cwd)

    def create_file(self, path: str, content: str, cwd: Optional[str] = None) -> FilesystemResult:
        return self._guarded_fs_op("create", path, content=content, cwd=cwd)

    def modify_file(self, path: str, content: str, cwd: Optional[str] = None) -> FilesystemResult:
        return self._guarded_fs_op("modify", path, content=content, cwd=cwd)

    def delete_file(self, path: str, cwd: Optional[str] = None) -> FilesystemResult:
        return self._guarded_fs_op("delete", path, cwd=cwd)

    def make_directory(self, path: str, cwd: Optional[str] = None) -> FilesystemResult:
        return self._guarded_fs_op("mkdir", path, cwd=cwd)

    def rename_file(self, src_path: str, dest_path: str, cwd: Optional[str] = None) -> FilesystemResult:
        return self._guarded_fs_op("rename", src_path, dest_path=dest_path, cwd=cwd)

    def _guarded_fs_op(
        self,
        operation: str,
        path: str,
        content: Optional[str] = None,
        dest_path: Optional[str] = None,
        cwd: Optional[str] = None,
    ) -> FilesystemResult:
        is_write = operation in {"create", "modify", "delete", "mkdir", "rename"}
        arguments = {
            "path": path,
            "operation": operation,
            "is_write": is_write,
        }
        if dest_path:
            arguments["dest_path"] = dest_path

        context = {"cwd": cwd or os.getcwd()}

        # 1. Firewall Evaluation
        envelope, decision = self.evaluate_action(
            tool="filesystem",
            operation=operation,
            arguments=arguments,
            context=context,
        )

        if not decision.allowed:
            self.record_execution_result(
                action_id=envelope.action_id,
                tool="filesystem",
                executed=False,
                error_class="FIREWALL_POLICY_BLOCKED",
            )
            return FilesystemResult(
                operation=operation,
                path=path,
                allowed=False,
                firewall_decision=decision,
                error=f"Blocked by firewall: {decision.reason}",
            )

        # 2. Check Enforceable Constraints
        try:
            ConstraintEnforcer.verify_mutation(is_write, decision.constraints)
            canonical_path = ConstraintEnforcer.verify_path(path, decision.constraints, base_dir=cwd)
            if dest_path:
                canonical_dest = ConstraintEnforcer.verify_path(dest_path, decision.constraints, base_dir=cwd)
            else:
                canonical_dest = None
        except ConstraintViolation as cv:
            self.record_execution_result(
                action_id=envelope.action_id,
                tool="filesystem",
                executed=False,
                error_class="CONSTRAINT_VIOLATION",
            )
            return FilesystemResult(
                operation=operation,
                path=path,
                allowed=False,
                firewall_decision=decision,
                error=f"Constraint violation: {str(cv)}",
            )

        # 3. Track Pre-Operation State (Hash & Size)
        prev_hash = _compute_sha256(canonical_path)
        prev_size = os.path.getsize(canonical_path) if os.path.isfile(canonical_path) else None

        # 4. Perform Operation
        out_content = None
        try:
            if operation == "read":
                with open(canonical_path, "r", encoding="utf-8", errors="replace") as f:
                    out_content = f.read(decision.constraints.max_output_bytes or (1024 * 1024))
            elif operation in {"create", "modify"}:
                data_to_write = content or ""
                # Check byte limits
                max_bytes = decision.constraints.max_bytes_written or (10 * 1024 * 1024)
                if len(data_to_write.encode("utf-8")) > max_bytes:
                    raise ConstraintViolation(f"Write exceeds max_bytes_written limit of {max_bytes}")
                os.makedirs(os.path.dirname(canonical_path), exist_ok=True)
                with open(canonical_path, "w", encoding="utf-8") as f:
                    f.write(data_to_write)
            elif operation == "delete":
                if os.path.isdir(canonical_path):
                    shutil.rmtree(canonical_path)
                elif os.path.exists(canonical_path):
                    os.remove(canonical_path)
            elif operation == "mkdir":
                os.makedirs(canonical_path, exist_ok=True)
            elif operation == "rename":
                if canonical_dest:
                    os.rename(canonical_path, canonical_dest)

            new_hash = _compute_sha256(canonical_path)
            new_size = os.path.getsize(canonical_path) if os.path.isfile(canonical_path) else None

            res = FilesystemResult(
                operation=operation,
                path=canonical_path,
                allowed=True,
                firewall_decision=decision,
                content=out_content,
                previous_hash=prev_hash,
                new_hash=new_hash,
                size_bytes=new_size or prev_size,
            )

            self.record_execution_result(
                action_id=envelope.action_id,
                tool="filesystem",
                executed=True,
                result=res.to_dict(),
            )
            return res

        except Exception as e:
            self.record_execution_result(
                action_id=envelope.action_id,
                tool="filesystem",
                executed=False,
                error_class=type(e).__name__,
            )
            return FilesystemResult(
                operation=operation,
                path=canonical_path,
                allowed=True,
                firewall_decision=decision,
                error=f"Filesystem operation failed: {str(e)}",
            )
