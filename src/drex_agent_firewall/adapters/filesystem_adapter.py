"""Filesystem adapter enforcing root confinement, symlink resolution, and hash tracking."""

from __future__ import annotations

import hashlib
import os
import shutil
from pathlib import Path
from typing import Any, Dict, List, Optional

from drex_agent_firewall.security.safe_filesystem import parent_fd, regular_fd, digest
from contextlib import ExitStack
import stat

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

    def list_dir(self, path: str, cwd: Optional[str] = None) -> FilesystemResult:
        return self._guarded_fs_op("list_dir", path, cwd=cwd)

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

        # Open trusted ancestors once; operations never reopen canonical paths.
        out_content = None
        prev_hash = new_hash = None
        prev_size = new_size = None
        try:
            with ExitStack() as stack:
                parent, leaf = stack.enter_context(parent_fd(
                    canonical_path, decision.constraints.allowed_paths,
                    create=operation in {"create", "modify", "mkdir"},
                ))
                if operation in {"read", "create", "modify"}:
                    writing = operation != "read"
                    data = (content or "").encode("utf-8")
                    if writing and len(data) > (decision.constraints.max_bytes_written or 10 * 1024 * 1024):
                        raise ConstraintViolation("Write exceeds max_bytes_written")
                    fd = regular_fd(parent, leaf, write=writing)
                    stack.callback(os.close, fd)
                    prev_size = os.fstat(fd).st_size
                    prev_hash = digest(fd)
                    if writing:
                        os.ftruncate(fd, 0)
                        with os.fdopen(os.dup(fd), "wb") as stream:
                            stream.write(data)
                            stream.flush()
                    else:
                        out_content = os.read(fd, decision.constraints.max_output_bytes or 1024 * 1024).decode("utf-8", errors="replace")
                    new_size = os.fstat(fd).st_size
                    new_hash = digest(fd)
                elif operation == "mkdir":
                    try:
                        os.mkdir(leaf, dir_fd=parent)
                    except FileExistsError:
                        fd = os.open(leaf, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
                        os.close(fd)
                elif operation == "delete":
                    try:
                        info = os.stat(leaf, dir_fd=parent, follow_symlinks=False)
                    except FileNotFoundError:
                        info = None
                    if info and stat.S_ISDIR(info.st_mode):
                        if not shutil.rmtree.avoids_symlink_attacks:
                            raise PermissionError("SAFE_RECURSIVE_DELETE_UNAVAILABLE")
                        shutil.rmtree(leaf, dir_fd=parent)
                    elif info:
                        os.unlink(leaf, dir_fd=parent)
                elif operation == "rename" and canonical_dest:
                    dest_parent, dest_leaf = stack.enter_context(parent_fd(canonical_dest, decision.constraints.allowed_paths))
                    os.rename(leaf, dest_leaf, src_dir_fd=parent, dst_dir_fd=dest_parent)
                elif operation in {"list_dir", "list_directory"}:
                    fd = os.open(leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
                    stack.callback(os.close, fd)
                    info = os.fstat(fd)
                    if stat.S_ISDIR(info.st_mode):
                        out_content = "\n".join(sorted(os.listdir(fd)))
                    elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
                        out_content = leaf
                    else:
                        raise PermissionError("UNSAFE_FILE_TYPE_OR_HARDLINK")

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
                allowed=False,
                firewall_decision=decision,
                error=f"Filesystem operation failed: {str(e)}",
            )
