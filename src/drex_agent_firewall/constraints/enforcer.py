"""Enforcement engine for machine-enforceable constraints."""

from __future__ import annotations

import os
import shlex
import shutil
from typing import List, Optional, Tuple
from urllib.parse import urlparse

from drex_agent_firewall.schemas.constraints import Constraints
from drex_agent_firewall.security.path_validator import PathValidator


class ConstraintViolation(Exception):
    """Raised when an execution adapter encounters a constraint violation."""
    pass


class ConstraintEnforcer:
    """Verifies that an execution request strictly satisfies active constraints."""

    @staticmethod
    def verify_path(path: str, constraints: Constraints, base_dir: Optional[str] = None) -> str:
        """Verify that path complies with constraints. Returns canonical path or raises ConstraintViolation."""
        validator = PathValidator(
            allowed_roots=constraints.allowed_paths,
            blocked_paths=constraints.denied_paths,
        )
        is_safe, canonical, reason = validator.validate_path(path, base_dir=base_dir)
        if not is_safe:
            raise ConstraintViolation(f"Constraint path violation: {reason}")
        return canonical

    @staticmethod
    def verify_command(command: str, constraints: Constraints) -> None:
        """Verify constrained commands as a single executable, never as shell text."""
        cmd_clean = command.strip()
        constrained = bool(constraints.command_prefix or constraints.allowed_commands)
        if constrained:
            try:
                argv = shlex.split(cmd_clean, posix=True)
            except ValueError as exc:
                raise ConstraintViolation(f"Malformed constrained command: {exc}") from exc
            if not argv or any(ch in cmd_clean for ch in ";&|><`$\n\r(){}"):
                raise ConstraintViolation("Shell syntax is forbidden when command constraints are active")
            executable = shutil.which(argv[0])
            if executable is None:
                raise ConstraintViolation(f"Constrained executable not found: {argv[0]}")
            real_executable = os.path.realpath(executable)
            allowed = set(constraints.allowed_commands)
            if constraints.command_prefix:
                allowed.add(constraints.command_prefix)
            matched = False
            for item in allowed:
                try:
                    expected = shlex.split(item)
                except ValueError:
                    continue
                if not expected:
                    continue
                expected_exe = shutil.which(expected[0])
                if expected_exe and os.path.realpath(expected_exe) == real_executable and argv[:len(expected)] == expected:
                    matched = True
            if not matched:
                raise ConstraintViolation(f"Command does not match an allowed executable/argv: {command}")
            return

    @staticmethod
    def verify_network_domain(url_or_host: str, constraints: Constraints) -> str:
        """Verify destination host complies with domain constraints and SSRF rules."""
        from drex_agent_firewall.security.network_validator import NetworkValidator

        validator = NetworkValidator(
            allowed_domains=constraints.allowed_domains,
            blocked_domains=constraints.denied_domains,
            block_private_ips=True,
        )
        is_safe, canonical_host, reason = validator.validate_destination(url_or_host)
        if not is_safe:
            raise ConstraintViolation(f"Constraint network violation: {reason}")
        return canonical_host

    @staticmethod
    def verify_mutation(operation_is_write: bool, constraints: Constraints) -> None:
        """Verify that write operations are not attempted under read_only constraint."""
        if constraints.read_only and operation_is_write:
            raise ConstraintViolation("Write/mutation rejected: read_only constraint is active")

    @staticmethod
    def verify_git_push(is_force: bool, branch: Optional[str], constraints: Constraints) -> None:
        """Verify git push constraints."""
        if constraints.no_force_push and is_force:
            raise ConstraintViolation("Git force push rejected: no_force_push constraint is active")
        if constraints.branch_only and branch in {"main", "master", "release", "prod"}:
            raise ConstraintViolation(f"Git push to protected branch '{branch}' rejected: branch_only constraint is active")
