"""Enforcement engine for machine-enforceable constraints."""

from __future__ import annotations

import os
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
        """Verify that shell command satisfies allowed prefixes or whitelist."""
        cmd_clean = command.strip()
        if constraints.command_prefix:
            if not cmd_clean.startswith(constraints.command_prefix):
                raise ConstraintViolation(
                    f"Command does not start with enforced prefix '{constraints.command_prefix}'"
                )
        if constraints.allowed_commands:
            matched = any(
                cmd_clean == ac or cmd_clean.startswith(ac + " ")
                for ac in constraints.allowed_commands
            )
            if not matched:
                raise ConstraintViolation(f"Command not in allowed_commands constraint list: {command}")

    @staticmethod
    def verify_network_domain(url_or_host: str, constraints: Constraints) -> str:
        """Verify destination host complies with domain constraints."""
        if "://" in url_or_host:
            host = urlparse(url_or_host).hostname or ""
        else:
            host = url_or_host.split(":")[0]

        host_lower = host.lower()

        # Denied domains
        for denied in constraints.denied_domains:
            if host_lower == denied.lower() or host_lower.endswith("." + denied.lower()):
                raise ConstraintViolation(f"Domain '{host}' is in denied_domains constraint: {denied}")

        # Allowed domains if configured
        if constraints.allowed_domains:
            matched = any(
                host_lower == allowed.lower() or host_lower.endswith("." + allowed.lower())
                for allowed in constraints.allowed_domains
            )
            if not matched:
                raise ConstraintViolation(f"Domain '{host}' is not in allowed_domains constraint whitelist")

        return host_lower

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
