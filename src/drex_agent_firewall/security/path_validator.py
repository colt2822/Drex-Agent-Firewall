"""Path validation and canonical confinement engine.

Prevents path traversal, symlink escape, and unauthorized root access.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import List, Optional, Tuple


class PathValidator:
    """Validates filesystem paths against allowed roots and blocked lists."""

    def __init__(self, allowed_roots: Optional[List[str]] = None, blocked_paths: Optional[List[str]] = None):
        self.allowed_roots = [
            os.path.realpath(os.path.abspath(os.path.expanduser(r)))
            for r in (allowed_roots or [os.getcwd()])
        ]
        self.blocked_paths = [
            os.path.realpath(os.path.abspath(os.path.expanduser(b)))
            for b in (blocked_paths or [])
        ]

    def canonicalize(self, target_path: str, base_dir: Optional[str] = None) -> str:
        """Resolve symlinks, handle relative paths, and canonicalize path."""
        target = str(target_path).strip()
        # Check for null byte injection
        if "\0" in target:
            raise ValueError("Null byte detected in path")

        if base_dir:
            base_real = os.path.realpath(os.path.abspath(os.path.expanduser(base_dir)))
            combined = os.path.join(base_real, target)
        else:
            combined = os.path.expanduser(target)

        # Canonicalize resolving symlinks and normalizing . and ..
        return os.path.realpath(os.path.abspath(combined))

    def is_within_root(self, canonical_target: str, canonical_root: str) -> bool:
        """Check if target path is strictly within or equal to root."""
        try:
            rel = os.path.relpath(canonical_target, canonical_root)
            return rel == "." or not rel.startswith("..")
        except ValueError:
            return False

    def validate_path(
        self,
        target_path: str,
        base_dir: Optional[str] = None,
        custom_allowed_roots: Optional[List[str]] = None,
        custom_blocked_paths: Optional[List[str]] = None,
    ) -> Tuple[bool, str, Optional[str]]:
        """
        Validate whether target path is safe to access.
        Returns: (is_safe, canonical_path, error_reason_if_any)
        """
        try:
            canonical = self.canonicalize(target_path, base_dir=base_dir)
        except Exception as e:
            return False, target_path, f"Path canonicalization failure: {str(e)}"

        roots = (
            [os.path.realpath(os.path.abspath(os.path.expanduser(r))) for r in custom_allowed_roots]
            if custom_allowed_roots is not None
            else self.allowed_roots
        )

        blocked = (
            [os.path.realpath(os.path.abspath(os.path.expanduser(b))) for b in custom_blocked_paths]
            if custom_blocked_paths is not None
            else self.blocked_paths
        )

        # Check blocked paths first
        for b in blocked:
            if canonical == b or self.is_within_root(canonical, b):
                return False, canonical, f"Path '{canonical}' is explicitly blocked (matches rule '{b}')"

        # Check allowed roots
        if roots:
            is_in_allowed = any(self.is_within_root(canonical, r) for r in roots)
            if not is_in_allowed:
                return False, canonical, f"Path '{canonical}' escapes allowed root(s): {roots}"

        return True, canonical, None
