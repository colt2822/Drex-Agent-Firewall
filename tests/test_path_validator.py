"""Tests for path traversal and symlink confinement validator."""

import os
import pytest
from drex_agent_firewall.security.path_validator import PathValidator


def test_path_within_root(temp_workspace):
    validator = PathValidator(allowed_roots=[str(temp_workspace)])
    is_safe, canonical, reason = validator.validate_path("src/app.py", base_dir=str(temp_workspace))
    assert is_safe
    assert canonical == os.path.realpath(str(temp_workspace / "src" / "app.py"))
    assert reason is None


def test_path_traversal_detection(temp_workspace):
    validator = PathValidator(allowed_roots=[str(temp_workspace)])
    is_safe, canonical, reason = validator.validate_path("../../etc/passwd", base_dir=str(temp_workspace))
    assert not is_safe
    assert "escapes allowed root" in reason


def test_symlink_escape_detection(temp_workspace, tmp_path):
    outside_dir = tmp_path / "outside"
    outside_dir.mkdir()
    secret_file = outside_dir / "secret.txt"
    secret_file.write_text("classified")

    symlink_path = temp_workspace / "link_to_outside"
    os.symlink(str(secret_file), str(symlink_path))

    validator = PathValidator(allowed_roots=[str(temp_workspace)])
    is_safe, canonical, reason = validator.validate_path(str(symlink_path))
    # Must resolve symlink to outside target and reject!
    assert not is_safe
    assert "escapes allowed root" in reason


def test_blocked_path_matching(temp_workspace):
    blocked = temp_workspace / "restricted.key"
    blocked.write_text("secret")

    validator = PathValidator(
        allowed_roots=[str(temp_workspace)],
        blocked_paths=[str(blocked)],
    )
    is_safe, canonical, reason = validator.validate_path(str(blocked))
    assert not is_safe
    assert "explicitly blocked" in reason


def test_file_uri_is_rejected(temp_workspace):
    safe, _, reason = PathValidator(allowed_roots=[str(temp_workspace)]).validate_path("file:///etc/passwd", base_dir=str(temp_workspace))
    assert not safe
    assert "URI schemes" in reason
