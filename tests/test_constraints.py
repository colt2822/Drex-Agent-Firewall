"""Tests for ConstraintEnforcer."""

import pytest
from drex_agent_firewall.constraints.enforcer import ConstraintEnforcer, ConstraintViolation
from drex_agent_firewall.schemas.constraints import Constraints


def test_command_prefix_constraint():
    constraints = Constraints(command_prefix="pytest")
    # Allowed
    ConstraintEnforcer.verify_command("pytest tests/", constraints)

    # Disallowed
    with pytest.raises(ConstraintViolation):
        ConstraintEnforcer.verify_command("rm -rf /", constraints)


def test_allowed_commands_constraint():
    constraints = Constraints(allowed_commands=["git status", "git diff"])
    ConstraintEnforcer.verify_command("git status", constraints)
    with pytest.raises(ConstraintViolation):
        ConstraintEnforcer.verify_command("git push", constraints)


@pytest.mark.parametrize("command", ["ls .; id", "ls$(id)", "ls`id`", "ls\\nid", "ls || id"])
def test_command_allowlist_rejects_shell_syntax(command):
    with pytest.raises(ConstraintViolation):
        ConstraintEnforcer.verify_command(command, Constraints(allowed_commands=["ls"]))


def test_command_prefix_matches_executable_not_raw_prefix():
    with pytest.raises(ConstraintViolation):
        ConstraintEnforcer.verify_command("git; id", Constraints(command_prefix="git"))
    ConstraintEnforcer.verify_command("git status --short", Constraints(command_prefix="git"))


def test_read_only_constraint():
    constraints = Constraints(read_only=True)
    ConstraintEnforcer.verify_mutation(operation_is_write=False, constraints=constraints)
    with pytest.raises(ConstraintViolation):
        ConstraintEnforcer.verify_mutation(operation_is_write=True, constraints=constraints)


def test_no_force_push_constraint():
    constraints = Constraints(no_force_push=True)
    ConstraintEnforcer.verify_git_push(is_force=False, branch="main", constraints=constraints)
    with pytest.raises(ConstraintViolation):
        ConstraintEnforcer.verify_git_push(is_force=True, branch="main", constraints=constraints)
