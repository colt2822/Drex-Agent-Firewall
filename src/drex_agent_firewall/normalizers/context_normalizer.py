"""Context normalizer converting heterogeneous agent tool requests into typed ActionEnvelopes."""

from __future__ import annotations

import os
import re
import shlex
import time
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from drex_agent_firewall.schemas.envelope import ActionEnvelope
from drex_agent_firewall.security.redactor import SecretRedactor


# Read-only commands and operations
READ_COMMANDS = {
    "cat", "head", "tail", "ls", "pwd", "grep", "rg", "find", "stat", "file",
    "git status", "git diff", "git log", "git show", "git branch", "echo",
    "which", "whereis", "python -V", "python --version", "node -v", "env",
}

DESTRUCTIVE_COMMANDS = [
    r"\brm\b", r"\bshred\b", r"\bkill\b", r"\bpkill\b", r"\bkillall\b",
    r"\bmkfs\b", r"\bfdisk\b", r"\bdd\b", r">", r"\btruncate\b"
]

NETWORK_COMMANDS = [
    r"\bcurl\b", r"\bwget\b", r"\bssh\b", r"\bscp\b", r"\brsync\b",
    r"\bnc\b", r"\bnetcat\b", r"\btelnet\b", r"\bftp\b", r"\bping\b"
]

SECRET_PATH_KEYWORDS = [
    ".env", "id_rsa", "id_ecdsa", "id_ed25519", ".aws", "credentials",
    "secrets.json", "private.key", "/etc/shadow", "/etc/sudoers",
    ".gnupg", ".git/config", "secring.gpg", "keystore",
]


class ContextNormalizer:
    """Normalizes raw agent tool invocations into typed, secret-scrubbed ActionEnvelopes."""

    def __init__(self, redactor: Optional[SecretRedactor] = None):
        self.redactor = redactor or SecretRedactor()

    def normalize(
        self,
        tool: str,
        operation: str,
        arguments: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None,
        agent_id: str = "agent",
        session_id: str = "default-session",
        parent_action_id: Optional[str] = None,
        trace_id: Optional[str] = None,
    ) -> ActionEnvelope:
        """Construct a validated, normalized, and sanitized ActionEnvelope."""
        ctx = context or {}

        # Detect secrets before scrubbing arguments
        raw_args_str = str(arguments)
        detected_secret_in_args = self.redactor.contains_secrets(raw_args_str)

        # 1. Scrub credentials from raw arguments and context values
        sanitized_arguments = self.redactor.sanitize(arguments)
        working_directory = ctx.get("cwd") or ctx.get("working_directory") or os.getcwd()
        repository = ctx.get("repository") or ctx.get("repo")

        # 2. Derive resource_target and type
        resource_target = ""
        resource_type = "unknown"

        read_only = False
        external_effect = False
        destructive = False
        reversible = True
        credential_access = detected_secret_in_args
        network_access = False
        filesystem_write = False
        process_execution = False
        external_write = False

        tool_lower = tool.lower().strip()
        op_lower = operation.lower().strip()

        # Tool-specific heuristics
        if tool_lower == "shell":
            process_execution = True
            resource_type = "command"
            cmd_raw = str(arguments.get("command") or arguments.get("cmd") or "")
            resource_target = self.redactor.redact_text(cmd_raw)

            cmd_clean = cmd_raw.strip()
            # Check read-only
            if any(cmd_clean == rc or cmd_clean.startswith(rc + " ") for rc in READ_COMMANDS):
                read_only = True
                reversible = True
                destructive = False
            else:
                read_only = False

            # Check destructive
            for pat in DESTRUCTIVE_COMMANDS:
                if re.search(pat, cmd_clean):
                    destructive = True
                    reversible = False
                    break

            # Check network
            for pat in NETWORK_COMMANDS:
                if re.search(pat, cmd_clean):
                    network_access = True
                    external_effect = True
                    break

            # Check credential access
            if any(secret_kw in cmd_clean for secret_kw in SECRET_PATH_KEYWORDS + ["passwd", "shadow"]):
                credential_access = True

        elif tool_lower == "filesystem":
            resource_type = "file"
            path_raw = str(arguments.get("path") or arguments.get("file_path") or arguments.get("target") or "")
            resource_target = path_raw

            if op_lower in {"read", "stat", "list_dir", "exists", "read_file"}:
                read_only = True
                filesystem_write = False
                destructive = False
                reversible = True
            elif op_lower in {"write", "modify", "append", "create", "mkdir", "write_file", "edit_file"}:
                read_only = False
                filesystem_write = True
                destructive = False
                reversible = True
            elif op_lower in {"delete", "remove", "unlink", "rmdir"}:
                read_only = False
                filesystem_write = True
                destructive = True
                reversible = False
            elif op_lower == "rename":
                filesystem_write = True
                read_only = False

            # Secret check
            if any(sec_path in path_raw for sec_path in SECRET_PATH_KEYWORDS):
                credential_access = True

        elif tool_lower == "git":
            resource_type = "repository"
            resource_target = str(arguments.get("repository") or repository or "local-repo")

            if op_lower in {"status", "diff", "log", "show", "branch"}:
                read_only = True
                reversible = True
            elif op_lower in {"add", "commit", "checkout", "stash", "reset", "clean"}:
                read_only = False
                filesystem_write = True
                reversible = (op_lower != "clean")
                destructive = (op_lower in {"clean", "reset"})
            elif op_lower == "push":
                read_only = False
                external_effect = True
                external_write = True
                network_access = True
                force = bool(arguments.get("force") or "+ref" in str(arguments) or "+master" in str(arguments) or "+main" in str(arguments))
                if force:
                    destructive = True
                    reversible = False

        elif tool_lower == "github":
            resource_type = "github_api"
            resource_target = str(arguments.get("repo") or arguments.get("target") or "github.com")

            if op_lower in {"read_issue", "read_pr", "list_issues", "list_prs", "get_file", "search"}:
                read_only = True
                network_access = True
            else:
                read_only = False
                network_access = True
                external_effect = True
                external_write = True

        elif tool_lower == "http":
            resource_type = "url"
            url_raw = str(arguments.get("url") or "")
            resource_target = url_raw
            network_access = True
            method = str(arguments.get("method") or op_lower or "GET").upper()

            if method in {"GET", "HEAD", "OPTIONS"}:
                read_only = True
                external_effect = False
                external_write = False
            else:
                read_only = False
                external_effect = True
                external_write = True

        elif tool_lower == "mcp":
            resource_type = "mcp_tool"
            mcp_tool_name = str(arguments.get("tool_name") or operation)
            resource_target = mcp_tool_name
            op_check = f"{op_lower} {mcp_tool_name.lower()}"
            if any(k in op_check for k in ["read", "list", "get", "status", "view", "fetch"]):
                read_only = True
            elif any(k in op_check for k in ["delete", "remove", "unlink"]):
                destructive = True
                filesystem_write = True
            elif any(k in op_check for k in ["write", "modify", "create", "edit", "update"]):
                filesystem_write = True


        envelope_data: Dict[str, Any] = {
            "agent_id": agent_id,
            "session_id": session_id,
            "parent_action_id": parent_action_id,
            "tool": tool,
            "operation": operation,
            "arguments": sanitized_arguments,
            "resource_type": resource_type,
            "resource_target": resource_target,
            "read_only": read_only,
            "external_effect": external_effect,
            "destructive": destructive,
            "reversible": reversible,
            "credential_access": credential_access,
            "network_access": network_access,
            "filesystem_write": filesystem_write,
            "process_execution": process_execution,
            "external_write": external_write,
            "repository": repository,
            "working_directory": working_directory,
            "requested_at": time.time(),
            "previous_actions": ctx.get("previous_actions", []),
            "current_task": ctx.get("current_task"),
            "known_policy": ctx.get("known_policy"),
            "repository_scope": ctx.get("repository_scope"),
            "allowed_paths": ctx.get("allowed_paths", []),
            "blocked_paths": ctx.get("blocked_paths", []),
            "allowed_domains": ctx.get("allowed_domains", []),
            "blocked_domains": ctx.get("blocked_domains", []),
            "git_branch": ctx.get("git_branch"),
            "git_status": ctx.get("git_status"),
            "human_approval_state": ctx.get("human_approval_state"),
            "metadata": ctx.get("metadata", {}),
        }

        if trace_id:
            envelope_data["trace_id"] = trace_id

        return ActionEnvelope(**envelope_data)
