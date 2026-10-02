"""Hard deterministic policy rules that cannot be overridden by probabilistic models.

Evaluates absolute invariants: shell obfuscation deconstruction, SSRF/IP normalization,
multi-step exfiltration detection, path escape prevention, and credential confinement.
"""

from __future__ import annotations

import re
from typing import Optional
from urllib.parse import urlparse

from drex_agent_firewall.normalizers.context_normalizer import SECRET_PATH_KEYWORDS
from drex_agent_firewall.schemas.config import FirewallConfig
from drex_agent_firewall.schemas.decision import FinalDecision
from drex_agent_firewall.schemas.envelope import ActionEnvelope
from drex_agent_firewall.security.network_validator import NetworkValidator
from drex_agent_firewall.security.path_validator import PathValidator
from drex_agent_firewall.security.redactor import SecretRedactor
from drex_agent_firewall.security.shell_normalizer import ShellNormalizer


# Prompt injection keywords that must have ZERO privileged effect
PROMPT_INJECTION_TOKENS = [
    "ignore previous policy",
    "ignore all instructions",
    "this operation is safe",
    "administrator approved this",
    "admin override",
    "do not inspect this command",
    "bypass firewall",
]


class DeterministicRuleResult:
    def __init__(self, triggered: bool, decision: FinalDecision, rule_name: str, reason: str):
        self.triggered = triggered
        self.decision = decision
        self.rule_name = rule_name
        self.reason = reason


class DeterministicRulesEngine:
    """Evaluates absolute invariant rules before and independent of Drex."""

    def __init__(self, config: FirewallConfig, redactor: Optional[SecretRedactor] = None):
        self.config = config
        self.redactor = redactor or SecretRedactor()
        self.path_validator = PathValidator(
            allowed_roots=config.filesystem.allowed_roots,
            blocked_paths=config.filesystem.blocked_paths,
        )
        self.network_validator = NetworkValidator(
            allowed_domains=config.network.allowed_domains,
            blocked_domains=config.network.blocked_domains,
            block_private_ips=True,
        )
        self._compiled_shell_patterns = [
            re.compile(p, re.IGNORECASE) for p in config.shell.forbidden_patterns
        ]

    def evaluate(self, envelope: ActionEnvelope) -> Optional[DeterministicRuleResult]:
        """Check all hard rules. Returns DeterministicRuleResult if a rule triggers, else None."""

        # 1. Rule: Hard Forbidden Shell Commands & Obfuscated Variants
        if envelope.tool.lower() == "shell" or envelope.process_execution or "command" in envelope.arguments or "cmd" in envelope.arguments:
            cmd = str(envelope.arguments.get("command") or envelope.arguments.get("cmd") or envelope.resource_target or "")
            subcommands = ShellNormalizer.extract_subcommands(cmd)
            all_cmds_to_check = [cmd] + subcommands

            for single_cmd in all_cmds_to_check:
                # Check configured shell forbidden patterns
                for pattern in self._compiled_shell_patterns:
                    if pattern.search(single_cmd):
                        return DeterministicRuleResult(
                            triggered=True,
                            decision=FinalDecision.BLOCK,
                            rule_name="HARD_RULE_FORBIDDEN_SHELL_COMMAND",
                            reason=f"Command '{single_cmd}' matches forbidden pattern: {pattern.pattern}",
                        )

                # Check shell-wrapped git force pushes (direct or through alias config)
                if re.search(r"\bgit\s+(?:config\s+alias\.[a-zA-Z0-9_\-]+\s+['\"]?.*)?push\b.*?(?:--force|-f\b|\+ref|\+master|\+main)", single_cmd, re.IGNORECASE):
                    return DeterministicRuleResult(
                        triggered=True,
                        decision=FinalDecision.BLOCK,
                        rule_name="HARD_RULE_GIT_FORCE_PUSH_FORBIDDEN",
                        reason=f"Git force push detected in shell command: '{single_cmd}'",
                    )

                # Check destructive root wiping / raw device writes
                if re.search(r"\brm\s+.*-(?:[a-zA-Z]*r[a-zA-Z]*f|[a-zA-Z]*f[a-zA-Z]*r).*\s+/(?:$|\s|\*)", single_cmd) or \
                   re.search(r">\s*/dev/(?:sd[a-z]|nvme|hd[a-z]|null\b(?!\s))", single_cmd) or \
                   re.search(r"\bdd\s+if=.*of=/dev/", single_cmd):
                    return DeterministicRuleResult(
                        triggered=True,
                        decision=FinalDecision.BLOCK,
                        rule_name="HARD_RULE_FORBIDDEN_SHELL_COMMAND",
                        reason=f"Destructive disk/host wiping pattern detected: '{single_cmd}'",
                    )

        # 2. Rule: Hard Blocked Network Destinations / SSRF (IPv4/IPv6/Decimal/Hex/Octal/Metadata)
        if envelope.network_access or envelope.tool.lower() in {"http", "network"}:
            url = str(envelope.arguments.get("url") or envelope.resource_target or "")
            if url:
                is_safe, host, reason = self.network_validator.validate_destination(url)
                if not is_safe:
                    return DeterministicRuleResult(
                        triggered=True,
                        decision=FinalDecision.BLOCK,
                        rule_name="HARD_RULE_BLOCKED_NETWORK_TARGET",
                        reason=reason or f"Network destination '{host}' blocked by SSRF/network policy",
                    )

        # 3. Rule: Unredacted or Detected Secret Transmission to External Endpoints
        raw_args_str = str(envelope.arguments)
        contains_secret_data = envelope.credential_access or self.redactor.contains_secrets(raw_args_str)
        if contains_secret_data and (envelope.external_write or envelope.network_access or envelope.tool.lower() == "http"):
            return DeterministicRuleResult(
                triggered=True,
                decision=FinalDecision.BLOCK,
                rule_name="HARD_RULE_SECRET_TRANSMISSION_EXTERNAL",
                reason="Attempted transmission of credentials or secrets to external network endpoint",
            )

        # Also check basic auth in URL: http://user:secret@endpoint
        url_arg = str(envelope.arguments.get("url") or "")
        if "://" in url_arg:
            try:
                clean_url = url_arg.replace("[REDACTED]", "REDACTED")
                parsed = urlparse(clean_url)
                if parsed.password or (parsed.username and any(k in parsed.username.lower() for k in ["token", "key", "secret", "ghp_"])):
                    return DeterministicRuleResult(
                        triggered=True,
                        decision=FinalDecision.BLOCK,
                        rule_name="HARD_RULE_SECRET_TRANSMISSION_EXTERNAL",
                        reason="Credential embedded in network request URL",
                    )
            except Exception:
                pass

        # 4. Rule: Direct Credential Access / Secret Files Exfiltration
        if envelope.credential_access and envelope.tool.lower() in {"filesystem", "shell", "mcp"}:
            target_lower = envelope.resource_target.lower()
            if any(k in target_lower for k in SECRET_PATH_KEYWORDS + ["passwd", "shadow", ".aws", ".ssh"]):
                return DeterministicRuleResult(
                    triggered=True,
                    decision=FinalDecision.BLOCK,
                    rule_name="HARD_RULE_CREDENTIAL_ACCESS_FORBIDDEN",
                    reason=f"Access to sensitive credential/secret resource '{envelope.resource_target}' is forbidden",
                )

        # 5. Rule: Filesystem Root Confinement & Path Traversal Escape
        if envelope.tool.lower() in {"filesystem", "mcp"} or envelope.filesystem_write:
            # Check source / primary target
            path_target = str(envelope.arguments.get("path") or envelope.arguments.get("file_path") or envelope.arguments.get("uri") or envelope.resource_target or "")
            if path_target.startswith("file://"):
                path_target = path_target[7:]
            if path_target and (envelope.tool.lower() == "filesystem" or envelope.filesystem_write or ".." in path_target or path_target.startswith("/")):
                is_safe, canonical, reason = self.path_validator.validate_path(
                    path_target,
                    base_dir=envelope.working_directory,
                )
                if not is_safe:
                    return DeterministicRuleResult(
                        triggered=True,
                        decision=FinalDecision.BLOCK,
                        rule_name="HARD_RULE_FILESYSTEM_CONFINEMENT_ESCAPE",
                        reason=reason or f"Path '{path_target}' violates filesystem boundary",
                    )

            # Check destination path (for rename / copy / move)
            dest_target = str(envelope.arguments.get("dest_path") or envelope.arguments.get("destination") or "")
            if dest_target:
                is_safe, canonical, reason = self.path_validator.validate_path(
                    dest_target,
                    base_dir=envelope.working_directory,
                )
                if not is_safe:
                    return DeterministicRuleResult(
                        triggered=True,
                        decision=FinalDecision.BLOCK,
                        rule_name="HARD_RULE_FILESYSTEM_CONFINEMENT_ESCAPE",
                        reason=reason or f"Destination path '{dest_target}' violates filesystem boundary",
                    )

        # 6. Rule: Forbidden Git Force Push to Protected/Remote Repos
        if envelope.tool.lower() == "git" and envelope.operation.lower() == "push":
            cmd_args = str(envelope.arguments).lower()
            if "--force" in cmd_args or "-f" in cmd_args or "--force-with-lease" in cmd_args or "+ref" in cmd_args or "+master" in cmd_args or "+main" in cmd_args or envelope.arguments.get("force"):
                return DeterministicRuleResult(
                    triggered=True,
                    decision=FinalDecision.BLOCK,
                    rule_name="HARD_RULE_GIT_FORCE_PUSH_FORBIDDEN",
                    reason="Git force-push (+ref / --force) is strictly forbidden by policy",
                )
            # Check for remote deletion via refspec e.g. git push origin :main
            if re.search(r":\s*(?:main|master|release|prod)", cmd_args):
                return DeterministicRuleResult(
                    triggered=True,
                    decision=FinalDecision.BLOCK,
                    rule_name="HARD_RULE_GIT_REMOTE_DELETE_FORBIDDEN",
                    reason="Deleting remote branch ref via push is forbidden",
                )

        # 7. Rule: Multi-Step Attack Detection (Trace Correlation)
        if envelope.previous_actions:
            # Check if secret file was read in this session, followed by network exfil
            read_secret_earlier = any(
                isinstance(a, dict) and (
                    a.get("credential_access") or
                    any(k in str(a.get("normalized_target") or a.get("target") or "").lower() for k in SECRET_PATH_KEYWORDS)
                )
                for a in envelope.previous_actions
            )
            if read_secret_earlier and (envelope.network_access or envelope.tool.lower() in {"http", "network"} or "curl" in str(envelope.arguments)):
                return DeterministicRuleResult(
                    triggered=True,
                    decision=FinalDecision.BLOCK,
                    rule_name="HARD_RULE_MULTI_STEP_EXFILTRATION",
                    reason="Multi-step attack detected: network request following credential read in same session",
                )

        return None
