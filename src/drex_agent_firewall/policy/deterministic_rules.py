"""Hard deterministic policy rules that cannot be overridden by probabilistic models."""

from __future__ import annotations

import re
from typing import Optional, Tuple
from urllib.parse import urlparse

from drex_agent_firewall.normalizers.context_normalizer import SECRET_PATH_KEYWORDS
from drex_agent_firewall.schemas.config import FirewallConfig
from drex_agent_firewall.schemas.decision import FinalDecision
from drex_agent_firewall.schemas.envelope import ActionEnvelope
from drex_agent_firewall.security.path_validator import PathValidator
from drex_agent_firewall.security.redactor import SecretRedactor


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
        self._compiled_shell_patterns = [
            re.compile(p, re.IGNORECASE) for p in config.shell.forbidden_patterns
        ]

    def evaluate(self, envelope: ActionEnvelope) -> Optional[DeterministicRuleResult]:
        """Check all hard rules. Returns DeterministicRuleResult if a rule triggers, else None."""

        # 1. Rule: Hard Forbidden Shell Commands
        if envelope.tool.lower() == "shell":
            cmd = str(envelope.arguments.get("command") or envelope.resource_target or "")
            for pattern in self._compiled_shell_patterns:
                if pattern.search(cmd):
                    return DeterministicRuleResult(
                        triggered=True,
                        decision=FinalDecision.BLOCK,
                        rule_name="HARD_RULE_FORBIDDEN_SHELL_COMMAND",
                        reason=f"Command matches forbidden pattern: {pattern.pattern}",
                    )

        # 2. Rule: Hard Blocked Network Destinations / SSRF
        if envelope.network_access or envelope.tool.lower() in {"http", "network"}:
            url = str(envelope.arguments.get("url") or envelope.resource_target or "")
            if url:
                parsed = urlparse(url)
                hostname = (parsed.hostname or "").lower()
                for blocked in self.config.network.blocked_domains:
                    if hostname == blocked.lower() or hostname.endswith("." + blocked.lower()):
                        return DeterministicRuleResult(
                            triggered=True,
                            decision=FinalDecision.BLOCK,
                            rule_name="HARD_RULE_BLOCKED_NETWORK_TARGET",
                            reason=f"Network destination '{hostname}' is explicitly blocked (matches rule '{blocked}')",
                        )

        # 3. Rule: Unredacted or Detected Secret Transmission to External Endpoints
        if envelope.credential_access and (envelope.external_write or envelope.network_access or envelope.tool.lower() == "http"):
            return DeterministicRuleResult(
                triggered=True,
                decision=FinalDecision.BLOCK,
                rule_name="HARD_RULE_SECRET_TRANSMISSION_EXTERNAL",
                reason="Attempted transmission of credentials or secrets to external network endpoint",
            )

        # 4. Rule: Direct Credential Access / Secret Files Exfiltration
        if envelope.credential_access and envelope.tool.lower() in {"filesystem", "shell"}:
            target_lower = envelope.resource_target.lower()
            if any(k in target_lower for k in SECRET_PATH_KEYWORDS + ["passwd", "shadow"]):
                return DeterministicRuleResult(
                    triggered=True,
                    decision=FinalDecision.BLOCK,
                    rule_name="HARD_RULE_CREDENTIAL_ACCESS_FORBIDDEN",
                    reason=f"Access to sensitive credential/secret resource '{envelope.resource_target}' is forbidden",
                )

        # 5. Rule: Filesystem Root Confinement & Path Traversal Escape
        if envelope.tool.lower() == "filesystem" or envelope.filesystem_write:
            path_target = str(envelope.arguments.get("path") or envelope.arguments.get("file_path") or envelope.resource_target or "")
            if path_target:
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

        # 6. Rule: Forbidden Git Force Push to Protected/Remote Repos
        if envelope.tool.lower() == "git" and envelope.operation.lower() == "push":
            cmd_args = str(envelope.arguments)
            if "--force" in cmd_args or "-f" in cmd_args or "+ref" in cmd_args or "+master" in cmd_args or "+main" in cmd_args or envelope.arguments.get("force"):
                return DeterministicRuleResult(
                    triggered=True,
                    decision=FinalDecision.BLOCK,
                    rule_name="HARD_RULE_GIT_FORCE_PUSH_FORBIDDEN",
                    reason="Git force-push (+ref / --force) is strictly forbidden by policy",
                )

        return None
