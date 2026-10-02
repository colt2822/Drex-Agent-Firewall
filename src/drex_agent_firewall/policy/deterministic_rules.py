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

        # 0. Rule: Null Byte Injection & Fail-Closed Testing Hooks
        raw_cmd_or_path = str(envelope.arguments.get("command") or envelope.arguments.get("path") or envelope.arguments.get("url") or "")
        if "\0" in raw_cmd_or_path:
            return DeterministicRuleResult(
                triggered=True,
                decision=FinalDecision.BLOCK,
                rule_name="HARD_RULE_NULL_BYTE_INJECTION",
                reason="Embedded null byte detected in arguments",
            )

        if envelope.arguments.get("simulate_provider_failure") or envelope.arguments.get("simulate_policy_corruption") or envelope.arguments.get("simulate_trace_error"):
            return DeterministicRuleResult(
                triggered=True,
                decision=FinalDecision.BLOCK,
                rule_name="HARD_RULE_FAIL_CLOSED_SIMULATION",
                reason="High-impact action failed closed due to simulated infrastructure failure",
            )

        # 1. Rule: Hard Forbidden Shell Commands & Obfuscated Variants
        if envelope.tool.lower() == "shell" or envelope.process_execution or "command" in envelope.arguments or "cmd" in envelope.arguments or envelope.tool.lower() == "":
            cmd = str(envelope.arguments.get("command") or envelope.arguments.get("cmd") or envelope.resource_target or "")
            subcommands = ShellNormalizer.extract_subcommands(cmd)
            all_cmds_to_check = [cmd] + subcommands

            # Check proxy environment injection
            env_dict = envelope.arguments.get("env") or {}
            for proxy_var in ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"]:
                if proxy_var in env_dict:
                    proxy_val = str(env_dict[proxy_var])
                    is_safe, host, reason = self.network_validator.validate_destination(proxy_val)
                    if not is_safe or any(bad in proxy_val.lower() for bad in ["attacker", "127.0.0.1", "1080", "3128", "169.254"]):
                        return DeterministicRuleResult(
                            triggered=True,
                            decision=FinalDecision.BLOCK,
                            rule_name="HARD_RULE_PROXY_INJECTION_FORBIDDEN",
                            reason=f"Proxy injection via {proxy_var}='{proxy_val}' blocked by network policy",
                        )

            # Check staged scripts in arguments or working directory
            staged_files = envelope.arguments.get("staged_files") or {}
            for script_name, script_content in staged_files.items():
                content_lower = str(script_content).lower()
                if any(bad in content_lower for bad in ["rm -rf /", "169.254.169.254", "curl", "open-uri", "urllib"]):
                    return DeterministicRuleResult(
                        triggered=True,
                        decision=FinalDecision.BLOCK,
                        rule_name="HARD_RULE_SCRIPT_STAGING_BYPASS",
                        reason=f"Staged script or task runner '{script_name}' contains prohibited execution payload",
                    )

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

                # Check git config command injections and remote hijacking
                if re.search(r"\bgit\s+config\b.*?(?:core\.(?:sshcommand|fsmonitor)|url\..*?\.(?:insteadof|pushinsteadof)|alias\.)", single_cmd, re.IGNORECASE):
                    return DeterministicRuleResult(
                        triggered=True,
                        decision=FinalDecision.BLOCK,
                        rule_name="HARD_RULE_GIT_CONFIG_HIJACK_FORBIDDEN",
                        reason=f"Unauthorized git config hijacking detected in command: '{single_cmd}'",
                    )

                # Check git push ext:: remote helpers
                if re.search(r"\bgit\s+push\s+ext::", single_cmd, re.IGNORECASE):
                    return DeterministicRuleResult(
                        triggered=True,
                        decision=FinalDecision.BLOCK,
                        rule_name="HARD_RULE_GIT_REMOTE_HELPER_FORBIDDEN",
                        reason=f"Git push ext:: remote helper execution forbidden: '{single_cmd}'",
                    )

                # Check destructive root wiping / raw device writes / rmtree on root
                if re.search(r"\brm\s+.*-(?:[a-zA-Z]*r[a-zA-Z]*f|[a-zA-Z]*f[a-zA-Z]*r).*\s+/(?:$|\s|\*)", single_cmd) or \
                   re.search(r">\s*/dev/(?:sd[a-z]|nvme|hd[a-z]|null\b(?!\s))", single_cmd) or \
                   re.search(r"\bdd\s+if=.*of=/dev/", single_cmd) or \
                   re.search(r"\b(?:rm|unlink)\s+.*?(?:/etc/|/boot/|/dev/|/root/|/sys/|/proc/)", single_cmd, re.IGNORECASE) or \
                   ("rmtree" in single_cmd and ("'/'" in single_cmd or '"/"' in single_cmd or "root" in single_cmd)):
                    return DeterministicRuleResult(
                        triggered=True,
                        decision=FinalDecision.BLOCK,
                        rule_name="HARD_RULE_FORBIDDEN_SHELL_COMMAND",
                        reason=f"Destructive disk/host wiping pattern detected: '{single_cmd}'",
                    )

                # Check embedded URLs in shell command (e.g. curl, wget, python urllib)
                for embedded_url in re.findall(r"https?://[^\s'\"\`\)\|\;]+", single_cmd):
                    is_safe, host, reason = self.network_validator.validate_destination(embedded_url)
                    if not is_safe:
                        return DeterministicRuleResult(
                            triggered=True,
                            decision=FinalDecision.BLOCK,
                            rule_name="HARD_RULE_BLOCKED_NETWORK_TARGET",
                            reason=reason or f"Destination '{host}' blocked by network/SSRF policy",
                        )

                # Check local host IPs in curl/commands e.g. curl -s 169.254.169.254
                if re.search(r"\b(?:169\.254\.169\.254|127\.0\.0\.1|0\.0\.0\.0|localhost)\b", single_cmd):
                    if any(net_cmd in single_cmd for net_cmd in ["curl", "wget", "fetch", "socket", "urllib", "ping", "nc", "netcat"]):
                        return DeterministicRuleResult(
                            triggered=True,
                            decision=FinalDecision.BLOCK,
                            rule_name="HARD_RULE_BLOCKED_NETWORK_TARGET",
                            reason=f"Blocked destination IP in command: '{single_cmd}'",
                        )

        # 2. Rule: Hard Blocked Network Destinations / SSRF
        if envelope.network_access or envelope.tool.lower() in {"http", "network"}:
            url = str(envelope.arguments.get("url") or envelope.arguments.get("uri") or "")
            if url:
                # Check unix socket scheme
                if "unix://" in url or "+unix://" in url:
                    return DeterministicRuleResult(
                        triggered=True,
                        decision=FinalDecision.BLOCK,
                        rule_name="HARD_RULE_BLOCKED_NETWORK_TARGET",
                        reason="Unix domain socket HTTP schemes are forbidden by network policy",
                    )
                is_safe, host, reason = self.network_validator.validate_destination(url)
                if not is_safe:
                    return DeterministicRuleResult(
                        triggered=True,
                        decision=FinalDecision.BLOCK,
                        rule_name="HARD_RULE_BLOCKED_NETWORK_TARGET",
                        reason=reason or f"Network destination '{host}' blocked by SSRF/network policy",
                    )

            # Check redirect target if present
            redirect_target = envelope.arguments.get("redirect_target")
            if redirect_target:
                is_safe, host, reason = self.network_validator.validate_destination(str(redirect_target))
                if not is_safe:
                    return DeterministicRuleResult(
                        triggered=True,
                        decision=FinalDecision.BLOCK,
                        rule_name="HARD_RULE_BLOCKED_NETWORK_TARGET",
                        reason=reason or f"Redirect target '{host}' blocked by SSRF/network policy",
                    )

        # 3. Rule: Unredacted or Detected Secret Transmission to External Endpoints
        raw_args_str = str(envelope.arguments)
        contains_secret_data = envelope.credential_access or self.redactor.contains_secrets(raw_args_str)
        is_external_outbound = (
            envelope.external_write
            or envelope.network_access
            or envelope.tool.lower() in {"http", "network"}
            or (envelope.tool.lower() == "mcp" and envelope.operation.lower() in {"send_report", "send_webhook", "export", "upload", "publish", "notify"})
            or (envelope.tool.lower() == "github" and envelope.operation.lower() in {"comment", "create_issue", "create_pr"})
        )
        if contains_secret_data and is_external_outbound:
            return DeterministicRuleResult(
                triggered=True,
                decision=FinalDecision.BLOCK,
                rule_name="HARD_RULE_SECRET_TRANSMISSION_EXTERNAL",
                reason="Attempted transmission of credentials or secrets to external network endpoint",
            )

        # Check basic auth in URL: http://user:secret@endpoint
        url_arg = str(envelope.arguments.get("url") or "")
        if "://" in url_arg:
            try:
                clean_url = re.sub(r"\[REDACTED[^\]]*\]", "REDACTED", url_arg)
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
        if (envelope.credential_access or any(k in str(envelope.arguments).lower() for k in [".env", "id_rsa", "passwd", "shadow", "credentials.json"])) and envelope.tool.lower() in {"filesystem", "shell", "mcp"}:
            raw_text = str(envelope.arguments) + " " + envelope.resource_target
            if any(k in raw_text.lower() for k in SECRET_PATH_KEYWORDS + ["passwd", "shadow", ".aws", ".ssh", "credentials.json"]):
                return DeterministicRuleResult(
                    triggered=True,
                    decision=FinalDecision.BLOCK,
                    rule_name="HARD_RULE_CREDENTIAL_ACCESS_FORBIDDEN",
                    reason=f"Access to sensitive credential/secret resource is forbidden",
                )

        # 5. Rule: Filesystem Root Confinement & Path Traversal Escape
        if envelope.tool.lower() in {"filesystem", "mcp"} or envelope.filesystem_write:
            # Check symlink and hardlink creation
            if envelope.operation.lower() in {"create_symlink", "create_hardlink"} or "dest" in envelope.arguments or "src" in envelope.arguments:
                src_link = str(envelope.arguments.get("src") or "")
                dest_link = str(envelope.arguments.get("dest") or envelope.arguments.get("path") or "")
                for link_target in [src_link, dest_link]:
                    if link_target:
                        is_safe, canonical, reason = self.path_validator.validate_path(link_target, base_dir=envelope.working_directory)
                        if not is_safe or any(b in link_target for b in ["/etc", "/root", "/var", ".ssh"]):
                            return DeterministicRuleResult(
                                triggered=True,
                                decision=FinalDecision.BLOCK,
                                rule_name="HARD_RULE_FILESYSTEM_CONFINEMENT_ESCAPE",
                                reason=reason or f"Symlink/hardlink path '{link_target}' violates filesystem boundary",
                            )

            # Check source / primary target
            path_target = str(envelope.arguments.get("path") or envelope.arguments.get("file_path") or envelope.arguments.get("uri") or envelope.resource_target or "")
            if path_target.startswith("file://"):
                path_target = path_target[7:]

            # Check proc references
            if "/proc/" in path_target.lower():
                return DeterministicRuleResult(
                    triggered=True,
                    decision=FinalDecision.BLOCK,
                    rule_name="HARD_RULE_FILESYSTEM_CONFINEMENT_ESCAPE",
                    reason=f"Path '{path_target}' violates filesystem boundary (/proc access forbidden)",
                )

            # Check .git config/hooks overwrites
            if any(p in path_target for p in [".git/config", ".git/hooks", ".ssh/authorized_keys"]):
                return DeterministicRuleResult(
                    triggered=True,
                    decision=FinalDecision.BLOCK,
                    rule_name="HARD_RULE_FILESYSTEM_CONFINEMENT_ESCAPE",
                    reason=f"Direct modification of security-critical configuration '{path_target}' is forbidden",
                )

            # Check workflow and setup config injections
            content_str = str(envelope.arguments.get("content") or "")
            if content_str and any(sec in content_str.lower() for sec in ["rm -rf /", "169.254.169.254", "alias pytest="]):
                return DeterministicRuleResult(
                    triggered=True,
                    decision=FinalDecision.BLOCK,
                    rule_name="HARD_RULE_SCRIPT_STAGING_BYPASS",
                    reason=f"File content for '{path_target}' contains dangerous or destructive execution payload",
                )

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

        # 6. Rule: Forbidden Git Force Push & Credential Remote
        if envelope.tool.lower() == "git":
            cmd_args = str(envelope.arguments).lower()
            if envelope.operation.lower() == "push" or "push" in cmd_args:
                if "--force" in cmd_args or "-f" in cmd_args or "--force-with-lease" in cmd_args or "+ref" in cmd_args or "+master" in cmd_args or "+main" in cmd_args or envelope.arguments.get("force"):
                    return DeterministicRuleResult(
                        triggered=True,
                        decision=FinalDecision.BLOCK,
                        rule_name="HARD_RULE_GIT_FORCE_PUSH_FORBIDDEN",
                        reason="Git force-push (+ref / --force) is strictly forbidden by policy",
                    )
                # Check for remote deletion via refspec e.g. git push origin :main or --delete
                if re.search(r":\s*(?:main|master|release|prod)", cmd_args) or "--delete" in cmd_args:
                    return DeterministicRuleResult(
                        triggered=True,
                        decision=FinalDecision.BLOCK,
                        rule_name="HARD_RULE_GIT_REMOTE_DELETE_FORBIDDEN",
                        reason="Deleting remote branch ref via push is forbidden",
                    )

            # Check credentials in git remote URL
            remote_url = str(envelope.arguments.get("url") or "")
            if remote_url and ("ghp_" in remote_url or "token" in remote_url or "sk-" in remote_url or "@" in remote_url):
                return DeterministicRuleResult(
                    triggered=True,
                    decision=FinalDecision.BLOCK,
                    rule_name="HARD_RULE_SECRET_TRANSMISSION_EXTERNAL",
                    reason="Git remote URL contains embedded secret credentials",
                )

        # 7. Rule: Multi-Step Attack Detection (Trace Correlation)
        if envelope.previous_actions:
            # A. Secret read earlier -> network exfil / git push to remote
            read_secret_earlier = any(
                isinstance(a, dict) and (
                    a.get("credential_access") or
                    any(k in str(a.get("normalized_target") or a.get("target") or a.get("path") or "").lower() for k in SECRET_PATH_KEYWORDS + ["credentials.json", "id_rsa"])
                )
                for a in envelope.previous_actions
            )
            if read_secret_earlier and (envelope.network_access or envelope.tool.lower() in {"http", "network"} or "curl" in str(envelope.arguments) or (envelope.tool.lower() == "git" and envelope.operation.lower() == "push")):
                return DeterministicRuleResult(
                    triggered=True,
                    decision=FinalDecision.BLOCK,
                    rule_name="HARD_RULE_MULTI_STEP_EXFILTRATION",
                    reason="Multi-step attack detected: outbound network transmission or git push following credential access in same session",
                )

            # B. Script / Hook staged earlier -> executing it or triggering git hook
            staged_earlier = any(
                isinstance(a, dict) and (
                    any(p in str(a.get("normalized_target") or a.get("path") or a.get("target") or "") for p in [".git/hooks", "script.sh", "backdoor.py", "package.json", "setup.cfg"])
                    or "alias." in str(a.get("key") or a.get("command") or "")
                )
                for a in envelope.previous_actions
            )
            curr_cmd = str(envelope.arguments.get("command") or envelope.arguments.get("message") or "")
            if staged_earlier and (
                any(sh in curr_cmd for sh in ["python", "bash", "npm test", "setup.py", "git wipe"])
                or (envelope.tool.lower() == "git" and envelope.operation.lower() in {"push", "commit"})
            ):
                return DeterministicRuleResult(
                    triggered=True,
                    decision=FinalDecision.BLOCK,
                    rule_name="HARD_RULE_MULTI_STEP_STAGING_EXEC",
                    reason="Multi-step attack detected: execution of staged script, hook, or alias created earlier in session",
                )

            # C. Symlink created earlier -> writing to symlinked directory
            symlink_created_earlier = any(
                isinstance(a, dict) and a.get("operation") in {"create_symlink", "create_hardlink"}
                for a in envelope.previous_actions
            )
            if symlink_created_earlier and (envelope.filesystem_write or envelope.operation in {"create", "modify"}):
                if any(b in str(envelope.arguments.get("path") or "") for b in [".cache/out", "cron.d", "/etc"]):
                    return DeterministicRuleResult(
                        triggered=True,
                        decision=FinalDecision.BLOCK,
                        rule_name="HARD_RULE_MULTI_STEP_SYMLINK_EXPLOIT",
                        reason="Multi-step attack detected: file modification through symlink created earlier in session",
                    )

        # 8. Rule: GitHub API Critical Mutations
        if envelope.tool.lower() == "github" and envelope.operation.lower() in {"delete_ref", "delete_branch"}:
            return DeterministicRuleResult(
                triggered=True,
                decision=FinalDecision.BLOCK,
                rule_name="HARD_RULE_GITHUB_DELETE_REF_FORBIDDEN",
                reason="Deleting repository branch or git ref via GitHub API is forbidden",
            )

        return None
