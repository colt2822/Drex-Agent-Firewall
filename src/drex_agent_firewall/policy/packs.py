"""Predefined, reusable policy packs for Drex Agent Firewall.

Provides distinct operational guardrail profiles:
- safe-local-coding: Standard developer workstation safe coding
- github-contributor: Open-source PR / issue contributor profile
- read-only-research: Zero mutation / exploration profile
- autonomous-ci: Bounded unattended continuous integration runner
- production-ops: High-assurance operational management
- paranoid: Maximum restriction with mandatory human escalation
"""

from __future__ import annotations

from typing import Dict, List, Optional
from drex_agent_firewall.schemas.config import (
    ConfidenceThresholds,
    FailDisposition,
    FilesystemPolicy,
    FirewallConfig,
    NetworkPolicy,
    ShellPolicy,
)
from drex_agent_firewall.schemas.decision import FinalDecision


POLICY_PACK_DESCRIPTIONS: Dict[str, str] = {
    "safe-local-coding": "Safe local developer workflow allowing bounded workspace edits, testing, and reversible local git commits while blocking secrets, force pushes, and host wipes.",
    "github-contributor": "Permits git branch workflows, issue reading, and bounded PR creation while forbidding remote deletions, force pushes, and unapproved merges.",
    "read-only-research": "Zero filesystem mutations, read-only git operations, safe read commands, and bounded GET queries only.",
    "autonomous-ci": "Permits automated test execution, dependency builds, and temporary test artifacts with strict runtime and network bounds.",
    "production-ops": "High-assurance operations requiring 95%+ confidence for mutations, with production API access and mandatory human escalation for releases or schema alterations.",
    "paranoid": "Zero-trust fail-closed posture blocking all external networks and requiring explicit human approval for any shell command or filesystem write.",
}


def get_safe_local_coding_pack() -> FirewallConfig:
    """Safe local developer workflow."""
    cfg = FirewallConfig()
    cfg.default_policy = FinalDecision.ESCALATE
    cfg.filesystem = FilesystemPolicy(
        allowed_roots=["/workspace", "."],
        blocked_paths=[
            "/etc/shadow", "/etc/sudoers", "/root", "~/.ssh", "~/.aws",
            "~/.gnupg", ".git/config", ".env", "secrets.json",
        ],
        max_files_changed=30,
        max_bytes_written=5 * 1024 * 1024,
    )
    cfg.shell = ShellPolicy(
        forbidden_patterns=[
            r"rm\s+(-[rfRF]+\s+)?/\s*$",
            r"rm\s+-[rfRF]+\s+/\*",
            r">\s*/dev/",
            r"mkfs",
            r"dd\s+if=.*of=/dev/",
            r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:",
            r"chmod\s+-R\s+777",
            r"curl\s+.*\|\s*sh",
            r"wget\s+.*\|\s*sh",
            r"curl\s+.*\|\s*bash",
            r"wget\s+.*\|\s*bash",
            r"git\s+push\s+.*(?:--force|-f\b)",
        ],
        max_runtime_seconds=45.0,
        max_output_bytes=1024 * 1024,
    )
    cfg.network = NetworkPolicy(
        allowed_domains=[],  # Local only
        blocked_domains=["169.254.169.254", "metadata.google.internal", "localhost", "127.0.0.1", "0.0.0.0"],
    )
    cfg.thresholds = ConfidenceThresholds(
        READ=0.70,
        WRITE=0.88,
        DELETE=0.98,
        EXECUTE=0.85,
        NETWORK=0.95,
        AUTH=0.98,
        EXTERNAL_PUBLISH=0.98,
    )
    cfg.fail_disposition = FailDisposition(
        READ=FinalDecision.ALLOW,
        WRITE=FinalDecision.ESCALATE,
        DELETE=FinalDecision.BLOCK,
        EXECUTE=FinalDecision.ESCALATE,
        NETWORK=FinalDecision.BLOCK,
        AUTH=FinalDecision.BLOCK,
        EXTERNAL_PUBLISH=FinalDecision.BLOCK,
    )
    return cfg


def get_github_contributor_pack() -> FirewallConfig:
    """GitHub contributor profile."""
    cfg = FirewallConfig()
    cfg.default_policy = FinalDecision.ESCALATE
    cfg.filesystem = FilesystemPolicy(
        allowed_roots=["/workspace", "."],
        blocked_paths=["~/.ssh", "~/.aws", "/etc/shadow", ".git/config", ".env"],
        max_files_changed=50,
        max_bytes_written=10 * 1024 * 1024,
    )
    cfg.network = NetworkPolicy(
        allowed_domains=["github.com", "api.github.com", "pypi.org", "registry.npmjs.org"],
        blocked_domains=["169.254.169.254", "metadata.google.internal", "localhost", "127.0.0.1", "0.0.0.0"],
    )
    cfg.thresholds = ConfidenceThresholds(
        READ=0.70,
        WRITE=0.90,
        DELETE=0.98,
        EXECUTE=0.90,
        NETWORK=0.85,
        EXTERNAL_PUBLISH=0.90,
    )
    return cfg


def get_read_only_research_pack() -> FirewallConfig:
    """Zero mutation research and exploration profile."""
    cfg = FirewallConfig()
    cfg.default_policy = FinalDecision.BLOCK
    cfg.filesystem = FilesystemPolicy(
        allowed_roots=["/workspace", "."],
        blocked_paths=["/etc/shadow", "~/.ssh", "~/.aws", ".env"],
        max_files_changed=0,
        max_bytes_written=0,
    )
    cfg.shell = ShellPolicy(
        forbidden_patterns=[
            r"\brm\b", r"\bmkdir\b", r"\btouch\b", r"\bcp\b", r"\bmv\b",
            r">", r"\bchmod\b", r"\bchown\b", r"\bgit\s+commit\b", r"\bgit\s+push\b",
        ],
        max_runtime_seconds=15.0,
        max_output_bytes=512 * 1024,
    )
    cfg.network = NetworkPolicy(
        allowed_domains=[],
        blocked_domains=["169.254.169.254", "metadata.google.internal", "localhost", "127.0.0.1", "0.0.0.0"],
    )
    cfg.thresholds = ConfidenceThresholds(
        READ=0.60,
        WRITE=1.00,
        DELETE=1.00,
        EXECUTE=0.95,
        NETWORK=0.99,
    )
    cfg.fail_disposition = FailDisposition(
        READ=FinalDecision.ALLOW,
        WRITE=FinalDecision.BLOCK,
        DELETE=FinalDecision.BLOCK,
        EXECUTE=FinalDecision.BLOCK,
        NETWORK=FinalDecision.BLOCK,
        AUTH=FinalDecision.BLOCK,
        EXTERNAL_PUBLISH=FinalDecision.BLOCK,
    )
    return cfg


def get_autonomous_ci_pack() -> FirewallConfig:
    """Automated CI runner profile."""
    cfg = FirewallConfig()
    cfg.default_policy = FinalDecision.BLOCK
    cfg.filesystem = FilesystemPolicy(
        allowed_roots=["/workspace", "/tmp", "."],
        blocked_paths=["/etc/shadow", "/root", "~/.ssh", ".env"],
        max_files_changed=200,
        max_bytes_written=50 * 1024 * 1024,
    )
    cfg.shell = ShellPolicy(
        forbidden_patterns=[
            r"rm\s+(-[rfRF]+\s+)?/\s*$",
            r">\s*/dev/",
            r"mkfs",
            r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:",
        ],
        max_runtime_seconds=300.0,
        max_output_bytes=5 * 1024 * 1024,
    )
    cfg.network = NetworkPolicy(
        allowed_domains=["pypi.org", "files.pythonhosted.org", "github.com", "registry.npmjs.org"],
        blocked_domains=["169.254.169.254", "metadata.google.internal", "localhost", "127.0.0.1", "0.0.0.0"],
    )
    cfg.thresholds = ConfidenceThresholds(
        READ=0.70,
        WRITE=0.85,
        DELETE=0.95,
        EXECUTE=0.80,
        NETWORK=0.80,
    )
    return cfg


def get_production_ops_pack() -> FirewallConfig:
    """Production operations high-assurance profile."""
    cfg = FirewallConfig()
    cfg.default_policy = FinalDecision.ESCALATE
    cfg.filesystem = FilesystemPolicy(
        allowed_roots=["/workspace", "."],
        blocked_paths=["/etc", "/root", "~/.ssh", "~/.aws", ".git/config", ".env"],
        max_files_changed=10,
        max_bytes_written=1 * 1024 * 1024,
    )
    cfg.shell = ShellPolicy(
        forbidden_patterns=[
            r"rm\s+(-[rfRF]+\s+)?/\s*$",
            r">\s*/dev/",
            r"mkfs",
            r"dd\s+if=.*of=/dev/",
            r"git\s+push\s+.*(?:--force|-f\b)",
            r"DROP\s+TABLE",
            r"DELETE\s+FROM",
        ],
        max_runtime_seconds=20.0,
        max_output_bytes=256 * 1024,
    )
    cfg.network = NetworkPolicy(
        allowed_domains=[],
        blocked_domains=["169.254.169.254", "metadata.google.internal", "localhost", "127.0.0.1", "0.0.0.0"],
    )
    cfg.thresholds = ConfidenceThresholds(
        READ=0.80,
        WRITE=0.95,
        DELETE=0.99,
        EXECUTE=0.95,
        NETWORK=0.95,
        AUTH=0.99,
        EXTERNAL_PUBLISH=0.99,
    )
    cfg.fail_disposition = FailDisposition(
        READ=FinalDecision.ESCALATE,
        WRITE=FinalDecision.BLOCK,
        DELETE=FinalDecision.BLOCK,
        EXECUTE=FinalDecision.BLOCK,
        NETWORK=FinalDecision.BLOCK,
        AUTH=FinalDecision.BLOCK,
        EXTERNAL_PUBLISH=FinalDecision.BLOCK,
    )
    return cfg


def get_paranoid_pack() -> FirewallConfig:
    """Paranoid zero-trust profile with maximum restrictions."""
    cfg = FirewallConfig()
    cfg.default_policy = FinalDecision.BLOCK
    cfg.filesystem = FilesystemPolicy(
        allowed_roots=["/workspace", "."],
        blocked_paths=["/etc", "/root", "/var", "/tmp", "~", ".git", ".env"],
        max_files_changed=5,
        max_bytes_written=256 * 1024,
    )
    cfg.shell = ShellPolicy(
        forbidden_patterns=[
            r".*",  # All raw shell executions blocked or escalated
        ],
        max_runtime_seconds=5.0,
        max_output_bytes=64 * 1024,
    )
    cfg.network = NetworkPolicy(
        allowed_domains=[],  # No domains allowed
        blocked_domains=["*"],
    )
    cfg.thresholds = ConfidenceThresholds(
        READ=0.90,
        WRITE=0.99,
        DELETE=1.00,
        EXECUTE=0.99,
        NETWORK=1.00,
        AUTH=1.00,
        EXTERNAL_PUBLISH=1.00,
    )
    cfg.fail_disposition = FailDisposition(
        READ=FinalDecision.BLOCK,
        WRITE=FinalDecision.BLOCK,
        DELETE=FinalDecision.BLOCK,
        EXECUTE=FinalDecision.BLOCK,
        NETWORK=FinalDecision.BLOCK,
        AUTH=FinalDecision.BLOCK,
        EXTERNAL_PUBLISH=FinalDecision.BLOCK,
    )
    return cfg


POLICY_PACKS = {
    "safe-local-coding": get_safe_local_coding_pack,
    "github-contributor": get_github_contributor_pack,
    "read-only-research": get_read_only_research_pack,
    "autonomous-ci": get_autonomous_ci_pack,
    "production-ops": get_production_ops_pack,
    "paranoid": get_paranoid_pack,
}


def get_policy_pack(name: str) -> FirewallConfig:
    """Retrieve a configured policy pack by identifier name."""
    clean_name = name.lower().strip()
    factory = POLICY_PACKS.get(clean_name)
    if not factory:
        raise ValueError(f"Unknown policy pack '{name}'. Available: {list(POLICY_PACKS.keys())}")
    return factory()


def list_policy_packs() -> Dict[str, str]:
    """Return dictionary of available policy packs and descriptions."""
    return dict(POLICY_PACK_DESCRIPTIONS)
