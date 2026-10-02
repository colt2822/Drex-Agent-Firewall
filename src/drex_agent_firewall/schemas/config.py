"""Configuration schema for Drex Agent Firewall."""

from __future__ import annotations

import os
from typing import Dict, List, Optional
from pydantic import BaseModel, Field

from drex_agent_firewall.schemas.decision import ActionClass, FinalDecision


class ProviderConfig(BaseModel):
    """Configuration for decision providers."""
    type: str = Field(default="replay", description="'drex' or 'replay'")
    api_url: str = Field(default="https://drex.nace.ai")
    api_key: Optional[str] = Field(default=None)
    requested_model: str = Field(default="drex-latest")
    timeout_seconds: float = Field(default=5.0)


class ConfidenceThresholds(BaseModel):
    """Per-action-class minimum confidence required to ALLOW."""
    READ: float = 0.70
    WRITE: float = 0.90
    DELETE: float = 0.98
    EXECUTE: float = 0.90
    NETWORK: float = 0.85
    AUTH: float = 0.95
    EXTERNAL_PUBLISH: float = 0.97
    MONEY_MOVEMENT: float = 0.99
    UNKNOWN: float = 0.90

    def for_action_class(self, action_class: ActionClass) -> float:
        return getattr(self, action_class.value, 0.90)


class FailDisposition(BaseModel):
    """Configurable fail-open vs fail-closed behavior by action class during provider error/timeout."""
    READ: FinalDecision = FinalDecision.ALLOW
    WRITE: FinalDecision = FinalDecision.ESCALATE
    DELETE: FinalDecision = FinalDecision.BLOCK
    EXECUTE: FinalDecision = FinalDecision.ESCALATE
    NETWORK: FinalDecision = FinalDecision.BLOCK
    AUTH: FinalDecision = FinalDecision.BLOCK
    EXTERNAL_PUBLISH: FinalDecision = FinalDecision.BLOCK
    MONEY_MOVEMENT: FinalDecision = FinalDecision.BLOCK
    UNKNOWN: FinalDecision = FinalDecision.ESCALATE

    def for_action_class(self, action_class: ActionClass) -> FinalDecision:
        return getattr(self, action_class.value, FinalDecision.ESCALATE)


class FilesystemPolicy(BaseModel):
    allowed_roots: List[str] = Field(default_factory=lambda: ["/workspace", "."])
    blocked_paths: List[str] = Field(
        default_factory=lambda: [
            "/etc/shadow",
            "/etc/sudoers",
            "/root",
            "~/.ssh",
            "~/.aws",
            "~/.gnupg",
            ".git/config",
        ]
    )
    max_files_changed: int = 50
    max_bytes_written: int = 10 * 1024 * 1024


class ShellPolicy(BaseModel):
    forbidden_patterns: List[str] = Field(
        default_factory=lambda: [
            r"rm\s+(-[rfRF]+\s+)?/\s*$",
            r"rm\s+-[rfRF]+\s+/\*",
            r">\s*/dev/sda",
            r"mkfs",
            r"dd\s+if=.*of=/dev/",
            r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:",  # fork bomb
            r"chmod\s+-R\s+777\s+/",
            r"curl\s+.*\|\s*sh",
            r"wget\s+.*\|\s*sh",
            r"curl\s+.*\|\s*bash",
            r"wget\s+.*\|\s*bash",
        ]
    )
    max_runtime_seconds: float = 30.0
    max_output_bytes: int = 1024 * 1024


class NetworkPolicy(BaseModel):
    allowed_domains: List[str] = Field(default_factory=list)
    blocked_domains: List[str] = Field(
        default_factory=lambda: [
            "169.254.169.254",          # AWS/GCP/Azure instance metadata
            "metadata.google.internal",  # GCP metadata
            "100.100.100.200",          # Alibaba metadata
            "localhost",
            "127.0.0.1",
            "0.0.0.0",
        ]
    )


class FirewallConfig(BaseModel):
    """Global configuration for Drex Agent Firewall."""
    provider: ProviderConfig = Field(default_factory=ProviderConfig)
    default_policy: FinalDecision = FinalDecision.ESCALATE
    thresholds: ConfidenceThresholds = Field(default_factory=ConfidenceThresholds)
    fail_disposition: FailDisposition = Field(default_factory=FailDisposition)
    filesystem: FilesystemPolicy = Field(default_factory=FilesystemPolicy)
    shell: ShellPolicy = Field(default_factory=ShellPolicy)
    network: NetworkPolicy = Field(default_factory=NetworkPolicy)
    database_path: str = "drex_firewall.db"

    @classmethod
    def load_default(cls) -> "FirewallConfig":
        """Instantiate config with environment variable overrides."""
        cfg = cls()
        api_key = os.environ.get("DREX_API_KEY")
        provider_type = os.environ.get("DREX_PROVIDER_TYPE")
        if provider_type:
            cfg.provider.type = provider_type.lower()
        elif api_key:
            cfg.provider.type = "drex"
            cfg.provider.api_key = api_key
        else:
            cfg.provider.type = "replay"

        if api_key:
            cfg.provider.api_key = api_key

        if "DREX_API_URL" in os.environ:
            cfg.provider.api_url = os.environ["DREX_API_URL"]
        if "DREX_REQUESTED_MODEL" in os.environ:
            cfg.provider.requested_model = os.environ["DREX_REQUESTED_MODEL"]
        if "DREX_DATABASE_PATH" in os.environ:
            cfg.database_path = os.environ["DREX_DATABASE_PATH"]

        return cfg

    @classmethod
    def from_pack(cls, pack_name: str) -> "FirewallConfig":
        """Instantiate configuration from a named policy pack."""
        from drex_agent_firewall.policy.packs import get_policy_pack
        cfg = get_policy_pack(pack_name)
        if "DREX_DATABASE_PATH" in os.environ:
            cfg.database_path = os.environ["DREX_DATABASE_PATH"]
        if "DREX_API_KEY" in os.environ:
            cfg.provider.api_key = os.environ["DREX_API_KEY"]
            cfg.provider.type = "drex"
        return cfg
