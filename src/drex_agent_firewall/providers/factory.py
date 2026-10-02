"""Provider factory for instantiating the configured decision provider."""

from __future__ import annotations

import os
from typing import Optional

from drex_agent_firewall.providers.base import BaseDecisionProvider
from drex_agent_firewall.providers.drex_provider import DrexProvider
from drex_agent_firewall.providers.replay_provider import ReplayProvider
from drex_agent_firewall.schemas.config import FirewallConfig, ProviderConfig


def create_provider(config: Optional[FirewallConfig] = None) -> BaseDecisionProvider:
    """Instantiate provider based on config and environment variables."""
    cfg = config or FirewallConfig.load_default()
    prov_cfg: ProviderConfig = cfg.provider

    # If provider type is explicitly drex and api_key is present, use live provider
    if prov_cfg.type.lower() == "drex" and prov_cfg.api_key:
        return DrexProvider(
            api_url=prov_cfg.api_url,
            api_key=prov_cfg.api_key,
            requested_model=prov_cfg.requested_model,
            timeout_seconds=prov_cfg.timeout_seconds,
        )

    # Otherwise default to deterministic ReplayProvider
    return ReplayProvider(requested_model=prov_cfg.requested_model)
