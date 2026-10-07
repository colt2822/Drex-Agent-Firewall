"""Drex Agent Firewall.

A vendor-neutral policy and decision firewall for autonomous AI agents,
powered by Drex.
"""

from drex_agent_firewall.sdk.client import DrexFirewall
from drex_agent_firewall.schemas.envelope import ActionEnvelope
from drex_agent_firewall.schemas.constraints import Constraints
from drex_agent_firewall.schemas.decision import (
    ActionRisk,
    ActionClass,
    ScopeMatch,
    Reversibility,
    ExternalEffect,
    CredentialRisk,
    DestructiveRisk,
    NeedsHumanApproval,
    FinalDecision,
    FullProbabilityDistribution,
    DrexEvaluationResult,
    FirewallDecision,
)
from drex_agent_firewall.schemas.outcome import ActionOutcome, OutcomeType
from drex_agent_firewall.schemas.config import FirewallConfig

__version__ = "0.1.3"

__all__ = [
    "DrexFirewall",
    "ActionEnvelope",
    "Constraints",
    "ActionRisk",
    "ActionClass",
    "ScopeMatch",
    "Reversibility",
    "ExternalEffect",
    "CredentialRisk",
    "DestructiveRisk",
    "NeedsHumanApproval",
    "FinalDecision",
    "FullProbabilityDistribution",
    "DrexEvaluationResult",
    "FirewallDecision",
    "ActionOutcome",
    "OutcomeType",
    "FirewallConfig",
    "__version__",
]
