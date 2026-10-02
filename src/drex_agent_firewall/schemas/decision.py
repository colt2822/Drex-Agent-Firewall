"""Decision taxonomy and probability distribution schemas for Drex Agent Firewall."""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional
import time
from pydantic import BaseModel, Field

from drex_agent_firewall.schemas.constraints import Constraints


class ActionRisk(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ActionClass(str, Enum):
    READ = "READ"
    WRITE = "WRITE"
    DELETE = "DELETE"
    EXECUTE = "EXECUTE"
    NETWORK = "NETWORK"
    AUTH = "AUTH"
    EXTERNAL_PUBLISH = "EXTERNAL_PUBLISH"
    MONEY_MOVEMENT = "MONEY_MOVEMENT"
    UNKNOWN = "UNKNOWN"


class ScopeMatch(str, Enum):
    IN_SCOPE = "IN_SCOPE"
    POSSIBLY_IN_SCOPE = "POSSIBLY_IN_SCOPE"
    OUT_OF_SCOPE = "OUT_OF_SCOPE"
    UNKNOWN = "UNKNOWN"


class Reversibility(str, Enum):
    FULLY_REVERSIBLE = "FULLY_REVERSIBLE"
    PARTIALLY_REVERSIBLE = "PARTIALLY_REVERSIBLE"
    IRREVERSIBLE = "IRREVERSIBLE"
    UNKNOWN = "UNKNOWN"


class ExternalEffect(str, Enum):
    NONE = "NONE"
    LOCAL_ONLY = "LOCAL_ONLY"
    REMOTE_REVERSIBLE = "REMOTE_REVERSIBLE"
    REMOTE_IRREVERSIBLE = "REMOTE_IRREVERSIBLE"
    UNKNOWN = "UNKNOWN"


class CredentialRisk(str, Enum):
    NONE = "NONE"
    READ_ONLY_SECRET_ACCESS = "READ_ONLY_SECRET_ACCESS"
    SECRET_TRANSMISSION = "SECRET_TRANSMISSION"
    SECRET_PERSISTENCE = "SECRET_PERSISTENCE"
    UNKNOWN = "UNKNOWN"


class DestructiveRisk(str, Enum):
    NONE = "NONE"
    LOW = "LOW"
    MODERATE = "MODERATE"
    HIGH = "HIGH"


class NeedsHumanApproval(str, Enum):
    YES = "YES"
    NO = "NO"
    UNCERTAIN = "UNCERTAIN"


class FinalDecision(str, Enum):
    ALLOW = "ALLOW"
    ALLOW_WITH_CONSTRAINTS = "ALLOW_WITH_CONSTRAINTS"
    ESCALATE = "ESCALATE"
    ABSTAIN = "ABSTAIN"
    BLOCK = "BLOCK"


class FullProbabilityDistribution(BaseModel):
    """Complete probability distributions across all classification dimensions."""

    risk: Dict[str, float] = Field(default_factory=dict)
    action_class: Dict[str, float] = Field(default_factory=dict)
    scope_match: Dict[str, float] = Field(default_factory=dict)
    reversibility: Dict[str, float] = Field(default_factory=dict)
    external_effect: Dict[str, float] = Field(default_factory=dict)
    credential_risk: Dict[str, float] = Field(default_factory=dict)
    destructive_risk: Dict[str, float] = Field(default_factory=dict)
    needs_human_approval: Dict[str, float] = Field(default_factory=dict)


class DrexEvaluationResult(BaseModel):
    """Structured evaluation output produced by a DecisionProvider (Drex or Replay)."""

    provider: str = Field(description="'drex' or 'REPLAY'")
    requested_model: str = Field(default="drex-latest")
    resolved_model: str = Field(default="unknown")

    # Winning classified labels
    risk: ActionRisk = ActionRisk.LOW
    action_class: ActionClass = ActionClass.UNKNOWN
    scope_match: ScopeMatch = ScopeMatch.UNKNOWN
    reversibility: Reversibility = Reversibility.UNKNOWN
    external_effect: ExternalEffect = ExternalEffect.UNKNOWN
    credential_risk: CredentialRisk = CredentialRisk.NONE
    destructive_risk: DestructiveRisk = DestructiveRisk.NONE
    needs_human_approval: NeedsHumanApproval = NeedsHumanApproval.NO

    # Overall / winning decision confidence
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)

    # Full preserved distributions
    distributions: FullProbabilityDistribution = Field(default_factory=FullProbabilityDistribution)

    # Latencies & Diagnostics
    provider_latency_ms: float = 0.0
    evaluation_notes: List[str] = Field(default_factory=list)
    raw_response: Optional[Dict[str, Any]] = None


class FirewallDecision(BaseModel):
    """Final typed decision emitted by the Drex Agent Firewall."""

    action_id: str
    trace_id: str
    decision: FinalDecision
    allowed: bool = Field(description="True if ALLOW or ALLOW_WITH_CONSTRAINTS")
    reason: str

    # Distinction between deterministic hard rules vs Drex probability guidance
    hard_policy_triggered: bool = False
    policy_rule: Optional[str] = None

    # Drex evaluation breakdown
    drex_evaluation: Optional[DrexEvaluationResult] = None

    # Active machine-enforceable constraints
    constraints: Constraints = Field(default_factory=Constraints)

    # Performance
    latency_ms: float = 0.0
    timestamp: float = Field(default_factory=time.time)
