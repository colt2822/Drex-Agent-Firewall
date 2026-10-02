"""Outcome feedback schemas for calibration and audit logs."""

from __future__ import annotations

from enum import Enum
import time
from typing import Optional
from pydantic import BaseModel, Field


class OutcomeType(str, Enum):
    EXECUTED_SUCCESSFULLY = "EXECUTED_SUCCESSFULLY"
    EXECUTION_FAILED = "EXECUTION_FAILED"
    POLICY_OVERRIDE_APPROVED = "POLICY_OVERRIDE_APPROVED"
    POLICY_OVERRIDE_REJECTED = "POLICY_OVERRIDE_REJECTED"
    ROLLBACK_REQUIRED = "ROLLBACK_REQUIRED"
    SECURITY_INCIDENT = "SECURITY_INCIDENT"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    FALSE_NEGATIVE = "FALSE_NEGATIVE"


class ActionOutcome(BaseModel):
    """Execution outcome feedback recorded after action execution or audit review."""

    action_id: str
    trace_id: Optional[str] = None
    outcome: OutcomeType
    notes: Optional[str] = None
    error_class: Optional[str] = None
    exit_code: Optional[int] = None
    execution_latency_ms: Optional[float] = None
    recorded_at: float = Field(default_factory=time.time)
