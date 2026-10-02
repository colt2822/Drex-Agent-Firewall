"""Base adapter with integrated firewall evaluation, constraint verification, and audit recording."""

from __future__ import annotations

from typing import Any, Dict, Optional, Tuple

from drex_agent_firewall.constraints.enforcer import ConstraintEnforcer, ConstraintViolation
from drex_agent_firewall.normalizers.context_normalizer import ContextNormalizer
from drex_agent_firewall.persistence.repository import ActionRepository
from drex_agent_firewall.policy.engine import DeterministicPolicyEngine
from drex_agent_firewall.schemas.decision import FirewallDecision
from drex_agent_firewall.schemas.envelope import ActionEnvelope
from drex_agent_firewall.telemetry.metrics import (
    EXECUTION_FAILURES,
    EXECUTION_TOTAL,
    record_firewall_metrics,
)


class BaseAdapter:
    """Base class for execution adapters wrapping tool operations with Drex Agent Firewall."""

    def __init__(
        self,
        engine: DeterministicPolicyEngine,
        repository: Optional[ActionRepository] = None,
        normalizer: Optional[ContextNormalizer] = None,
    ):
        self.engine = engine
        self.repository = repository
        self.normalizer = normalizer or ContextNormalizer(engine.redactor)

    def evaluate_action(
        self,
        tool: str,
        operation: str,
        arguments: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None,
        agent_id: str = "agent",
        session_id: str = "default-session",
        parent_action_id: Optional[str] = None,
    ) -> Tuple[ActionEnvelope, FirewallDecision]:
        """Normalize, evaluate through policy engine, record in audit DB and telemetry."""
        envelope = self.normalizer.normalize(
            tool=tool,
            operation=operation,
            arguments=arguments,
            context=context,
            agent_id=agent_id,
            session_id=session_id,
            parent_action_id=parent_action_id,
        )

        decision = self.engine.evaluate(envelope)

        # Telemetry
        record_firewall_metrics(decision, tool)

        # Audit persistence
        if self.repository:
            self.repository.record_decision(envelope, decision)

        return envelope, decision

    def record_execution_result(
        self,
        action_id: str,
        tool: str,
        executed: bool,
        result: Any = None,
        error_class: Optional[str] = None,
    ) -> None:
        """Update audit record and telemetry with execution outcome."""
        status = "success" if executed and not error_class else "failed"
        EXECUTION_TOTAL.labels(tool=tool, status=status).inc()
        if error_class:
            EXECUTION_FAILURES.labels(tool=tool).inc()

        if self.repository:
            self.repository.record_execution(
                action_id=action_id,
                executed=executed,
                result=result,
                error_class=error_class,
            )
