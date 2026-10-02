"""Python SDK client for Drex Agent Firewall."""

from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

from drex_agent_firewall.adapters.filesystem_adapter import FilesystemAdapter
from drex_agent_firewall.adapters.git_adapter import GitAdapter
from drex_agent_firewall.adapters.http_adapter import HttpAdapter
from drex_agent_firewall.adapters.shell_adapter import ShellAdapter, ShellExecutionResult
from drex_agent_firewall.normalizers.context_normalizer import ContextNormalizer
from drex_agent_firewall.persistence.repository import ActionRepository
from drex_agent_firewall.policy.engine import DeterministicPolicyEngine
from drex_agent_firewall.providers.base import BaseDecisionProvider
from drex_agent_firewall.schemas.config import FirewallConfig
from drex_agent_firewall.schemas.decision import FirewallDecision
from drex_agent_firewall.schemas.envelope import ActionEnvelope
from drex_agent_firewall.schemas.outcome import ActionOutcome, OutcomeType
from drex_agent_firewall.security.redactor import SecretRedactor
from drex_agent_firewall.telemetry.metrics import record_firewall_metrics


class DrexFirewall:
    """High-level Python SDK client for Drex Agent Firewall."""

    def __init__(
        self,
        config: Optional[FirewallConfig] = None,
        provider: Optional[BaseDecisionProvider] = None,
        database_path: Optional[str] = None,
        enable_audit_db: bool = True,
    ):
        self.config = config or FirewallConfig.load_default()
        if database_path:
            self.config.database_path = database_path

        self.redactor = SecretRedactor()
        self.engine = DeterministicPolicyEngine(
            config=self.config,
            provider=provider,
            redactor=self.redactor,
        )
        self.normalizer = ContextNormalizer(self.redactor)
        self.repository = ActionRepository(self.config.database_path, self.redactor) if enable_audit_db else None

        # Pre-configured guarded adapters
        self.shell_adapter = ShellAdapter(self.engine, self.repository, self.normalizer)
        self.fs_adapter = FilesystemAdapter(self.engine, self.repository, self.normalizer)
        self.git_adapter = GitAdapter(self.engine, self.repository, self.normalizer)
        self.http_adapter = HttpAdapter(self.engine, self.repository, self.normalizer)

    def evaluate(
        self,
        tool: str,
        operation: str,
        arguments: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None,
        agent_id: str = "agent",
        session_id: str = "default-session",
        parent_action_id: Optional[str] = None,
        trace_id: Optional[str] = None,
    ) -> FirewallDecision:
        """Evaluate a proposed tool action synchronously."""
        envelope = self.normalizer.normalize(
            tool=tool,
            operation=operation,
            arguments=arguments,
            context=context,
            agent_id=agent_id,
            session_id=session_id,
            parent_action_id=parent_action_id,
            trace_id=trace_id,
        )

        decision = self.engine.evaluate(envelope)

        record_firewall_metrics(decision, tool)

        if self.repository:
            self.repository.record_decision(envelope, decision)

        return decision

    async def evaluate_async(
        self,
        tool: str,
        operation: str,
        arguments: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None,
        agent_id: str = "agent",
        session_id: str = "default-session",
        parent_action_id: Optional[str] = None,
        trace_id: Optional[str] = None,
    ) -> FirewallDecision:
        """Evaluate a proposed tool action asynchronously."""
        envelope = self.normalizer.normalize(
            tool=tool,
            operation=operation,
            arguments=arguments,
            context=context,
            agent_id=agent_id,
            session_id=session_id,
            parent_action_id=parent_action_id,
            trace_id=trace_id,
        )

        decision = await self.engine.evaluate_async(envelope)

        record_firewall_metrics(decision, tool)

        if self.repository:
            self.repository.record_decision(envelope, decision)

        return decision

    def enforce(
        self,
        tool: str,
        operation: str,
        arguments: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None,
    ) -> FirewallDecision:
        """Evaluate action and raise PermissionError if blocked or escalated."""
        decision = self.evaluate(tool, operation, arguments, context)
        if not decision.allowed:
            raise PermissionError(
                f"Drex Agent Firewall blocked action [{tool}:{operation}]: {decision.reason} ({decision.decision.value})"
            )
        return decision

    # Convenience Guarded Executors
    def execute_shell(self, command: str, cwd: Optional[str] = None, env: Optional[Dict[str, str]] = None) -> ShellExecutionResult:
        """Execute a guarded shell command through the firewall."""
        return self.shell_adapter.execute(command, cwd=cwd, env=env)

    @property
    def filesystem(self) -> FilesystemAdapter:
        return self.fs_adapter

    @property
    def git(self) -> GitAdapter:
        return self.git_adapter

    @property
    def http(self) -> HttpAdapter:
        return self.http_adapter

    def record_outcome(
        self,
        action_id: str,
        outcome: OutcomeType,
        notes: Optional[str] = None,
        error_class: Optional[str] = None,
    ) -> None:
        """Attach calibration outcome feedback to a previously evaluated action."""
        if not self.repository:
            return
        ao = ActionOutcome(
            action_id=action_id,
            outcome=outcome,
            notes=notes,
            error_class=error_class,
        )
        self.repository.record_outcome(ao)

    def get_action(self, action_id: str) -> Optional[Dict[str, Any]]:
        return self.repository.get_action(action_id) if self.repository else None

    def get_trace(self, trace_id: str) -> List[Dict[str, Any]]:
        return self.repository.get_trace(trace_id) if self.repository else []

    def get_stats(self) -> Dict[str, Any]:
        return self.repository.get_stats() if self.repository else {}
