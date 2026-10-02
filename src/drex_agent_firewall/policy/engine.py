"""Deterministic Policy Engine coordinating hard invariants, Drex probabilistic evaluation, and constraint synthesis."""

from __future__ import annotations

import time
from typing import Optional

from drex_agent_firewall.policy.deterministic_rules import DeterministicRulesEngine
from drex_agent_firewall.policy.fail_disposition import FailDispositionResolver
from drex_agent_firewall.policy.thresholds import ThresholdEvaluator
from drex_agent_firewall.providers.base import BaseDecisionProvider
from drex_agent_firewall.providers.factory import create_provider
from drex_agent_firewall.schemas.config import FirewallConfig
from drex_agent_firewall.schemas.constraints import Constraints
from drex_agent_firewall.schemas.decision import (
    ActionClass,
    ActionRisk,
    CredentialRisk,
    DestructiveRisk,
    DrexEvaluationResult,
    ExternalEffect,
    FinalDecision,
    FirewallDecision,
    NeedsHumanApproval,
    ScopeMatch,
)
from drex_agent_firewall.schemas.envelope import ActionEnvelope
from drex_agent_firewall.security.redactor import SecretRedactor


class DeterministicPolicyEngine:
    """Core decision engine separating probabilistic judgment from deterministic enforcement."""

    def __init__(
        self,
        config: Optional[FirewallConfig] = None,
        provider: Optional[BaseDecisionProvider] = None,
        redactor: Optional[SecretRedactor] = None,
    ):
        self.config = config or FirewallConfig.load_default()
        self.redactor = redactor or SecretRedactor()
        self.provider = provider or create_provider(self.config)
        self.hard_rules = DeterministicRulesEngine(self.config, self.redactor)
        self.thresholds = ThresholdEvaluator(self.config.thresholds)
        self.fail_resolver = FailDispositionResolver(self.config.fail_disposition)

    def evaluate(self, envelope: ActionEnvelope) -> FirewallDecision:
        """Evaluate an ActionEnvelope synchronously through the complete firewall pipeline."""
        start_t = time.perf_counter()

        # Step 1: Evaluate hard deterministic rules (pre-Drex absolute invariants)
        hard_rule_result = self.hard_rules.evaluate(envelope)
        if hard_rule_result is not None:
            latency_ms = (time.perf_counter() - start_t) * 1000.0
            return FirewallDecision(
                action_id=envelope.action_id,
                trace_id=envelope.trace_id,
                decision=hard_rule_result.decision,
                allowed=(hard_rule_result.decision in {FinalDecision.ALLOW, FinalDecision.ALLOW_WITH_CONSTRAINTS}),
                reason=f"[DETERMINISTIC_HARD_POLICY]: {hard_rule_result.reason}",
                hard_policy_triggered=True,
                policy_rule=hard_rule_result.rule_name,
                drex_evaluation=None,
                constraints=Constraints(),
                latency_ms=latency_ms,
            )

        # Step 2: Query Decision Provider (Live Drex or Replay)
        try:
            drex_eval = self.provider.evaluate(envelope)
        except Exception as exc:
            disposition = self.fail_resolver.resolve(envelope, exc)
            latency_ms = (time.perf_counter() - start_t) * 1000.0
            return FirewallDecision(
                action_id=envelope.action_id,
                trace_id=envelope.trace_id,
                decision=disposition,
                allowed=(disposition in {FinalDecision.ALLOW, FinalDecision.ALLOW_WITH_CONSTRAINTS}),
                reason=f"[PROVIDER_FAILURE_FALLBACK]: {type(exc).__name__}: {str(exc)} -> Fail disposition applied: {disposition.value}",
                hard_policy_triggered=False,
                policy_rule="FAIL_DISPOSITION_FALLBACK",
                drex_evaluation=None,
                constraints=Constraints(),
                latency_ms=latency_ms,
            )

        # Step 3: Interpret Drex probabilities via Deterministic Policy
        final_decision, reason, constraints = self._apply_policy(envelope, drex_eval)
        latency_ms = (time.perf_counter() - start_t) * 1000.0

        return FirewallDecision(
            action_id=envelope.action_id,
            trace_id=envelope.trace_id,
            decision=final_decision,
            allowed=(final_decision in {FinalDecision.ALLOW, FinalDecision.ALLOW_WITH_CONSTRAINTS}),
            reason=reason,
            hard_policy_triggered=False,
            policy_rule=None,
            drex_evaluation=drex_eval,
            constraints=constraints,
            latency_ms=latency_ms,
        )

    async def evaluate_async(self, envelope: ActionEnvelope) -> FirewallDecision:
        """Evaluate an ActionEnvelope asynchronously."""
        start_t = time.perf_counter()

        hard_rule_result = self.hard_rules.evaluate(envelope)
        if hard_rule_result is not None:
            latency_ms = (time.perf_counter() - start_t) * 1000.0
            return FirewallDecision(
                action_id=envelope.action_id,
                trace_id=envelope.trace_id,
                decision=hard_rule_result.decision,
                allowed=(hard_rule_result.decision in {FinalDecision.ALLOW, FinalDecision.ALLOW_WITH_CONSTRAINTS}),
                reason=f"[DETERMINISTIC_HARD_POLICY]: {hard_rule_result.reason}",
                hard_policy_triggered=True,
                policy_rule=hard_rule_result.rule_name,
                drex_evaluation=None,
                constraints=Constraints(),
                latency_ms=latency_ms,
            )

        try:
            drex_eval = await self.provider.evaluate_async(envelope)
        except Exception as exc:
            disposition = self.fail_resolver.resolve(envelope, exc)
            latency_ms = (time.perf_counter() - start_t) * 1000.0
            return FirewallDecision(
                action_id=envelope.action_id,
                trace_id=envelope.trace_id,
                decision=disposition,
                allowed=(disposition in {FinalDecision.ALLOW, FinalDecision.ALLOW_WITH_CONSTRAINTS}),
                reason=f"[PROVIDER_FAILURE_FALLBACK]: {type(exc).__name__}: {str(exc)} -> Fail disposition applied: {disposition.value}",
                hard_policy_triggered=False,
                policy_rule="FAIL_DISPOSITION_FALLBACK",
                drex_evaluation=None,
                constraints=Constraints(),
                latency_ms=latency_ms,
            )

        final_decision, reason, constraints = self._apply_policy(envelope, drex_eval)
        latency_ms = (time.perf_counter() - start_t) * 1000.0

        return FirewallDecision(
            action_id=envelope.action_id,
            trace_id=envelope.trace_id,
            decision=final_decision,
            allowed=(final_decision in {FinalDecision.ALLOW, FinalDecision.ALLOW_WITH_CONSTRAINTS}),
            reason=reason,
            hard_policy_triggered=False,
            policy_rule=None,
            drex_evaluation=drex_eval,
            constraints=constraints,
            latency_ms=latency_ms,
        )

    def _apply_policy(
        self, envelope: ActionEnvelope, drex_eval: DrexEvaluationResult
    ) -> tuple[FinalDecision, str, Constraints]:
        """Apply deterministic policy interpretation over Drex structured evaluation."""
        constraints = Constraints(
            allowed_paths=self.config.filesystem.allowed_roots,
            denied_paths=self.config.filesystem.blocked_paths,
            max_runtime_seconds=self.config.shell.max_runtime_seconds,
            max_output_bytes=self.config.shell.max_output_bytes,
            allowed_domains=self.config.network.allowed_domains,
            denied_domains=self.config.network.blocked_domains,
            max_files_changed=self.config.filesystem.max_files_changed,
            max_bytes_written=self.config.filesystem.max_bytes_written,
        )

        # 1. Critical risk or high destructive risk -> BLOCK
        if drex_eval.risk == ActionRisk.CRITICAL or drex_eval.destructive_risk == DestructiveRisk.HIGH:
            return (
                FinalDecision.BLOCK,
                f"Action blocked due to {drex_eval.risk.value} risk / {drex_eval.destructive_risk.value} destructive classification (confidence {drex_eval.confidence:.2f})",
                constraints,
            )

        # 2. Secret transmission attempt -> BLOCK
        if drex_eval.credential_risk == CredentialRisk.SECRET_TRANSMISSION:
            return (
                FinalDecision.BLOCK,
                "Action blocked due to potential external secret transmission",
                constraints,
            )

        # 3. Explicitly Out-of-Scope actions -> BLOCK or ESCALATE
        if drex_eval.scope_match == ScopeMatch.OUT_OF_SCOPE:
            return (
                FinalDecision.BLOCK,
                f"Action target '{envelope.resource_target}' classified as OUT_OF_SCOPE",
                constraints,
            )

        # 4. Check confidence thresholds
        passes_conf, actual_conf, req_conf = self.thresholds.check(drex_eval)
        if not passes_conf:
            # Low confidence must not silently become ALLOW
            return (
                FinalDecision.ESCALATE,
                f"Evaluation confidence {actual_conf:.2f} did not meet required threshold {req_conf:.2f} for action class {drex_eval.action_class.value}",
                constraints,
            )

        # 5. Check if Drex indicates human approval is required
        if drex_eval.needs_human_approval == NeedsHumanApproval.YES:
            return (
                FinalDecision.ESCALATE,
                "Action classified as requiring explicit human authorization",
                constraints,
            )
        elif drex_eval.needs_human_approval == NeedsHumanApproval.UNCERTAIN:
            return (
                FinalDecision.ESCALATE,
                "Action policy clearance uncertain; escalating to human review",
                constraints,
            )

        # 6. Git Push / Remote External Writes
        if envelope.tool.lower() == "git" and envelope.operation.lower() == "push":
            return (
                FinalDecision.ESCALATE,
                "Remote git push requires human policy sign-off",
                constraints,
            )

        # 7. GitHub External Publishing (issues, PRs, comments)
        if drex_eval.action_class == ActionClass.EXTERNAL_PUBLISH or envelope.tool.lower() == "github":
            if envelope.operation.lower() in {"read_issue", "read_pr", "list_issues", "list_prs"}:
                constraints.read_only = True
                return (FinalDecision.ALLOW, "Read-only GitHub inspection allowed", constraints)
            # Mutations escalate or allow with constraints
            return (
                FinalDecision.ESCALATE,
                f"External publishing action '{envelope.operation}' escalated for review",
                constraints,
            )

        # 8. Filesystem Writes & Git Commits: ALLOW_WITH_CONSTRAINTS
        if (
            envelope.filesystem_write
            or drex_eval.action_class == ActionClass.WRITE
            or (envelope.tool.lower() == "git" and envelope.operation.lower() in {"commit", "add", "checkout"})
        ):
            constraints.read_only = False
            constraints.no_force_push = True
            constraints.no_secret_access = True
            return (
                FinalDecision.ALLOW_WITH_CONSTRAINTS,
                "Filesystem modification permitted within verified repository boundary constraints",
                constraints,
            )

        # 9. Read-only + Low Risk + In-Scope -> ALLOW
        if (
            envelope.read_only
            or drex_eval.action_class == ActionClass.READ
        ) and drex_eval.risk in {ActionRisk.LOW, ActionRisk.MEDIUM}:
            constraints.read_only = True
            return (
                FinalDecision.ALLOW,
                "Read-only action verified safe and within configured scope",
                constraints,
            )

        # 10. General execution (safe shell, test runner, builds)
        if drex_eval.action_class == ActionClass.EXECUTE and drex_eval.risk == ActionRisk.LOW:
            return (
                FinalDecision.ALLOW,
                "Low-risk execution permitted within bounded runtime limits",
                constraints,
            )

        # Default fallback
        return (
            self.config.default_policy,
            f"Action evaluated with default policy: {self.config.default_policy.value}",
            constraints,
        )
