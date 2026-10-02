"""Live Drex Decision Provider communicating with https://drex.nace.ai.

Strictly records requested_model and resolved_model.
Never logs raw authorization tokens or secrets.
"""

from __future__ import annotations

import time
from typing import Any, Dict, Optional
import httpx

from drex_agent_firewall.providers.base import BaseDecisionProvider
from drex_agent_firewall.schemas.decision import (
    ActionClass,
    ActionRisk,
    CredentialRisk,
    DestructiveRisk,
    DrexEvaluationResult,
    ExternalEffect,
    FullProbabilityDistribution,
    NeedsHumanApproval,
    Reversibility,
    ScopeMatch,
)
from drex_agent_firewall.schemas.envelope import ActionEnvelope


class DrexProvider(BaseDecisionProvider):
    """Client for the live Drex Decision Engine."""

    def __init__(
        self,
        api_url: str = "https://drex.nace.ai",
        api_key: Optional[str] = None,
        requested_model: str = "drex-latest",
        timeout_seconds: float = 5.0,
    ):
        self.api_url = api_url.rstrip("/")
        self.api_key = api_key
        self.requested_model = requested_model
        self.timeout_seconds = timeout_seconds

    @property
    def provider_name(self) -> str:
        return "drex"

    def _build_request_payload(self, envelope: ActionEnvelope) -> Dict[str, Any]:
        """Construct prompt/payload for Drex evaluation without secret exposure."""
        return {
            "model": self.requested_model,
            "envelope": {
                "action_id": envelope.action_id,
                "tool": envelope.tool,
                "operation": envelope.operation,
                "resource_type": envelope.resource_type,
                "resource_target": envelope.resource_target,
                "read_only": envelope.read_only,
                "external_effect": envelope.external_effect,
                "destructive": envelope.destructive,
                "reversible": envelope.reversible,
                "credential_access": envelope.credential_access,
                "network_access": envelope.network_access,
                "filesystem_write": envelope.filesystem_write,
                "process_execution": envelope.process_execution,
                "external_write": envelope.external_write,
                "repository": envelope.repository,
                "working_directory": envelope.working_directory,
                "arguments": envelope.arguments,  # already scrubbed
                "context": {
                    "current_task": envelope.current_task,
                    "repository_scope": envelope.repository_scope,
                    "git_branch": envelope.git_branch,
                    "allowed_paths": envelope.allowed_paths,
                    "blocked_paths": envelope.blocked_paths,
                    "allowed_domains": envelope.allowed_domains,
                    "blocked_domains": envelope.blocked_domains,
                },
            },
            "taxonomy": {
                "risk": [r.value for r in ActionRisk],
                "action_class": [ac.value for ac in ActionClass],
                "scope_match": [s.value for s in ScopeMatch],
                "reversibility": [rev.value for rev in Reversibility],
                "external_effect": [ee.value for ee in ExternalEffect],
                "credential_risk": [cr.value for cr in CredentialRisk],
                "destructive_risk": [dr.value for dr in DestructiveRisk],
                "needs_human_approval": [ha.value for ha in NeedsHumanApproval],
            },
        }

    def _headers(self) -> Dict[str, str]:
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "DrexAgentFirewall/0.1.0",
        }
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers

    def _parse_response(
        self,
        resp_data: Dict[str, Any],
        resolved_model: str,
        latency_ms: float,
    ) -> DrexEvaluationResult:
        """Parse structured classification response into DrexEvaluationResult."""
        distributions_raw = resp_data.get("distributions", {})

        dist = FullProbabilityDistribution(
            risk=distributions_raw.get("risk", {}),
            action_class=distributions_raw.get("action_class", {}),
            scope_match=distributions_raw.get("scope_match", {}),
            reversibility=distributions_raw.get("reversibility", {}),
            external_effect=distributions_raw.get("external_effect", {}),
            credential_risk=distributions_raw.get("credential_risk", {}),
            destructive_risk=distributions_raw.get("destructive_risk", {}),
            needs_human_approval=distributions_raw.get("needs_human_approval", {}),
        )

        winning = resp_data.get("classifications", {})

        return DrexEvaluationResult(
            provider="drex",
            requested_model=self.requested_model,
            resolved_model=resolved_model,
            risk=ActionRisk(winning.get("risk", ActionRisk.MEDIUM.value)),
            action_class=ActionClass(winning.get("action_class", ActionClass.UNKNOWN.value)),
            scope_match=ScopeMatch(winning.get("scope_match", ScopeMatch.UNKNOWN.value)),
            reversibility=Reversibility(winning.get("reversibility", Reversibility.UNKNOWN.value)),
            external_effect=ExternalEffect(winning.get("external_effect", ExternalEffect.UNKNOWN.value)),
            credential_risk=CredentialRisk(winning.get("credential_risk", CredentialRisk.NONE.value)),
            destructive_risk=DestructiveRisk(winning.get("destructive_risk", DestructiveRisk.NONE.value)),
            needs_human_approval=NeedsHumanApproval(winning.get("needs_human_approval", NeedsHumanApproval.NO.value)),
            confidence=float(resp_data.get("confidence", 0.0)),
            distributions=dist,
            provider_latency_ms=latency_ms,
            raw_response=resp_data,
        )

    def evaluate(self, envelope: ActionEnvelope) -> DrexEvaluationResult:
        payload = self._build_request_payload(envelope)
        start_t = time.perf_counter()

        with httpx.Client(timeout=self.timeout_seconds) as client:
            resp = client.post(
                f"{self.api_url}/v1/evaluate",
                json=payload,
                headers=self._headers(),
            )
            latency_ms = (time.perf_counter() - start_t) * 1000.0

            resp.raise_for_status()
            data = resp.json()

            # Record model resolution from response headers or payload
            resolved_model = (
                resp.headers.get("x-drex-resolved-model")
                or data.get("resolved_model")
                or data.get("model")
                or "unknown"
            )

            return self._parse_response(data, resolved_model, latency_ms)

    async def evaluate_async(self, envelope: ActionEnvelope) -> DrexEvaluationResult:
        payload = self._build_request_payload(envelope)
        start_t = time.perf_counter()

        async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
            resp = await client.post(
                f"{self.api_url}/v1/evaluate",
                json=payload,
                headers=self._headers(),
            )
            latency_ms = (time.perf_counter() - start_t) * 1000.0

            resp.raise_for_status()
            data = resp.json()

            resolved_model = (
                resp.headers.get("x-drex-resolved-model")
                or data.get("resolved_model")
                or data.get("model")
                or "unknown"
            )

            return self._parse_response(data, resolved_model, latency_ms)
