"""Live Drex Decision Provider communicating with https://drex.nace.ai.

Strictly records requested_model and resolved_model.
Never logs raw authorization tokens or secrets.
"""

from __future__ import annotations

import json
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
        if "/systemone" in self.api_url:
            state = f"Tool: {envelope.tool}\nOperation: {envelope.operation}\nTarget: {envelope.resource_target}\nArguments: {json.dumps(envelope.arguments)}\nRead-only: {envelope.read_only}\nDestructive: {envelope.destructive}\nCredential access: {envelope.credential_access}\nNetwork access: {envelope.network_access}"
            return {
                "model": "drex-latest",
                "state": state,
                "questions": {
                    "decision": {
                        "type": "choice",
                        "instructions": "Evaluate risk and safety of this proposed agent action",
                        "criteria": {
                            "allow_1": "allow benign coding action",
                            "block_2": "block dangerous or harmful action",
                            "escalate_3": "escalate ambiguous or high-risk action",
                        },
                    }
                },
            }

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
            "User-Agent": "DrexAgentFirewall/0.1.1",
        }
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers

    def _parse_response(
        self,
        resp_data: Dict[str, Any],
        resolved_model: str,
        latency_ms: float,
        envelope: Optional[ActionEnvelope] = None,
    ) -> DrexEvaluationResult:
        """Parse structured classification response into DrexEvaluationResult."""
        if "answers" in resp_data and "decision" in resp_data["answers"]:
            ans = resp_data["answers"]["decision"]
            choice = ans.get("choice", "escalate_3")
            conf = float(ans.get("confidence", 0.90))
            probs = ans.get("probabilities", {})

            p_allow = float(probs.get("allow_1", 0.0))
            p_block = float(probs.get("block_2", 0.0))
            p_escalate = float(probs.get("escalate_3", 0.0))

            if "allow" in choice:
                risk = ActionRisk.LOW
                needs_ha = NeedsHumanApproval.NO
            elif "block" in choice:
                risk = ActionRisk.HIGH
                needs_ha = NeedsHumanApproval.YES
            else:
                risk = ActionRisk.MEDIUM
                needs_ha = NeedsHumanApproval.YES

            ac = ActionClass.READ
            if envelope:
                if envelope.filesystem_write:
                    ac = ActionClass.WRITE
                elif envelope.process_execution:
                    ac = ActionClass.EXECUTE
                elif envelope.network_access:
                    ac = ActionClass.NETWORK

            dist = FullProbabilityDistribution(
                risk={"LOW": p_allow, "MEDIUM": p_escalate, "HIGH": p_block * 0.7, "CRITICAL": p_block * 0.3},
                action_class={ac.value: conf},
                scope_match={"IN_SCOPE": p_allow, "OUT_OF_SCOPE": p_block, "UNKNOWN": p_escalate},
                reversibility={"FULLY_REVERSIBLE": p_allow, "PARTIALLY_REVERSIBLE": p_escalate, "IRREVERSIBLE": p_block},
                external_effect={"LOCAL_ONLY": p_allow, "NONE": 0.0, "REMOTE_REVERSIBLE": p_escalate, "REMOTE_IRREVERSIBLE": p_block},
                credential_risk={"NONE": 1.0 - p_block, "SECRET_TRANSMISSION": p_block},
                destructive_risk={"NONE": p_allow, "LOW": p_escalate, "HIGH": p_block},
                needs_human_approval={"NO": p_allow, "UNCERTAIN": p_escalate, "YES": p_block},
            )

            return DrexEvaluationResult(
                provider="drex",
                requested_model=self.requested_model,
                resolved_model=resolved_model,
                risk=risk,
                action_class=ac,
                scope_match=ScopeMatch.IN_SCOPE if "allow" in choice else ScopeMatch.OUT_OF_SCOPE,
                reversibility=Reversibility.FULLY_REVERSIBLE if "allow" in choice else Reversibility.IRREVERSIBLE,
                external_effect=ExternalEffect.LOCAL_ONLY if "allow" in choice else ExternalEffect.REMOTE_IRREVERSIBLE,
                credential_risk=CredentialRisk.SECRET_TRANSMISSION if (envelope and envelope.credential_access) else CredentialRisk.NONE,
                destructive_risk=DestructiveRisk.HIGH if "block" in choice else DestructiveRisk.NONE,
                needs_human_approval=needs_ha,
                confidence=conf,
                distributions=dist,
                provider_latency_ms=latency_ms,
                raw_response=resp_data,
            )

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

        endpoint = self.api_url if "/v1/" in self.api_url else f"{self.api_url}/v1/evaluate"
        with httpx.Client(timeout=self.timeout_seconds) as client:
            resp = client.post(
                endpoint,
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

            return self._parse_response(data, resolved_model, latency_ms, envelope=envelope)

    async def evaluate_async(self, envelope: ActionEnvelope) -> DrexEvaluationResult:
        payload = self._build_request_payload(envelope)
        start_t = time.perf_counter()

        endpoint = self.api_url if "/v1/" in self.api_url else f"{self.api_url}/v1/evaluate"
        async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
            resp = await client.post(
                endpoint,
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

            return self._parse_response(data, resolved_model, latency_ms, envelope=envelope)
