"""Guarded HTTP client adapter with domain filtering and SSRF/secret leakage prevention."""

from __future__ import annotations

from typing import Any, Dict, Optional
import httpx

from drex_agent_firewall.adapters.base import BaseAdapter
from drex_agent_firewall.adapters.guarded_http_transport import GuardedHTTPTransport
from drex_agent_firewall.constraints.enforcer import ConstraintEnforcer, ConstraintViolation
from drex_agent_firewall.schemas.decision import FirewallDecision


class HttpResult:
    def __init__(
        self,
        method: str,
        url: str,
        allowed: bool,
        firewall_decision: FirewallDecision,
        status_code: Optional[int] = None,
        text: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
        error: Optional[str] = None,
    ):
        self.method = method
        self.url = url
        self.allowed = allowed
        self.firewall_decision = firewall_decision
        self.status_code = status_code
        self.text = text
        self.headers = headers
        self.error = error

    def to_dict(self) -> Dict[str, Any]:
        return {
            "method": self.method,
            "url": self.url,
            "allowed": self.allowed,
            "decision": self.firewall_decision.decision.value,
            "status_code": self.status_code,
            "error": self.error,
        }


class HttpAdapter(BaseAdapter):
    """Guarded HTTP adapter inspecting destinations, methods, payloads, and domain restrictions."""

    def request(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
        data: Optional[Any] = None,
        json_data: Optional[Any] = None,
        timeout: float = 10.0,
    ) -> HttpResult:
        m = method.upper()
        arguments = {
            "method": m,
            "url": url,
            "headers": headers or {},
            "params": params or {},
            "data": data,
            "json": json_data,
        }

        # 1. Firewall Evaluation
        envelope, decision = self.evaluate_action(
            tool="http",
            operation=m,
            arguments=arguments,
            context={"url": url},
        )

        if not decision.allowed:
            self.record_execution_result(
                action_id=envelope.action_id,
                tool="http",
                executed=False,
                error_class="FIREWALL_POLICY_BLOCKED",
            )
            return HttpResult(
                method=m,
                url=url,
                allowed=False,
                firewall_decision=decision,
                error=f"Blocked by firewall: {decision.reason}",
            )

        # 2. Check Enforceable Constraints (Domain & Mutations)
        try:
            ConstraintEnforcer.verify_network_domain(url, decision.constraints)
            ConstraintEnforcer.verify_mutation(m not in {"GET", "HEAD", "OPTIONS"}, decision.constraints)
        except ConstraintViolation as cv:
            self.record_execution_result(
                action_id=envelope.action_id,
                tool="http",
                executed=False,
                error_class="CONSTRAINT_VIOLATION",
            )
            return HttpResult(
                method=m,
                url=url,
                allowed=False,
                firewall_decision=decision,
                error=f"Constraint violation: {str(cv)}",
            )

        # 3. Guarded HTTP Request
        try:
            with httpx.Client(
                timeout=timeout,
                follow_redirects=False,
                transport=GuardedHTTPTransport(),
            ) as client:
                with client.stream(
                    m,
                    url,
                    headers=headers,
                    params=params,
                    data=data,
                    json=json_data,
                ) as resp:
                    max_bytes = decision.constraints.max_output_bytes or (1024 * 1024)
                    body = bytearray()
                    truncated = False
                    for chunk in resp.iter_bytes():
                        remaining = max_bytes - len(body)
                        if len(chunk) > remaining:
                            body.extend(chunk[:remaining])
                            truncated = True
                            break
                        body.extend(chunk)

                    body_text = body.decode(resp.encoding or "utf-8", errors="replace")
                    if truncated:
                        body_text += "... [TRUNCATED_RESPONSE]"

                    result = HttpResult(
                        method=m,
                        url=url,
                        allowed=True,
                        firewall_decision=decision,
                        status_code=resp.status_code,
                        text=body_text,
                        headers=dict(resp.headers),
                    )

                self.record_execution_result(
                    action_id=envelope.action_id,
                    tool="http",
                    executed=True,
                    result={"status_code": resp.status_code},
                    error_class=None if resp.status_code < 400 else f"HTTP_{resp.status_code}",
                )
                return result

        except Exception as e:
            self.record_execution_result(
                action_id=envelope.action_id,
                tool="http",
                executed=False,
                error_class=type(e).__name__,
            )
            return HttpResult(
                method=m,
                url=url,
                allowed=True,
                firewall_decision=decision,
                error=f"HTTP request failed: {str(e)}",
            )
