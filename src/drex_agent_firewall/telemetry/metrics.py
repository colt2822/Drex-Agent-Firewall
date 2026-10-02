"""Prometheus metrics exporter for Drex Agent Firewall."""

from __future__ import annotations

from typing import Optional
from prometheus_client import (
    Counter,
    Histogram,
    generate_latest,
    CONTENT_TYPE_LATEST,
    CollectorRegistry,
    REGISTRY,
)

from drex_agent_firewall.schemas.decision import FinalDecision, FirewallDecision


# Global Prometheus metrics registered with standard names
DECISIONS_TOTAL = Counter(
    "drex_firewall_decisions_total",
    "Total number of evaluated agent actions",
    ["decision", "tool", "provider"],
)

ALLOWED_TOTAL = Counter(
    "drex_firewall_allowed_total",
    "Total actions permitted without extra constraints",
    ["tool"],
)

CONSTRAINED_TOTAL = Counter(
    "drex_firewall_constrained_total",
    "Total actions permitted with enforceable constraints",
    ["tool"],
)

ESCALATED_TOTAL = Counter(
    "drex_firewall_escalated_total",
    "Total actions escalated for review",
    ["tool"],
)

BLOCKED_TOTAL = Counter(
    "drex_firewall_blocked_total",
    "Total actions rejected/blocked",
    ["tool", "policy_rule"],
)

ABSTAINED_TOTAL = Counter(
    "drex_firewall_abstained_total",
    "Total actions where firewall abstained",
    ["tool"],
)

DECISION_LATENCY = Histogram(
    "drex_firewall_decision_latency_seconds",
    "Latency of firewall decision evaluation pipeline",
    buckets=[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0],
)

PROVIDER_LATENCY = Histogram(
    "drex_firewall_provider_latency_seconds",
    "Latency of decision provider queries",
    ["provider"],
    buckets=[0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0],
)

PROVIDER_ERRORS = Counter(
    "drex_firewall_provider_errors_total",
    "Total errors when querying decision provider",
    ["provider", "error_type"],
)

EXECUTION_TOTAL = Counter(
    "drex_firewall_execution_total",
    "Total tool actions executed through adapters",
    ["tool", "status"],
)

EXECUTION_FAILURES = Counter(
    "drex_firewall_execution_failures_total",
    "Total execution failures in adapters",
    ["tool"],
)


def record_firewall_metrics(decision: FirewallDecision, tool: str) -> None:
    """Record telemetry counters and histograms for a completed decision."""
    prov = decision.drex_evaluation.provider if decision.drex_evaluation else "none"
    DECISIONS_TOTAL.labels(decision=decision.decision.value, tool=tool, provider=prov).inc()

    if decision.decision == FinalDecision.ALLOW:
        ALLOWED_TOTAL.labels(tool=tool).inc()
    elif decision.decision == FinalDecision.ALLOW_WITH_CONSTRAINTS:
        CONSTRAINED_TOTAL.labels(tool=tool).inc()
    elif decision.decision == FinalDecision.ESCALATE:
        ESCALATED_TOTAL.labels(tool=tool).inc()
    elif decision.decision == FinalDecision.BLOCK:
        BLOCKED_TOTAL.labels(tool=tool, policy_rule=decision.policy_rule or "drex_risk").inc()
    elif decision.decision == FinalDecision.ABSTAIN:
        ABSTAINED_TOTAL.labels(tool=tool).inc()

    DECISION_LATENCY.observe(decision.latency_ms / 1000.0)

    if decision.drex_evaluation and decision.drex_evaluation.provider_latency_ms > 0:
        PROVIDER_LATENCY.labels(provider=prov).observe(decision.drex_evaluation.provider_latency_ms / 1000.0)


def get_prometheus_metrics() -> bytes:
    """Export current metrics in Prometheus text format."""
    return generate_latest(REGISTRY)
