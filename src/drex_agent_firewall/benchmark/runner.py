"""Benchmark execution runner computing accuracy, false allow, false block, and latency metrics."""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional
from rich.console import Console
from rich.table import Table

from drex_agent_firewall.benchmark.dataset import BENCHMARK_SCENARIOS, BenchmarkScenario
from drex_agent_firewall.schemas.decision import FinalDecision, FirewallDecision
from drex_agent_firewall.sdk.client import DrexFirewall


class BenchmarkResults(dict):
    """Structured benchmark metrics summary."""
    pass


class BenchmarkRunner:
    """Executes evaluation benchmarks and generates verification reports."""

    def __init__(self, firewall: Optional[DrexFirewall] = None):
        self.firewall = firewall or DrexFirewall(enable_audit_db=False)

    def run(self, scenarios: Optional[List[BenchmarkScenario]] = None) -> Dict[str, Any]:
        dataset = scenarios or BENCHMARK_SCENARIOS
        total = len(dataset)
        correct = 0
        false_allows = 0
        false_blocks = 0
        escalations = 0
        abstentions = 0
        high_impact_total = 0
        high_impact_false_allows = 0
        latencies: List[float] = []

        scenario_details: List[Dict[str, Any]] = []

        for sc in dataset:
            start_t = time.perf_counter()
            decision: FirewallDecision = self.firewall.evaluate(
                tool=sc.tool,
                operation=sc.operation,
                arguments=sc.arguments,
                context=sc.context,
            )
            lat = (time.perf_counter() - start_t) * 1000.0
            latencies.append(lat)

            is_correct = (decision.decision == sc.expected_decision)
            if is_correct:
                correct += 1

            if decision.decision == FinalDecision.ESCALATE:
                escalations += 1
            elif decision.decision == FinalDecision.ABSTAIN:
                abstentions += 1

            # High impact check
            if sc.is_high_impact:
                high_impact_total += 1
                if decision.allowed:
                    high_impact_false_allows += 1

            # False allow: allowed when expected BLOCK or ESCALATE
            if decision.allowed and sc.expected_decision in {FinalDecision.BLOCK, FinalDecision.ESCALATE}:
                false_allows += 1

            # False block: blocked when expected ALLOW or ALLOW_WITH_CONSTRAINTS
            if decision.decision == FinalDecision.BLOCK and sc.expected_decision in {FinalDecision.ALLOW, FinalDecision.ALLOW_WITH_CONSTRAINTS}:
                false_blocks += 1

            scenario_details.append({
                "id": sc.id,
                "category": sc.category,
                "description": sc.description,
                "expected": sc.expected_decision.value,
                "actual": decision.decision.value,
                "matched": is_correct,
                "is_high_impact": sc.is_high_impact,
                "latency_ms": round(lat, 2),
                "reason": decision.reason,
            })

        accuracy = (correct / total) if total > 0 else 0.0
        false_allow_rate = (false_allows / total) if total > 0 else 0.0
        false_block_rate = (false_blocks / total) if total > 0 else 0.0
        escalation_rate = (escalations / total) if total > 0 else 0.0
        abstention_rate = (abstentions / total) if total > 0 else 0.0
        high_impact_false_allow_rate = (
            (high_impact_false_allows / high_impact_total) if high_impact_total > 0 else 0.0
        )
        avg_latency = (sum(latencies) / len(latencies)) if latencies else 0.0

        return {
            "total_scenarios": total,
            "accuracy": round(accuracy * 100.0, 2),
            "false_allow_rate": round(false_allow_rate * 100.0, 2),
            "false_block_rate": round(false_block_rate * 100.0, 2),
            "escalation_rate": round(escalation_rate * 100.0, 2),
            "abstention_rate": round(abstention_rate * 100.0, 2),
            "high_impact_scenarios": high_impact_total,
            "false_allow_rate_high_impact": round(high_impact_false_allow_rate * 100.0, 2),
            "average_latency_ms": round(avg_latency, 2),
            "scenario_details": scenario_details,
        }

    def print_summary(self, results: Dict[str, Any]) -> None:
        console = Console()
        console.print("\n[bold cyan]═══════════════════════════════════════════════════════════[/bold cyan]")
        console.print("[bold cyan]       Drex Agent Firewall Benchmark Summary Report       [/bold cyan]")
        console.print("[bold cyan]═══════════════════════════════════════════════════════════[/bold cyan]\n")

        table = Table(title="Evaluation Metrics", show_header=True, header_style="bold magenta")
        table.add_column("Metric", style="dim")
        table.add_column("Value", justify="right")

        table.add_row("Total Scenarios Evaluated", str(results["total_scenarios"]))
        table.add_row("Accuracy", f"{results['accuracy']}%")
        table.add_row("False Allow Rate (Overall)", f"{results['false_allow_rate']}%")
        table.add_row("False Block Rate", f"{results['false_block_rate']}%")
        table.add_row("Escalation Rate", f"{results['escalation_rate']}%")
        table.add_row("Abstention Rate", f"{results['abstention_rate']}%")
        table.add_row(
            "[bold red]False Allow Rate (High-Impact)[/bold red]",
            f"[bold green]{results['false_allow_rate_high_impact']}%[/bold green]"
            if results["false_allow_rate_high_impact"] == 0.0
            else f"[bold red]{results['false_allow_rate_high_impact']}%[/bold red]",
        )
        table.add_row("Average Decision Latency", f"{results['average_latency_ms']} ms")

        console.print(table)
        console.print("\n[green]✔ Benchmark verification complete.[/green]\n")
