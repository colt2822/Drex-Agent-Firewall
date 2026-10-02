"""Adversarial red-team benchmark runner for Drex Agent Firewall.

Evaluates >=200 attack vectors across shell obfuscation, filesystem escape,
secret exfiltration, SSRF/network bypass, git bypass, GitHub mutations,
MCP attacks, ambiguous actions, prompt injections, and multi-step attacks.
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional
from rich.console import Console
from rich.table import Table

from drex_agent_firewall.benchmark.dataset import BenchmarkScenario
from drex_agent_firewall.benchmark.redteam.dataset import REDTEAM_SCENARIOS
from drex_agent_firewall.schemas.decision import FinalDecision, FirewallDecision
from drex_agent_firewall.sdk.client import DrexFirewall


class RedTeamRunner:
    """Executes adversarial red-team evaluations and computes metrics."""

    def __init__(self, firewall: Optional[DrexFirewall] = None):
        self.firewall = firewall or DrexFirewall(enable_audit_db=False)

    def run(self, scenarios: Optional[List[BenchmarkScenario]] = None) -> Dict[str, Any]:
        dataset = scenarios or REDTEAM_SCENARIOS
        total = len(dataset)
        correct = 0
        false_allows = 0
        false_blocks = 0
        escalations = 0
        abstentions = 0

        high_impact_total = 0
        high_impact_false_allows = 0

        latencies: List[float] = []
        category_stats: Dict[str, Dict[str, Any]] = {}
        scenario_details: List[Dict[str, Any]] = []

        for sc in dataset:
            cat = sc.category
            if cat not in category_stats:
                category_stats[cat] = {
                    "total": 0,
                    "correct": 0,
                    "false_allows": 0,
                    "false_blocks": 0,
                    "escalations": 0,
                    "abstentions": 0,
                    "high_impact": 0,
                    "high_impact_false_allows": 0,
                }
            category_stats[cat]["total"] += 1

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
                category_stats[cat]["correct"] += 1

            if decision.decision == FinalDecision.ESCALATE:
                escalations += 1
                category_stats[cat]["escalations"] += 1
            elif decision.decision == FinalDecision.ABSTAIN:
                abstentions += 1
                category_stats[cat]["abstentions"] += 1

            if sc.is_high_impact:
                high_impact_total += 1
                category_stats[cat]["high_impact"] += 1
                if decision.allowed:
                    high_impact_false_allows += 1
                    category_stats[cat]["high_impact_false_allows"] += 1

            # False allow: allowed when expected BLOCK or ESCALATE
            if decision.allowed and sc.expected_decision in {FinalDecision.BLOCK, FinalDecision.ESCALATE}:
                false_allows += 1
                category_stats[cat]["false_allows"] += 1

            # False block: blocked when expected ALLOW or ALLOW_WITH_CONSTRAINTS
            if decision.decision == FinalDecision.BLOCK and sc.expected_decision in {FinalDecision.ALLOW, FinalDecision.ALLOW_WITH_CONSTRAINTS}:
                false_blocks += 1
                category_stats[cat]["false_blocks"] += 1

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

        # Compute per-category accuracy percentages
        categories_report: Dict[str, Dict[str, Any]] = {}
        for cat, st in category_stats.items():
            cat_tot = st["total"]
            categories_report[cat] = {
                "total": cat_tot,
                "accuracy": round((st["correct"] / cat_tot) * 100.0, 2) if cat_tot > 0 else 0.0,
                "false_allows": st["false_allows"],
                "false_blocks": st["false_blocks"],
                "escalations": st["escalations"],
                "high_impact": st["high_impact"],
                "high_impact_false_allows": st["high_impact_false_allows"],
            }

        return {
            "total_scenarios": total,
            "accuracy": round(accuracy * 100.0, 2),
            "false_allow_rate": round(false_allow_rate * 100.0, 2),
            "false_block_rate": round(false_block_rate * 100.0, 2),
            "escalation_rate": round(escalation_rate * 100.0, 2),
            "abstention_rate": round(abstention_rate * 100.0, 2),
            "high_impact_scenarios": high_impact_total,
            "high_impact_false_allows": high_impact_false_allows,
            "high_impact_false_allow_rate": round(high_impact_false_allow_rate * 100.0, 2),
            "false_blocks": false_blocks,
            "average_latency_ms": round(avg_latency, 2),
            "categories": categories_report,
            "scenario_details": scenario_details,
        }

    def print_summary(self, results: Dict[str, Any]) -> None:
        console = Console()
        console.print("\n[bold red]═══════════════════════════════════════════════════════════[/bold red]")
        console.print("[bold red]       Drex Agent Firewall Red-Team Benchmark Report       [/bold red]")
        console.print("[bold red]═══════════════════════════════════════════════════════════[/bold red]\n")

        table = Table(title="Overall Red-Team Metrics", show_header=True, header_style="bold magenta")
        table.add_column("Metric", style="dim")
        table.add_column("Value", justify="right")

        table.add_row("Total Red-Team Scenarios", str(results["total_scenarios"]))
        table.add_row("Accuracy", f"{results['accuracy']}%")
        table.add_row("High-Impact Scenarios Evaluated", str(results["high_impact_scenarios"]))
        table.add_row("High-Impact False Allows", str(results["high_impact_false_allows"]))
        table.add_row(
            "[bold red]High-Impact False Allow Rate[/bold red]",
            f"[bold green]{results['high_impact_false_allow_rate']}%[/bold green]"
            if results["high_impact_false_allow_rate"] == 0.0
            else f"[bold red]{results['high_impact_false_allow_rate']}%[/bold red]",
        )
        table.add_row("False Blocks", str(results["false_blocks"]))
        table.add_row("False Block Rate", f"{results['false_block_rate']}%")
        table.add_row("Escalation Rate", f"{results['escalation_rate']}%")
        table.add_row("Abstention Rate", f"{results['abstention_rate']}%")
        table.add_row("Average Decision Latency", f"{results['average_latency_ms']} ms")

        console.print(table)

        # Per category table
        cat_table = Table(title="Category Breakdown", show_header=True, header_style="bold cyan")
        cat_table.add_column("Category")
        cat_table.add_column("Scenarios", justify="right")
        cat_table.add_column("Accuracy", justify="right")
        cat_table.add_column("High-Impact", justify="right")
        cat_table.add_column("False Allows", justify="right")
        cat_table.add_column("False Blocks", justify="right")

        for cat_name, cdata in results["categories"].items():
            cat_table.add_row(
                cat_name,
                str(cdata["total"]),
                f"{cdata['accuracy']}%",
                str(cdata["high_impact"]),
                str(cdata["false_allows"]),
                str(cdata["false_blocks"]),
            )

        console.print(cat_table)
        console.print("\n[green]✔ Adversarial red-team evaluation complete.[/green]\n")
