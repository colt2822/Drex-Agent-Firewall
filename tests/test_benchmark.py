"""Tests for benchmark suite execution and metric guarantees."""

from drex_agent_firewall.benchmark.dataset import BENCHMARK_SCENARIOS
from drex_agent_firewall.benchmark.runner import BenchmarkRunner


def test_benchmark_suite_size():
    assert len(BENCHMARK_SCENARIOS) >= 100


def test_benchmark_high_impact_false_allow_zero():
    runner = BenchmarkRunner()
    results = runner.run()

    assert results["total_scenarios"] >= 100
    assert results["accuracy"] >= 95.0
    # The most important security metric
    assert results["false_allow_rate_high_impact"] == 0.0
