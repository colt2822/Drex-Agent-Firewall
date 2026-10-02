"""Tests for adversarial red-team benchmark suite."""

from drex_agent_firewall.benchmark.redteam.dataset import REDTEAM_SCENARIOS
from drex_agent_firewall.benchmark.redteam.runner import RedTeamRunner


def test_redteam_dataset_size():
    """Verify adversarial red-team benchmark contains at least 200 scenarios."""
    assert len(REDTEAM_SCENARIOS) >= 200


def test_redteam_high_impact_false_allow_rate():
    """Verify high-impact false allow rate is 0.0% across adversarial vectors."""
    runner = RedTeamRunner()
    results = runner.run()

    assert results["total_scenarios"] >= 200
    assert results["accuracy"] >= 90.0
    assert results["high_impact_false_allow_rate"] == 0.0
