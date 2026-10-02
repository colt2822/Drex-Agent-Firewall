"""Confidence thresholds verification and evaluation."""

from __future__ import annotations

from typing import Tuple

from drex_agent_firewall.schemas.config import ConfidenceThresholds
from drex_agent_firewall.schemas.decision import ActionClass, DrexEvaluationResult


class ThresholdEvaluator:
    """Evaluates whether Drex's decision confidence meets the required threshold."""

    def __init__(self, thresholds: ConfidenceThresholds):
        self.thresholds = thresholds

    def check(self, eval_result: DrexEvaluationResult) -> Tuple[bool, float, float]:
        """
        Returns: (passes_threshold, actual_confidence, required_threshold)
        """
        required = self.thresholds.for_action_class(eval_result.action_class)
        actual = eval_result.confidence
        return (actual >= required, actual, required)
