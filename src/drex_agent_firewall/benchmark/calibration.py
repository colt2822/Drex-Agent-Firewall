"""Calibration and outcome evaluation for Drex Agent Firewall probabilistic predictions.

Evaluates correlation between Drex predicted risk/approval probabilities and actual execution outcomes.
Computes:
1. Brier Score on high-risk prediction
2. Expected Calibration Error (ECE) across probability deciles
3. Outcome correlation matrix (predicted risk vs actual blocked/failed execution)
"""

from __future__ import annotations

import json
import math
from typing import Any, Dict, List, Optional, Tuple

from drex_agent_firewall.persistence.repository import ActionRepository


class CalibrationEvaluator:
    """Evaluates probabilistic calibration of Drex Agent Firewall against real execution outcomes."""

    def __init__(self, db_path: str = "drex_firewall.db"):
        self.repository = ActionRepository(db_path=db_path)

    def evaluate_calibration(self, limit: int = 500) -> Dict[str, Any]:
        """Compute calibration metrics from recorded audit actions."""
        actions = self.repository.list_actions(limit=limit)
        if not actions:
            return {"status": "no_data", "samples": 0}

        evaluated_pairs: List[Tuple[float, int]] = []
        outcomes_by_risk: Dict[str, Dict[str, int]] = {
            "LOW": {"total": 0, "blocked": 0, "error": 0, "success": 0},
            "MEDIUM": {"total": 0, "blocked": 0, "error": 0, "success": 0},
            "HIGH": {"total": 0, "blocked": 0, "error": 0, "success": 0},
            "CRITICAL": {"total": 0, "blocked": 0, "error": 0, "success": 0},
        }

        for act in actions:
            raw_dist = act.get("full_probability_distribution")
            if not raw_dist:
                if act.get("hard_policy_triggered"):
                    evaluated_pairs.append((1.0, 1))
                    outcomes_by_risk["CRITICAL"]["total"] += 1
                    outcomes_by_risk["CRITICAL"]["blocked"] += 1
                continue

            dist = json.loads(raw_dist) if isinstance(raw_dist, str) else raw_dist
            risk_dist = dist.get("risk", {})

            # Predicted probability of High or Critical risk
            p_high_risk = float(risk_dist.get("HIGH", 0.0) + risk_dist.get("CRITICAL", 0.0))

            # Actual outcome: was it blocked or an execution error/failure?
            was_adverse = 1 if (not act.get("allowed") or act.get("outcome") in {"FAILURE", "ERROR"}) else 0
            evaluated_pairs.append((p_high_risk, was_adverse))

            # Tally by winning risk
            winning_risk = max(risk_dist, key=risk_dist.get) if risk_dist else "LOW"
            if winning_risk in outcomes_by_risk:
                outcomes_by_risk[winning_risk]["total"] += 1
                if not act.get("allowed"):
                    outcomes_by_risk[winning_risk]["blocked"] += 1
                elif act.get("outcome") in {"FAILURE", "ERROR"}:
                    outcomes_by_risk[winning_risk]["error"] += 1
                else:
                    outcomes_by_risk[winning_risk]["success"] += 1

        if not evaluated_pairs:
            return {"status": "insufficient_probabilistic_data", "samples": 0}

        # 1. Brier Score
        brier_score = sum((p - actual) ** 2 for p, actual in evaluated_pairs) / len(evaluated_pairs)

        # 2. Expected Calibration Error (ECE) with 10 bins
        num_bins = 10
        bin_size = 1.0 / num_bins
        ece = 0.0
        bin_details = []

        for b in range(num_bins):
            bin_lower = b * bin_size
            bin_upper = (b + 1) * bin_size
            in_bin = [pair for pair in evaluated_pairs if bin_lower <= pair[0] < bin_upper or (b == num_bins - 1 and pair[0] == bin_upper)]
            if in_bin:
                avg_confidence = sum(p for p, _ in in_bin) / len(in_bin)
                empirical_accuracy = sum(actual for _, actual in in_bin) / len(in_bin)
                weight = len(in_bin) / len(evaluated_pairs)
                ece += weight * abs(avg_confidence - empirical_accuracy)
                bin_details.append({
                    "bin_range": f"{bin_lower:.1f}-{bin_upper:.1f}",
                    "count": len(in_bin),
                    "avg_confidence": round(avg_confidence, 4),
                    "empirical_adverse_rate": round(empirical_accuracy, 4),
                })

        # 3. Correlation (Point-Biserial)
        mean_p = sum(p for p, _ in evaluated_pairs) / len(evaluated_pairs)
        mean_y = sum(y for _, y in evaluated_pairs) / len(evaluated_pairs)
        var_p = sum((p - mean_p) ** 2 for p, _ in evaluated_pairs)
        var_y = sum((y - mean_y) ** 2 for _, y in evaluated_pairs)

        if var_p > 0 and var_y > 0:
            cov = sum((p - mean_p) * (y - mean_y) for p, y in evaluated_pairs)
            correlation = cov / math.sqrt(var_p * var_y)
        else:
            correlation = 1.0 if (var_p == 0 and var_y == 0) else 0.0

        return {
            "samples": len(evaluated_pairs),
            "brier_score": round(brier_score, 4),
            "expected_calibration_error": round(ece, 4),
            "risk_outcome_correlation": round(correlation, 4),
            "calibration_quality": "HIGH" if brier_score < 0.15 and correlation > 0.70 else "MODERATE",
            "outcomes_by_risk": outcomes_by_risk,
            "bins": bin_details,
        }
