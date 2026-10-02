"""Policy simulator for replaying historical traces across different policy packs.

Compares ALLOW, CONSTRAIN, ESCALATE, ABSTAIN, and BLOCK decisions without
re-executing any side effects or mutating state.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from drex_agent_firewall.normalizers.context_normalizer import ContextNormalizer
from drex_agent_firewall.policy.engine import DeterministicPolicyEngine
from drex_agent_firewall.policy.packs import POLICY_PACKS, get_policy_pack
from drex_agent_firewall.providers.base import BaseDecisionProvider
from drex_agent_firewall.providers.replay_provider import ReplayProvider
from drex_agent_firewall.schemas.config import FirewallConfig
from drex_agent_firewall.schemas.decision import FinalDecision, FirewallDecision
from drex_agent_firewall.schemas.envelope import ActionEnvelope


class PolicySimulator:
    """Simulates policy evaluations over historical traces or synthetic action envelopes."""

    def __init__(self, provider: Optional[BaseDecisionProvider] = None):
        self.provider = provider or ReplayProvider(requested_model="drex-latest")
        self.normalizer = ContextNormalizer()

    def compare_packs(
        self,
        actions: List[Dict[str, Any] | ActionEnvelope],
        pack_names: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Replay a set of actions against multiple policy packs and return comparative outcomes."""
        selected_packs = pack_names or ["safe-local-coding", "github-contributor", "read-only-research", "paranoid"]

        # Build policy engines for each pack
        engines: Dict[str, DeterministicPolicyEngine] = {}
        for p_name in selected_packs:
            cfg = get_policy_pack(p_name)
            engines[p_name] = DeterministicPolicyEngine(config=cfg, provider=self.provider)

        # Standardize action envelopes
        envelopes: List[ActionEnvelope] = []
        for item in actions:
            if isinstance(item, ActionEnvelope):
                envelopes.append(item)
            elif isinstance(item, dict):
                # Check if it has raw action parameters or stored audit row format
                tool = item.get("tool", "shell")
                op = item.get("operation", "execute")
                args = item.get("arguments_json") if "arguments_json" in item else item.get("arguments", {})
                if isinstance(args, str):
                    import json
                    try:
                        args = json.loads(args)
                    except Exception:
                        args = {}
                ctx = item.get("context", {})
                env = self.normalizer.normalize(
                    tool=tool,
                    operation=op,
                    arguments=args,
                    context=ctx,
                    action_id=item.get("action_id"),
                    trace_id=item.get("trace_id"),
                )
                envelopes.append(env)

        # Run comparative simulations
        comparison_rows: List[Dict[str, Any]] = []
        pack_summaries: Dict[str, Dict[str, int]] = {
            p: {"ALLOW": 0, "ALLOW_WITH_CONSTRAINTS": 0, "ESCALATE": 0, "ABSTAIN": 0, "BLOCK": 0}
            for p in selected_packs
        }

        for env in envelopes:
            row: Dict[str, Any] = {
                "action_id": env.action_id,
                "tool": env.tool,
                "operation": env.operation,
                "target": env.resource_target,
                "decisions": {},
            }

            for p_name, eng in engines.items():
                decision: FirewallDecision = eng.evaluate(env)
                dec_val = decision.decision.value
                row["decisions"][p_name] = {
                    "decision": dec_val,
                    "allowed": decision.allowed,
                    "reason": decision.reason,
                    "hard_policy_triggered": decision.hard_policy_triggered,
                }
                if dec_val in pack_summaries[p_name]:
                    pack_summaries[p_name][dec_val] += 1

            comparison_rows.append(row)

        return {
            "total_actions": len(envelopes),
            "packs_compared": selected_packs,
            "summaries": pack_summaries,
            "comparisons": comparison_rows,
        }

    def simulate_historical_traces(
        self,
        limit: int = 100,
        db_path: str = "drex_firewall.db",
        pack_names: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Query historical actions from database and simulate across policy packs."""
        from drex_agent_firewall.persistence.repository import ActionRepository
        repo = ActionRepository(db_path=db_path)
        actions = repo.list_actions(limit=limit)
        res = self.compare_packs(actions, pack_names)

        matrix = {}
        for p, counts in res["summaries"].items():
            tot = res["total_actions"]
            allowed = counts.get("ALLOW", 0) + counts.get("ALLOW_WITH_CONSTRAINTS", 0)
            blocked = counts.get("BLOCK", 0)
            escalated = counts.get("ESCALATE", 0)
            matrix[p] = {
                "total": tot,
                "allowed": allowed,
                "blocked": blocked,
                "escalated": escalated,
                "pass_rate": round(allowed / tot * 100, 1) if tot > 0 else 0.0,
            }
        return matrix
