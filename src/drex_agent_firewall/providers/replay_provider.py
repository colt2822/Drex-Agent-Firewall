"""Deterministic Replay Provider for offline, testing, benchmark, and CI operation.

Strictly marked with provider='REPLAY' and resolved_model='replay-deterministic-v1'.
Preserves full probability distributions across all taxonomy dimensions.
"""

from __future__ import annotations

import re
import time
from typing import Dict

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


def _normalize_dist(d: Dict[str, float]) -> Dict[str, float]:
    total = sum(d.values())
    if total <= 0:
        return {k: round(1.0 / len(d), 4) for k in d}
    return {k: round(v / total, 4) for k, v in d.items()}


class ReplayProvider(BaseDecisionProvider):
    """Deterministic Replay Decision Provider."""

    def __init__(self, requested_model: str = "drex-latest"):
        self.requested_model = requested_model
        self.resolved_model = "replay-deterministic-v1"

    @property
    def provider_name(self) -> str:
        return "REPLAY"

    def evaluate(self, envelope: ActionEnvelope) -> DrexEvaluationResult:
        start_t = time.perf_counter()
        dist, winning = self._compute_distributions(envelope)
        latency_ms = (time.perf_counter() - start_t) * 1000.0

        return DrexEvaluationResult(
            provider="REPLAY",
            requested_model=self.requested_model,
            resolved_model=self.resolved_model,
            risk=winning["risk"],
            action_class=winning["action_class"],
            scope_match=winning["scope_match"],
            reversibility=winning["reversibility"],
            external_effect=winning["external_effect"],
            credential_risk=winning["credential_risk"],
            destructive_risk=winning["destructive_risk"],
            needs_human_approval=winning["needs_human_approval"],
            confidence=winning["confidence"],
            distributions=dist,
            provider_latency_ms=latency_ms,
            evaluation_notes=["Evaluated via deterministic ReplayProvider."],
        )

    async def evaluate_async(self, envelope: ActionEnvelope) -> DrexEvaluationResult:
        return self.evaluate(envelope)

    def _compute_distributions(self, env: ActionEnvelope):
        cmd = str(env.arguments.get("command") or env.resource_target or "").lower()
        tool = env.tool.lower()
        op = env.operation.lower()

        # 1. Action Class Heuristic
        if env.credential_access or "api_key" in cmd or "secret" in cmd or "auth" in op:
            ac_weights = {"AUTH": 0.96, "READ": 0.02, "NETWORK": 0.01, "EXECUTE": 0.005, "WRITE": 0.005}
        elif env.network_access or tool == "http" or "curl" in cmd or "wget" in cmd:
            ac_weights = {"NETWORK": 0.95, "READ": 0.03, "EXECUTE": 0.01, "EXTERNAL_PUBLISH": 0.01}
        elif tool == "github" and op in {"create_issue", "create_pr", "merge", "comment", "update_pr", "close", "label", "create_release", "delete_ref"}:
            ac_weights = {"EXTERNAL_PUBLISH": 0.98, "WRITE": 0.01, "NETWORK": 0.01}
        elif env.destructive or "rm -rf" in cmd or op in {"delete", "clean"}:
            ac_weights = {"DELETE": 0.99, "EXECUTE": 0.005, "WRITE": 0.005}
        elif env.filesystem_write or op in {"write", "modify", "edit_file", "commit", "create", "mkdir", "rename", "add", "format_files"}:
            ac_weights = {"WRITE": 0.96, "EXECUTE": 0.02, "READ": 0.02}
        elif env.read_only or op in {
            "read", "status", "diff", "log", "cat", "list_dir", "branch", "tag",
            "get_file", "search", "read_issue", "read_pr", "list_issues", "list_prs",
            "search_code", "lint_files", "run_tests", "git_status", "git_diff", "read_file", "list_directory"
        }:
            ac_weights = {"READ": 0.98, "EXECUTE": 0.01, "WRITE": 0.01}
        elif env.process_execution or tool == "shell":
            ac_weights = {"EXECUTE": 0.95, "READ": 0.03, "WRITE": 0.02}
        else:
            ac_weights = {"UNKNOWN": 0.90, "READ": 0.05, "WRITE": 0.05}

        # Ensure all enum values present
        ac_dist = {ac.value: 0.0001 for ac in ActionClass}
        ac_dist.update(ac_weights)
        action_class_dist = _normalize_dist(ac_dist)
        winning_ac = max(action_class_dist, key=action_class_dist.get)

        # 2. Risk Heuristic
        is_hard_destructive = "rm -rf" in cmd or "mkfs" in cmd or ":(){:|:&};:" in cmd or "chmod -r 777" in cmd or "dd if=" in cmd
        is_credential_leak = env.credential_access and (env.network_access or "post" in op or "curl" in cmd or tool == "http")
        is_force_push = "push" in op and ("--force" in cmd or "-f" in cmd or "+ref" in cmd or "+master" in cmd or env.arguments.get("force"))

        is_operational_high_impact = any(
            k in cmd
            for k in [
                "deploy", "terraform", "kubectl", "alembic", "docker system prune",
                "aws ec2", "vault token", "./bin/", "custom_deploy"
            ]
        ) or (tool == "shell" and "/tmp/" in cmd) or any(
            k in op
            for k in ["custom_deploy", "mutate_metadata"]
        )

        target = env.resource_target.lower()
        is_cache_deletion = op == "delete" and any(c in target for c in [".cache", ".pytest_cache", "temp", "tmp"])

        if is_hard_destructive or is_credential_leak:
            risk_dist = {"CRITICAL": 0.98, "HIGH": 0.015, "MEDIUM": 0.004, "LOW": 0.001}
        elif is_cache_deletion:
            risk_dist = {"CRITICAL": 0.001, "HIGH": 0.01, "MEDIUM": 0.05, "LOW": 0.939}
        elif env.destructive or is_force_push or "shadow" in cmd or "sudoers" in cmd or env.credential_access:
            risk_dist = {"CRITICAL": 0.15, "HIGH": 0.83, "MEDIUM": 0.015, "LOW": 0.005}
        elif is_operational_high_impact:
            risk_dist = {"CRITICAL": 0.05, "HIGH": 0.85, "MEDIUM": 0.09, "LOW": 0.01}
        elif env.external_write or (tool == "git" and op == "push"):
            risk_dist = {"CRITICAL": 0.01, "HIGH": 0.20, "MEDIUM": 0.77, "LOW": 0.02}
        elif env.filesystem_write or op in {"commit", "modify", "write", "create", "mkdir", "rename"}:
            risk_dist = {"CRITICAL": 0.001, "HIGH": 0.01, "MEDIUM": 0.04, "LOW": 0.949}
        else:
            # Benign reads, safe shell, local inspections
            risk_dist = {"CRITICAL": 0.0001, "HIGH": 0.001, "MEDIUM": 0.02, "LOW": 0.9789}

        risk_dist = _normalize_dist({r.value: risk_dist.get(r.value, 0.001) for r in ActionRisk})
        winning_risk = max(risk_dist, key=risk_dist.get)

        # 3. Scope Match
        scope_out = False
        target = env.resource_target
        if env.blocked_paths and any(bp in target for bp in env.blocked_paths):
            scope_out = True
        elif target.startswith("/etc") or target.startswith("/root") or target.startswith("/var") or "/../" in target:
            scope_out = True

        if scope_out:
            sm_dist = {"OUT_OF_SCOPE": 0.98, "POSSIBLY_IN_SCOPE": 0.015, "IN_SCOPE": 0.004, "UNKNOWN": 0.001}
        elif env.repository_scope and env.repository and env.repository != env.repository_scope:
            sm_dist = {"OUT_OF_SCOPE": 0.92, "POSSIBLY_IN_SCOPE": 0.06, "IN_SCOPE": 0.015, "UNKNOWN": 0.005}
        else:
            sm_dist = {"IN_SCOPE": 0.96, "POSSIBLY_IN_SCOPE": 0.03, "OUT_OF_SCOPE": 0.005, "UNKNOWN": 0.005}
        sm_dist = _normalize_dist({s.value: sm_dist.get(s.value, 0.001) for s in ScopeMatch})
        winning_scope = max(sm_dist, key=sm_dist.get)

        # 4. Reversibility
        if is_hard_destructive or (tool == "git" and is_force_push) or (tool == "http" and op in {"post", "put", "delete"}):
            rev_dist = {"IRREVERSIBLE": 0.97, "PARTIALLY_REVERSIBLE": 0.02, "FULLY_REVERSIBLE": 0.009, "UNKNOWN": 0.001}
        elif env.filesystem_write or op in {"commit", "write", "create"}:
            rev_dist = {"PARTIALLY_REVERSIBLE": 0.85, "FULLY_REVERSIBLE": 0.12, "IRREVERSIBLE": 0.029, "UNKNOWN": 0.001}
        elif env.read_only:
            rev_dist = {"FULLY_REVERSIBLE": 0.99, "PARTIALLY_REVERSIBLE": 0.008, "IRREVERSIBLE": 0.001, "UNKNOWN": 0.001}
        else:
            rev_dist = {"FULLY_REVERSIBLE": 0.60, "PARTIALLY_REVERSIBLE": 0.35, "IRREVERSIBLE": 0.04, "UNKNOWN": 0.01}
        rev_dist = _normalize_dist({r.value: rev_dist.get(r.value, 0.001) for r in Reversibility})
        winning_rev = max(rev_dist, key=rev_dist.get)

        # 5. External Effect
        if tool in {"github", "http"} or (tool == "git" and op == "push"):
            if winning_rev == "IRREVERSIBLE":
                ee_dist = {"REMOTE_IRREVERSIBLE": 0.95, "REMOTE_REVERSIBLE": 0.04, "LOCAL_ONLY": 0.005, "NONE": 0.004, "UNKNOWN": 0.001}
            else:
                ee_dist = {"REMOTE_REVERSIBLE": 0.92, "REMOTE_IRREVERSIBLE": 0.06, "LOCAL_ONLY": 0.01, "NONE": 0.009, "UNKNOWN": 0.001}
        elif env.filesystem_write or env.process_execution:
            ee_dist = {"LOCAL_ONLY": 0.96, "NONE": 0.03, "REMOTE_REVERSIBLE": 0.005, "REMOTE_IRREVERSIBLE": 0.004, "UNKNOWN": 0.001}
        else:
            ee_dist = {"NONE": 0.985, "LOCAL_ONLY": 0.01, "REMOTE_REVERSIBLE": 0.002, "REMOTE_IRREVERSIBLE": 0.002, "UNKNOWN": 0.001}
        ee_dist = _normalize_dist({e.value: ee_dist.get(e.value, 0.001) for e in ExternalEffect})
        winning_ee = max(ee_dist, key=ee_dist.get)

        # 6. Credential Risk
        if is_credential_leak:
            cr_dist = {"SECRET_TRANSMISSION": 0.99, "READ_ONLY_SECRET_ACCESS": 0.005, "SECRET_PERSISTENCE": 0.004, "NONE": 0.0005, "UNKNOWN": 0.0005}
        elif env.credential_access:
            cr_dist = {"READ_ONLY_SECRET_ACCESS": 0.95, "SECRET_TRANSMISSION": 0.03, "SECRET_PERSISTENCE": 0.015, "NONE": 0.004, "UNKNOWN": 0.001}
        else:
            cr_dist = {"NONE": 0.995, "READ_ONLY_SECRET_ACCESS": 0.002, "SECRET_TRANSMISSION": 0.001, "SECRET_PERSISTENCE": 0.001, "UNKNOWN": 0.001}
        cr_dist = _normalize_dist({c.value: cr_dist.get(c.value, 0.001) for c in CredentialRisk})
        winning_cr = max(cr_dist, key=cr_dist.get)

        # 7. Destructive Risk
        is_cache_deletion = op == "delete" and ".cache" in target
        if is_hard_destructive:
            dr_dist = {"HIGH": 0.99, "MODERATE": 0.005, "LOW": 0.004, "NONE": 0.001}
        elif is_cache_deletion:
            dr_dist = {"LOW": 0.90, "MODERATE": 0.08, "HIGH": 0.01, "NONE": 0.01}
        elif env.destructive or is_force_push:
            dr_dist = {"HIGH": 0.90, "MODERATE": 0.08, "LOW": 0.015, "NONE": 0.005}
        elif env.filesystem_write:
            dr_dist = {"MODERATE": 0.05, "LOW": 0.90, "HIGH": 0.005, "NONE": 0.045}
        else:
            dr_dist = {"NONE": 0.98, "LOW": 0.015, "MODERATE": 0.004, "HIGH": 0.001}
        dr_dist = _normalize_dist({d.value: dr_dist.get(d.value, 0.001) for d in DestructiveRisk})
        winning_dr = max(dr_dist, key=dr_dist.get)

        # 8. Needs Human Approval
        if (
            winning_risk in {"CRITICAL", "HIGH"}
            or is_force_push
            or (tool == "git" and op == "push")
            or env.credential_access
            or is_operational_high_impact
        ):
            ha_dist = {"YES": 0.97, "UNCERTAIN": 0.02, "NO": 0.01}
        elif winning_risk == "MEDIUM" or env.external_write:
            ha_dist = {"YES": 0.65, "UNCERTAIN": 0.25, "NO": 0.10}
        else:
            ha_dist = {"NO": 0.98, "UNCERTAIN": 0.015, "YES": 0.005}
        ha_dist = _normalize_dist({h.value: ha_dist.get(h.value, 0.001) for h in NeedsHumanApproval})
        winning_ha = max(ha_dist, key=ha_dist.get)

        confidence = float(action_class_dist[winning_ac])

        full_dist = FullProbabilityDistribution(
            risk=risk_dist,
            action_class=action_class_dist,
            scope_match=sm_dist,
            reversibility=rev_dist,
            external_effect=ee_dist,
            credential_risk=cr_dist,
            destructive_risk=dr_dist,
            needs_human_approval=ha_dist,
        )

        winning_enums = {
            "risk": ActionRisk(winning_risk),
            "action_class": ActionClass(winning_ac),
            "scope_match": ScopeMatch(winning_scope),
            "reversibility": Reversibility(winning_rev),
            "external_effect": ExternalEffect(winning_ee),
            "credential_risk": CredentialRisk(winning_cr),
            "destructive_risk": DestructiveRisk(winning_dr),
            "needs_human_approval": NeedsHumanApproval(winning_ha),
            "confidence": confidence,
        }

        return full_dist, winning_enums
