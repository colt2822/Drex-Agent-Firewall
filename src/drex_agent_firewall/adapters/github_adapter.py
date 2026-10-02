"""GitHub API adapter with remote side-effect isolation and credential stripping."""

from __future__ import annotations

import hashlib
import time
from typing import Any, Dict, List, Optional
import httpx

from drex_agent_firewall.adapters.base import BaseAdapter
from drex_agent_firewall.schemas.decision import FirewallDecision


class GitHubResult:
    def __init__(
        self,
        operation: str,
        allowed: bool,
        firewall_decision: FirewallDecision,
        data: Optional[Dict[str, Any]] = None,
        idempotency_key: Optional[str] = None,
        error: Optional[str] = None,
    ):
        self.operation = operation
        self.allowed = allowed
        self.firewall_decision = firewall_decision
        self.data = data
        self.idempotency_key = idempotency_key
        self.error = error

    def to_dict(self) -> Dict[str, Any]:
        return {
            "operation": self.operation,
            "allowed": self.allowed,
            "decision": self.firewall_decision.decision.value,
            "idempotency_key": self.idempotency_key,
            "data": self.data,
            "error": self.error,
        }


class GitHubAdapter(BaseAdapter):
    """Guarded GitHub adapter managing API requests and preventing secret leakage."""

    def __init__(
        self,
        engine,
        repository=None,
        normalizer=None,
        github_token: Optional[str] = None,
        base_url: str = "https://api.github.com",
    ):
        super().__init__(engine, repository, normalizer)
        self.github_token = github_token
        self.base_url = base_url.rstrip("/")
        # Register token in redactor so it is never leaked
        if github_token:
            self.engine.redactor.register_secret(github_token)

    def read_issue(self, repo: str, issue_number: int) -> GitHubResult:
        return self._run_gh_op("read_issue", repo, {"issue_number": issue_number}, method="GET", path=f"/repos/{repo}/issues/{issue_number}")

    def read_pr(self, repo: str, pr_number: int) -> GitHubResult:
        return self._run_gh_op("read_pr", repo, {"pr_number": pr_number}, method="GET", path=f"/repos/{repo}/pulls/{pr_number}")

    def comment(self, repo: str, issue_or_pr_number: int, body: str) -> GitHubResult:
        return self._run_gh_op(
            "comment",
            repo,
            {"number": issue_or_pr_number, "body": body},
            method="POST",
            path=f"/repos/{repo}/issues/{issue_or_pr_number}/comments",
            json_body={"body": body},
        )

    def create_issue(self, repo: str, title: str, body: str, labels: Optional[List[str]] = None) -> GitHubResult:
        payload = {"title": title, "body": body}
        if labels:
            payload["labels"] = labels
        return self._run_gh_op("create_issue", repo, payload, method="POST", path=f"/repos/{repo}/issues", json_body=payload)

    def create_pr(self, repo: str, title: str, head: str, base: str, body: str) -> GitHubResult:
        payload = {"title": title, "head": head, "base": base, "body": body}
        return self._run_gh_op("create_pr", repo, payload, method="POST", path=f"/repos/{repo}/pulls", json_body=payload)

    def update_pr(self, repo: str, pr_number: int, title: Optional[str] = None, body: Optional[str] = None) -> GitHubResult:
        payload = {}
        if title:
            payload["title"] = title
        if body:
            payload["body"] = body
        return self._run_gh_op("update_pr", repo, payload, method="PATCH", path=f"/repos/{repo}/pulls/{pr_number}", json_body=payload)

    def merge_pr(self, repo: str, pr_number: int, commit_title: Optional[str] = None) -> GitHubResult:
        payload = {"commit_title": commit_title} if commit_title else {}
        return self._run_gh_op("merge", repo, payload, method="PUT", path=f"/repos/{repo}/pulls/{pr_number}/merge", json_body=payload)

    def close_issue(self, repo: str, issue_number: int) -> GitHubResult:
        payload = {"state": "closed"}
        return self._run_gh_op("close", repo, payload, method="PATCH", path=f"/repos/{repo}/issues/{issue_number}", json_body=payload)

    def add_labels(self, repo: str, issue_number: int, labels: List[str]) -> GitHubResult:
        payload = {"labels": labels}
        return self._run_gh_op("label", repo, payload, method="POST", path=f"/repos/{repo}/issues/{issue_number}/labels", json_body=payload)

    def _run_gh_op(
        self,
        operation: str,
        repo: str,
        arguments: Dict[str, Any],
        method: str,
        path: str,
        json_body: Optional[Dict[str, Any]] = None,
    ) -> GitHubResult:
        is_read = method == "GET"
        args_payload = dict(arguments)
        args_payload.update({"repo": repo, "operation": operation, "method": method})

        # Calculate idempotency key for mutations
        idempotency_key = None
        if not is_read:
            hash_input = f"{repo}:{path}:{method}:{str(json_body)}"
            idempotency_key = hashlib.sha256(hash_input.encode("utf-8")).hexdigest()[:16]
            args_payload["idempotency_key"] = idempotency_key

        envelope, decision = self.evaluate_action(
            tool="github",
            operation=operation,
            arguments=args_payload,
            context={"repo": repo, "repository_scope": repo},
        )

        if not decision.allowed:
            self.record_execution_result(
                action_id=envelope.action_id,
                tool="github",
                executed=False,
                error_class="FIREWALL_POLICY_BLOCKED",
            )
            return GitHubResult(
                operation=operation,
                allowed=False,
                firewall_decision=decision,
                idempotency_key=idempotency_key,
                error=f"Blocked by firewall: {decision.reason}",
            )

        # If live token not present, return simulated successful response
        if not self.github_token:
            simulated_data = {
                "simulated": True,
                "operation": operation,
                "repo": repo,
                "method": method,
                "idempotency_key": idempotency_key,
                "status": "mock_success_no_token",
            }
            self.record_execution_result(
                action_id=envelope.action_id,
                tool="github",
                executed=True,
                result=simulated_data,
            )
            return GitHubResult(
                operation=operation,
                allowed=True,
                firewall_decision=decision,
                data=simulated_data,
                idempotency_key=idempotency_key,
            )

        # Live call with token
        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {self.github_token}",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if idempotency_key:
            headers["Idempotency-Key"] = idempotency_key

        try:
            with httpx.Client(timeout=10.0) as client:
                resp = client.request(
                    method,
                    f"{self.base_url}{path}",
                    headers=headers,
                    json=json_body,
                )
                resp.raise_for_status()
                data = resp.json() if resp.content else {"status": "ok"}
                self.record_execution_result(
                    action_id=envelope.action_id,
                    tool="github",
                    executed=True,
                    result={"status_code": resp.status_code},
                )
                return GitHubResult(
                    operation=operation,
                    allowed=True,
                    firewall_decision=decision,
                    data=data,
                    idempotency_key=idempotency_key,
                )
        except Exception as e:
            self.record_execution_result(
                action_id=envelope.action_id,
                tool="github",
                executed=False,
                error_class=type(e).__name__,
            )
            return GitHubResult(
                operation=operation,
                allowed=True,
                firewall_decision=decision,
                error=f"GitHub API request failed: {str(e)}",
            )
