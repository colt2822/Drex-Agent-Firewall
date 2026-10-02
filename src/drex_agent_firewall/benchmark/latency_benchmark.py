"""Latency and overhead benchmark for Drex Agent Firewall.

Measures latency profiles across:
1. Local deterministic policy only (invariants & regex & normalizer)
2. Drex Replay mode (local probabilistic provider + deterministic policy + SQLite audit)
3. Live Drex mode (live API provider over HTTPS to drex.nace.ai)

Reports P50, P95, P99, mean, min, max, and throughput.
"""

from __future__ import annotations

import os
import statistics
import time
from typing import Any, Dict, List, Optional

from drex_agent_firewall.normalizers.context_normalizer import ContextNormalizer
from drex_agent_firewall.persistence.repository import ActionRepository
from drex_agent_firewall.policy.engine import DeterministicPolicyEngine
from drex_agent_firewall.providers.drex_provider import DrexProvider
from drex_agent_firewall.providers.replay_provider import ReplayProvider
from drex_agent_firewall.schemas.config import FirewallConfig
from drex_agent_firewall.security.redactor import SecretRedactor


class LatencyBenchmark:
    """Measures latency distributions for firewall decision components."""

    SAMPLE_ACTIONS = [
        {"tool": "shell", "operation": "execute", "arguments": {"command": "pytest tests/ -v"}, "context": {"cwd": "/workspace"}},
        {"tool": "filesystem", "operation": "read", "arguments": {"path": "/workspace/src/app.py"}, "context": {}},
        {"tool": "filesystem", "operation": "modify", "arguments": {"path": "/workspace/src/app.py", "content": "print('hello')"}, "context": {}},
        {"tool": "git", "operation": "commit", "arguments": {"command": "git commit -m 'fix: bug'"}, "context": {}},
        {"tool": "http", "operation": "GET", "arguments": {"url": "https://api.github.com/repos/test/repo"}, "context": {}},
    ]

    @staticmethod
    def _compute_percentiles(times_ms: List[float]) -> Dict[str, float]:
        if not times_ms:
            return {"p50": 0.0, "p95": 0.0, "p99": 0.0, "mean": 0.0, "min": 0.0, "max": 0.0}
        times_sorted = sorted(times_ms)
        n = len(times_sorted)
        p50 = times_sorted[int(n * 0.50)]
        p95 = times_sorted[min(int(n * 0.95), n - 1)]
        p99 = times_sorted[min(int(n * 0.99), n - 1)]
        return {
            "p50": round(p50, 3),
            "p95": round(p95, 3),
            "p99": round(p99, 3),
            "mean": round(statistics.mean(times_ms), 3),
            "min": round(min(times_ms), 3),
            "max": round(max(times_ms), 3),
        }

    def benchmark_local_policy(self, iterations: int = 200) -> Dict[str, Any]:
        """Measure pure deterministic policy engine without provider or DB persistence."""
        cfg = FirewallConfig()
        cfg.provider.type = "replay"
        redactor = SecretRedactor()
        normalizer = ContextNormalizer(redactor)
        engine = DeterministicPolicyEngine(config=cfg, provider=None, redactor=redactor)

        latencies_ms = []
        for i in range(iterations):
            sample = self.SAMPLE_ACTIONS[i % len(self.SAMPLE_ACTIONS)]
            t0 = time.perf_counter()
            env = normalizer.normalize(
                tool=sample["tool"],
                operation=sample["operation"],
                arguments=sample["arguments"],
                context=sample["context"],
            )
            engine.hard_rules.evaluate(env)
            t1 = time.perf_counter()
            latencies_ms.append((t1 - t0) * 1000.0)

        metrics = self._compute_percentiles(latencies_ms)
        metrics["iterations"] = iterations
        metrics["throughput_ops_sec"] = round(iterations / (sum(latencies_ms) / 1000.0), 1) if sum(latencies_ms) > 0 else 0
        return metrics

    def benchmark_replay_firewall(self, iterations: int = 200) -> Dict[str, Any]:
        """Measure full firewall stack with replay provider and SQLite logging."""
        db_path = "/tmp/bench_replay_latency.db"
        if os.path.exists(db_path):
            os.remove(db_path)

        cfg = FirewallConfig()
        cfg.provider.type = "replay"
        cfg.database_path = db_path
        redactor = SecretRedactor()
        normalizer = ContextNormalizer(redactor)
        provider = ReplayProvider()
        engine = DeterministicPolicyEngine(config=cfg, provider=provider, redactor=redactor)
        repo = ActionRepository(db_path=db_path)

        latencies_ms = []
        for i in range(iterations):
            sample = self.SAMPLE_ACTIONS[i % len(self.SAMPLE_ACTIONS)]
            t0 = time.perf_counter()
            env = normalizer.normalize(
                tool=sample["tool"],
                operation=sample["operation"],
                arguments=sample["arguments"],
                context=sample["context"],
            )
            decision = engine.evaluate(env)
            repo.record_decision(env, decision)
            t1 = time.perf_counter()
            latencies_ms.append((t1 - t0) * 1000.0)

        if os.path.exists(db_path):
            os.remove(db_path)

        metrics = self._compute_percentiles(latencies_ms)
        metrics["iterations"] = iterations
        metrics["throughput_ops_sec"] = round(iterations / (sum(latencies_ms) / 1000.0), 1) if sum(latencies_ms) > 0 else 0
        return metrics

    def benchmark_live_drex(self, max_requests: int = 5) -> Dict[str, Any]:
        """Measure live Drex API provider latency over HTTPS (bounded count)."""
        api_key = os.environ.get("DREX_API_KEY", "")
        if not api_key:
            key_path = os.path.expanduser("~/DREX KEY.txt")
            if os.path.exists(key_path):
                with open(key_path) as f:
                    api_key = f.read().strip()

        if not api_key:
            return {"status": "skipped", "reason": "No live Drex API key available"}

        provider = DrexProvider(
            api_url="https://drex.nace.ai/v1/systemone",
            api_key=api_key,
            timeout_seconds=5.0,
        )
        redactor = SecretRedactor()
        normalizer = ContextNormalizer(redactor)

        latencies_ms = []
        for i in range(max_requests):
            sample = self.SAMPLE_ACTIONS[i % len(self.SAMPLE_ACTIONS)]
            env = normalizer.normalize(
                tool=sample["tool"],
                operation=sample["operation"],
                arguments=sample["arguments"],
                context=sample["context"],
            )
            t0 = time.perf_counter()
            try:
                res = provider.evaluate(env)
                t1 = time.perf_counter()
                latencies_ms.append((t1 - t0) * 1000.0)
            except Exception as e:
                latencies_ms.append(5000.0)

        metrics = self._compute_percentiles(latencies_ms)
        metrics["requests"] = len(latencies_ms)
        metrics["status"] = "completed"
        return metrics

    def benchmark_sandbox_overhead(self, iterations: int = 15) -> Dict[str, Any]:
        """Measure sandbox creation and execution overhead."""
        from drex_agent_firewall.sandbox.manager import SandboxManager

        mgr = SandboxManager()
        startup_ms = []
        exec_ms = []

        for i in range(iterations):
            t0 = time.perf_counter()
            info = mgr.create_session(workspace_path=".", policy_pack="safe-local-coding")
            t1 = time.perf_counter()
            startup_ms.append((t1 - t0) * 1000.0)

            t2 = time.perf_counter()
            res = mgr.exec_command(info.session_id, ["python3", "-c", "pass"])
            t3 = time.perf_counter()
            exec_ms.append((t3 - t2) * 1000.0)

            mgr.stop_session(info.session_id)
            mgr.destroy_session(info.session_id)

        startup_metrics = self._compute_percentiles(startup_ms)
        exec_metrics = self._compute_percentiles(exec_ms)
        return {
            "startup": startup_metrics,
            "exec": exec_metrics,
            "p50": startup_metrics["p50"],
            "p95": startup_metrics["p95"],
            "p99": startup_metrics["p99"],
            "mean": startup_metrics["mean"],
            "throughput_ops_sec": round(iterations / (sum(startup_ms) / 1000.0), 1) if sum(startup_ms) > 0 else 0,
        }

    def run_all(self) -> Dict[str, Any]:
        """Run all latency benchmarks and return combined report."""
        return {
            "local_deterministic_policy": self.benchmark_local_policy(iterations=200),
            "full_replay_firewall": self.benchmark_replay_firewall(iterations=200),
            "sandbox_startup_overhead": self.benchmark_sandbox_overhead(iterations=10),
            "live_drex_api": self.benchmark_live_drex(max_requests=5),
        }
