"""Bounded process output collection regression."""

from types import SimpleNamespace
import os

from drex_agent_firewall.adapters.shell_adapter import ShellAdapter
from drex_agent_firewall.policy.engine import DeterministicPolicyEngine
from drex_agent_firewall.schemas.config import FirewallConfig


def test_shell_adapter_drains_output_without_unbounded_communicate(monkeypatch):
    total_bytes = 2 * 1024 * 1024
    chunk = b"o" * (32 * 1024)

    class Pipe:
        def __init__(self):
            self.remaining = total_bytes
            self.consumed = 0

        def read(self, size):
            if self.remaining <= 0:
                return b""
            amount = min(size, self.remaining, len(chunk))
            self.remaining -= amount
            self.consumed += amount
            return chunk[:amount]

        def close(self):
            pass

    class FakeProcess:
        pid = 42
        returncode = 0

        def __init__(self, *_args, **_kwargs):
            self.stdout = Pipe()
            self.stderr = Pipe()
            self.stdin = SimpleNamespace(close=lambda: None)

        def wait(self, timeout=None):
            return self.returncode

        def communicate(self, **_kwargs):
            raise AssertionError("unbounded communicate must not be used")

        def kill(self):
            self.returncode = -9

    fake_process = FakeProcess()
    monkeypatch.setattr("drex_agent_firewall.adapters.shell_adapter.subprocess.Popen", lambda *a, **k: fake_process)
    config = FirewallConfig.from_pack("safe-local-coding")
    config.provider.type = "replay"
    config.thresholds.EXECUTE = 0.80
    result = ShellAdapter(DeterministicPolicyEngine(config=config)).execute("echo synthetic-output")

    assert result.allowed
    assert result.exit_code == 0
    assert "[TRUNCATED at 1048576 bytes]" in result.stdout
    assert fake_process.stdout.consumed == total_bytes
    assert len(result.stdout.encode()) < total_bytes


def test_no_isolation_cleans_background_process_tracking(tmp_path, monkeypatch):
    from drex_agent_firewall.sandbox.backend import SandboxSpec
    from drex_agent_firewall.sandbox.no_isolation import NoIsolationBackend
    from drex_agent_firewall.sandbox.resource_guard import ResourceGuard
    killed = []
    original_kill = ResourceGuard.kill
    def observed_kill(guard):
        killed.append(guard.path)
        original_kill(guard)
    monkeypatch.setattr(ResourceGuard, "kill", observed_kill)
    backend = NoIsolationBackend()
    spec = SandboxSpec(session_id="background-child-test", workspace_path=str(tmp_path))
    backend.prepare(spec)
    backend.launch(spec)
    result = backend.exec(spec.session_id, ["sh", "-c", "sleep 30 >/dev/null 2>&1 &"], timeout=2)
    assert result.returncode == 0
    # ResourceGuard closes and kills cgroup descendants before exec returns;
    # an empty process-group set is therefore a valid, already-clean state.
    assert killed
    backend.destroy(spec.session_id)
    assert not backend._sessions
