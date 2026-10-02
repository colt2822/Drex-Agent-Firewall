"""Bounded process output collection regression."""

from types import SimpleNamespace

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
