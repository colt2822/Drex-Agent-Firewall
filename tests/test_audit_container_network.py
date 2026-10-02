"""OCI network mode isolation regression."""

from types import SimpleNamespace

from drex_agent_firewall.sandbox.backend import SandboxSpec
from drex_agent_firewall.sandbox.container import DockerBackend


def test_allowlisted_container_network_is_isolated(tmp_path, monkeypatch):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    backend = DockerBackend()
    backend.is_available = lambda: True
    commands = []

    def fake_run(args, **_kwargs):
        commands.append(args)
        return SimpleNamespace(returncode=0, stdout="synthetic-container-id", stderr="")

    monkeypatch.setattr("drex_agent_firewall.sandbox.container.subprocess.run", fake_run)
    spec = SandboxSpec(
        session_id="allowlisted-canary",
        workspace_path=str(workspace),
        network_mode="allowlisted",
    )

    backend.prepare(spec)
    backend.launch(spec)

    index = commands[0].index("--network")
    assert commands[0][index:index + 2] == ["--network", "none"]
