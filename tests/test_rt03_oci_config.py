"""OCI audit-boundary configuration checks (not runtime containment tests)."""

from __future__ import annotations

import os
from types import SimpleNamespace

import pytest

from drex_agent_firewall.sandbox.backend import SandboxLimits, SandboxSpec, SandboxStatus
from drex_agent_firewall.sandbox.container import ContainerCLIBackend
from drex_agent_firewall.sandbox.factory import get_isolation_backend
from drex_agent_firewall.sandbox.manager import SandboxManager
from drex_agent_firewall.schemas.config import SandboxMount


@pytest.mark.parametrize("runtime", ["docker", "podman"])
def test_oci_run_mounts_only_workspace_mcp_config_and_session_socket(tmp_path, monkeypatch, runtime):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    socket_path = tmp_path / "ipc" / "writer.sock"
    socket_path.parent.mkdir(mode=0o700)
    socket_path.touch(mode=0o600)
    db_path = tmp_path / "private" / "history.db"

    backend = ContainerCLIBackend(runtime, runtime)
    spec = SandboxSpec(
        session_id=f"oci-{runtime}",
        workspace_path=str(workspace),
        network_mode="none",
        drex_db_path=str(db_path),
        limits=SandboxLimits(),
        extra_mounts=[
            SandboxMount(host_path=str(socket_path), container_path="/run/drex-audit.sock", mode="ro"),
        ],
    )
    monkeypatch.setattr(backend, "is_available", lambda: True)
    backend.prepare(spec)
    observed = {}

    def fake_run(args, **kwargs):
        observed["args"] = args
        return SimpleNamespace(returncode=0, stdout="container-id\n", stderr="")

    monkeypatch.setattr("drex_agent_firewall.sandbox.container.subprocess.run", fake_run)
    backend.launch(spec)

    args = observed["args"]
    mounts = [args[i + 1] for i, arg in enumerate(args[:-1]) if arg == "-v"]
    assert f"{workspace}:/workspace:rw" in mounts
    assert f"{socket_path}:/run/drex-audit.sock:ro" in mounts
    assert all(str(db_path) not in mount for mount in mounts)
    assert all(str(db_path.parent) not in mount for mount in mounts)
    assert "--user" in args
    assert args[args.index("--user") + 1] == f"{os.getuid()}:{os.getgid()}"
    assert "--cap-drop" in args and args[args.index("--cap-drop") + 1] == "ALL"
    assert "--security-opt" in args and "no-new-privileges" in args
    assert args[args.index("--network") + 1] == "none"


class _CaptureBackend:
    name = "docker"

    def prepare(self, spec):
        self.spec = spec

    def launch(self, spec):
        self.spec = spec
        return SimpleNamespace(session_id=spec.session_id, status=SandboxStatus.RUNNING)

    def destroy(self, _session_id):
        return True


def test_manager_gives_oci_one_private_per_session_socket_and_no_database_mount(tmp_path, monkeypatch):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    backend = _CaptureBackend()
    monkeypatch.setattr("drex_agent_firewall.sandbox.manager.get_isolation_backend", lambda _kind: backend)
    manager = SandboxManager("docker", str(private / "history.db"))

    info = manager.create_session(str(workspace), session_id="oci-socket-boundary", agent_type="generic", network_mode="none")
    try:
        mounts = backend.spec.extra_mounts
        socket_mounts = [m for m in mounts if m.container_path == "/run/drex-audit.sock"]
        assert len(socket_mounts) == 1
        socket_mount = socket_mounts[0]
        assert socket_mount.mode == "ro"
        assert os.path.basename(socket_mount.host_path) == "writer.sock"
        assert os.stat(socket_mount.host_path).st_mode & 0o777 == 0o600
        assert os.stat(os.path.dirname(socket_mount.host_path)).st_mode & 0o777 == 0o700
        assert all(m.host_path != manager.db_path for m in mounts)
        assert all(os.path.realpath(m.host_path) != os.path.realpath(os.path.dirname(manager.db_path)) for m in mounts)
        assert manager._audit_brokers[info.session_id].session_id == info.session_id
    finally:
        manager.destroy_session(info.session_id)
        manager.repository.conn.close()


def test_requested_oci_runtime_unavailable_fails_closed(monkeypatch):
    from drex_agent_firewall.sandbox import factory

    monkeypatch.setattr(factory.BubblewrapBackend, "is_available", lambda _self: False)
    monkeypatch.setattr(factory.PodmanBackend, "is_available", lambda _self: False)
    monkeypatch.setattr(factory.DockerBackend, "is_available", lambda _self: False)
    for requested in ("docker", "podman", "auto"):
        with pytest.raises(RuntimeError, match="unavailable|available|FAIL-CLOSED"):
            get_isolation_backend(requested)


def test_oci_launch_error_is_reported_without_backend_substitution(tmp_path, monkeypatch):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    backend = ContainerCLIBackend("docker", "docker")
    spec = SandboxSpec(session_id="oci-launch-fail", workspace_path=str(workspace), network_mode="none")
    monkeypatch.setattr(backend, "is_available", lambda: True)
    backend.prepare(spec)
    monkeypatch.setattr(
        "drex_agent_firewall.sandbox.container.subprocess.run",
        lambda *_args, **_kwargs: SimpleNamespace(returncode=1, stdout="", stderr="local synthetic launch failure"),
    )
    with pytest.raises(RuntimeError, match="Failed to start container"):
        backend.launch(spec)
    assert backend.status(spec.session_id) == SandboxStatus.FAILED
    assert backend.name == "docker"
