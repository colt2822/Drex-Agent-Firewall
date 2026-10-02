"""Unit tests for Drex Isolated Agent Runtime (drex-firewall sandbox)."""

import os
import shutil
import tempfile
import pytest
from fastapi.testclient import TestClient

from drex_agent_firewall.sandbox.backend import SandboxLimits, SandboxSpec, SandboxStatus
from drex_agent_firewall.sandbox.bubblewrap import BubblewrapBackend
from drex_agent_firewall.sandbox.factory import get_isolation_backend
from drex_agent_firewall.sandbox.manager import SandboxManager
from drex_agent_firewall.sandbox.no_isolation import NoIsolationBackend
from drex_agent_firewall.sandbox.probes import SandboxEscapeProbeRunner
from drex_agent_firewall.server.app import create_app


@pytest.fixture
def tmp_workspace():
    tmp = tempfile.mkdtemp(prefix="drex_test_ws_")
    yield tmp
    shutil.rmtree(tmp, ignore_errors=True)


def test_no_isolation_backend(tmp_workspace):
    backend = NoIsolationBackend()
    assert backend.name == "none"
    assert backend.is_available() is True

    spec = SandboxSpec(session_id="test-no-iso", workspace_path=tmp_workspace)
    assert backend.prepare(spec) is True
    info = backend.launch(spec)
    assert info.status == SandboxStatus.RUNNING

    res = backend.exec("test-no-iso", ["echo", "hello"])
    assert res.returncode == 0
    assert "hello" in res.stdout
    assert backend.stop("test-no-iso") is True
    assert backend.destroy("test-no-iso") is True


def test_bubblewrap_availability():
    bwrap = BubblewrapBackend()
    # Bubblewrap is installed on host
    assert bwrap.name == "bubblewrap"
    assert bwrap.is_available() is True


def test_bubblewrap_environment_cleansing(tmp_workspace):
    bwrap = BubblewrapBackend()
    spec = SandboxSpec(
        session_id="test-env-clean",
        workspace_path=tmp_workspace,
        env_allowlist=["TERM", "LANG"],
    )
    bwrap.prepare(spec)
    # Check that sensitive keys are stripped
    sanitized = bwrap._sanitize_environment(spec)
    assert "OPENAI_API_KEY" not in sanitized
    assert "GITHUB_TOKEN" not in sanitized
    assert "AWS_ACCESS_KEY_ID" not in sanitized
    assert sanitized["HOME"] == "/home/agent"
    bwrap.destroy("test-env-clean")


def test_bubblewrap_exec_and_isolation(tmp_workspace):
    bwrap = BubblewrapBackend()
    spec = SandboxSpec(
        session_id="test-bwrap-exec",
        workspace_path=tmp_workspace,
    )
    bwrap.prepare(spec)
    info = bwrap.launch(spec)
    assert info.status == SandboxStatus.RUNNING

    # 1. Benign execution inside sandbox
    res = bwrap.exec("test-bwrap-exec", ["python3", "-c", "print('SANDBOX_OK')"])
    assert res.returncode == 0
    assert "SANDBOX_OK" in res.stdout

    # 2. Filesystem isolation: /home should not reveal host users
    res_home = bwrap.exec("test-bwrap-exec", ["ls", "/home"])
    assert res_home.returncode == 0
    assert "agent" in res_home.stdout
    assert "colton-mcclain" not in res_home.stdout

    # 3. Read-only system mount: writing to /usr must fail
    res_usr = bwrap.exec("test-bwrap-exec", ["touch", "/usr/should_fail"])
    assert res_usr.returncode != 0

    bwrap.destroy("test-bwrap-exec")


def test_sandbox_manager_lifecycle(tmp_workspace):
    mgr = SandboxManager(backend_type="bubblewrap")
    info = mgr.create_session(
        workspace_path=tmp_workspace,
        policy_pack="safe-local-coding",
        agent_type="claude",
    )
    assert info.session_id.startswith("sbx-")
    assert info.backend_name == "bubblewrap"

    # Command execution
    res = mgr.exec_command(info.session_id, ["pwd"])
    assert res.returncode == 0
    assert "/workspace" in res.stdout

    # Audit tracking in SQLite
    sess_record = mgr.repository.get_sandbox_session(info.session_id)
    assert sess_record is not None
    assert sess_record["status"] == "RUNNING"
    assert sess_record["workspace_path"] == os.path.realpath(tmp_workspace)

    assert mgr.stop_session(info.session_id) is True
    assert mgr.destroy_session(info.session_id) is True


def test_sandbox_escape_probes(tmp_workspace):
    mgr = SandboxManager(backend_type="bubblewrap")
    info = mgr.create_session(workspace_path=tmp_workspace)

    runner = SandboxEscapeProbeRunner(mgr)
    results = runner.run_all_probes(info.session_id)
    assert len(results) >= 10

    # Every probe must be blocked by the isolation boundary
    for r in results:
        assert r["blocked"] is True, f"Escape probe breached: {r['name']}"

    mgr.destroy_session(info.session_id)


def test_sandbox_api_endpoints(tmp_workspace):
    app = create_app()
    client = TestClient(app)

    # 1. /v1/sandbox/status
    res_status = client.get("/v1/sandbox/status")
    assert res_status.status_code == 200
    data_status = res_status.json()
    assert data_status["backend_name"] == "bubblewrap"
    assert data_status["is_available"] is True

    # 2. /v1/sandbox/sessions
    res_sess = client.get("/v1/sandbox/sessions")
    assert res_sess.status_code == 200
    assert "sandbox_sessions" in res_sess.json()

    # 3. /v1/sandbox/test-escape
    res_esc = client.post("/v1/sandbox/test-escape")
    assert res_esc.status_code == 200
    esc_data = res_esc.json()
    assert esc_data["backend"] == "bubblewrap"
    assert len(esc_data["probes"]) >= 10
    assert all(p["blocked"] for p in esc_data["probes"])
