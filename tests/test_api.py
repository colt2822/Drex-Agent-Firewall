"""Tests for FastAPI HTTP API endpoints."""

from fastapi.testclient import TestClient
from drex_agent_firewall import DrexFirewall
from drex_agent_firewall.server.app import create_app


def _authenticated_client(app):
    return TestClient(app, headers={"Authorization": f"Bearer {app.state.api_token}"})


def test_api_healthz():
    client = _authenticated_client(create_app())
    resp = client.get("/healthz")
    assert resp.status_code == 200
    assert resp.json()["status"] == "healthy"


def test_api_bearer_token_protects_routes_except_healthz(monkeypatch, tmp_path):
    monkeypatch.setenv("DREX_API_TOKEN", "synthetic-test-token")
    app = create_app(DrexFirewall(database_path=str(tmp_path / "auth.db")))
    client = TestClient(app)
    assert client.get("/healthz").status_code == 200
    assert client.get("/v1/actions").status_code == 401
    assert client.get("/v1/actions", headers={"Authorization": "Bearer synthetic-test-token"}).status_code == 200


def test_api_refuses_non_loopback_bind_without_token(monkeypatch):
    from click.testing import CliRunner
    from drex_agent_firewall.cli.main import cli
    monkeypatch.delenv("DREX_API_TOKEN", raising=False)
    result = CliRunner().invoke(cli, ["serve", "--host", "0.0.0.0"])
    assert result.exit_code != 0
    assert "DREX_API_TOKEN is required" in result.output


def test_api_cors_requires_explicit_exact_origin(monkeypatch, tmp_path):
    monkeypatch.setenv("DREX_FIREWALL_CORS_ORIGINS", "https://trusted.example")
    fw = DrexFirewall(database_path=str(tmp_path / "cors.db"))
    client = _authenticated_client(create_app(firewall=fw))
    attacker = client.get("/healthz", headers={"Origin": "https://attacker.example"})
    trusted = client.get("/healthz", headers={"Origin": "https://trusted.example"})
    assert "access-control-allow-origin" not in attacker.headers
    assert trusted.headers.get("access-control-allow-origin") == "https://trusted.example"
    assert "access-control-allow-credentials" not in trusted.headers


def test_api_cors_rejects_wildcard_configuration(monkeypatch, tmp_path):
    monkeypatch.setenv("DREX_FIREWALL_CORS_ORIGINS", "*")
    fw = DrexFirewall(database_path=str(tmp_path / "cors-wildcard.db"))
    try:
        create_app(firewall=fw)
    except ValueError as exc:
        assert "exact HTTP(S) origins" in str(exc)
    else:
        raise AssertionError("wildcard CORS configuration must fail closed")


def test_api_readyz():
    client = _authenticated_client(create_app())
    resp = client.get("/readyz")
    assert resp.status_code == 200
    assert resp.json()["ready"] is True


def test_api_metrics():
    client = _authenticated_client(create_app())
    resp = client.get("/metrics")
    assert resp.status_code == 200
    assert "drex_firewall_decisions_total" in resp.text


def test_api_evaluate():
    client = _authenticated_client(create_app())
    payload = {
        "tool": "shell",
        "operation": "execute",
        "arguments": {"command": "cat README.md"},
    }
    resp = client.post("/v1/evaluate", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["decision"] == "ALLOW"
    assert data["allowed"] is True


def test_api_enforce_blocks_forbidden():
    client = _authenticated_client(create_app())
    payload = {
        "tool": "shell",
        "operation": "execute",
        "arguments": {"command": "rm -rf /"},
    }
    resp = client.post("/v1/enforce", json=payload)
    assert resp.status_code == 403


def test_api_actions_and_outcome(tmp_path):
    fw = DrexFirewall(database_path=str(tmp_path / "api_test.db"))
    client = _authenticated_client(create_app(firewall=fw))

    # Evaluate
    eval_resp = client.post(
        "/v1/evaluate",
        json={"tool": "git", "operation": "status", "arguments": {}},
    )
    action_id = eval_resp.json()["action_id"]

    # Get actions
    act_resp = client.get(f"/v1/actions/{action_id}")
    assert act_resp.status_code == 200

    # Attach outcome
    outcome_resp = client.post(
        f"/v1/actions/{action_id}/outcome",
        json={"outcome": "EXECUTED_SUCCESSFULLY", "notes": "Verified via test"},
    )
    assert outcome_resp.status_code == 200
    assert outcome_resp.json()["status"] == "outcome_recorded"


def test_api_policies_simulate():
    client = _authenticated_client(create_app())
    resp = client.post(
        "/v1/policies/simulate",
        json={
            "envelope": {"tool": "shell", "operation": "execute", "arguments": {"command": "cat README.md"}},
            "thresholds": {"READ": 0.80},
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["simulated_decision"]["decision"] == "ALLOW"
