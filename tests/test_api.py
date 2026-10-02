"""Tests for FastAPI HTTP API endpoints."""

from fastapi.testclient import TestClient
from drex_agent_firewall import DrexFirewall
from drex_agent_firewall.server.app import create_app


def test_api_healthz():
    client = TestClient(create_app())
    resp = client.get("/healthz")
    assert resp.status_code == 200
    assert resp.json()["status"] == "healthy"


def test_api_readyz():
    client = TestClient(create_app())
    resp = client.get("/readyz")
    assert resp.status_code == 200
    assert resp.json()["ready"] is True


def test_api_metrics():
    client = TestClient(create_app())
    resp = client.get("/metrics")
    assert resp.status_code == 200
    assert "drex_firewall_decisions_total" in resp.text


def test_api_evaluate():
    client = TestClient(create_app())
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
    client = TestClient(create_app())
    payload = {
        "tool": "shell",
        "operation": "execute",
        "arguments": {"command": "rm -rf /"},
    }
    resp = client.post("/v1/enforce", json=payload)
    assert resp.status_code == 403


def test_api_actions_and_outcome(tmp_path):
    fw = DrexFirewall(database_path=str(tmp_path / "api_test.db"))
    client = TestClient(create_app(firewall=fw))

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
    client = TestClient(create_app())
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
