"""Tests for DrexFirewall Python SDK."""

import pytest
from drex_agent_firewall import DrexFirewall, OutcomeType


def test_sdk_sync_evaluate():
    fw = DrexFirewall()
    decision = fw.evaluate(tool="shell", operation="execute", arguments={"command": "cat README.md"})
    assert decision.allowed is True
    assert decision.decision.value == "ALLOW"


@pytest.mark.asyncio
async def test_sdk_async_evaluate():
    fw = DrexFirewall()
    decision = await fw.evaluate_async(tool="shell", operation="execute", arguments={"command": "cat README.md"})
    assert decision.allowed is True


def test_sdk_enforce_raises_on_block():
    fw = DrexFirewall()
    with pytest.raises(PermissionError) as exc_info:
        fw.enforce(tool="shell", operation="execute", arguments={"command": "rm -rf /"})
    assert "blocked action" in str(exc_info.value).lower()
