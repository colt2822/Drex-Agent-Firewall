"""Bounded HTTP response body regression."""

import httpx

from drex_agent_firewall.adapters.http_adapter import HttpAdapter
from drex_agent_firewall.policy.engine import DeterministicPolicyEngine
from drex_agent_firewall.schemas.config import FirewallConfig


def test_http_adapter_stops_consuming_response_after_output_limit(monkeypatch):
    consumed = 0
    chunk = b"x" * (32 * 1024)
    chunk_count = 80

    class Body(httpx.SyncByteStream):
        def __iter__(self):
            nonlocal consumed
            for _ in range(chunk_count):
                consumed += len(chunk)
                yield chunk

    def handler(_request):
        return httpx.Response(200, stream=Body())

    monkeypatch.setattr(
        "drex_agent_firewall.adapters.http_adapter.GuardedHTTPTransport",
        lambda: httpx.MockTransport(handler),
    )
    config = FirewallConfig.from_pack("safe-local-coding")
    config.provider.type = "replay"
    config.thresholds.NETWORK = 0.90

    result = HttpAdapter(DeterministicPolicyEngine(config=config)).request(
        "GET", "https://example.com/large-response"
    )

    assert result.status_code == 200
    assert "[TRUNCATED_RESPONSE]" in result.text
    assert consumed < len(chunk) * chunk_count
