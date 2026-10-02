"""HTTP destination resolution and ambient proxy regression."""

import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

from drex_agent_firewall.adapters.http_adapter import HttpAdapter
from drex_agent_firewall.policy.engine import DeterministicPolicyEngine
from drex_agent_firewall.schemas.config import FirewallConfig


def test_http_adapter_rejects_private_dns_answer_without_connecting(tmp_path, monkeypatch):
    seen = threading.Event()
    proxy_seen = threading.Event()

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            seen.set()
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"loopback canary")

        def log_message(self, *_args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    class ProxyHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            proxy_seen.set()
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"proxy canary")

        def log_message(self, *_args):
            pass

    proxy = HTTPServer(("127.0.0.1", 0), ProxyHandler)
    proxy_thread = threading.Thread(target=proxy.serve_forever, daemon=True)
    proxy_thread.start()
    original_getaddrinfo = socket.getaddrinfo
    hostname = "drex-rebind.example.test"

    def mapped_getaddrinfo(host, *args, **kwargs):
        if host == hostname:
            return original_getaddrinfo("127.0.0.1", *args, **kwargs)
        return original_getaddrinfo(host, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", mapped_getaddrinfo)
    proxy_url = f"http://127.0.0.1:{proxy.server_port}"
    for name in ("HTTP_PROXY", "http_proxy"):
        monkeypatch.setenv(name, proxy_url)
    for name in ("NO_PROXY", "no_proxy"):
        monkeypatch.setenv(name, "")
    config = FirewallConfig.from_pack("safe-local-coding")
    config.provider.type = "replay"
    config.thresholds.NETWORK = 0.90

    try:
        result = HttpAdapter(DeterministicPolicyEngine(config=config)).request(
            "GET", f"http://{hostname}:{server.server_port}/canary"
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
        proxy.shutdown()
        proxy.server_close()
        proxy_thread.join(timeout=2)

    assert result.status_code is None
    assert not seen.is_set()
    assert not proxy_seen.is_set()
