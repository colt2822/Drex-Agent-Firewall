"""Run an agent behind a loopback-only HTTP CONNECT proxy.

This file intentionally uses only the Python standard library so it can run
from the system Python mounted read-only in Bubblewrap without exposing the
host user's Python packages.
"""

from __future__ import annotations

import argparse
import os
import select
import stat
import socket
import socketserver
import subprocess
import sys
import threading
from typing import FrozenSet, Optional


MAX_HEADER = 16384


def _valid_host(host: str, allowed_hosts: FrozenSet[str]) -> bool:
    try:
        normalized = host.encode("ascii").decode("ascii").lower().rstrip(".")
    except UnicodeError:
        return False
    return normalized == host.lower().rstrip(".") and normalized in allowed_hosts


def _read_headers(client: socket.socket) -> bytes:
    data = bytearray()
    while len(data) < MAX_HEADER:
        byte = client.recv(1)
        if not byte:
            break
        data.extend(byte)
        if data.endswith(b"\r\n\r\n"):
            return bytes(data)
    raise ValueError("incomplete or oversized proxy request")


def _parse_connect(header: bytes, allowed_hosts: FrozenSet[str]) -> tuple[str, int]:
    lines = header.decode("iso-8859-1").split("\r\n")
    request = lines[0].split()
    if len(request) != 3 or request[0].upper() != "CONNECT" or request[2] not in ("HTTP/1.0", "HTTP/1.1"):
        raise ValueError("only HTTPS CONNECT requests are allowed")
    for line in lines[1:]:
        if line.lower().startswith("proxy-authorization:"):
            raise ValueError("proxy credentials are not accepted")
    authority = request[1]
    if authority.count(":") != 1:
        raise ValueError("invalid CONNECT authority")
    host, raw_port = authority.rsplit(":", 1)
    if not raw_port.isascii() or not raw_port.isdecimal():
        raise ValueError("invalid CONNECT port")
    port = int(raw_port)
    if not _valid_host(host, allowed_hosts) or port != 443:
        raise PermissionError("CONNECT target is outside the configured provider policy")
    return host.lower().rstrip("."), port


def _serve_tunnel(client: socket.socket, bridge: socket.socket) -> None:
    client_write_closed = False
    upstream_write_closed = False
    while not (client_write_closed and upstream_write_closed):
        readers = []
        if not client_write_closed:
            readers.append(client)
        if not upstream_write_closed:
            readers.append(bridge)
        ready, _, _ = select.select(readers, [], [], 0.5)
        for source in ready:
            if source is client:
                data = client.recv(32768)
                if data:
                    bridge.sendall(data)
                else:
                    client_write_closed = True
                    try:
                        bridge.shutdown(socket.SHUT_WR)
                    except OSError:
                        pass
            else:
                data = bridge.recv(32768)
                if data:
                    client.sendall(data)
                else:
                    upstream_write_closed = True
                    try:
                        client.shutdown(socket.SHUT_WR)
                    except OSError:
                        pass


class _ProxyServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = False
    daemon_threads = True
    block_on_close = False

    def __init__(self, bridge_path: str, allowed_hosts: FrozenSet[str]):
        self.bridge_path = bridge_path
        self.allowed_hosts = allowed_hosts
        super().__init__(("127.0.0.1", 0), _ProxyHandler)


class _ProxyHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        client: socket.socket = self.request
        try:
            header = _read_headers(client)
            host, port = _parse_connect(header, self.server.allowed_hosts)
        except PermissionError:
            client.sendall(b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n")
            return
        except (ValueError, UnicodeError):
            client.sendall(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")
            return

        bridge = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            bridge.connect(self.server.bridge_path)
            bridge.sendall(f"CONNECT {host} {port}\n".encode("ascii"))
            response = bytearray()
            while len(response) < 128 and not response.endswith(b"\n"):
                part = bridge.recv(1)
                if not part:
                    break
                response.extend(part)
            if bytes(response) != b"OK\n":
                client.sendall(b"HTTP/1.1 502 Egress Denied\r\nConnection: close\r\n\r\n")
                return
            client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            _serve_tunnel(client, bridge)
        except (BrokenPipeError, ConnectionResetError, OSError, ConnectionError):
            try:
                client.sendall(b"HTTP/1.1 502 Egress Bridge Failed\r\nConnection: close\r\n\r\n")
            except OSError:
                pass
        finally:
            bridge.close()


def run(bridge_path: str, command: list[str]) -> int:
    allowed_hosts: FrozenSet[str] = frozenset(
        item.strip().lower().rstrip(".")
        for item in os.environ.get("DREX_EGRESS_HOSTS", "").split(",")
        if item.strip()
    )
    if not allowed_hosts or not command:
        raise RuntimeError("controlled egress requires an explicit host policy and agent command")
    try:
        st = os.stat(bridge_path)
    except OSError as exc:
        raise RuntimeError("controlled egress bridge socket is unavailable") from exc
    if not stat.S_ISSOCK(st.st_mode):
        raise RuntimeError("controlled egress bridge path is not a socket")
    probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        probe.settimeout(2.0)
        probe.connect(bridge_path)
        probe.sendall(b"PROBE\n")
        response = bytearray()
        while len(response) < 128 and not response.endswith(b"\n"):
            part = probe.recv(1)
            if not part:
                break
            response.extend(part)
        if bytes(response) != b"ERR protocol\n":
            raise RuntimeError("controlled egress broker health check failed")
    finally:
        probe.close()

    server = _ProxyServer(bridge_path, allowed_hosts)
    proxy_url = f"http://127.0.0.1:{server.server_address[1]}"
    safe_agent_env = {
        "PATH",
        "HOME",
        "USER",
        "SHELL",
        "LANG",
        "LC_ALL",
        "TERM",
        "PYTHONPATH",
        "CODEX_HOME",
        "CLAUDE_CONFIG_DIR",
    }
    env = {key: value for key, value in os.environ.items() if key in safe_agent_env}
    env.update({
        "HTTP_PROXY": proxy_url,
        "HTTPS_PROXY": proxy_url,
        "ALL_PROXY": proxy_url,
        "http_proxy": proxy_url,
        "https_proxy": proxy_url,
        "all_proxy": proxy_url,
        "NO_PROXY": "",
        "no_proxy": "",
    })
    server_thread = threading.Thread(target=server.serve_forever, name="drex-loopback-proxy", daemon=True)
    server_thread.start()
    child: Optional[subprocess.Popen] = None
    try:
        child = subprocess.Popen(command, env=env, close_fds=True)
        return child.wait()
    finally:
        if child is not None and child.poll() is None:
            child.terminate()
            try:
                child.wait(timeout=3.0)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()
        server.shutdown()
        server.server_close()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bridge-socket", required=True)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    try:
        return run(args.bridge_socket, command)
    except Exception:
        print("controlled egress setup failed; agent was not started", file=sys.stderr)
        return 125


if __name__ == "__main__":
    raise SystemExit(main())
