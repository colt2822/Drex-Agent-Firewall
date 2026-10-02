"""Private host-side HTTPS CONNECT bridge for controlled agent egress.

Bubblewrap keeps an unshared network namespace. A mode-0600 AF_UNIX socket is
mounted at one fixed path for the session; the in-sandbox loopback proxy uses
it to request CONNECT tunnels. The host broker permits exact provider hostnames
on TCP/443 and refuses DNS results that are not globally routable.
"""

from __future__ import annotations

import ipaddress
import os
import select
import socket
import threading
from typing import FrozenSet, Optional


AGENT_EGRESS_ALLOWLISTS = {
    "codex": frozenset({"api.openai.com", "auth.openai.com", "chatgpt.com"}),
    "claude": frozenset({"api.anthropic.com"}),
}


def _valid_host(host: str, allowed_hosts: FrozenSet[str]) -> bool:
    try:
        normalized = host.encode("ascii").decode("ascii").lower().rstrip(".")
    except UnicodeError:
        return False
    return normalized == host.lower().rstrip(".") and normalized in allowed_hosts


def _connect_public(host: str, port: int) -> socket.socket:
    """Resolve and connect directly, refusing private, local, or reserved IPs."""
    last_error: Optional[BaseException] = None
    try:
        addresses = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise ConnectionError("provider DNS lookup failed") from exc

    for family, socktype, proto, _canonname, sockaddr in addresses:
        try:
            ip = ipaddress.ip_address(sockaddr[0].split("%", 1)[0])
        except ValueError:
            continue
        if not ip.is_global:
            continue
        upstream = socket.socket(family, socktype, proto)
        try:
            upstream.settimeout(12.0)
            upstream.connect(sockaddr)
            upstream.settimeout(None)
            return upstream
        except OSError as exc:
            last_error = exc
            upstream.close()
    raise ConnectionError("no globally routable provider address was reachable") from last_error


def _recv_line(sock: socket.socket, limit: int = 512) -> bytes:
    data = bytearray()
    while len(data) < limit:
        byte = sock.recv(1)
        if not byte:
            break
        data.extend(byte)
        if byte == b"\n":
            return bytes(data)
    raise ValueError("invalid controlled egress request")


def _relay(bridge: socket.socket, upstream: socket.socket) -> None:
    agent_write_closed = False
    upstream_write_closed = False
    while not (agent_write_closed and upstream_write_closed):
        readers = []
        if not agent_write_closed:
            readers.append(bridge)
        if not upstream_write_closed:
            readers.append(upstream)
        ready, _, _ = select.select(readers, [], [], 0.5)
        for source in ready:
            if source is bridge:
                data = bridge.recv(32768)
                if data:
                    upstream.sendall(data)
                else:
                    agent_write_closed = True
                    try:
                        upstream.shutdown(socket.SHUT_WR)
                    except OSError:
                        pass
            else:
                data = upstream.recv(32768)
                if data:
                    bridge.sendall(data)
                else:
                    upstream_write_closed = True
                    try:
                        bridge.shutdown(socket.SHUT_WR)
                    except OSError:
                        pass


class ControlledEgressBroker:
    """Accepts per-connection CONNECT requests on one private session socket."""

    def __init__(self, socket_path: str, allowed_hosts: FrozenSet[str]):
        self.socket_path = socket_path
        self.allowed_hosts = allowed_hosts
        self.error: Optional[BaseException] = None
        self._closed = threading.Event()
        self._active: set[socket.socket] = set()
        self._active_lock = threading.Lock()
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            os.unlink(socket_path)
        except FileNotFoundError:
            pass
        self.listener.bind(socket_path)
        os.chmod(socket_path, 0o600)
        self.listener.listen(16)
        self.listener.settimeout(0.5)
        self.thread = threading.Thread(target=self._serve, name="drex-egress-broker", daemon=True)

    def start(self) -> None:
        self.thread.start()

    def _serve_connection(self, connection: socket.socket) -> None:
        upstream: Optional[socket.socket] = None
        try:
            request = _recv_line(connection).decode("ascii", errors="ignore").split()
            if len(request) != 3 or request[0] != "CONNECT":
                connection.sendall(b"ERR protocol\n")
                return
            host, raw_port = request[1].lower().rstrip("."), request[2]
            try:
                port = int(raw_port)
            except ValueError:
                port = 0
            if not _valid_host(host, self.allowed_hosts) or port != 443:
                connection.sendall(b"ERR policy\n")
                return
            try:
                upstream = _connect_public(host, port)
            except OSError:
                connection.sendall(b"ERR upstream\n")
                return
            connection.sendall(b"OK\n")
            _relay(connection, upstream)
        except (BrokenPipeError, ConnectionResetError, OSError, ValueError):
            pass
        except BaseException as exc:
            self.error = exc
        finally:
            if upstream is not None:
                upstream.close()
            with self._active_lock:
                self._active.discard(connection)
            connection.close()

    def _serve(self) -> None:
        try:
            while not self._closed.is_set():
                try:
                    connection, _ = self.listener.accept()
                except socket.timeout:
                    continue
                except OSError:
                    return
                with self._active_lock:
                    self._active.add(connection)
                threading.Thread(
                    target=self._serve_connection,
                    args=(connection,),
                    name="drex-egress-connection",
                    daemon=True,
                ).start()
        except BaseException as exc:
            if not self._closed.is_set():
                self.error = exc

    def close(self) -> None:
        self._closed.set()
        try:
            self.listener.close()
        except OSError:
            pass
        with self._active_lock:
            active = list(self._active)
        for connection in active:
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            connection.close()
        if self.thread.is_alive():
            self.thread.join(timeout=2.0)
        try:
            os.unlink(self.socket_path)
        except OSError:
            pass

