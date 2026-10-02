"""HTTP transport that pins DNS answers and rejects non-public destinations."""

from __future__ import annotations

import ipaddress
import socket
from typing import Iterable, Optional

import httpcore
import httpx


class _PublicAddressNetworkBackend(httpcore.NetworkBackend):
    """Resolve once per connection, reject private answers, then connect by IP."""

    def __init__(self) -> None:
        self._backend = httpcore.SyncBackend()

    def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: Optional[float] = None,
        local_address: Optional[str] = None,
        socket_options: Optional[Iterable[tuple]] = None,
    ) -> httpcore.NetworkStream:
        records = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        addresses = []
        for family, _socktype, _protocol, _canonname, sockaddr in records:
            if family not in (socket.AF_INET, socket.AF_INET6):
                continue
            address = ipaddress.ip_address(str(sockaddr[0]).split("%", 1)[0])
            if not address.is_global:
                raise OSError(f"HTTP destination resolved to a non-public address: {address}")
            addresses.append(str(address))

        if not addresses:
            raise OSError("HTTP destination did not resolve to a public address")

        last_error: Optional[OSError] = None
        for address in dict.fromkeys(addresses):
            try:
                # Passing the numeric answer prevents a second DNS lookup after
                # the address has passed the public-address check.
                return self._backend.connect_tcp(
                    address,
                    port,
                    timeout=timeout,
                    local_address=local_address,
                    socket_options=socket_options,
                )
            except OSError as exc:
                last_error = exc
        assert last_error is not None
        raise last_error

    def connect_unix_socket(
        self,
        path: str,
        timeout: Optional[float] = None,
        socket_options: Optional[Iterable[tuple]] = None,
    ) -> httpcore.NetworkStream:
        raise OSError("Unix socket destinations are disabled for guarded HTTP requests")


class GuardedHTTPTransport(httpx.HTTPTransport):
    """HTTPX transport pinned to globally routable DNS results.

    Ambient proxy variables are ignored so a host proxy cannot silently change
    the destination path validated by the firewall. Configure any future proxy
    explicitly in policy rather than through inherited process environment.
    """

    def __init__(self, **kwargs) -> None:
        super().__init__(trust_env=False, **kwargs)
        # HTTPX does not expose httpcore's network backend publicly. httpcore is
        # a direct dependency so this adapter controls its connection resolver.
        self._pool._network_backend = _PublicAddressNetworkBackend()
