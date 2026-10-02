"""Network destination and SSRF validation engine.

Normalizes IP addresses across decimal, hex, octal, IPv6, and IPv4-mapped representations.
Blocks RFC1918 private ranges, loopback, link-local, cloud metadata endpoints,
and dangerous schemes.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Optional, Tuple
from urllib.parse import urlparse


METADATA_HOSTNAMES = {
    "169.254.169.254",
    "metadata.google.internal",
    "metadata.internal",
    "100.100.100.200",  # Alibaba Cloud metadata
    "instance-data",
}

BLOCKED_SCHEMES = {"file", "gopher", "dict", "ftp", "sftp", "tftp", "ldap", "ldaps", "expect"}
ALLOWED_SCHEMES = {"http", "https"}


def parse_ip_flexibly(host_str: str) -> Optional[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    """Parse various IP string formats (decimal integer, hex, octal, standard dotted-quad, IPv6)."""
    clean_host = host_str.strip().strip("[]").lower()

    # 1. Standard ipaddress parser handles dotted-quad and IPv6
    try:
        return ipaddress.ip_address(clean_host)
    except ValueError:
        pass

    # 2. Decimal integer IP: e.g. 2130706433 -> 127.0.0.1
    if clean_host.isdigit():
        try:
            val = int(clean_host)
            if 0 <= val <= 0xFFFFFFFF:
                return ipaddress.IPv4Address(val)
        except ValueError:
            pass

    # 3. Hexadecimal IP: e.g. 0x7f000001 or 0x7f.0x0.0x0.0x1
    if clean_host.startswith("0x") and not any(sep in clean_host for sep in [".", ":"]):
        try:
            val = int(clean_host, 16)
            if 0 <= val <= 0xFFFFFFFF:
                return ipaddress.IPv4Address(val)
        except ValueError:
            pass

    # 4. Mixed octal/hex/decimal dotted quad: e.g. 0177.0.0.1 or 0x7f.0.0.1
    parts = clean_host.split(".")
    if len(parts) == 4:
        try:
            int_parts = []
            for p in parts:
                if p.startswith("0x") or p.startswith("0X"):
                    int_parts.append(int(p, 16))
                elif p.startswith("0") and len(p) > 1 and p.isdigit():
                    int_parts.append(int(p, 8))
                elif p.isdigit():
                    int_parts.append(int(p, 10))
                else:
                    return None
            if all(0 <= x <= 255 for x in int_parts):
                ip_int = (int_parts[0] << 24) + (int_parts[1] << 16) + (int_parts[2] << 8) + int_parts[3]
                return ipaddress.IPv4Address(ip_int)
        except ValueError:
            pass

    return None


class NetworkValidator:
    """Validates destination URLs and hostnames against SSRF, metadata, and private IP policies."""

    def __init__(
        self,
        allowed_domains: Optional[list[str]] = None,
        blocked_domains: Optional[list[str]] = None,
        block_private_ips: bool = True,
    ):
        self.allowed_domains = [d.lower().strip() for d in (allowed_domains or []) if d.strip()]
        self.blocked_domains = [d.lower().strip() for d in (blocked_domains or []) if d.strip()]
        self.block_private_ips = block_private_ips

    def validate_destination(self, url_or_target: str) -> Tuple[bool, str, Optional[str]]:
        """Validate destination URL/host.
        
        Returns: (is_safe, canonical_host, reason_if_blocked)
        """
        raw = str(url_or_target).strip()
        if not raw:
            return False, "", "Empty network destination"

        try:
            # Strip bracketed redactions (e.g. [REDACTED]) in authority to avoid Python 3.12 bracketed host ValueError
            clean_raw = re.sub(r"\[REDACTED[^\]]*\]", "REDACTED", raw)
            if "://" in clean_raw:
                parsed = urlparse(clean_raw)
                scheme = (parsed.scheme or "").lower()
                if scheme in BLOCKED_SCHEMES or scheme not in ALLOWED_SCHEMES:
                    return False, raw, f"Blocked or unsupported network scheme '{scheme}://'"
                hostname = parsed.hostname or ""
                port = parsed.port
            else:
                if "/" in raw:
                    raw_with_scheme = "http://" + raw
                    parsed = urlparse(raw_with_scheme)
                    hostname = parsed.hostname or ""
                else:
                    hostname = raw.split(":")[0]
        except ValueError as ve:
            return False, raw, f"Malformed URL or authority: {str(ve)}"

        host_lower = hostname.strip("[]").lower()
        if not host_lower:
            return False, raw, "Could not determine hostname from destination"

        # 1. Direct metadata hostname / IP string match
        if host_lower in METADATA_HOSTNAMES:
            return False, host_lower, f"Destination '{host_lower}' is a blocked cloud metadata endpoint"

        # 2. Localhost strings
        if host_lower in {"localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback"}:
            return False, host_lower, f"Destination '{host_lower}' resolves to loopback/localhost"

        # 3. Explicit blocked domains list
        for blocked in self.blocked_domains:
            b_clean = blocked.strip("[]").lower()
            if host_lower == b_clean or host_lower.endswith("." + b_clean):
                return False, host_lower, f"Destination '{host_lower}' matches blocked domain rule '{blocked}'"

        # 4. IP address parsing (decimal, hex, octal, IPv6, IPv4-mapped)
        ip_obj = parse_ip_flexibly(host_lower)
        if ip_obj is not None:
            # IPv4 mapped IPv6 e.g. ::ffff:127.0.0.1
            if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped:
                ip_obj = ip_obj.ipv4_mapped

            # Check loopback
            if ip_obj.is_loopback:
                return False, str(ip_obj), f"IP address '{ip_obj}' is loopback"

            # Check unspecified (0.0.0.0 / ::)
            if ip_obj.is_unspecified:
                return False, str(ip_obj), f"IP address '{ip_obj}' is unspecified / bind-all address"

            # Check link-local / cloud metadata (169.254.x.x / fe80::)
            if ip_obj.is_link_local:
                return False, str(ip_obj), f"IP address '{ip_obj}' is link-local / metadata address"

            # Check private RFC1918 / RFC4193
            if self.block_private_ips and (ip_obj.is_private or ip_obj.is_reserved):
                return False, str(ip_obj), f"IP address '{ip_obj}' is in private or reserved IP range"

            # Check if canonical IP string matches any blocked domain
            ip_str = str(ip_obj)
            for blocked in self.blocked_domains:
                if ip_str == blocked.strip("[]").lower():
                    return False, ip_str, f"IP address '{ip_str}' matches blocked rule '{blocked}'"

        # 5. Whitelist validation if configured
        if self.allowed_domains:
            matched = any(
                host_lower == allowed or host_lower.endswith("." + allowed)
                for allowed in self.allowed_domains
            )
            if not matched:
                return False, host_lower, f"Destination '{host_lower}' is not in allowed_domains whitelist"

        return True, host_lower, None
