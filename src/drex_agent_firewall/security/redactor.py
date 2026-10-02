"""Secret redaction engine for Drex Agent Firewall.

Ensures credentials, private keys, bearer tokens, and sensitive env variables
are never transmitted to Drex or persisted in logs or database traces.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Set, Union


# Regex patterns matching secret types
SECRET_PATTERNS = [
    # AWS Access Key
    re.compile(r"\b(AKIA[0-9A-Z]{16})\b"),
    # AWS Secret Key
    re.compile(r"(?i)(?:aws_secret_access_key|aws_secret_key)\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"),
    # GitHub Tokens
    re.compile(r"\b(gh[pousr]_[A-Za-z0-9_]{36,255})\b"),
    re.compile(r"\b(github_pat_[A-Za-z0-9_]{82})\b"),
    # OpenAI & Generic sk- Keys (sk-..., sk-proj-...)
    re.compile(r"\b(sk-(?:proj-)?[a-zA-Z0-9_-]{20,120})\b"),
    # Slack tokens
    re.compile(r"\b(xox[baprs]-[0-9a-zA-Z-]{10,72})\b"),
    # Private Keys (RSA, EC, OPENSSH, PGP)
    re.compile(r"-----BEGIN [A-Z0-9_-]+ PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9_-]+ PRIVATE KEY-----"),
    re.compile(r"-----BEGIN PGP PRIVATE KEY BLOCK-----[\s\S]*?-----END PGP PRIVATE KEY BLOCK-----"),
    # Bearer Tokens in headers or strings
    re.compile(r"(?i)\bBearer\s+([a-zA-Z0-9\-._~+/]+=*)"),
    # Basic auth embedded in URLs
    re.compile(r"(https?://)([^:\s]+):([^@\s]+)@"),
    # Generic password and key assignments (quoted or unquoted in query string or form data)
    re.compile(r"(?i)(?:password|passwd|secret|api_key|apikey|token|access_token|auth_token)\s*[:=]\s*['\"]?([^\s'\"&;,]{4,})['\"]?"),
]

SENSITIVE_FIELD_NAMES = {
    "password",
    "passwd",
    "secret",
    "api_key",
    "apikey",
    "token",
    "access_token",
    "auth_token",
    "authorization",
    "private_key",
    "secret_key",
    "drex_api_key",
}


class SecretRedactor:
    """Detects and redacts credentials from strings, dicts, lists, and tool arguments."""

    def __init__(self, custom_secrets: Optional[Set[str]] = None):
        self._custom_secrets: Set[str] = set(custom_secrets or [])

    def register_secret(self, secret: str) -> None:
        """Register a known raw secret string to explicitly scrub."""
        if secret and len(secret) >= 4:
            self._custom_secrets.add(secret)

    def redact_text(self, text: str) -> str:
        """Redact secrets within a raw string."""
        if not text or not isinstance(text, str):
            return text

        redacted = text

        # Exact custom secrets scrub
        for sec in self._custom_secrets:
            if sec in redacted:
                redacted = redacted.replace(sec, "[REDACTED_CUSTOM_SECRET]")

        # Private keys replacement
        redacted = re.sub(
            r"-----BEGIN [A-Z0-9_-]+ PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9_-]+ PRIVATE KEY-----",
            "[REDACTED_PRIVATE_KEY]",
            redacted,
        )
        redacted = re.sub(
            r"-----BEGIN PGP PRIVATE KEY BLOCK-----[\s\S]*?-----END PGP PRIVATE KEY BLOCK-----",
            "[REDACTED_PGP_KEY]",
            redacted,
        )

        # Basic Auth in URLs: http://user:pass@host -> http://user:[REDACTED]@host
        redacted = re.sub(
            r"(https?://)([^:\s]+):([^@\s]+)@",
            r"\1\2:[REDACTED]@",
            redacted,
        )

        # Standard token & key patterns
        for pattern in SECRET_PATTERNS:
            def _replace_match(m: re.Match) -> str:
                full = m.group(0)
                if m.groups():
                    target = m.group(1)
                    return full.replace(target, "[REDACTED_SECRET]")
                return "[REDACTED_SECRET]"

            redacted = pattern.sub(_replace_match, redacted)

        return redacted

    def sanitize(self, data: Any) -> Any:
        """Recursively sanitize an object, dict, list, or primitive."""
        if isinstance(data, str):
            return self.redact_text(data)
        elif isinstance(data, dict):
            sanitized: Dict[str, Any] = {}
            for k, v in data.items():
                k_lower = str(k).lower()
                if any(sens == k_lower or sens in k_lower for sens in SENSITIVE_FIELD_NAMES):
                    sanitized[k] = "[REDACTED_SECRET_VALUE]"
                else:
                    sanitized[k] = self.sanitize(v)
            return sanitized
        elif isinstance(data, list):
            return [self.sanitize(item) for item in data]
        elif isinstance(data, tuple):
            return tuple(self.sanitize(item) for item in data)
        return data

    def contains_secrets(self, text: str) -> bool:
        """Return True if text appears to contain unredacted secrets or sensitive key assignment."""
        if not text or not isinstance(text, str):
            return False
        for sec in self._custom_secrets:
            if sec in text:
                return True
        for pattern in SECRET_PATTERNS:
            if pattern.search(text):
                return True
        return False
