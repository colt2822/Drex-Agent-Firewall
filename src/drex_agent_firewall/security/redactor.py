"""Secret redaction engine for Drex Agent Firewall.

Ensures credentials, private keys, bearer tokens, and sensitive env variables
are never transmitted to Drex or persisted in logs or database traces.
Handles raw, URL-encoded, base64-encoded, and hex-encoded secret representations.
"""

from __future__ import annotations

import base64
import binascii
import re
from typing import Any, Dict, List, Optional, Set, Union
from urllib.parse import unquote, unquote_plus


# Regex patterns matching secret types
SECRET_PATTERNS = [
    # AWS Access Key
    re.compile(r"\b(AKIA[0-9A-Z]{16})\b"),
    # AWS Secret Key
    re.compile(r"(?i)(?:aws_secret_access_key|aws_secret_key)\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"),
    # GitHub Tokens (ghp, gho, ghu, ghs, ghr, github_pat)
    re.compile(r"\b(gh[pousr]_[A-Za-z0-9_]{6,255})\b"),
    re.compile(r"\b(github_pat_[A-Za-z0-9_]{82})\b"),
    # OpenAI & Generic sk- Keys (sk-..., sk-proj-..., sk-ant-...)
    re.compile(r"\b(sk-(?:proj-|ant-)?[a-zA-Z0-9_-]{8,120})\b"),
    # Drex API Keys (nace_sk_...)
    re.compile(r"\b(nace_sk_[A-Za-z0-9_-]{16,64})\b"),
    # Slack tokens
    re.compile(r"\b(xox[baprs]-[0-9a-zA-Z-]{10,72})\b"),
    # Private Keys (RSA, EC, OPENSSH, PGP)
    re.compile(r"-----BEGIN [A-Z0-9_-]+ PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9_-]+ PRIVATE KEY-----"),
    re.compile(r"-----BEGIN[ +]PGP[ +]PRIVATE[ +]KEY[ +]BLOCK-----[\s\S]*?-----END[ +]PGP[ +]PRIVATE[ +]KEY[ +]BLOCK-----"),
    # Bearer Tokens in headers or strings
    re.compile(r"(?i)\bBearer\s+([a-zA-Z0-9\-._~+/]+=*)"),
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

# Regex to detect base64 candidates (length >= 16) with proper boundaries
B64_CANDIDATE_REGEX = re.compile(r"(?<![A-Za-z0-9+/])([A-Za-z0-9+/]{16,}={0,2})(?![A-Za-z0-9+/=])")
# Regex to detect hex candidates (length >= 32)
HEX_CANDIDATE_REGEX = re.compile(r"\b([0-9a-fA-F]{32,})\b")


class SecretRedactor:
    """Detects and redacts credentials from strings, dicts, lists, and tool arguments."""

    def __init__(self, custom_secrets: Optional[Set[str]] = None):
        self._custom_secrets: Set[str] = set(custom_secrets or [])

    def register_secret(self, secret: str) -> None:
        """Register a known raw secret string to explicitly scrub."""
        clean = str(secret or "").strip()
        if clean and len(clean) >= 4:
            self._custom_secrets.add(clean)

    def redact_text(self, text: str) -> str:
        """Redact secrets within a raw string, handling nested encodings."""
        if not text or not isinstance(text, str):
            return text

        redacted = text

        # Exact custom secrets scrub (raw)
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
            r"(https?://)([^:\s@]+):([^@\s]+)@",
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



        # Also check for base64-encoded secret payloads inside text
        for m in B64_CANDIDATE_REGEX.finditer(redacted):
            cand = m.group(1)
            try:
                decoded_bytes = base64.b64decode(cand, validate=True)
                decoded_str = decoded_bytes.decode("utf-8", errors="ignore")
                if any(sec in decoded_str for sec in self._custom_secrets) or any(pat.search(decoded_str) for pat in SECRET_PATTERNS):
                    redacted = redacted.replace(cand, "[REDACTED_BASE64_SECRET]")
            except Exception:
                pass

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

        # Limit scan buffer to avoid polynomial regex slowdown on huge payloads
        scan_text = (text[:32768] + "\n" + text[-32768:]) if len(text) > 65536 else text

        # 1. Direct check
        for sec in self._custom_secrets:
            if sec in scan_text:
                return True
        for pattern in SECRET_PATTERNS:
            if pattern.search(scan_text):
                return True

        if "PRIVATE KEY" in scan_text or "PRIVATE KEY" in unquote_plus(scan_text):
            return True

        if re.search(r"https?://[^:\s@]+:[^@\s]+@", scan_text):
            return True

        # 2. URL-decoded check (single and double unquote with + space handling)
        if "%" in scan_text or "+" in scan_text:
            unquoted = unquote_plus(scan_text)
            if unquoted != scan_text:
                if any(sec in unquoted for sec in self._custom_secrets) or any(pat.search(unquoted) for pat in SECRET_PATTERNS):
                    return True
            double_unquoted = unquote_plus(unquoted)
            if double_unquoted != unquoted:
                if any(sec in double_unquoted for sec in self._custom_secrets) or any(pat.search(double_unquoted) for pat in SECRET_PATTERNS):
                    return True

        # 3. Base64 candidates check
        for m in B64_CANDIDATE_REGEX.finditer(scan_text):
            cand = m.group(1)
            try:
                decoded_bytes = base64.b64decode(cand, validate=True)
                decoded_str = decoded_bytes.decode("utf-8", errors="ignore")
                if any(sec in decoded_str for sec in self._custom_secrets) or any(pat.search(decoded_str) for pat in SECRET_PATTERNS):
                    return True
            except Exception:
                pass

        # 4. Hex candidates check
        for m in HEX_CANDIDATE_REGEX.finditer(scan_text):
            cand = m.group(1)
            try:
                decoded_bytes = binascii.unhexlify(cand)
                decoded_str = decoded_bytes.decode("utf-8", errors="ignore")
                if any(sec in decoded_str for sec in self._custom_secrets) or any(pat.search(decoded_str) for pat in SECRET_PATTERNS):
                    return True
            except Exception:
                pass

        # 5. Split token concatenation across JSON / query parameters
        collapsed_query = re.sub(r"[?&][a-zA-Z0-9_]+=", "", scan_text)
        if any(pat.search(collapsed_query) for pat in SECRET_PATTERNS):
            return True

        collapsed_json = re.sub(r"['\",\s\[\]\{\}]+", "", scan_text)
        for pattern in SECRET_PATTERNS:
            if pattern.search(collapsed_json):
                return True

        return False
