"""Shared filtering for credential and proxy environment variables."""

from __future__ import annotations

from typing import Mapping


_BLOCKED_PREFIXES = (
    "GITHUB_",
    "GH_",
    "AWS_",
    "OPENAI_",
    "ANTHROPIC_",
    "GOOGLE_",
    "GEMINI_",
    "DREX_",
    "SSH_",
    "SLACK_",
)

_BLOCKED_EXACT = {
    "SSH_AUTH_SOCK",
    "SSH_AGENT_PID",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
    "FTP_PROXY",
    "GIT_ASKPASS",
    "GIT_TERMINAL_PROMPT",
    "API_KEY",
    "APIKEY",
    "ACCESS_TOKEN",
    "AUTH_TOKEN",
    "TOKEN",
    "SECRET",
    "PASSWORD",
    "PASSWD",
    "CREDENTIAL",
    "CREDENTIALS",
}

_SENSITIVE_MARKERS = (
    "API_KEY",
    "APIKEY",
    "ACCESS_KEY",
    "ACCESSKEY",
    "TOKEN",
    "SECRET",
    "PASSWORD",
    "PASSWD",
    "CREDENTIAL",
    "COOKIE",
)


def is_sensitive_environment_name(name: str) -> bool:
    normalized = str(name).upper()
    return (
        normalized in _BLOCKED_EXACT
        or any(normalized.startswith(prefix) for prefix in _BLOCKED_PREFIXES)
        or any(marker in normalized for marker in _SENSITIVE_MARKERS)
        or normalized == "KEY"
        or normalized.endswith("_KEY")
        or normalized in {"AUTH", "AUTHORIZATION"}
        or normalized.endswith("_AUTHORIZATION")
        or normalized.endswith("_AUTH")
        or "_AUTH_" in normalized
    )


def filter_environment(values: Mapping[str, str]) -> dict[str, str]:
    """Copy an environment while removing credential and proxy variables."""
    return {key: value for key, value in values.items() if not is_sensitive_environment_name(key)}
