"""Drex Isolated Agent Runtime: outer OS boundary isolation layer."""

from drex_agent_firewall.sandbox.backend import (
    IsolationBackend,
    SandboxLimits,
    SandboxResult,
    SandboxSessionInfo,
    SandboxSpec,
    SandboxStatus,
)
from drex_agent_firewall.sandbox.bubblewrap import BubblewrapBackend
from drex_agent_firewall.sandbox.container import DockerBackend, PodmanBackend
from drex_agent_firewall.sandbox.factory import get_isolation_backend
from drex_agent_firewall.sandbox.manager import SandboxManager
from drex_agent_firewall.sandbox.microvm import MicroVMBackend
from drex_agent_firewall.sandbox.no_isolation import NoIsolationBackend
from drex_agent_firewall.sandbox.probes import SandboxEscapeProbeRunner

__all__ = [
    "IsolationBackend",
    "BubblewrapBackend",
    "PodmanBackend",
    "DockerBackend",
    "NoIsolationBackend",
    "MicroVMBackend",
    "SandboxSpec",
    "SandboxLimits",
    "SandboxResult",
    "SandboxStatus",
    "SandboxSessionInfo",
    "SandboxManager",
    "SandboxEscapeProbeRunner",
    "get_isolation_backend",
]
