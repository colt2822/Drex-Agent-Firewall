"""Abstract base classes and schemas for Drex Isolated Agent Runtime backends."""

from __future__ import annotations

from abc import ABC, abstractmethod
from enum import Enum
import time
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from drex_agent_firewall.schemas.config import FirewallConfig, SandboxConfig, SandboxLimits, SandboxMount


class SandboxStatus(str, Enum):
    CREATED = "CREATED"
    RUNNING = "RUNNING"
    STOPPED = "STOPPED"
    FAILED = "FAILED"
    DESTROYED = "DESTROYED"


class SandboxSpec(BaseModel):
    """Execution specification for an isolated agent runtime sandbox."""
    session_id: str
    workspace_path: str
    policy_pack: str = "safe-local-coding"
    agent_type: str = "generic"
    config: Optional[FirewallConfig] = None
    network_mode: str = "firewall-only"  # none, firewall-only, allowlisted, host
    workspace_mode: str = "rw"          # rw or ro
    expose_host_home: bool = False
    expose_host_root: bool = False
    expose_container_socket: bool = False
    inherit_env: bool = False
    env_allowlist: List[str] = Field(default_factory=lambda: ["PATH", "LANG", "LC_ALL", "TERM", "USER", "HOME", "SHELL", "PYTHONPATH"])
    env_overrides: Dict[str, str] = Field(default_factory=dict)
    extra_mounts: List[SandboxMount] = Field(default_factory=list)
    limits: SandboxLimits = Field(default_factory=SandboxLimits)
    mcp_config_path: Optional[str] = None
    drex_db_path: Optional[str] = None


class SandboxResult(BaseModel):
    """Result of command or process execution inside the sandbox boundary."""
    returncode: int = 0
    stdout: str = ""
    stderr: str = ""
    duration_seconds: float = 0.0
    timed_out: bool = False
    limit_exceeded: bool = False
    error: Optional[str] = None


class SandboxSessionInfo(BaseModel):
    """Runtime metadata for an active or completed sandbox session."""
    session_id: str
    backend_name: str
    runtime_id: Optional[str] = None
    workspace_path: str
    policy_pack: str
    agent_type: str
    network_mode: str
    status: SandboxStatus = SandboxStatus.CREATED
    created_at: float = Field(default_factory=time.time)
    stopped_at: Optional[float] = None
    limits: SandboxLimits = Field(default_factory=SandboxLimits)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class IsolationBackend(ABC):
    """Abstract interface defining the outer OS isolation boundary contract."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Name of the isolation backend."""
        pass

    @abstractmethod
    def is_available(self) -> bool:
        """Check whether runtime dependencies (binary, permissions) are satisfied."""
        pass

    @abstractmethod
    def prepare(self, spec: SandboxSpec) -> bool:
        """Prepare sandbox environment, synthetic roots, and bind mounts."""
        pass

    @abstractmethod
    def launch(self, spec: SandboxSpec) -> SandboxSessionInfo:
        """Launch or initialize the isolated sandbox session."""
        pass

    @abstractmethod
    def exec(
        self,
        session_id: str,
        command: List[str],
        cwd: Optional[str] = None,
        env: Optional[Dict[str, str]] = None,
        timeout: Optional[float] = None,
        input: Optional[str] = None,
    ) -> SandboxResult:
        """Execute a process strictly confined within the isolated sandbox."""
        pass

    @abstractmethod
    def stop(self, session_id: str) -> bool:
        """Terminate all running processes within the sandbox."""
        pass

    @abstractmethod
    def destroy(self, session_id: str) -> bool:
        """Clean up ephemeral mount points, namespaces, and runtime state."""
        pass

    @abstractmethod
    def status(self, session_id: str) -> SandboxStatus:
        """Retrieve current lifecycle status of the sandbox session."""
        pass
