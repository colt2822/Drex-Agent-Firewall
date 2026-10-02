"""Extensible MicroVM / Hardware-Isolated Isolation Backend interface for Drex Agent Firewall."""

from __future__ import annotations

import logging
import os
import shutil
from typing import Any, Dict, List, Optional

from drex_agent_firewall.sandbox.backend import (
    IsolationBackend,
    SandboxResult,
    SandboxSessionInfo,
    SandboxSpec,
    SandboxStatus,
)

logger = logging.getLogger(__name__)


class MicroVMBackend(IsolationBackend):
    """Architectural interface for hardware-assisted microVM runtimes (Firecracker, Kata, Cloud-Hypervisor, gVisor).
    
    Provides the contract for hypervisor-based VM boundary enforcement where the agent
    runs with a dedicated virtual machine kernel, virtio-fs workspace mount, and vsock
    mediated communication to the Drex firewall host service.
    """

    def __init__(self, hypervisor_bin: Optional[str] = None):
        self.hypervisor_bin = hypervisor_bin or shutil.which("firecracker") or shutil.which("kata-runtime")
        self._sessions: Dict[str, Dict[str, Any]] = {}

    @property
    def name(self) -> str:
        return "microvm"

    def is_available(self) -> bool:
        # Check for /dev/kvm availability and hypervisor binary
        kvm_accessible = os.path.exists("/dev/kvm") and os.access("/dev/kvm", os.R_OK | os.W_OK)
        return bool(kvm_accessible and self.hypervisor_bin and os.path.exists(self.hypervisor_bin))

    def prepare(self, spec: SandboxSpec) -> bool:
        if not self.is_available():
            raise NotImplementedError(
                "Hardware-assisted MicroVM backend is not available on this host. "
                "Ensure KVM is enabled (/dev/kvm) and a supported hypervisor (Firecracker or Kata) is installed."
            )
        self._sessions[spec.session_id] = {
            "spec": spec,
            "status": SandboxStatus.CREATED,
        }
        return True

    def launch(self, spec: SandboxSpec) -> SandboxSessionInfo:
        if not self.is_available():
            raise NotImplementedError("MicroVM hypervisor unavailable")
        raise NotImplementedError("MicroVM backend driver stub - ready for external hypervisor integration")

    def exec(
        self,
        session_id: str,
        command: List[str],
        cwd: Optional[str] = None,
        env: Optional[Dict[str, str]] = None,
        timeout: Optional[float] = None,
        input: Optional[str] = None,
    ) -> SandboxResult:
        raise NotImplementedError("MicroVM execution requires live hypervisor")

    def stop(self, session_id: str) -> bool:
        return True

    def destroy(self, session_id: str) -> bool:
        self._sessions.pop(session_id, None)
        return True

    def status(self, session_id: str) -> SandboxStatus:
        if session_id not in self._sessions:
            return SandboxStatus.DESTROYED
        return self._sessions[session_id]["status"]
