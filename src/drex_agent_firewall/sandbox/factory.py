"""Factory and auto-discovery for Drex Isolation Backends."""

from __future__ import annotations

import logging
from typing import Optional

from drex_agent_firewall.sandbox.backend import IsolationBackend
from drex_agent_firewall.sandbox.bubblewrap import BubblewrapBackend
from drex_agent_firewall.sandbox.container import DockerBackend, PodmanBackend
from drex_agent_firewall.sandbox.microvm import MicroVMBackend
from drex_agent_firewall.sandbox.no_isolation import NoIsolationBackend

logger = logging.getLogger(__name__)


def get_isolation_backend(backend_type: str = "auto") -> IsolationBackend:
    """Instantiate the requested or safest available isolation backend.
    
    Priority for 'auto':
    1. Bubblewrap (rootless unprivileged container namespaces)
    2. Podman (rootless OCI container)
    3. Docker (daemon-backed container)
    
    FAIL CLOSED:
    If a sandbox is requested but no isolation backend is available,
    raises RuntimeError immediately instead of silently degrading to host execution.
    """
    clean_type = backend_type.lower().strip()

    if clean_type in ("none", "host", "no_isolation"):
        return NoIsolationBackend()

    if clean_type == "microvm":
        backend = MicroVMBackend()
        if not backend.is_available():
            raise RuntimeError("Requested microvm isolation backend is not available on this host (missing /dev/kvm or hypervisor binary)")
        return backend

    if clean_type == "bubblewrap" or clean_type == "bwrap":
        bwrap = BubblewrapBackend()
        if not bwrap.is_available():
            raise RuntimeError("SANDBOX_UNAVAILABLE: Bubblewrap (bwrap) isolation runtime is not installed or available on this system")
        return bwrap

    if clean_type == "podman":
        podman = PodmanBackend()
        if not podman.is_available():
            raise RuntimeError("Podman container runtime is not installed or available on this system")
        return podman

    if clean_type == "docker":
        docker = DockerBackend()
        if not docker.is_available():
            raise RuntimeError("Docker container runtime is not installed or available on this system")
        return docker

    if clean_type == "auto":
        # 1. Bubblewrap (safest, unprivileged rootless namespaces)
        bwrap = BubblewrapBackend()
        if bwrap.is_available():
            return bwrap

        # 2. Podman
        podman = PodmanBackend()
        if podman.is_available():
            return podman

        # 3. Docker
        docker = DockerBackend()
        if docker.is_available():
            return docker

        # Fail closed: No isolation engine is functional
        raise RuntimeError(
            "FAIL-CLOSED: No supported sandbox isolation runtime (bubblewrap, podman, docker) is available on this system. "
            "Refusing to execute unconfined when sandbox mode is requested."
        )

    raise ValueError(f"Unknown isolation backend '{backend_type}'. Valid: auto, bubblewrap, podman, docker, microvm, none")
