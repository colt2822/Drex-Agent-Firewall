"""Explicit read-only package mounts for the system-Python guest MCP runtime.

Do not mount host site-packages or user-home parents: they may contain unrelated
data. These package sources and the system Python must be trusted and ABI-matched.
"""
from importlib.util import find_spec
from pathlib import Path

from drex_agent_firewall.schemas.config import SandboxMount


MCP_PACKAGES = (
    "pydantic", "pydantic_core", "annotated_types", "typing_extensions",
    "typing_inspection", "yaml", "httpx", "httpcore", "anyio", "idna",
    "certifi", "h11", "prometheus_client",
)


def python_dependency_mounts():
    mounts = []
    for name in MCP_PACKAGES:
        spec = find_spec(name)
        if not spec or not spec.origin:
            raise RuntimeError(f"Required guest MCP dependency unavailable: {name}")
        source = Path(spec.origin).resolve()
        if spec.submodule_search_locations:
            source = source.parent
        mounts.append(SandboxMount(host_path=str(source), container_path=f"/opt/drex-python/{source.name}", mode="ro"))
    return mounts
