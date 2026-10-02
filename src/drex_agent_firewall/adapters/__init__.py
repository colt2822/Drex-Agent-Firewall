"""Adapters package export."""

from drex_agent_firewall.adapters.base import BaseAdapter
from drex_agent_firewall.adapters.shell_adapter import ShellAdapter, ShellExecutionResult
from drex_agent_firewall.adapters.filesystem_adapter import FilesystemAdapter, FilesystemResult
from drex_agent_firewall.adapters.git_adapter import GitAdapter, GitResult
from drex_agent_firewall.adapters.github_adapter import GitHubAdapter, GitHubResult
from drex_agent_firewall.adapters.http_adapter import HttpAdapter, HttpResult
from drex_agent_firewall.adapters.mcp_proxy import McpFirewallProxy

__all__ = [
    "BaseAdapter",
    "ShellAdapter",
    "ShellExecutionResult",
    "FilesystemAdapter",
    "FilesystemResult",
    "GitAdapter",
    "GitResult",
    "GitHubAdapter",
    "GitHubResult",
    "HttpAdapter",
    "HttpResult",
    "McpFirewallProxy",
]
