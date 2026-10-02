"""MCP package for Drex Agent Firewall."""

def get_mcp_server(*args, **kwargs):
    from drex_agent_firewall.mcp.server import DrexMcpServer
    return DrexMcpServer(*args, **kwargs)

__all__ = ["get_mcp_server"]
