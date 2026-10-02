"""Standards-compliant MCP test servers for verifying firewall proxy interoperability.

Provides mock implementations of:
1. Filesystem-style MCP Server (tools/list, tools/call, resources/read, resources/write)
2. Git/GitHub-style MCP Server (git status, commit, push, PR creation)
3. Generic Tool Server (math, echo, system info, streaming notifications)
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional


class BaseMockMcpServer:
    """Base JSON-RPC 2.0 MCP server implementation."""

    def __init__(self, name: str):
        self.name = name

    def handle_request(self, req: Dict[str, Any]) -> Dict[str, Any]:
        req_id = req.get("id")
        method = req.get("method")
        params = req.get("params", {})

        if method == "tools/list":
            return {"jsonrpc": "2.0", "id": req_id, "result": {"tools": self.list_tools()}}
        elif method == "tools/call":
            tool_name = params.get("name")
            args = params.get("arguments", {})
            return self.call_tool(req_id, tool_name, args)
        elif method == "resources/list":
            return {"jsonrpc": "2.0", "id": req_id, "result": {"resources": self.list_resources()}}
        elif method == "resources/read":
            uri = params.get("uri")
            return self.read_resource(req_id, uri)
        elif method == "resources/write":
            uri = params.get("uri")
            content = params.get("content")
            return self.write_resource(req_id, uri, content)
        elif method == "notifications/message":
            return {"jsonrpc": "2.0", "method": "notifications/message", "params": {"status": "streaming_ack"}}
        else:
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": -32601, "message": f"Method '{method}' not found"},
            }

    def list_tools(self) -> List[Dict[str, Any]]:
        return []

    def call_tool(self, req_id: Any, name: str, args: Dict[str, Any]) -> Dict[str, Any]:
        return {"jsonrpc": "2.0", "id": req_id, "result": {"content": [{"type": "text", "text": "ok"}]}}

    def list_resources(self) -> List[Dict[str, Any]]:
        return []

    def read_resource(self, req_id: Any, uri: str) -> Dict[str, Any]:
        return {"jsonrpc": "2.0", "id": req_id, "result": {"contents": [{"uri": uri, "text": "mock content"}]}}

    def write_resource(self, req_id: Any, uri: str, content: str) -> Dict[str, Any]:
        return {"jsonrpc": "2.0", "id": req_id, "result": {"status": "written", "bytes": len(content)}}


class FilesystemMcpServer(BaseMockMcpServer):
    """MCP server providing file reading, directory listing, and file modification."""

    def __init__(self):
        super().__init__("filesystem-mcp-server")

    def list_tools(self) -> List[Dict[str, Any]]:
        return [
            {"name": "read_file", "description": "Read file contents", "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}}},
            {"name": "write_file", "description": "Write file contents", "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}, "content": {"type": "string"}}}},
            {"name": "list_directory", "description": "List files in directory", "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}}},
        ]

    def call_tool(self, req_id: Any, name: str, args: Dict[str, Any]) -> Dict[str, Any]:
        if name == "read_file":
            path = args.get("path", "")
            return {"jsonrpc": "2.0", "id": req_id, "result": {"content": [{"type": "text", "text": f"# File content for {path}"}]}}
        elif name == "write_file":
            path = args.get("path", "")
            return {"jsonrpc": "2.0", "id": req_id, "result": {"content": [{"type": "text", "text": f"Successfully wrote to {path}"}]}}
        elif name == "list_directory":
            return {"jsonrpc": "2.0", "id": req_id, "result": {"content": [{"type": "text", "text": "file1.py\nfile2.py"}]}}
        return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32601, "message": f"Unknown tool {name}"}}


class GitGitHubMcpServer(BaseMockMcpServer):
    """MCP server providing Git version control and GitHub API interactions."""

    def __init__(self):
        super().__init__("git-github-mcp-server")

    def list_tools(self) -> List[Dict[str, Any]]:
        return [
            {"name": "git_status", "description": "Check git repository status", "inputSchema": {"type": "object"}},
            {"name": "git_commit", "description": "Commit changes locally", "inputSchema": {"type": "object", "properties": {"message": {"type": "string"}}}},
            {"name": "git_push", "description": "Push commits to remote", "inputSchema": {"type": "object", "properties": {"branch": {"type": "string"}, "force": {"type": "boolean"}}}},
            {"name": "create_pull_request", "description": "Create GitHub PR", "inputSchema": {"type": "object", "properties": {"title": {"type": "string"}, "body": {"type": "string"}}}},
        ]

    def call_tool(self, req_id: Any, name: str, args: Dict[str, Any]) -> Dict[str, Any]:
        if name == "git_status":
            return {"jsonrpc": "2.0", "id": req_id, "result": {"content": [{"type": "text", "text": "On branch main\nnothing to commit"}]}}
        elif name == "git_commit":
            return {"jsonrpc": "2.0", "id": req_id, "result": {"content": [{"type": "text", "text": "[main abc1234] committed"}]}}
        elif name == "git_push":
            return {"jsonrpc": "2.0", "id": req_id, "result": {"content": [{"type": "text", "text": "Pushed to origin"}]}}
        elif name == "create_pull_request":
            return {"jsonrpc": "2.0", "id": req_id, "result": {"content": [{"type": "text", "text": "PR #101 created"}]}}
        return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32601, "message": f"Unknown tool {name}"}}


class GenericToolMcpServer(BaseMockMcpServer):
    """Generic tool server providing calculation, echo, and system metrics."""

    def __init__(self):
        super().__init__("generic-tool-server")

    def list_tools(self) -> List[Dict[str, Any]]:
        return [
            {"name": "calculate", "description": "Perform basic arithmetic", "inputSchema": {"type": "object", "properties": {"expression": {"type": "string"}}}},
            {"name": "echo_tool", "description": "Echo input text", "inputSchema": {"type": "object", "properties": {"text": {"type": "string"}}}},
            {"name": "execute_shell", "description": "Execute shell command", "inputSchema": {"type": "object", "properties": {"command": {"type": "string"}}}},
        ]

    def call_tool(self, req_id: Any, name: str, args: Dict[str, Any]) -> Dict[str, Any]:
        if name == "calculate":
            return {"jsonrpc": "2.0", "id": req_id, "result": {"content": [{"type": "text", "text": "42"}]}}
        elif name == "echo_tool":
            return {"jsonrpc": "2.0", "id": req_id, "result": {"content": [{"type": "text", "text": args.get("text", "")}]}}
        elif name == "execute_shell":
            return {"jsonrpc": "2.0", "id": req_id, "result": {"content": [{"type": "text", "text": "Command executed"}]}}
        return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32601, "message": f"Unknown tool {name}"}}
