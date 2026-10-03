"""Stdio MCP server exposing Drex Agent Firewall guarded tools to autonomous agents.

Mediates calls made to these MCP tools. Native agent execution can bypass policy.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any, Dict, List, Optional

from drex_agent_firewall.adapters.filesystem_adapter import FilesystemAdapter
from drex_agent_firewall.adapters.git_adapter import GitAdapter
from drex_agent_firewall.adapters.shell_adapter import ShellAdapter
from drex_agent_firewall.persistence.repository import ActionRepository
from drex_agent_firewall.persistence.audit_broker import AuditClient
from drex_agent_firewall.policy.engine import DeterministicPolicyEngine
from drex_agent_firewall.policy.packs import POLICY_PACK_DESCRIPTIONS
from drex_agent_firewall.schemas.config import FirewallConfig


class DrexMcpServer:
    """Stdio JSON-RPC 2.0 MCP server wrapping Drex Agent Firewall adapters."""

    def __init__(
        self,
        workspace_dir: str,
        config: Optional[FirewallConfig] = None,
        agent_id: str = "claude-code",
        session_id: str = "mcp-session",
        host_audit: bool = False,
    ):
        self.workspace_dir = os.path.abspath(workspace_dir)
        self.config = config or FirewallConfig(allowed_roots=[self.workspace_dir])
        self.agent_id = agent_id
        self.session_id = session_id

        self.engine = DeterministicPolicyEngine(config=self.config)
        self.repository = AuditClient() if host_audit else ActionRepository(db_path=self.config.database_path)

        # Initialize adapters
        self.shell_adapter = ShellAdapter(engine=self.engine, repository=self.repository)
        self.fs_adapter = FilesystemAdapter(engine=self.engine, repository=self.repository)
        self.git_adapter = GitAdapter(engine=self.engine, repository=self.repository)

    def list_tools(self) -> List[Dict[str, Any]]:
        return [
            {
                "name": "execute_shell",
                "description": "Execute a shell command inside the workspace. Guarded by Drex Agent Firewall.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "command": {"type": "string", "description": "Shell command line to execute."},
                        "timeout": {"type": "number", "description": "Timeout in seconds (optional)."},
                    },
                    "required": ["command"],
                },
            },
            {
                "name": "read_file",
                "description": "Read contents of a file inside the repository workspace. Guarded by Drex Agent Firewall.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "description": "Relative or absolute file path to read."},
                    },
                    "required": ["path"],
                },
            },
            {
                "name": "write_file",
                "description": "Write or overwrite a file inside the repository workspace. Guarded by Drex Agent Firewall.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "description": "Relative or absolute file path to write."},
                        "content": {"type": "string", "description": "File text content."},
                    },
                    "required": ["path", "content"],
                },
            },
            {
                "name": "list_directory",
                "description": "List files and directories within a workspace directory. Guarded by Drex Agent Firewall.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "description": "Directory path (defaults to root)."},
                    },
                },
            },
            {
                "name": "git_command",
                "description": "Run a git operation in the workspace. Guarded by Drex Agent Firewall.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "command": {"type": "string", "description": "Git subcommand and arguments (e.g., 'status', 'diff', 'commit -m \"fix\"')."},
                    },
                    "required": ["command"],
                },
            },
        ]

    def handle_request(self, req: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        req_id = req.get("id")
        method = req.get("method")
        params = req.get("params", {})

        if method == "initialize":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {"tools": {}},
                    "serverInfo": {
                        "name": "drex-agent-firewall",
                        "version": "1.0.0",
                    },
                },
            }

        if method == "notifications/initialized":
            return None

        if method == "ping":
            return {"jsonrpc": "2.0", "id": req_id, "result": {}}

        if method == "tools/list":
            return {"jsonrpc": "2.0", "id": req_id, "result": {"tools": self.list_tools()}}

        if method == "tools/call":
            tool_name = params.get("name")
            args = params.get("arguments", {})
            return self._dispatch_tool_call(req_id, tool_name, args)

        # Unsupported method
        if req_id is not None:
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": -32601, "message": f"Method '{method}' not found"},
            }
        return None

    def _resolve_path(self, path_arg: str) -> str:
        if not path_arg:
            return self.workspace_dir
        if os.path.isabs(path_arg):
            return path_arg
        return os.path.join(self.workspace_dir, path_arg)

    def _dispatch_tool_call(self, req_id: Any, name: str, args: Dict[str, Any]) -> Dict[str, Any]:
        try:
            if name == "execute_shell":
                cmd = args.get("command", "")
                timeout = args.get("timeout")
                res = self.shell_adapter.execute(
                    command=cmd,
                    cwd=self.workspace_dir,
                    timeout=timeout,
                    agent_id=self.agent_id,
                    session_id=self.session_id,
                )
                if not res.allowed:
                    msg = f"DREX FIREWALL BLOCKED command '{cmd}': {res.firewall_decision.reason} ({res.firewall_decision.decision.value})"
                    return {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "result": {"content": [{"type": "text", "text": msg}], "isError": True},
                    }
                output = f"stdout:\n{res.stdout}\nstderr:\n{res.stderr}\nexit_code: {res.exit_code}"
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {"content": [{"type": "text", "text": output}], "isError": res.exit_code != 0},
                }

            elif name == "read_file":
                path = self._resolve_path(args.get("path", ""))
                res = self.fs_adapter.read_file(path=path, cwd=self.workspace_dir)
                if not res.allowed:
                    msg = f"DREX FIREWALL BLOCKED read_file '{path}': {res.firewall_decision.reason} ({res.firewall_decision.decision.value})"
                    return {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "result": {"content": [{"type": "text", "text": msg}], "isError": True},
                    }
                if res.error:
                    return {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "result": {"content": [{"type": "text", "text": f"Error: {res.error}"}], "isError": True},
                    }
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {"content": [{"type": "text", "text": res.content or ""}], "isError": False},
                }

            elif name == "write_file":
                path = self._resolve_path(args.get("path", ""))
                content = args.get("content", "")
                if os.path.exists(path):
                    res = self.fs_adapter.modify_file(path=path, content=content, cwd=self.workspace_dir)
                else:
                    res = self.fs_adapter.create_file(path=path, content=content, cwd=self.workspace_dir)
                if not res.allowed:
                    msg = f"DREX FIREWALL BLOCKED write_file '{path}': {res.firewall_decision.reason} ({res.firewall_decision.decision.value})"
                    return {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "result": {"content": [{"type": "text", "text": msg}], "isError": True},
                    }
                if res.error:
                    return {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "result": {"content": [{"type": "text", "text": f"Error: {res.error}"}], "isError": True},
                    }
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {"content": [{"type": "text", "text": f"Successfully wrote {res.size_bytes} bytes to {path}"}], "isError": False},
                }

            elif name == "list_directory":
                path = self._resolve_path(args.get("path", ""))
                res = self.fs_adapter.list_dir(path=path, cwd=self.workspace_dir)
                if not res.allowed:
                    msg = f"DREX FIREWALL BLOCKED list_dir '{path}': {res.firewall_decision.reason} ({res.firewall_decision.decision.value})"
                    return {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "result": {"content": [{"type": "text", "text": msg}], "isError": True},
                    }
                entries = "\n".join(res.content.splitlines()) if res.content else "(empty)"
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {"content": [{"type": "text", "text": entries}], "isError": False},
                }

            elif name == "git_command":
                cmd = args.get("command", "").strip()
                import shlex
                try:
                    tokens = shlex.split(cmd)
                except Exception:
                    tokens = cmd.split()
                subcmd = tokens[0] if tokens else "status"
                git_args = tokens[1:] if len(tokens) > 1 else []
                res = self.git_adapter._run_git(
                    operation=subcmd,
                    git_cmd_args=[subcmd] + git_args,
                    repo_dir=self.workspace_dir,
                    extra_args={"command": f"git {cmd}"},
                )
                if not res.allowed:
                    msg = f"DREX FIREWALL BLOCKED git '{cmd}': {res.firewall_decision.reason} ({res.firewall_decision.decision.value})"
                    return {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "result": {"content": [{"type": "text", "text": msg}], "isError": True},
                    }
                out = f"stdout:\n{res.stdout}\nstderr:\n{res.stderr}\nexit_code: {res.exit_code}"
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {"content": [{"type": "text", "text": out}], "isError": res.exit_code != 0},
                }

            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": -32601, "message": f"Unknown tool: {name}"},
            }
        except Exception as e:
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": -32603, "message": f"Tool execution failed: {str(e)}"},
            }

    def run_stdio(self) -> None:
        """Run continuous stdio JSON-RPC loop reading from sys.stdin."""
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                req = json.loads(line)
                resp = self.handle_request(req)
                if resp is not None:
                    sys.stdout.write(json.dumps(resp) + "\n")
                    sys.stdout.flush()
            except Exception as e:
                err = {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32700, "message": f"JSON parse error: {str(e)}"},
                }
                sys.stdout.write(json.dumps(err) + "\n")
                sys.stdout.flush()


def main() -> None:
    parser = argparse.ArgumentParser(description="Drex Agent Firewall MCP Server")
    parser.add_argument("--workspace", default=os.getcwd(), help="Allowed workspace path")
    parser.add_argument("--policy", default="safe-local-coding", help="Policy pack to use")
    parser.add_argument("--agent-id", default="claude-code", help="Agent identifier")
    parser.add_argument("--session-id", default="real-agent-demo", help="Session ID")
    parser.add_argument("--live-drex", action="store_true", help="Enable live Drex API provider")
    parser.add_argument("--policy-file", help="Host-generated pinned policy snapshot")
    parser.add_argument("--policy-digest", help="Expected SHA256 of the effective policy")
    parser.add_argument("--host-audit", action="store_true", help="Require the fixed host audit socket; never open a guest DB")
    args = parser.parse_args()

    if args.policy_file:
        import hashlib
        with open(args.policy_file, encoding="utf-8") as stream:
            snapshot = json.load(stream)["drexPolicy"]
        digest = hashlib.sha256(json.dumps(snapshot["config"], sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        if snapshot["version"] != 1 or digest != args.policy_digest or digest != snapshot["digest"]:
            raise RuntimeError("POLICY_INVALID: snapshot digest mismatch")
        config = FirewallConfig.model_validate(snapshot["config"])
    else:
        config = FirewallConfig.from_pack(args.policy)
    config.filesystem.allowed_roots = [os.path.abspath(args.workspace)]
    if args.live_drex:
        config.provider.type = "drex"
        config.provider.api_url = "https://drex.nace.ai/v1/systemone"
        # API key: prefer environment variable, then generic home-relative path
        api_key = os.environ.get("DREX_API_KEY", "")
        if not api_key:
            key_path = os.path.expanduser("~/DREX KEY.txt")
            if os.path.exists(key_path):
                with open(key_path) as f:
                    api_key = f.read().strip()
        if api_key:
            config.provider.api_key = api_key

    server = DrexMcpServer(
        workspace_dir=args.workspace,
        config=config,
        agent_id=args.agent_id,
        session_id=args.session_id,
        host_audit=args.host_audit,
    )
    server.run_stdio()


if __name__ == "__main__":
    main()
