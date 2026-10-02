"""MCP (Model Context Protocol) Firewall Proxy.

Intercepts JSON-RPC 2.0 messages (tools/list, tools/call, resources/read, resources/write)
between MCP clients (Claude Code, OpenHands, Codex) and arbitrary upstream MCP servers.
"""

from __future__ import annotations

import json
import subprocess
import sys
import threading
from typing import Any, Callable, Dict, Optional, Tuple

from drex_agent_firewall.adapters.base import BaseAdapter
from drex_agent_firewall.constraints.enforcer import ConstraintEnforcer, ConstraintViolation
from drex_agent_firewall.schemas.decision import FirewallDecision


class McpFirewallProxy(BaseAdapter):
    """Intercepts and enforces policy on MCP JSON-RPC 2.0 protocol exchanges."""

    def handle_jsonrpc_message(
        self,
        request_dict: Dict[str, Any],
        forward_handler: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Process a single JSON-RPC 2.0 message.
        If allowed, invokes forward_handler; otherwise returns a JSON-RPC error.
        """
        req_id = request_dict.get("id")
        method = request_dict.get("method", "")
        params = request_dict.get("params", {})

        # Handle tools/list and resources/list
        if method in {"tools/list", "resources/list"}:
            if forward_handler:
                return forward_handler(request_dict)
            return {"jsonrpc": "2.0", "id": req_id, "result": {"tools": []}}

        # Handle tools/call
        if method == "tools/call":
            tool_name = params.get("name", "unknown_tool")
            tool_args = params.get("arguments", {})

            # 1. Normalize and Evaluate through Firewall
            envelope, decision = self.evaluate_action(
                tool="mcp",
                operation=tool_name,
                arguments=tool_args,
                context={"mcp_method": method, "tool_name": tool_name},
            )

            # 2. Rejection / Blocking
            if not decision.allowed:
                self.record_execution_result(
                    action_id=envelope.action_id,
                    tool="mcp",
                    executed=False,
                    error_class="FIREWALL_POLICY_BLOCKED",
                )
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {
                        "code": -32003,  # Custom MCP policy rejection code
                        "message": f"Drex Agent Firewall blocked tool '{tool_name}': {decision.reason}",
                        "data": {
                            "decision": decision.decision.value,
                            "trace_id": decision.trace_id,
                            "action_id": decision.action_id,
                            "reason": decision.reason,
                        },
                    },
                }

            # 3. Constraint Verification
            try:
                # If command argument present
                if "command" in tool_args:
                    ConstraintEnforcer.verify_command(tool_args["command"], decision.constraints)
                if "path" in tool_args:
                    ConstraintEnforcer.verify_path(tool_args["path"], decision.constraints)
            except ConstraintViolation as cv:
                self.record_execution_result(
                    action_id=envelope.action_id,
                    tool="mcp",
                    executed=False,
                    error_class="CONSTRAINT_VIOLATION",
                )
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {
                        "code": -32003,
                        "message": f"Drex Agent Firewall constraint violation: {str(cv)}",
                        "data": {
                            "decision": decision.decision.value,
                            "trace_id": decision.trace_id,
                            "action_id": decision.action_id,
                        },
                    },
                }

            # 4. Forward to upstream server
            if forward_handler:
                try:
                    upstream_resp = forward_handler(request_dict)
                    self.record_execution_result(
                        action_id=envelope.action_id,
                        tool="mcp",
                        executed=True,
                        result={"status": "forwarded_successfully"},
                    )
                    return upstream_resp
                except Exception as e:
                    self.record_execution_result(
                        action_id=envelope.action_id,
                        tool="mcp",
                        executed=False,
                        error_class=type(e).__name__,
                    )
                    return {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "error": {
                            "code": -32603,
                            "message": f"Upstream MCP error: {str(e)}",
                        },
                    }

            # If no forwarder specified (direct mock/test mode)
            self.record_execution_result(
                action_id=envelope.action_id,
                tool="mcp",
                executed=True,
                result={"status": "allowed_simulated"},
            )
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [
                        {
                            "type": "text",
                            "text": f"Drex Firewall permitted tool '{tool_name}' ({decision.decision.value})",
                        }
                    ],
                    "isError": False,
                },
            }

        # Handle resources/read
        if method == "resources/read":
            uri = params.get("uri", "")
            envelope, decision = self.evaluate_action(
                tool="mcp",
                operation="resources/read",
                arguments={"uri": uri},
            )
            if not decision.allowed:
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {
                        "code": -32003,
                        "message": f"Blocked resource read: {decision.reason}",
                    },
                }
            if forward_handler:
                return forward_handler(request_dict)
            return {"jsonrpc": "2.0", "id": req_id, "result": {"contents": []}}

        # Default passthrough for initialize, ping, notifications
        if forward_handler:
            return forward_handler(request_dict)
        return {"jsonrpc": "2.0", "id": req_id, "result": {}}

    def run_stdio_proxy(self, upstream_cmd: str) -> None:
        """Run continuous stdio proxy wrapping an upstream MCP process."""
        proc = subprocess.Popen(
            upstream_cmd,
            shell=True,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=sys.stderr,
            text=True,
            bufsize=1,
        )

        def _forward(req: Dict[str, Any]) -> Dict[str, Any]:
            req_line = json.dumps(req) + "\n"
            proc.stdin.write(req_line)
            proc.stdin.flush()
            resp_line = proc.stdout.readline()
            if not resp_line:
                raise RuntimeError("Upstream MCP process terminated unexpectedly")
            return json.loads(resp_line.strip())

        try:
            for line in sys.stdin:
                line = line.strip()
                if not line:
                    continue
                try:
                    req_dict = json.loads(line)
                    resp_dict = self.handle_jsonrpc_message(req_dict, forward_handler=_forward)
                    sys.stdout.write(json.dumps(resp_dict) + "\n")
                    sys.stdout.flush()
                except Exception as ex:
                    err_resp = {
                        "jsonrpc": "2.0",
                        "id": None,
                        "error": {"code": -32700, "message": f"Parse or processing error: {str(ex)}"},
                    }
                    sys.stdout.write(json.dumps(err_resp) + "\n")
                    sys.stdout.flush()
        finally:
            proc.terminate()
