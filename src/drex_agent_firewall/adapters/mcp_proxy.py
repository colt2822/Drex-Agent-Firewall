"""MCP (Model Context Protocol) Firewall Proxy.

Intercepts JSON-RPC 2.0 messages (tools/list, tools/call, resources/read, resources/write)
between MCP clients (Claude Code, OpenHands, Codex) and arbitrary upstream MCP servers.
"""

from __future__ import annotations

import json
import os
import re
import select
import signal
import subprocess
import sys
import threading
from typing import Any, Callable, Dict, Optional, Tuple

from drex_agent_firewall.adapters.base import BaseAdapter
from drex_agent_firewall.constraints.enforcer import ConstraintEnforcer, ConstraintViolation
from drex_agent_firewall.schemas.decision import FirewallDecision


class McpFirewallProxy(BaseAdapter):
    """Intercepts and enforces policy on MCP JSON-RPC 2.0 protocol exchanges."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.client_info: Dict[str, str] = {}

    def _agent_id(self) -> str:
        name = self.client_info.get("name", "MCP client")
        version = self.client_info.get("version", "")
        label = f"{name}/{version}" if version else name
        return re.sub(r"[^A-Za-z0-9._ /-]", "", label)[:120] or "MCP client"

    def handle_jsonrpc_message(
        self,
        request_dict: Dict[str, Any],
        forward_handler: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]] = None,
    ) -> Optional[Dict[str, Any]]:
        """
        Process a single JSON-RPC 2.0 message.
        If allowed, invokes forward_handler; otherwise returns a JSON-RPC error.
        """
        req_id = request_dict.get("id")
        method = request_dict.get("method", "")
        params = request_dict.get("params", {})
        if method == "initialize" and isinstance(params, dict):
            info = params.get("clientInfo", {})
            if isinstance(info, dict):
                self.client_info = {key: str(info[key])[:80] for key in ("name", "version") if isinstance(info.get(key), (str, int, float))}

        # Read-only protocol discovery is forwarded, but its returned inventory
        # is validated and audited so upstream metadata is never invisible.
        if method in {"tools/list", "resources/list", "prompts/list"}:
            try:
                response = forward_handler(request_dict) if forward_handler else {
                    "jsonrpc": "2.0", "id": req_id, "result": {method.split("/")[0]: []}}
                if not isinstance(response, dict) or response.get("jsonrpc") != "2.0" or "error" in response:
                    raise ValueError("invalid or failed upstream response")
                result = response.get("result")
                key = method.split("/")[0]
                entries = result.get(key, []) if isinstance(result, dict) else None
                if not isinstance(entries, list):
                    raise ValueError("invalid inventory metadata")
                env, decision = self.evaluate_action("mcp", method, {key: entries},
                    context={"mcp_method": method, "inventory_count": len(entries)}, agent_id=self._agent_id())
                if self.repository:
                    self.record_execution_result(env.action_id, "mcp", True,
                        result={"inventory_count": len(entries)})
                return response
            except Exception as exc:
                return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32603,
                    "message": f"Drex upstream/protocol failure: {type(exc).__name__}"}}

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
                agent_id=self._agent_id(),
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
                agent_id=self._agent_id(),
            )
            if not decision.allowed:
                self.record_execution_result(envelope.action_id, "mcp", False, error_class="FIREWALL_POLICY_BLOCKED")
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {
                        "code": -32003,
                        "message": f"Blocked resource read: {decision.reason}",
                    },
                }
            if forward_handler:
                try:
                    response = forward_handler(request_dict)
                    if not isinstance(response, dict) or response.get("jsonrpc") != "2.0" or "error" in response:
                        raise ValueError("invalid or failed upstream response")
                    self.record_execution_result(envelope.action_id, "mcp", True, result={"status": "read_returned"})
                    return response
                except Exception as exc:
                    self.record_execution_result(envelope.action_id, "mcp", False, error_class=type(exc).__name__)
                    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32603,
                        "message": f"Drex upstream/protocol failure: {type(exc).__name__}"}}
            return {"jsonrpc": "2.0", "id": req_id, "result": {"contents": []}}

        # Only defined non-mutating session methods are allowed through. Unknown
        # methods fail closed because their side effects cannot be classified.
        if method in {"initialize", "ping", "notifications/initialized", "notifications/cancelled"}:
            if forward_handler:
                try:
                    if method.startswith("notifications/"):
                        forward_handler(request_dict)
                        return None
                    return forward_handler(request_dict)
                except Exception as exc:
                    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32603,
                        "message": f"Drex upstream failure: {type(exc).__name__}"}}
            return {"jsonrpc": "2.0", "id": req_id, "result": {}}
        return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32601,
            "message": "Drex blocked unsupported MCP method"}}

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
            start_new_session=True,
        )

        def _forward(req: Dict[str, Any]) -> Optional[Dict[str, Any]]:
            req_line = json.dumps(req) + "\n"
            proc.stdin.write(req_line)
            proc.stdin.flush()
            if "id" not in req:
                return None
            timeout = float(os.environ.get("DREX_MCP_UPSTREAM_TIMEOUT", "30"))
            ready, _, _ = select.select([proc.stdout], [], [], timeout)
            if not ready:
                raise TimeoutError("upstream MCP response timed out")
            resp_line = proc.stdout.readline()
            if not resp_line:
                raise RuntimeError("Upstream MCP process terminated unexpectedly")
            response = json.loads(resp_line.strip())
            if (not isinstance(response, dict) or response.get("jsonrpc") != "2.0"
                    or response.get("id") != req.get("id")
                    or not ("result" in response or "error" in response)):
                raise ValueError("invalid upstream JSON-RPC response")
            return response

        try:
            for line in sys.stdin:
                line = line.strip()
                if not line:
                    continue
                try:
                    req_dict = json.loads(line)
                    resp_dict = self.handle_jsonrpc_message(req_dict, forward_handler=_forward)
                    if resp_dict is None:
                        continue
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
            try:
                os.killpg(proc.pid, signal.SIGTERM)
                proc.wait(timeout=2)
            except (ProcessLookupError, PermissionError, OSError, subprocess.TimeoutExpired):
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except OSError:
                    proc.kill()
