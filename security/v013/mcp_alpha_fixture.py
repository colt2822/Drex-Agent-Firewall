"""Harmless stdio MCP fixture for a disposable Claude Code alpha canary."""
import json
import os
import sys
from pathlib import Path


def respond(message):
    method = message.get("method")
    request_id = message.get("id")
    if method == "notifications/initialized" or method == "notifications/cancelled":
        return None
    if method == "initialize":
        result = {"protocolVersion": message.get("params", {}).get("protocolVersion", "2024-11-05"),
                  "capabilities": {"tools": {"listChanged": False}},
                  "serverInfo": {"name": "drex-alpha-fixture", "version": "1.0.0"}}
    elif method == "ping":
        result = {}
    elif method == "tools/list":
        result = {"tools": [
            {"name": "read_safe_fixture", "description": "Return harmless canned text for the Drex canary.",
             "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False}},
            {"name": "delete_test_workspace", "description": "Simulate deleting /workspace/disposable-fixture. This fixture never deletes files.",
             "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]}},
        ]}
    elif method == "tools/call":
        params = message.get("params", {})
        tool = params.get("name", "")
        args = params.get("arguments", {})
        log_path = os.environ.get("DREX_CANARY_UPSTREAM_LOG")
        if log_path:
            with Path(log_path).open("a", encoding="utf-8") as f:
                f.write(json.dumps({"tool": tool, "arguments": args}) + "\n")
        result = {"content": [{"type": "text", "text": "safe fixture result" if tool == "read_safe_fixture" else "SIMULATED ONLY; no files deleted"}]}
    else:
        return {"jsonrpc": "2.0", "id": request_id,
                "error": {"code": -32601, "message": "unsupported fixture method"}}
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def main():
    for line in sys.stdin:
        try:
            message = json.loads(line)
            response = respond(message)
            if response is not None:
                sys.stdout.write(json.dumps(response, separators=(",", ":")) + "\n")
                sys.stdout.flush()
        except Exception as exc:
            sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": None,
                "error": {"code": -32603, "message": type(exc).__name__}}) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
