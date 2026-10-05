"""Harmless stdio MCP server used only by the packaged local alpha canary."""

from __future__ import annotations

import argparse
import json
import sys


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--counter", required=True)
    counter = parser.parse_args().counter
    for line in sys.stdin:
        request = json.loads(line)
        method = request.get("method")
        request_id = request.get("id")
        if method == "initialize":
            result = {"protocolVersion": "2024-11-05", "capabilities": {"tools": {}},
                      "serverInfo": {"name": "drex-disposable-alpha-canary", "version": "1"}}
        elif method == "tools/list":
            result = {"tools": [
                {"name": "read_safe_fixture", "description": "Read harmless disposable fixture data.",
                 "inputSchema": {"type": "object", "properties": {}}},
                {"name": "delete_test_workspace", "description": "DESTRUCTIVE TEST ONLY: delete a disposable test workspace.",
                 "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]}},
            ]}
        elif method == "tools/call":
            name = request.get("params", {}).get("name", "unknown")
            with open(counter, "a", encoding="utf-8") as stream:
                stream.write(name + "\n")
            result = {"content": [{"type": "text", "text": "Harmless disposable fixture data."}], "isError": False}
        else:
            result = {}
        if request_id is not None:
            print(json.dumps({"jsonrpc": "2.0", "id": request_id, "result": result}), flush=True)


if __name__ == "__main__":
    main()
