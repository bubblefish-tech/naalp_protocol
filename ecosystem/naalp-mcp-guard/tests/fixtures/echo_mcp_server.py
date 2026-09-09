# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""A minimal, REAL synchronous MCP-shaped stdio JSON-RPC server, used ONLY as a fixture for
naalp-mcp-guard's transport tests (tests/test_cli.py). It is a genuine subprocess speaking the
real newline-delimited JSON-RPC framing (not a mock of the transport under test) -- what it lacks
is protocol breadth (no resources/prompts/sampling), which the guard's transport tests do not
need. Reads requests from stdin, writes responses to stdout, one line per JSON-RPC message.
"""
import json
import sys


def _tools():
    return [
        {"name": "list_files", "annotations": {"readOnlyHint": True}},
        {"name": "delete_repo", "annotations": {"readOnlyHint": False, "destructiveHint": True}},
        {"name": "echo"},  # no annotations at all -- classifies destructive (fail-closed)
    ]


def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        method = msg.get("method")
        mid = msg.get("id")
        if method is None:
            continue  # a notification/response FROM the client; this fixture ignores it
        if method == "tools/list":
            response = {"jsonrpc": "2.0", "id": mid, "result": {"tools": _tools()}}
        elif method == "tools/call":
            name = msg.get("params", {}).get("name")
            args = msg.get("params", {}).get("arguments", {})
            if name == "notify_then_reply":
                # exercise the unsolicited-message path: emit a bare notification BEFORE the
                # real response, with no "id" -- the proxy must relay it upstream untouched.
                sys.stdout.write(json.dumps({
                    "jsonrpc": "2.0", "method": "notifications/message",
                    "params": {"level": "info", "data": "hello-from-server"},
                }) + "\n")
                sys.stdout.flush()
            response = {
                "jsonrpc": "2.0", "id": mid,
                "result": {"content": [{"type": "text", "text": "echoed:%s" % json.dumps(args, sort_keys=True)}],
                           "isError": False},
            }
        else:
            response = {"jsonrpc": "2.0", "id": mid, "result": {}}
        sys.stdout.write(json.dumps(response) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
