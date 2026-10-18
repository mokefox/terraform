#!/usr/bin/env python3
"""
mock_mcp_server.py - Minimal Standard I/O MCP (Model Context Protocol) Server for Testing

Implements standard MCP JSON-RPC 2.0 messages:
- initialize
- tools/list
- tools/call
"""

import sys
import json
import subprocess


def send_response(response: dict):
    line = json.dumps(response)
    sys.stdout.write(line + "\n")
    sys.stdout.flush()


def handle_initialize(req_id):
    send_response({
        "jsonrpc": "2.0",
        "id": req_id,
        "result": {
            "protocolVersion": "2024-11-05",
            "capabilities": {
                "tools": {}
            },
            "serverInfo": {
                "name": "mock-mcp-server",
                "version": "1.0.0"
            }
        }
    })


def handle_tools_list(req_id):
    send_response({
        "jsonrpc": "2.0",
        "id": req_id,
        "result": {
            "tools": [
                {
                    "name": "run_shell",
                    "description": "Execute a shell command in the local environment",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "command": {"type": "string", "description": "The command to execute"}
                        },
                        "required": ["command"]
                    }
                },
                {
                    "name": "read_file",
                    "description": "Read file contents",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "path": {"type": "string", "description": "Path to the file"}
                        },
                        "required": ["path"]
                    }
                }
            ]
        }
    })


def handle_tools_call(req_id, params):
    tool_name = params.get("name")
    args = params.get("arguments", {})

    if tool_name == "run_shell":
        command = args.get("command", "")
        # Mock execution
        send_response({
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "content": [
                    {
                        "type": "text",
                        "text": f"[MOCK SERVER EXECUTED] Output of `{command}`: total 42 files..."
                    }
                ],
                "isError": False
            }
        })
    elif tool_name == "read_file":
        path = args.get("path", "")
        send_response({
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "content": [
                    {
                        "type": "text",
                        "text": f"[MOCK SERVER EXECUTED] Contents of {path}: simulated safe contents."
                    }
                ],
                "isError": False
            }
        })
    else:
        send_response({
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {
                "code": -32601,
                "message": f"Method/Tool {tool_name} not found"
            }
        })


def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError:
            continue

        method = req.get("method")
        req_id = req.get("id")
        params = req.get("params", {})

        if method == "initialize":
            handle_initialize(req_id)
        elif method == "tools/list":
            handle_tools_list(req_id)
        elif method == "tools/call":
            handle_tools_call(req_id, params)
        elif method == "notifications/initialized":
            pass  # No response needed for notification
        else:
            if req_id is not None:
                send_response({
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {
                        "code": -32601,
                        "message": f"Unknown method: {method}"
                    }
                })


if __name__ == "__main__":
    main()
