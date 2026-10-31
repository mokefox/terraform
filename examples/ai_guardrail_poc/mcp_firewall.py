#!/usr/bin/env python3
"""
mcp_firewall.py - Jev-Inspired Dynamic Guardrail Proxy for Model Context Protocol (MCP)

Usage as transparent proxy in claude_desktop_config.json:
{
  "mcpServers": {
    "protected-shell": {
      "command": "python3",
      "args": ["/path/to/mcp_firewall.py", "--", "npx", "-y", "@modelcontextprotocol/server-everything"]
    }
  }
}
"""

import sys
import os
import json
import subprocess
import threading
import time
from typing import Dict, Any, List, Optional

# Ensure local modules can be imported
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from guardrail import JevDecisionEngine, DecisionAction
from local_slm_guardrail import AirGappedCascadeEngine
from alerts import AlertNotifier, BOLD, RED, GREEN, CYAN, RESET


class MCPFirewallProxy:
    def __init__(
        self,
        target_command: List[str],
        log_file: str = "mcp_firewall_audit.log",
        engine: Optional[Any] = None
    ):
        self.target_command = target_command
        self.engine = engine or JevDecisionEngine()
        self.notifier = AlertNotifier(log_file=log_file, output_stream=sys.stderr)
        self.process = None

    def start_target(self):
        """Start the target MCP server subprocess."""
        self.process = subprocess.Popen(
            self.target_command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=sys.stderr,
            text=True,
            bufsize=1
        )

        # Thread to relay target's stdout back to client
        t = threading.Thread(target=self._relay_target_stdout, daemon=True)
        t.start()

    def _relay_target_stdout(self):
        """Relay response lines from target server to client stdout."""
        try:
            for line in self.process.stdout:
                sys.stdout.write(line)
                sys.stdout.flush()
        except (IOError, BrokenPipeError):
            pass

    def run(self):
        """Main loop: Read client requests from stdin, intercept tools/call."""
        self.start_target()

        try:
            for line in sys.stdin:
                line = line.strip()
                if not line:
                    continue

                try:
                    req = json.loads(line)
                except json.JSONDecodeError:
                    # Forward non-JSON lines directly
                    self._forward_to_target(line)
                    continue

                method = req.get("method")
                req_id = req.get("id")

                # Intercept MCP Tool Calls
                if method == "tools/call":
                    params = req.get("params", {})
                    tool_name = params.get("name", "unknown")
                    args = params.get("arguments", {})

                    # Extract target string to evaluate (e.g. command, query, path)
                    inspect_target = self._extract_payload(args)

                    # Dynamic System 1 Decision
                    decision = self.engine.evaluate(inspect_target, context={"tool": tool_name})

                    if decision.action == DecisionAction.BLOCK:
                        # 🚨 Blocked! Do NOT forward to target server.
                        self.notifier.emit_alert(
                            command=f"[{tool_name}] {inspect_target}",
                            decision=decision.to_dict(),
                            caller_context={"source": "MCP_CLIENT", "tool": tool_name}
                        )

                        # Return standard MCP tool execution error
                        blocked_response = {
                            "jsonrpc": "2.0",
                            "id": req_id,
                            "result": {
                                "content": [
                                    {
                                        "type": "text",
                                        "text": (
                                            f"🛑 [MCP FIREWALL BLOCKED]\n"
                                            f"Reason   : {decision.reason}\n"
                                            f"Category : {decision.risk_category.value}\n"
                                            f"Confidence: {decision.confidence * 100:.1f}%\n"
                                            f"Latency  : {decision.latency_ms} ms (System 1 Gate)\n"
                                            f"Action   : Execution rejected before reaching MCP Server."
                                        )
                                    }
                                ],
                                "isError": True
                            }
                        }
                        sys.stdout.write(json.dumps(blocked_response) + "\n")
                        sys.stdout.flush()
                        continue

                    elif decision.action == DecisionAction.ESCALATE:
                        # Notify escalation warning, then forward
                        self.notifier.emit_alert(
                            command=f"[{tool_name}] {inspect_target}",
                            decision=decision.to_dict(),
                            caller_context={"source": "MCP_CLIENT", "tool": tool_name}
                        )

                # Safe or non-tool call -> Forward to target server
                self._forward_to_target(line)

        except (KeyboardInterrupt, BrokenPipeError):
            pass
        finally:
            if self.process:
                self.process.terminate()

    def _extract_payload(self, args: Dict[str, Any]) -> str:
        """Extract the most sensitive string payload from tool arguments."""
        for key in ["command", "cmd", "query", "sql", "path", "url", "code"]:
            if key in args and isinstance(args[key], str):
                return args[key]
        return json.dumps(args)

    def _forward_to_target(self, line: str):
        if self.process and self.process.stdin:
            self.process.stdin.write(line + "\n")
            self.process.stdin.flush()


def main():
    if len(sys.argv) < 2 or "--" not in sys.argv:
        print(f"Usage: {sys.argv[0]} [--air-gapped | --local-slm] -- <target_mcp_command> [args...]", file=sys.stderr)
        print("Example: python3 mcp_firewall.py --air-gapped -- python3 mock_mcp_server.py", file=sys.stderr)
        sys.exit(1)

    delimiter_idx = sys.argv.index("--")
    flags = sys.argv[1:delimiter_idx]
    target_command = sys.argv[delimiter_idx + 1:]

    if not target_command:
        print("Error: No target command specified after '--'", file=sys.stderr)
        sys.exit(1)

    # Configure engine
    if "--air-gapped" in flags or "--local-slm" in flags:
        engine = AirGappedCascadeEngine()
    else:
        engine = JevDecisionEngine()

    proxy = MCPFirewallProxy(target_command, engine=engine)
    proxy.run()


if __name__ == "__main__":
    main()
