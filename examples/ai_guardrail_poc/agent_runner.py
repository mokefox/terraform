#!/usr/bin/env python3
"""
agent_runner.py - Protected Execution Interceptor for AI Agents
Demonstrates dynamic interception with Defense-in-Depth fallback.
"""

import subprocess
from typing import Dict, Any, Optional
from guardrail import JevDecisionEngine, DecisionAction
from alerts import AlertNotifier


class GuardrailBlockedException(Exception):
    """Raised when an action is blocked by the dynamic security guardrail."""
    pass


class SafeAgentRunner:
    """
    Simulates an AI Agent runtime environment equipped with a Jev-style Guardrail Interceptor.
    """

    def __init__(self, guardrail_engine: Optional[JevDecisionEngine] = None, notifier: Optional[AlertNotifier] = None):
        self.engine = guardrail_engine or JevDecisionEngine()
        self.notifier = notifier or AlertNotifier()

    def execute_tool(self, tool_name: str, command: str, caller_context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Intercept tool call execution before it reaches the OS / backend.
        """
        print(f"🤖 [Agent Request] Executing `{tool_name}`: \"{command}\"")

        # 1. System 1 Dynamic Evaluation (Interceptor)
        decision = self.engine.evaluate(command, context=caller_context)

        # 2. Enforcement based on Typed Decision
        if decision.action == DecisionAction.BLOCK:
            self.notifier.emit_alert(command, decision.to_dict(), caller_context)
            raise GuardrailBlockedException(f"Action blocked by Guardrail: {decision.reason}")

        elif decision.action == DecisionAction.ESCALATE:
            self.notifier.emit_alert(command, decision.to_dict(), caller_context)
            return {
                "status": "ESCALATED",
                "message": f"Action requires human approval: {decision.reason}",
                "decision": decision.to_dict()
            }

        # 3. If ALLOWed, execute in constrained environment
        print(f"  ↳ ✅ Decision: {decision.action.value} ({decision.confidence * 100:.1f}%) in {decision.latency_ms} ms")
        return {
            "status": "SUCCESS",
            "executed": True,
            "command": command,
            "decision": decision.to_dict()
        }
