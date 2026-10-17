#!/usr/bin/env python3
"""
alerts.py - Automated Alerting and Audit Dispatcher for Guardrail Decisions
"""

import json
import os
import sys
from datetime import datetime, timezone
from typing import Dict, Any, Optional

# ANSI Color codes for clean terminal output
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"


class AlertNotifier:
    """
    Handles automated alerting when dynamic guardrails block or escalate actions.
    Supports console formatting, JSON audit logging, and webhook mocks.
    """

    def __init__(self, log_file: Optional[str] = "guardrail_audit.log"):
        self.log_file = log_file

    def emit_alert(self, command: str, decision: Dict[str, Any], caller_context: Optional[Dict[str, Any]] = None):
        """Dispatch high-priority alert notification."""
        timestamp = datetime.now(timezone.utc).isoformat()
        alert_payload = {
            "timestamp": timestamp,
            "event": "GUARDRAIL_INTERCEPTION",
            "action": decision.get("action"),
            "risk_category": decision.get("risk_category"),
            "confidence": decision.get("confidence"),
            "reason": decision.get("reason"),
            "latency_ms": decision.get("latency_ms"),
            "blocked_command": command,
            "caller": caller_context or {"agent_id": "ai-assistant-01", "role": "developer"}
        }

        # 1. Print formatted alert banner
        action = decision.get("action")
        if action == "BLOCK":
            print(f"\n{BOLD}{RED}🚨 [SECURITY ALERT: COMMAND BLOCKED]{RESET}")
            print(f"{RED}├─ Reason      : {decision.get('reason')}{RESET}")
            print(f"{RED}├─ Category    : {decision.get('risk_category')}{RESET}")
            print(f"{RED}├─ Confidence  : {decision.get('confidence') * 100:.1f}%{RESET}")
            print(f"{RED}├─ Latency     : {decision.get('latency_ms')} ms (System 1 Instant Decision){RESET}")
            print(f"{RED}└─ Command     : `{command}`{RESET}\n")
        elif action == "ESCALATE":
            print(f"\n{BOLD}{YELLOW}⚠️  [SECURITY WARNING: HUMAN REVIEW REQUIRED]{RESET}")
            print(f"{YELLOW}├─ Reason      : {decision.get('reason')}{RESET}")
            print(f"{YELLOW}├─ Confidence  : {decision.get('confidence') * 100:.1f}%{RESET}")
            print(f"{YELLOW}└─ Command     : `{command}`{RESET}\n")

        # 2. Append to audit log
        if self.log_file:
            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(alert_payload, ensure_ascii=False) + "\n")
