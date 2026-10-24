#!/usr/bin/env python3
"""
alerts.py - Automated Alerting and Audit Dispatcher for Guardrail Decisions
Supports terminal output, JSON audit logging, and Slack Block Kit webhook notifications.
"""

import json
import os
import sys
import urllib.request
import urllib.error
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
    Supports console formatting, JSON audit logging, and Slack Block Kit webhook notifications.
    """

    def __init__(
        self,
        log_file: Optional[str] = "guardrail_audit.log",
        output_stream=None,
        slack_webhook_url: Optional[str] = None
    ):
        self.log_file = log_file
        self.stream = output_stream or sys.stdout
        self.slack_webhook_url = slack_webhook_url or os.getenv("SLACK_WEBHOOK_URL")

    def build_slack_block_kit(self, alert_payload: Dict[str, Any]) -> Dict[str, Any]:
        """Construct a structured Slack Block Kit message payload."""
        action = alert_payload.get("action", "UNKNOWN")
        reason = alert_payload.get("reason", "No reason provided")
        category = alert_payload.get("risk_category", "UNKNOWN")
        confidence = alert_payload.get("confidence", 0.0) * 100.0
        latency = alert_payload.get("latency_ms", 0.0)
        command = alert_payload.get("blocked_command", "")
        caller = alert_payload.get("caller", {})
        agent_id = caller.get("agent_id", "ai-assistant")
        timestamp = alert_payload.get("timestamp", datetime.now(timezone.utc).isoformat())

        # Status icon and color
        if action == "BLOCK":
            title_emoji = "🚨"
            status_text = "INTERCEPTED & BLOCKED"
        elif action == "ESCALATE":
            title_emoji = "⚠️"
            status_text = "HUMAN CONFIRMATION REQUIRED"
        else:
            title_emoji = "ℹ️"
            status_text = "AUDIT NOTICE"

        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"{title_emoji} [SOAR Alert] AI Guardrail: {status_text}",
                    "emoji": True
                }
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Action:*\n`{action}`"},
                    {"type": "mrkdwn", "text": f"*Category:*\n`{category}`"},
                    {"type": "mrkdwn", "text": f"*Confidence:*\n{confidence:.1f}%"},
                    {"type": "mrkdwn", "text": f"*Decision Latency:*\n{latency:.3f} ms"}
                ]
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Reason:*\n> {reason}\n\n*Target Command:*\n```{command}```"
                }
            },
            {
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": f"👤 *Agent:* `{agent_id}` | ⏱ *Timestamp:* `{timestamp}` | 🛡️ *Engine:* `Jev System 1`"
                    }
                ]
            }
        ]

        return {"blocks": blocks}

    def send_slack_notification(self, alert_payload: Dict[str, Any]) -> bool:
        """Send formatted Block Kit alert to Slack webhook."""
        if not self.slack_webhook_url:
            return False

        payload = self.build_slack_block_kit(alert_payload)
        data = json.dumps(payload).encode("utf-8")

        req = urllib.request.Request(
            self.slack_webhook_url,
            data=data,
            headers={"Content-Type": "application/json"}
        )

        try:
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                return resp.status == 200
        except Exception as e:
            # Never let alerting failures break the main application execution
            print(f"{YELLOW}[WARN] Failed to send Slack alert: {e}{RESET}", file=self.stream)
            return False

    def emit_alert(self, command: str, decision: Dict[str, Any], caller_context: Optional[Dict[str, Any]] = None):
        """Dispatch high-priority alert notification across all configured channels."""
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

        # 1. Print formatted alert banner to configured stream (e.g. stderr for MCP)
        action = decision.get("action")
        if action == "BLOCK":
            print(f"\n{BOLD}{RED}🚨 [SECURITY ALERT: COMMAND BLOCKED]{RESET}", file=self.stream)
            print(f"{RED}├─ Reason      : {decision.get('reason')}{RESET}", file=self.stream)
            print(f"{RED}├─ Category    : {decision.get('risk_category')}{RESET}", file=self.stream)
            print(f"{RED}├─ Confidence  : {decision.get('confidence') * 100:.1f}%{RESET}", file=self.stream)
            print(f"{RED}├─ Latency     : {decision.get('latency_ms')} ms (System 1 Instant Decision){RESET}", file=self.stream)
            print(f"{RED}└─ Command     : `{command}`{RESET}\n", file=self.stream)
        elif action == "ESCALATE":
            print(f"\n{BOLD}{YELLOW}⚠️  [SECURITY WARNING: HUMAN REVIEW REQUIRED]{RESET}", file=self.stream)
            print(f"{YELLOW}├─ Reason      : {decision.get('reason')}{RESET}", file=self.stream)
            print(f"{YELLOW}├─ Confidence  : {decision.get('confidence') * 100:.1f}%{RESET}", file=self.stream)
            print(f"{YELLOW}└─ Command     : `{command}`{RESET}\n", file=self.stream)

        # 2. Append to audit log
        if self.log_file:
            try:
                with open(self.log_file, "a", encoding="utf-8") as f:
                    f.write(json.dumps(alert_payload, ensure_ascii=False) + "\n")
            except Exception as e:
                print(f"{YELLOW}[WARN] Failed to write audit log: {e}{RESET}", file=self.stream)

        # 3. Dispatch to Slack Webhook (if configured)
        if self.slack_webhook_url:
            self.send_slack_notification(alert_payload)
