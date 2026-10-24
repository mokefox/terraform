#!/usr/bin/env python3
"""
test_alerts_slack.py - Unit and Integration Tests for Slack SOAR Alerting
"""

import json
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
import unittest
from alerts import AlertNotifier


class MockSlackWebhookHandler(BaseHTTPRequestHandler):
    received_payloads = []

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        post_data = self.rfile.read(content_length)
        payload = json.loads(post_data.decode("utf-8"))
        MockSlackWebhookHandler.received_payloads.append(payload)

        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, format, *args):
        # Suppress server output during test
        pass


class TestSlackAlerting(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        MockSlackWebhookHandler.received_payloads.clear()
        cls.server = HTTPServer(("127.0.0.1", 18888), MockSlackWebhookHandler)
        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def test_block_kit_payload_structure(self):
        notifier = AlertNotifier(slack_webhook_url="http://127.0.0.1:18888/mock-webhook")

        decision = {
            "action": "BLOCK",
            "risk_category": "DESTRUCTIVE_COMMAND",
            "confidence": 0.99,
            "reason": "Recursive forceful deletion detected",
            "latency_ms": 0.005
        }
        caller = {"agent_id": "claude-code-worker-01", "role": "sre"}

        # Emit alert
        notifier.emit_alert("rm -rf / --no-preserve-root", decision, caller)

        self.assertEqual(len(MockSlackWebhookHandler.received_payloads), 1)
        sent = MockSlackWebhookHandler.received_payloads[0]

        # Verify Block Kit structure
        self.assertIn("blocks", sent)
        blocks = sent["blocks"]
        self.assertEqual(blocks[0]["type"], "header")
        self.assertIn("INTERCEPTED & BLOCKED", blocks[0]["text"]["text"])

        # Verify fields
        fields_text = json.dumps(blocks[1]["fields"])
        self.assertIn("DESTRUCTIVE_COMMAND", fields_text)
        self.assertIn("99.0%", fields_text)

        # Verify command section
        section_text = blocks[2]["text"]["text"]
        self.assertIn("rm -rf / --no-preserve-root", section_text)
        self.assertIn("Recursive forceful deletion detected", section_text)


if __name__ == "__main__":
    unittest.main()
