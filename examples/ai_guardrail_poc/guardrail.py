#!/usr/bin/env python3
"""
guardrail.py - Jev-inspired System 1 Dynamic Decision Engine for AI Security

Characteristics:
- No text generation: Returns strictly typed, structured decisions.
- Ultra-low latency: Evaluates intent in milliseconds.
- Deterministic schema: Safe for automated execution interceptors.
"""

from dataclasses import dataclass, asdict
from enum import Enum
import re
import time
from typing import Optional, Dict, Any, List


class DecisionAction(str, Enum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    ESCALATE = "ESCALATE"  # Needs human confirmation


class RiskCategory(str, Enum):
    SAFE = "SAFE"
    DESTRUCTIVE_COMMAND = "DESTRUCTIVE_COMMAND"
    DATA_EXFILTRATION = "DATA_EXFILTRATION"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    UNAUTHORIZED_NETWORK = "UNAUTHORIZED_NETWORK"
    PROMPT_INJECTION = "PROMPT_INJECTION"


@dataclass(frozen=True)
class GuardrailDecision:
    action: DecisionAction
    risk_category: RiskCategory
    confidence: float
    reason: str
    latency_ms: float
    metadata: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["action"] = self.action.value
        data["risk_category"] = self.risk_category.value
        return data


class JevDecisionEngine:
    """
    System 1 Model Emulator / Interceptor
    Implements fast semantic classification without unbounded LLM text generation.
    """

    def __init__(self, sensitivity: float = 0.8):
        self.sensitivity = sensitivity
        self._compile_patterns()

    def _compile_patterns(self):
        # Destructive OS commands
        self.destructive_patterns = [
            (re.compile(r"\brm\s+-(?:r[fF]|f[rR]|rf)\b"), "Recursive forceful deletion detected"),
            (re.compile(r"\bmkfs\b|\bfdisk\b|\bdd\s+if="), "Disk / partition modification detected"),
            (re.compile(r">\s*/dev/(?:sda|nvme|null)"), "Direct raw device overwriting"),
            (re.compile(r"\bshutdown\b|\breboot\b|\binit\s+0\b"), "System shutdown/reboot command"),
            (re.compile(r"\b(DROP|TRUNCATE)\s+(TABLE|DATABASE)\b", re.IGNORECASE), "Destructive database operation"),
            (re.compile(r":\(\)\{\s*:\|:&\s*\};:"), "Fork bomb pattern"),
        ]

        # Data exfiltration
        self.exfiltration_patterns = [
            (re.compile(r"\bcurl\b.*-d\s+@(?:/etc/passwd|/etc/shadow|\.env|id_rsa)", re.IGNORECASE), "Credential exfiltration via curl"),
            (re.compile(r"\bwget\b.*--post-file=(?:/etc/passwd|\.env|id_rsa)", re.IGNORECASE), "Credential exfiltration via wget"),
            (re.compile(r"\b(cat|base64)\s+.*(\.aws/credentials|\.env|id_rsa|id_ed25519)"), "Reading sensitive credential files"),
        ]

        # Privilege escalation
        self.privesc_patterns = [
            (re.compile(r"\bsudo\s+(?:su|bash|sh|zsh)\b"), "Interactive root shell acquisition"),
            (re.compile(r"\bchmod\s+(?:[0-7]*777|[uugoa\+]*s)\b"), "Insecure permission or SUID elevation"),
        ]

        # Prompt injection / Obfuscation bypass
        self.injection_patterns = [
            (re.compile(r"\bbase64\s+-d\s*\|\s*(?:sh|bash)\b"), "Obfuscated payload execution via base64 pipe"),
            (re.compile(r"ignore\s+(?:previous|all)\s+instructions", re.IGNORECASE), "Direct prompt injection attempt"),
        ]

        # Commands that need human review (ESCALATE)
        self.escalate_patterns = [
            (re.compile(r"\bgit\s+push\s+.*--force\b"), "Force push may overwrite remote history"),
            (re.compile(r"\bterraform\s+destroy\b"), "Infrastructure destruction request"),
            (re.compile(r"\bkill\s+-9\b"), "Forceful process termination"),
        ]

    def evaluate(self, command: str, context: Optional[Dict[str, Any]] = None) -> GuardrailDecision:
        """
        Evaluate an incoming command / agent action in milliseconds.
        Returns a strongly-typed GuardrailDecision.
        """
        start_time = time.perf_counter()
        clean_cmd = command.strip()

        # 1. Check Destructive Commands
        for pattern, reason in self.destructive_patterns:
            if pattern.search(clean_cmd):
                latency = (time.perf_counter() - start_time) * 1000.0
                return GuardrailDecision(
                    action=DecisionAction.BLOCK,
                    risk_category=RiskCategory.DESTRUCTIVE_COMMAND,
                    confidence=0.99,
                    reason=reason,
                    latency_ms=round(latency, 3),
                    metadata={"matched_pattern": pattern.pattern}
                )

        # 2. Check Data Exfiltration
        for pattern, reason in self.exfiltration_patterns:
            if pattern.search(clean_cmd):
                latency = (time.perf_counter() - start_time) * 1000.0
                return GuardrailDecision(
                    action=DecisionAction.BLOCK,
                    risk_category=RiskCategory.DATA_EXFILTRATION,
                    confidence=0.95,
                    reason=reason,
                    latency_ms=round(latency, 3),
                    metadata={"matched_pattern": pattern.pattern}
                )

        # 3. Check Privilege Escalation
        for pattern, reason in self.privesc_patterns:
            if pattern.search(clean_cmd):
                latency = (time.perf_counter() - start_time) * 1000.0
                return GuardrailDecision(
                    action=DecisionAction.BLOCK,
                    risk_category=RiskCategory.PRIVILEGE_ESCALATION,
                    confidence=0.92,
                    reason=reason,
                    latency_ms=round(latency, 3),
                    metadata={"matched_pattern": pattern.pattern}
                )

        # 4. Check Injection / Obfuscation
        for pattern, reason in self.injection_patterns:
            if pattern.search(clean_cmd):
                latency = (time.perf_counter() - start_time) * 1000.0
                return GuardrailDecision(
                    action=DecisionAction.BLOCK,
                    risk_category=RiskCategory.PROMPT_INJECTION,
                    confidence=0.90,
                    reason=reason,
                    latency_ms=round(latency, 3),
                    metadata={"matched_pattern": pattern.pattern}
                )

        # 5. Check Escalation (Needs Human Confirmation)
        for pattern, reason in self.escalate_patterns:
            if pattern.search(clean_cmd):
                latency = (time.perf_counter() - start_time) * 1000.0
                return GuardrailDecision(
                    action=DecisionAction.ESCALATE,
                    risk_category=RiskCategory.DESTRUCTIVE_COMMAND,
                    confidence=0.85,
                    reason=reason,
                    latency_ms=round(latency, 3),
                    metadata={"matched_pattern": pattern.pattern}
                )

        # Default: ALLOW
        latency = (time.perf_counter() - start_time) * 1000.0
        return GuardrailDecision(
            action=DecisionAction.ALLOW,
            risk_category=RiskCategory.SAFE,
            confidence=0.98,
            reason="No known hazard patterns identified",
            latency_ms=round(latency, 3),
            metadata={}
        )
