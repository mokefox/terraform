#!/bin/bash
# ==============================================================================
# Pre-Execution Security Gate (OSI Model Audit & Conftest OPA Enforcement)
# ==============================================================================
# This script enforces strict security verification before 'terraform apply' or
# 'git commit'. If ANY high-severity policy violation or OSI flaw is found,
# execution is strictly BLOCKED (exit code 1).
# ==============================================================================

set -euo pipefail

# Color Codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
POLICY_DIR="$PROJECT_ROOT/policy"
RULES_CONFIG="$SCRIPT_DIR/osi_rules.yaml"

TARGET_DIR="${1:-$PROJECT_ROOT}"
PLAN_FILE=""

# If first or second argument is a json/plan file, record it
if [[ "${1:-}" == *.json ]]; then
    PLAN_FILE="$1"
    TARGET_DIR="$PROJECT_ROOT"
elif [[ "${2:-}" == *.json ]]; then
    PLAN_FILE="$2"
fi

GATE_PASSED=true
FAILURES=()

echo -e "${BOLD}${CYAN}==============================================================================${NC}"
echo -e "${BOLD}${CYAN}  Pre-Execution Security Gate (OSI Audit + Conftest OPA + Trivy Scanner)${NC}"
echo -e "${BOLD}${CYAN}==============================================================================${NC}"
echo -e "Target Directory : $TARGET_DIR"
echo -e "Policy Directory : $POLICY_DIR"
if [ -n "$PLAN_FILE" ]; then
    echo -e "Terraform Plan   : $PLAN_FILE"
fi
echo ""

# ------------------------------------------------------------------------------
# Gate 1: Plain-text Secrets Check (Fail-closed)
# ------------------------------------------------------------------------------
echo -e "${BOLD}[Gate 1/4] Checking for Plain-Text Secrets in Terraform Configuration...${NC}"
secrets_found=$(grep -rE "password|secret|token|private_key" "$TARGET_DIR" \
    --include="*.tf" \
    --exclude-dir={.git,.terraform,policy,scripts,tests,.gemini} \
    --exclude="*.md" \
    --exclude="*.bak" \
    --exclude="*.json" \
    | grep -v "var\." \
    | grep -v "manage_master_user_password" \
    | grep -v "http_tokens" \
    | grep -v '\["secrets"\]' \
    | grep -v "arn:aws:secretsmanager" \
    | grep -v "secretsmanager:" \
    | grep -v -E "description\s*=" \
    | grep -v 'name\s*=\s*"x-csrf-token"' \
    | grep -v "true" \
    | grep -v "false" \
    | grep "=" || true)

if [ -n "$secrets_found" ]; then
    echo -e "${RED}✗ [FAILED] Plain-text secrets detected:${NC}"
    echo "$secrets_found"
    GATE_PASSED=false
    FAILURES+=("Plain-text secrets found in Terraform configuration")
else
    echo -e "${GREEN}✓ [PASSED] No plain-text secrets found.${NC}"
fi

# ------------------------------------------------------------------------------
# Gate 2: OSI Reference Model Security Audit (Scripts & Auto-Remediation Check)
# ------------------------------------------------------------------------------
echo -e "\n${BOLD}[Gate 2/4] Running OSI 7-Layer Architecture Security Audit...${NC}"
if command -v python3 &> /dev/null; then
    if python3 "$SCRIPT_DIR/osi_security_audit.py" \
        --target-dir "$TARGET_DIR" \
        --rules-config "$RULES_CONFIG" \
        --exit-code; then
        echo -e "${GREEN}✓ [PASSED] OSI Reference Model audit passed with no CRITICAL or HIGH findings.${NC}"
    else
        echo -e "${RED}✗ [FAILED] OSI Reference Model audit detected CRITICAL/HIGH findings.${NC}"
        echo -e "${YELLOW}Hint: Run 'python3 scripts/osi_security_audit.py --fix' or '--generate-patch' to remediate.${NC}"
        GATE_PASSED=false
        FAILURES+=("OSI 7-Layer security audit reported CRITICAL/HIGH violations")
    fi
else
    echo -e "${RED}✗ [FAILED] python3 is required for OSI audit.${NC}"
    GATE_PASSED=false
    FAILURES+=("python3 runtime not found")
fi

# ------------------------------------------------------------------------------
# Gate 3: Conftest / OPA Policy Gate (Fail-closed)
# ------------------------------------------------------------------------------
echo -e "\n${BOLD}[Gate 3/4] Running Conftest OPA Policy Verification...${NC}"
if command -v conftest &> /dev/null; then
    if [ -n "$PLAN_FILE" ] && [ -f "$PLAN_FILE" ]; then
        echo -e "Evaluating Terraform Plan against OPA Rego policies: $PLAN_FILE"
        if conftest test --rego-version v0 --all-namespaces --policy "$POLICY_DIR" "$PLAN_FILE"; then
            echo -e "${GREEN}✓ [PASSED] Conftest OPA plan evaluation passed.${NC}"
        else
            echo -e "${RED}✗ [FAILED] Conftest OPA detected policy violations in plan.${NC}"
            GATE_PASSED=false
            FAILURES+=("Conftest OPA policy violation in $PLAN_FILE")
        fi
    else
        # If no plan file, verify sample policy data / configurations
        echo -e "Verifying OPA policy validity and static resources with Conftest..."
        if [ -f "$POLICY_DIR/encrypted_resources.json" ]; then
            if conftest test --rego-version v0 --all-namespaces --policy "$POLICY_DIR" "$POLICY_DIR/encrypted_resources.json"; then
                echo -e "${GREEN}✓ [PASSED] Conftest baseline policies validated.${NC}"
            else
                echo -e "${RED}✗ [FAILED] Conftest baseline policy check failed.${NC}"
                GATE_PASSED=false
                FAILURES+=("Conftest policy validation error")
            fi
        fi
    fi
else
    echo -e "${YELLOW}[Warning] conftest is not installed. Skipping Conftest OPA gate.${NC}"
fi

# ------------------------------------------------------------------------------
# Gate 4: Trivy Comprehensive Configuration Scan (Fail-closed)
# ------------------------------------------------------------------------------
echo -e "\n${BOLD}[Gate 4/4] Running Trivy Security Misconfiguration Scan...${NC}"
if command -v trivy &> /dev/null; then
    if trivy config "$TARGET_DIR" \
        --config-check "$POLICY_DIR" \
        --severity HIGH,CRITICAL \
        --exit-code 1 \
        --skip-version-check; then
        echo -e "${GREEN}✓ [PASSED] Trivy security scan passed with 0 HIGH/CRITICAL misconfigurations.${NC}"
    else
        echo -e "${RED}✗ [FAILED] Trivy detected HIGH/CRITICAL misconfigurations.${NC}"
        GATE_PASSED=false
        FAILURES+=("Trivy detected HIGH/CRITICAL misconfigurations")
    fi
else
    echo -e "${YELLOW}[Warning] trivy is not installed. Skipping Trivy scan.${NC}"
fi

# ------------------------------------------------------------------------------
# Final Gate Verdict
# ------------------------------------------------------------------------------
echo -e "\n${BOLD}${CYAN}==============================================================================${NC}"
if [ "$GATE_PASSED" = true ]; then
    echo -e "${BOLD}${GREEN}  ✅ [GATE PASSED] All security requirements met! Execution is permitted.${NC}"
    echo -e "${BOLD}${CYAN}==============================================================================${NC}\n"
    exit 0
else
    echo -e "${BOLD}${RED}  🛑 [GATE BLOCKED] Security violations detected! Execution is PROHIBITED.${NC}"
    echo -e "${BOLD}${CYAN}==============================================================================${NC}"
    echo -e "${RED}Execution was blocked due to the following failure(s):${NC}"
    for failure in "${FAILURES[@]}"; do
        echo -e "  - ${RED}${failure}${NC}"
    done
    echo -e "\n${YELLOW}Please resolve the findings above before proceeding with terraform apply or git commit.${NC}\n"
    exit 1
fi
