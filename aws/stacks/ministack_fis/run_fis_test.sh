#!/usr/bin/env bash
# -------------------------------------------------------------
# run_fis_test.sh – repeatable FIS + Floci test for article data
# -------------------------------------------------------------
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TF_OUTPUT="${SCRIPT_DIR}/tf-output.json"
CSV="${SCRIPT_DIR}/article_assets/fis_rto_data.csv"
LOG_DIR="${SCRIPT_DIR}/article_assets/screenshots"
mkdir -p "$(dirname "$CSV")" "$LOG_DIR"

# -----------------------------------------------------------------
# 1️⃣  Load the experiment ID (must exist, otherwise abort)
# -----------------------------------------------------------------
EXP_ID=$(jq -r '.fis_experiment_task_stop_id.value' "$TF_OUTPUT")
if [[ -z "$EXP_ID" || "$EXP_ID" == "null" ]]; then
  echo "❌ No experiment ID – did you enable_fis & apply?"
  exit 1
fi

# -----------------------------------------------------------------
# 2️⃣  Generate a unique run identifier (timestamp)
# -----------------------------------------------------------------
RUN_ID=$(date -u +"%Y%m%dT%H%M%SZ")
START_TIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
LOG_FILE="${LOG_DIR}/floci_${RUN_ID}.log"

echo "▶️  [$RUN_ID] Starting experiment $EXP_ID (UTC $START_TIME)" | tee -a "$LOG_FILE"

# -----------------------------------------------------------------
# 3️⃣  Kick off the fault (Floci runs in background)
# -----------------------------------------------------------------
floci start --experiment-id "$EXP_ID" 2>&1 | tee -a "$LOG_FILE" &
FLOCI_PID=$!
# give the fault a couple of seconds to be injected
sleep 12

# -----------------------------------------------------------------
# 4️⃣  Poll ECS until service recovers (runningCount == desiredCount)
# -----------------------------------------------------------------
CLUSTER=$(terraform output -raw ecs_cluster_name)
SERVICE=$(terraform output -raw ecs_service_name)

while :; do
  RUNNING=$(aws ecs describe-services \
    --cluster "$CLUSTER" \
    --services "$SERVICE" \
    --query "services[0].runningCount" \
    --output text)

  DESIRED=$(aws ecs describe-services \
    --cluster "$CLUSTER" \
    --services "$SERVICE" \
    --query "services[0].desiredCount" \
    --output text)

  if [[ "$RUNNING" -eq "$DESIRED" ]]; then
    END_TIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    echo "✅ Service recovered at $END_TIME" | tee -a "$LOG_FILE"
    break
  fi
  sleep 5
done

# -----------------------------------------------------------------
# 5️⃣  Compute RTO (seconds) and append to CSV
# -----------------------------------------------------------------
RTO=$(python3 - <<PY
from datetime import datetime
s = datetime.strptime("$START_TIME", "%Y-%m-%dT%H:%M:%SZ")
e = datetime.strptime("$END_TIME",   "%Y-%m-%dT%H:%M:%SZ")
print(int((e - s).total_seconds()))
PY
)

echo "⏱️ RTO = $RTO seconds" | tee -a "$LOG_FILE"

# CSV header on first run
[[ -f "$CSV" ]] || echo "run_id,start_utc,end_utc,rto_seconds" > "$CSV"
echo "${RUN_ID},${START_TIME},${END_TIME},${RTO}" >> "$CSV"

# -----------------------------------------------------------------
# 6️⃣  Clean up Floci (normally it exits on its own)
# -----------------------------------------------------------------
wait "$FLOCI_PID" 2>/dev/null || true
echo "📁 Log saved to $LOG_FILE"
echo "📊 CSV row added to $CSV"
