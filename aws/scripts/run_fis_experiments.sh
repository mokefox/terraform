#!/usr/bin/env bash

# ------------------------------------------------------------
# run_fis_experiments.sh
# ------------------------------------------------------------
# This script performs the three actions described in the previous
# assistant message:
#   1. Verify full Terraform deployment (terraform plan).
#   2. Optionally enable FIS resources (for real AWS) and apply.
#   3. Run FIS experiments, collect CloudWatch logs, compute RTO/RPO,
#      and generate a markdown table (rto_rpo_results.md).
# ------------------------------------------------------------

set -euo pipefail

# ----- Configurable variables --------------------------------
# Set to "true" to create FIS resources (required for real AWS).
# For local Ministack use "false" (default). Can be overridden via
# environment variable ENABLE_FIS.
ENABLE_FIS="${ENABLE_FIS:-false}"

# If you are targeting real AWS, comment out the LOCALSTACK_ENDPOINT and
# the corresponding "--endpoint-url" options below.
LOCALSTACK_ENDPOINT="http://localhost:4566"

# Log group where FIS writes its experiment logs (LocalStack mimics this).
LOG_GROUP="/aws/fis/experiment"

# Output markdown file
OUTPUT_MD="rto_rpo_results.md"

# ------------------------------------------------------------
# Helper functions
# ------------------------------------------------------------
log() { echo "[$(date +%H:%M:%S)] $*"; }

run_terraform_plan() {
  log "Running terraform plan..."
  terraform plan -out=tfplan.out
  log "Terraform plan succeeded."
}

apply_terraform() {
  if [[ "$ENABLE_FIS" == "true" ]]; then
    log "Applying with FIS enabled..."
    terraform apply -var='enable_fis=true' -auto-approve
  else
    log "Applying without FIS (default for Ministack)..."
    terraform apply -auto-approve
  fi
}

# Returns the experiment template ID for a given name.
get_experiment_id() {
  local name=$1
  terraform output -raw "${name}_id"
}

start_experiment() {
  local tmpl_id=$1
  log "Starting experiment template $tmpl_id"
  if [[ -n "$LOCALSTACK_ENDPOINT" ]]; then
    EXP_JSON=$(aws --endpoint-url "$LOCALSTACK_ENDPOINT" fis start-experiment \
      --experiment-template-id "$tmpl_id" \
      --query '{id: experiment.id, start: experiment.startTime}' \
      --output json)
  else
    EXP_JSON=$(aws fis start-experiment \
      --experiment-template-id "$tmpl_id" \
      --query '{id: experiment.id, start: experiment.startTime}' \
      --output json)
  fi
  echo "$EXP_JSON" | jq -r '.id, .start'
}

wait_experiment_complete() {
  local exp_id=$1
  log "Waiting for experiment $exp_id to complete..."
  while true; do
    if [[ -n "$LOCALSTACK_ENDPOINT" ]]; then
      STATUS=$(aws --endpoint-url "$LOCALSTACK_ENDPOINT" fis get-experiment --id "$exp_id" \
        --query 'experiment.state' --output text)
    else
      STATUS=$(aws fis get-experiment --id "$exp_id" \
        --query 'experiment.state' --output text)
    fi
    if [[ "$STATUS" != "RUNNING" ]]; then
      log "Experiment $exp_id finished with state $STATUS"
      break
    fi
    sleep 5
  done
}

fetch_log_times() {
  local exp_id=$1
  # The log stream name for a given experiment is usually the experiment ID.
  # Adjust if your environment uses a different naming scheme.
  if [[ -n "$LOCALSTACK_ENDPOINT" ]]; then
    LOG_EVENTS=$(aws --endpoint-url "$LOCALSTACK_ENDPOINT" logs get-log-events \
      --log-group-name "$LOG_GROUP" \
      --log-stream-name "$exp_id" \
      --limit 1000 \
      --output json)
  else
    LOG_EVENTS=$(aws logs get-log-events \
      --log-group-name "$LOG_GROUP" \
      --log-stream-name "$exp_id" \
      --limit 1000 \
      --output json)
  fi
  # Extract earliest and latest timestamps (in milliseconds since epoch)
  START_MS=$(echo "$LOG_EVENTS" | jq '[.events[].timestamp] | min')
  END_MS=$(echo "$LOG_EVENTS" | jq '[.events[].timestamp] | max')
  echo "$START_MS $END_MS"
}

ms_to_seconds() { echo $(( $1 / 1000 )); }

generate_markdown() {
  cat > "$OUTPUT_MD" <<EOF
| Experiment | RTO (seconds) | RPO (seconds) |
|------------|---------------|--------------|
| Task Stop          | $1 | $2 |
| Network Latency    | $3 | $4 |
| Network Blackhole  | $5 | $6 |
EOF
  log "Results written to $OUTPUT_MD"
}

# ------------------------------------------------------------
# Main workflow
# ------------------------------------------------------------
run_terraform_plan
apply_terraform

# Gather experiment template IDs
TASK_STOP_ID=$(get_experiment_id "task_stop")
NETWORK_LATENCY_ID=$(get_experiment_id "network_latency")
NETWORK_BLACKHOLE_ID=$(get_experiment_id "network_blackhole")

# Array of experiments
declare -A EXP_MAP=(
  [task_stop]="$TASK_STOP_ID"
  [network_latency]="$NETWORK_LATENCY_ID"
  [network_blackhole]="$NETWORK_BLACKHOLE_ID"
)

# Store RTO/RPO values (seconds)
RTO_TS=0 RPO_TS=0 RTO_NL=0 RPO_NL=0 RTO_NB=0 RPO_NB=0

for name in "${!EXP_MAP[@]}"; do
  tmpl_id="${EXP_MAP[$name]}"
  read -r exp_id start_iso <<<$(start_experiment "$tmpl_id")
  log "Experiment $name started: $exp_id (start $start_iso)"
  wait_experiment_complete "$exp_id"
  read -r start_ms end_ms <<<$(fetch_log_times "$exp_id")
  # Convert to seconds
  start_sec=$(ms_to_seconds "$start_ms")
  end_sec=$(ms_to_seconds "$end_ms")
  rto=$(( end_sec - start_sec ))
  # For simplicity we treat RPO as the same as RTO here; adjust if you have a separate metric.
  rpo=$rto
  case "$name" in
    task_stop) RTO_TS=$rto; RPO_TS=$rpo ;;
    network_latency) RTO_NL=$rto; RPO_NL=$rpo ;;
    network_blackhole) RTO_NB=$rto; RPO_NB=$rpo ;;
  esac
  log "$name: RTO=$rto s, RPO=$rpo s"
done

# Generate markdown result file
generate_markdown "$RTO_TS" "$RPO_TS" "$RTO_NL" "$RPO_NL" "$RTO_NB" "$RPO_NB"

log "All done."
