#!/usr/bin/env bash
set -euo pipefail

if [[ "$#" -ne 2 ]]; then
  echo "Usage: scripts/capture_controlled_run.sh SCENARIO SEED" >&2
  exit 2
fi

scenario="$1"
seed="$2"
case "$scenario" in
  copying|archiving|compression|small-build|bulk-editing|rapid-generated-file-replacement|create-delete-churn|paced-replacement) ;;
  *) echo "Unknown controlled scenario: $scenario" >&2; exit 2 ;;
esac
case "$seed" in
  11|23|37|41|53) ;;
  *) echo "Seed must be one of: 11 23 37 41 53" >&2; exit 2 ;;
esac

project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$project_root"
ransomlab_bin="${RANSOMLAB_BIN:-$project_root/.venv/bin/ransomlab}"
plan="${RANSOMLAB_PLAN:-$project_root/var/controlled-workloads.json}"

if [[ "$(id -u)" -eq 0 ]]; then
  echo "Run this script as the ordinary lab user." >&2
  exit 1
fi
if [[ ! -x "$ransomlab_bin" || ! -f "$plan" ]]; then
  echo "Bootstrap the environment and create the fixed experiment plan first." >&2
  exit 1
fi
if ! sudo -n true; then
  echo "Passwordless sudo is required for non-interactive collection." >&2
  exit 1
fi

run_id="controlled-${scenario}-seed-${seed}"
capture="$project_root/var/captures/${run_id}.jsonl"
runtime_manifest="$project_root/var/captures/${run_id}.manifest.json"
acceptance="$project_root/var/captures/${run_id}.accepted.json"
features="$project_root/var/features/${run_id}.jsonl"
dataset="$project_root/var/datasets/runs/${run_id}.jsonl"
workload_root="$project_root/var/workloads"

for output in "$capture" "$runtime_manifest" "$acceptance" "$features" "$dataset"; do
  if [[ -e "$output" ]]; then
    echo "Refusing to overwrite existing run evidence: $output" >&2
    exit 1
  fi
done
mkdir -p \
  "$project_root/var/captures" \
  "$project_root/var/features" \
  "$project_root/var/datasets/runs" \
  "$workload_root"

collector_pid=""
stop_collector() {
  if [[ -n "$collector_pid" ]] && kill -0 "$collector_pid" 2>/dev/null; then
    sudo -n kill "$collector_pid" 2>/dev/null || true
    wait "$collector_pid" 2>/dev/null || true
  fi
}
trap stop_collector EXIT

sudo -n "$ransomlab_bin" collect \
  --run-id "$run_id" \
  --duration-seconds 60 \
  > "$capture" &
collector_pid=$!

for _ in $(seq 1 100); do
  if [[ -s "$capture" ]]; then
    break
  fi
  sleep 0.1
done
if [[ ! -s "$capture" ]]; then
  echo "Collector did not emit run-start metadata for $run_id." >&2
  wait "$collector_pid"
  exit 1
fi

"$ransomlab_bin" workload run "$scenario" \
  --seed "$seed" \
  --root "$workload_root" \
  --max-seconds 15 \
  --max-files 256 \
  --max-bytes 16777216 \
  --hold-seconds 50 \
  --manifest "$runtime_manifest"

wait "$collector_pid"
collector_pid=""

"$ransomlab_bin" capture validate \
  "$capture" \
  "$runtime_manifest" \
  --plan "$plan" \
  --output "$acceptance"
"$ransomlab_bin" features "$capture" --output "$features"
"$ransomlab_bin" dataset build \
  "$features" \
  "$runtime_manifest" \
  --capture "$capture" \
  --plan "$plan" \
  --output "$dataset"

echo "Controlled run accepted and built: $run_id"
