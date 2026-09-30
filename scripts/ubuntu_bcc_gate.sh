#!/usr/bin/env bash
set -euo pipefail

project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$project_root"

ransomlab_bin="${RANSOMLAB_BIN:-$project_root/.venv/bin/ransomlab}"
python_bin="${RANSOMLAB_PYTHON:-$project_root/.venv/bin/python}"

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "Integration gate requires Linux." >&2
  exit 1
fi
if [[ ! -x "$ransomlab_bin" || ! -x "$python_bin" ]]; then
  echo "Run scripts/bootstrap_ubuntu.sh before the integration gate." >&2
  exit 1
fi
if [[ "$(id -u)" -eq 0 ]]; then
  echo "Run this gate as the ordinary lab user; it invokes sudo only for collection." >&2
  exit 1
fi
if ! sudo -n true; then
  echo "Passwordless sudo is required for the non-interactive collector smoke test." >&2
  exit 1
fi

"$ransomlab_bin" doctor --scope app
sudo -n "$ransomlab_bin" doctor --scope collector
"$python_bin" -m coverage run -m unittest discover -s tests -v
"$python_bin" -m coverage report

gate_directory="$(mktemp -d)"
collector_pid=""
cleanup() {
  if [[ -n "$collector_pid" ]] && kill -0 "$collector_pid" 2>/dev/null; then
    sudo -n kill "$collector_pid" 2>/dev/null || true
    wait "$collector_pid" 2>/dev/null || true
  fi
  rm -rf -- "$gate_directory"
}
trap cleanup EXIT

run_id="integration-smoke-$(date +%s)-$$"
capture="$gate_directory/capture.jsonl"
features="$gate_directory/features.jsonl"
database="$gate_directory/runs.sqlite"
workspace="$gate_directory/workload"
mkdir -p "$workspace"

sudo -n "$ransomlab_bin" collect \
  --run-id "$run_id" \
  --duration-seconds 8 \
  > "$capture" &
collector_pid=$!

for _ in $(seq 1 100); do
  if [[ -s "$capture" ]]; then
    break
  fi
  sleep 0.1
done
if [[ ! -s "$capture" ]]; then
  echo "Collector did not emit a run-start record." >&2
  wait "$collector_pid"
  exit 1
fi

"$python_bin" -c '
from pathlib import Path
import sys
root = Path(sys.argv[1])
for index in range(32):
    path = root / f"smoke-{index}.dat"
    path.write_bytes(bytes([index]) * 256)
for path in root.iterdir():
    path.unlink()
' "$workspace"

wait "$collector_pid"
collector_pid=""
"$ransomlab_bin" features "$capture" --output "$features"
"$ransomlab_bin" replay "$capture" --database "$database"
"$python_bin" -c '
import json
from pathlib import Path
import sys
records = [json.loads(line) for line in Path(sys.argv[1]).read_text().splitlines()]
assert records[0]["type"] == "run_start"
assert records[-1]["type"] == "run_end"
assert records[-1]["status"] == "complete"
assert records[-1]["total_lost_events"] == 0
assert any(record["type"] == "event" for record in records)
' "$capture"

echo "Ubuntu/BCC integration gate passed."
