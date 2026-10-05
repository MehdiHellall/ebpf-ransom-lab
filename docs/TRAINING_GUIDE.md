# Controlled experiment runbook

This runbook starts at a clean Ubuntu 24.04 VM and ends with a report tied to
all 40 planned captures. Run collector commands with `sudo`; run workloads,
dataset tools, training, and the dashboard as the ordinary lab user.

## 0. Provision the required VM

Create the Ubuntu Server 24.04 LTS VirtualBox guest described in the
[Ubuntu lab setup](LAB_SETUP.md). The recommended profile is 4 virtual CPUs,
8 GB RAM, a 40 GB dynamically allocated disk, NAT networking, and OpenSSH.
Keep the repository on the guest's Linux filesystem, not in a shared folder.

Before bootstrap, prove that the guest—not the host—is the active shell:

```bash
. /etc/os-release
test "$VERSION_ID" = "24.04" || { echo "Ubuntu 24.04 is required"; exit 1; }
python3 -c 'import sys; assert sys.version_info[:2] == (3, 12), sys.version'
```

Stop if either check fails. In particular, Ubuntu 26.04 with Python 3.14 is
not the controlled experiment environment.

## 1. Freeze the revision

Use one reviewed commit for the complete experiment. Do not change source,
dependencies, workload plans, or feature code between captures.

```bash
cd ~/ebpf-ransom-lab
git status --short
git rev-parse HEAD
```

Record the commit ID. The working tree should be empty before continuing.

## 2. Build the Ubuntu environment

Install the pinned Python dependencies and Ubuntu BCC packages:

```bash
scripts/bootstrap_ubuntu.sh
```

The Python lock uses SHA-256 hashes. The bootstrap records the kernel, Python,
APT, and Python package versions in `var/lab_versions.txt`.

Confirm that bootstrap created the supported environment and CLI:

```bash
.venv/bin/python --version
test -x .venv/bin/ransomlab
```

The version must be Python 3.12. If the executable check fails, stop and fix
the VM rather than mixing another Python installation with the system BCC
bindings.

Authorize `sudo` for the upcoming non-interactive collector command, then run
the portable and live integration gate:

```bash
mkdir -p var/reports
sudo -v
set -o pipefail
scripts/ubuntu_bcc_gate.sh 2>&1 \
  | tee var/reports/ubuntu-bcc-gate.log
```

Do not start the experiment unless this ends with:

```text
Ubuntu/BCC integration gate passed.
```

If the gate fails, keep its output and fix the VM or collector first. A failed
gate is not a usable experiment run.

## 3. Create and freeze the 40-run plan

```bash
mkdir -p var/captures var/features var/datasets/runs var/artifacts var/reports
.venv/bin/ransomlab workload plan \
  --output var/controlled-workloads.json
sha256sum var/controlled-workloads.json | tee var/controlled-workloads.sha256
```

The plan has eight scenarios and five preassigned seeds:

| Split | Seeds | Runs |
|---|---|---:|
| Training | `11`, `23`, `37` | 24 |
| Validation | `41` | 8 |
| Test | `53` | 8 |

Do not regenerate the plan after collection starts.

## 4. Check one capture before the full run

Refresh `sudo`, then collect the first run:

```bash
sudo -v
scripts/capture_controlled_run.sh copying 11
```

The script performs the complete per-run transaction:

1. Starts a 60-second root BCC capture.
2. Waits for the `RunStart` record.
3. Runs the bounded workload as the ordinary user with a 50-second hold.
4. Waits for the terminal collector record.
5. Rejects sequence gaps, missing syscall results, degraded telemetry, any
   reported loss, a missing process exit, or a plan mismatch.
6. Recomputes feature windows from the accepted raw capture.
7. Writes only classifiable windows for the exact workload process.

Inspect the acceptance record:

```bash
.venv/bin/python -m json.tool \
  var/captures/controlled-copying-seed-11.accepted.json
```

Confirm that `status` is `accepted` and `total_lost_events` is `0`.

The five files for this run are:

```text
var/captures/controlled-copying-seed-11.jsonl
var/captures/controlled-copying-seed-11.manifest.json
var/captures/controlled-copying-seed-11.accepted.json
var/features/controlled-copying-seed-11.jsonl
var/datasets/runs/controlled-copying-seed-11.jsonl
```

## 5. Execute all 40 captures

The first run already exists, so run the other seeds for `copying`, followed by
all seeds for the remaining scenarios:

```bash
set -euo pipefail

for seed in 23 37 41 53; do
  sudo -v
  scripts/capture_controlled_run.sh copying "$seed"
done

for scenario in \
  archiving \
  compression \
  small-build \
  bulk-editing \
  rapid-generated-file-replacement \
  create-delete-churn \
  paced-replacement
do
  for seed in 11 23 37 41 53; do
    sudo -v
    scripts/capture_controlled_run.sh "$scenario" "$seed"
  done
done
```

Run one capture at a time. Do not run other file-heavy jobs in the VM during
collection. The complete loop takes at least 40 minutes because every capture
is 60 seconds.

If a run fails, do not edit or append to its files. Move all files with that
run ID into a separate `var/rejected/` directory, record the failure reason,
and rerun that scenario and seed from fresh output paths.

## 6. Verify the run inventory

Each command below must print `40`:

```bash
find var/captures -maxdepth 1 -name 'controlled-*.jsonl' | wc -l
find var/captures -maxdepth 1 -name 'controlled-*.manifest.json' | wc -l
find var/captures -maxdepth 1 -name 'controlled-*.accepted.json' | wc -l
find var/features -maxdepth 1 -name 'controlled-*.jsonl' | wc -l
find var/datasets/runs -maxdepth 1 -name 'controlled-*.jsonl' | wc -l
```

Check every acceptance record without relying on filename counts alone:

```bash
.venv/bin/python - <<'PY'
import json
from pathlib import Path

paths = sorted(Path("var/captures").glob("controlled-*.accepted.json"))
assert len(paths) == 40, len(paths)
for path in paths:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert value["status"] == "accepted", path
    assert value["total_lost_events"] == 0, path
    assert value["tracked_event_count"] > 0, path
print("40 accepted, lossless captures")
PY
```

## 7. Assemble the experiment dataset

Do not concatenate JSONL files manually. The assembly command requires exactly
the 40 planned per-run files and rejects missing or unexpected files:

```bash
.venv/bin/ransomlab dataset assemble \
  var/datasets/runs \
  --plan var/controlled-workloads.json \
  --output var/datasets/controlled-v2
```

It creates:

```text
var/datasets/controlled-v2/all.jsonl
var/datasets/controlled-v2/selection.jsonl
var/datasets/controlled-v2/test.jsonl
var/datasets/controlled-v2/manifest.json
```

The manifest binds the frozen plan, all 40 run IDs, each raw-capture SHA-256,
each capture's complete row content, and the exact aggregate file bytes. Review
it before training:

```bash
.venv/bin/python -m json.tool var/datasets/controlled-v2/manifest.json | less
sha256sum var/datasets/controlled-v2/*
```

## 8. Select the model without test data

Training accepts only the manifest-bound `selection.jsonl`, which contains the
training and validation seeds but no seed-53 rows:

```bash
.venv/bin/ransomlab train \
  var/datasets/controlled-v2/selection.jsonl \
  --manifest var/datasets/controlled-v2/manifest.json \
  --output var/artifacts/controlled-v2 \
  --seed 37
```

The artifact records the complete selection-row hash, selection file hash,
aggregate dataset-manifest hash, dependency versions, candidate validation
metrics, selected model, and threshold.

## 9. Evaluate the held-out split once

Run this only after the model and threshold have been accepted. The command
creates `test-evaluation.json` with exclusive creation and refuses a second
evaluation in the same artifact directory.

```bash
.venv/bin/ransomlab evaluate \
  var/artifacts/controlled-v2 \
  var/datasets/controlled-v2/test.jsonl \
  --manifest var/datasets/controlled-v2/manifest.json
```

Do not tune the model after reading these results. A new model decision requires
a new experiment version and a new untouched test set.

## 10. Export and preserve the evidence

```bash
.venv/bin/ransomlab report \
  var/artifacts/controlled-v2 \
  --output var/reports/controlled-v2.json

find \
  var/captures \
  var/features \
  var/datasets \
  var/artifacts \
  -type f -print0 \
  | sort -z \
  | xargs -0 sha256sum \
  > var/reports/SHA256SUMS
```

Retain the Git commit ID, `var/lab_versions.txt`, integration-gate output,
plan and plan hash, raw captures, runtime manifests, acceptance records,
features, aggregate manifest and datasets, artifact, report, and `SHA256SUMS`.

## Feature interpretation

Feature version 2 counts successful `open`, create-intent `open/openat`, and
`unlink/unlinkat` syscalls in fixed ten-second per-process windows. Failed
syscalls are excluded. `C` means a successful call made with `O_CREAT`; it does
not prove that the path was newly created. The collector does not observe file
content entropy or every write and rename operation. Reported metrics therefore
apply to these eight controlled scenarios, not to ransomware in general.
