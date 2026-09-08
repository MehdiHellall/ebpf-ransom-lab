# Controlled-workload training guide

This guide is the handoff from the portable implementation to the Ubuntu 24.04
VM. It creates evidence for a suspicious-behavior demonstration; it does not
validate protection against real ransomware.

## Before capturing

Run these from the project checkout on the VM's Linux filesystem:

```bash
.venv/bin/ransomlab doctor --scope app
sudo .venv/bin/ransomlab doctor --scope collector
.venv/bin/ransomlab workload plan --output var/controlled-workloads.json
```

The plan contains exactly 40 independent captures: eight scenarios by the five
fixed seeds. Use `11`, `23`, and `37` only for training; `41` only for
validation; and `53` only for the final test. Do not change the split after
viewing features or model results.

## Capture one run

Use a disposable VM and an ordinary user for every command except the
collector. The workload's `--hold-seconds 60` keeps its tracked process alive
long enough to yield complete ten-second windows while keeping file-operation
limits bounded.

Create output directories once, then pipe the privileged collector directly
into the ordinary-user dashboard consumer. Run this command once from the VM
shell:

```bash
mkdir -p var/captures var/features var/datasets var/artifacts var/reports
```

```bash
sudo .venv/bin/ransomlab collect --run-id controlled-copying-seed-11 --duration-seconds 60 |
  .venv/bin/ransomlab serve --input - --database var/live.sqlite
```

For a durable capture used for training, redirect the collector to a file,
then use the same file for replay/features. The collector writes a `run_start`
record, so the capture-aligned time origin travels with the recording.

```bash
capture=var/captures/controlled-copying-seed-11.jsonl
sudo .venv/bin/ransomlab collect --run-id controlled-copying-seed-11 --duration-seconds 60 \
  > "$capture" &
collector_pid=$!
for _ in $(seq 1 100); do test -s "$capture" && break; sleep 0.1; done
test -s "$capture" || { wait "$collector_pid"; exit 1; }
.venv/bin/ransomlab workload run copying --seed 11 --hold-seconds 60 \
  --manifest var/captures/controlled-copying-seed-11.manifest.json
wait "$collector_pid"
```

The pipe example is for a live visual check. The durable capture is the
reproducible training path; do not run both collectors for the same capture.
Capture failures, event loss, missing lifecycle identity, or a missing runtime
manifest invalidate the run rather than producing benign labels.

## Build data and train

For each successful capture:

```bash
.venv/bin/ransomlab features var/captures/controlled-copying-seed-11.jsonl \
  --output var/features/controlled-copying-seed-11.jsonl
.venv/bin/ransomlab dataset build var/features/controlled-copying-seed-11.jsonl \
  var/captures/controlled-copying-seed-11.manifest.json \
  --output var/datasets/controlled-copying-seed-11.jsonl
```

`dataset build` labels only the exact boot/TGID/start-time identities frozen in
the runtime manifest. Background windows, partial windows, late windows, and
loss-affected windows are excluded. Extend `tracked_processes` only with
collector lifecycle evidence for verified descendants; never match a PID by
time or by numeric similarity.

Combine one JSONL row set per capture into a new dataset file in the prescribed
order, preserving every line exactly. The training command fails closed if a
capture ID or capture hash crosses splits, labels are unknown, or feature order
does not match the fixed live schema.

```bash
.venv/bin/ransomlab train var/datasets/controlled-all.jsonl \
  --output var/artifacts/controlled-v1 --seed 37
.venv/bin/ransomlab evaluate var/artifacts/controlled-v1 var/datasets/controlled-all.jsonl \
  --split test
.venv/bin/ransomlab report var/artifacts/controlled-v1 \
  --output var/reports/controlled-v1.json
```

Training compares a transparent count/rate rule, a `StandardScaler` + RBF SVM
pipeline, and a random forest. Hyperparameters are tuned with three-fold
capture-grouped CV on training data only. The winner and threshold are selected
on validation F1, then false positives, then a fixed simplicity order. The test
split is evaluated once.

Artifacts use `skops`, not arbitrary pickle/joblib loading. Their manifest
records the feature schema and order, split/capture hash, threshold, seed,
dependency versions, metrics, and model-file checksum. Loading rejects any
incompatible or unexpected artifact.

## Required VM evidence

Keep the following with the experiment report:

- `ransomlab doctor` output and `var/lab_versions.txt`.
- The 40 raw JSONL captures, runtime manifests, feature files, and dataset
  hashes.
- A BCC attach/smoke result plus failed-operation, threaded-process, PID-reuse,
  churn, and forced-loss checks.
- Validation selection output and the one held-out test report.
- Event-loss counters and the statement that results concern only the bounded
  simulations.

The dashboard is localhost-only. From Windows, use the documented SSH tunnel
in [the lab setup guide](LAB_SETUP.md) rather than exposing port 8000 to a
network.
