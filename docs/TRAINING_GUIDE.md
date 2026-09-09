# Controlled-workload training guide

This guide is the handoff from the portable implementation to the Ubuntu 24.04
VM. It creates evidence for a suspicious-behavior demonstration; it does not
validate protection against real ransomware.

## Before capturing

Run these from the project checkout on the VM's Linux filesystem:

```bash
.venv/bin/ransomlab doctor --scope app
sudo .venv/bin/ransomlab doctor --scope collector
.venv/bin/python -m coverage run -m unittest discover -s tests -v
.venv/bin/python -m coverage report
.venv/bin/ransomlab workload plan --output var/controlled-workloads.json
```

The plan contains exactly 40 independent captures: eight scenarios by the five
fixed seeds. Use `11`, `23`, and `37` only for training; `41` only for
validation; and `53` only for the final test. Do not change the split after
viewing features or model results.

## Capture one run

Use a disposable VM and an ordinary user for every command except the
collector. The fixed `--hold-seconds 50` keeps the tracked process alive long
enough to yield complete ten-second windows, then leaves time for the collector
to record its exact exit before the 60-second terminal record.

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
.venv/bin/ransomlab workload run copying --seed 11 --hold-seconds 50 \
  --manifest var/captures/controlled-copying-seed-11.manifest.json
wait "$collector_pid"
.venv/bin/ransomlab capture validate "$capture" \
  var/captures/controlled-copying-seed-11.manifest.json \
  --plan var/controlled-workloads.json \
  --output var/captures/controlled-copying-seed-11.accepted.json
```

The pipe example is for a live visual check. The durable capture is the
reproducible training path; do not run both collectors for the same capture.
Capture failures, a missing terminal `run_end`, any sequence gap, unreadable or
nonzero loss telemetry, degraded events, a missing exact root-process event or
exit, plan drift, or a missing runtime manifest invalidate the whole run. Never
salvage apparently clean windows from a rejected capture.

## Build data and train

For each successful capture:

```bash
.venv/bin/ransomlab features var/captures/controlled-copying-seed-11.jsonl \
  --output var/features/controlled-copying-seed-11.jsonl
.venv/bin/ransomlab dataset build var/features/controlled-copying-seed-11.jsonl \
  var/captures/controlled-copying-seed-11.manifest.json \
  --capture var/captures/controlled-copying-seed-11.jsonl \
  --plan var/controlled-workloads.json \
  --output var/datasets/controlled-copying-seed-11.jsonl
```

`dataset build` reruns the full capture validator, hashes the raw JSONL, and
recomputes feature windows from that evidence. The supplied feature file must
match exactly. It labels only the exact boot/TGID/start-time root identity in
the runtime manifest. Background activity and descendants remain unlabeled;
never match a PID by time or numeric similarity.

Combine rows into two new files in the prescribed order, preserving every line
exactly: a selection dataset containing only seeds `11`, `23`, `37`, and `41`,
and a held-out test dataset containing only seed `53`. Do not open, summarize,
or pass test rows to `train`. The commands fail closed if a capture ID or raw
capture hash crosses splits, labels are unknown, or feature order differs from
the fixed schema.

```bash
.venv/bin/ransomlab train var/datasets/controlled-selection.jsonl \
  --output var/artifacts/controlled-v1 --seed 37
.venv/bin/ransomlab evaluate var/artifacts/controlled-v1 \
  var/datasets/controlled-test.jsonl
.venv/bin/ransomlab report var/artifacts/controlled-v1 \
  --output var/reports/controlled-v1.json
```

Training compares a transparent count/rate rule, a `StandardScaler` + RBF SVM
pipeline, and a random forest. Hyperparameters are tuned with three-fold
capture-grouped CV on training data only. The winner and threshold are selected
on validation F1, then false positives, then a fixed simplicity order. `train`
rejects test rows. `evaluate` accepts only test rows and writes one immutable
evaluation record into the artifact; a second evaluation is refused.

Artifacts use `skops`, not arbitrary pickle/joblib loading. Their manifest
records the feature schema and order, split/capture hash, threshold, seed,
dependency versions, validation metrics, and model-file checksum. The held-out
evaluation is separately bound to both the artifact-manifest hash and the test
dataset hash. Loading rejects incompatible or unexpected artifacts.

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
