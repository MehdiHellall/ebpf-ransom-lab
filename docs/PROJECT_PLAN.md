# Project plan

## Goal

Build a reproducible research project with two outputs: an honest audit of the
published ebpfangel experiment and a working Linux demonstration that observes
file operations, computes ten-second behavioral features, and raises alerts in
a CLI and local dashboard.

The live system detects **suspicious file behavior**. Its controlled workload
results must not be presented as proof that it detects novel ransomware.

## Fixed design

- New Python package with the inspiration repository kept as a frozen external
  reference.
- Ubuntu Server 24.04 LTS in VirtualBox for privileged eBPF collection.
- BCC for the first collector; Python for normalization, features, models, API,
  and dashboard.
- JSONL for raw normalized recordings and SQLite for runs, windows,
  predictions, and alerts.
- Non-overlapping ten-second feature windows shared by replay and live paths.
- FastAPI dashboard bound to Linux localhost and reached from Windows through
  an SSH tunnel.
- Alert-only response. No live malware, process termination, or fleet
  deployment in version one.

## Milestones

### 1. Project and lab foundation

Create the package and CLI, pin and checksum upstream evidence, provide Ubuntu
and VirtualBox setup instructions, and implement `ransomlab doctor`. Portable
tests must pass before Linux collector work begins.

### 2. Auditable research inputs

Create a manifest for each capture and label source, validate label joins, and
reproduce the original integer feature tables. Keep upstream-compatible and
corrected experiment metrics separate. Unresolved labels remain quarantined.

Completed: see [Milestone 2 findings](MILESTONE_2.md). Both published integer
feature tables reconstruct exactly; training labels remain unresolved, blocking
the corrected published-data experiment without blocking milestone 3.

### 3. Shared feature engine and replay dashboard

Implement legacy process aggregates and ten-second live windows. Replaying the
same normalized recording in a batch or arbitrary chunks must produce identical
features. Drive the first dashboard with recorded fixtures and a transparent
rule baseline.

### 4. Reliable Linux collection

Observe syscall entry and exit, distinguish attempts from results, retain TGID
and TID separately, track process lifecycle and telemetry loss, and stream
normalized events to an unprivileged service. Keep optional crypto-library
probes outside the initial model.

### 5. Controlled workload experiment

Collect reproducible benign and suspicious-behavior workloads with fixed seeds.
Compare a rule, a scaled RBF SVM, and a random forest using capture-grouped
splits. Save the feature schema, threshold, data manifest, and dependency
versions with every model.

### 6. Live demo and evaluation

Connect collection through inference to consolidated alerts. Report recall,
precision, F1, MCC, false alerts per benign host-hour, detection delay, files
changed before alert, event loss, CPU and memory use, and workload slowdown.

## Current implementation boundary

Milestones 3–5 are implemented as a portable, training-ready pipeline:
versioned normalized recordings, a shared ten-second feature engine, local
dashboard and replay path, BCC collector source and ABI tests, bounded
controlled workloads, manifest-bound labels, fixed capture splits,
capture-grouped model selection, and checksummed safe artifacts.

The remaining acceptance work must happen on the pinned Ubuntu VM: compile and
attach BCC, exercise the collector under syscall/loss/PID-reuse stress, make
the planned 40 captures, and perform the single held-out evaluation. Until
then, the project reports implementation readiness rather than experimental
performance.

## Completion criteria

Version one is complete when a fresh VM can follow the setup guide, reproduce
the input audit, replay a recording, train the controlled-workload model, and
show a live alert in the Windows browser. Automated tests must pass with at
least 80% coverage of first-party Python code, and the report must retain misses,
false alarms, and experimental limitations.
