<p align="center">
  <img src="src/ebpf_ransom_lab/static/logo.png" width="128" alt="eBPF Ransom Lab logo">
</p>

# eBPF Ransom Lab

eBPF Ransom Lab is a Linux research project for detecting high-volume file
activity. It captures file operations with eBPF, builds fixed ten-second
behavioral features, scores them, and displays alerts in a local dashboard.

The repository also contains a reproducible audit of the published `ebpfangel`
dataset and preprocessing pipeline.

## Project status

The portable pipeline is implemented and covered by automated tests:

- strict, versioned JSONL telemetry with complete run envelopes;
- replay and live feature extraction;
- a localhost FastAPI dashboard backed by SQLite;
- a BCC collector with explicit ABI and loss counters;
- bounded controlled workloads and fixed data splits;
- 40-run aggregate dataset manifests and grouped model selection;
- strictly validated, dataset-bound `skops` artifacts;
- capture validation tied to raw hashes, workload manifests, and the experiment
  plan.

The portable gate is implemented. The Ubuntu/BCC gate, 40 controlled captures,
and final held-out evaluation must be executed in the lab VM before reporting
performance results.

## Quick start

Python 3.12 is required.

```bash
python3.12 -m venv .venv
.venv/bin/python -m pip install --require-hashes -r requirements.lock
.venv/bin/python -m pip install --no-deps -e .
.venv/bin/ransomlab replay examples/replay-demo.jsonl \
  --threshold 0.2 \
  --database var/demo.sqlite
.venv/bin/ransomlab serve --database var/demo.sqlite
```

Open <http://127.0.0.1:8000>. On Windows, use `.venv\Scripts\` instead of
`.venv/bin/`.

Run the portable test gate with:

```bash
.venv/bin/python -m coverage run -m unittest discover -s tests -v
.venv/bin/python -m coverage report
```

## Pipeline

```text
BCC collector or complete JSONL recording
  -> normalized file-operation records
  -> successful-operation, ten-second process windows
  -> transparent rule score
  -> SQLite
  -> local dashboard and alerts
```

Controlled training adds three provenance gates before model selection:

```text
fixed workload plan
  -> 60-second raw capture
  -> lossless capture validation and SHA-256
  -> per-run labeled rows
  -> 40-run aggregate manifest and full-row hashes
  -> grouped training and validation
  -> one held-out test evaluation
```

Create the fixed 40-run experiment plan with:

```bash
.venv/bin/ransomlab workload plan --output var/controlled-workloads.json
```

Seeds `11`, `23`, and `37` are assigned to training, `41` to validation, and
`53` to the held-out test set. The complete capture workflow is in the
[training guide](docs/TRAINING_GUIDE.md).

## Main commands

| Command | Purpose |
|---|---|
| `ransomlab doctor` | Check application or collector prerequisites |
| `ransomlab reference verify` | Verify the pinned upstream reference |
| `ransomlab audit` | Rebuild and compare the published feature tables |
| `ransomlab collect` | Run the Linux BCC collector |
| `ransomlab features` | Generate ten-second feature windows |
| `ransomlab replay` | Score a recording and populate SQLite |
| `ransomlab serve` | Start the local dashboard |
| `ransomlab workload plan/run` | Plan or execute a controlled workload |
| `ransomlab capture validate` | Validate a raw controlled capture |
| `ransomlab dataset build/assemble` | Build per-run rows and bind all 40 runs |
| `ransomlab train/evaluate/report` | Train, evaluate, and export model results |

## Operating boundaries

- Collection runs as root on Linux; the dashboard, workloads, and model tools
  run as an ordinary user.
- Workloads operate only in generated directories with file, byte, and time
  limits.
- Replay, feature extraction, and live ingestion reject incomplete, lossy,
  degraded, sequence-gapped, or result-less collector streams.
- Feature version 2 counts successful open, create-intent, and delete syscalls;
  it does not measure content entropy or every write/rename operation.
- The dashboard listens on `127.0.0.1` and uses no external frontend assets.
- The project generates suspicious file behavior with disposable files; it does
  not require malware samples.

## Documentation

- [Ubuntu lab setup](docs/LAB_SETUP.md)
- [Controlled capture and training](docs/TRAINING_GUIDE.md)
- [Published-data audit](docs/PUBLISHED_DATA_AUDIT.md)
- [Upstream reference](references/README.md)
- [Third-party notices](THIRD_PARTY_NOTICES.md)

Generated captures, databases, artifacts, reports, and VM images are excluded
from Git.
