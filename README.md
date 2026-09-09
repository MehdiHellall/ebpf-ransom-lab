<p align="center">
  <img src="src/ebpf_ransom_lab/static/logo.png" width="128" alt="Pixel-art telemetry shield logo">
</p>

# eBPF Ransom Lab

A reproducible, alert-only research prototype for detecting suspicious Linux
file-operation behavior. It keeps two things deliberately separate: auditing
the published `ebpfangel` experiment and building a controlled, safe live
demonstration. It is not a production anti-ransomware product.

## Status

Milestones 1–2 are complete and committed. Milestones 3–5 are now
**training-ready**: portable replay, dashboard, collector protocol/ABI,
bounded workloads, deterministic splits, grouped training, model artifacts,
and reports are implemented and covered by portable tests.

The Ubuntu-VM gates remain intentionally open: BCC compile/attach, syscall
stress tests, the 40 real sixty-second captures, and the final held-out model
evaluation must be run in the pinned Linux VM. This repository does not claim
those measurements have happened on this Windows host.

| Track | State |
|---|---|
| Published-data audit | Complete; corrected experiment blocked by incomplete label provenance |
| Replay → dashboard | Ready on any supported host |
| BCC collector | Implemented and portable-contract tested; requires Ubuntu VM validation |
| Controlled workloads → model | Ready; requires real VM captures before fitting a result worth reporting |

## Quick start: replay the dashboard

Python 3.12 is required.

```powershell
python -m venv .venv
.\.venv\Scripts\python -m pip install -r requirements.lock
.\.venv\Scripts\python -m pip install --no-deps -e .
.\.venv\Scripts\ransomlab replay examples\replay-demo.jsonl --capture-start-ns 0 --capture-end-ns 10000000000 --threshold 0.2 --database var\demo.sqlite
.\.venv\Scripts\ransomlab serve --database var\demo.sqlite
```

Open <http://127.0.0.1:8000>. The bundled recording is intentionally tiny and
uses a low rule threshold only to demonstrate the alert path. Scores are not
probabilities.

Run the portable quality gate with:

```powershell
.\.venv\Scripts\python -m coverage run -m unittest discover -s tests -v
.\.venv\Scripts\python -m coverage report
```

## Training workflow

The workflow is designed to prevent the usual research leaks: the split is
fixed before training, capture groups never cross folds, background activity is
unlabeled, and an entire capture is rejected when it is truncated, lossy,
degraded, detached from the frozen plan, or missing the tracked process exit.

```text
bounded workload + 60-second collector capture
  → normalized JSONL
  → lossless capture acceptance + raw SHA-256
  → fixed 10-second feature windows
  → manifest-bound labeled dataset rows
  → grouped CV + validation selection
  → safe local artifact + one held-out test evaluation
```

Create the immutable 40-capture plan first:

```powershell
ransomlab workload plan --output var\controlled-workloads.json
```

The fixed seeds are `11, 23, 37` for training, `41` for validation, and `53`
for final test, across five benign and three suspicious-behavior simulations.
See [the training guide](docs/TRAINING_GUIDE.md) for the VM commands and
manifest-to-dataset sequence.

## Safety boundaries

- No malware is downloaded, executed, or needed.
- Every workload uses a fresh generated child directory; symlinks, traversal,
  arbitrary target directories, and resource-limit bypasses are rejected.
- Controlled workloads refuse to run as root. Only their exact root-process
  identity is labeled; unrelated activity and unverified descendants remain
  unlabeled.
- Only `ransomlab collect` runs as root, on Linux. Its JSONL output is consumed
  by an ordinary-user service.
- A collector run is complete only when its terminal `run_end` is present and
  kernel loss counters were readable. Dataset construction revalidates the raw
  recording and recomputes its feature rows before labeling.
- The dashboard binds only to `127.0.0.1`, contains no CDN dependency, and
  renders telemetry as text rather than HTML.
- The published corpus remains frozen; its unresolved labels are never silently
  treated as benign.

## Key commands

| Command | Purpose |
|---|---|
| `ransomlab doctor` | Check app or collector prerequisites |
| `ransomlab audit <checkout>` | Reproduce the deterministic upstream-input audit |
| `ransomlab features <recording>` | Create fixed live-window feature records |
| `ransomlab replay <recording>` | Populate SQLite with rule predictions and alerts |
| `ransomlab serve` | Run the localhost dashboard; optionally consume a JSONL pipe |
| `ransomlab collect` | Run the privileged BCC sensor in the Ubuntu VM |
| `ransomlab workload plan/run` | Plan or safely execute a controlled scenario |
| `ransomlab capture validate` | Bind a complete, lossless raw capture to its plan and runtime manifest |
| `ransomlab dataset build` | Label only manifest-tracked workload processes |
| `ransomlab train/evaluate/report` | Select without test data, evaluate the held-out test once, and export a report |

## Documentation

- [Project plan](docs/PROJECT_PLAN.md)
- [Training and VM capture guide](docs/TRAINING_GUIDE.md)
- [Ubuntu / VirtualBox setup](docs/LAB_SETUP.md)
- [Published-data audit findings](docs/MILESTONE_2.md)
- [Frozen upstream attribution](references/README.md) and
  [third-party notices](THIRD_PARTY_NOTICES.md)

Generated captures, model artifacts, reports, and VM images are ignored by
Git. Keep the Linux checkout on the VM filesystem rather than a Windows shared
folder.
