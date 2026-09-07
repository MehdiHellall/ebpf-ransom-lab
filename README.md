# eBPF Ransom Lab

This project reproduces and corrects the research behind
[ebpfangel](https://github.com/TomasPhilippart/ebpfangel), then builds an
alert-only Linux prototype that detects suspicious file-operation behavior.
It is a research lab and demonstration, not a production anti-ransomware
product.

The project keeps two evidence tracks separate:

- **Upstream-compatible:** explain and replay the published behavior, including
  discrepancies.
- **Corrected prototype:** use validated labels, consistent feature generation,
  controlled workloads, and the same feature path for offline and live data.

Version one uses published traces and bounded synthetic workloads. It does not
execute real ransomware, terminate processes, or block filesystem operations.

## Current status

Milestone 1 establishes the package, environment checker, frozen upstream
manifest, automated tests, and Ubuntu/VirtualBox lab instructions. See the
[project plan](docs/PROJECT_PLAN.md), [lab setup guide](docs/LAB_SETUP.md), and
[Milestone 1 checklist](docs/MILESTONE_1.md).

## Quick start

Python 3.11 or newer is required. This Windows host did not have a user Python
installation during the initial preflight, so install Python 3.12 first and
enable its `Add python.exe to PATH` option. Then, from the repository root:

```powershell
python -m venv .venv
.\.venv\Scripts\python -m pip install -e .
.\.venv\Scripts\ransomlab doctor --scope app
.\.venv\Scripts\python -m unittest discover -s tests -v
```

On Linux, verify collector prerequisites after completing the lab setup:

```bash
sudo .venv/bin/ransomlab doctor --scope collector
```

To verify a local clone of the inspiration repository against the pinned
evidence manifest:

```bash
ransomlab reference verify /path/to/ebpfangel
```

The command fails if the checkout is at a different commit, a required file is
missing, or a recorded file hash or size has changed.

## Repository layout

```text
src/ebpf_ransom_lab/   application and CLI code
tests/                 portable automated tests
docs/                  project and lab documentation
references/            upstream provenance and attribution
scripts/               repeatable environment setup helpers
```

Generated captures, VM disks, model artifacts, dependency-version captures, and
temporary audit material are ignored by Git.

## Safety boundary

Only the future eBPF collector will run as root. Feature processing, model
training, storage, and the dashboard run as an ordinary user. Controlled
workloads will be limited to newly created disposable directories.
