# Milestone 1 checklist

Milestone 1 turns the idea into a reproducible lab foundation. It does not
collect live events yet; it proves that the project can be installed, audited,
and moved into a Linux VM without losing provenance.

## Completed in the repository

- Python package scaffold with `ransomlab` CLI entry point.
- Portable `ransomlab doctor` checks for app prerequisites.
- Linux collector checks for BCC, root privileges, kernel BTF, matching
  headers, required syscall tracepoints, and BPF ring-buffer support.
- Frozen upstream manifest for the inspiration repository and paper.
- Reference verifier that rejects unsafe manifest paths, non-HTTPS repository
  URLs, malformed file hashes, invalid sizes, and non-full commit hashes.
- Ubuntu bootstrap script that installs BCC dependencies and records installed
  kernel, Python, pip, and apt package versions in `var/lab_versions.txt`.
- VirtualBox lab setup guide with NAT-only SSH, no shared folders, no shared
  clipboard, no drag-and-drop, and a clean snapshot target.
- Portable unit tests and CI coverage gate.

## VM-only acceptance checks

Run these after the Ubuntu VM exists and the project is cloned onto the VM's
Linux filesystem:

```bash
bash scripts/bootstrap_ubuntu.sh
.venv/bin/ransomlab doctor --scope app
sudo .venv/bin/ransomlab doctor --scope collector
```

Milestone 1 is ready for Milestone 2 when both doctor commands pass and a
VirtualBox snapshot named `clean-lab-m1` exists.
