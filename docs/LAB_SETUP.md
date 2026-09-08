# Ubuntu VirtualBox lab setup

This lab is for published traces and controlled workloads on disposable files.
Do not import or execute real malware in this version of the project.

## Host preflight

The preferred VM profile is 4 virtual CPUs, 8 GB RAM, and a dynamically
allocated 40 GB disk. Before creating it, confirm that the host has at least
10 GB free RAM and 25 GB free disk space for the ISO, VM, snapshots, and
captures. If that is not available, use the fallback profile of 2 virtual CPUs
and 4 GB RAM, accepting slower model training.

## Create the VM

1. Download the current Ubuntu Server 24.04 LTS ISO from
   <https://ubuntu.com/download/server> and verify the published SHA-256 digest.
2. In VirtualBox, create a Linux/Ubuntu 64-bit VM named `ebpf-ransom-lab`.
3. Select the 4 CPU, 8 GB RAM, and 40 GB dynamic-disk profile when the host
   preflight passes. Otherwise select the documented fallback profile.
4. Keep the network adapter in NAT mode. Do not enable bridged networking,
   shared folders, shared clipboard, or drag-and-drop.
5. Install Ubuntu Server with OpenSSH Server selected. Enable automatic security
   updates and use an ordinary user with sudo access.
6. Apply all updates, reboot, and install the lab prerequisites from the project
   checkout:

   ```bash
   bash scripts/bootstrap_ubuntu.sh
   ```

7. Run the application and collector checks:

   ```bash
   .venv/bin/ransomlab doctor --scope app
   sudo .venv/bin/ransomlab doctor --scope collector
   ```

8. Confirm that `var/lab_versions.txt` exists and records the kernel, Python,
   pip, BCC, and Linux-header package versions from the VM.
9. Shut down the VM and create a snapshot named `clean-training-lab`.

## Localhost-only SSH access

Add a VirtualBox NAT port-forwarding rule:

| Field | Value |
|---|---|
| Name | `ssh` |
| Protocol | TCP |
| Host IP | `127.0.0.1` |
| Host port | `2222` |
| Guest IP | blank |
| Guest port | `22` |

Connect from Windows with:

```powershell
ssh -p 2222 <ubuntu-user>@127.0.0.1
```

Later, reach the dashboard without exposing it to the LAN:

```powershell
ssh -p 2222 -L 8000:127.0.0.1:8000 <ubuntu-user>@127.0.0.1
```

Then open <http://127.0.0.1:8000> in the Windows browser.

## Checkout policy

Clone this project onto the VM's Linux filesystem, such as
`~/src/ebpf-ransom-lab`. Do not execute the collector from a VirtualBox shared
folder or the Windows OneDrive checkout. Transfer changes with Git or `scp`.

Only collector commands use `sudo`. Never run the dashboard, training, model
loading, or workload runner as root.

## Verification and troubleshooting

`ransomlab doctor --scope collector` verifies Linux, root privileges, BCC Python
bindings, kernel BTF, matching kernel headers, BPF ring-buffer support, and the
syscall tracepoints used by the first collector. A failed check must be fixed
before collection begins. Then make and replay a short smoke capture before
recording experiment data:

```bash
sudo .venv/bin/ransomlab collect --run-id collector-smoke --duration-seconds 10 > var/collector-smoke.jsonl
.venv/bin/ransomlab features var/collector-smoke.jsonl --output var/collector-smoke-features.jsonl
```

Keep the raw capture and feature output only when lifecycle identity and health
records are present and no loss is reported.

Ubuntu's BCC package may lag upstream, but the packaged version is suitable for
this pinned prototype if the doctor and smoke test pass. Record the kernel, BCC,
Python, and package versions in the run manifest before gathering data.
