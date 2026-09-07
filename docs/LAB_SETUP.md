# Ubuntu VirtualBox lab setup

This lab is for published traces and controlled workloads on disposable files.
Do not import or execute real malware in this version of the project.

## Host preflight

The planned VM profile is 4 virtual CPUs, 8 GB RAM, and a dynamically allocated
40 GB disk. It assumes a host with at least 16 GB RAM and roughly 10 GB free
memory before the VM starts.

The host inspected on 2026-09-06 has VirtualBox 7.2.12, 12 logical CPUs, 12,064
MB total RAM, and only about 1,761 MB available at inspection time. Starting an
8 GB VM in that state is unsafe for host stability. Close memory-heavy programs
and recheck. If the host cannot provide enough free memory, use the fallback lab
profile of 2 virtual CPUs and 4 GB RAM after accepting slower model training.

Keep at least 25 GB of real disk space free for the ISO, dynamically growing VM,
snapshots, and captures. The project drive had about 14.2 GB free during the
preflight, so storage must also be freed before creating the planned VM.
VirtualBox reported no existing VM for this project, and no Ubuntu 24.04 ISO was
found in the Downloads folder during the preflight.

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
9. Shut down the VM and create a snapshot named `clean-lab-m1`.

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
before collection begins. Milestone 4 adds the event-delivery smoke test; these
static checks do not claim that events have already reached a consumer.

Ubuntu's BCC package may lag upstream, but the packaged version is suitable for
this pinned prototype if the doctor and smoke test pass. Record the kernel, BCC,
Python, and package versions in the run manifest before gathering data.
