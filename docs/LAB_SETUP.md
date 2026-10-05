# Ubuntu lab setup

The live collector and controlled experiment target **Ubuntu Server 24.04
LTS** in a disposable VirtualBox VM. Do not substitute the host operating
system: the experiment depends on Ubuntu 24.04's Python 3.12, BCC packages,
kernel headers, and tracepoints. Replay, audit, and most tests can run without
privileged collection.

## Install VirtualBox on the host

On an Ubuntu host with the VirtualBox packages available, install the manager
and graphical interface outside the future guest:

```bash
sudo apt-get update
sudo apt-get install -y virtualbox virtualbox-qt
VBoxManage --version
```

Reboot the host if package installation adds or updates kernel modules. With
Secure Boot enabled, complete any Machine Owner Key enrollment requested by
Ubuntu so the `vboxdrv` module can load. Confirm that VirtualBox starts before
continuing. These host packages do not replace the Ubuntu 24.04 guest.

## Create the VirtualBox VM

1. Download an Ubuntu Server 24.04 LTS ISO from the
   [official Ubuntu releases site](https://releases.ubuntu.com/24.04/) and
   verify its SHA-256 checksum against the published checksum file.
2. In VirtualBox, create a Linux/Ubuntu (64-bit) VM with the profile below.
3. Attach the ISO to the virtual optical drive and leave networking on NAT.
4. Install Ubuntu Server using the whole virtual disk. Create a normal user
   with `sudo` access and select **Install OpenSSH server**. Extra server snaps
   and a desktop environment are unnecessary.
5. Reboot, eject the ISO, install updates, and reboot again if a new kernel was
   installed:

   ```bash
   sudo apt-get update
   sudo apt-get upgrade -y
   sudo reboot
   ```

Verify the guest before cloning the repository:

```bash
. /etc/os-release
test "$VERSION_ID" = "24.04" || { echo "Ubuntu 24.04 is required"; exit 1; }
python3 --version
python3 -c 'import sys; assert sys.version_info[:2] == (3, 12), sys.version'
```

The final two commands must report Python 3.12 and exit successfully. Do not
continue on Ubuntu 26.04 or with Python 3.14.

## VM profile

Recommended configuration:

- 4 virtual CPUs;
- 8 GB RAM;
- 40 GB dynamically allocated disk;
- NAT networking;
- OpenSSH Server enabled.

A 2 CPU and 4 GB RAM VM is sufficient for a slower run. Keep the repository on
the VM's Linux filesystem rather than in a VirtualBox shared folder.

Enable hardware virtualization (Intel VT-x or AMD-V) in the host firmware if
VirtualBox does not offer 64-bit guests. The VM needs internet access while
installing packages; the experiment itself does not need inbound internet
access.

## Clone the repository inside the guest

Use the VM's own Linux filesystem:

```bash
git clone https://github.com/MehdiHellall/ebpf-ransom-lab.git
cd ebpf-ransom-lab
git status --short
```

If an experiment revision was already chosen, check out that exact full commit
ID. Otherwise, select and record one immediately before starting the controlled
experiment. Do not collect from a VirtualBox shared folder.

## Install the environment

From the repository root, run:

```bash
bash scripts/bootstrap_ubuntu.sh
```

The script installs BCC, kernel headers, Clang/LLVM, Python tooling, and the
locked Python dependencies. It also writes resolved component versions to
`var/lab_versions.txt`.

Verify the application and collector environments:

```bash
.venv/bin/python --version
test -x .venv/bin/ransomlab
.venv/bin/ransomlab doctor --scope app
sudo .venv/bin/ransomlab doctor --scope collector
```

The virtual-environment interpreter must be Python 3.12, and the executable
check must succeed. If `.venv/bin/ransomlab` is absent, stop: do not attempt
the experiment with a different Python version.

Authorize `sudo` and run the complete portable plus live-collector gate:

```bash
sudo -v
scripts/ubuntu_bcc_gate.sh
```

Do not begin controlled captures until the script reports
`Ubuntu/BCC integration gate passed.`

The collector check covers privileges, BCC bindings, kernel headers, BTF, ring
buffer support, and the tracepoints used by the sensor.

After a successful gate, power off the VM and create a VirtualBox snapshot
named `experiment-ready`. Resume the VM and continue at plan creation in the
[controlled experiment runbook](TRAINING_GUIDE.md); its Git revision must
already be frozen. Do not restore the snapshot after collection starts unless
you intend to restart the entire experiment.

## Network access

Use a VirtualBox NAT port-forwarding rule for SSH:

| Field | Value |
|---|---|
| Name | `ssh` |
| Protocol | TCP |
| Host IP | `127.0.0.1` |
| Host port | `2222` |
| Guest port | `22` |

Connect from the host with:

```bash
ssh -p 2222 <ubuntu-user>@127.0.0.1
```

Forward the dashboard through SSH:

```bash
ssh -p 2222 -L 8000:127.0.0.1:8000 <ubuntu-user>@127.0.0.1
```

Then open <http://127.0.0.1:8000> on the host.

## Collector smoke test

Only the collector command needs `sudo`:

```bash
mkdir -p var
sudo .venv/bin/ransomlab collect \
  --run-id collector-smoke \
  --duration-seconds 10 \
  > var/collector-smoke.jsonl

.venv/bin/ransomlab features \
  var/collector-smoke.jsonl \
  --output var/collector-smoke-features.jsonl
```

A usable recording ends with a successful `run_end` record and reports zero
event loss. Continue with the controlled capture workflow in
[TRAINING_GUIDE.md](TRAINING_GUIDE.md).
