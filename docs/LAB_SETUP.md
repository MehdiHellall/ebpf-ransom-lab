# Ubuntu lab setup

The live collector targets Ubuntu Server 24.04 LTS in a disposable VirtualBox
VM. Replay, audit, and most tests also run without privileged collection.

## VM profile

Recommended configuration:

- 4 virtual CPUs;
- 8 GB RAM;
- 40 GB dynamically allocated disk;
- NAT networking;
- OpenSSH Server enabled.

A 2 CPU and 4 GB RAM VM is sufficient for a slower run. Keep the repository on
the VM's Linux filesystem rather than in a VirtualBox shared folder.

## Install the environment

Clone the project into the VM and run:

```bash
bash scripts/bootstrap_ubuntu.sh
```

The script installs BCC, kernel headers, Clang/LLVM, Python tooling, and the
locked Python dependencies. It also writes resolved component versions to
`var/lab_versions.txt`.

Verify the application and collector environments:

```bash
.venv/bin/ransomlab doctor --scope app
sudo .venv/bin/ransomlab doctor --scope collector
```

Authorize `sudo` and run the complete portable plus live-collector gate:

```bash
sudo -v
scripts/ubuntu_bcc_gate.sh
```

Do not begin controlled captures until the script reports
`Ubuntu/BCC integration gate passed.`

The collector check covers privileges, BCC bindings, kernel headers, BTF, ring
buffer support, and the tracepoints used by the sensor.

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
