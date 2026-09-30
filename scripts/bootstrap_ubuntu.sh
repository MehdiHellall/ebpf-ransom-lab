#!/usr/bin/env bash
set -euo pipefail

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "This script must run on the Ubuntu lab VM." >&2
  exit 1
fi

sudo apt-get update
sudo apt-get install -y \
  bpfcc-tools \
  clang \
  git \
  libbpfcc-dev \
  linux-headers-"$(uname -r)" \
  llvm \
  python3-coverage \
  python3-bpfcc \
  python3-pip \
  python3-setuptools \
  python3-venv

python3 -m venv --system-site-packages .venv
.venv/bin/python -m pip install --require-hashes -r requirements.lock
.venv/bin/python -m pip install --no-build-isolation --no-deps -e .

mkdir -p var
{
  echo "# Lab dependency versions"
  date --iso-8601=seconds
  uname -a
  echo
  .venv/bin/python --version
  .venv/bin/python -m pip freeze
  echo
  apt-cache policy \
    bpfcc-tools \
    libbpfcc-dev \
    linux-headers-"$(uname -r)" \
    python3-bpfcc
} > var/lab_versions.txt

echo "Ubuntu lab dependencies installed."
echo "Recorded dependency versions in var/lab_versions.txt"
echo "Run: .venv/bin/ransomlab doctor --scope app"
echo "Run: sudo .venv/bin/ransomlab doctor --scope collector"
