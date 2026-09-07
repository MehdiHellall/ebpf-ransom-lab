from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from importlib.resources import files
from pathlib import Path
from typing import Sequence, TextIO

from ebpf_ransom_lab.doctor import (
    DoctorContext,
    Status,
    evaluate_doctor,
    overall_status,
)
from ebpf_ransom_lab.reference import load_manifest, verify_reference


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ransomlab",
        description="Research tools for the eBPF ransomware-behavior detection lab.",
    )
    subcommands = parser.add_subparsers(dest="command", required=True)

    doctor = subcommands.add_parser("doctor", help="check environment prerequisites")
    doctor.add_argument("--scope", choices=("app", "collector", "all"), default="all")
    doctor.add_argument("--data-dir", type=Path, default=Path("var"))
    doctor.add_argument("--json", action="store_true", dest="as_json")

    reference = subcommands.add_parser("reference", help="verify frozen upstream evidence")
    reference_commands = reference.add_subparsers(dest="reference_command", required=True)
    verify = reference_commands.add_parser("verify", help="verify a checkout")
    verify.add_argument("checkout", type=Path)
    verify.add_argument("--manifest", type=Path)
    verify.add_argument("--json", action="store_true", dest="as_json")
    return parser


def run(
    argv: Sequence[str] | None = None,
    *,
    stdout: TextIO = sys.stdout,
    doctor_context: DoctorContext | None = None,
) -> int:
    arguments = build_parser().parse_args(argv)
    if arguments.command == "doctor":
        context = doctor_context or DoctorContext.from_host(arguments.data_dir)
        checks = evaluate_doctor(context, arguments.scope)
        summary = overall_status(checks)
        payload = {
            "scope": arguments.scope,
            "summary": summary.value,
            "checks": [
                {**asdict(check), "status": check.status.value} for check in checks
            ],
        }
        _print_payload(payload, arguments.as_json, stdout)
        return 1 if summary is Status.FAIL else 0

    manifest_path = arguments.manifest or Path(
        str(files("ebpf_ransom_lab").joinpath("data/ebpfangel.json"))
    )
    manifest = load_manifest(manifest_path)
    report = verify_reference(arguments.checkout, manifest)
    payload = {
        "ok": report.ok,
        "repository": report.repository,
        "expected_commit": report.expected_commit,
        "actual_commit": report.actual_commit,
        "commit_status": report.commit_status,
        "files": [asdict(item) for item in report.files],
    }
    _print_payload(payload, arguments.as_json, stdout)
    return 0 if report.ok else 1


def _print_payload(payload: dict[str, object], as_json: bool, stdout: TextIO) -> None:
    if as_json:
        print(json.dumps(payload, indent=2), file=stdout)
        return

    if "summary" in payload:
        print(f"Environment: {str(payload['summary']).upper()}", file=stdout)
        for check in payload["checks"]:
            print(
                f"[{check['status'].upper():4}] {check['name']}: {check['message']}",
                file=stdout,
            )
        return

    state = "PASS" if payload["ok"] else "FAIL"
    print(f"Upstream reference: {state}", file=stdout)
    print(
        f"Commit: {payload['commit_status']} "
        f"({payload['actual_commit']} / {payload['expected_commit']})",
        file=stdout,
    )
    for item in payload["files"]:
        print(f"[{item['status'].upper():8}] {item['path']}", file=stdout)


def main() -> None:
    raise SystemExit(run())
