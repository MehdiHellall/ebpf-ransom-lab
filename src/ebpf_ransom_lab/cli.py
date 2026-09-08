from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import threading
import time
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
from ebpf_ransom_lab.audit import audit_checkout, write_report
from ebpf_ransom_lab.artifacts import load_artifact, save_artifact
from ebpf_ransom_lab.detection import RuleScorer
from ebpf_ransom_lab.dataset import (
    build_labeled_windows,
    load_workload_manifest,
    read_feature_windows,
    write_labeled_windows,
)
from ebpf_ransom_lab.modeling import (
    evaluate_loaded_artifact,
    load_dataset,
    train_and_select,
)
from ebpf_ransom_lab.reference import load_manifest, verify_reference
from ebpf_ransom_lab.recording import read_jsonl, write_jsonl
from ebpf_ransom_lab.replay import replay_records
from ebpf_ransom_lab.service import create_app
from ebpf_ransom_lab.storage import Store
from ebpf_ransom_lab.workloads import (
    RUN_SEEDS,
    WorkloadLimits,
    build_experiment_manifest,
    run_workload,
    workload_run_manifest,
)
from ebpf_ransom_lab.contracts import RunStart, record_to_dict


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
    audit = subcommands.add_parser('audit', help='audit published research inputs and feature discrepancies')
    audit.add_argument('checkout', type=Path)
    audit.add_argument('--output', type=Path, default=Path('var/audit'))

    features = subcommands.add_parser(
        "features", help="generate fixed live-window features from a normalized recording"
    )
    features.add_argument("recording", type=Path)
    features.add_argument("--capture-start-ns", type=int)
    features.add_argument("--capture-end-ns", type=int)
    features.add_argument("--output", type=Path, required=True)

    replay = subcommands.add_parser(
        "replay", help="run a normalized recording through the rule dashboard path"
    )
    replay.add_argument("recording", type=Path)
    replay.add_argument("--capture-start-ns", type=int)
    replay.add_argument("--capture-end-ns", type=int)
    replay.add_argument("--database", type=Path, default=Path("var/runs.sqlite"))
    replay.add_argument("--threshold", type=float, default=4.0)

    serve = subcommands.add_parser("serve", help="serve the local read-only dashboard")
    serve.add_argument("--database", type=Path, default=Path("var/runs.sqlite"))
    serve.add_argument("--port", type=int, default=8000)
    serve.add_argument("--input", type=Path, help="normalized collector JSONL path, or - for standard input")
    serve.add_argument("--capture-start-ns", type=int)
    serve.add_argument("--threshold", type=float, default=4.0)

    collect = subcommands.add_parser(
        "collect", help="emit normalized live Linux records to standard output"
    )
    collect.add_argument("--run-id", required=True)
    collect.add_argument("--duration-seconds", type=float, default=60.0)
    collect.add_argument("--queue-limit", type=int, default=4096)
    collect.add_argument("--heartbeat-ms", type=int, default=1000)

    workload = subcommands.add_parser(
        "workload", help="plan or safely run a bounded controlled workload"
    )
    workload_commands = workload.add_subparsers(dest="workload_command", required=True)
    workload_plan = workload_commands.add_parser("plan", help="write the fixed 40-run plan")
    workload_plan.add_argument("--output", type=Path, default=Path("var/controlled-workloads.json"))
    workload_run = workload_commands.add_parser("run", help="run one fixed scenario in a fresh workspace")
    workload_run.add_argument("scenario")
    workload_run.add_argument("--seed", type=int, choices=RUN_SEEDS, required=True)
    workload_run.add_argument("--root", type=Path, default=Path("var/workloads"))
    workload_run.add_argument("--max-seconds", type=float, default=15.0)
    workload_run.add_argument("--max-files", type=int, default=256)
    workload_run.add_argument("--max-bytes", type=int, default=16 * 1024 * 1024)
    workload_run.add_argument("--hold-seconds", type=float, default=0.0)
    workload_run.add_argument("--manifest", type=Path)

    dataset = subcommands.add_parser(
        "dataset", help="build label-safe training rows from one controlled capture"
    )
    dataset_commands = dataset.add_subparsers(dest="dataset_command", required=True)
    dataset_build = dataset_commands.add_parser("build", help="join windows to an actual workload manifest")
    dataset_build.add_argument("features", type=Path)
    dataset_build.add_argument("manifest", type=Path)
    dataset_build.add_argument("--output", type=Path, required=True)

    train = subcommands.add_parser("train", help="train and select a controlled-workload model")
    train.add_argument("dataset", type=Path)
    train.add_argument("--output", type=Path, required=True)
    train.add_argument("--seed", type=int, default=37)

    evaluate = subcommands.add_parser("evaluate", help="evaluate a saved artifact without refitting")
    evaluate.add_argument("artifact", type=Path)
    evaluate.add_argument("dataset", type=Path)
    evaluate.add_argument("--split", choices=("training", "validation", "test"), default="test")

    report = subcommands.add_parser("report", help="export the reproducibility section of a model artifact")
    report.add_argument("artifact", type=Path)
    report.add_argument("--output", type=Path, required=True)
    return parser


def run(
    argv: Sequence[str] | None = None,
    *,
    stdout: TextIO = sys.stdout,
    doctor_context: DoctorContext | None = None,
) -> int:
    arguments = build_parser().parse_args(argv)
    if arguments.command == "features":
        return _features(arguments, stdout)
    if arguments.command == "replay":
        return _replay(arguments, stdout)
    if arguments.command == "serve":
        return _serve(arguments, stdout)
    if arguments.command == "collect":
        return _collect(arguments, stdout)
    if arguments.command == "workload":
        return _workload(arguments, stdout)
    if arguments.command == "dataset":
        return _dataset(arguments, stdout)
    if arguments.command == "train":
        return _train(arguments, stdout)
    if arguments.command == "evaluate":
        return _evaluate(arguments, stdout)
    if arguments.command == "report":
        return _report(arguments, stdout)
    if arguments.command == 'audit':
        try:
            report = audit_checkout(arguments.checkout)
            write_report(report, arguments.output, checkout=arguments.checkout)
        except (OSError, ValueError) as error:
            print(f'Audit error: {error}', file=stdout)
            return 2
        print(f"Audit {'PASS' if report['ok'] else 'FAIL'}: {arguments.output / 'audit.json'}", file=stdout)
        print(f"Differences: {arguments.output / 'feature_differences.csv'}", file=stdout)
        print('Paper results: not reproduced. Corrected published experiment: blocked.', file=stdout)
        return 0 if report['ok'] else 1
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


def _features(arguments: argparse.Namespace, stdout: TextIO) -> int:
    try:
        windows = replay_records(
            read_jsonl(arguments.recording),
            capture_start_ns=arguments.capture_start_ns,
            capture_end_ns=arguments.capture_end_ns,
        )
        write_jsonl(arguments.output, windows)
    except (OSError, RuntimeError, ValueError) as error:
        print(f"Features error: {error}", file=stdout)
        return 2
    print(f"Features complete: {len(windows)} windows -> {arguments.output}", file=stdout)
    return 0


def _replay(arguments: argparse.Namespace, stdout: TextIO) -> int:
    try:
        records = read_jsonl(arguments.recording)
        capture_start = (
            arguments.capture_start_ns
            if arguments.capture_start_ns is not None
            else _recorded_capture_start(records)
        )
        windows = replay_records(
            records,
            capture_start_ns=capture_start,
            capture_end_ns=arguments.capture_end_ns,
        )
        run_id = _run_id(records)
        store = Store(arguments.database)
        store.initialize()
        store.upsert_run(run_id, source="replay", started_ns=capture_start, status="complete")
        scorer = RuleScorer(arguments.threshold)
        alerts = 0
        for window in windows:
            prediction = scorer.predict(window)
            store.upsert_window(window)
            store.upsert_prediction(prediction)
            if prediction.suspicious:
                store.create_alert(prediction, window)
                alerts += 1
        store.update_health(connected=False, event_rate=0.0, lost_events=0, recording=False, error=None)
    except (OSError, RuntimeError, ValueError) as error:
        print(f"Replay error: {error}", file=stdout)
        return 2
    print(
        f"Replay complete: {len(windows)} windows, {alerts} rule alerts -> {arguments.database}",
        file=stdout,
    )
    return 0


def _serve(arguments: argparse.Namespace, stdout: TextIO) -> int:
    if not 1 <= arguments.port <= 65535:
        print("Serve error: port must be between 1 and 65535", file=stdout)
        return 2
    # The host is intentionally not configurable: the dashboard is accessed via
    # the documented localhost SSH tunnel rather than exposed on the network.
    import uvicorn

    source = None
    if arguments.input is not None:
        try:
            source = sys.stdin if str(arguments.input) == "-" else arguments.input.open(encoding="utf-8")
        except OSError as error:
            print(f"Serve error: {error}", file=stdout)
            return 2
        from ebpf_ransom_lab.ingestion import ingest_jsonl_stream

        def consume() -> None:
            try:
                ingest_jsonl_stream(
                    source, Store(arguments.database),
                    capture_start_ns=arguments.capture_start_ns, threshold=arguments.threshold,
                )
            finally:
                if source is not sys.stdin:
                    source.close()

        threading.Thread(target=consume, name="ransomlab-ingestion", daemon=True).start()

    print(f"Dashboard: http://127.0.0.1:{arguments.port}", file=stdout)
    uvicorn.run(create_app(arguments.database), host="127.0.0.1", port=arguments.port)
    return 0


def _collect(arguments: argparse.Namespace, stdout: TextIO) -> int:
    """Run the privileged BCC sensor while keeping stdout pipe-safe JSONL."""
    if os.name != "posix" or not hasattr(os, "geteuid") or os.geteuid() != 0:
        print("Collect error: live collection requires Linux root privileges", file=sys.stderr)
        return 2
    if not 0 < arguments.duration_seconds <= 300:
        print("Collect error: duration must be greater than 0 and no more than 300 seconds", file=sys.stderr)
        return 2
    if arguments.heartbeat_ms < 100 or arguments.heartbeat_ms > 10_000:
        print("Collect error: heartbeat must be between 100 and 10000 ms", file=sys.stderr)
        return 2
    try:
        from ebpf_ransom_lab.collector.adapter import CollectorProtocolAdapter, ProcessExitNotice
        from ebpf_ransom_lab.collector.runtime import BccCollector, CollectorConsumer, read_boot_id

        consumer = CollectorConsumer(
            run_id=arguments.run_id, boot_id=read_boot_id(), queue_limit=arguments.queue_limit
        )
        collector = BccCollector(consumer)
        adapter = CollectorProtocolAdapter()
        collector.start()
    except (ImportError, OSError, RuntimeError, ValueError) as error:
        print(f"Collect error: {error}", file=sys.stderr)
        return 2

    deadline = time.monotonic() + arguments.duration_seconds
    next_heartbeat = time.monotonic()
    try:
        _emit_record(RunStart(arguments.run_id, time.monotonic_ns(), source="live"), stdout)
        while time.monotonic() < deadline:
            collector.poll(timeout_ms=min(arguments.heartbeat_ms, 250))
            for event in consumer.drain():
                record = (
                    event.to_contract_event()
                    if event.event_type == "syscall"
                    else ProcessExitNotice.from_event(event).to_contract_record()
                )
                _emit_record(record, stdout)
            now = time.monotonic()
            if now >= next_heartbeat:
                health = collector.health(monotonic_ns=time.monotonic_ns())
                heartbeat = adapter.health_to_heartbeat(
                    health, collector_sequence=consumer.claim_sequence()
                )
                _emit_record(heartbeat, stdout)
                next_heartbeat = now + arguments.heartbeat_ms / 1000.0
        health = collector.health(monotonic_ns=time.monotonic_ns())
        _emit_record(
            adapter.health_to_heartbeat(health, collector_sequence=consumer.claim_sequence()),
            stdout,
        )
    except (RuntimeError, ValueError) as error:
        print(f"Collect error: {error}", file=sys.stderr)
        return 2
    finally:
        collector.stop()
    return 0


def _workload(arguments: argparse.Namespace, stdout: TextIO) -> int:
    try:
        if arguments.workload_command == "plan":
            if arguments.output.exists():
                raise FileExistsError(f"refusing to overwrite {arguments.output}")
            arguments.output.parent.mkdir(parents=True, exist_ok=True)
            arguments.output.write_text(
                json.dumps(build_experiment_manifest(), indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            print(f"Controlled workload plan: {arguments.output}", file=stdout)
            return 0
        arguments.root.mkdir(parents=True, exist_ok=True)
        result = run_workload(
            arguments.scenario, arguments.seed, arguments.root,
            limits=WorkloadLimits(arguments.max_seconds, arguments.max_files, arguments.max_bytes),
            hold_seconds=arguments.hold_seconds,
        )
        if arguments.manifest is not None:
            if arguments.manifest.exists():
                raise FileExistsError(f"refusing to overwrite {arguments.manifest}")
            arguments.manifest.parent.mkdir(parents=True, exist_ok=True)
            arguments.manifest.write_text(
                json.dumps(workload_run_manifest(result), indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
    except (OSError, RuntimeError, ValueError) as error:
        print(f"Workload error: {error}", file=stdout)
        return 2
    print(json.dumps(_workload_payload(result), sort_keys=True), file=stdout)
    return 0


def _dataset(arguments: argparse.Namespace, stdout: TextIO) -> int:
    try:
        windows = read_feature_windows(arguments.features)
        manifest = load_workload_manifest(arguments.manifest)
        rows = build_labeled_windows(
            windows, manifest, capture_hash=_sha256_file(arguments.features)
        )
        if not rows:
            raise ValueError("no complete windows matched the tracked workload process")
        write_labeled_windows(arguments.output, rows)
    except (OSError, RuntimeError, ValueError, FileExistsError) as error:
        print(f"Dataset error: {error}", file=stdout)
        return 2
    print(f"Dataset complete: {len(rows)} labeled windows -> {arguments.output}", file=stdout)
    return 0


def _train(arguments: argparse.Namespace, stdout: TextIO) -> int:
    try:
        with arguments.dataset.open(encoding="utf-8") as stream:
            samples = load_dataset(stream)
        result = train_and_select(samples, random_seed=arguments.seed)
        save_artifact(arguments.output, result)
    except (OSError, RuntimeError, ValueError, FileExistsError) as error:
        print(f"Train error: {error}", file=stdout)
        return 2
    print(json.dumps({
        "artifact": str(arguments.output), "model": result.selected_name,
        "threshold": result.threshold, "test_metrics": dict(result.test_metrics),
    }, sort_keys=True), file=stdout)
    return 0


def _evaluate(arguments: argparse.Namespace, stdout: TextIO) -> int:
    try:
        artifact = load_artifact(arguments.artifact)
        with arguments.dataset.open(encoding="utf-8") as stream:
            samples = tuple(sample for sample in load_dataset(stream) if sample.split == arguments.split)
        metrics = evaluate_loaded_artifact(artifact, samples)
    except (OSError, RuntimeError, ValueError) as error:
        print(f"Evaluate error: {error}", file=stdout)
        return 2
    print(json.dumps({"split": arguments.split, "metrics": metrics}, sort_keys=True), file=stdout)
    return 0


def _report(arguments: argparse.Namespace, stdout: TextIO) -> int:
    try:
        # Validate the artifact before exporting any of its user-visible claims.
        load_artifact(arguments.artifact)
        source = arguments.artifact / "manifest.json"
        manifest = json.loads(source.read_text(encoding="utf-8"))
        if arguments.output.exists():
            raise FileExistsError(f"refusing to overwrite {arguments.output}")
        payload = {
            "artifact_version": manifest["artifact_version"],
            "model": manifest["model_name"],
            "training_manifest_hash": manifest["training_manifest_hash"],
            "validation_metrics": manifest["validation_metrics"],
            "test_metrics": manifest["test_metrics"],
            "report_sections": manifest["report_sections"],
        }
        arguments.output.parent.mkdir(parents=True, exist_ok=True)
        arguments.output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    except (OSError, RuntimeError, ValueError, KeyError, FileExistsError) as error:
        print(f"Report error: {error}", file=stdout)
        return 2
    print(f"Report exported: {arguments.output}", file=stdout)
    return 0


def _run_id(records: Sequence[object]) -> str:
    run_ids = {getattr(record, "run_id", None) for record in records}
    run_ids.discard(None)
    if len(run_ids) != 1:
        raise ValueError("recording must contain exactly one run ID")
    return next(iter(run_ids))


def _recorded_capture_start(records: Sequence[object]) -> int | None:
    starts = tuple(record.capture_start_ns for record in records if isinstance(record, RunStart))
    if len(starts) > 1:
        raise ValueError("recording has multiple run-start records")
    return starts[0] if starts else None


def _workload_payload(result: object) -> dict[str, object]:
    return {
        "run_id": result.run_id,
        "scenario": result.scenario,
        "seed": result.seed,
        "split": result.split,
        "behavior_label": result.behavior_label,
        "workspace": str(result.workspace),
        "files_created": result.files_created,
        "bytes_written": result.bytes_written,
        "process": {
            "boot_id": result.process_identity.boot_id,
            "tgid": result.process_identity.tgid,
            "start_time_ns": result.process_identity.start_time_ns,
        },
    }


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _emit_record(record: object, stdout: TextIO) -> None:
    print(
        json.dumps(record_to_dict(record), sort_keys=True, separators=(",", ":"), ensure_ascii=False),
        file=stdout,
        flush=True,
    )


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
