"""Bounded, reproducible file workloads for controlled data collection.

Only paths produced under a newly-created workspace are accepted.  The public
runner executes the workload in a child process so collectors can label that
exact process without assigning labels to unrelated host activity.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import marshal
import math
import os
import random
import signal
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import Callable, Iterable, Mapping

from ebpf_ransom_lab.contracts import ProcessIdentity


RUN_SEEDS = (11, 23, 37, 41, 53)
MAX_WORKLOAD_SECONDS = 15.0
MAX_CAPTURE_HOLD_SECONDS = 60.0
EXPERIMENT_CAPTURE_SECONDS = 60.0
EXPERIMENT_WORKLOAD_HOLD_SECONDS = 50.0
MAX_WORKLOAD_FILES = 256
MAX_WORKLOAD_BYTES = 16 * 1024 * 1024
SPLIT_BY_SEED: Mapping[int, str] = MappingProxyType(
    {11: "training", 23: "training", 37: "training", 41: "validation", 53: "test"}
)
SCENARIOS: Mapping[str, str] = MappingProxyType(
    {
        "copying": "benign",
        "archiving": "benign",
        "compression": "benign",
        "small-build": "benign",
        "bulk-editing": "benign",
        "rapid-generated-file-replacement": "suspicious",
        "create-delete-churn": "suspicious",
        "paced-replacement": "suspicious",
    }
)


@dataclass(frozen=True)
class WorkloadLimits:
    """Cumulative limits for a single workload process."""

    max_seconds: float = MAX_WORKLOAD_SECONDS
    max_files: int = MAX_WORKLOAD_FILES
    max_bytes: int = MAX_WORKLOAD_BYTES

    def validate(self) -> None:
        if not isinstance(self.max_seconds, (int, float)) or not math.isfinite(
            self.max_seconds
        ):
            raise ValueError("workload max_seconds must be finite")
        if self.max_seconds <= 0 or self.max_seconds > MAX_WORKLOAD_SECONDS:
            raise ValueError(
                f"workload max_seconds must be between 0 and {MAX_WORKLOAD_SECONDS}"
            )
        if (
            not isinstance(self.max_files, int)
            or isinstance(self.max_files, bool)
            or self.max_files <= 0
            or self.max_files > MAX_WORKLOAD_FILES
        ):
            raise ValueError(
                f"workload max_files must be between 1 and {MAX_WORKLOAD_FILES}"
            )
        if (
            not isinstance(self.max_bytes, int)
            or isinstance(self.max_bytes, bool)
            or self.max_bytes <= 0
            or self.max_bytes > MAX_WORKLOAD_BYTES
        ):
            raise ValueError(
                f"workload max_bytes must be between 1 and {MAX_WORKLOAD_BYTES}"
            )


@dataclass(frozen=True)
class Action:
    """One deterministic, workspace-relative workload operation."""

    operation: str
    path: str = ""
    data: bytes = b""
    source: str = ""
    sources: tuple[str, ...] = ()
    delay_seconds: float = 0.0

    @property
    def paths(self) -> tuple[str, ...]:
        values = (self.path, self.source, *self.sources)
        return tuple(value for value in values if value)


@dataclass(frozen=True)
class WorkloadPlan:
    scenario: str
    seed: int
    actions: tuple[Action, ...]


@dataclass(frozen=True)
class LabelScope:
    kind: str
    root_identity: ProcessIdentity
    include_descendants: bool
    background_activity: str


@dataclass(frozen=True)
class WorkloadRun:
    run_id: str
    scenario: str
    seed: int
    split: str
    behavior_label: str
    plan_sha256: str
    workspace: Path
    status: str
    files_created: int
    bytes_written: int
    elapsed_seconds: float
    process_identity: ProcessIdentity
    label_scope: LabelScope
    limits: WorkloadLimits
    hold_seconds: float = 0.0


@dataclass(frozen=True)
class ExecutionStats:
    files_created: int
    bytes_written: int
    elapsed_seconds: float


class _Budget:
    def __init__(self, limits: WorkloadLimits, clock: Callable[[], float]) -> None:
        limits.validate()
        self.limits = limits
        self.clock = clock
        self.started = clock()
        self.files_created = 0
        self.bytes_written = 0

    @property
    def elapsed(self) -> float:
        return self.clock() - self.started

    @property
    def remaining_bytes(self) -> int:
        return self.limits.max_bytes - self.bytes_written

    def check_time(self, additional_seconds: float = 0.0) -> None:
        if additional_seconds < 0:
            raise ValueError("workload delay cannot be negative")
        if self.elapsed + additional_seconds > self.limits.max_seconds:
            raise RuntimeError("workload time limit exceeded")

    def reserve(self, *, files: int, byte_count: int) -> None:
        self.check_time()
        if files < 0 or byte_count < 0:
            raise ValueError("workload budget reservations cannot be negative")
        if self.files_created + files > self.limits.max_files:
            raise RuntimeError("workload file-count limit exceeded")
        if self.bytes_written + byte_count > self.limits.max_bytes:
            raise RuntimeError("workload byte limit exceeded")
        self.files_created += files
        self.bytes_written += byte_count

    def ensure_capacity(self, *, files: int, byte_count: int) -> None:
        """Check a pending allocation without charging it to the budget."""

        self.check_time()
        if self.files_created + files > self.limits.max_files:
            raise RuntimeError("workload file-count limit exceeded")
        if self.bytes_written + byte_count > self.limits.max_bytes:
            raise RuntimeError("workload byte limit exceeded")


def split_for_seed(seed: int) -> str:
    """Return the pre-assigned capture split for a controlled seed."""

    try:
        return SPLIT_BY_SEED[seed]
    except KeyError as error:
        raise ValueError(f"unsupported workload seed: {seed}") from error


def build_experiment_manifest() -> dict[str, object]:
    """Build the deterministic 8-scenario by 5-seed capture manifest."""

    runs: list[dict[str, object]] = []
    for scenario, behavior in SCENARIOS.items():
        for seed in RUN_SEEDS:
            plan_hash = plan_sha256(plan_workload(scenario, seed))
            runs.append(
                {
                    "run_id": f"controlled-{scenario}-seed-{seed}",
                    "source": "controlled_workload",
                    "scenario": scenario,
                    "workload_identity": f"{scenario}:seed={seed}",
                    "seed": seed,
                    "split": split_for_seed(seed),
                    "behavior_label": behavior,
                    "label_provenance": "controlled_workload",
                    "plan_sha256": plan_hash,
                    "label_scope": {
                        "kind": "process",
                        "root_identity": "recorded_at_workload_start",
                        "include_descendants": False,
                        "background_activity": "unlabeled",
                    },
                    "capture_duration_seconds": EXPERIMENT_CAPTURE_SECONDS,
                    "workload_hold_seconds": EXPERIMENT_WORKLOAD_HOLD_SECONDS,
                }
            )
    return {
        "schema_version": 1,
        "experiment": "controlled-workloads-v1",
        "split_policy": {
            "training": [11, 23, 37],
            "validation": [41],
            "test": [53],
        },
        "runs": runs,
    }


def workload_run_manifest(result: WorkloadRun) -> dict[str, object]:
    """Freeze actual runtime identity for label-safe dataset construction."""

    if not isinstance(result, WorkloadRun):
        raise ValueError("workload result is required")
    identity = result.process_identity
    return {
        "schema_version": 1,
        "run_id": result.run_id,
        "scenario": result.scenario,
        "seed": result.seed,
        "split": result.split,
        "behavior_label": result.behavior_label,
        "plan_sha256": result.plan_sha256,
        "label_provenance": "controlled_workload",
        "tracked_processes": [{
            "boot_id": identity.boot_id,
            "tgid": identity.tgid,
            "start_time_ns": identity.start_time_ns,
        }],
        "process_scope_policy": "root_process_only",
        "background_activity": "unlabeled",
        "workspace": str(result.workspace),
        "status": result.status,
        "workload_hold_seconds": result.hold_seconds,
        "limits": {
            "max_seconds": result.limits.max_seconds,
            "max_files": result.limits.max_files,
            "max_bytes": result.limits.max_bytes,
        },
    }


def plan_workload(scenario: str, seed: int) -> WorkloadPlan:
    """Return a deterministic plan without touching the filesystem."""

    if scenario not in SCENARIOS:
        raise ValueError(f"unknown workload scenario: {scenario}")
    split_for_seed(seed)
    rng = _scenario_random(scenario, seed)
    planner = _PLANNERS[scenario]
    return WorkloadPlan(scenario, seed, tuple(planner(rng)))


def plan_sha256(plan: WorkloadPlan) -> str:
    """Hash the complete plan using an unambiguous canonical representation."""

    actions = [
        {
            "operation": action.operation,
            "path": action.path,
            "data_hex": action.data.hex(),
            "source": action.source,
            "sources": list(action.sources),
            "delay_seconds": action.delay_seconds,
        }
        for action in plan.actions
    ]
    document = {"scenario": plan.scenario, "seed": plan.seed, "actions": actions}
    encoded = json.dumps(
        document, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def run_workload(
    scenario: str,
    seed: int,
    approved_root: Path,
    *,
    limits: WorkloadLimits | None = None,
    hold_seconds: float = 0.0,
) -> WorkloadRun:
    """Run one scenario in a new child process and generated workspace."""

    ensure_unprivileged_workload()
    selected_limits = limits or WorkloadLimits()
    selected_limits.validate()
    _validate_hold_seconds(hold_seconds)
    plan = plan_workload(scenario, seed)
    root = _validate_approved_root(approved_root)
    workspace = Path(tempfile.mkdtemp(prefix="workload-", dir=root))
    try:
        workspace.chmod(0o700)
    except OSError:
        pass
    _validate_workspace(root, workspace)

    command = [
        sys.executable,
        "-m",
        "ebpf_ransom_lab.workloads",
        "--internal-run",
        scenario,
        str(seed),
        str(root),
        str(workspace),
        str(selected_limits.max_seconds),
        str(selected_limits.max_files),
        str(selected_limits.max_bytes),
        str(hold_seconds),
    ]
    process_options: dict[str, object] = {}
    if os.name == "posix":
        process_options["start_new_session"] = True
    elif os.name == "nt":
        process_options["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP

    launched = time.monotonic()
    process = subprocess.Popen(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        **process_options,
    )
    try:
        stdout, stderr = process.communicate(
            timeout=selected_limits.max_seconds + hold_seconds + 2.0
        )
    except subprocess.TimeoutExpired as error:
        _terminate_process(process)
        process.communicate()
        raise RuntimeError("workload time limit exceeded") from error

    messages = [json.loads(line) for line in stdout.splitlines() if line.strip()]
    if process.returncode != 0 or not messages or messages[-1].get("status") != "completed":
        detail = messages[-1].get("error") if messages else stderr.strip()
        raise RuntimeError(f"workload execution failed: {detail or 'unknown error'}")
    result = messages[-1]
    identity_document = result["process_identity"]
    identity = ProcessIdentity(
        boot_id=str(identity_document["boot_id"]),
        tgid=int(identity_document["tgid"]),
        start_time_ns=int(identity_document["start_time_ns"]),
    )
    elapsed = min(float(result["elapsed_seconds"]), time.monotonic() - launched)
    return WorkloadRun(
        run_id=f"controlled-{scenario}-seed-{seed}",
        scenario=scenario,
        seed=seed,
        split=split_for_seed(seed),
        behavior_label=SCENARIOS[scenario],
        plan_sha256=plan_sha256(plan),
        workspace=workspace,
        status="completed",
        files_created=int(result["files_created"]),
        bytes_written=int(result["bytes_written"]),
        elapsed_seconds=elapsed,
        process_identity=identity,
        label_scope=LabelScope(
            kind="process",
            root_identity=identity,
            include_descendants=False,
            background_activity="unlabeled",
        ),
        limits=selected_limits,
        hold_seconds=hold_seconds,
    )


def execute_plan(
    plan: WorkloadPlan,
    approved_root: Path,
    workspace: Path,
    limits: WorkloadLimits | None = None,
    *,
    clock: Callable[[], float] = time.monotonic,
    sleeper: Callable[[float], None] = time.sleep,
) -> ExecutionStats:
    """Execute a plan in an already generated, validated workspace.

    This function is public to make containment and budget enforcement directly
    testable. Normal callers should use :func:`run_workload` for process isolation.
    """

    if plan.scenario not in SCENARIOS:
        raise ValueError(f"unknown workload scenario: {plan.scenario}")
    split_for_seed(plan.seed)
    root = _validate_approved_root(approved_root)
    safe_workspace = _validate_workspace(root, workspace)
    budget = _Budget(limits or WorkloadLimits(), clock)

    for index, action in enumerate(plan.actions):
        budget.check_time()
        _execute_action(action, index, safe_workspace, budget, sleeper)
        budget.check_time()
    return ExecutionStats(
        files_created=budget.files_created,
        bytes_written=budget.bytes_written,
        elapsed_seconds=budget.elapsed,
    )


def _execute_action(
    action: Action,
    index: int,
    workspace: Path,
    budget: _Budget,
    sleeper: Callable[[float], None],
) -> None:
    operation = action.operation
    if operation == "pause":
        budget.check_time(action.delay_seconds)
        sleeper(action.delay_seconds)
        return

    destination = _safe_workspace_path(workspace, action.path)
    if operation == "write":
        _bounded_write(destination, action.data, budget)
    elif operation == "copy":
        source = _safe_workspace_path(workspace, action.source)
        _bounded_write(destination, _bounded_read(source, budget), budget)
    elif operation == "archive":
        sources = tuple(
            _safe_workspace_path(workspace, source) for source in action.sources
        )
        _write_archive(destination, sources, workspace, budget)
    elif operation == "compress":
        source = _safe_workspace_path(workspace, action.source)
        _write_compressed(destination, _bounded_read(source, budget), budget)
    elif operation == "compile":
        source = _safe_workspace_path(workspace, action.source)
        source_bytes = _bounded_read(source, budget)
        code = compile(source_bytes, action.source, "exec")
        _bounded_write(destination, marshal.dumps(code), budget)
    elif operation == "replace":
        temporary = _safe_workspace_path(
            workspace, f".replacement-{index:04d}.tmp"
        )
        _bounded_write(temporary, action.data, budget)
        _assert_not_symlink(destination)
        os.replace(temporary, destination)
    elif operation == "delete":
        _assert_not_symlink(destination)
        if destination.exists():
            if not destination.is_file():
                raise ValueError(f"workload target is not a regular file: {action.path}")
            destination.unlink()
    else:
        raise ValueError(f"unsupported workload action: {operation}")


def _bounded_write(path: Path, data: bytes, budget: _Budget) -> None:
    _ensure_safe_parent(path)
    _assert_not_symlink(path)
    budget.reserve(files=1, byte_count=len(data))
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as stream:
            descriptor = -1
            stream.write(data)
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _bounded_read(path: Path, budget: _Budget) -> bytes:
    budget.check_time()
    _assert_not_symlink(path)
    if not path.is_file():
        raise ValueError(f"workload source is not a regular file: {path.name}")
    size = path.stat().st_size
    if size > budget.remaining_bytes:
        raise RuntimeError("workload byte limit exceeded")
    return path.read_bytes()


def _write_archive(
    destination: Path,
    sources: tuple[Path, ...],
    workspace: Path,
    budget: _Budget,
) -> None:
    source_sizes = tuple(_bounded_source_size(source, budget) for source in sources)
    # USTAR uses one 512-byte header per member, padded 512-byte data blocks,
    # two end blocks, and 10 KiB record padding. Check before allocating BytesIO.
    blocks = 2 + sum(1 + ((size + 511) // 512) for size in source_sizes)
    archive_size = ((blocks + 19) // 20) * 20 * 512
    budget.ensure_capacity(files=1, byte_count=archive_size)
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for source in sources:
            data = _bounded_read(source, budget)
            relative = source.relative_to(workspace).as_posix()
            info = tarfile.TarInfo(relative)
            info.size = len(data)
            info.mode = 0o600
            info.mtime = 0
            archive.addfile(info, io.BytesIO(data))
    _bounded_write(destination, output.getvalue(), budget)


def _bounded_source_size(path: Path, budget: _Budget) -> int:
    budget.check_time()
    _assert_not_symlink(path)
    if not path.is_file():
        raise ValueError(f"workload source is not a regular file: {path.name}")
    size = path.stat().st_size
    if size > budget.remaining_bytes:
        raise RuntimeError("workload byte limit exceeded")
    return size


def _write_compressed(destination: Path, data: bytes, budget: _Budget) -> None:
    output = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=output, mtime=0) as stream:
        stream.write(data)
    _bounded_write(destination, output.getvalue(), budget)


def _validate_approved_root(approved_root: Path) -> Path:
    absolute = _absolute_without_resolving(Path(approved_root))
    _reject_symlink_components(absolute, require_exists=True)
    if not absolute.is_dir():
        raise ValueError(f"approved workload root is not a directory: {approved_root}")
    return absolute.resolve(strict=True)


def _validate_workspace(approved_root: Path, workspace: Path) -> Path:
    absolute = _absolute_without_resolving(Path(workspace))
    _reject_symlink_components(absolute, require_exists=True)
    resolved = absolute.resolve(strict=True)
    if resolved.parent != approved_root or not resolved.name.startswith("workload-"):
        raise ValueError("workload workspace escaped approved root")
    if not resolved.is_dir():
        raise ValueError("workload workspace is not a directory")
    return resolved


def _absolute_without_resolving(path: Path) -> Path:
    return Path(os.path.abspath(os.fspath(path.expanduser())))


def _reject_symlink_components(path: Path, *, require_exists: bool) -> None:
    components = (Path(path.anchor),) if path.anchor else ()
    current = components[0] if components else Path()
    parts = path.parts[1:] if path.anchor else path.parts
    for part in parts:
        current = current / part
        try:
            mode = current.lstat().st_mode
        except FileNotFoundError:
            if require_exists:
                raise ValueError(f"workload path does not exist: {current}")
            return
        if stat.S_ISLNK(mode):
            raise ValueError(f"symlink is not allowed in workload path: {current}")


def _safe_workspace_path(workspace: Path, relative_path: str) -> Path:
    if not relative_path or "\\" in relative_path:
        raise ValueError(f"unsafe workload path: {relative_path}")
    pure = PurePosixPath(relative_path)
    if pure.is_absolute() or any(part in {"", ".", ".."} for part in pure.parts):
        raise ValueError(f"unsafe workload path: {relative_path}")
    candidate = workspace.joinpath(*pure.parts)
    _reject_symlink_components(candidate, require_exists=False)
    resolved = candidate.resolve(strict=False)
    try:
        resolved.relative_to(workspace)
    except ValueError as error:
        raise ValueError(f"workload path escaped workspace: {relative_path}") from error
    return candidate


def _ensure_safe_parent(path: Path) -> None:
    workspace = next(
        (parent for parent in path.parents if parent.name.startswith("workload-")),
        None,
    )
    if workspace is None:
        raise ValueError("workload destination has no generated workspace")
    relative_parent = path.parent.relative_to(workspace)
    current = workspace
    for part in relative_parent.parts:
        current = current / part
        if current.exists():
            _assert_not_symlink(current)
            if not current.is_dir():
                raise ValueError(f"workload parent is not a directory: {current}")
        else:
            current.mkdir(mode=0o700)


def _assert_not_symlink(path: Path) -> None:
    try:
        mode = path.lstat().st_mode
    except FileNotFoundError:
        return
    if stat.S_ISLNK(mode):
        raise ValueError(f"symlink is not allowed in workload path: {path}")


def _scenario_random(scenario: str, seed: int) -> random.Random:
    digest = hashlib.sha256(f"{scenario}:{seed}".encode("utf-8")).digest()
    return random.Random(int.from_bytes(digest, "big"))


def _random_bytes(rng: random.Random, size: int) -> bytes:
    return bytes(rng.getrandbits(8) for _ in range(size))


def _copying_plan(rng: random.Random) -> Iterable[Action]:
    for index in range(rng.randint(3, 16)):
        source = f"source/document-{index}.dat"
        yield Action("write", source, _random_bytes(rng, rng.randint(384, 1024)))
        yield Action("copy", f"copies/document-{index}.dat", source=source)


def _archiving_plan(rng: random.Random) -> Iterable[Action]:
    sources = tuple(
        f"archive-input/item-{index}.txt" for index in range(rng.randint(8, 40))
    )
    for source in sources:
        yield Action("write", source, _random_bytes(rng, rng.randint(256, 768)))
    yield Action("archive", "output/bundle.tar", sources=sources)


def _compression_plan(rng: random.Random) -> Iterable[Action]:
    for index in range(rng.randint(3, 20)):
        source = f"compression-input/log-{index}.txt"
        yield Action("write", source, _random_bytes(rng, rng.randint(512, 1536)))
        yield Action("compress", f"compressed/log-{index}.txt.gz", source=source)


def _small_build_plan(rng: random.Random) -> Iterable[Action]:
    salt = rng.randrange(1_000_000)
    for index in range(rng.randint(2, 10)):
        source = f"build/src/{salt:06d}/module_{index}.py"
        code = (
            f"BUILD_SALT = {salt}\n"
            f"def value_{index}():\n"
            f"    return BUILD_SALT + {index}\n"
        ).encode("utf-8")
        yield Action("write", source, code)
        yield Action("compile", f"build/out/{salt:06d}/module_{index}.pyc", source=source)


def _bulk_editing_plan(rng: random.Random) -> Iterable[Action]:
    for index in range(rng.randint(5, 12)):
        path = f"documents/note-{index}.txt"
        for _ in range(rng.randint(2, 5)):
            yield Action("write", path, _random_bytes(rng, rng.randint(128, 384)))


def _rapid_replacement_plan(rng: random.Random) -> Iterable[Action]:
    target = "generated/current.dat"
    yield Action("write", target, _random_bytes(rng, rng.randint(192, 512)))
    for _ in range(rng.randint(8, 40)):
        yield Action("replace", target, _random_bytes(rng, rng.randint(192, 512)))


def _churn_plan(rng: random.Random) -> Iterable[Action]:
    for index in range(rng.randint(12, 30)):
        path = f"churn/transient-{index:02d}.tmp"
        yield Action("write", path, _random_bytes(rng, rng.randint(64, 320)))
        yield Action("delete", path)


def _paced_replacement_plan(rng: random.Random) -> Iterable[Action]:
    target = "paced/current.dat"
    yield Action("write", target, _random_bytes(rng, rng.randint(192, 512)))
    for _ in range(rng.randint(6, 15)):
        yield Action("pause", delay_seconds=rng.uniform(0.01, 0.08))
        yield Action("replace", target, _random_bytes(rng, rng.randint(192, 512)))


_PLANNERS: Mapping[str, Callable[[random.Random], Iterable[Action]]] = MappingProxyType(
    {
        "copying": _copying_plan,
        "archiving": _archiving_plan,
        "compression": _compression_plan,
        "small-build": _small_build_plan,
        "bulk-editing": _bulk_editing_plan,
        "rapid-generated-file-replacement": _rapid_replacement_plan,
        "create-delete-churn": _churn_plan,
        "paced-replacement": _paced_replacement_plan,
    }
)


def _process_identity() -> ProcessIdentity:
    boot_id = "unavailable"
    boot_path = Path("/proc/sys/kernel/random/boot_id")
    try:
        boot_id = boot_path.read_text(encoding="ascii").strip()
    except OSError:
        pass

    process_start_ns = time.monotonic_ns()
    stat_path = Path(f"/proc/{os.getpid()}/stat")
    try:
        stat_line = stat_path.read_text(encoding="ascii")
        start_ticks = int(stat_line[stat_line.rfind(")") + 2 :].split()[19])
        ticks_per_second = int(os.sysconf("SC_CLK_TCK"))
        process_start_ns = start_ticks * 1_000_000_000 // ticks_per_second
    except (OSError, ValueError, IndexError, AttributeError):
        pass
    return ProcessIdentity(boot_id, os.getpid(), process_start_ns)


def _effective_uid() -> int | None:
    return os.geteuid() if hasattr(os, "geteuid") else None


def ensure_unprivileged_workload() -> None:
    """Fail before mutation when a workload is invoked with root privileges."""

    if _effective_uid() == 0:
        raise PermissionError("controlled workloads must run as an ordinary user")


def _validate_hold_seconds(value: float) -> None:
    if not isinstance(value, (int, float)) or isinstance(value, bool) or not math.isfinite(value):
        raise ValueError("hold_seconds must be a finite number")
    if value < 0 or value > MAX_CAPTURE_HOLD_SECONDS:
        raise ValueError(
            f"hold_seconds must be between 0 and {MAX_CAPTURE_HOLD_SECONDS}"
        )


def _terminate_process(process: subprocess.Popen[str]) -> None:
    if process.poll() is not None:
        return
    if os.name == "posix":
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            return
    elif os.name == "nt":
        subprocess.run(
            ["taskkill", "/PID", str(process.pid), "/T", "/F"],
            check=False,
            capture_output=True,
            timeout=2,
        )
    else:
        process.terminate()
    try:
        process.wait(timeout=1)
    except subprocess.TimeoutExpired:
        if os.name == "posix":
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        else:
            process.kill()


def _internal_run(arguments: argparse.Namespace) -> int:
    try:
        ensure_unprivileged_workload()
        identity = _process_identity()
        limits = WorkloadLimits(arguments.max_seconds, arguments.max_files, arguments.max_bytes)
        plan = plan_workload(arguments.scenario, arguments.seed)
        stats = execute_plan(
            plan, Path(arguments.approved_root), Path(arguments.workspace), limits
        )
        _validate_hold_seconds(arguments.hold_seconds)
        if arguments.hold_seconds:
            time.sleep(arguments.hold_seconds)
        document: dict[str, object] = {
            "status": "completed",
            "process_identity": {
                "boot_id": identity.boot_id,
                "tgid": identity.tgid,
                "start_time_ns": identity.start_time_ns,
            },
            "files_created": stats.files_created,
            "bytes_written": stats.bytes_written,
            "elapsed_seconds": stats.elapsed_seconds + arguments.hold_seconds,
        }
        print(json.dumps(document, sort_keys=True), flush=True)
        return 0
    except (OSError, ValueError, RuntimeError) as error:
        print(
            json.dumps({"status": "failed", "error": str(error)}, sort_keys=True),
            flush=True,
        )
        return 2


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--internal-run", dest="scenario")
    parser.add_argument("seed", type=int)
    parser.add_argument("approved_root")
    parser.add_argument("workspace")
    parser.add_argument("max_seconds", type=float)
    parser.add_argument("max_files", type=int)
    parser.add_argument("max_bytes", type=int)
    parser.add_argument("hold_seconds", type=float)
    return parser


def _main(argv: list[str] | None = None) -> int:
    return _internal_run(_parser().parse_args(argv))


if __name__ == "__main__":
    raise SystemExit(_main())
