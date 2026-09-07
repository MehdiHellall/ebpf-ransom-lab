from __future__ import annotations

import importlib.util
import os
import platform
import shutil
import sys
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Iterable


MINIMUM_PYTHON = (3, 11)
MINIMUM_FREE_BYTES = 5 * 1024**3
MINIMUM_RING_BUFFER_KERNEL = (5, 8)
TRACEPOINT_NAMES = (
    "sys_enter_openat",
    "sys_exit_openat",
    "sys_enter_unlinkat",
    "sys_exit_unlinkat",
)
TRACEPOINT_BASES = (
    "/sys/kernel/debug/tracing/events/syscalls",
    "/sys/kernel/tracing/events/syscalls",
)
TRACEPOINT_GROUPS = tuple(
    tuple(f"{base}/{name}" for name in TRACEPOINT_NAMES) for base in TRACEPOINT_BASES
)
# Kept as the conventional debugfs paths for callers that build test contexts.
TRACEPOINTS = TRACEPOINT_GROUPS[0]


class Status(str, Enum):
    PASS = "pass"
    WARN = "warn"
    FAIL = "fail"


@dataclass(frozen=True)
class CheckResult:
    name: str
    status: Status
    message: str


@dataclass(frozen=True)
class DoctorContext:
    system: str
    python_version: tuple[int, int, int]
    kernel_release: str
    effective_uid: int | None
    free_bytes: int
    available_modules: frozenset[str]
    existing_paths: frozenset[str]
    data_directory_writable: bool

    @classmethod
    def from_host(cls, data_directory: Path) -> "DoctorContext":
        kernel_release = platform.release()
        candidate_paths = {
            "/sys/kernel/btf/vmlinux",
            f"/lib/modules/{kernel_release}/build",
            *(path for group in TRACEPOINT_GROUPS for path in group),
        }
        storage_path = _nearest_existing_parent(data_directory)
        module_names = {
            name for name in ("bcc",) if importlib.util.find_spec(name) is not None
        }
        effective_uid = os.geteuid() if hasattr(os, "geteuid") else None
        return cls(
            system=platform.system(),
            python_version=tuple(sys.version_info[:3]),
            kernel_release=kernel_release,
            effective_uid=effective_uid,
            free_bytes=shutil.disk_usage(storage_path).free,
            available_modules=frozenset(module_names),
            existing_paths=frozenset(
                path for path in candidate_paths if Path(path).exists()
            ),
            data_directory_writable=os.access(storage_path, os.W_OK),
        )


def _nearest_existing_parent(path: Path) -> Path:
    candidate = path.expanduser().resolve()
    while not candidate.exists() and candidate != candidate.parent:
        candidate = candidate.parent
    return candidate


def evaluate_doctor(context: DoctorContext, scope: str) -> tuple[CheckResult, ...]:
    if scope not in {"app", "collector", "all"}:
        raise ValueError(f"unsupported doctor scope: {scope}")

    checks: list[CheckResult] = []
    if scope in {"app", "all"}:
        checks.extend(_application_checks(context))
    if scope in {"collector", "all"}:
        checks.extend(_collector_checks(context))
    return tuple(checks)


def overall_status(checks: Iterable[CheckResult]) -> Status:
    statuses = {check.status for check in checks}
    if Status.FAIL in statuses:
        return Status.FAIL
    if Status.WARN in statuses:
        return Status.WARN
    return Status.PASS


def _application_checks(context: DoctorContext) -> tuple[CheckResult, ...]:
    python_ok = context.python_version[:2] >= MINIMUM_PYTHON
    python_status = Status.PASS if python_ok else Status.FAIL
    python_message = (
        f"Python {'.'.join(map(str, context.python_version))}; "
        f"requires {MINIMUM_PYTHON[0]}.{MINIMUM_PYTHON[1]} or newer"
    )

    storage_status = (
        Status.PASS if context.free_bytes >= MINIMUM_FREE_BYTES else Status.WARN
    )
    storage_message = (
        f"{context.free_bytes / 1024**3:.1f} GiB free; "
        f"{MINIMUM_FREE_BYTES / 1024**3:.0f} GiB recommended"
    )

    writable_status = Status.PASS if context.data_directory_writable else Status.FAIL
    writable_message = (
        "data directory is writable"
        if context.data_directory_writable
        else "data directory is not writable"
    )
    return (
        CheckResult("python", python_status, python_message),
        CheckResult("storage", storage_status, storage_message),
        CheckResult("data_directory", writable_status, writable_message),
    )


def _collector_checks(context: DoctorContext) -> tuple[CheckResult, ...]:
    is_linux = context.system == "Linux"
    platform_result = CheckResult(
        "collector_platform",
        Status.PASS if is_linux else Status.FAIL,
        f"detected {context.system}; live collection requires Linux",
    )

    is_root = context.effective_uid == 0
    privilege_result = CheckResult(
        "collector_privileges",
        Status.PASS if is_root else Status.FAIL,
        "running as root" if is_root else "collector must run as root",
    )

    has_bcc = "bcc" in context.available_modules
    bcc_result = CheckResult(
        "bcc",
        Status.PASS if has_bcc else Status.FAIL,
        "Python BCC bindings available" if has_bcc else "Python BCC bindings missing",
    )

    btf_path = "/sys/kernel/btf/vmlinux"
    has_btf = btf_path in context.existing_paths
    btf_result = CheckResult(
        "kernel_btf",
        Status.PASS if has_btf else Status.FAIL,
        "kernel BTF available" if has_btf else f"missing {btf_path}",
    )

    headers_path = f"/lib/modules/{context.kernel_release}/build"
    has_headers = headers_path in context.existing_paths
    headers_result = CheckResult(
        "kernel_headers",
        Status.PASS if has_headers else Status.FAIL,
        "matching kernel headers available"
        if has_headers
        else f"missing {headers_path}",
    )

    tracepoint_group = max(
        TRACEPOINT_GROUPS,
        key=lambda group: sum(path in context.existing_paths for path in group),
    )
    missing_tracepoints = [
        path for path in tracepoint_group if path not in context.existing_paths
    ]
    tracepoint_result = CheckResult(
        "tracepoints",
        Status.PASS if not missing_tracepoints else Status.FAIL,
        "required syscall tracepoints available"
        if not missing_tracepoints
        else "missing tracepoints: " + ", ".join(missing_tracepoints),
    )

    kernel_version = _kernel_version(context.kernel_release)
    has_ring_buffer = is_linux and kernel_version >= MINIMUM_RING_BUFFER_KERNEL
    ring_buffer_result = CheckResult(
        "ring_buffer",
        Status.PASS if has_ring_buffer else Status.FAIL,
        "kernel supports BPF ring buffers"
        if has_ring_buffer
        else "BPF ring buffers require Linux 5.8 or newer",
    )
    return (
        platform_result,
        privilege_result,
        bcc_result,
        btf_result,
        headers_result,
        tracepoint_result,
        ring_buffer_result,
    )


def _kernel_version(release: str) -> tuple[int, int]:
    version = release.split("-", maxsplit=1)[0]
    pieces = version.split(".")
    major = _int_or_zero(pieces[0]) if pieces else 0
    minor = _int_or_zero(pieces[1]) if len(pieces) > 1 else 0
    return major, minor


def _int_or_zero(value: str) -> int:
    return int(value) if value.isdigit() else 0
