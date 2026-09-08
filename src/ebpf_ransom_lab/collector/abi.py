"""Explicit C/Python ABI for records copied from the BPF ring buffer."""

from __future__ import annotations

import ctypes

from .protocol import FilenameBytes, NormalizedEvent, ProcessIdentity


FILENAME_CAPACITY = 256
EVENT_KIND_SYSCALL = 1
EVENT_KIND_PROCESS_EXIT = 2
EVENT_KIND_MASK = 0x7F
EVENT_FLAG_FILENAME_TRUNCATED = 0x80

OPERATION_NAMES = {
    1: "open",
    2: "openat",
    3: "unlink",
    4: "unlinkat",
    5: "process_exit",
}


class KernelEvent(ctypes.Structure):
    """Mirror of ``struct event_t`` in :mod:`bcc_source`."""

    _fields_ = [
        ("monotonic_ns", ctypes.c_uint64),
        ("process_start_ns", ctypes.c_uint64),
        ("return_value", ctypes.c_int64),
        ("tgid", ctypes.c_uint32),
        ("tid", ctypes.c_uint32),
        ("open_flags", ctypes.c_uint32),
        ("filename_len", ctypes.c_uint16),
        ("operation", ctypes.c_uint8),
        ("event_kind", ctypes.c_uint8),
        ("filename", ctypes.c_uint8 * FILENAME_CAPACITY),
    ]


EVENT_ABI_SIZE = ctypes.sizeof(KernelEvent)


def decode_kernel_event(
    payload: bytes, *, run_id: str, boot_id: str, sequence: int
) -> NormalizedEvent:
    """Copy and validate one fixed-width BPF record."""

    if len(payload) != EVENT_ABI_SIZE:
        raise ValueError(
            f"kernel event ABI size is {len(payload)} bytes, expected {EVENT_ABI_SIZE}"
        )
    raw = KernelEvent.from_buffer_copy(payload)
    if raw.operation not in OPERATION_NAMES:
        raise ValueError(f"unknown kernel operation code: {raw.operation}")
    if raw.filename_len > FILENAME_CAPACITY:
        raise ValueError(
            f"invalid kernel filename length: {raw.filename_len} > {FILENAME_CAPACITY}"
        )
    if raw.process_start_ns == 0:
        raise ValueError("kernel process start time is unavailable")
    event_kind = raw.event_kind & EVENT_KIND_MASK
    identity = ProcessIdentity(
        boot_id=boot_id,
        tgid=raw.tgid,
        start_time_ns=raw.process_start_ns,
    )
    if event_kind == EVENT_KIND_PROCESS_EXIT:
        if raw.operation != 5:
            raise ValueError("process-exit event has a non-exit operation")
        if raw.tid != raw.tgid:
            raise ValueError("process-exit event must describe the group leader")
        return NormalizedEvent.process_exit(
            run_id=run_id,
            sequence=sequence,
            monotonic_ns=raw.monotonic_ns,
            identity=identity,
            tid=raw.tid,
        )
    if event_kind != EVENT_KIND_SYSCALL or raw.operation == 5:
        raise ValueError(f"unknown kernel event kind: {event_kind}")
    filename = bytes(raw.filename[: raw.filename_len])
    return NormalizedEvent.syscall(
        run_id=run_id,
        sequence=sequence,
        monotonic_ns=raw.monotonic_ns,
        identity=identity,
        tid=raw.tid,
        operation=OPERATION_NAMES[raw.operation],
        return_value=raw.return_value,
        open_flags=raw.open_flags,
        filename=FilenameBytes.from_bytes(
            filename,
            truncated=bool(raw.event_kind & EVENT_FLAG_FILENAME_TRUNCATED),
        ),
    )
