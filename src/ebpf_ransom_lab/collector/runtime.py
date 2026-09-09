"""BCC runtime adapter with a portable, bounded consumer."""

from __future__ import annotations

import ctypes
import importlib
import os
import re
from collections import deque
from dataclasses import replace
from pathlib import Path
from threading import Lock
from typing import Any

from .abi import decode_kernel_event
from .bcc_source import BCC_SOURCE
from .protocol import CollectorHealth, LossCounters, NormalizedEvent


BOOT_ID_PATH = Path("/proc/sys/kernel/random/boot_id")
NSEC_PER_SECOND = 1_000_000_000
MAX_QUEUE_LIMIT = 65_536
RUN_ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")


class CollectorUnavailableError(RuntimeError):
    """Raised when the Linux-only BCC runtime cannot be loaded."""


def read_boot_id(path: Path = BOOT_ID_PATH) -> str:
    try:
        boot_id = path.read_text(encoding="ascii").strip()
    except (OSError, UnicodeError) as error:
        raise CollectorUnavailableError(f"cannot read Linux boot ID from {path}") from error
    if not boot_id:
        raise CollectorUnavailableError(f"Linux boot ID is empty: {path}")
    return boot_id


def _user_hz() -> int:
    """Return the /proc process-start resolution accepted by the BPF source."""

    reader = getattr(os, "sysconf", None)
    if reader is None:
        # BCC cannot be used from this host, but retaining the Linux default
        # keeps the isolated runtime adapter portable-testable.
        return 100
    try:
        value = reader("SC_CLK_TCK")
    except (OSError, ValueError) as error:
        raise CollectorUnavailableError("cannot determine Linux USER_HZ") from error
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise CollectorUnavailableError("Linux USER_HZ is invalid")
    if NSEC_PER_SECOND % value:
        raise CollectorUnavailableError("Linux USER_HZ cannot canonically represent process starts")
    return value


class CollectorConsumer:
    """Validate kernel records before placing them on a bounded user-space queue."""

    def __init__(self, *, run_id: str, boot_id: str, queue_limit: int) -> None:
        if not isinstance(run_id, str) or RUN_ID_PATTERN.fullmatch(run_id) is None:
            raise ValueError("run_id must be 1-128 characters using letters, numbers, dots, underscores, colons, or dashes")
        if (
            not isinstance(queue_limit, int)
            or isinstance(queue_limit, bool)
            or queue_limit < 1
            or queue_limit > MAX_QUEUE_LIMIT
        ):
            raise ValueError(f"queue_limit must be between 1 and {MAX_QUEUE_LIMIT}")
        self.run_id = run_id
        self.boot_id = boot_id
        self.queue_limit = queue_limit
        self._queue: deque[NormalizedEvent] = deque()
        self._counters = LossCounters()
        self._next_sequence = 1
        self._lock = Lock()

    def _increment(self, field: str, amount: int = 1) -> None:
        with self._lock:
            self._counters = replace(
                self._counters, **{field: getattr(self._counters, field) + amount}
            )

    def consume_bytes(self, payload: bytes) -> bool:
        sequence = self.claim_sequence()
        try:
            event = decode_kernel_event(
                payload,
                run_id=self.run_id,
                boot_id=self.boot_id,
                sequence=sequence,
            )
        except (TypeError, ValueError):
            self._increment("consumer_decode_errors")
            return False

        with self._lock:
            if len(self._queue) >= self.queue_limit:
                self._counters = replace(
                    self._counters,
                    consumer_queue_drops=self._counters.consumer_queue_drops + 1,
                )
                return False
            self._queue.append(event)
            return True

    def claim_sequence(self) -> int:
        """Reserve the next stream position for an event or heartbeat."""

        with self._lock:
            sequence = self._next_sequence
            self._next_sequence += 1
            return sequence

    def drain(self) -> list[NormalizedEvent]:
        with self._lock:
            events = list(self._queue)
            self._queue.clear()
            return events

    def counters(self) -> LossCounters:
        with self._lock:
            return self._counters


class BccCollector:
    """Own the BCC program while leaving serialization to the caller."""

    def __init__(self, consumer: CollectorConsumer) -> None:
        self.consumer = consumer
        self.bpf: Any | None = None
        self.connected = False

    def start(self) -> None:
        if self.connected:
            raise RuntimeError("collector is already running")
        try:
            bcc = importlib.import_module("bcc")
        except ImportError as error:
            raise CollectorUnavailableError(
                "BCC Python bindings are required to start live collection"
            ) from error
        self.bpf = bcc.BPF(text=BCC_SOURCE, cflags=[f"-DUSER_HZ={_user_hz()}"])
        self.bpf["events"].open_ring_buffer(self._on_event)
        self.connected = True

    def _on_event(self, _context: Any, data: int, size: int) -> None:
        try:
            payload = ctypes.string_at(data, size)
        except (TypeError, ValueError, OSError):
            self.consumer._increment("consumer_decode_errors")
            return
        self.consumer.consume_bytes(payload)

    def poll(self, *, timeout_ms: int = 100) -> None:
        if not self.connected or self.bpf is None:
            raise RuntimeError("collector is not running")
        if not isinstance(timeout_ms, int) or isinstance(timeout_ms, bool) or timeout_ms < 0:
            raise ValueError("timeout_ms must be a non-negative integer")
        try:
            self.bpf.ring_buffer_poll(timeout_ms)
        except Exception as error:
            self.connected = False
            raise CollectorUnavailableError("collector polling failed") from error

    def stop(self) -> None:
        self.connected = False

    def _kernel_loss(self, index: int) -> int:
        if self.bpf is None:
            raise CollectorUnavailableError("kernel loss telemetry is unavailable")
        try:
            value = self.bpf["loss_counters"][ctypes.c_uint(index)]
            raw = value.value if hasattr(value, "value") else value
        except Exception as error:
            raise CollectorUnavailableError("kernel loss telemetry is unreadable") from error
        if isinstance(raw, bool) or not isinstance(raw, int) or not 0 <= raw < 2**64:
            raise CollectorUnavailableError("kernel loss telemetry contains an invalid counter")
        return raw

    def health(self, *, monotonic_ns: int) -> CollectorHealth:
        user = self.consumer.counters()
        counters = replace(
            user,
            ring_buffer_reservation_failures=self._kernel_loss(0),
            pending_map_update_failures=self._kernel_loss(1),
            filename_read_failures=self._kernel_loss(2),
            identity_read_failures=self._kernel_loss(3),
        )
        return CollectorHealth(
            run_id=self.consumer.run_id,
            connected=self.connected,
            monotonic_ns=monotonic_ns,
            counters=counters,
        )
