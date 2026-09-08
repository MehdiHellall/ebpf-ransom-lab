"""Shared ten-second O/C/D window feature engine."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from itertools import product
from typing import Iterable

from ebpf_ransom_lab.contracts import (
    FEATURE_VERSION,
    Event,
    FeatureWindow,
    Heartbeat,
    ProcessExit,
    ProcessIdentity,
    StreamRecord,
)


SECOND_NS = 1_000_000_000
WINDOW_NS = 10 * SECOND_NS
OPERATIONS = ("O", "C", "D")
SEQUENCE_NAMES = tuple("".join(sequence) for sequence in product(OPERATIONS, repeat=3))
FEATURE_NAMES = tuple(f"{operation}_sum" for operation in OPERATIONS) + tuple(
    f"{operation}_max_1s" for operation in OPERATIONS
) + SEQUENCE_NAMES


@dataclass(frozen=True, slots=True)
class _WindowState:
    run_id: str
    process: ProcessIdentity
    start_ns: int
    events: tuple[Event, ...] = ()
    loss_count: int = 0
    late_event_count: int = 0
    partial: bool = False


WindowKey = tuple[ProcessIdentity, int]


class WindowFeatureEngine:
    """Incrementally produce immutable window views.

    Emitted records are snapshots. A late event produces a replacement with
    the same window ID; persistence layers should upsert it by that ID.
    """

    def __init__(self, capture_start_ns: int):
        if type(capture_start_ns) is not int or capture_start_ns < 0:
            raise ValueError("capture_start_ns must be a non-negative integer")
        self.capture_start_ns = capture_start_ns
        self._run_id: str | None = None
        self._watermark_ns = capture_start_ns
        self._active: dict[WindowKey, _WindowState] = {}
        self._closed: dict[WindowKey, _WindowState] = {}
        self._window_loss: dict[int, int] = {}
        self._seen_sequences: set[int] = set()

    @property
    def watermark_ns(self) -> int:
        return self._watermark_ns

    @property
    def windows(self) -> tuple[FeatureWindow, ...]:
        states = (*self._closed.values(), *self._active.values())
        return tuple(self._snapshot(state) for state in sorted(states, key=_state_order))

    def feed(self, records: Iterable[StreamRecord]) -> tuple[FeatureWindow, ...]:
        emitted: list[FeatureWindow] = []
        for record in records:
            if not isinstance(record, (Event, Heartbeat, ProcessExit)):
                raise ValueError("feature input must contain Event, Heartbeat, or ProcessExit records")
            if record.timestamp_ns < self.capture_start_ns:
                raise ValueError("record timestamp precedes capture start")
            self._accept_run(record.run_id)
            self._accept_sequence(record.collector_sequence)
            if isinstance(record, Heartbeat):
                emitted.extend(
                    self._record_loss(record.timestamp_ns, record.lost_events, emit_closed=True)
                )
                emitted.extend(self._advance(record.timestamp_ns))
            elif isinstance(record, ProcessExit):
                emitted.extend(self._advance(record.timestamp_ns))
                emitted.extend(self.close_process(record.process, record.timestamp_ns))
            else:
                target_key = (record.process, self._window_start(record.timestamp_ns))
                emitted.extend(self._record_loss(
                    record.timestamp_ns, record.lost_events,
                    emit_closed=True, suppress_key=target_key,
                ))
                emitted.extend(self._advance(record.timestamp_ns))
                emitted.extend(self._add_event(record))
        return tuple(emitted)

    def close_process(
        self, process: ProcessIdentity, timestamp_ns: int
    ) -> tuple[FeatureWindow, ...]:
        """Close a process's open windows, preserving incomplete ones."""

        if not isinstance(process, ProcessIdentity):
            raise ValueError("process must be a ProcessIdentity")
        emitted = list(self._advance(timestamp_ns))
        keys = tuple(key for key in self._active if key[0] == process)
        for key in sorted(keys, key=_key_order):
            state = self._active.pop(key)
            replacement = _replace_state(state, partial=True)
            self._closed[key] = replacement
            emitted.append(self._snapshot(replacement))
        return tuple(emitted)

    def finish(self, capture_end_ns: int) -> tuple[FeatureWindow, ...]:
        """Close complete windows and preserve every remaining window as partial."""

        if type(capture_end_ns) is not int or capture_end_ns < self._watermark_ns:
            raise ValueError("capture end must be an integer at or after the watermark")
        emitted = list(self._advance(capture_end_ns))
        for key in sorted(tuple(self._active), key=_key_order):
            state = self._active.pop(key)
            replacement = _replace_state(state, partial=True)
            self._closed[key] = replacement
            emitted.append(self._snapshot(replacement))
        return tuple(emitted)

    def _accept_run(self, run_id: str) -> None:
        if self._run_id is None:
            self._run_id = run_id
        elif run_id != self._run_id:
            raise ValueError(f"record run {run_id!r} does not match run {self._run_id!r}")

    def _accept_sequence(self, collector_sequence: int) -> None:
        if collector_sequence in self._seen_sequences:
            raise ValueError(f"duplicate collector sequence {collector_sequence}")
        self._seen_sequences.add(collector_sequence)

    def _advance(self, timestamp_ns: int) -> tuple[FeatureWindow, ...]:
        if timestamp_ns <= self._watermark_ns:
            return ()
        self._watermark_ns = timestamp_ns
        keys = tuple(
            key for key, state in self._active.items()
            if state.start_ns + WINDOW_NS <= timestamp_ns
        )
        emitted = []
        for key in sorted(keys, key=_key_order):
            state = self._active.pop(key)
            self._closed[key] = state
            emitted.append(self._snapshot(state))
        return tuple(emitted)

    def _add_event(self, event: Event) -> tuple[FeatureWindow, ...]:
        start_ns = self._window_start(event.timestamp_ns)
        key = (event.process, start_ns)
        state = self._closed.get(key)
        if state is not None:
            replacement = _replace_state(
                state,
                events=state.events + (event,),
                late_event_count=state.late_event_count + 1,
            )
            self._closed[key] = replacement
            return (self._snapshot(replacement),)
        state = self._active.get(key) or _WindowState(
            event.run_id, event.process, start_ns,
            loss_count=self._window_loss.get(start_ns, 0),
        )
        replacement = _replace_state(
            state,
            events=state.events + (event,),
        )
        if start_ns + WINDOW_NS <= self._watermark_ns:
            replacement = _replace_state(replacement, late_event_count=1)
            self._closed[key] = replacement
            return (self._snapshot(replacement),)
        self._active[key] = replacement
        return ()

    def _record_loss(
        self, timestamp_ns: int, lost_events: int, *, emit_closed: bool,
        suppress_key: WindowKey | None = None,
    ) -> tuple[FeatureWindow, ...]:
        if lost_events == 0:
            return ()
        start_ns = self._loss_window_start(timestamp_ns)
        self._window_loss[start_ns] = self._window_loss.get(start_ns, 0) + lost_events
        emitted = []
        for key, state in tuple(self._active.items()):
            if state.start_ns == start_ns:
                self._active[key] = _replace_state(
                    state, loss_count=state.loss_count + lost_events
                )
        for key, state in tuple(self._closed.items()):
            if state.start_ns == start_ns:
                replacement = _replace_state(
                    state, loss_count=state.loss_count + lost_events
                )
                self._closed[key] = replacement
                if emit_closed and key != suppress_key:
                    emitted.append(self._snapshot(replacement))
        return tuple(sorted(emitted, key=_window_order))

    def _loss_window_start(self, timestamp_ns: int) -> int:
        delta = timestamp_ns - self.capture_start_ns
        # A loss report exactly on a boundary covers the interval that just
        # ended; elsewhere it belongs to the containing open interval.
        if delta > 0 and delta % WINDOW_NS == 0:
            delta -= 1
        return self.capture_start_ns + (delta // WINDOW_NS) * WINDOW_NS

    def _window_start(self, timestamp_ns: int) -> int:
        delta = timestamp_ns - self.capture_start_ns
        return self.capture_start_ns + (delta // WINDOW_NS) * WINDOW_NS

    @staticmethod
    def _snapshot(state: _WindowState) -> FeatureWindow:
        ordered = tuple(sorted(state.events, key=lambda event: event.collector_sequence))
        operation_counts = Counter(event.operation for event in ordered)
        maxima = []
        for operation in OPERATIONS:
            seconds = Counter(
                (event.timestamp_ns - state.start_ns) // SECOND_NS
                for event in ordered if event.operation == operation
            )
            maxima.append(max(seconds.values(), default=0))
        sequence_counts = Counter(
            "".join(event.operation for event in ordered[index:index + 3])
            for index in range(max(0, len(ordered) - 2))
        )
        values = tuple(operation_counts[name] for name in OPERATIONS) + tuple(maxima) + tuple(
            sequence_counts[name] for name in SEQUENCE_NAMES
        )
        return FeatureWindow(
            run_id=state.run_id,
            process=state.process,
            start_ns=state.start_ns,
            end_ns=state.start_ns + WINDOW_NS,
            feature_names=FEATURE_NAMES,
            values=values,
            partial=state.partial,
            loss_count=state.loss_count,
            late_event_count=state.late_event_count,
        )


def _replace_state(state: _WindowState, **changes: object) -> _WindowState:
    values = {
        "run_id": state.run_id,
        "process": state.process,
        "start_ns": state.start_ns,
        "events": state.events,
        "loss_count": state.loss_count,
        "late_event_count": state.late_event_count,
        "partial": state.partial,
        **changes,
    }
    return _WindowState(**values)


def _key_order(key: WindowKey) -> tuple[int, str, int, int]:
    process, start_ns = key
    return (start_ns, process.boot_id, process.tgid, process.start_time_ns)


def _state_order(state: _WindowState) -> tuple[int, str, int, int]:
    return _key_order((state.process, state.start_ns))


def _window_order(window: FeatureWindow) -> tuple[int, str, int, int]:
    return (window.start_ns, window.process.boot_id, window.process.tgid, window.process.start_time_ns)


def build_windows(
    records: Iterable[StreamRecord], capture_start_ns: int, capture_end_ns: int
) -> tuple[FeatureWindow, ...]:
    """Build final window views for an already bounded capture."""

    engine = WindowFeatureEngine(capture_start_ns)
    engine.feed(records)
    engine.finish(capture_end_ns)
    return engine.windows
