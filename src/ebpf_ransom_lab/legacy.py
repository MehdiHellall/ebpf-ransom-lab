"""Reconstruct the upstream process features, including its legacy quirks.

The caller supplies captures in lexical filename order. Sequence order is CSV
row order; timestamps are used only for the global-origin one-second buckets.
This module intentionally preserves fixed PID-offset collisions and P_max's
sum of independently maximized event-type pattern totals.
"""

from collections import Counter
from dataclasses import dataclass
from itertools import groupby


TIME_PERIOD = 1_000_000_000
PID_OFFSET = 10_000
EVENT_TYPES = frozenset(("O", "C", "D", "E"))


@dataclass(frozen=True, slots=True)
class Event:
    ts: int
    pid: int
    kind: str
    pattern: int


@dataclass(frozen=True, slots=True)
class FeatureTable:
    columns: tuple[str, ...]
    rows: tuple[tuple[int, ...], ...]


def _adjust(event: Event, index: int) -> Event:
    if any(type(value) is not int for value in (event.ts, event.pid, event.pattern)):
        raise ValueError("Event timestamp, PID, and pattern must be integers")
    if event.kind not in EVENT_TYPES:
        raise ValueError("Event kind must be O, C, D, or E")
    return Event(event.ts, event.pid + index * PID_OFFSET, event.kind, event.pattern)


def _period(timestamp: int, origin: int) -> int:
    delta = timestamp - origin
    # Integer arithmetic avoids float precision loss and floor-division's
    # different treatment of the negative deltas present in separate captures.
    return delta // TIME_PERIOD if delta >= 0 else -((-delta) // TIME_PERIOD)


def _type_statistics(
    events: tuple[Event, ...], kind: str, origin: int, period_count: int
) -> tuple[int, int, int, int]:
    buckets = tuple(
        tuple(bucket)
        for _, bucket in groupby(
            sorted(
                (event for event in events if event.kind == kind),
                key=lambda event: _period(event.ts, origin),
            ),
            key=lambda event: _period(event.ts, origin),
        )
    )
    counts = tuple(len(bucket) for bucket in buckets)
    sums = tuple(sum(event.pattern for event in bucket) for bucket in buckets)
    # pandas unstack fills missing TYPE/PERIOD combinations with zero. This
    # matters for negative pattern values, though the supplied logs use flags.
    candidates = sums + ((0,) if len(buckets) < period_count else ())
    return max(counts, default=0), sum(counts), max(candidates, default=0), sum(sums)


def _process_features(
    events: tuple[Event, ...], kinds: tuple[str, ...], origin: int
) -> tuple[tuple[int, ...], tuple[tuple[str, int], ...]]:
    period_count = len(frozenset(_period(event.ts, origin) for event in events))
    statistics = tuple(
        _type_statistics(events, kind, origin, period_count) for kind in kinds
    )
    counts = tuple(value for entry in statistics for value in entry[:2])
    patterns = (sum(entry[2] for entry in statistics), sum(entry[3] for entry in statistics))
    sequences = tuple(sorted(Counter(
        "".join(event.kind for event in events[index:index + 3])
        for index in range(len(events) - 2)
    ).items()))
    return counts + patterns, sequences


def reconstruct(captures: tuple[tuple[Event, ...], ...]) -> FeatureTable:
    """Return integer features for ordered captures without changing inputs.

    Columns consist of PID, observed types' max/sum counts, P_max/P_sum, then
    observed length-three sequences. PIDs, types, and sequences sort ascending.
    Empty input yields the fixed PID/P_max/P_sum columns and no rows.
    """
    events = tuple(
        _adjust(event, index)
        for index, capture in enumerate(captures)
        for event in capture
    )
    kinds = tuple(sorted(frozenset(event.kind for event in events)))
    columns = ("PID",) + tuple(
        f"{kind}_{stat}" for kind in kinds for stat in ("max", "sum")
    ) + ("P_max", "P_sum")
    if not events:
        return FeatureTable(columns, ())
    # Python's stable sort retains capture/row order inside colliding PIDs.
    processes = tuple(
        (pid, _process_features(tuple(group), kinds, events[0].ts))
        for pid, group in groupby(sorted(events, key=lambda event: event.pid), key=lambda event: event.pid)
    )
    sequences = tuple(sorted(frozenset(
        name for _, (_, values) in processes for name, _ in values
    )))
    rows = tuple(
        (pid,) + counts + tuple(dict(values).get(name, 0) for name in sequences)
        for pid, (counts, values) in processes
    )
    return FeatureTable(columns + sequences, rows)
