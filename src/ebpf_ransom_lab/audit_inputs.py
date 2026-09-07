from __future__ import annotations

import csv
import re
from decimal import Decimal, InvalidOperation
from pathlib import Path

from ebpf_ransom_lab.legacy import Event, FeatureTable

CAPTURE_COLUMNS = ('TS', 'PID', 'TYPE', 'FLAG', 'PATTERN', 'OPEN', 'CREATE',
                   'DELETE', 'ENCRYPT', 'FILENAME')
FEATURE_NAME = re.compile(r'(?:[OCDE]_(?:max|sum)|P_(?:max|sum)|[OCDE]{3})\Z')


def integer(value: str) -> int:
    try:
        number = Decimal(value)
    except InvalidOperation as error:
        raise ValueError('invalid numeric cell') from error
    if (not number.is_finite() or number < 0 or number > 2**64 - 1
            or number != number.to_integral_value()):
        raise ValueError('expected a nonnegative 64-bit integer')
    return int(number)


def read_rows(path: Path) -> tuple[tuple[str, ...], tuple[tuple[str, ...], ...]]:
    with path.open(encoding='utf-8', newline='') as stream:
        reader = csv.reader(stream, strict=True)
        header = tuple(next(reader, ()))
        if not header or len(set(header)) != len(header):
            raise ValueError('empty schema or duplicate columns')
        rows = tuple(tuple(row) for row in reader)
    if any(len(row) != len(header) for row in rows):
        raise ValueError('malformed row width')
    return header, rows


def read_capture(path: Path) -> tuple[Event, ...]:
    header, rows = read_rows(path)
    if header != CAPTURE_COLUMNS:
        raise ValueError('unexpected capture schema')
    return tuple(_event(row) for row in rows)


def _event(row: tuple[str, ...]) -> Event:
    values = tuple(integer(value) for value in row[:-1])
    if values[2] > 3:
        raise ValueError('unknown event type')
    return Event(values[0], values[1], 'OCDE'[values[2]], values[4])


def read_features(path: Path) -> FeatureTable:
    columns, rows = read_rows(path)
    if (columns[0] != 'PID' or len(columns) < 2
            or any(not FEATURE_NAME.fullmatch(name) for name in columns[1:])):
        raise ValueError('unexpected feature schema')
    values = tuple(tuple(integer(value) for value in row) for row in rows)
    _unique(tuple(row[0] for row in values))
    return FeatureTable(columns, values)


def read_labels(path: Path) -> tuple[int, ...]:
    header, rows = read_rows(path)
    if header != ('PID',):
        raise ValueError('unexpected label schema')
    values = tuple(integer(row[0]) for row in rows)
    _unique(values)
    return values


def _unique(values: tuple[int, ...]) -> None:
    if len(set(values)) != len(values):
        raise ValueError('duplicate identifier')
