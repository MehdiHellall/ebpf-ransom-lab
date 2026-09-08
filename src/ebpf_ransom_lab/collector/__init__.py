"""Portable protocol and Linux BCC collector boundary.

Importing this package is safe on non-Linux hosts.  The optional ``bcc`` module
is loaded only when :class:`BccCollector` is started.
"""

from .abi import EVENT_ABI_SIZE, FILENAME_CAPACITY, KernelEvent, decode_kernel_event
from .adapter import CollectorProtocolAdapter, ProcessExitNotice, to_contract_event
from .protocol import (
    CollectorHealth,
    FilenameBytes,
    LossCounters,
    NormalizedEvent,
    ProcessIdentity,
    PROTOCOL_VERSION,
)
from .runtime import BccCollector, CollectorConsumer, CollectorUnavailableError

__all__ = [
    "BccCollector",
    "CollectorConsumer",
    "CollectorHealth",
    "CollectorProtocolAdapter",
    "CollectorUnavailableError",
    "EVENT_ABI_SIZE",
    "FILENAME_CAPACITY",
    "FilenameBytes",
    "KernelEvent",
    "LossCounters",
    "NormalizedEvent",
    "PROTOCOL_VERSION",
    "ProcessIdentity",
    "ProcessExitNotice",
    "decode_kernel_event",
    "to_contract_event",
]
