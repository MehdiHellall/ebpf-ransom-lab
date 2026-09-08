import ctypes
import importlib
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from ebpf_ransom_lab.collector.abi import KernelEvent
from ebpf_ransom_lab.collector.runtime import (
    BccCollector,
    CollectorConsumer,
    CollectorUnavailableError,
    read_boot_id,
)


class FakeScalar:
    def __init__(self, value):
        self.value = value


class FakeLossMap:
    def __init__(self, values):
        self.values = values

    def __getitem__(self, key):
        index = key.value if hasattr(key, "value") else int(key)
        return FakeScalar(self.values[index])


class FakeEventsMap:
    def open_ring_buffer(self, callback):
        self.callback = callback


class FakeBpf:
    def __init__(self, text, cflags=None):
        self.text = text
        self.cflags = cflags
        self.events = FakeEventsMap()
        self.loss = FakeLossMap([13, 17, 19, 23])
        self.polls = []

    def __getitem__(self, name):
        return {"events": self.events, "loss_counters": self.loss}[name]

    def ring_buffer_poll(self, timeout):
        self.polls.append(timeout)


class FakeBccModule:
    BPF = FakeBpf


class CollectorRuntimeTests(unittest.TestCase):
    def raw(self, sequence):
        event = KernelEvent()
        event.monotonic_ns = sequence * 10
        event.process_start_ns = 1
        event.return_value = 0
        event.tgid = 2
        event.tid = 3
        event.operation = 1
        event.event_kind = 1
        return bytes(event)

    def test_package_import_does_not_load_bcc(self):
        sys.modules.pop("bcc", None)
        import ebpf_ransom_lab.collector as collector

        importlib.reload(collector)

        self.assertNotIn("bcc", sys.modules)

    def test_consumer_assigns_callback_order_and_exposes_decode_and_queue_losses(self):
        consumer = CollectorConsumer(run_id="run", boot_id="boot", queue_limit=1)

        self.assertTrue(consumer.consume_bytes(self.raw(1)))
        self.assertFalse(consumer.consume_bytes(self.raw(3)))
        self.assertFalse(consumer.consume_bytes(b"bad"))

        counters = consumer.counters()
        self.assertEqual(1, counters.consumer_queue_drops)
        self.assertEqual(1, counters.consumer_decode_errors)
        first = consumer.drain()
        self.assertEqual([1], [event.sequence for event in first])
        self.assertTrue(consumer.consume_bytes(self.raw(900)))
        self.assertEqual([4], [event.sequence for event in consumer.drain()])
        self.assertEqual([], consumer.drain())

    def test_bcc_import_is_deferred_until_start_and_kernel_losses_are_merged(self):
        consumer = CollectorConsumer(run_id="run", boot_id="boot", queue_limit=2)
        with patch(
            "ebpf_ransom_lab.collector.runtime.importlib.import_module",
            return_value=FakeBccModule,
        ) as importer:
            collector = BccCollector(consumer)
            importer.assert_not_called()

            collector.start()
            importer.assert_called_once_with("bcc")
            collector.poll(timeout_ms=25)

        self.assertEqual([25], collector.bpf.polls)
        health = collector.health(monotonic_ns=123).to_dict()
        self.assertEqual(13, health["loss_counters"]["ring_buffer_reservation_failures"])
        self.assertEqual(17, health["loss_counters"]["pending_map_update_failures"])
        self.assertEqual(19, health["loss_counters"]["filename_read_failures"])
        self.assertEqual(23, health["loss_counters"]["identity_read_failures"])
        self.assertTrue(health["connected"])

    def test_bcc_uses_the_same_proc_start_tick_resolution_as_workloads(self):
        consumer = CollectorConsumer(run_id="run", boot_id="boot", queue_limit=2)
        with patch("ebpf_ransom_lab.collector.runtime.os.sysconf", return_value=100, create=True), patch(
            "ebpf_ransom_lab.collector.runtime.importlib.import_module",
            return_value=FakeBccModule,
        ):
            collector = BccCollector(consumer)
            collector.start()

        self.assertEqual(["-DUSER_HZ=100"], collector.bpf.cflags)

    def test_bcc_rejects_a_clock_tick_value_that_cannot_match_proc_stat(self):
        consumer = CollectorConsumer(run_id="run", boot_id="boot", queue_limit=2)
        with patch("ebpf_ransom_lab.collector.runtime.os.sysconf", return_value=60, create=True), patch(
            "ebpf_ransom_lab.collector.runtime.importlib.import_module",
            return_value=FakeBccModule,
        ):
            with self.assertRaisesRegex(CollectorUnavailableError, "canonically"):
                BccCollector(consumer).start()

    def test_callback_copies_ctypes_payload_and_stop_marks_disconnected(self):
        consumer = CollectorConsumer(run_id="run", boot_id="boot", queue_limit=2)
        with patch(
            "ebpf_ransom_lab.collector.runtime.importlib.import_module",
            return_value=FakeBccModule,
        ):
            collector = BccCollector(consumer)
            collector.start()
            payload = ctypes.create_string_buffer(self.raw(1))
            collector.bpf.events.callback(None, ctypes.addressof(payload), len(payload.raw) - 1)
            collector.stop()

        self.assertEqual(1, len(consumer.drain()))
        self.assertFalse(collector.health(monotonic_ns=1).connected)

    def test_sequence_claims_are_unique_under_concurrency(self):
        consumer = CollectorConsumer(run_id="run", boot_id="boot", queue_limit=1)
        claimed = []
        claimed_lock = threading.Lock()

        def claim_many():
            values = [consumer.claim_sequence() for _ in range(100)]
            with claimed_lock:
                claimed.extend(values)

        threads = [threading.Thread(target=claim_many) for _ in range(4)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        self.assertEqual(list(range(1, 401)), sorted(claimed))

    def test_boot_id_reader_is_explicit_and_reports_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "boot_id"
            path.write_text("boot-value\n", encoding="ascii")
            self.assertEqual("boot-value", read_boot_id(path))
            with self.assertRaises(CollectorUnavailableError):
                read_boot_id(path.with_name("missing"))

    def test_missing_bcc_is_a_clear_runtime_error(self):
        consumer = CollectorConsumer(run_id="run", boot_id="boot", queue_limit=1)
        with patch(
            "ebpf_ransom_lab.collector.runtime.importlib.import_module",
            side_effect=ImportError("missing"),
        ):
            with self.assertRaisesRegex(CollectorUnavailableError, "BCC"):
                BccCollector(consumer).start()


if __name__ == "__main__":
    unittest.main()
