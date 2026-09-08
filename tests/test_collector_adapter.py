import base64
import unittest

from ebpf_ransom_lab.collector.adapter import (
    CollectorProtocolAdapter,
    ProcessExitNotice,
)
from ebpf_ransom_lab.collector.abi import KernelEvent
from ebpf_ransom_lab.collector.protocol import (
    CollectorHealth,
    FilenameBytes,
    LossCounters,
    NormalizedEvent,
    ProcessIdentity,
)
from ebpf_ransom_lab.collector.runtime import CollectorConsumer
from ebpf_ransom_lab.contracts import Event, Heartbeat


class CollectorAdapterTests(unittest.TestCase):
    def setUp(self):
        self.identity = ProcessIdentity("boot-a", 42, 500)

    def syscall(self, operation, flags=0):
        return NormalizedEvent.syscall(
            run_id="run-a",
            sequence=7,
            monotonic_ns=1_234,
            identity=self.identity,
            tid=43,
            operation=operation,
            return_value=-13,
            open_flags=flags,
            filename=FilenameBytes.from_bytes(b"bad-\xff"),
        )

    def test_file_operations_map_to_shared_feature_contract(self):
        cases = (
            ("open", 0, "O"),
            ("openat", 0x40, "C"),
            ("unlink", 0, "D"),
            ("unlinkat", 0, "D"),
        )
        for syscall, flags, operation in cases:
            with self.subTest(syscall=syscall, flags=flags):
                event = self.syscall(syscall, flags).to_contract_event()
                self.assertIsInstance(event, Event)
                self.assertEqual(operation, event.operation)
                self.assertEqual(7, event.collector_sequence)
                self.assertEqual(1_234, event.timestamp_ns)
                self.assertEqual(43, event.tid)
                self.assertEqual(-13, event.result)
                self.assertEqual("bad-\\xff", event.filename)
                self.assertEqual(
                    b"bad-\xff", base64.b64decode(event.filename_bytes_b64, validate=True)
                )
                self.assertEqual("boot-a", event.process.boot_id)
                self.assertEqual(42, event.process.tgid)
                self.assertEqual(500, event.process.start_time_ns)

    def test_process_exit_is_an_explicit_notice_not_a_fake_feature_event(self):
        event = NormalizedEvent.process_exit(
            run_id="run-a",
            sequence=8,
            monotonic_ns=2_000,
            identity=self.identity,
            tid=42,
        )

        with self.assertRaisesRegex(ValueError, "process exit"):
            event.to_contract_event()

        notice = ProcessExitNotice.from_event(event)
        self.assertEqual("run-a", notice.run_id)
        self.assertEqual(8, notice.collector_sequence)
        self.assertEqual(2_000, notice.timestamp_ns)
        self.assertEqual(42, notice.process.tgid)
        self.assertEqual("process_exit", notice.to_contract_record().to_dict()["type"])

    def test_health_cumulative_totals_become_heartbeat_deltas(self):
        adapter = CollectorProtocolAdapter()
        first = CollectorHealth(
            run_id="run-a",
            connected=True,
            monotonic_ns=10,
            counters=LossCounters(
                ring_buffer_reservation_failures=2,
                pending_map_update_failures=1,
                consumer_queue_drops=1,
            ),
        )
        second = CollectorHealth(
            run_id="run-a",
            connected=True,
            monotonic_ns=20,
            counters=LossCounters(
                ring_buffer_reservation_failures=3,
                pending_map_update_failures=1,
                consumer_queue_drops=2,
            ),
        )

        heartbeat1 = adapter.health_to_heartbeat(first, collector_sequence=9)
        heartbeat2 = adapter.health_to_heartbeat(second, collector_sequence=10)

        self.assertIsInstance(heartbeat1, Heartbeat)
        self.assertEqual(4, heartbeat1.lost_events)
        self.assertEqual(2, heartbeat2.lost_events)
        self.assertEqual(20, heartbeat2.timestamp_ns)

    def test_health_adapter_rejects_counter_regression_or_changed_run(self):
        adapter = CollectorProtocolAdapter()
        adapter.health_to_heartbeat(
            CollectorHealth("run-a", True, 10, LossCounters(consumer_queue_drops=2)),
            collector_sequence=1,
        )
        with self.assertRaisesRegex(ValueError, "regressed"):
            adapter.health_to_heartbeat(
                CollectorHealth("run-a", True, 20, LossCounters()),
                collector_sequence=2,
            )
        with self.assertRaisesRegex(ValueError, "run"):
            adapter.health_to_heartbeat(
                CollectorHealth("run-b", True, 20, LossCounters(consumer_queue_drops=2)),
                collector_sequence=2,
            )

    def test_consumer_sequence_is_shared_with_heartbeat_emission(self):
        consumer = CollectorConsumer(run_id="run-a", boot_id="boot-a", queue_limit=2)
        raw = KernelEvent()
        raw.monotonic_ns = 1
        raw.process_start_ns = 1
        raw.tgid = 2
        raw.tid = 2
        raw.operation = 1
        raw.event_kind = 1
        self.assertTrue(consumer.consume_bytes(bytes(raw)))

        sequence = consumer.claim_sequence()
        heartbeat = CollectorProtocolAdapter().health_to_heartbeat(
            CollectorHealth("run-a", True, 2, LossCounters()),
            collector_sequence=sequence,
        )

        self.assertEqual(2, heartbeat.collector_sequence)
        self.assertTrue(consumer.consume_bytes(bytes(raw)))
        self.assertEqual([1, 3], [event.sequence for event in consumer.drain()])


if __name__ == "__main__":
    unittest.main()
