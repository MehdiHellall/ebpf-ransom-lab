import ctypes
import unittest

from ebpf_ransom_lab.collector.abi import (
    EVENT_ABI_SIZE,
    FILENAME_CAPACITY,
    KernelEvent,
    decode_kernel_event,
)
from ebpf_ransom_lab.collector.bcc_source import BCC_SOURCE


class CollectorAbiTests(unittest.TestCase):
    def make_event(self, **overrides):
        event = KernelEvent()
        values = {
            "monotonic_ns": 1_000,
            "process_start_ns": 500,
            "return_value": -2,
            "tgid": 100,
            "tid": 101,
            "open_flags": 0x40,
            "filename_len": 3,
            "operation": 2,
            "event_kind": 1,
        }
        values.update(overrides)
        for name, value in values.items():
            setattr(event, name, value)
        event.filename[:3] = b"a\xffz"
        return event

    def test_python_layout_matches_c_static_contract(self):
        self.assertEqual(296, ctypes.sizeof(KernelEvent))
        self.assertEqual(296, EVENT_ABI_SIZE)
        self.assertEqual(40, KernelEvent.filename.offset)
        self.assertIn("_Static_assert(sizeof(struct event_t) == 296", BCC_SOURCE)
        self.assertIn("_Static_assert(__builtin_offsetof(struct event_t, filename) == 40", BCC_SOURCE)
        offsets = {
            "monotonic_ns": 0,
            "process_start_ns": 8,
            "return_value": 16,
            "tgid": 24,
            "tid": 28,
            "open_flags": 32,
            "filename_len": 36,
            "operation": 38,
            "event_kind": 39,
            "filename": 40,
        }
        for field, offset in offsets.items():
            with self.subTest(field=field):
                self.assertEqual(offset, getattr(KernelEvent, field).offset)
                self.assertIn(
                    f"__builtin_offsetof(struct event_t, {field}) == {offset}",
                    BCC_SOURCE,
                )

    def test_decode_preserves_abi_bytes_and_process_thread_identity(self):
        event = decode_kernel_event(
            bytes(self.make_event()),
            run_id="run-1",
            boot_id="boot-1",
            sequence=33,
        )
        decoded = event.to_dict()

        self.assertEqual("openat", decoded["attempt"]["name"])
        self.assertTrue(decoded["attempt"]["create_intent"])
        self.assertEqual(-2, decoded["result"]["return_value"])
        self.assertEqual(
            {"boot_id": "boot-1", "tgid": 100, "start_time_ns": 500},
            decoded["process"],
        )
        self.assertEqual(101, decoded["tid"])
        self.assertEqual(33, decoded["collector_sequence"])
        self.assertEqual(b"a\xffz", event.filename.raw)

    def test_decode_rejects_wrong_size_unknown_codes_and_invalid_length(self):
        with self.assertRaisesRegex(ValueError, "ABI size"):
            decode_kernel_event(b"tiny", run_id="run", boot_id="boot", sequence=1)
        with self.assertRaisesRegex(ValueError, "operation"):
            decode_kernel_event(
                bytes(self.make_event(operation=99)),
                run_id="run",
                boot_id="boot",
                sequence=1,
            )
        with self.assertRaisesRegex(ValueError, "process start"):
            decode_kernel_event(
                bytes(self.make_event(process_start_ns=0)),
                run_id="run",
                boot_id="boot",
                sequence=1,
            )
        with self.assertRaisesRegex(ValueError, "filename length"):
            decode_kernel_event(
                bytes(self.make_event(filename_len=FILENAME_CAPACITY + 1)),
                run_id="run",
                boot_id="boot",
                sequence=1,
            )

    def test_exit_event_decodes_without_filename_or_result(self):
        event = self.make_event(
            event_kind=2,
            operation=5,
            filename_len=0,
            tgid=100,
            tid=100,
        )

        decoded = decode_kernel_event(
            bytes(event), run_id="run", boot_id="boot", sequence=1
        ).to_dict()

        self.assertEqual("process_exit", decoded["event_type"])
        self.assertIsNone(decoded["filename"])
        self.assertIsNone(decoded["result"])

    def test_maximum_filename_and_truncation_flag_round_trip(self):
        event = self.make_event(filename_len=FILENAME_CAPACITY, event_kind=0x81)
        expected = bytes(index % 256 for index in range(FILENAME_CAPACITY))
        event.filename[:] = expected

        decoded = decode_kernel_event(
            bytes(event), run_id="run", boot_id="boot", sequence=1
        )

        self.assertEqual(expected, decoded.filename.raw)
        self.assertTrue(decoded.filename.truncated)

    def test_threads_share_process_identity_but_keep_distinct_tid(self):
        first = decode_kernel_event(
            bytes(self.make_event(tid=101)),
            run_id="run",
            boot_id="boot",
            sequence=1,
        )
        second = decode_kernel_event(
            bytes(self.make_event(tid=102)),
            run_id="run",
            boot_id="boot",
            sequence=2,
        )

        self.assertEqual(first.identity, second.identity)
        self.assertNotEqual(first.tid, second.tid)

    def test_pid_reuse_is_disambiguated_by_process_start(self):
        old = decode_kernel_event(
            bytes(self.make_event(process_start_ns=500)),
            run_id="run",
            boot_id="boot",
            sequence=1,
        )
        reused = decode_kernel_event(
            bytes(self.make_event(process_start_ns=900)),
            run_id="run",
            boot_id="boot",
            sequence=2,
        )

        self.assertNotEqual(old.identity, reused.identity)


if __name__ == "__main__":
    unittest.main()
