import unittest

from ebpf_ransom_lab.collector.bcc_source import BCC_SOURCE


class CollectorBccSourceTests(unittest.TestCase):
    def test_baseline_syscall_tracepoints_are_explicit(self):
        for syscall in ("open", "openat", "unlink", "unlinkat"):
            self.assertIn(
                f"TRACEPOINT_PROBE(syscalls, sys_enter_{syscall})", BCC_SOURCE
            )
            self.assertIn(
                f"TRACEPOINT_PROBE(syscalls, sys_exit_{syscall})", BCC_SOURCE
            )

    def test_source_correlates_entry_and_exit_and_cleans_thread_state(self):
        self.assertIn("BPF_HASH(pending", BCC_SOURCE)
        self.assertIn("pending.lookup(&pid_tgid)", BCC_SOURCE)
        self.assertIn("pending.delete(&pid_tgid)", BCC_SOURCE)
        self.assertIn("TRACEPOINT_PROBE(sched, sched_process_exit)", BCC_SOURCE)
        self.assertIn("if (tid != tgid)", BCC_SOURCE)

    def test_source_tracks_visible_kernel_loss_causes(self):
        self.assertIn("BPF_ARRAY(loss_counters", BCC_SOURCE)
        self.assertIn("LOSS_RINGBUF_RESERVATION", BCC_SOURCE)
        self.assertIn("LOSS_PENDING_MAP_UPDATE", BCC_SOURCE)
        self.assertIn("LOSS_FILENAME_READ", BCC_SOURCE)
        self.assertIn("LOSS_IDENTITY_READ", BCC_SOURCE)
        self.assertIn("if (!event)", BCC_SOURCE)
        self.assertIn("if (update_result < 0)", BCC_SOURCE)

    def test_source_uses_process_start_not_only_numeric_pid(self):
        self.assertIn("group_leader", BCC_SOURCE)
        self.assertIn("start_boottime", BCC_SOURCE)
        self.assertIn("event->tgid = pid_tgid >> 32", BCC_SOURCE)
        self.assertIn("event->tid = (__u32)pid_tgid", BCC_SOURCE)

    def test_source_canonicalizes_start_time_to_proc_stat_resolution(self):
        self.assertIn("#define USER_HZ 100", BCC_SOURCE)
        self.assertIn("NSEC_PER_SEC / USER_HZ", BCC_SOURCE)
        self.assertIn("return (start_boottime / tick_ns) * tick_ns", BCC_SOURCE)

    def test_source_leaves_consumer_order_sequence_to_python(self):
        self.assertNotIn("sequence_counter", BCC_SOURCE)
        self.assertNotIn("event->sequence", BCC_SOURCE)

    def test_filename_copy_is_bounded_and_truncation_is_flagged(self):
        self.assertIn("bpf_probe_read_user_str", BCC_SOURCE)
        self.assertIn("FILENAME_CAPACITY", BCC_SOURCE)
        self.assertIn("EVENT_FLAG_FILENAME_TRUNCATED", BCC_SOURCE)


if __name__ == "__main__":
    unittest.main()
