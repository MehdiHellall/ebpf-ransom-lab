import tempfile
import sys
import unittest
from pathlib import Path

from ebpf_ransom_lab.doctor import (
    DoctorContext,
    Status,
    evaluate_doctor,
    overall_status,
)


class DoctorTests(unittest.TestCase):
    def make_context(self, **overrides):
        values = {
            "system": "Linux",
            "python_version": (3, 12, 0),
            "kernel_release": "6.8.0-test",
            "effective_uid": 0,
            "free_bytes": 10 * 1024**3,
            "available_modules": frozenset({"bcc"}),
            "existing_paths": frozenset(
                {
                    "/sys/kernel/btf/vmlinux",
                    "/lib/modules/6.8.0-test/build",
                    "/sys/kernel/debug/tracing/events/syscalls/sys_enter_openat",
                    "/sys/kernel/debug/tracing/events/syscalls/sys_exit_openat",
                    "/sys/kernel/debug/tracing/events/syscalls/sys_enter_unlinkat",
                    "/sys/kernel/debug/tracing/events/syscalls/sys_exit_unlinkat",
                }
            ),
            "data_directory_writable": True,
        }
        values.update(overrides)
        return DoctorContext(**values)

    def test_application_scope_passes_on_supported_python(self):
        checks = evaluate_doctor(self.make_context(system="Windows"), "app")

        self.assertTrue(checks)
        self.assertFalse(any(check.status is Status.FAIL for check in checks))

    def test_application_scope_rejects_old_python(self):
        checks = evaluate_doctor(
            self.make_context(python_version=(3, 10, 14)), "app"
        )

        python_check = next(check for check in checks if check.name == "python")
        self.assertEqual(Status.FAIL, python_check.status)

    def test_collector_scope_fails_outside_linux(self):
        checks = evaluate_doctor(self.make_context(system="Windows"), "collector")

        platform_check = next(
            check for check in checks if check.name == "collector_platform"
        )
        self.assertEqual(Status.FAIL, platform_check.status)

    def test_collector_scope_checks_bcc_kernel_and_privileges(self):
        checks = evaluate_doctor(self.make_context(), "collector")

        self.assertFalse(any(check.status is Status.FAIL for check in checks))
        self.assertEqual(
            {
                "collector_platform",
                "collector_privileges",
                "bcc",
                "kernel_btf",
                "kernel_headers",
                "tracepoints",
                "ring_buffer",
            },
            {check.name for check in checks},
        )

    def test_collector_accepts_modern_tracefs_mount(self):
        tracefs_paths = {
            path.replace("/sys/kernel/debug/tracing", "/sys/kernel/tracing")
            for path in self.make_context().existing_paths
            if "tracepoints" not in path
        }
        checks = evaluate_doctor(
            self.make_context(existing_paths=frozenset(tracefs_paths)), "collector"
        )

        tracepoints = next(check for check in checks if check.name == "tracepoints")
        self.assertEqual(Status.PASS, tracepoints.status)

    def test_collector_rejects_kernel_without_ring_buffers(self):
        checks = evaluate_doctor(
            self.make_context(kernel_release="5.4.0-generic"), "collector"
        )

        ring_buffer = next(check for check in checks if check.name == "ring_buffer")
        self.assertEqual(Status.FAIL, ring_buffer.status)

    def test_collector_reports_every_missing_prerequisite(self):
        checks = evaluate_doctor(
            self.make_context(
                effective_uid=1000,
                available_modules=frozenset(),
                existing_paths=frozenset(),
            ),
            "collector",
        )

        failed = {check.name for check in checks if check.status is Status.FAIL}
        self.assertEqual(
            {"collector_privileges", "bcc", "kernel_btf", "kernel_headers", "tracepoints"},
            failed,
        )

    def test_low_storage_is_reported_as_warning(self):
        checks = evaluate_doctor(
            self.make_context(free_bytes=2 * 1024**3), "app"
        )

        storage = next(check for check in checks if check.name == "storage")
        self.assertEqual(Status.WARN, storage.status)

    def test_host_context_uses_nearest_existing_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "future" / "captures"

            context = DoctorContext.from_host(target)

            self.assertEqual(context.python_version, tuple(sys.version_info[:3]))
            self.assertGreater(context.free_bytes, 0)
            self.assertTrue(context.data_directory_writable)

    def test_invalid_scope_is_rejected(self):
        with self.assertRaises(ValueError):
            evaluate_doctor(self.make_context(), "unknown")

    def test_warning_becomes_overall_warning(self):
        checks = evaluate_doctor(
            self.make_context(free_bytes=2 * 1024**3), "app"
        )

        self.assertEqual(Status.WARN, overall_status(checks))


if __name__ == "__main__":
    unittest.main()
