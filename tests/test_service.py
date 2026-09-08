import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

from ebpf_ransom_lab.service import create_app
from ebpf_ransom_lab.storage import Store


class ServiceTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.database = Path(self.directory.name) / "runs.sqlite"
        store = Store(self.database)
        store.initialize()
        store.upsert_run("run-1", source="replay", started_ns=0, status="complete")
        self.client = TestClient(create_app(self.database))

    def tearDown(self):
        self.directory.cleanup()

    def test_read_only_versioned_endpoints_and_security_headers(self):
        response = self.client.get("/api/v1/health")
        self.assertEqual(200, response.status_code)
        self.assertFalse(response.json()["collector_connected"])
        self.assertIn("default-src 'self'", response.headers["content-security-policy"])
        for endpoint in ("runs", "processes", "windows", "alerts", "metrics"):
            self.assertEqual(200, self.client.get(f"/api/v1/{endpoint}").status_code)
        self.assertEqual(405, self.client.post("/api/v1/runs").status_code)

    def test_pagination_is_bounded(self):
        self.assertEqual(422, self.client.get("/api/v1/runs?limit=101").status_code)
        self.assertEqual(422, self.client.get("/api/v1/runs?offset=-1").status_code)

    def test_dashboard_is_local_and_uses_safe_text_rendering(self):
        page = self.client.get("/")
        script = self.client.get("/static/app.js")
        self.assertEqual(200, page.status_code)
        self.assertIn("eBPF Ransom Lab", page.text)
        self.assertIn("textContent", script.text)
        self.assertNotIn("innerHTML", script.text)
        self.assertNotIn("https://", page.text)


if __name__ == "__main__":
    unittest.main()
