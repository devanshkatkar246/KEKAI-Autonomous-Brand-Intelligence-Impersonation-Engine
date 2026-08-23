import unittest
from fastapi.testclient import TestClient
from main import app
from database import log_case_event, fetch_case_timeline

client = TestClient(app)


class TestInvestigationTimeline(unittest.TestCase):

    def test_01_log_and_fetch_timeline(self):
        log_case_event("case_test_01", "scan_run", "Test domain scan executed for paypal-fake.com")
        log_case_event("case_test_01", "evidence_added", "Added domain paypal-fake.com to case")

        response = client.get("/api/case/case_test_01/timeline")
        self.assertEqual(response.status_code, 200)
        res = response.json()
        self.assertEqual(res["status"], "success")
        self.assertIn("timeline", res["data"])
        events = res["data"]["timeline"]
        self.assertGreaterEqual(len(events), 2)

    def test_02_post_timeline_event_endpoint(self):
        payload = {
            "event_type": "cluster_linked",
            "description": "Linked cluster CLUSTER-001 with 3 assets"
        }
        response = client.post("/api/case/case_test_01/event", json=payload)
        self.assertEqual(response.status_code, 200)
        res = response.json()
        self.assertEqual(res["status"], "success")


if __name__ == "__main__":
    unittest.main()
