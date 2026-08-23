import unittest
from fastapi.testclient import TestClient
from main import app

client = TestClient(app)


class TestCaseRescan(unittest.TestCase):

    def test_01_rescan_endpoint(self):
        payload = {
            "evidence_domains": [
                {"domain": "google.com", "isRegistered": True, "dns_a": ["142.250.190.46"]},
                {"domain": "unregistered-fake-domain-999.com", "isRegistered": False, "dns_a": []}
            ],
            "evidence_logos": [],
            "evidence_visual_phishing": []
        }
        response = client.post("/api/case/test_case_rescan/rescan", json=payload)
        self.assertEqual(response.status_code, 200)
        res = response.json()
        self.assertEqual(res["status"], "success")
        self.assertIn("last_checked", res["data"])
        self.assertIn("new_activity_detected", res["data"])
        self.assertIn("diffs", res["data"])


if __name__ == "__main__":
    unittest.main()
