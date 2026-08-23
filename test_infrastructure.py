import unittest
from fastapi.testclient import TestClient
from main import app
from database import insert_scanned_asset

client = TestClient(app)


class TestInfrastructureFingerprinting(unittest.TestCase):

    def setUp(self):
        # Insert sample fingerprint data into SQLite for testing correlation
        insert_scanned_asset(
            asset_type="domain",
            asset_id="paypal-verify-login.com",
            ip_address="192.168.1.100",
            target_brand="PayPal"
        )
        insert_scanned_asset(
            asset_type="domain",
            asset_id="paypal-secure-auth.org",
            ip_address="192.168.1.100",
            target_brand="PayPal"
        )
        insert_scanned_asset(
            asset_type="visual_phishing",
            asset_id="https://paypal-fake-portal.com/login",
            ip_address="192.168.1.100",
            target_brand="PayPal",
            confidence=95.0
        )

    def test_01_offender_clusters_endpoint(self):
        response = client.get("/api/offender-clusters")
        self.assertEqual(response.status_code, 200)
        res = response.json()
        self.assertEqual(res["status"], "success")
        self.assertEqual(res["meta"]["source_tool"], "infrastructure_fingerprinting")
        self.assertIn("clusters", res["data"])
        clusters = res["data"]["clusters"]
        self.assertGreaterEqual(len(clusters), 1)

        cluster = clusters[0]
        self.assertIn("cluster_id", cluster)
        self.assertIn("confidence", cluster)
        self.assertIn("nodes", cluster)
        self.assertIn("edges", cluster)

    def test_02_link_infrastructure_endpoint(self):
        payload = {
            "evidence_domains": [
                {"domain": "paypal-verify-login.com", "dns_a": ["192.168.1.100"]}
            ],
            "evidence_logos": [],
            "evidence_visual_phishing": []
        }
        response = client.post("/api/link-infrastructure", json=payload)
        self.assertEqual(response.status_code, 200)
        res = response.json()
        self.assertEqual(res["status"], "success")
        self.assertIn("linked_assets", res["data"])


if __name__ == "__main__":
    unittest.main()
