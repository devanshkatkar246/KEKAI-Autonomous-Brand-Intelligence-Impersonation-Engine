import unittest
from fastapi.testclient import TestClient
from main import app
from services.infrastructure_service import get_offender_clusters
from database import fetch_all_assets

client = TestClient(app)


class TestMasterIntegrationPass(unittest.TestCase):

    def test_01_master_demo_scenario_endpoint(self):
        response = client.get("/api/demo/run-full-scenario")
        self.assertEqual(response.status_code, 200)
        res = response.json()
        self.assertEqual(res["status"], "success")

        data = res["data"]
        self.assertEqual(data["total_assets_linked"], 5)
        self.assertEqual(data["target_brand"], "Rolex")
        self.assertEqual(data["cluster_id"], "CLUSTER-ROLEX-OFFENDER-01")
        self.assertGreater(data["composite_risk_score"], 90.0)

        # Verify 5 distinct evidence arrays present
        self.assertEqual(len(data["selected_domains"]), 1)
        self.assertEqual(len(data["selected_logos"]), 1)
        self.assertEqual(len(data["selected_visual_phishing"]), 1)
        self.assertEqual(len(data["selected_listings"]), 1)
        self.assertEqual(len(data["selected_social_profiles"]), 1)

    def test_02_multi_surface_offender_graph_clustering(self):
        # Run demo scenario to ensure assets are inserted into SQLite
        client.get("/api/demo/run-full-scenario")

        clusters_res = get_offender_clusters()
        self.assertGreaterEqual(clusters_res["total_clusters"], 1)

        # Find the master demo cluster
        demo_cluster = None
        for c in clusters_res["clusters"]:
            if "CLUSTER-ROLEX" in c["cluster_id"] or c["asset_count"] >= 5:
                demo_cluster = c
                break

        self.assertIsNotNone(demo_cluster)
        self.assertEqual(demo_cluster["confidence"], "High")
        self.assertGreaterEqual(demo_cluster["asset_count"], 5)
        self.assertIn("Derived from", demo_cluster["data_sources_summary"])

    def test_03_pdf_report_generation_with_master_scenario(self):
        demo_res = client.get("/api/demo/run-full-scenario").json()["data"]

        pdf_payload = {
            "case_id": "CASE-MASTER-DEMO-TEST",
            "timestamp": "2026-08-22T09:00:00Z",
            "brand_name": "Rolex Corporate",
            "composite_risk_score": demo_res["composite_risk_score"],
            "manual_notes": demo_res["notes"],
            "score_breakdown": {
                "domain_factor": 23.0,
                "logo_factor": 23.1,
                "phish_factor": 19.2,
                "listing_factor": 14.1,
                "social_factor": 14.2,
                "notes_factor": 10.0,
                "intent_discount": 0.0,
                "weights": {"domain": 25, "logo": 25, "phish": 20, "listing": 15, "social": 15, "notes": 10}
            },
            "flagged_domains": demo_res["selected_domains"],
            "flagged_logos": demo_res["selected_logos"],
            "visual_phishing": demo_res["selected_visual_phishing"],
            "flagged_listings": demo_res["selected_listings"],
            "flagged_social_profiles": demo_res["selected_social_profiles"]
        }

        pdf_response = client.post("/api/generate-report", json=pdf_payload)
        self.assertEqual(pdf_response.status_code, 200)
        self.assertTrue(pdf_response.content.startswith(b"%PDF"))


if __name__ == "__main__":
    unittest.main()
