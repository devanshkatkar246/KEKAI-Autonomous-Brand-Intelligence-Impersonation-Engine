import unittest
from fastapi.testclient import TestClient
from main import app
from services.listing_service import analyze_marketplace_listing, check_price_anomaly, get_sample_listings
from services.infrastructure_service import get_offender_clusters

client = TestClient(app)


class TestCounterfeitListingDetection(unittest.TestCase):

    def test_01_price_anomaly_detection_heuristic(self):
        # Rolex ($249.99 vs MSRP $10,000) -> 97.5% discount -> Price Anomaly ALERT
        res = check_price_anomaly(price=249.99, target_brand="Rolex")
        self.assertTrue(res["price_anomaly"])
        self.assertEqual(res["msrp"], 10000.0)
        self.assertGreater(res["discount_percentage"], 90.0)

        # Nike ($140.00 vs MSRP $150) -> 6.7% discount -> Normal price
        res_legit = check_price_anomaly(price=140.00, target_brand="Nike")
        self.assertFalse(res_legit["price_anomaly"])
        self.assertEqual(res_legit["msrp"], 150.0)

    def test_02_single_listing_analysis(self):
        res = analyze_marketplace_listing(
            title="Rolex Submariner Replica Brand New",
            seller_name="ReplicaDiscounts_Direct",
            description="1:1 copycat watch with box",
            price=199.99,
            target_brand="Rolex"
        )
        self.assertIn("listing_id", res)
        self.assertEqual(res["verdict"], "High Risk Counterfeit")
        self.assertTrue(res["price_anomaly"])
        self.assertGreater(res["risk_rating"], 70.0)

    def test_03_sample_demo_listings_retrieval(self):
        samples = get_sample_listings()
        self.assertGreaterEqual(len(samples), 5)
        self.assertEqual(samples[0]["target_brand"], "Rolex")
        self.assertTrue(samples[0]["price_anomaly"])

    def test_04_api_listing_check_endpoint(self):
        data = {
            "title": "Apple AirPods Max Replica White",
            "seller_name": "CheapTechSeller",
            "description": "Counterfeit replica headphones",
            "price": "99.00",
            "target_brand": "Apple"
        }
        response = client.post("/api/listing-check", data=data)
        self.assertEqual(response.status_code, 200)
        res = response.json()
        self.assertEqual(res["status"], "success")
        self.assertIn("verdict", res["data"])
        self.assertTrue(res["data"]["price_anomaly"])

    def test_05_api_listing_batch_upload_endpoint(self):
        payload = {
            "listings": [
                {
                    "title": "Louis Vuitton Monogram Handbag Replica",
                    "seller_name": "FakeBagsShop",
                    "price": 150.00,
                    "target_brand": "Louis Vuitton"
                },
                {
                    "title": "Ray-Ban Classic Wayfarer Genuine",
                    "seller_name": "OfficialEyewear",
                    "price": 160.00,
                    "target_brand": "Ray-Ban"
                }
            ]
        }
        response = client.post("/api/listing-batch-upload", json=payload)
        self.assertEqual(response.status_code, 200)
        res = response.json()
        self.assertEqual(res["status"], "success")
        self.assertEqual(res["data"]["total_ingested"], 2)

    def test_06_api_listing_sample_data_endpoint(self):
        response = client.get("/api/listing-sample-data")
        self.assertEqual(response.status_code, 200)
        res = response.json()
        self.assertEqual(res["status"], "success")
        self.assertGreaterEqual(res["data"]["count"], 5)


if __name__ == "__main__":
    unittest.main()
