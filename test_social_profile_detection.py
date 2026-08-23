import unittest
from fastapi.testclient import TestClient
from main import app
from services.social_profile_service import (
    analyze_social_profile,
    toggle_social_allowlist_handle,
    get_sample_social_profiles
)

client = TestClient(app)


class TestSocialProfileDetection(unittest.TestCase):

    def test_01_fake_social_profile_analysis(self):
        res = analyze_social_profile(
            platform="Instagram",
            handle="@rolex_fake_vip_support",
            display_name="Rolex Official Support",
            bio_text="Official Rolex support & free watch giveaway bot",
            follower_count=120,
            account_age_days=10,
            target_brand="Rolex"
        )
        self.assertEqual(res["verdict"], "High Risk Fake Account")
        self.assertGreater(res["risk_rating"], 70.0)
        self.assertFalse(res["is_verified_official"])
        self.assertTrue(res["age_penalty"])

    def test_02_creator_giveaway_impersonation_analysis(self):
        res = analyze_social_profile(
            platform="X (Twitter)",
            handle="@alexrivers_tech_giveaway",
            display_name="Alex Rivers — Free ETH Giveaway",
            bio_text="Official tech giveaway! Send 0.1 ETH get 1 ETH back, DM for claim link",
            follower_count=350,
            account_age_days=5,
            protected_entity="Alex Rivers (Tech Creator - Demo)",
            entity_type="individual",
            official_handle="@alexrivers_tech"
        )
        self.assertEqual(res["verdict"], "High Risk Creator Impersonator / Scam")
        self.assertGreater(res["risk_rating"], 75.0)
        self.assertEqual(res["intent_label"], "Scam/giveaway impersonation")
        self.assertTrue(res["handle_spoof_penalty"])

    def test_03_handle_allowlist_override(self):
        toggle_res = toggle_social_allowlist_handle("@rolex_official_support", add=True)
        self.assertEqual(toggle_res["status"], "success")
        self.assertTrue(toggle_res["is_verified"])

        res = analyze_social_profile(
            platform="Instagram",
            handle="@rolex_official_support",
            display_name="Rolex Support",
            target_brand="Rolex"
        )
        self.assertEqual(res["verdict"], "Verified Official Account")
        self.assertEqual(res["risk_rating"], 0.0)
        self.assertTrue(res["is_verified_official"])

        toggle_social_allowlist_handle("@rolex_official_support", add=False)

    def test_04_sample_demo_profiles_retrieval(self):
        samples = get_sample_social_profiles()
        self.assertGreaterEqual(len(samples), 5)
        creators = [s for s in samples if s.get("entity_type") == "individual"]
        brands = [s for s in samples if s.get("entity_type") == "brand"]
        self.assertGreaterEqual(len(creators), 2)
        self.assertGreaterEqual(len(brands), 2)

    def test_05_api_social_profile_check_endpoint(self):
        data = {
            "platform": "X (Twitter)",
            "handle": "@AppleCare_FakeBot",
            "display_name": "Apple Care Bot",
            "bio_text": "DM for password reset",
            "follower_count": "50",
            "account_age_days": "5",
            "target_brand": "Apple"
        }
        response = client.post("/api/social-profile-check", data=data)
        self.assertEqual(response.status_code, 200)
        res = response.json()
        self.assertEqual(res["status"], "success")
        self.assertEqual(res["data"]["verdict"], "High Risk Fake Account")

    def test_06_api_creator_profile_check_endpoint(self):
        data = {
            "platform": "X (Twitter)",
            "handle": "@marcuschen_crypto_vip",
            "display_name": "Marcus Chen Crypto Mentorship",
            "bio_text": "Join free VIP signal telegram channel",
            "follower_count": "200",
            "account_age_days": "12",
            "protected_entity": "Marcus Chen (Crypto Educator - Demo)",
            "entity_type": "individual",
            "official_handle": "@marcuschen_crypto"
        }
        response = client.post("/api/social-profile-check", data=data)
        self.assertEqual(response.status_code, 200)
        res = response.json()
        self.assertEqual(res["status"], "success")
        self.assertEqual(res["data"]["verdict"], "High Risk Creator Impersonator / Scam")
        self.assertEqual(res["data"]["entity_type"], "individual")

    def test_07_api_social_profile_batch_upload_endpoint(self):
        payload = {
            "profiles": [
                {
                    "platform": "TikTok",
                    "handle": "@fake_louis_vuitton",
                    "display_name": "Free LV Bags",
                    "target_brand": "Louis Vuitton",
                    "entity_type": "brand"
                },
                {
                    "platform": "X (Twitter)",
                    "handle": "@alexrivers_giveaways",
                    "display_name": "Alex Rivers Free Tech",
                    "protected_entity": "Alex Rivers",
                    "entity_type": "individual"
                }
            ]
        }
        response = client.post("/api/social-profile-batch-upload", json=payload)
        self.assertEqual(response.status_code, 200)
        res = response.json()
        self.assertEqual(res["status"], "success")
        self.assertEqual(res["data"]["total_ingested"], 2)

    def test_08_api_social_profile_verify_override_endpoint(self):
        payload = {
            "handle": "@nike_store_official",
            "is_verified": True
        }
        response = client.post("/api/social-profile-verify-override", json=payload)
        self.assertEqual(response.status_code, 200)
        res = response.json()
        self.assertEqual(res["status"], "success")
        self.assertTrue(res["data"]["is_verified"])


if __name__ == "__main__":
    unittest.main()
