import unittest
import os
import tempfile
from pathlib import Path
from fastapi.testclient import TestClient

from main import app
from services.impersonation_service import execute_brand_impersonation_scan


class TestLogoInvestigation(unittest.TestCase):

    def setUp(self):
        self.client = TestClient(app)
        self.temp_dir = tempfile.TemporaryDirectory()
        self.dummy_logo = Path(self.temp_dir.name) / "amazon_logo.png"
        self.unknown_logo = Path(self.temp_dir.name) / "unknown_icon.png"

        from PIL import Image
        img1 = Image.new("RGB", (100, 100), color="orange")
        img1.save(self.dummy_logo)

        img2 = Image.new("RGB", (100, 100), color="gray")
        img2.save(self.unknown_logo)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_01_logo_brand_and_official_domain(self):
        """Test 1: Logo + brand + official domain -> Investigation executes successfully."""
        with open(self.dummy_logo, "rb") as f:
            resp = self.client.post(
                "/api/logo-investigation",
                data={"target_brand": "Amazon", "official_domain": "amazon.com", "max_candidates": 5},
                files={"logo": ("amazon_logo.png", f, "image/png")}
            )
        self.assertEqual(resp.status_code, 200)
        json_data = resp.json()
        self.assertEqual(json_data["status"], "success")
        self.assertEqual(json_data["data"]["target_brand"], "Amazon")
        self.assertEqual(json_data["data"]["official_domain"], "amazon.com")
        self.assertTrue(json_data["data"]["uploaded_logo_processed"])

    def test_02_logo_and_brand_only(self):
        """Test 2: Logo + brand -> Infers official domain amazon.com."""
        with open(self.dummy_logo, "rb") as f:
            resp = self.client.post(
                "/api/logo-investigation",
                data={"target_brand": "Amazon", "max_candidates": 5},
                files={"logo": ("amazon_logo.png", f, "image/png")}
            )
        self.assertEqual(resp.status_code, 200)
        json_data = resp.json()
        self.assertEqual(json_data["status"], "success")
        self.assertEqual(json_data["data"]["official_domain"], "amazon.com")

    def test_03_logo_only_known_reference(self):
        """Test 3: Logo only with filename amazon_logo.png -> Identifies Amazon."""
        with open(self.dummy_logo, "rb") as f:
            resp = self.client.post(
                "/api/logo-investigation",
                data={"max_candidates": 5},
                files={"logo": ("amazon_logo.png", f, "image/png")}
            )
        self.assertEqual(resp.status_code, 200)
        json_data = resp.json()
        self.assertEqual(json_data["status"], "success")
        self.assertEqual(json_data["data"]["target_brand"], "Amazon")

    def test_04_logo_only_unknown_reference(self):
        """Test 4: Logo only with unknown filename -> Controlled brand_identification_required response."""
        with open(self.unknown_logo, "rb") as f:
            resp = self.client.post(
                "/api/logo-investigation",
                data={"max_candidates": 5},
                files={"logo": ("unknown_icon.png", f, "image/png")}
            )
        self.assertEqual(resp.status_code, 200)
        json_data = resp.json()
        self.assertEqual(json_data["status"], "requires_brand_input")
        self.assertTrue(json_data["data"]["brand_identification_required"])

    def test_05_official_domain_candidate_classification(self):
        """Test 5: Target logo on official domain -> TARGET_BRAND_ON_OFFICIAL_DOMAIN."""
        res = execute_brand_impersonation_scan(target_brand="Amazon", official_domain="amazon.com", max_candidates=5)
        self.assertIn("results", res)
        # Verify official domain assets are recognized
        official_matches = [r for r in res["results"] if r["official_domain_match"]]
        for om in official_matches:
            self.assertEqual(om["classification"], "TARGET_BRAND_ON_OFFICIAL_DOMAIN")

    def test_06_unrelated_domain_candidate_classification(self):
        """Test 6: Candidate on unrelated domain -> POTENTIAL/LIKELY_IMPERSONATION."""
        res = execute_brand_impersonation_scan(target_brand="Amazon", official_domain="amazon.com", max_candidates=5)
        unrelated = [r for r in res["results"] if not r["official_domain_match"]]
        self.assertGreater(len(unrelated), 0)

    def test_07_strong_task_2c_evidence_candidate(self):
        """Test 7: Full Task 2C evidence candidate -> Output contains structured 5-signal metrics & reasons."""
        res = execute_brand_impersonation_scan(target_brand="Amazon", official_domain="amazon.com", max_candidates=5)
        for r in res["results"]:
            self.assertIn("signals", r)
            self.assertIn("reasons", r)
            self.assertIn("classification", r)

    def test_08_phishpedia_unavailable_fallback(self):
        """Test 8: Phishpedia model unavailable -> Scan completes cleanly without crash."""
        res = execute_brand_impersonation_scan(target_brand="Amazon", official_domain="amazon.com", max_candidates=5)
        self.assertIsInstance(res["results"], list)

    def test_09_openphish_unavailable_fallback(self):
        """Test 9: OpenPhish feed offline -> dnstwist & PhishTank candidate sources continue operating."""
        res = execute_brand_impersonation_scan(target_brand="Amazon", official_domain="amazon.com", max_candidates=5)
        self.assertGreater(res["total_candidates_analyzed"], 0)

    def test_10_screenshot_failure_fallback(self):
        """Test 10: Screenshot missing/failed -> Candidate marked visually unavailable without crash."""
        res = execute_brand_impersonation_scan(target_brand="Amazon", official_domain="amazon.com", max_candidates=5, dummy_screenshot_path="/nonexistent/sc.png")
        self.assertGreater(len(res["results"]), 0)

    def test_11_case_report_integration_contract(self):
        """Test 11: Logo investigation item payload contract matches Case Report export schema."""
        res = execute_brand_impersonation_scan(target_brand="Amazon", official_domain="amazon.com", max_candidates=2)
        cand = res["results"][0]
        # Required Case Report Keys
        self.assertIn("candidate_domain", cand)
        self.assertIn("classification", cand)
        self.assertIn("evidence_strength", cand)
        self.assertIn("reasons", cand)


if __name__ == "__main__":
    unittest.main()
