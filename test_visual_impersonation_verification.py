import unittest
import os
import tempfile
from pathlib import Path
from services.impersonation_service import (
    calculate_impersonation_evidence,
    evaluate_visual_similarity,
    extract_brand_text_evidence,
    detect_credential_taking_indicators
)


class TestVisualImpersonationVerification(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.dummy_img_1 = Path(self.temp_dir.name) / "img1.png"
        self.dummy_img_2 = Path(self.temp_dir.name) / "img2.png"

        from PIL import Image
        img1 = Image.new("RGB", (100, 100), color="blue")
        img1.save(self.dummy_img_1)
        img2 = Image.new("RGB", (100, 100), color="blue")
        img2.save(self.dummy_img_2)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_01_official_amazon_domain_with_logo(self):
        """Test 1: Target Amazon logo on official amazon.com -> TARGET_BRAND_ON_OFFICIAL_DOMAIN."""
        visual_analysis = {"status": "success", "brands": [{"brand": "Amazon", "confidence": 0.98}]}
        res = calculate_impersonation_evidence(
            candidate_domain="amazon.com",
            target_brand="Amazon",
            official_domains=["amazon.com"],
            sources=["dnstwist"],
            is_known_phishing=False,
            visual_analysis=visual_analysis
        )
        self.assertEqual(res["classification"], "TARGET_BRAND_ON_OFFICIAL_DOMAIN")
        self.assertTrue(res["official_domain_match"])

    def test_02_unrelated_domain_with_amazon_logo(self):
        """Test 2: Unrelated domain + Amazon logo -> POTENTIAL_IMPERSONATION."""
        visual_analysis = {"status": "success", "brands": [{"brand": "Amazon", "confidence": 0.70}]}
        res = calculate_impersonation_evidence(
            candidate_domain="amazon-security-login.xyz",
            target_brand="Amazon",
            official_domains=["amazon.com"],
            sources=["dnstwist"],
            is_known_phishing=False,
            visual_analysis=visual_analysis
        )
        self.assertIn(res["classification"], ["POTENTIAL_IMPERSONATION", "LIKELY_IMPERSONATION"])

    def test_03_unrelated_domain_with_high_visual_similarity(self):
        """Test 3: Unrelated domain + Amazon logo + high visual similarity -> LIKELY_IMPERSONATION."""
        visual_analysis = {"status": "success", "brands": [{"brand": "Amazon", "confidence": 0.96}]}
        res = calculate_impersonation_evidence(
            candidate_domain="amazon-security-login.xyz",
            target_brand="Amazon",
            official_domains=["amazon.com"],
            sources=["dnstwist"],
            is_known_phishing=False,
            visual_analysis=visual_analysis,
            candidate_image_path=str(self.dummy_img_1),
            reference_image_path=str(self.dummy_img_2)
        )
        self.assertIn(res["classification"], ["LIKELY_IMPERSONATION", "STRONG_IMPERSONATION_EVIDENCE"])
        self.assertIn("visual_similarity", res["signals"])

    def test_04_full_5_signal_impersonation_fusion(self):
        """Test 4: Unrelated domain + logo + password field + brand text -> STRONG_IMPERSONATION_EVIDENCE."""
        visual_analysis = {"status": "success", "brands": [{"brand": "Amazon", "confidence": 0.97}]}
        html_content = '<html><head><title>Amazon Sign In</title></head><body><form><input type="password" name="pwd"/><button>Sign in</button></form></body></html>'
        page_text = "Amazon Sign In. Enter your password to access your Amazon account."

        res = calculate_impersonation_evidence(
            candidate_domain="amazon-verify-login.xyz",
            target_brand="Amazon",
            official_domains=["amazon.com"],
            sources=["dnstwist", "openphish"],
            is_known_phishing=True,
            visual_analysis=visual_analysis,
            candidate_image_path=str(self.dummy_img_1),
            reference_image_path=str(self.dummy_img_2),
            page_text=page_text,
            page_title="Amazon Sign In",
            html_content=html_content
        )

        self.assertEqual(res["classification"], "STRONG_IMPERSONATION_EVIDENCE")
        self.assertEqual(res["evidence_strength"], "STRONG")
        self.assertGreater(len(res["reasons"]), 3)

    def test_05_generic_login_page_no_logo(self):
        """Test 5: Generic login page with no Amazon logo -> NO_TARGET_BRAND_DETECTED."""
        visual_analysis = {"status": "success", "brands": []}
        res = calculate_impersonation_evidence(
            candidate_domain="generic-login.com",
            target_brand="Amazon",
            official_domains=["amazon.com"],
            sources=["dnstwist"],
            is_known_phishing=False,
            visual_analysis=visual_analysis
        )
        self.assertEqual(res["classification"], "NO_TARGET_BRAND_DETECTED")

    def test_06_legitimate_partner_related_domain(self):
        """Test 6: Amazon logo on legitimate partner/related domain -> RELATED_DOMAIN_REVIEW."""
        visual_analysis = {"status": "success", "brands": [{"brand": "Amazon", "confidence": 0.99}]}
        res = calculate_impersonation_evidence(
            candidate_domain="amazon.co.uk",
            target_brand="Amazon",
            official_domains=["amazon.com"],
            sources=["dnstwist"],
            is_known_phishing=False,
            visual_analysis=visual_analysis
        )
        self.assertEqual(res["classification"], "RELATED_DOMAIN_REVIEW")

    def test_07_phishpedia_unavailable_fallback(self):
        """Test 7: Phishpedia unavailable -> non-visual signals evaluate cleanly without crash."""
        visual_analysis = {"status": "unavailable", "reason": "Weights missing", "brands": []}
        html_content = '<form><input type="password"/></form>'
        res = calculate_impersonation_evidence(
            candidate_domain="suspicious-site.xyz",
            target_brand="Amazon",
            official_domains=["amazon.com"],
            sources=["dnstwist", "phishtank"],
            is_known_phishing=True,
            visual_analysis=visual_analysis,
            html_content=html_content
        )
        self.assertEqual(res["classification"], "POTENTIAL_IMPERSONATION")
        self.assertFalse(res["brand_match"])

    def test_08_visual_similarity_unavailable_fallback(self):
        """Test 8: Visual similarity unavailable -> scan completes cleanly."""
        sim = evaluate_visual_similarity(None, None)
        self.assertEqual(sim["status"], "unavailable")
        self.assertEqual(sim["similarity_level"], "UNKNOWN")

    def test_09_dom_extraction_fallback(self):
        """Test 9: DOM extraction fails -> credential indicators return NONE without crash."""
        cred = detect_credential_taking_indicators(None, None)
        self.assertEqual(cred["assessment"], "NONE")
        self.assertEqual(cred["password_fields"], 0)


if __name__ == "__main__":
    unittest.main()
