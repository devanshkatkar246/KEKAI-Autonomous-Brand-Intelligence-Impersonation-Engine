import unittest
import os
import tempfile
from pathlib import Path
from services.impersonation_service import (
    evaluate_domain_relationship,
    calculate_impersonation_evidence,
    execute_brand_impersonation_scan,
    clean_domain_string
)


class TestImpersonationDiscovery(unittest.TestCase):

    def test_01_legitimate_official_site(self):
        """Test 1: Target Amazon on amazon.com -> TARGET_BRAND_ON_OFFICIAL_DOMAIN."""
        rel, is_match = evaluate_domain_relationship("https://www.amazon.com/login", ["amazon.com"])
        self.assertTrue(is_match)
        self.assertEqual(rel, "official")

        visual_analysis = {
            "status": "success",
            "detected": True,
            "brands": [{"brand": "Amazon", "confidence": 0.98, "bounding_box": [10, 10, 50, 50]}]
        }

        res = calculate_impersonation_evidence(
            candidate_domain="amazon.com",
            target_brand="Amazon",
            official_domains=["amazon.com"],
            sources=["dnstwist"],
            is_known_phishing=False,
            visual_analysis=visual_analysis
        )

        self.assertTrue(res["official_domain_match"])
        self.assertTrue(res["brand_match"])
        self.assertEqual(res["classification"], "TARGET_BRAND_ON_OFFICIAL_DOMAIN")
        self.assertEqual(res["evidence_strength"], "NONE")

    def test_02_amazon_impersonation_candidate(self):
        """Test 2: Amazon logo on suspicious domain -> LIKELY_IMPERSONATION or STRONG_IMPERSONATION_EVIDENCE."""
        rel, is_match = evaluate_domain_relationship("amazon-security-login.xyz", ["amazon.com"])
        self.assertFalse(is_match)
        self.assertEqual(rel, "unrelated")

        visual_analysis = {
            "status": "success",
            "detected": True,
            "brands": [{"brand": "Amazon", "confidence": 0.968, "bounding_box": [120, 80, 310, 145]}]
        }

        res = calculate_impersonation_evidence(
            candidate_domain="amazon-security-login.xyz",
            target_brand="Amazon",
            official_domains=["amazon.com"],
            sources=["dnstwist", "openphish"],
            is_known_phishing=True,
            visual_analysis=visual_analysis
        )

        self.assertFalse(res["official_domain_match"])
        self.assertTrue(res["brand_match"])
        self.assertIn(res["classification"], ["LIKELY_IMPERSONATION", "STRONG_IMPERSONATION_EVIDENCE"])

    def test_03_different_brand_logo(self):
        """Test 3: Microsoft logo on screenshot when target is Amazon -> brand_match = False."""
        visual_analysis = {
            "status": "success",
            "detected": True,
            "brands": [{"brand": "Microsoft", "confidence": 0.94, "bounding_box": [50, 50, 100, 100]}]
        }

        res = calculate_impersonation_evidence(
            candidate_domain="microsoft-login.com",
            target_brand="Amazon",
            official_domains=["amazon.com"],
            sources=["dnstwist"],
            is_known_phishing=False,
            visual_analysis=visual_analysis
        )

        self.assertFalse(res["brand_match"])
        self.assertNotIn(res["classification"], ["LIKELY_IMPERSONATION", "STRONG_IMPERSONATION_EVIDENCE"])

    def test_04_no_logo_detected(self):
        """Test 4: Plain page with no logo -> NO_TARGET_BRAND_DETECTED."""
        visual_analysis = {
            "status": "success",
            "detected": False,
            "brands": []
        }

        res = calculate_impersonation_evidence(
            candidate_domain="example.com",
            target_brand="Amazon",
            official_domains=["amazon.com"],
            sources=["dnstwist"],
            is_known_phishing=False,
            visual_analysis=visual_analysis
        )

        self.assertFalse(res["brand_match"])
        self.assertEqual(res["classification"], "NO_TARGET_BRAND_DETECTED")

    def test_05_phishpedia_unavailable_fallback(self):
        """Test 5: Phishpedia unavailable -> non-visual domain analysis continues cleanly."""
        visual_analysis = {
            "status": "unavailable",
            "reason": "Model weights missing",
            "brands": []
        }

        res = calculate_impersonation_evidence(
            candidate_domain="amazon-alert.xyz",
            target_brand="Amazon",
            official_domains=["amazon.com"],
            sources=["dnstwist", "openphish"],
            is_known_phishing=True,
            visual_analysis=visual_analysis
        )

        self.assertFalse(res["brand_match"])
        self.assertIn(res["classification"], ["POTENTIAL_IMPERSONATION", "KNOWN_PHISHING_UNRELATED_LOGO"])

    def test_06_candidate_prioritization_and_cap(self):
        """Test 6: Bounded candidate scan respects max_candidates limit."""
        scan_output = execute_brand_impersonation_scan(
            target_brand="Amazon",
            official_domain="amazon.com",
            max_candidates=10
        )
        self.assertEqual(scan_output["target_brand"], "Amazon")
        self.assertLessEqual(scan_output["total_candidates_analyzed"], 10)
        self.assertIsInstance(scan_output["results"], list)

    def test_07_legitimate_related_domain(self):
        """Test 7: Regional/partner domain -> RELATED_DOMAIN_REVIEW (not marked malicious)."""
        rel, is_match = evaluate_domain_relationship("amazon.co.uk", ["amazon.com"])
        self.assertFalse(is_match)
        self.assertEqual(rel, "related")

        visual_analysis = {
            "status": "success",
            "detected": True,
            "brands": [{"brand": "Amazon", "confidence": 0.99, "bounding_box": [10, 10, 50, 50]}]
        }

        res = calculate_impersonation_evidence(
            candidate_domain="amazon.co.uk",
            target_brand="Amazon",
            official_domains=["amazon.com"],
            sources=["dnstwist"],
            is_known_phishing=False,
            visual_analysis=visual_analysis
        )

        self.assertEqual(res["domain_relationship"], "related")
        self.assertEqual(res["classification"], "RELATED_DOMAIN_REVIEW")
        self.assertEqual(res["evidence_strength"], "LOW")


if __name__ == "__main__":
    unittest.main()
