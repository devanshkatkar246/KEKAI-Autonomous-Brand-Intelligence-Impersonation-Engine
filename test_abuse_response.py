import hashlib
import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

from main import app
from services.abuse_response_service import (
    build_screenshot_artifact,
    evaluate_abuse_response,
    evaluate_evidence,
    evaluate_legitimacy,
)


REGISTRY = {
    "source": "BRAND_AUTHORIZATION_REGISTRY",
    "brands": {"amazon": {"domains": [
        {"domain": "amazon.in", "classification": "AUTHORIZED_DOMAIN"},
        {"domain": "partner.example.com", "classification": "KNOWN_PARTNER"},
        {"domain": "amazon-subsidiary.example", "classification": "KNOWN_SUBSIDIARY"},
        {"domain": "related.example.com", "classification": "KNOWN_RELATED_DOMAIN"},
    ]}},
}


def strong_evidence(**overrides):
    evidence = {
        "sources": ["dnstwist", "openphish"], "domain_permutation": True,
        "strong_visual_match": True, "credential_indicators": True,
        "screenshot": {"status": "SUCCESS", "source": "candidate_acquisition"},
    }
    evidence.update(overrides)
    return evidence


class TestAbuseResponse(unittest.TestCase):
    def test_01_official_domain_and_subdomain_are_blocked(self):
        for domain in ("https://amazon.com", "www.amazon.com", "login.amazon.com"):
            with self.subTest(domain=domain):
                decision = evaluate_legitimacy(domain, "amazon.com", "Amazon", REGISTRY, strong_evidence())
                self.assertEqual(decision["classification"], "OFFICIAL_DOMAIN")
                self.assertEqual(decision["reporting_eligibility"], "BLOCKED")

    def test_02_authorized_domain_and_subdomain_are_blocked(self):
        for domain in ("amazon.in", "login.amazon.in"):
            with self.subTest(domain=domain):
                decision = evaluate_legitimacy(domain, "amazon.com", "Amazon", REGISTRY, strong_evidence())
                self.assertEqual(decision["classification"], "AUTHORIZED_DOMAIN")
                self.assertEqual(decision["reporting_eligibility"], "BLOCKED")

    def test_03_partner_requires_manual_review(self):
        self.assertEqual(evaluate_legitimacy("portal.partner.example.com", "amazon.com", "Amazon", REGISTRY)["classification"], "KNOWN_PARTNER")

    def test_04_subsidiary_requires_manual_review(self):
        self.assertEqual(evaluate_legitimacy("console.amazon-subsidiary.example", "amazon.com", "Amazon", REGISTRY)["classification"], "KNOWN_SUBSIDIARY")

    def test_05_related_requires_manual_review(self):
        self.assertEqual(evaluate_legitimacy("related.example.com", "amazon.com", "Amazon", REGISTRY)["classification"], "KNOWN_RELATED_DOMAIN")

    def test_06_unknown_is_not_malicious(self):
        decision = evaluate_legitimacy("unrelated.example", "amazon.com", "Amazon", REGISTRY, {})
        self.assertEqual(decision["classification"], "UNKNOWN_DOMAIN")
        self.assertEqual(decision["reporting_eligibility"], "MANUAL_REVIEW_REQUIRED")

    def test_07_typosquat_and_homograph_are_suspicious_only_with_evidence(self):
        for domain in ("amaz0n-login.example", "xn--amzon-9za.example"):
            with self.subTest(domain=domain):
                decision = evaluate_legitimacy(domain, "amazon.com", "Amazon", REGISTRY, strong_evidence())
                self.assertEqual(decision["classification"], "SUSPICIOUS_UNAUTHORIZED_DOMAIN")

    def test_08_no_substring_authorization_match(self):
        decision = evaluate_legitimacy("amazon.com.attacker.example", "amazon.com", "Amazon", REGISTRY, strong_evidence())
        self.assertEqual(decision["classification"], "SUSPICIOUS_UNAUTHORIZED_DOMAIN")

    def test_09_strong_evidence_is_high_and_explainable(self):
        evidence = evaluate_evidence(strong_evidence(), candidate_domain="fake.example")
        self.assertEqual(evidence["evidence_level"], "EVIDENCE_HIGH")
        self.assertEqual(evidence["score_percent"], 100)
        self.assertEqual(len(evidence["signals"]), 5)

    def test_10_weak_evidence_is_low(self):
        evidence = evaluate_evidence({"sources": ["dnstwist"]})
        self.assertEqual(evidence["evidence_level"], "EVIDENCE_LOW")
        self.assertFalse(evidence["ready"])

    def test_11_feed_and_credentials_have_documented_contributions(self):
        evidence = evaluate_evidence({"sources": ["openphish"], "credential_indicators": True})
        self.assertEqual(evidence["score_percent"], 45)
        self.assertEqual(evidence["evidence_level"], "EVIDENCE_MEDIUM")

    def test_12_screenshot_failure_is_not_safe(self):
        evidence = evaluate_evidence({"screenshot": {"status": "FAILED"}})
        self.assertIn("Visual evidence unavailable: screenshot acquisition failed", evidence["missing"])
        self.assertEqual(evidence["screenshot_status"], "FAILED")

    def test_13_screenshot_not_run_is_missing(self):
        self.assertIn("Screenshot evidence not available", evaluate_evidence({})["missing"])

    def test_14_screenshot_hash_and_duplicate_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "evidence.png"
            path.write_bytes(b"fixed evidence bytes")
            first, second = build_screenshot_artifact(path), build_screenshot_artifact(path)
        expected = hashlib.sha256(b"fixed evidence bytes").hexdigest()
        self.assertEqual(first["artifact_hash"], expected)
        self.assertEqual(first["artifact_id"], second["artifact_id"])
        self.assertEqual(first["reference"], "evidence.png")
        self.assertNotIn(str(path.parent), str(first))

    def test_15_high_evidence_official_is_blocked(self):
        result = evaluate_abuse_response({"candidate_domain": "amazon.com", "official_domain": "amazon.com", "target_brand": "Amazon", "evidence": strong_evidence(), "authorization_registry": REGISTRY})
        self.assertEqual(result["reporting_eligibility"]["decision"], "BLOCKED")

    def test_16_high_evidence_unauthorized_is_ready_for_human_review(self):
        result = evaluate_abuse_response({"candidate_domain": "amaz0n-login.example", "official_domain": "amazon.com", "target_brand": "Amazon", "evidence": strong_evidence(), "authorization_registry": REGISTRY})
        self.assertEqual(result["reporting_eligibility"]["decision"], "READY_FOR_HUMAN_REVIEW")

    def test_17_low_evidence_unauthorized_is_insufficient(self):
        result = evaluate_abuse_response({"candidate_domain": "amaz0n-login.example", "official_domain": "amazon.com", "target_brand": "Amazon", "evidence": {"sources": ["dnstwist"]}, "authorization_registry": REGISTRY})
        self.assertEqual(result["reporting_eligibility"]["decision"], "INSUFFICIENT_EVIDENCE")

    def test_18_unknown_high_evidence_requires_manual_review(self):
        result = evaluate_abuse_response({"candidate_domain": "unrelated.example", "official_domain": "amazon.com", "target_brand": "Amazon", "evidence": {"strong_visual_match": True, "logo_detected": True, "page_content_brand_match": True, "screenshot": {"status": "SUCCESS"}}, "authorization_registry": REGISTRY})
        self.assertEqual(result["legitimacy"]["classification"], "UNKNOWN_DOMAIN")
        self.assertEqual(result["reporting_eligibility"]["decision"], "MANUAL_REVIEW_REQUIRED")

    def test_19_invalid_domain_requires_manual_review(self):
        result = evaluate_abuse_response({"candidate_domain": "", "official_domain": "amazon.com", "evidence": strong_evidence()})
        self.assertEqual(result["reporting_eligibility"]["decision"], "MANUAL_REVIEW_REQUIRED")

    def test_20_api_contract(self):
        client = TestClient(app)
        response = client.post("/api/abuse-response/evaluate", json={"investigation_id": "INV-1", "candidate_domain": "amaz0n-login.example", "target_brand": "Amazon", "official_domain": "amazon.com", "evidence": strong_evidence(), "authorization_registry": REGISTRY})
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["status"], "success")
        self.assertEqual(body["data"]["reporting_eligibility"]["decision"], "READY_FOR_HUMAN_REVIEW")


if __name__ == "__main__":
    unittest.main(verbosity=2)
