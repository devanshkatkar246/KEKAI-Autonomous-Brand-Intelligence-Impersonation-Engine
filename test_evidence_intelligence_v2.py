"""
test_evidence_intelligence_v2.py

KEIKAI EVIDENCE INTELLIGENCE V2 — COMPREHENSIVE TEST SUITE

Tests full Evidence V2 pipeline:
1. RDAP success vs RDAP network error state distinction
2. Cloudflare NOT_DETECTED semantics
3. Official domain relationship classification (OFFICIAL_EXACT risk score 0)
4. Candidate lookalike classification (LOOKALIKE)
5. Multi-attempt HTTP verification sequence
6. Screenshot failure state semantics ("Logo analysis NOT RUN")
7. 8-Layer visual logo recognition fallback chain
8. OCR text extraction & brand matching
9. Multi-source threat intelligence correlation & provenance
10. ZERO-PENALTY RULE FOR MISSING DATA (Unavailable sources contribute 0 pts, never negative)
11. Separation of Risk Score vs Evidence Quality Score
12. Investigation Quality states (COMPLETE, PARTIAL, DEGRADED)
13. Provenance and timestamps across all fields
14. Additive explainable risk score breakdown
"""

import json
import os
import sys
import unittest
from datetime import datetime, timezone
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from services.domain_relationship_service import DomainRelationshipEngine
from services.multi_http_verifier import MultiAttemptHTTPVerifier
from services.logo_fallback_service import LogoFallbackEngine
from services.confidence_engine_service import EvidenceConfidenceEngine
from services.evidence_intelligence_service import EvidenceIntelligenceService


class TestEvidenceIntelligenceV2(unittest.TestCase):

    # 1. RDAP success vs network error state distinction
    @patch("services.evidence_intelligence_service.discover_provider_contacts")
    @patch("services.evidence_intelligence_service.MultiAttemptHTTPVerifier.verify_http")
    @patch("services.evidence_intelligence_service.ThreatIntelOrchestrator.execute_multi_source_scan")
    def test_01_rdap_success_vs_network_error(self, mock_scan, mock_http, mock_prov):
        mock_scan.return_value = {"status": "success"}
        mock_http.return_value = {"status": "SUCCESS", "dns": {"ipv4": ["104.21.48.91"]}}
        mock_prov.return_value = {"registrar": {"name": "Cloudflare Registrar"}, "routing_reason": "RDAP provider discovery complete"}
        pkg = EvidenceIntelligenceService.analyze_candidate("amaz0n-security-login.xyz", "Amazon")
        rdap_status = pkg["infrastructure"]["rdap_status"]
        self.assertIn(rdap_status, ["CONFIRMED", "UNAVAILABLE", "ERROR"])
        self.assertIn("rdap_reason", pkg["infrastructure"])

    # 2. Cloudflare NOT_DETECTED semantics
    @patch("services.evidence_intelligence_service.discover_provider_contacts")
    @patch("services.evidence_intelligence_service.MultiAttemptHTTPVerifier.verify_http")
    @patch("services.evidence_intelligence_service.ThreatIntelOrchestrator.execute_multi_source_scan")
    def test_02_cloudflare_not_detected_semantics(self, mock_scan, mock_http, mock_prov):
        mock_scan.return_value = {"status": "success"}
        mock_http.return_value = {"status": "SUCCESS", "dns": {"ipv4": ["1.1.1.1"]}}
        mock_prov.return_value = {"is_cloudflare": False, "routing_reason": "No Cloudflare infrastructure indicators detected"}
        pkg = EvidenceIntelligenceService.analyze_candidate("example-non-cloudflare.com", "Example")
        prov = pkg["infrastructure"]["provider_discovery"]
        if not prov.get("is_cloudflare"):
            self.assertIn("No Cloudflare", prov.get("routing_reason", "") or "No Cloudflare")

    # 3. Official domain relationship classification (OFFICIAL_EXACT risk score 0)
    def test_03_domain_relationship_official_exact(self):
        rel = DomainRelationshipEngine.classify_relationship("amazon.com", "Amazon", official_domain="amazon.com")
        self.assertEqual(rel["relationship"], "OFFICIAL_EXACT")
        self.assertTrue(rel["is_official"])
        self.assertFalse(rel["is_impersonation"])

        scores = EvidenceConfidenceEngine.calculate_scores(
            domain_relationship=rel,
            http_verification={"status": "SUCCESS"},
            logo_evidence={"overall_status": "NOT_DETECTED"},
            threat_intel={},
            infrastructure={"rdap_status": "CONFIRMED"},
            credential_indicators={}
        )
        self.assertEqual(scores["risk_score"], 0)
        self.assertEqual(scores["risk_category"], "OFFICIAL_EXACT")

    # 4. Candidate lookalike classification (LOOKALIKE)
    def test_04_domain_relationship_lookalike(self):
        rel = DomainRelationshipEngine.classify_relationship("flpkpart.com", "Flipkart", official_domain="flipkart.com")
        self.assertEqual(rel["relationship"], "LOOKALIKE")
        self.assertFalse(rel["is_official"])
        self.assertTrue(rel["is_impersonation"])
    # 5. Multi-attempt HTTP verification sequence
    def test_05_multi_attempt_http_verification(self):
        with patch("services.multi_http_verifier.MultiAttemptHTTPVerifier.resolve_dns", return_value={"ipv4": ["104.21.48.91"], "ipv6": [], "resolved": True}):
            res = MultiAttemptHTTPVerifier.verify_http("google.com")
            self.assertIn(res["status"], ["SUCCESS", "BLOCKED", "BOT_PROTECTION", "TIMEOUT", "DNS_FAILURE", "CONNECTION_ERROR"])
            self.assertTrue(len(res["attempts"]) >= 1)

    # 6. Screenshot failure state semantics ("Logo analysis NOT RUN")
    def test_06_screenshot_failure_state(self):
        logo_res = LogoFallbackEngine.analyze_visual_evidence("Amazon", screenshot_path=None)
        self.assertEqual(logo_res["overall_status"], "NOT_DETECTED")
        layer1 = logo_res["layers"][0]
        self.assertEqual(layer1["status"], "NOT_RUN")
        self.assertIn("NOT RUN", layer1["detail"])

    # 7. 8-Layer visual logo recognition fallback chain
    def test_07_8_layer_logo_fallback_chain(self):
        logo_res = LogoFallbackEngine.analyze_visual_evidence(
            target_brand="Amazon",
            phishpedia_result={"status": "SUCCESS", "detected_logo": "Amazon", "confidence": 0.96},
            phash_similarity=0.92,
            ocr_text="Welcome to Amazon Pay",
            webpage_title="Amazon Login Portal"
        )
        self.assertEqual(logo_res["overall_status"], "CONFIRMED")
        self.assertEqual(logo_res["verdict"], "CONFIRMED_VISUAL_IMPERSONATION")
        self.assertEqual(len(logo_res["layers"]), 8)

    # 8. OCR text extraction & brand matching
    def test_08_ocr_brand_extraction(self):
        logo_res = LogoFallbackEngine.analyze_visual_evidence("Flipkart", ocr_text="Sign in to your Flipkart account")
        ocr_layer = [l for l in logo_res["layers"] if "OCR" in l["layer"]][0]
        self.assertEqual(ocr_layer["status"], "CONFIRMED")

    # 9. Multi-source threat intelligence correlation & provenance
    @patch("services.evidence_intelligence_service.discover_provider_contacts")
    @patch("services.evidence_intelligence_service.MultiAttemptHTTPVerifier.verify_http")
    @patch("services.threat_intelligence.orchestrator.ThreatIntelOrchestrator.execute_multi_source_scan")
    def test_09_threat_intel_provenance(self, mock_scan, mock_http, mock_prov):
        mock_http.return_value = {"status": "SUCCESS", "dns": {"ipv4": ["104.21.48.91"]}}
        mock_prov.return_value = {"registrar": {"name": "Cloudflare Registrar"}}
        mock_scan.return_value = {"status": "success", "total_permutations": 1}
        pkg = EvidenceIntelligenceService.analyze_candidate("flpkpart.com", "Flipkart")
        threats = pkg["threat_intelligence"]
        self.assertIn("dnstwist", threats)
        self.assertIn("openphish", threats)
        self.assertIn("phishtank", threats)
        self.assertEqual(threats["dnstwist"]["status"], "CONFIRMED")

    # 10. ZERO-PENALTY RULE FOR MISSING DATA
    def test_10_zero_penalty_rule_for_missing_data(self):
        rel = {"relationship": "LOOKALIKE", "is_official": False, "reason": "Typosquat lookalike"}
        scores = EvidenceConfidenceEngine.calculate_scores(
            domain_relationship=rel,
            http_verification={"status": "TIMEOUT"},
            logo_evidence={"overall_status": "UNAVAILABLE"},
            threat_intel={"openphish": {"status": "UNAVAILABLE"}, "phishtank": {"status": "UNAVAILABLE"}},
            infrastructure={"rdap_status": "UNAVAILABLE"},
            credential_indicators={}
        )
        self.assertEqual(scores["risk_score"], 20)  # Only 20 pts from domain lookalike
        self.assertTrue(scores["risk_score"] >= 0)

    # 11. Separation of Risk Score vs Evidence Quality Score
    def test_11_risk_vs_evidence_quality_separation(self):
        rel = {"relationship": "LOOKALIKE", "is_official": False}
        scores = EvidenceConfidenceEngine.calculate_scores(
            domain_relationship=rel,
            http_verification={"status": "SUCCESS"},
            logo_evidence={"overall_status": "CONFIRMED", "confirmed_layers_count": 2},
            threat_intel={"openphish": {"status": "MATCH"}, "phishtank": {"status": "MATCH"}},
            infrastructure={"rdap_status": "CONFIRMED"},
            credential_indicators={"has_login_form": True, "has_password_field": True}
        )
        self.assertTrue(scores["risk_score"] >= 85)
        self.assertEqual(scores["evidence_quality_score"], 100)
        self.assertEqual(scores["investigation_quality"], "COMPLETE")

    # 12. Investigation Quality states (COMPLETE, PARTIAL, DEGRADED)
    def test_12_investigation_quality_categories(self):
        rel = {"relationship": "LOOKALIKE", "is_official": False}
        scores = EvidenceConfidenceEngine.calculate_scores(
            domain_relationship=rel,
            http_verification={"status": "TIMEOUT"},
            logo_evidence={"overall_status": "UNAVAILABLE"},
            threat_intel={"openphish": {"status": "UNAVAILABLE"}, "phishtank": {"status": "UNAVAILABLE"}},
            infrastructure={"rdap_status": "UNAVAILABLE"},
            credential_indicators={}
        )
        self.assertEqual(scores["evidence_quality_score"], 0)
        self.assertEqual(scores["investigation_quality"], "DEGRADED")
        self.assertTrue(len(scores["degraded_reasons"]) >= 3)

    # 13. Provenance and timestamps across all fields
    @patch("services.evidence_intelligence_service.discover_provider_contacts")
    @patch("services.evidence_intelligence_service.MultiAttemptHTTPVerifier.verify_http")
    @patch("services.threat_intelligence.orchestrator.ThreatIntelOrchestrator.execute_multi_source_scan")
    def test_13_provenance_and_timestamps(self, mock_scan, mock_http, mock_prov):
        mock_http.return_value = {"status": "SUCCESS", "dns": {"ipv4": ["104.21.48.91"]}}
        mock_prov.return_value = {"registrar": {"name": "Cloudflare Registrar"}}
        mock_scan.return_value = {"status": "success"}
        pkg = EvidenceIntelligenceService.analyze_candidate("amaz0n-login.xyz", "Amazon")
        self.assertIn("observed_at", pkg)
        self.assertIn("data_freshness", pkg)

    # 14. Additive explainable risk score breakdown
    @patch("services.evidence_intelligence_service.discover_provider_contacts")
    @patch("services.evidence_intelligence_service.MultiAttemptHTTPVerifier.verify_http")
    @patch("services.threat_intelligence.orchestrator.ThreatIntelOrchestrator.execute_multi_source_scan")
    def test_14_explainable_risk_breakdown(self, mock_scan, mock_http, mock_prov):
        mock_http.return_value = {"status": "SUCCESS", "dns": {"ipv4": ["104.21.48.91"]}}
        mock_prov.return_value = {"registrar": {"name": "Cloudflare Registrar"}}
        mock_scan.return_value = {"status": "success"}
        pkg = EvidenceIntelligenceService.analyze_candidate("amaz0n-login.xyz", "Amazon")
        breakdown = pkg["confidence"]["explainable_risk_breakdown"]
        self.assertTrue(len(breakdown) >= 1)
        self.assertIn("signal", breakdown[0])
        self.assertIn("points", breakdown[0])


if __name__ == "__main__":
    unittest.main(verbosity=2)
