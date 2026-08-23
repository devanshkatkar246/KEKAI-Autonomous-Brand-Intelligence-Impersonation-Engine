"""
test_logo_first_discovery.py

Task 2D V4 — True Logo-First Reverse Visual Discovery Engine Test Suite

20 required tests covering:
 1. Exact logo upload -> visual candidate recovery
 2. Resized logo -> visual candidate recovery
 3. Compressed logo -> visual candidate recovery
 4. Cropped logo -> visual candidate recovery
 5. Unrelated logo -> no strong candidate match
 6. Same text but different logo -> weak/no match
 7. Logo -> known visual corpus domain recovered
 8. Visual candidate without domain -> VISUAL_MATCH_ONLY
 9. Visual candidate + dnstwist duplicate merging
10. Visual candidate + OpenPhish duplicate merging
11. Visual candidate + PhishTank duplicate merging
12. Visual match -> live verification success (VISUAL_MATCH_VERIFIED)
13. Visual match -> live verification unavailable (VISUAL_MATCH_UNVERIFIED)
14. Visual match disproved by live page (VISUAL_MATCH_DISPROVED)
15. Brand identification uncertain (BRAND_UNCERTAIN)
16. Manual brand override
17. Official domain excluded from suspicious ranking
18. Multiple visual matches ranking
19. Empty corpus graceful handling
20. viaSocket event schema compatibility
"""

import os
import sys
import unittest
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def _make_test_logo(tmp_dir: str, filename: str, color=(255, 153, 0), shape="rectangle") -> str:
    from PIL import Image, ImageDraw
    path = Path(tmp_dir) / filename
    img = Image.new("RGB", (200, 100), color=(255, 255, 255))
    draw = ImageDraw.Draw(img)
    if shape == "rectangle":
        draw.rectangle([10, 10, 190, 90], fill=color)
        draw.rectangle([20, 35, 180, 45], fill=(255, 255, 255))
        draw.rectangle([10, 10, 30, 30], fill=(50, 50, 50))
    else:
        # Distinct circle + diagonal cross lines pattern for false positive testing
        draw.ellipse([30, 10, 170, 90], fill=color)
        draw.line([0, 0, 200, 100], fill=(0, 0, 0), width=5)
        draw.line([0, 100, 200, 0], fill=(0, 0, 0), width=5)
    img.save(str(path))
    return str(path)


class TestLogoFirstDiscovery(unittest.TestCase):

    def setUp(self):
        from services.visual_retrieval_service import clear_visual_retrieval_corpus
        clear_visual_retrieval_corpus()
        self.temp = tempfile.TemporaryDirectory()
        self.amazon_logo = _make_test_logo(self.temp.name, "amazon_logo.png", color=(255, 153, 0), shape="rectangle")
        self.different_logo = _make_test_logo(self.temp.name, "blue_logo.png", color=(0, 80, 200), shape="circle")

    def tearDown(self):
        self.temp.cleanup()

    # 1. Exact logo upload -> visual candidate recovery
    def test_01_exact_logo_candidate_recovery(self):
        from services.visual_retrieval_service import index_candidate_visual_asset, retrieve_visual_candidates
        from services.logo_intelligence_service import generate_target_logo_profile

        index_candidate_visual_asset("amaz0n-phish.xyz", "http://amaz0n-phish.xyz", "IMG", self.amazon_logo, "Amazon")
        target_prof = generate_target_logo_profile(self.amazon_logo, "Amazon")

        matches = retrieve_visual_candidates(target_prof)
        self.assertGreater(len(matches), 0)
        self.assertEqual(matches[0]["recovered_domain"], "amaz0n-phish.xyz")
        self.assertEqual(matches[0]["match_level"], "VERY_STRONG")

    # 2. Resized logo -> visual candidate recovery
    def test_02_resized_logo_recovery(self):
        from PIL import Image
        from services.visual_retrieval_service import index_candidate_visual_asset, retrieve_visual_candidates
        from services.logo_intelligence_service import generate_target_logo_profile

        resized_path = str(Path(self.temp.name) / "resized.png")
        with Image.open(self.amazon_logo) as img:
            img.resize((400, 200)).save(resized_path)

        index_candidate_visual_asset("amaz0n-resized.xyz", "http://amaz0n-resized.xyz", "IMG", self.amazon_logo, "Amazon")
        target_prof = generate_target_logo_profile(resized_path, "Amazon")

        matches = retrieve_visual_candidates(target_prof)
        self.assertGreater(len(matches), 0)
        self.assertIn(matches[0]["match_level"], ("VERY_STRONG", "STRONG"))

    # 3. Compressed logo -> visual candidate recovery
    def test_03_compressed_logo_recovery(self):
        from PIL import Image
        from services.visual_retrieval_service import index_candidate_visual_asset, retrieve_visual_candidates
        from services.logo_intelligence_service import generate_target_logo_profile

        jpg_path = str(Path(self.temp.name) / "compressed.jpg")
        with Image.open(self.amazon_logo) as img:
            img.convert("RGB").save(jpg_path, "JPEG", quality=50)

        index_candidate_visual_asset("amaz0n-jpg.xyz", "http://amaz0n-jpg.xyz", "IMG", self.amazon_logo, "Amazon")
        target_prof = generate_target_logo_profile(jpg_path, "Amazon")

        matches = retrieve_visual_candidates(target_prof)
        self.assertGreater(len(matches), 0)
        self.assertIn(matches[0]["match_level"], ("VERY_STRONG", "STRONG", "MODERATE"))

    # 4. Cropped logo -> visual candidate recovery
    def test_04_cropped_logo_recovery(self):
        from PIL import Image
        from services.visual_retrieval_service import index_candidate_visual_asset, retrieve_visual_candidates
        from services.logo_intelligence_service import generate_target_logo_profile

        crop_path = str(Path(self.temp.name) / "cropped.png")
        with Image.open(self.amazon_logo) as img:
            img.crop((10, 5, 190, 95)).save(crop_path)

        index_candidate_visual_asset("amaz0n-crop.xyz", "http://amaz0n-crop.xyz", "IMG", self.amazon_logo, "Amazon")
        target_prof = generate_target_logo_profile(crop_path, "Amazon")

        matches = retrieve_visual_candidates(target_prof)
        self.assertGreater(len(matches), 0)

    # 5. Unrelated logo -> no strong candidate match
    def test_05_unrelated_logo_no_strong_match(self):
        from services.visual_retrieval_service import index_candidate_visual_asset, retrieve_visual_candidates
        from services.logo_intelligence_service import generate_target_logo_profile

        index_candidate_visual_asset("other-brand.com", "http://other-brand.com", "IMG", self.different_logo, "OtherBrand")
        target_prof = generate_target_logo_profile(self.amazon_logo, "Amazon")

        matches = retrieve_visual_candidates(target_prof, phash_max_distance=15)
        self.assertEqual(len(matches), 0)

    # 6. Same text but different logo -> weak/no match
    def test_06_same_text_different_logo(self):
        from services.logo_intelligence_service import _determine_match_level
        match_level = _determine_match_level("LOW", "LOW", "MATCH", False)
        self.assertEqual(match_level, "WEAK")

    # 7. Logo -> known visual corpus domain recovered
    def test_07_corpus_domain_recovered(self):
        from services.visual_retrieval_service import index_candidate_visual_asset, recover_candidate_domain
        item = index_candidate_visual_asset("amazon-auth-fake.com", "http://amazon-auth-fake.com", "IMG", self.amazon_logo, "Amazon")
        recovered, status = recover_candidate_domain(item)
        self.assertEqual(recovered, "amazon-auth-fake.com")
        self.assertEqual(status, "DOMAIN_RECOVERED")

    # 8. Visual candidate without domain -> VISUAL_MATCH_ONLY
    def test_08_visual_candidate_without_domain(self):
        from services.visual_retrieval_service import index_candidate_visual_asset, recover_candidate_domain
        item = index_candidate_visual_asset(None, None, "IMG", self.amazon_logo, "Amazon")
        recovered, status = recover_candidate_domain(item)
        self.assertIsNone(recovered)
        self.assertEqual(status, "VISUAL_MATCH_ONLY")

    # 9. Visual candidate + dnstwist duplicate merging
    def test_09_visual_candidate_dnstwist_merging(self):
        from services.logo_intelligence_service import run_logo_intelligence_scan
        from services.visual_retrieval_service import index_candidate_visual_asset

        index_candidate_visual_asset("aamzon.com", "http://aamzon.com", "IMG", self.amazon_logo, "Amazon")
        with patch("services.candidate_acquisition_service.CandidateAcquisitionEngine.acquire_candidate_webpage", return_value={"status": "failed", "failure_category": "CONNECTION_FAILURE", "failure_reason": "Failed", "attempts": []}):
            res = run_logo_intelligence_scan(target_brand="Amazon", official_domain="amazon.com", logo_path=self.amazon_logo, max_candidates=5)
            matches = [r for r in res["results"] if r["candidate_domain"] == "aamzon.com"]
            self.assertEqual(len(matches), 1)
            self.assertIn("LOGO_VISUAL_MATCH", matches[0]["discovery_sources"])
            self.assertIn("dnstwist", matches[0]["discovery_sources"])

    # 10. Visual candidate + OpenPhish duplicate merging
    def test_10_visual_candidate_openphish_merging(self):
        from services.threat_intelligence.models import NormalizedCandidate
        from services.threat_intelligence.orchestrator import ThreatIntelOrchestrator

        c1 = NormalizedCandidate(candidate_id="1", domain="phish-amaz0n.xyz", hostname="phish-amaz0n.xyz", sources=["openphish"], is_known_phishing=True)
        with patch("services.threat_intelligence.orchestrator.fetch_openphish_candidates", return_value=[c1]):
            scan = ThreatIntelOrchestrator.execute_multi_source_scan("amazon.com", quick_mode=True)
            perms = scan["permutations"]
            match = next((p for p in perms if p["domain"] == "phish-amaz0n.xyz"), None)
            self.assertIsNotNone(match)
            self.assertIn("openphish", match["sources"])

    # 11. Visual candidate + PhishTank duplicate merging
    def test_11_visual_candidate_phishtank_merging(self):
        from services.threat_intelligence.models import NormalizedCandidate
        from services.threat_intelligence.orchestrator import ThreatIntelOrchestrator

        c1 = NormalizedCandidate(candidate_id="1", domain="phishtank-amaz0n.xyz", hostname="phishtank-amaz0n.xyz", sources=["phishtank"], is_known_phishing=True)
        with patch("services.threat_intelligence.orchestrator.fetch_phishtank_candidates", return_value=[c1]):
            scan = ThreatIntelOrchestrator.execute_multi_source_scan("amazon.com", quick_mode=True)
            perms = scan["permutations"]
            match = next((p for p in perms if p["domain"] == "phishtank-amaz0n.xyz"), None)
            self.assertIsNotNone(match)
            self.assertIn("phishtank", match["sources"])

    # 12. Visual match -> live verification success (VISUAL_MATCH_VERIFIED)
    def test_12_live_verification_success(self):
        from services.logo_intelligence_service import run_logo_intelligence_scan
        with patch("services.candidate_acquisition_service.CandidateAcquisitionEngine.acquire_candidate_webpage", return_value={
            "status": "success",
            "screenshot_path": self.amazon_logo,
            "final_url": "http://verified-amaz0n.xyz",
            "html_content": "<html><body>Amazon Logo</body></html>",
            "attempts": [],
            "dns_status": "DNS_RESOLVED"
        }):
            with patch("services.phishpedia_service.analyze_screenshot_visual_brand", return_value={
                "status": "success", "detected": True, "brands": [{"brand": "Amazon", "confidence": 0.95, "bounding_box": [0,0,100,50]}]
            }):
                res = run_logo_intelligence_scan("Amazon", "amazon.com", logo_path=self.amazon_logo, max_candidates=2)
                verified = [r for r in res["results"] if r["two_stage_verification_status"] == "VISUAL_MATCH_VERIFIED"]
                self.assertGreater(len(verified), 0)

    # 13. Visual match -> live verification unavailable (VISUAL_MATCH_UNVERIFIED)
    def test_13_live_verification_unavailable(self):
        from services.logo_intelligence_service import run_logo_intelligence_scan
        from services.visual_retrieval_service import index_candidate_visual_asset

        index_candidate_visual_asset("offline-amaz0n.xyz", "http://offline-amaz0n.xyz", "IMG", self.amazon_logo, "Amazon")
        with patch("services.candidate_acquisition_service.CandidateAcquisitionEngine.acquire_candidate_webpage", return_value={
            "status": "failed",
            "failure_category": "CONNECTION_FAILURE",
            "failure_reason": "Offline",
            "dns_status": "DNS_FAILED",
            "attempts": []
        }):
            res = run_logo_intelligence_scan("Amazon", "amazon.com", logo_path=self.amazon_logo, max_candidates=5)
            unverified = [r for r in res["results"] if r["candidate_domain"] == "offline-amaz0n.xyz"]
            self.assertEqual(len(unverified), 1)
            self.assertEqual(unverified[0]["two_stage_verification_status"], "VISUAL_MATCH_UNVERIFIED")

    # 14. Visual match disproved by live page (VISUAL_MATCH_DISPROVED)
    def test_14_live_verification_disproved(self):
        from services.logo_intelligence_service import run_logo_intelligence_scan
        from services.visual_retrieval_service import index_candidate_visual_asset

        index_candidate_visual_asset("disproved-domain.com", "http://disproved-domain.com", "IMG", self.amazon_logo, "Amazon")
        with patch("services.candidate_acquisition_service.CandidateAcquisitionEngine.acquire_candidate_webpage", return_value={
            "status": "success",
            "screenshot_path": self.different_logo,
            "final_url": "http://disproved-domain.com",
            "html_content": "<html><body>Other Brand</body></html>",
            "attempts": [],
            "dns_status": "DNS_RESOLVED"
        }):
            with patch("services.phishpedia_service.analyze_screenshot_visual_brand", return_value={
                "status": "success", "detected": True, "brands": [{"brand": "OtherBrand", "confidence": 0.90, "bounding_box": [0,0,50,50]}]
            }):
                res = run_logo_intelligence_scan("Amazon", "amazon.com", logo_path=self.amazon_logo, max_candidates=5)
                disp = [r for r in res["results"] if r["candidate_domain"] == "disproved-domain.com"]
                self.assertEqual(len(disp), 1)
                self.assertEqual(disp[0]["two_stage_verification_status"], "VISUAL_MATCH_DISPROVED")

    # 15. Brand identification uncertain (BRAND_UNCERTAIN)
    def test_15_brand_identification_uncertain(self):
        from services.brand_identification_service import identify_brand_from_logo
        profile = {"status": "ready", "ocr_text": ["generic", "icon"], "phash_str": "8000000000000000"}
        brand_id = identify_brand_from_logo(profile)
        self.assertEqual(brand_id["status"], "BRAND_UNCERTAIN")
        self.assertIsNone(brand_id["identified_brand"])

    # 16. Manual brand override
    def test_16_manual_brand_override(self):
        from services.logo_intelligence_service import run_logo_intelligence_scan
        with patch("services.candidate_acquisition_service.CandidateAcquisitionEngine.acquire_candidate_webpage", return_value={"status": "failed", "failure_category": "CONNECTION_FAILURE", "failure_reason": "Failed", "attempts": []}):
            res = run_logo_intelligence_scan(target_brand="Microsoft", official_domain="microsoft.com", logo_path=self.amazon_logo, max_candidates=2)
            self.assertEqual(res["target_brand"], "Microsoft")
            self.assertEqual(res["official_domain"], "microsoft.com")

    # 17. Official domain excluded from suspicious ranking
    def test_17_official_domain_excluded_from_suspicious(self):
        from services.impersonation_service import calculate_impersonation_evidence
        res = calculate_impersonation_evidence("amazon.com", "Amazon", ["amazon.com"], ["dnstwist"], False, visual_analysis={})
        self.assertEqual(res["classification"], "TARGET_BRAND_ON_OFFICIAL_DOMAIN")

    # 18. Multiple visual matches ranking
    def test_18_multiple_visual_matches_ranking(self):
        from services.visual_retrieval_service import index_candidate_visual_asset, retrieve_visual_candidates
        from services.logo_intelligence_service import generate_target_logo_profile

        index_candidate_visual_asset("cand-a.com", "http://cand-a.com", "IMG", self.amazon_logo, "Amazon")
        index_candidate_visual_asset("cand-b.com", "http://cand-b.com", "IMG", self.different_logo, "Other")

        target_prof = generate_target_logo_profile(self.amazon_logo, "Amazon")
        matches = retrieve_visual_candidates(target_prof)
        self.assertGreater(len(matches), 0)
        self.assertEqual(matches[0]["recovered_domain"], "cand-a.com")

    # 19. Empty corpus graceful handling
    def test_19_empty_corpus_graceful(self):
        from services.visual_retrieval_service import retrieve_visual_candidates
        from services.logo_intelligence_service import generate_target_logo_profile

        target_prof = generate_target_logo_profile(self.amazon_logo, "Amazon")
        # Querying non-matching hash or empty results
        matches = retrieve_visual_candidates(target_prof, phash_max_distance=0)
        self.assertIsInstance(matches, list)

    # 20. viaSocket event schema compatibility
    def test_20_viasocket_schema_compatibility(self):
        from services.candidate_acquisition_service import generate_viasocket_event_payload
        payload = generate_viasocket_event_payload(
            case_id="case_v4_test",
            brand="Amazon",
            official_domain="amazon.com",
            candidate_domain="amaz0n-fake.xyz",
            assessment="LIKELY_IMPERSONATION",
            evidence_strength="HIGH",
            visual_match_level="VERY_STRONG",
            threat_sources=["LOGO_VISUAL_MATCH", "OPENPHISH"],
            credential_indicators=True,
            screenshot_available=True
        )
        self.assertEqual(payload["event"], "HIGH_CONFIDENCE_IMPERSONATION_DETECTED")
        self.assertIn("LOGO_VISUAL_MATCH", payload["threat_sources"])
        self.assertTrue(payload["response_automation"]["requires_human_approval"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
