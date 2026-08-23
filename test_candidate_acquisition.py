"""
test_candidate_acquisition.py

Task 2D V3 — Candidate Acquisition & Visual Engine Test Suite

22 required tests covering:
 1. DNS precheck resolution success (`DNS_RESOLVED`)
 2. DNS precheck resolution failure (`DNS_FAILED`)
 3. Candidate acquisition multi-strategy URL generation
 4. Valid HTTPS webpage acquisition (`status: success`)
 5. HTTP -> HTTPS redirect chain tracking
 6. Connection failure taxonomy classification (`CONNECTION_FAILURE`)
 7. TLS failure with fallback retry handling
 8. Timeout failure taxonomy classification (`TIMEOUT`)
 9. Non-HTML content validation (`CONTENT_NOT_HTML`)
10. HTML <img> tag visual asset extraction
11. HTML <svg> element extraction
12. Favicon extraction
13. Visual asset matching against target logo profile
14. Phishpedia corroboration ("VISUAL IDENTITY CORROBORATED")
15. Text-only brand mention degraded to WEAK (text-only protection)
16. Domain mismatch + screenshot failure degraded to INSUFFICIENT_EVIDENCE
17. Official domain candidate classification (TARGET_BRAND_ON_OFFICIAL_DOMAIN)
18. Unrelated domain + strong logo -> LIKELY/STRONG impersonation
19. viaSocket event payload structure validation
20. Visual Intelligence Corpus indexing & querying
21. Multi-source candidate deduplication & priority scoring
22. Recursive numpy primitive serialization safety
"""

import os
import sys
import unittest
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def _make_test_logo(tmp_dir: str, filename: str, color=(255, 153, 0)) -> str:
    from PIL import Image, ImageDraw
    path = Path(tmp_dir) / filename
    img = Image.new("RGB", (200, 100), color=(255, 255, 255))
    draw = ImageDraw.Draw(img)
    draw.rectangle([10, 10, 190, 90], fill=color)
    draw.rectangle([20, 35, 180, 45], fill=(255, 255, 255))
    draw.rectangle([10, 10, 30, 30], fill=(50, 50, 50))
    img.save(str(path))
    return str(path)


class TestCandidateAcquisition(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.target_logo = _make_test_logo(self.temp.name, "amazon_logo.png", color=(255, 153, 0))

    def tearDown(self):
        self.temp.cleanup()

    # 1. DNS precheck resolution success
    def test_01_dns_resolution_success(self):
        from services.candidate_acquisition_service import check_dns_resolution
        with patch("socket.getaddrinfo", return_value=[(None, None, None, None, ("93.184.216.34", 80))]):
            res = check_dns_resolution("example.com")
            self.assertEqual(res["status"], "DNS_RESOLVED")
            self.assertTrue(res["resolved"])
            self.assertIn("93.184.216.34", res["ip_addresses"])

    # 2. DNS precheck resolution failure
    def test_02_dns_resolution_failure(self):
        import socket
        from services.candidate_acquisition_service import check_dns_resolution
        with patch("socket.getaddrinfo", side_effect=socket.gaierror("Name or service not known")):
            res = check_dns_resolution("nonexistent-domain-test-999.invalid")
            self.assertEqual(res["status"], "DNS_FAILED")
            self.assertFalse(res["resolved"])
            self.assertEqual(res["ip_addresses"], [])

    # 3. Candidate acquisition multi-strategy URL generation
    def test_03_url_strategy_generation(self):
        from services.candidate_acquisition_service import CandidateAcquisitionEngine
        urls = CandidateAcquisitionEngine._generate_candidate_urls("flipkarn.com")
        self.assertEqual(urls, [
            "https://flipkarn.com",
            "https://www.flipkarn.com",
            "http://flipkarn.com",
            "http://www.flipkarn.com"
        ])

    # 4. Valid HTTPS webpage acquisition
    def test_04_valid_https_webpage_acquisition(self):
        from services.candidate_acquisition_service import CandidateAcquisitionEngine
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {"content-type": "text/html; charset=utf-8"}
        mock_resp.text = "<html><head><title>Test Page</title></head><body><h1>Welcome</h1></body></html>"
        mock_resp.url = "https://example.com"
        mock_resp.history = []

        with patch("services.candidate_acquisition_service.check_dns_resolution", return_value={"status": "DNS_RESOLVED", "resolved": True, "ip_addresses": ["93.184.216.34"]}):
            with patch("requests.Session.get", return_value=mock_resp):
                acq = CandidateAcquisitionEngine.acquire_candidate_webpage("example.com")
                self.assertEqual(acq["status"], "success")
                self.assertEqual(acq["successful_url"], "https://example.com")
                self.assertEqual(acq["dns_status"], "DNS_RESOLVED")

    # 5. HTTP -> HTTPS redirect chain tracking
    def test_05_redirect_chain_tracking(self):
        from services.candidate_acquisition_service import CandidateAcquisitionEngine
        r1 = MagicMock()
        r1.url = "http://example.com"

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {"content-type": "text/html"}
        mock_resp.text = "<html><body>Redirected</body></html>"
        mock_resp.url = "https://www.example.com/login"
        mock_resp.history = [r1]

        with patch("services.candidate_acquisition_service.check_dns_resolution", return_value={"status": "DNS_RESOLVED", "resolved": True, "ip_addresses": ["1.1.1.1"]}):
            with patch("requests.Session.get", return_value=mock_resp):
                acq = CandidateAcquisitionEngine.acquire_candidate_webpage("example.com")
                self.assertEqual(acq["status"], "success")
                self.assertEqual(acq["redirect_chain"], ["http://example.com", "https://www.example.com/login"])

    # 6. Connection failure taxonomy classification
    def test_06_connection_failure_taxonomy(self):
        import requests
        from services.candidate_acquisition_service import CandidateAcquisitionEngine
        with patch("services.candidate_acquisition_service.check_dns_resolution", return_value={"status": "DNS_RESOLVED", "resolved": True, "ip_addresses": ["1.1.1.1"]}):
            with patch("requests.Session.get", side_effect=requests.exceptions.ConnectionError("Connection refused")):
                acq = CandidateAcquisitionEngine.acquire_candidate_webpage("refused-domain.com")
                self.assertEqual(acq["status"], "failed")
                self.assertEqual(acq["failure_category"], "CONNECTION_FAILURE")

    # 7. TLS failure with fallback retry handling
    def test_07_tls_failure_fallback_retry(self):
        import requests
        from services.candidate_acquisition_service import CandidateAcquisitionEngine

        mock_fallback = MagicMock()
        mock_fallback.status_code = 200
        mock_fallback.headers = {"content-type": "text/html"}
        mock_fallback.text = "<html><body>Insecure TLS Page</body></html>"
        mock_fallback.url = "https://self-signed.com"
        mock_fallback.history = []

        def side_effect(url, verify=True, **kwargs):
            if verify:
                raise requests.exceptions.SSLError("CERTIFICATE_VERIFY_FAILED")
            return mock_fallback

        with patch("services.candidate_acquisition_service.check_dns_resolution", return_value={"status": "DNS_RESOLVED", "resolved": True, "ip_addresses": ["1.1.1.1"]}):
            with patch("requests.Session.get", side_effect=side_effect):
                acq = CandidateAcquisitionEngine.acquire_candidate_webpage("self-signed.com", allow_insecure_tls_fallback=True)
                self.assertEqual(acq["status"], "success")
                self.assertTrue(acq["tls_fallback_used"])

    # 8. Timeout failure taxonomy classification
    def test_08_timeout_failure_taxonomy(self):
        import requests
        from services.candidate_acquisition_service import CandidateAcquisitionEngine
        with patch("services.candidate_acquisition_service.check_dns_resolution", return_value={"status": "DNS_RESOLVED", "resolved": True, "ip_addresses": ["1.1.1.1"]}):
            with patch("requests.Session.get", side_effect=requests.exceptions.Timeout("Read timeout")):
                acq = CandidateAcquisitionEngine.acquire_candidate_webpage("slow-domain.com")
                self.assertEqual(acq["status"], "failed")
                self.assertEqual(acq["failure_category"], "TIMEOUT")

    # 9. Non-HTML content validation
    def test_09_non_html_content_validation(self):
        from services.candidate_acquisition_service import CandidateAcquisitionEngine
        mock_pdf = MagicMock()
        mock_pdf.status_code = 200
        mock_pdf.headers = {"content-type": "application/pdf"}
        mock_pdf.content = b"%PDF-1.4 binary data"

        with patch("services.candidate_acquisition_service.check_dns_resolution", return_value={"status": "DNS_RESOLVED", "resolved": True, "ip_addresses": ["1.1.1.1"]}):
            with patch("requests.Session.get", return_value=mock_pdf):
                acq = CandidateAcquisitionEngine.acquire_candidate_webpage("pdf-domain.com")
                self.assertEqual(acq["status"], "failed")
                self.assertEqual(acq["failure_category"], "CONTENT_NOT_HTML")

    # 10. HTML <img> tag visual asset extraction
    def test_10_html_img_asset_extraction(self):
        from services.candidate_acquisition_service import extract_webpage_visual_assets
        html = '<html><body><img src="https://example.com/logo.png" alt="Amazon Logo"></body></html>'
        
        mock_img_resp = MagicMock()
        mock_img_resp.status_code = 200
        mock_img_resp.headers = {"content-type": "image/png"}
        
        # 10x10 dummy PNG bytes
        from PIL import Image
        import io
        buf = io.BytesIO()
        Image.new("RGB", (50, 50), "orange").save(buf, format="PNG")
        mock_img_resp.content = buf.getvalue()

        with patch("requests.Session.get", return_value=mock_img_resp):
            assets = extract_webpage_visual_assets(html, "https://example.com")
            self.assertGreater(assets["images_found"], 0)
            self.assertEqual(assets["assets"][0]["asset_type"], "IMG")
            self.assertTrue(assets["assets"][0]["is_branding_hint"])

    # 11. HTML <svg> element extraction
    def test_11_html_svg_element_extraction(self):
        from services.candidate_acquisition_service import extract_webpage_visual_assets
        html = '<html><body><svg width="100" height="50"><rect fill="orange"/></svg></body></html>'
        assets = extract_webpage_visual_assets(html, "https://example.com")
        self.assertEqual(assets["svg_found"], 1)
        self.assertEqual(assets["assets"][0]["asset_type"], "SVG")

    # 12. Favicon extraction
    def test_12_favicon_extraction(self):
        from services.candidate_acquisition_service import extract_webpage_visual_assets
        html = '<html><head><link rel="shortcut icon" href="/favicon.ico"></head></html>'
        mock_fav = MagicMock()
        mock_fav.status_code = 200
        mock_fav.headers = {"content-type": "image/x-icon"}
        mock_fav.content = b"\x00\x00\x01\x00 dummy favicon bytes"

        with patch("requests.Session.get", return_value=mock_fav):
            assets = extract_webpage_visual_assets(html, "https://example.com")
            self.assertEqual(assets["favicons_found"], 1)
            self.assertEqual(assets["assets"][0]["asset_type"], "FAVICON")

    # 13. Visual asset matching against target logo profile
    def test_13_visual_asset_matching(self):
        from services.logo_intelligence_service import generate_target_logo_profile, compare_logo_profiles
        target = generate_target_logo_profile(self.target_logo, "Amazon")
        candidate_asset = generate_target_logo_profile(self.target_logo, "Amazon")

        cmp_res = compare_logo_profiles(target, candidate_asset, "Amazon")
        self.assertIn(cmp_res["level"], ("VERY_STRONG", "STRONG"))
        self.assertTrue(cmp_res["matched"])

    # 14. Phishpedia corroboration ("VISUAL IDENTITY CORROBORATED")
    def test_14_phishpedia_corroboration(self):
        from services.impersonation_service import calculate_impersonation_evidence
        visual_analysis = {
            "status": "success",
            "detected": True,
            "brands": [{"brand": "Amazon", "confidence": 0.965, "bounding_box": [0, 0, 100, 50]}]
        }
        res = calculate_impersonation_evidence(
            candidate_domain="amaz0n-secure.xyz",
            target_brand="Amazon",
            official_domains=["amazon.com"],
            sources=["dnstwist", "openphish"],
            is_known_phishing=True,
            visual_analysis=visual_analysis
        )
        self.assertEqual(res["classification"], "STRONG_IMPERSONATION_EVIDENCE")

    # 15. Text-only brand mention degraded to WEAK
    def test_15_text_only_brand_degraded_to_weak(self):
        from services.logo_intelligence_service import _determine_match_level
        # Low hash similarity + positive OCR -> WEAK
        lvl = _determine_match_level(phash_level="LOW", dhash_level="LOW", ocr_status="MATCH", brand_matches=False)
        self.assertEqual(lvl, "WEAK")

    # 16. Domain mismatch + screenshot failure degraded to INSUFFICIENT_EVIDENCE
    def test_16_domain_mismatch_failed_screenshot_insufficient_evidence(self):
        from services.logo_intelligence_service import run_logo_intelligence_scan
        with patch("services.candidate_acquisition_service.CandidateAcquisitionEngine.acquire_candidate_webpage", return_value={
            "status": "failed",
            "requested_domain": "unrelated-cand.com",
            "failure_category": "CONNECTION_FAILURE",
            "failure_reason": "Connection refused",
            "dns_status": "DNS_FAILED",
            "dns_ip_addresses": [],
            "attempts": [],
            "successful_url": None,
            "final_url": None,
            "screenshot_path": None,
            "html_content": None,
            "headers": {},
            "redirect_chain": [],
            "tls_fallback_used": False
        }):
            scan_res = run_logo_intelligence_scan("Amazon", "amazon.com", logo_path=self.target_logo, max_candidates=2)
            cands = scan_res["results"]
            for c in cands:
                if not c["official_domain_match"]:
                    self.assertEqual(c["classification"], "INSUFFICIENT_EVIDENCE")

    # 17. Official domain candidate classification
    def test_17_official_domain_classification(self):
        from services.impersonation_service import calculate_impersonation_evidence
        res = calculate_impersonation_evidence("amazon.com", "Amazon", ["amazon.com"], ["dnstwist"], False, visual_analysis={})
        self.assertEqual(res["classification"], "TARGET_BRAND_ON_OFFICIAL_DOMAIN")

    # 18. Unrelated domain + strong logo -> LIKELY/STRONG impersonation
    def test_18_unrelated_domain_strong_logo(self):
        from services.impersonation_service import calculate_impersonation_evidence
        visual_analysis = {
            "status": "success",
            "detected": True,
            "brands": [{"brand": "Amazon", "confidence": 0.95, "bounding_box": [0, 0, 50, 50]}]
        }
        res = calculate_impersonation_evidence("fake-amazon.xyz", "Amazon", ["amazon.com"], ["dnstwist"], False, visual_analysis=visual_analysis)
        self.assertIn(res["classification"], ("STRONG_IMPERSONATION_EVIDENCE", "LIKELY_IMPERSONATION"))

    # 19. viaSocket event payload structure validation
    def test_19_viasocket_event_payload_structure(self):
        from services.candidate_acquisition_service import generate_viasocket_event_payload
        payload = generate_viasocket_event_payload(
            case_id="case_12345",
            brand="Amazon",
            official_domain="amazon.com",
            candidate_domain="amaz0n-login.xyz",
            assessment="LIKELY_IMPERSONATION",
            evidence_strength="HIGH",
            visual_match_level="VERY_STRONG",
            threat_sources=["dnstwist", "openphish"],
            credential_indicators=True,
            screenshot_available=True
        )
        self.assertEqual(payload["event"], "HIGH_CONFIDENCE_IMPERSONATION_DETECTED")
        self.assertEqual(payload["case_id"], "case_12345")
        self.assertEqual(payload["brand"], "Amazon")
        self.assertTrue(payload["response_automation"]["requires_human_approval"])
        self.assertFalse(payload["response_automation"]["takedown_requested"])

    # 20. Visual Intelligence Corpus indexing & querying
    def test_20_visual_corpus_indexing_querying(self):
        from services.visual_corpus_service import index_reference_logo, query_visual_corpus, get_corpus_size
        from services.imagehash_service import compute_image_hashes

        success = index_reference_logo("Amazon", self.target_logo)
        self.assertTrue(success)
        self.assertGreater(get_corpus_size(), 0)

        hashes = compute_image_hashes(self.target_logo)
        corpus_results = query_visual_corpus(hashes["phash_str"])
        self.assertGreater(len(corpus_results), 0)
        self.assertEqual(corpus_results[0]["match_level"], "VERY_HIGH")

    # 21. Multi-source candidate deduplication & priority scoring
    def test_21_multisource_deduplication(self):
        from services.threat_intelligence.orchestrator import ThreatIntelOrchestrator
        from services.threat_intelligence.models import NormalizedCandidate

        c1 = NormalizedCandidate(candidate_id="1", domain="test-domain.com", hostname="test-domain.com", sources=["dnstwist"])
        c2 = NormalizedCandidate(candidate_id="2", domain="test-domain.com", hostname="test-domain.com", sources=["openphish"], is_known_phishing=True)

        with patch("services.threat_intelligence.orchestrator.fetch_dnstwist_candidates", return_value=[c1]):
            with patch("services.threat_intelligence.orchestrator.fetch_openphish_candidates", return_value=[c2]):
                with patch("services.threat_intelligence.orchestrator.fetch_phishtank_candidates", return_value=[]):
                    scan = ThreatIntelOrchestrator.execute_multi_source_scan("example.com", quick_mode=True)
                    perms = scan["permutations"]
                    matches = [p for p in perms if p["domain"] == "test-domain.com"]
                    self.assertEqual(len(matches), 1)
                    self.assertIn("dnstwist", matches[0]["sources"])
                    self.assertIn("openphish", matches[0]["sources"])

    # 22. Recursive numpy primitive serialization safety
    def test_22_numpy_serialization_safety(self):
        from services.logo_intelligence_service import sanitize_numpy_primitives
        try:
            import numpy as np
            data = {
                "int_val": np.int64(42),
                "float_val": np.float64(3.14159),
                "array_val": np.array([1, 2, 3]),
                "nested": {"val": np.int32(10)}
            }
            sanitized = sanitize_numpy_primitives(data)
            self.assertIsInstance(sanitized["int_val"], int)
            self.assertIsInstance(sanitized["float_val"], float)
            self.assertIsInstance(sanitized["array_val"], list)
            self.assertIsInstance(sanitized["nested"]["val"], int)
        except ImportError:
            # If numpy not present, verify function works on standard types
            data = {"int_val": 42, "nested": {"val": 10}}
            sanitized = sanitize_numpy_primitives(data)
            self.assertEqual(sanitized["int_val"], 42)


if __name__ == "__main__":
    unittest.main(verbosity=2)
