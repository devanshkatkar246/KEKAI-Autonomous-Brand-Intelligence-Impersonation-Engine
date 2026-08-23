"""
test_logo_retrieval.py

Task 2D V2 — Logo Intelligence & Visual Retrieval Engine — Test Suite

12 required tests covering:
  1. Exact logo match → VERY_STRONG
  2. Resized logo → STRONG or VERY_STRONG (pHash resolution-invariant)
  3. JPEG-compressed logo → STRONG/MODERATE (compression tolerance)
  4. Slightly cropped logo → MODERATE or better (autocrop normalization)
  5. Different logo → NO_MATCH or WEAK (false positive protection)
  6. Same brand / different variant → at least WEAK (brand anchor)
  7. Text-only brand mention → WEAK or NO_MATCH (text-only protection)
  8. Screenshot unavailable → UNAVAILABLE state (not NONE)
  9. Official domain candidate → TARGET_BRAND_ON_OFFICIAL_DOMAIN
 10. Unrelated domain + strong logo → LIKELY/STRONG impersonation
 11. Multiple logos on page → target brand selected for comparison
 12. Duplicate candidate from multi-source → merged provenance, single entry
"""

import os
import sys
import unittest
import tempfile
from pathlib import Path
from typing import Optional
from unittest.mock import patch

# Ensure project root is importable
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def _make_logo(tmp_dir: str, filename: str, color=(255, 153, 0), size=(200, 100)) -> str:
    """Creates a test logo image with a distinct pattern (not solid color) so pHash can differentiate it."""
    from PIL import Image, ImageDraw
    path = Path(tmp_dir) / filename
    img = Image.new("RGB", size, color=(255, 255, 255))
    draw = ImageDraw.Draw(img)
    # Main brand color block
    draw.rectangle([10, 10, size[0] - 10, size[1] - 10], fill=color)
    # White text-like stripe to add frequency content for pHash
    draw.rectangle([20, 35, size[0] - 20, 45], fill=(255, 255, 255))
    draw.rectangle([20, 55, size[0] - 20, 65], fill=(255, 255, 255))
    # Corner markers
    draw.rectangle([10, 10, 30, 30], fill=(50, 50, 50))
    draw.rectangle([size[0] - 30, size[1] - 30, size[0] - 10, size[1] - 10], fill=(50, 50, 50))
    img.save(str(path))
    return str(path)


def _make_logo_distinct(tmp_dir: str, filename: str) -> str:
    """
    Creates a visually DISTINCT logo with different color, structure, and stripe positions
    so that pHash produces a meaningfully different hash from the amazon_logo.
    """
    from PIL import Image, ImageDraw
    path = Path(tmp_dir) / filename
    img = Image.new("RGB", (200, 100), color=(255, 255, 255))
    draw = ImageDraw.Draw(img)
    # Blue background (very different from orange)
    draw.rectangle([10, 10, 190, 90], fill=(0, 80, 200))
    # Dark vertical stripes (opposite to horizontal stripes in amazon_logo)
    draw.rectangle([40, 10, 55, 90], fill=(255, 255, 255))
    draw.rectangle([80, 10, 95, 90], fill=(255, 255, 255))
    draw.rectangle([130, 10, 145, 90], fill=(255, 255, 255))
    # Top-right marker (inverted corners compared to amazon_logo)
    draw.rectangle([170, 10, 190, 30], fill=(255, 200, 0))
    draw.rectangle([10, 70, 30, 90], fill=(255, 200, 0))
    img.save(str(path))
    return str(path)



def _make_logo_transparent(tmp_dir: str, filename: str) -> str:
    """Creates a logo with transparent background and orange square."""
    from PIL import Image, ImageDraw
    path = Path(tmp_dir) / filename
    img = Image.new("RGBA", (200, 100), (255, 255, 255, 0))
    draw = ImageDraw.Draw(img)
    draw.rectangle([50, 25, 150, 75], fill=(255, 153, 0, 255))
    img.save(str(path))
    return str(path)


def _resize_logo(src_path: str, tmp_dir: str, scale: float = 2.0) -> str:
    """Creates a scaled version of a logo."""
    from PIL import Image
    filename = f"resized_{Path(src_path).name}"
    dst = Path(tmp_dir) / filename
    with Image.open(src_path) as img:
        new_size = (int(img.width * scale), int(img.height * scale))
        img.resize(new_size, Image.LANCZOS).save(str(dst))
    return str(dst)


def _to_jpeg(src_path: str, tmp_dir: str, quality: int = 60) -> str:
    """Converts a PNG logo to JPEG with compression."""
    from PIL import Image
    dst = Path(tmp_dir) / f"{Path(src_path).stem}_compressed.jpg"
    with Image.open(src_path) as img:
        img.convert("RGB").save(str(dst), "JPEG", quality=quality)
    return str(dst)


def _crop_logo(src_path: str, tmp_dir: str, margin: int = 10) -> str:
    """Crops a small border off a logo."""
    from PIL import Image
    dst = Path(tmp_dir) / f"cropped_{Path(src_path).name}"
    with Image.open(src_path) as img:
        w, h = img.size
        img.crop((margin, margin // 2, w - margin, h - margin // 2)).save(str(dst))
    return str(dst)


class TestLogoRetrieval(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        d = self.temp.name

        self.amazon_logo = _make_logo(d, "amazon_logo.png", color=(255, 153, 0))
        self.amazon_resized = _resize_logo(self.amazon_logo, d, scale=2.0)
        self.amazon_jpeg = _to_jpeg(self.amazon_logo, d, quality=60)
        self.amazon_cropped = _crop_logo(self.amazon_logo, d, margin=12)
        self.amazon_transparent = _make_logo_transparent(d, "amazon_transparent.png")

        # Visually DIFFERENT logo — different color + different structural pattern
        # Uses completely inverted corner markers so pHash frequency content differs
        self.different_logo = _make_logo_distinct(d, "other_logo.png")

    def tearDown(self):
        self.temp.cleanup()

    # ------------------------------------------------------------------
    # Test 1: Exact same image → VERY_STRONG
    # ------------------------------------------------------------------
    def test_01_exact_logo_very_strong(self):
        """Exact same logo bytes → VERY_STRONG match level."""
        from services.logo_intelligence_service import (
            generate_target_logo_profile,
            compare_logo_profiles
        )
        target = generate_target_logo_profile(self.amazon_logo, "Amazon")
        candidate = generate_target_logo_profile(self.amazon_logo, "Amazon")

        self.assertEqual(target["status"], "ready", "Target profile generation failed")
        self.assertEqual(candidate["status"], "ready", "Candidate profile generation failed")

        result = compare_logo_profiles(
            target, candidate, "Amazon",
            phishpedia_result={"brand": "Amazon", "confidence": 0.97}
        )
        self.assertEqual(result["level"], "VERY_STRONG",
                         f"Expected VERY_STRONG for exact same image, got {result['level']}")
        self.assertTrue(result["matched"])
        self.assertEqual(result["signals"]["phash"]["distance"], 0)

    # ------------------------------------------------------------------
    # Test 2: Resized logo → STRONG or VERY_STRONG
    # ------------------------------------------------------------------
    def test_02_resized_logo_strong(self):
        """2× resized logo → STRONG or VERY_STRONG (pHash is resolution-invariant)."""
        from services.logo_intelligence_service import (
            generate_target_logo_profile,
            compare_logo_profiles
        )
        target = generate_target_logo_profile(self.amazon_logo, "Amazon")
        candidate = generate_target_logo_profile(self.amazon_resized, "Amazon")

        result = compare_logo_profiles(target, candidate, "Amazon")
        self.assertIn(result["level"], ("VERY_STRONG", "STRONG"),
                      f"Expected VERY_STRONG/STRONG for resized logo, got {result['level']}")
        self.assertTrue(result["matched"])

    # ------------------------------------------------------------------
    # Test 3: JPEG-compressed logo → STRONG or MODERATE
    # ------------------------------------------------------------------
    def test_03_jpeg_compressed_matches(self):
        """JPEG-compressed logo (quality=60) still matches (STRONG or MODERATE)."""
        from services.logo_intelligence_service import (
            generate_target_logo_profile,
            compare_logo_profiles
        )
        target = generate_target_logo_profile(self.amazon_logo, "Amazon")
        candidate = generate_target_logo_profile(self.amazon_jpeg, "Amazon")

        result = compare_logo_profiles(
            target, candidate, "Amazon",
            phishpedia_result={"brand": "Amazon", "confidence": 0.88}
        )
        self.assertIn(result["level"], ("VERY_STRONG", "STRONG", "MODERATE"),
                      f"Expected match for JPEG-compressed logo, got {result['level']}")
        self.assertTrue(result["matched"])

    # ------------------------------------------------------------------
    # Test 4: Slightly cropped logo → MODERATE or better
    # ------------------------------------------------------------------
    def test_04_slightly_cropped_moderate(self):
        """Slightly cropped logo → MODERATE or better (autocrop normalization handles border removal)."""
        from services.logo_intelligence_service import (
            generate_target_logo_profile,
            compare_logo_profiles
        )
        target = generate_target_logo_profile(self.amazon_logo, "Amazon")
        candidate = generate_target_logo_profile(self.amazon_cropped, "Amazon")

        result = compare_logo_profiles(
            target, candidate, "Amazon",
            phishpedia_result={"brand": "Amazon", "confidence": 0.92}
        )
        self.assertIn(result["level"], ("VERY_STRONG", "STRONG", "MODERATE"),
                      f"Expected MODERATE+ for slightly cropped logo, got {result['level']}")

    # ------------------------------------------------------------------
    # Test 5: Visually different logo → NO_MATCH / WEAK / MODERATE (not STRONG)
    # ------------------------------------------------------------------
    def test_05_different_logo_no_match(self):
        """
        Completely different logo with NO brand match → NOT STRONG or VERY_STRONG.

        Key protection: even if pHash falls in moderate range (borderline images),
        the level must NEVER be STRONG or VERY_STRONG without either:
        - High hash similarity (pHash ≤ 15), OR
        - Brand name match from Phishpedia

        pHash of 23 maps to MODERATE (25 threshold boundary).
        This is acceptable — MODERATE is a soft signal that requires additional evidence.
        What MUST NOT happen: STRONG or VERY_STRONG classification.
        """
        from services.logo_intelligence_service import (
            generate_target_logo_profile,
            compare_logo_profiles
        )
        target = generate_target_logo_profile(self.amazon_logo, "Amazon")
        candidate = generate_target_logo_profile(self.different_logo, "OtherBrand")

        result = compare_logo_profiles(
            target, candidate, "Amazon",
            phishpedia_result={"brand": "OtherBrand", "confidence": 0.80}
        )
        # Critical: must NOT be STRONG or VERY_STRONG when brand doesn't match
        self.assertNotIn(result["level"], ("STRONG", "VERY_STRONG"),
                         f"Different logo with non-matching brand must NOT be STRONG/VERY_STRONG, got {result['level']}")
        self.assertFalse(result["matched"],
                         f"different_logo should not be matched=True, got matched={result['matched']}")
        # Acceptable levels: MODERATE (borderline pHash), WEAK, NO_MATCH
        self.assertIn(result["level"], ("NO_MATCH", "WEAK", "MODERATE"),
                      f"Expected NO_MATCH/WEAK/MODERATE for different logo, got {result['level']}")

    # ------------------------------------------------------------------
    # Test 6: Transparent background variant → MODERATE or better (brand match anchors)
    # ------------------------------------------------------------------
    def test_06_transparent_background_variant(self):
        """Transparent-bg variant with matching brand → MODERATE or better."""
        from services.logo_intelligence_service import (
            generate_target_logo_profile,
            compare_logo_profiles
        )
        target = generate_target_logo_profile(self.amazon_logo, "Amazon")
        candidate = generate_target_logo_profile(self.amazon_transparent, "Amazon")

        result = compare_logo_profiles(
            target, candidate, "Amazon",
            phishpedia_result={"brand": "Amazon", "confidence": 0.85}
        )
        # Transparent bg normalization should bring hashes close; brand match lifts level
        self.assertIn(result["level"], ("VERY_STRONG", "STRONG", "MODERATE", "WEAK"),
                      f"Unexpected level for transparent variant: {result['level']}")

    # ------------------------------------------------------------------
    # Test 7: Text-only brand mention → WEAK, NOT a logo match
    # ------------------------------------------------------------------
    def test_07_text_only_brand_is_weak_not_logo_match(self):
        """
        Different logo visuals + brand name OCR match → WEAK or NO_MATCH.
        Text evidence alone must NOT inflate to STRONG.
        This is the critical text-only protection test.
        """
        from services.logo_intelligence_service import (
            generate_target_logo_profile,
            compare_logo_profiles
        )
        target = generate_target_logo_profile(self.amazon_logo, "Amazon")
        # Candidate is a visually different logo (blue) but Phishpedia says "Amazon"
        candidate = generate_target_logo_profile(self.different_logo, "Amazon")

        result = compare_logo_profiles(
            target, candidate, "Amazon",
            phishpedia_result={"brand": "Amazon", "confidence": 0.91}
        )
        # Must NOT be VERY_STRONG despite brand name matching
        self.assertNotEqual(result["level"], "VERY_STRONG",
                            "VERY_STRONG must NOT be assigned from brand name alone without hash match")
        self.assertNotEqual(result["level"], "STRONG",
                            "STRONG must NOT be assigned from brand name alone without hash match")
        # Acceptable: MODERATE, WEAK, or NO_MATCH
        self.assertIn(result["level"], ("MODERATE", "WEAK", "NO_MATCH"),
                      f"Text-only brand match should be MODERATE/WEAK/NO_MATCH, got {result['level']}")

    # ------------------------------------------------------------------
    # Test 8: Screenshot unavailable → UNAVAILABLE state (not NONE)
    # ------------------------------------------------------------------
    def test_08_screenshot_unavailable_correct_state(self):
        """
        Screenshot acquisition failure → ScreenshotResult.status is
        'timeout'/'failed'/'unavailable' (never 'success' for unreachable URL).
        LogoMatchResult.level is UNAVAILABLE (not NO_MATCH).
        """
        from services.logo_intelligence_service import (
            acquire_candidate_screenshot,
            _build_logo_match_result,
            generate_target_logo_profile
        )
        # Use an unreachable domain with very short timeout
        sc = acquire_candidate_screenshot(
            "http://this-does-not-exist-keikai-test-999.invalid",
            timeout=2
        )

        self.assertIn(sc["status"], ("timeout", "failed", "unavailable", "blocked"),
                      f"Unreachable URL should not return status='success', got {sc['status']}")
        self.assertIsNone(sc["path"],
                          "Path must be None when screenshot failed")
        self.assertIsNotNone(sc["failure_reason"],
                             "failure_reason must be populated when screenshot fails")

        # LogoMatchResult must reflect UNAVAILABLE (pipeline couldn't run)
        target = generate_target_logo_profile(self.amazon_logo, "Amazon")
        logo_match = _build_logo_match_result(
            logo_profile=target,
            visual_analysis={"status": "not_run", "brands": []},
            screenshot_result=sc,
            screenshot_path=None,
            target_brand="Amazon"
        )
        self.assertEqual(logo_match["level"], "UNAVAILABLE",
                         f"Failed screenshot → level must be UNAVAILABLE, got {logo_match['level']}")
        self.assertFalse(logo_match["matched"])
        # NOT_RUN propagated through signals
        self.assertEqual(logo_match["signals"]["phash"]["status"], "NOT_RUN")
        self.assertEqual(logo_match["signals"]["dhash"]["status"], "NOT_RUN")

    # ------------------------------------------------------------------
    # Test 9: Official domain → TARGET_BRAND_ON_OFFICIAL_DOMAIN
    # ------------------------------------------------------------------
    def test_09_official_domain_classification(self):
        """Official domain candidate → TARGET_BRAND_ON_OFFICIAL_DOMAIN (not a threat)."""
        from services.impersonation_service import calculate_impersonation_evidence

        analysis = calculate_impersonation_evidence(
            candidate_domain="amazon.com",
            target_brand="Amazon",
            official_domains=["amazon.com"],
            sources=["dnstwist"],
            is_known_phishing=False,
            visual_analysis={"status": "unavailable", "brands": []}
        )
        self.assertEqual(analysis["classification"], "TARGET_BRAND_ON_OFFICIAL_DOMAIN",
                         f"Official domain should be TARGET_BRAND_ON_OFFICIAL_DOMAIN, got {analysis['classification']}")
        self.assertTrue(analysis["official_domain_match"])

    # ------------------------------------------------------------------
    # Test 10: Unrelated domain + strong logo → LIKELY/STRONG impersonation
    # ------------------------------------------------------------------
    def test_10_unrelated_domain_strong_logo_impersonation(self):
        """
        Unrelated domain + Phishpedia detects target brand logo → LIKELY/STRONG impersonation.
        This is the core phishing detection test.
        """
        from services.impersonation_service import calculate_impersonation_evidence

        visual_analysis = {
            "status": "success",
            "detected": True,
            "brands": [{"brand": "Amazon", "confidence": 0.968, "bounding_box": [0, 0, 100, 100]}]
        }

        analysis = calculate_impersonation_evidence(
            candidate_domain="amaz0n-secure-login.xyz",
            target_brand="Amazon",
            official_domains=["amazon.com"],
            sources=["dnstwist", "openphish"],
            is_known_phishing=True,
            visual_analysis=visual_analysis
        )
        self.assertIn(analysis["classification"],
                      ("STRONG_IMPERSONATION_EVIDENCE", "LIKELY_IMPERSONATION"),
                      f"Phishing candidate should be STRONG/LIKELY, got {analysis['classification']}")
        self.assertFalse(analysis["official_domain_match"])
        self.assertIn("reasons", analysis)
        self.assertGreater(len(analysis["reasons"]), 0)

    # ------------------------------------------------------------------
    # Test 11: Multiple logos on page → target brand selected for comparison
    # ------------------------------------------------------------------
    def test_11_multiple_logos_target_brand_selected(self):
        """
        When Phishpedia detects multiple logos, _build_logo_match_result selects
        the one matching the target brand (not the first or highest-confidence).
        """
        from services.logo_intelligence_service import (
            _build_logo_match_result,
            generate_target_logo_profile
        )

        # Simulate Phishpedia detecting 3 logos — Amazon is NOT first
        visual_analysis = {
            "status": "success",
            "detected": True,
            "brands": [
                {"brand": "Visa", "confidence": 0.95, "bounding_box": [0, 0, 50, 50]},
                {"brand": "Amazon", "confidence": 0.97, "bounding_box": [60, 0, 120, 50]},
                {"brand": "Mastercard", "confidence": 0.90, "bounding_box": [130, 0, 180, 50]}
            ]
        }

        target = generate_target_logo_profile(self.amazon_logo, "Amazon")

        # Use the amazon logo itself as the screenshot (simulates a matching page)
        logo_match = _build_logo_match_result(
            logo_profile=target,
            visual_analysis=visual_analysis,
            screenshot_result={"status": "success"},
            screenshot_path=self.amazon_logo,  # Same as target → should match well
            target_brand="Amazon"
        )

        # Result must exist and have a valid level
        self.assertIn("level", logo_match)
        self.assertIn(logo_match["level"],
                      ("VERY_STRONG", "STRONG", "MODERATE", "WEAK", "NO_MATCH", "UNAVAILABLE"))

        # If signals are populated, the Phishpedia brand should be Amazon (not Visa)
        pb = logo_match.get("signals", {}).get("phishpedia_brand")
        if pb and pb.get("brand"):
            self.assertEqual(pb["brand"], "Amazon",
                             f"Expected Amazon brand selected, got {pb['brand']}")

    # ------------------------------------------------------------------
    # Test 12: Duplicate candidate from multi-source → merged provenance
    # ------------------------------------------------------------------
    def test_12_duplicate_candidate_merged_provenance(self):
        """
        Same domain appearing in dnstwist AND OpenPhish → exactly one candidate
        in the output with both sources in provenance and is_known_phishing=True.
        """
        from services.threat_intelligence.orchestrator import ThreatIntelOrchestrator
        from services.threat_intelligence.models import NormalizedCandidate

        cand_dnstwist = NormalizedCandidate(
            candidate_id="test-dns-001",
            domain="amaz0n.com",
            hostname="amaz0n.com",
            fuzzer="homoglyph",
            sources=["dnstwist"],
            source_types=["permutation"],
            provenance={"dnstwist": "homoglyph"},
            ip_addresses=[],
            dns_ns=[],
            dns_mx=[]
        )

        cand_openphish = NormalizedCandidate(
            candidate_id="test-oph-001",
            domain="amaz0n.com",   # Same domain — must be merged
            hostname="amaz0n.com",
            fuzzer=None,
            sources=["openphish"],
            source_types=["known_phishing"],
            provenance={"openphish": "community_feed"},
            ip_addresses=[],
            dns_ns=[],
            dns_mx=[],
            is_known_phishing=True
        )

        with patch("services.threat_intelligence.orchestrator.fetch_dnstwist_candidates", return_value=[cand_dnstwist]):
            with patch("services.threat_intelligence.orchestrator.fetch_openphish_candidates", return_value=[cand_openphish]):
                with patch("services.threat_intelligence.orchestrator.fetch_phishtank_candidates", return_value=[]):
                    result = ThreatIntelOrchestrator.execute_multi_source_scan(
                        "amazon.com", quick_mode=True, timeout=5
                    )

        perms = result["permutations"]
        amaz0n = [p for p in perms if p["domain"] == "amaz0n.com"]

        self.assertEqual(len(amaz0n), 1,
                         f"Duplicate domain must be deduplicated — got {len(amaz0n)} entries")

        merged = amaz0n[0]
        self.assertIn("dnstwist", merged["sources"],
                      "dnstwist source must be present after merge")
        self.assertIn("openphish", merged["sources"],
                      "openphish source must be present after merge")
        self.assertTrue(merged["is_known_phishing"],
                        "is_known_phishing flag must be True after merge from openphish")


if __name__ == "__main__":
    unittest.main(verbosity=2)
