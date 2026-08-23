import unittest
import os
import json
from pathlib import Path
from services.threat_intelligence.models import NormalizedCandidate, SourceHealth
from services.threat_intelligence.dnstwist_adapter import fetch_dnstwist_candidates, get_dnstwist_health
from services.threat_intelligence.openphish_adapter import fetch_openphish_candidates, get_openphish_health, fetch_openphish_feed
from services.threat_intelligence.phishtank_adapter import fetch_phishtank_candidates, get_phishtank_health, fetch_phishtank_dataset
from services.threat_intelligence.orchestrator import ThreatIntelOrchestrator


class TestThreatIntelIntegration(unittest.TestCase):

    def test_01_dnstwist_adapter_normalization(self):
        """Test dnstwist candidate normalization schema contract."""
        candidates = fetch_dnstwist_candidates("amazon.com", quick_mode=True, timeout=5)
        self.assertIsInstance(candidates, list)
        self.assertGreater(len(candidates), 0)

        c = candidates[0]
        self.assertIsInstance(c, NormalizedCandidate)
        self.assertIn("dnstwist", c.sources)
        self.assertIn("permutation", c.source_types)
        self.assertEqual(c.target_brand, "Amazon")
        self.assertIn("dnstwist", c.provenance)

    def test_02_openphish_adapter_cache_fallback(self):
        """Test OpenPhish feed parsing, keyword matching, and cache fallback."""
        health = get_openphish_health()
        self.assertIn(health.status, ["AVAILABLE", "DEGRADED"])

        candidates = fetch_openphish_candidates("amazon.com", timeout=2)
        self.assertIsInstance(candidates, list)
        for cand in candidates:
            self.assertIn("openphish", cand.sources)
            self.assertTrue(cand.is_known_phishing)
            self.assertIn("openphish", cand.provenance)

    def test_03_phishtank_adapter_integration(self):
        """Test PhishTank database fetching, env var config, and candidate normalization."""
        health = get_phishtank_health()
        self.assertIn(health.status, ["AVAILABLE", "UNAVAILABLE"])

        candidates = fetch_phishtank_candidates("amazon.com", timeout=2)
        self.assertIsInstance(candidates, list)
        for cand in candidates:
            self.assertIn("phishtank", cand.sources)
            self.assertTrue(cand.is_known_phishing)
            self.assertIn("phishtank", cand.provenance)

    def test_04_deduplication_and_provenance_merging(self):
        """Test that candidates appearing across multiple sources merge into a single candidate with unified provenance."""
        result = ThreatIntelOrchestrator.execute_multi_source_scan("amazon.com", quick_mode=True, timeout=5)
        self.assertIn("permutations", result)
        self.assertIn("sources_health", result)

        perms = result["permutations"]
        self.assertGreater(len(perms), 0)

        # Check for deduplication by domain
        domains = [p["domain"] for p in perms]
        self.assertEqual(len(domains), len(set(domains)), "Candidate domains must be uniquely deduplicated")

        # Verify provenance array structure
        for p in perms:
            self.assertIsInstance(p["sources"], list)
            self.assertIsInstance(p["provenance"], dict)
            self.assertGreater(len(p["sources"]), 0)

    def test_05_source_failure_isolation(self):
        """Verify that if network fetches fail or time out, the multi-source scan completes cleanly using cached/fallback sources."""
        # Execute scan with ultra short timeout
        result = ThreatIntelOrchestrator.execute_multi_source_scan("flipkart.com", quick_mode=True, timeout=2)
        self.assertEqual(result["target_domain"], "flipkart.com")
        self.assertGreater(result["total_candidates"], 0)
        self.assertIn("dnstwist", result["sources_health"])
        self.assertIn("openphish", result["sources_health"])
        self.assertIn("phishtank", result["sources_health"])


if __name__ == "__main__":
    unittest.main()
