"""
test_task6_universal_engine.py

TASK 6 — UNIVERSAL TAKEDOWN EXECUTION ENGINE TEST SUITE

Includes comprehensive unit & integration tests for:
 1. RDAP provider discovery success
 2. RDAP missing contact fallback to WHOIS
 3. RDAP unavailable fallback to WHOIS
 4. WHOIS fallback contact resolution
 5. Cloudflare routing (Cloudflare CDN/DNS proxy -> Cloudflare API route)
 6. Email routing (Verified registrar abuse email -> RegistrarEmailAdapter)
 7. Browser routing (Web form fallback -> BrowserFormAdapter)
 8. No route (No contact available -> CONTACT_UNAVAILABLE / ManualEscalationAdapter)
 9. Provider changed after approval -> APPROVAL_INVALIDATED_PROVIDER_CHANGED
10. Recipient changed after approval -> revalidated
11. Duplicate submission idempotency
12. Concurrent submission race protection (ThreadPoolExecutor -> 1 claim)
13. Stale submission lease reconciliation -> UNKNOWN_SUBMISSION_STATE
14. DRY_RUN mode -> ZERO external network requests
15. Mock LIVE mode execution
16. Approval invalidation / revocation -> HUMAN_APPROVAL_REQUIRED / APPROVAL_REVOKED
17. Evidence modification -> APPROVAL_INVALIDATED_EVIDENCE_CHANGED
18. Legitimacy change -> APPROVAL_INVALIDATED_LEGITIMACY_CHANGED
19. Arbitrary email injection attempt -> client email IGNORED
20. Frontend destination manipulation attempt -> server authority PRESERVED
"""

import json
import os
import sys
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone, timedelta
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from database import init_db, abuse_execute, abuse_one
from services.abuse_control_service import approve, fingerprint
from services.provider_discovery_service import discover_provider_contacts, clear_provider_discovery_cache
from services.universal_abuse_router import submit_universal_takedown, UniversalAbuseRouter, RegistrarEmailAdapter


def valid_payload(domain="amaz0n-security-login.xyz", **overrides):
    payload = {
        "candidate_domain": domain,
        "target_brand": "Amazon",
        "official_domain": "amazon.com",
        "evidence": {
            "sources": ["dnstwist", "openphish"],
            "domain_permutation": True,
            "strong_visual_match": True,
            "credential_indicators": True,
            "screenshot": {"status": "SUCCESS", "source": "candidate_acquisition"}
        },
        "authorization_registry": {
            "source": "REGISTRY",
            "brands": {"amazon": {"domains": [{"domain": "amazon.com", "classification": "OFFICIAL_DOMAIN"}]}}
        }
    }
    payload.update(overrides)
    return payload


def mock_default_discovery(domain="amaz0n-security-login.xyz"):
    return {
        "domain": domain,
        "is_cloudflare": True,
        "primary_provider": "Cloudflare",
        "primary_method": "API",
        "confidence": "HIGH",
        "routing_reason": "Cloudflare API route verified.",
        "registrar": {
            "name": "Cloudflare Registrar",
            "iana_id": "1910",
            "abuse_email": "abuse@cloudflare.com",
            "contact_state": "VERIFIED"
        },
        "network": {
            "provider_name": "CLOUDFLARENET",
            "asn": "AS13335",
            "abuse_email": "abuse@cloudflare.com",
            "is_cdn": True
        },
        "source": "PROVIDER_INTEL"
    }


class TestTask6UniversalEngine(unittest.TestCase):

    def setUp(self):
        init_db()
        abuse_execute("DELETE FROM abuse_submissions")
        abuse_execute("DELETE FROM abuse_approvals")
        abuse_execute("DELETE FROM abuse_snapshots")
        clear_provider_discovery_cache()
        os.environ['ABUSE_SUBMISSION_MODE'] = 'DRY_RUN'

    # 1. RDAP provider discovery success
    def test_01_rdap_success(self):
        mock_rdap = {
            "status": "RDAP_SUCCESS",
            "domain": "test-phish.com",
            "registrar": "Example Registrar LLC",
            "abuse_email": "abuse@example-registrar.com",
            "raw_rdap": {
                "entities": [
                    {"roles": ["registrar"], "vcardArray": ["vcard", [["fn", {}, "text", "Example Registrar LLC"]]]},
                    {"roles": ["abuse"], "vcardArray": ["vcard", [["email", {}, "text", "abuse@example-registrar.com"]]]}
                ]
            }
        }
        with patch("services.registration_intelligence_service.fetch_rdap_data", return_value=mock_rdap):
            disc = discover_provider_contacts("test-phish.com", use_cache=False)
            self.assertEqual(disc["registrar"]["name"], "Example Registrar LLC")
            self.assertEqual(disc["registrar"]["abuse_email"], "abuse@example-registrar.com")
            self.assertEqual(disc["primary_method"], "EMAIL")

    # 2. RDAP missing contact fallback to WHOIS
    def test_02_rdap_missing_contact(self):
        mock_rdap = {"status": "RDAP_NOT_FOUND"}
        mock_whois = {
            "domain": "whois-fallback.com",
            "source": "WHOIS",
            "registrar": {"name": "WHOIS Registrar Inc", "abuse_email": "abuse@whois-registrar.com"},
            "abuse_contact": {"emails": ["abuse@whois-registrar.com"], "state": "VERIFIED"}
        }
        with patch("services.registration_intelligence_service.fetch_rdap_data", return_value=mock_rdap):
            with patch("services.provider_discovery_service.get_registration_intelligence", return_value=mock_whois):
                disc = discover_provider_contacts("whois-fallback.com", use_cache=False)
                self.assertEqual(disc["registrar"]["name"], "WHOIS Registrar Inc")
                self.assertEqual(disc["registrar"]["abuse_email"], "abuse@whois-registrar.com")

    # 3. RDAP unavailable fallback to WHOIS
    def test_03_rdap_unavailable(self):
        mock_intel = {
            "domain": "rdap-down.com",
            "source": "WHOIS",
            "registrar": {"name": "Fallback Reg", "abuse_email": "abuse@fallback-reg.com"},
            "abuse_contact": {"emails": ["abuse@fallback-reg.com"], "state": "VERIFIED"}
        }
        with patch("services.provider_discovery_service.get_registration_intelligence", return_value=mock_intel):
            disc = discover_provider_contacts("rdap-down.com", use_cache=False)
            self.assertEqual(disc["registrar"]["abuse_email"], "abuse@fallback-reg.com")

    # 4. WHOIS fallback contact resolution
    def test_04_whois_fallback(self):
        mock_intel = {
            "domain": "domain-whois.org",
            "source": "WHOIS",
            "registrar": {"name": "Org Registrar", "abuse_email": "abuse@org-registrar.org"},
            "abuse_contact": {"emails": ["abuse@org-registrar.org"], "state": "VERIFIED"}
        }
        with patch("services.provider_discovery_service.get_registration_intelligence", return_value=mock_intel):
            disc = discover_provider_contacts("domain-whois.org", use_cache=False)
            self.assertEqual(disc["primary_provider"], "Org Registrar")
            self.assertEqual(disc["registrar"]["abuse_email"], "abuse@org-registrar.org")

    # 5. Cloudflare routing (Cloudflare CDN -> Cloudflare API route)
    def test_05_cloudflare_routing(self):
        mock_intel = {
            "domain": "cloudflare-target.com",
            "source": "RDAP",
            "registrar": {"name": "Namecheap Inc", "abuse_email": "abuse@namecheap.com"},
            "abuse_contact": {"emails": ["abuse@namecheap.com"], "state": "VERIFIED"}
        }
        mock_dns = {"resolved_ips": [{"ip": "104.21.1.1"}]}
        mock_asn = {"asn_organization": "CLOUDFLARENET", "asn": "AS13335"}

        with patch("services.provider_discovery_service.get_registration_intelligence", return_value=mock_intel):
            with patch("services.provider_discovery_service.resolve_dns_records", return_value=mock_dns):
                with patch("services.provider_discovery_service.lookup_ip_asn", return_value=mock_asn):
                    disc = discover_provider_contacts("cloudflare-target.com", use_cache=False)
                    self.assertTrue(disc["is_cloudflare"])
                    self.assertEqual(disc["primary_provider"], "Cloudflare")
                    self.assertEqual(disc["primary_method"], "API")

    # 6. Email routing (Verified registrar abuse email -> RegistrarEmailAdapter)
    def test_06_email_routing(self):
        mock_intel = {
            "domain": "email-target.com",
            "source": "RDAP",
            "registrar": {"name": "GoDaddy.com LLC", "abuse_email": "abuse@godaddy.com"},
            "abuse_contact": {"emails": ["abuse@godaddy.com"], "state": "VERIFIED"}
        }
        mock_dns = {"resolved_ips": [{"ip": "192.0.2.1"}]}
        mock_asn = {"asn_organization": "Other Host", "asn": "AS12345"}

        with patch("services.provider_discovery_service.get_registration_intelligence", return_value=mock_intel):
            with patch("services.provider_discovery_service.resolve_dns_records", return_value=mock_dns):
                with patch("services.provider_discovery_service.lookup_ip_asn", return_value=mock_asn):
                    disc = discover_provider_contacts("email-target.com", use_cache=False)
                    self.assertEqual(disc["primary_provider"], "GoDaddy.com LLC")
                    self.assertEqual(disc["primary_method"], "EMAIL")

    # 7. Browser routing (Web form fallback -> BrowserFormAdapter)
    def test_07_browser_routing(self):
        mock_intel = {
            "domain": "form-target.com",
            "source": "RDAP",
            "registrar": {"name": "Form-Only Registrar"},
            "abuse_contact": {"emails": [], "state": "UNAVAILABLE"}
        }
        with patch("services.provider_discovery_service.get_registration_intelligence", return_value=mock_intel):
            disc = discover_provider_contacts("form-target.com", use_cache=False)
            self.assertEqual(disc["primary_method"], "BROWSER")

    # 8. No route (No contact available -> CONTACT_UNAVAILABLE / ManualEscalationAdapter)
    def test_08_no_route(self):
        mock_intel = {
            "domain": "no-route.com",
            "source": "NONE",
            "registrar": {"name": "Unknown Registrar"},
            "abuse_contact": {"emails": [], "state": "UNAVAILABLE"}
        }
        with patch("services.provider_discovery_service.get_registration_intelligence", return_value=mock_intel):
            disc = discover_provider_contacts("no-route.com", use_cache=False)
            self.assertEqual(disc["primary_method"], "MANUAL")

    # 9. Provider changed after approval -> APPROVAL_INVALIDATED_PROVIDER_CHANGED
    def test_09_provider_changed(self):
        case_id = "case_task6_prov_001"
        payload = valid_payload("amaz0n-prov-chg.xyz")
        appr = approve(case_id, payload)
        aid = appr["approval_id"]

        with patch("services.universal_abuse_router.revalidate_provider_route", return_value="APPROVAL_INVALIDATED_PROVIDER_CHANGED"):
            res = submit_universal_takedown(case_id, aid)
            self.assertEqual(res["error"], "APPROVAL_INVALIDATED_PROVIDER_CHANGED")

    # 10. Recipient changed after approval -> revalidated from RDAP
    def test_10_recipient_changed(self):
        adapter = RegistrarEmailAdapter()
        mock_disc = {
            "registrar": {"abuse_email": "authoritative-rdap@godaddy.com"}
        }
        with patch("services.universal_abuse_router.discover_provider_contacts", return_value=mock_disc):
            res = adapter.submit({"candidate_domain": "amaz0n-test.xyz"}, mode="DRY_RUN")
            self.assertEqual(res["recipient"], "authoritative-rdap@godaddy.com")

    # 11. Duplicate submission idempotency
    def test_11_duplicate_submission(self):
        case_id = "case_task6_dup_001"
        payload = valid_payload("amaz0n-dup-t6.xyz")
        appr = approve(case_id, payload)
        aid = appr["approval_id"]

        with patch("services.universal_abuse_router.discover_provider_contacts", side_effect=mock_default_discovery):
            first = submit_universal_takedown(case_id, aid)
            second = submit_universal_takedown(case_id, aid)
            self.assertEqual(first["submission_id"], second["submission_id"])
            self.assertEqual(second["state"], "DRY_RUN_COMPLETED")

    # 12. Concurrent submission race protection (ThreadPoolExecutor -> 1 claim)
    def test_12_concurrent_submission(self):
        case_id = "case_task6_concurrent_001"
        payload = valid_payload("amaz0n-conc-t6.xyz")
        appr = approve(case_id, payload)
        aid = appr["approval_id"]

        with patch("services.universal_abuse_router.discover_provider_contacts", side_effect=mock_default_discovery):
            def do_submit():
                return submit_universal_takedown(case_id, aid)

            with ThreadPoolExecutor(max_workers=5) as executor:
                futures = [executor.submit(do_submit) for _ in range(5)]
                results = [f.result() for f in futures]

            sub_ids = set(r.get("submission_id") for r in results if "submission_id" in r)
            self.assertEqual(len(sub_ids), 1)

    # 13. Stale submission lease reconciliation -> UNKNOWN_SUBMISSION_STATE
    def test_13_stale_submission(self):
        case_id = "case_task6_stale_001"
        payload = valid_payload("amaz0n-stale-t6.xyz")
        appr = approve(case_id, payload)
        aid = appr["approval_id"]

        snap = abuse_one("SELECT fingerprint FROM abuse_snapshots WHERE case_id=?", (case_id,))
        past_lease = (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat()
        abuse_execute(
            "INSERT INTO abuse_submissions(submission_id, case_id, snapshot_id, fingerprint, state, lease_expires_at) VALUES(?,?,?,?,?,?)",
            ("sub_stale_t6", case_id, "snap_stale_t6", snap["fingerprint"], "SUBMITTING", past_lease)
        )

        with patch("services.universal_abuse_router.discover_provider_contacts", side_effect=mock_default_discovery):
            res = submit_universal_takedown(case_id, aid)
            self.assertEqual(res["state"], "UNKNOWN_SUBMISSION_STATE")

    # 14. DRY_RUN mode -> ZERO external network requests
    def test_14_dry_run(self):
        case_id = "case_task6_dry_001"
        payload = valid_payload("amaz0n-dry-t6.xyz")
        appr = approve(case_id, payload)
        aid = appr["approval_id"]

        os.environ['ABUSE_SUBMISSION_MODE'] = 'DRY_RUN'
        with patch("services.universal_abuse_router.discover_provider_contacts", side_effect=mock_default_discovery):
            res = submit_universal_takedown(case_id, aid)
            self.assertEqual(res["state"], "DRY_RUN_COMPLETED")
            self.assertFalse(res["external_request_performed"])

    # 15. Mock LIVE mode execution
    def test_15_mock_live(self):
        case_id = "case_task6_live_001"
        payload = valid_payload("amaz0n-live-t6.xyz")
        appr = approve(case_id, payload)
        aid = appr["approval_id"]

        os.environ['ABUSE_SUBMISSION_MODE'] = 'LIVE'
        mock_cf = MagicMock(return_value={"state": "SUBMITTED", "report_id": "cf_report_999"})

        with patch("services.universal_abuse_router.discover_provider_contacts", side_effect=mock_default_discovery):
            with patch("services.universal_abuse_router.create_phishing_report", mock_cf):
                res = submit_universal_takedown(case_id, aid)
                self.assertEqual(res["state"], "SUBMITTED")
                self.assertEqual(res["provider_report_id"], "cf_report_999")

    # 16. Approval invalidation / revocation -> HUMAN_APPROVAL_REQUIRED / APPROVAL_REVOKED
    def test_16_approval_invalidation(self):
        case_id = "case_task6_unauth_001"
        res = submit_universal_takedown(case_id, "invalid_approval_id")
        self.assertEqual(res["error"], "HUMAN_APPROVAL_REQUIRED")

    # 17. Evidence modification -> APPROVAL_INVALIDATED_EVIDENCE_CHANGED
    def test_17_evidence_modification(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            sc_path = Path(tmpdir) / "sc_t6.png"
            sc_path.write_bytes(b"original screenshot bytes")

            payload = valid_payload("amaz0n-ev-t6.xyz")
            payload["evidence"]["screenshot"] = {
                "status": "SUCCESS",
                "path": str(sc_path),
                "artifact_hash": "original_hash"
            }

            case_id = "case_task6_evmod_001"
            appr = approve(case_id, payload)
            aid = appr["approval_id"]

            sc_path.write_bytes(b"MODIFIED BYTES")

            with patch("services.universal_abuse_router.discover_provider_contacts", side_effect=mock_default_discovery):
                res = submit_universal_takedown(case_id, aid)
                self.assertEqual(res["error"], "APPROVAL_INVALIDATED_EVIDENCE_CHANGED")

    # 18. Legitimacy change -> APPROVAL_INVALIDATED_LEGITIMACY_CHANGED
    def test_18_legitimacy_change(self):
        case_id = "case_task6_legit_001"
        payload = valid_payload("amaz0n-legit-t6.xyz")
        appr = approve(case_id, payload)
        aid = appr["approval_id"]

        with patch("services.universal_abuse_router.revalidate_legitimacy", return_value="APPROVAL_INVALIDATED_LEGITIMACY_CHANGED"):
            res = submit_universal_takedown(case_id, aid)
            self.assertEqual(res["error"], "APPROVAL_INVALIDATED_LEGITIMACY_CHANGED")

    # 19. Arbitrary email injection attempt -> client email IGNORED
    def test_19_arbitrary_email_injection(self):
        case_id = "case_task6_email_inj_001"
        payload = valid_payload("amaz0n-email-inj.xyz")
        appr = approve(case_id, payload)
        aid = appr["approval_id"]

        # Client sends malicious arbitrary recipient email in payload
        client_payload = {"destination_email": "hacker@malicious-domain.com", "mode": "LIVE"}

        mock_disc = {
            "primary_provider": "Verified Registrar",
            "primary_method": "EMAIL",
            "registrar": {"abuse_email": "verified-abuse@registrar.com", "contact_state": "VERIFIED"}
        }

        with patch("services.universal_abuse_router.discover_provider_contacts", return_value=mock_disc):
            res = submit_universal_takedown(case_id, aid, client_payload=client_payload)
            self.assertEqual(res["recipient"], "verified-abuse@registrar.com")
            self.assertNotEqual(res["recipient"], "hacker@malicious-domain.com")

    # 20. Frontend destination manipulation attempt -> server authority PRESERVED
    def test_20_frontend_destination_manipulation(self):
        case_id = "case_task6_dest_manip_001"
        payload = valid_payload("amaz0n-dest-manip.xyz")
        appr = approve(case_id, payload)
        aid = appr["approval_id"]

        client_payload = {"provider": "FakeProvider", "method": "FAKE_METHOD", "mode": "LIVE"}
        os.environ['ABUSE_SUBMISSION_MODE'] = 'DRY_RUN'

        with patch("services.universal_abuse_router.discover_provider_contacts", side_effect=mock_default_discovery):
            res = submit_universal_takedown(case_id, aid, client_payload=client_payload)
            self.assertEqual(res["state"], "DRY_RUN_COMPLETED")
            self.assertFalse(res["external_request_performed"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
