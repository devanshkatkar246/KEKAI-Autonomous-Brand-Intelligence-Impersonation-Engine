"""
test_abuse_target_resolution.py

TASK 3D — Unified Abuse Target Resolution Engine Test Suite

15 required unit & integration tests covering:
 1. Registrar found (RDAP)
 2. Abuse email found & verified confidence
 3. Network operator found (IP RDAP/ASN)
 4. No registrar handling
 5. No abuse email handling (NO_ABUSE_CONTACT)
 6. Authorized domain protection (reporting_eligibility = BLOCKED)
 7. Official domain protection (reporting_eligibility = BLOCKED)
 8. Suspicious unrelated domain (reporting_eligibility = ELIGIBLE)
 9. Insufficient evidence handling (INSUFFICIENT_EVIDENCE)
10. Multiple infrastructure providers
11. RDAP failure handling (RDAP_UNAVAILABLE)
12. DNS failure handling (DNS_FAILURE)
13. Complete successful case (READY_FOR_HUMAN_REVIEW)
14. Target provenance preservation (RDAP vs IP_RDAP)
15. Readiness calculation boolean flag
"""

import os
import sys
import unittest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from services.abuse_target_service import resolve_abuse_targets, clear_abuse_target_cache
from services.infrastructure_service import get_domain_intelligence
from services.dns_intelligence_service import clear_dns_cache
from services.rdap_service import clear_rdap_cache
from services.asn_intelligence_service import clear_asn_cache


class TestAbuseTargetResolution(unittest.TestCase):

    def setUp(self):
        clear_abuse_target_cache()
        clear_dns_cache()
        clear_rdap_cache()
        clear_asn_cache()

    # 1. Registrar found
    def test_01_registrar_found(self):
        mock_rdap = {"status": "RDAP_SUCCESS", "registrar": "Namecheap Inc.", "abuse_email": "abuse@namecheap.com"}
        mock_dns = {"dns_status": "DNS_SUCCESS", "resolved_ips": [{"ip": "1.1.1.1"}]}

        res = resolve_abuse_targets("amaz0n-fake.xyz", rdap_data=mock_rdap, dns_data=mock_dns, use_cache=False)
        self.assertEqual(res["abuse_targets"]["primary"]["type"], "REGISTRAR")
        self.assertEqual(res["abuse_targets"]["primary"]["name"], "Namecheap Inc.")

    # 2. Abuse email found & verified
    def test_02_abuse_email_found(self):
        mock_rdap = {"status": "RDAP_SUCCESS", "registrar": "GoDaddy.com LLC", "abuse_email": "abuse@godaddy.com"}
        mock_dns = {"dns_status": "DNS_SUCCESS", "resolved_ips": [{"ip": "1.1.1.1"}]}

        res = resolve_abuse_targets("fake-brand.com", rdap_data=mock_rdap, dns_data=mock_dns, use_cache=False)
        self.assertEqual(res["abuse_targets"]["primary"]["email"], "abuse@godaddy.com")
        self.assertEqual(res["abuse_targets"]["primary"]["confidence"], "VERIFIED")

    # 3. Network operator found
    def test_03_network_found(self):
        mock_rdap = {"status": "RDAP_SUCCESS", "registrar": "Reg LLC", "abuse_email": "abuse@reg.com"}
        mock_dns = {"dns_status": "DNS_SUCCESS", "resolved_ips": [{
            "ip": "104.16.1.1", "asn": "AS13335", "asn_organization": "Cloudflare, Inc.", "abuse_contact": "abuse@cloudflare.com"
        }]}

        res = resolve_abuse_targets("phish.com", rdap_data=mock_rdap, dns_data=mock_dns, use_cache=False)
        sec = res["abuse_targets"]["secondary"]
        self.assertEqual(sec["type"], "NETWORK")
        self.assertEqual(sec["asn"], "AS13335")
        self.assertEqual(sec["name"], "Cloudflare, Inc.")

    # 4. No registrar
    def test_04_no_registrar(self):
        mock_rdap = {"status": "RDAP_SUCCESS", "registrar": "Unknown Registrar", "abuse_email": "abuse@reg.com"}
        mock_dns = {"dns_status": "DNS_SUCCESS", "resolved_ips": [{"ip": "1.1.1.1"}]}

        res = resolve_abuse_targets("noreg.com", rdap_data=mock_rdap, dns_data=mock_dns, use_cache=False)
        self.assertEqual(res["abuse_targets"]["primary"]["name"], "Unknown Registrar")

    # 5. No abuse email handling
    def test_05_no_abuse_email(self):
        mock_rdap = {"status": "RDAP_SUCCESS", "registrar": "NoEmail Registrar", "abuse_email": None}
        mock_dns = {"dns_status": "DNS_SUCCESS", "resolved_ips": [{"ip": "1.1.1.1"}]}

        res = resolve_abuse_targets("noemail.com", rdap_data=mock_rdap, dns_data=mock_dns, use_cache=False)
        readiness = res["reporting_readiness"]
        self.assertEqual(readiness["status"], "NOT_READY")
        self.assertEqual(readiness["readiness_code"], "NO_ABUSE_CONTACT")

    # 6. Authorized domain protection
    def test_06_authorized_domain(self):
        res = resolve_abuse_targets(
            domain="partner-portal.amazon.com",
            official_domain="amazon.com",
            authorized_domains=["partner-portal.amazon.com"],
            use_cache=False
        )
        gate = res["legitimacy_gate"]
        self.assertEqual(gate["status"], "AUTHORIZED_DOMAIN")
        self.assertEqual(gate["reporting_eligibility"], "BLOCKED")
        self.assertEqual(res["reporting_readiness"]["status"], "NOT_READY")

    # 7. Official domain protection
    def test_07_official_domain(self):
        res = resolve_abuse_targets(
            domain="amazon.com",
            official_domain="amazon.com",
            use_cache=False
        )
        gate = res["legitimacy_gate"]
        self.assertEqual(gate["status"], "OFFICIAL_DOMAIN")
        self.assertEqual(gate["reporting_eligibility"], "BLOCKED")
        self.assertFalse(res["reporting_readiness"]["can_prepare_report"])

    # 8. Suspicious unrelated domain
    def test_08_suspicious_unrelated_domain(self):
        res = resolve_abuse_targets(
            domain="amaz0n-login-phish.xyz",
            official_domain="amazon.com",
            use_cache=False
        )
        gate = res["legitimacy_gate"]
        self.assertEqual(gate["status"], "SUSPICIOUS_UNAUTHORIZED_DOMAIN")
        self.assertEqual(gate["reporting_eligibility"], "ELIGIBLE")

    # 9. Insufficient evidence handling
    def test_09_insufficient_evidence(self):
        mock_rdap = {"status": "RDAP_SUCCESS", "registrar": "Reg LLC", "abuse_email": "abuse@reg.com"}
        mock_dns = {"dns_status": "DNS_SUCCESS", "resolved_ips": [{"ip": "1.1.1.1"}]}

        res = resolve_abuse_targets(
            domain="weak-candidate.com",
            evidence_score=30.0,
            rdap_data=mock_rdap,
            dns_data=mock_dns,
            use_cache=False
        )
        readiness = res["reporting_readiness"]
        self.assertEqual(readiness["status"], "NOT_READY")
        self.assertEqual(readiness["readiness_code"], "INSUFFICIENT_EVIDENCE")

    # 10. Multiple infrastructure providers
    def test_10_multiple_infrastructure_providers(self):
        mock_dns = {
            "dns_status": "DNS_SUCCESS",
            "resolved_ips": [
                {"ip": "104.16.1.1", "asn": "AS13335", "asn_organization": "Cloudflare, Inc."},
                {"ip": "198.51.100.1", "asn": "AS16509", "asn_organization": "Amazon.com, Inc."}
            ]
        }
        mock_rdap = {"status": "RDAP_SUCCESS", "registrar": "Reg", "abuse_email": "abuse@reg.com"}

        res = resolve_abuse_targets("multi.com", rdap_data=mock_rdap, dns_data=mock_dns, use_cache=False)
        self.assertEqual(res["abuse_targets"]["secondary"]["asn"], "AS13335")

    # 11. RDAP failure handling
    def test_11_rdap_failure(self):
        mock_rdap = {"status": "RDAP_UNAVAILABLE", "registrar": "Unavailable", "abuse_email": "Unavailable"}
        mock_dns = {"dns_status": "DNS_SUCCESS", "resolved_ips": [{"ip": "1.1.1.1"}]}

        res = resolve_abuse_targets("rdapfail.com", rdap_data=mock_rdap, dns_data=mock_dns, use_cache=False)
        self.assertEqual(res["reporting_readiness"]["status"], "NOT_READY")
        self.assertEqual(res["reporting_readiness"]["readiness_code"], "RDAP_UNAVAILABLE")

    # 12. DNS failure handling
    def test_12_dns_failure(self):
        mock_rdap = {"status": "RDAP_SUCCESS", "registrar": "Reg", "abuse_email": "abuse@reg.com"}
        mock_dns = {"dns_status": "DNS_NXDOMAIN", "resolved_ips": []}

        res = resolve_abuse_targets("dnsfail.com", rdap_data=mock_rdap, dns_data=mock_dns, use_cache=False)
        self.assertEqual(res["reporting_readiness"]["status"], "NOT_READY")
        self.assertEqual(res["reporting_readiness"]["readiness_code"], "DNS_FAILURE")

    # 13. Complete successful case
    def test_13_complete_successful_case(self):
        mock_rdap = {"status": "RDAP_SUCCESS", "registrar": "Namecheap Inc.", "abuse_email": "abuse@namecheap.com"}
        mock_dns = {"dns_status": "DNS_SUCCESS", "resolved_ips": [{"ip": "104.16.1.1", "asn": "AS13335", "asn_organization": "Cloudflare, Inc."}]}

        res = resolve_abuse_targets(
            domain="amaz0n-security-login.xyz",
            official_domain="amazon.com",
            evidence_score=90.0,
            rdap_data=mock_rdap,
            dns_data=mock_dns,
            use_cache=False
        )
        self.assertEqual(res["reporting_readiness"]["status"], "READY_FOR_HUMAN_REVIEW")
        self.assertTrue(res["reporting_readiness"]["can_prepare_report"])

    # 14. Target provenance preservation
    def test_14_target_provenance(self):
        mock_rdap = {"status": "RDAP_SUCCESS", "registrar": "Namecheap Inc.", "abuse_email": "abuse@namecheap.com"}
        mock_dns = {"dns_status": "DNS_SUCCESS", "resolved_ips": [{"ip": "104.16.1.1", "asn": "AS13335", "asn_organization": "Cloudflare, Inc."}]}

        res = resolve_abuse_targets("prov.com", rdap_data=mock_rdap, dns_data=mock_dns, use_cache=False)
        self.assertEqual(res["abuse_targets"]["primary"]["source"], "RDAP")
        self.assertEqual(res["abuse_targets"]["secondary"]["source"], "IP_RDAP")

    # 15. Readiness calculation boolean flag
    def test_15_readiness_calculation(self):
        mock_rdap = {"status": "RDAP_SUCCESS", "registrar": "Namecheap Inc.", "abuse_email": "abuse@namecheap.com"}
        mock_dns = {"dns_status": "DNS_SUCCESS", "resolved_ips": [{"ip": "104.16.1.1"}]}

        res = resolve_abuse_targets("ready.com", evidence_score=80.0, rdap_data=mock_rdap, dns_data=mock_dns, use_cache=False)
        self.assertTrue(res["reporting_readiness"]["can_prepare_report"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
