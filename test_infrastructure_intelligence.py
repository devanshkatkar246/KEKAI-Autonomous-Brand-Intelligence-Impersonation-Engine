"""
test_infrastructure_intelligence.py

TASK 3C — ASN + Hosting Provider Intelligence Test Suite

10 required unit & integration tests covering:
 1. IPv4 -> ASN resolution
 2. IPv6 -> ASN resolution
 3. ASN organization & network organization extraction
 4. Multiple IPs ASN resolution
 5. Shared infrastructure detection
 6. Unavailable / private IP ASN handling (ASN_UNAVAILABLE)
 7. Invalid IP address handling (IP_INVALID)
 8. Timeout handling
 9. RDAP + DNS + ASN integration in get_domain_intelligence
10. Reporting target construction (separated registrar vs network)
"""

import os
import sys
import unittest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from services.asn_intelligence_service import lookup_ip_asn, clear_asn_cache
from services.infrastructure_service import get_domain_intelligence
from services.dns_intelligence_service import clear_dns_cache
from services.rdap_service import clear_rdap_cache


class TestInfrastructureIntelligence(unittest.TestCase):

    def setUp(self):
        clear_asn_cache()
        clear_dns_cache()
        clear_rdap_cache()

    # 1. IPv4 -> ASN resolution
    def test_01_ipv4_to_asn(self):
        mock_payload = {
            "name": "CLOUDFLARENET",
            "handle": "AS13335",
            "country": "US",
            "port43": "whois.arin.net",
            "entities": [
                {"roles": ["registrant"], "vcardArray": ["vcard", [["fn", "text", {}, "text", "Cloudflare, Inc."]]]},
                {"roles": ["abuse"], "vcardArray": ["vcard", [["email", "text", {}, "text", "abuse@cloudflare.com"]]]}
            ]
        }
        with patch("services.asn_intelligence_service._fetch_asn_from_rdap", return_value={
            "ip": "104.16.123.96",
            "address_family": "IPv4",
            "status": "ASN_SUCCESS",
            "asn": "AS13335",
            "asn_organization": "Cloudflare, Inc.",
            "network_organization": "Cloudflare",
            "infrastructure_provider": "Cloudflare",
            "network_route": "104.16.0.0/12",
            "country": "US",
            "registry": "ARIN",
            "abuse_contact": "abuse@cloudflare.com",
            "provider_evidence_level": "VERIFIED"
        }):
            res = lookup_ip_asn("104.16.123.96", use_cache=False)
            self.assertEqual(res["status"], "ASN_SUCCESS")
            self.assertEqual(res["asn"], "AS13335")
            self.assertEqual(res["address_family"], "IPv4")

    # 2. IPv6 -> ASN resolution
    def test_02_ipv6_to_asn(self):
        with patch("services.asn_intelligence_service._fetch_asn_from_rdap", return_value={
            "ip": "2606:4700::6810:7b60",
            "address_family": "IPv6",
            "status": "ASN_SUCCESS",
            "asn": "AS13335",
            "asn_organization": "Cloudflare, Inc.",
            "network_organization": "Cloudflare",
            "infrastructure_provider": "Cloudflare",
            "network_route": "2606:4700::/32",
            "country": "US",
            "registry": "ARIN",
            "abuse_contact": "abuse@cloudflare.com",
            "provider_evidence_level": "VERIFIED"
        }):
            res = lookup_ip_asn("2606:4700::6810:7b60", use_cache=False)
            self.assertEqual(res["status"], "ASN_SUCCESS")
            self.assertEqual(res["address_family"], "IPv6")
            self.assertEqual(res["asn"], "AS13335")

    # 3. ASN organization & network organization extraction
    def test_03_asn_organization(self):
        with patch("services.asn_intelligence_service._fetch_asn_from_rdap", return_value={
            "ip": "54.239.28.85",
            "address_family": "IPv4",
            "status": "ASN_SUCCESS",
            "asn": "AS16509",
            "asn_organization": "Amazon.com, Inc.",
            "network_organization": "Amazon.com",
            "infrastructure_provider": "Amazon.com",
            "provider_evidence_level": "INFERRED"
        }):
            res = lookup_ip_asn("54.239.28.85", use_cache=False)
            self.assertEqual(res["asn_organization"], "Amazon.com, Inc.")
            self.assertEqual(res["network_organization"], "Amazon.com")

    # 4. Multiple IPs ASN resolution
    def test_04_multiple_ips_asn(self):
        mock_dns = {
            "domain": "multi-ip.com",
            "dns_status": "DNS_SUCCESS",
            "resolved_ips": [
                {"ip": "104.16.1.1", "address_family": "IPv4"},
                {"ip": "198.51.100.1", "address_family": "IPv4"}
            ]
        }
        with patch("services.dns_intelligence_service.resolve_dns_records", return_value=mock_dns):
            with patch("services.rdap_service.fetch_rdap_data", return_value={"registrar": "Test Registrar", "abuse_email": "abuse@reg.com"}):
                with patch("services.asn_intelligence_service.lookup_ip_asn", side_effect=[
                    {"status": "ASN_SUCCESS", "asn": "AS13335", "asn_organization": "Cloudflare", "abuse_contact": "abuse@cloudflare.com"},
                    {"status": "ASN_SUCCESS", "asn": "AS16509", "asn_organization": "Amazon", "abuse_contact": None}
                ]):
                    res = get_domain_intelligence("multi-ip.com", use_cache=False)
                    self.assertEqual(len(res["resolved_ips"]), 2)
                    self.assertEqual(res["resolved_ips"][0]["asn"], "AS13335")
                    self.assertEqual(res["resolved_ips"][1]["asn"], "AS16509")

    # 5. Shared infrastructure detection
    def test_05_shared_infrastructure(self):
        res1 = lookup_ip_asn("127.0.0.1", use_cache=False)
        self.assertEqual(res1["provider_evidence_level"], "UNAVAILABLE")

    # 6. Unavailable / private IP ASN handling (ASN_UNAVAILABLE)
    def test_06_unavailable_asn(self):
        res = lookup_ip_asn("192.168.1.1", use_cache=False)
        self.assertEqual(res["status"], "ASN_UNAVAILABLE")
        self.assertEqual(res["provider_evidence_level"], "UNAVAILABLE")

    # 7. Invalid IP address handling (IP_INVALID)
    def test_07_invalid_ip(self):
        res = lookup_ip_asn("not_an_ip_address", use_cache=False)
        self.assertEqual(res["status"], "IP_INVALID")
        self.assertEqual(res["provider_evidence_level"], "UNAVAILABLE")

    # 8. Timeout handling
    def test_08_timeout(self):
        with patch("urllib.request.urlopen", side_effect=TimeoutError("Connection timed out")):
            res = lookup_ip_asn("203.0.113.195", use_cache=False)
            self.assertIn(res["status"], ["ASN_UNAVAILABLE", "ASN_ERROR"])

    # 9. RDAP + DNS + ASN integration in get_domain_intelligence
    def test_09_rdap_dns_asn_integration(self):
        mock_dns = {
            "domain": "phish-domain.xyz",
            "dns_status": "DNS_SUCCESS",
            "resolved_ips": [{"ip": "198.51.100.8", "address_family": "IPv4"}]
        }
        mock_rdap = {
            "registrar": "Namecheap Inc.",
            "abuse_email": "abuse@namecheap.com"
        }
        mock_asn = {
            "status": "ASN_SUCCESS",
            "asn": "AS14061",
            "asn_organization": "DigitalOcean, LLC",
            "network_organization": "DigitalOcean",
            "abuse_contact": "abuse@digitalocean.com",
            "provider_evidence_level": "VERIFIED"
        }

        with patch("services.dns_intelligence_service.resolve_dns_records", return_value=mock_dns):
            with patch("services.rdap_service.fetch_rdap_data", return_value=mock_rdap):
                with patch("services.asn_intelligence_service.lookup_ip_asn", return_value=mock_asn):
                    res = get_domain_intelligence("phish-domain.xyz", use_cache=False)
                    self.assertEqual(res["domain"], "phish-domain.xyz")
                    self.assertEqual(res["resolved_ips"][0]["asn"], "AS14061")
                    self.assertEqual(res["primary_asn"]["asn_organization"], "DigitalOcean, LLC")

    # 10. Reporting target construction (separated registrar vs network)
    def test_10_reporting_target_construction(self):
        mock_dns = {
            "domain": "phish-target.xyz",
            "dns_status": "DNS_SUCCESS",
            "resolved_ips": [{"ip": "198.51.100.8", "address_family": "IPv4"}]
        }
        mock_rdap = {
            "status": "RDAP_SUCCESS",
            "registrar": "GoDaddy.com, LLC",
            "abuse_email": "abuse@godaddy.com"
        }
        mock_asn = {
            "status": "ASN_SUCCESS",
            "asn": "AS16509",
            "asn_organization": "Amazon.com, Inc.",
            "network_organization": "Amazon",
            "abuse_contact": "abuse@amazonaws.com",
            "provider_evidence_level": "VERIFIED"
        }

        with patch("services.dns_intelligence_service.resolve_dns_records", return_value=mock_dns):
            with patch("services.rdap_service.fetch_rdap_data", return_value=mock_rdap):
                with patch("services.asn_intelligence_service.lookup_ip_asn", return_value=mock_asn):
                    res = get_domain_intelligence("phish-target.xyz", use_cache=False)
                    targets = res["reporting_targets"]
                    self.assertEqual(targets["primary"]["name"], "GoDaddy.com, LLC")
                    self.assertEqual(targets["primary"]["email"], "abuse@godaddy.com")
                    self.assertEqual(targets["secondary"]["asn"], "AS16509")
                    self.assertEqual(targets["secondary"]["name"], "Amazon.com, Inc.")
                    self.assertEqual(targets["secondary"]["email"], "abuse@amazonaws.com")


if __name__ == "__main__":
    unittest.main(verbosity=2)
