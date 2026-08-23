"""
test_dns_intelligence.py

TASK 3B — DNS + IP Infrastructure Intelligence Test Suite

14 required unit & integration tests covering:
 1. A record resolution
 2. AAAA record resolution
 3. CNAME resolution
 4. NS resolution
 5. MX resolution
 6. Multiple IPs extraction
 7. Duplicate records deduplication
 8. NXDOMAIN status handling (DNS_NXDOMAIN)
 9. Timeout status handling (DNS_TIMEOUT)
10. SERVFAIL status handling (DNS_SERVFAIL)
11. Invalid domain format handling (DNS_ERROR)
12. Reverse DNS (PTR) lookup
13. In-memory caching mechanism
14. Integration with RDAP in get_domain_intelligence
"""

import os
import sys
import unittest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from services.dns_intelligence_service import resolve_dns_records, clear_dns_cache, resolve_reverse_dns
from services.rdap_service import fetch_rdap_data, clear_rdap_cache
from services.infrastructure_service import get_domain_intelligence


class TestDNSIntelligence(unittest.TestCase):

    def setUp(self):
        clear_dns_cache()
        clear_rdap_cache()

    # 1. A record resolution
    def test_01_a_record(self):
        with patch("dns.resolver.Resolver.resolve") as mock_resolve:
            mock_a = MagicMock()
            mock_a.__iter__.return_value = ["192.0.2.1"]
            mock_a.ttl = 300

            def side_effect(domain, rtype):
                if rtype == "A":
                    return mock_a
                raise Exception("No answer")

            mock_resolve.side_effect = side_effect

            res = resolve_dns_records("example.com", use_cache=False)
            self.assertEqual(res["dns_status"], "DNS_SUCCESS")
            a_recs = res["dns_intelligence"]["a"]
            self.assertEqual(len(a_recs), 1)
            self.assertEqual(a_recs[0]["value"], "192.0.2.1")
            self.assertEqual(a_recs[0]["ttl"], 300)

    # 2. AAAA record resolution
    def test_02_aaaa_record(self):
        with patch("dns.resolver.Resolver.resolve") as mock_resolve:
            mock_aaaa = MagicMock()
            mock_aaaa.__iter__.return_value = ["2001:db8::1"]
            mock_aaaa.ttl = 600

            def side_effect(domain, rtype):
                if rtype == "AAAA":
                    return mock_aaaa
                raise Exception("No answer")

            mock_resolve.side_effect = side_effect

            res = resolve_dns_records("example.com", use_cache=False)
            self.assertEqual(res["dns_status"], "DNS_SUCCESS")
            aaaa_recs = res["dns_intelligence"]["aaaa"]
            self.assertEqual(len(aaaa_recs), 1)
            self.assertEqual(aaaa_recs[0]["value"], "2001:db8::1")
            self.assertEqual(res["resolved_ips"][0]["address_family"], "IPv6")

    # 3. CNAME resolution
    def test_03_cname_record(self):
        with patch("dns.resolver.Resolver.resolve") as mock_resolve:
            mock_cname = MagicMock()
            cname_target = MagicMock()
            cname_target.target = "target.example.net."
            mock_cname.__iter__.return_value = [cname_target]

            def side_effect(domain, rtype):
                if rtype == "CNAME":
                    return mock_cname
                raise Exception("No answer")

            mock_resolve.side_effect = side_effect

            res = resolve_dns_records("sub.example.com", use_cache=False)
            self.assertEqual(res["dns_status"], "DNS_SUCCESS")
            cnames = res["dns_intelligence"]["cname"]
            self.assertEqual(len(cnames), 1)
            self.assertEqual(cnames[0]["value"], "target.example.net")

    # 4. NS resolution
    def test_04_ns_record(self):
        with patch("dns.resolver.Resolver.resolve") as mock_resolve:
            mock_ns = MagicMock()
            ns1 = MagicMock()
            ns1.target = "ns1.exampledns.com."
            mock_ns.__iter__.return_value = [ns1]

            def side_effect(domain, rtype):
                if rtype == "NS":
                    return mock_ns
                raise Exception("No answer")

            mock_resolve.side_effect = side_effect

            res = resolve_dns_records("example.com", use_cache=False)
            self.assertEqual(res["dns_status"], "DNS_SUCCESS")
            ns_recs = res["dns_intelligence"]["ns"]
            self.assertEqual(len(ns_recs), 1)
            self.assertEqual(ns_recs[0]["value"], "ns1.exampledns.com")

    # 5. MX resolution
    def test_05_mx_record(self):
        with patch("dns.resolver.Resolver.resolve") as mock_resolve:
            mock_mx = MagicMock()
            mx1 = MagicMock()
            mx1.exchange = "mail.example.com."
            mock_mx.__iter__.return_value = [mx1]

            def side_effect(domain, rtype):
                if rtype == "MX":
                    return mock_mx
                raise Exception("No answer")

            mock_resolve.side_effect = side_effect

            res = resolve_dns_records("example.com", use_cache=False)
            self.assertEqual(res["dns_status"], "DNS_SUCCESS")
            mx_recs = res["dns_intelligence"]["mx"]
            self.assertEqual(len(mx_recs), 1)
            self.assertEqual(mx_recs[0]["value"], "mail.example.com")

    # 6. Multiple IPs extraction
    def test_06_multiple_ips(self):
        with patch("dns.resolver.Resolver.resolve") as mock_resolve:
            mock_a = MagicMock()
            mock_a.__iter__.return_value = ["192.0.2.1", "192.0.2.2"]
            mock_aaaa = MagicMock()
            mock_aaaa.__iter__.return_value = ["2001:db8::1"]

            def side_effect(domain, rtype):
                if rtype == "A":
                    return mock_a
                if rtype == "AAAA":
                    return mock_aaaa
                raise Exception("No answer")

            mock_resolve.side_effect = side_effect

            res = resolve_dns_records("multi.example.com", use_cache=False)
            self.assertEqual(res["dns_status"], "DNS_SUCCESS")
            self.assertEqual(len(res["resolved_ips"]), 3)

    # 7. Duplicate records deduplication
    def test_07_duplicate_records(self):
        with patch("dns.resolver.Resolver.resolve") as mock_resolve:
            mock_a = MagicMock()
            mock_a.__iter__.return_value = ["192.0.2.1", "192.0.2.1"]

            def side_effect(domain, rtype):
                if rtype == "A":
                    return mock_a
                raise Exception("No answer")

            mock_resolve.side_effect = side_effect

            res = resolve_dns_records("example.com", use_cache=False)
            self.assertEqual(len(res["dns_intelligence"]["a"]), 1)

    # 8. NXDOMAIN status handling
    def test_08_nxdomain(self):
        import dns.resolver
        with patch("dns.resolver.Resolver.resolve", side_effect=dns.resolver.NXDOMAIN):
            res = resolve_dns_records("nonexistent-domain-12345.xyz", use_cache=False)
            self.assertEqual(res["dns_status"], "DNS_NXDOMAIN")
            self.assertEqual(len(res["resolved_ips"]), 0)

    # 9. Timeout status handling
    def test_09_timeout(self):
        import dns.exception
        with patch("dns.resolver.Resolver.resolve", side_effect=dns.exception.Timeout):
            res = resolve_dns_records("timeout-domain.xyz", use_cache=False)
            self.assertEqual(res["dns_status"], "DNS_TIMEOUT")

    # 10. SERVFAIL status handling
    def test_10_servfail(self):
        import dns.resolver
        with patch("dns.resolver.Resolver.resolve", side_effect=dns.resolver.NoNameservers):
            res = resolve_dns_records("servfail-domain.xyz", use_cache=False)
            self.assertEqual(res["dns_status"], "DNS_SERVFAIL")

    # 11. Invalid domain format handling
    def test_11_invalid_domain(self):
        res = resolve_dns_records("invalid_domain_without_tld", use_cache=False)
        self.assertEqual(res["dns_status"], "DNS_ERROR")

    # 12. Reverse DNS lookup
    def test_12_reverse_dns(self):
        with patch("socket.gethostbyaddr", return_value=("ptr-host.example.com", [], ["192.0.2.10"])):
            ptr = resolve_reverse_dns("192.0.2.10")
            self.assertEqual(ptr, "ptr-host.example.com")

    # 13. In-memory caching mechanism
    def test_13_caching(self):
        with patch("dns.resolver.Resolver.resolve") as mock_resolve:
            mock_a = MagicMock()
            mock_a.__iter__.return_value = ["192.0.2.1"]
            mock_resolve.return_value = mock_a

            res1 = resolve_dns_records("cached-domain.com", use_cache=True)
            initial_count = mock_resolve.call_count
            self.assertGreater(initial_count, 0)

            res2 = resolve_dns_records("cached-domain.com", use_cache=True)
            self.assertEqual(mock_resolve.call_count, initial_count)  # No additional network calls
            self.assertEqual(res1["domain"], res2["domain"])

    # 14. Integration with RDAP in get_domain_intelligence
    def test_14_rdap_integration(self):
        mock_dns = {
            "domain": "test-brand-phish.xyz",
            "dns_status": "DNS_SUCCESS",
            "dns_intelligence": {"a": [{"value": "1.2.3.4"}], "aaaa": [], "cname": [], "mx": [], "ns": []},
            "resolved_ips": [{"ip": "1.2.3.4", "address_family": "IPv4"}],
            "reverse_dns": [{"ip": "1.2.3.4", "ptr": "host.provider.com"}],
            "lookup_timestamp": "2026-08-22T21:12:00Z"
        }
        mock_rdap = {
            "status": "RDAP_SUCCESS",
            "domain": "test-brand-phish.xyz",
            "registrar": "Example Registrar LLC",
            "abuse_email": "abuse@exampleregistrar.com",
            "creation_date": "2024-01-01T00:00:00Z",
            "expiration_date": "2026-01-01T00:00:00Z",
            "status_flags": ["clientTransferProhibited"],
            "nameservers": ["ns1.example.com"]
        }

        with patch("services.dns_intelligence_service.resolve_dns_records", return_value=mock_dns):
            with patch("services.rdap_service.fetch_rdap_data", return_value=mock_rdap):
                res = get_domain_intelligence("test-brand-phish.xyz", use_cache=False)
                self.assertEqual(res["domain"], "test-brand-phish.xyz")
                self.assertEqual(res["dns_status"], "DNS_SUCCESS")
                self.assertEqual(res["rdap"]["registrar"], "Example Registrar LLC")
                self.assertEqual(res["rdap"]["abuse_email"], "abuse@exampleregistrar.com")
                self.assertEqual(len(res["resolved_ips"]), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
