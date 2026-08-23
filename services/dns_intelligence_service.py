"""
services/dns_intelligence_service.py

TASK 3B — DNS + IP Infrastructure Intelligence Service

Given a suspicious domain, resolves and records its network infrastructure via passive DNS queries (A, AAAA, CNAME, MX, NS), extracts resolved IP addresses, performs reverse DNS (PTR) lookups, and classifies DNS query statuses according to the KEIKAI taxonomy:

    DNS_SUCCESS
    DNS_NXDOMAIN
    DNS_TIMEOUT
    DNS_SERVFAIL
    DNS_NO_RECORD
    DNS_ERROR

Does NOT interpret DNS failure as maliciousness.
Includes in-memory caching and clean test isolation.
"""

import os
import socket
import logging
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple

logger = logging.getLogger(__name__)

# Try importing dnspython
try:
    import dns.resolver
    import dns.reversename
    import dns.exception
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False

_DNS_CACHE: Dict[str, Tuple[float, Dict[str, Any]]] = {}
_CACHE_TTL_SECONDS = 300  # 5 minutes in-memory cache


def clear_dns_cache() -> None:
    """Clears the in-memory DNS lookup cache."""
    _DNS_CACHE.clear()


def get_dns_cache_size() -> int:
    """Returns number of cached DNS entries."""
    return len(_DNS_CACHE)


def _get_utc_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()


def resolve_reverse_dns(ip_address: str) -> Optional[str]:
    """
    Performs passive reverse DNS (PTR) lookup for a given IPv4/IPv6 address.
    Does not execute commands or perform active port scans.
    """
    if not ip_address or ip_address == "—":
        return None

    try:
        if HAS_DNSPYTHON:
            try:
                rev_name = dns.reversename.from_address(ip_address)
                answers = dns.resolver.resolve(rev_name, "PTR", lifetime=3.0)
                if answers:
                    return str(answers[0].target).rstrip(".")
            except Exception:
                pass

        # Fallback to system socket gethostbyaddr
        host_tuple = socket.gethostbyaddr(ip_address)
        if host_tuple and host_tuple[0]:
            return host_tuple[0]
    except (socket.herror, socket.gaierror, socket.timeout, Exception):
        pass

    return None


def resolve_dns_records(domain: str, use_cache: bool = True) -> Dict[str, Any]:
    """
    Performs complete DNS record resolution for a suspicious domain.
    Queries A, AAAA, CNAME, MX, NS records, extracts IPs, performs PTR lookups,
    and returns normalized infrastructure intelligence.
    """
    if not domain or not isinstance(domain, str):
        return _build_dns_error_response("", "DNS_ERROR", "Invalid or missing domain input")

    clean_domain = domain.strip().lower().replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
    if not clean_domain or "." not in clean_domain:
        return _build_dns_error_response(clean_domain, "DNS_ERROR", f"Malformed domain format: '{domain}'")

    # Check cache
    now = datetime.now(timezone.utc).timestamp()
    if use_cache and clean_domain in _DNS_CACHE:
        cached_time, cached_data = _DNS_CACHE[clean_domain]
        if now - cached_time < _CACHE_TTL_SECONDS:
            return cached_data

    records_a: List[Dict[str, Any]] = []
    records_aaaa: List[Dict[str, Any]] = []
    records_cname: List[Dict[str, Any]] = []
    records_mx: List[Dict[str, Any]] = []
    records_ns: List[Dict[str, Any]] = []

    resolved_ips_map: Dict[str, Dict[str, Any]] = {}
    overall_status = "DNS_SUCCESS"
    encountered_exceptions: List[str] = []

    if HAS_DNSPYTHON:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = 3.0
        resolver.timeout = 2.0

        for r_type in ["A", "AAAA", "CNAME", "MX", "NS"]:
            try:
                answers = resolver.resolve(clean_domain, r_type)
                for rdata in answers:
                    if r_type in ["CNAME", "NS"] and hasattr(rdata, "target"):
                        val = str(rdata.target).rstrip(".")
                    elif r_type == "MX" and hasattr(rdata, "exchange"):
                        val = str(rdata.exchange).rstrip(".")
                    else:
                        val = str(rdata).rstrip(".")

                    ttl = getattr(answers, "ttl", getattr(rdata, "ttl", None))
                    ts = _get_utc_timestamp()

                    rec = {
                        "hostname": clean_domain,
                        "record_type": r_type,
                        "value": val,
                        "ttl": ttl,
                        "lookup_timestamp": ts,
                        "resolver": "dnspython"
                    }

                    if r_type == "A":
                        records_a.append(rec)
                        resolved_ips_map[val] = {"ip": val, "address_family": "IPv4", "lookup_timestamp": ts}
                    elif r_type == "AAAA":
                        records_aaaa.append(rec)
                        resolved_ips_map[val] = {"ip": val, "address_family": "IPv6", "lookup_timestamp": ts}
                    elif r_type == "CNAME":
                        records_cname.append(rec)
                    elif r_type == "MX":
                        records_mx.append(rec)
                    elif r_type == "NS":
                        records_ns.append(rec)

            except dns.resolver.NXDOMAIN:
                encountered_exceptions.append("NXDOMAIN")
            except dns.resolver.NoNameservers:
                encountered_exceptions.append("SERVFAIL")
            except (dns.exception.Timeout, getattr(dns.resolver, "LifetimeTimeout", dns.exception.Timeout)):
                encountered_exceptions.append("TIMEOUT")
            except dns.resolver.NoAnswer:
                encountered_exceptions.append("NO_ANSWER")
            except Exception as ex:
                ex_name = ex.__class__.__name__
                ex_str = str(ex).upper()
                if "SERVFAIL" in ex_name or "SERVFAIL" in ex_str or "NAMESERVERS" in ex_str:
                    encountered_exceptions.append("SERVFAIL")
                elif "TIMEOUT" in ex_name or "TIMEOUT" in ex_str:
                    encountered_exceptions.append("TIMEOUT")
                elif "NXDOMAIN" in ex_name or "NXDOMAIN" in ex_str:
                    encountered_exceptions.append("NXDOMAIN")
                else:
                    encountered_exceptions.append(f"ERROR: {str(ex)}")

    else:
        # Fallback to standard socket library
        ts = _get_utc_timestamp()
        try:
            addr_info = socket.getaddrinfo(clean_domain, None)
            for item in addr_info:
                family = item[0]
                sock_addr = item[4]
                ip_val = sock_addr[0]

                if family == socket.AF_INET and ip_val not in resolved_ips_map:
                    rec = {
                        "hostname": clean_domain,
                        "record_type": "A",
                        "value": ip_val,
                        "ttl": None,
                        "lookup_timestamp": ts,
                        "resolver": "system_socket"
                    }
                    records_a.append(rec)
                    resolved_ips_map[ip_val] = {"ip": ip_val, "address_family": "IPv4", "lookup_timestamp": ts}

                elif family == socket.AF_INET6 and ip_val not in resolved_ips_map:
                    rec = {
                        "hostname": clean_domain,
                        "record_type": "AAAA",
                        "value": ip_val,
                        "ttl": None,
                        "lookup_timestamp": ts,
                        "resolver": "system_socket"
                    }
                    records_aaaa.append(rec)
                    resolved_ips_map[ip_val] = {"ip": ip_val, "address_family": "IPv6", "lookup_timestamp": ts}

        except socket.gaierror as e:
            if "not known" in str(e).lower() or "nodename" in str(e).lower():
                encountered_exceptions.append("NXDOMAIN")
            else:
                encountered_exceptions.append("ERROR")
        except socket.timeout:
            encountered_exceptions.append("TIMEOUT")
        except Exception:
            encountered_exceptions.append("ERROR")

    # Deduplicate records
    records_a = _deduplicate_records(records_a)
    records_aaaa = _deduplicate_records(records_aaaa)
    records_cname = _deduplicate_records(records_cname)
    records_mx = _deduplicate_records(records_mx)
    records_ns = _deduplicate_records(records_ns)

    total_records = len(records_a) + len(records_aaaa) + len(records_cname) + len(records_mx) + len(records_ns)

    # Classify overall status
    if total_records > 0:
        overall_status = "DNS_SUCCESS"
    elif "NXDOMAIN" in encountered_exceptions:
        overall_status = "DNS_NXDOMAIN"
    elif "TIMEOUT" in encountered_exceptions:
        overall_status = "DNS_TIMEOUT"
    elif "SERVFAIL" in encountered_exceptions:
        overall_status = "DNS_SERVFAIL"
    elif "NO_ANSWER" in encountered_exceptions:
        overall_status = "DNS_NO_RECORD"
    else:
        overall_status = "DNS_NO_RECORD" if encountered_exceptions else "DNS_ERROR"

    # Reverse DNS lookups for resolved IPs
    resolved_ips_list: List[Dict[str, Any]] = []
    reverse_dns_list: List[Dict[str, Any]] = []

    for ip_val, ip_meta in resolved_ips_map.items():
        ptr_val = resolve_reverse_dns(ip_val)
        ip_meta["reverse_dns"] = ptr_val
        resolved_ips_list.append(ip_meta)
        reverse_dns_list.append({"ip": ip_val, "ptr": ptr_val or "No PTR record"})

    result = {
        "domain": clean_domain,
        "dns_status": overall_status,
        "dns_intelligence": {
            "a": records_a,
            "aaaa": records_aaaa,
            "cname": records_cname,
            "mx": records_mx,
            "ns": records_ns
        },
        "resolved_ips": resolved_ips_list,
        "reverse_dns": reverse_dns_list,
        "lookup_timestamp": _get_utc_timestamp()
    }

    if use_cache:
        _DNS_CACHE[clean_domain] = (now, result)

    return result


def _deduplicate_records(records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen: set = set()
    deduped: List[Dict[str, Any]] = []
    for r in records:
        key = (r.get("record_type"), r.get("value"))
        if key not in seen:
            seen.add(key)
            deduped.append(r)
    return deduped


def _build_dns_error_response(domain: str, status: str, error_message: str) -> Dict[str, Any]:
    return {
        "domain": domain,
        "dns_status": status,
        "dns_intelligence": {
            "a": [],
            "aaaa": [],
            "cname": [],
            "mx": []
        },
        "resolved_ips": [],
        "reverse_dns": [],
        "error_message": error_message,
        "lookup_timestamp": _get_utc_timestamp()
    }
