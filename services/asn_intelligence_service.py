"""
services/asn_intelligence_service.py

TASK 3C — ASN + Hosting Provider Intelligence Service

Given a resolved IPv4/IPv6 address, resolves its BGP Autonomous System Number (ASN),
ASN Organization name, Network Organization, CIDR route prefix, country, registry source,
and verified network abuse contact.

Terminology Rules:
- Network Organization: BGP Autonomous System name / ASN registrant (e.g. "Cloudflare, Inc.", "Amazon.com, Inc.")
- ASN Owner: Entity managing the Autonomous System number
- Infrastructure Provider: Network infrastructure operator
- Hosting Provider: Marked as INFERRED or VERIFIED (never automatically claims ASN owner = website operator)

Evidence Level Taxonomy:
- VERIFIED: Authoritative RDAP / WHOIS record confirmed
- INFERRED: Derived from ASN network organization / BGP route
- UNAVAILABLE: Private / local / unresolvable IP address
"""

import logging
import urllib.request
import urllib.error
import json
import ipaddress
from datetime import datetime, timezone
from typing import Dict, Any, Optional, Tuple

logger = logging.getLogger(__name__)

_ASN_CACHE: Dict[str, Tuple[float, Dict[str, Any]]] = {}
_CACHE_TTL_SECONDS = 600  # 10 minutes cache for ASN lookups


def clear_asn_cache() -> None:
    """Clears the in-memory ASN lookup cache."""
    _ASN_CACHE.clear()


def get_asn_cache_size() -> int:
    """Returns number of cached ASN entries."""
    return len(_ASN_CACHE)


def _get_utc_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()


def lookup_ip_asn(ip_address: str, use_cache: bool = True) -> Dict[str, Any]:
    """
    Performs ASN and network organization lookup for a resolved IPv4 or IPv6 address.
    Returns normalized infrastructure evidence object.
    """
    if not ip_address or not isinstance(ip_address, str):
        return _build_asn_error_response(str(ip_address), "IP_INVALID", "Invalid or empty IP address input")

    clean_ip = ip_address.strip()

    # Validate IP address and detect private / local ranges
    try:
        ip_obj = ipaddress.ip_address(clean_ip)
        address_family = "IPv6" if ip_obj.version == 6 else "IPv4"

        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_multicast or ip_obj.is_reserved:
            return {
                "ip": clean_ip,
                "address_family": address_family,
                "status": "ASN_UNAVAILABLE",
                "asn": None,
                "asn_organization": "Private / Reserved Network Range",
                "network_organization": "Private Network",
                "infrastructure_provider": "Internal / Private Infrastructure",
                "network_route": None,
                "country": "LOCAL",
                "registry": "RESERVED",
                "abuse_contact": None,
                "provider_evidence_level": "UNAVAILABLE",
                "lookup_timestamp": _get_utc_timestamp()
            }
    except ValueError:
        return _build_asn_error_response(clean_ip, "IP_INVALID", f"Invalid IP address syntax: '{clean_ip}'")

    # Check cache
    now = datetime.now(timezone.utc).timestamp()
    if use_cache and clean_ip in _ASN_CACHE:
        cached_time, cached_data = _ASN_CACHE[clean_ip]
        if now - cached_time < _CACHE_TTL_SECONDS:
            return cached_data

    # Query RDAP IP endpoint
    result = _fetch_asn_from_rdap(clean_ip, address_family)

    if use_cache and result.get("status") in ["ASN_SUCCESS", "ASN_UNAVAILABLE"]:
        _ASN_CACHE[clean_ip] = (now, result)

    return result


def _fetch_asn_from_rdap(ip: str, address_family: str) -> Dict[str, Any]:
    url = f"https://rdap.org/ip/{ip}"
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "KEIKAI-Brand-Protection/1.0", "Accept": "application/rdap+json, application/json"}
    )

    try:
        with urllib.request.urlopen(req, timeout=4.0) as resp:
            if resp.status == 200:
                raw_bytes = resp.read()
                data = json.loads(raw_bytes.decode("utf-8"))
                return _parse_ip_rdap_payload(ip, address_family, data)

    except urllib.error.HTTPError as e:
        logger.warning(f"RDAP IP HTTP {e.code} for {ip}")
    except (urllib.error.URLError, TimeoutError, Exception) as err:
        logger.warning(f"RDAP IP fetch failed for {ip}: {err}")

    # Fallback to ip-api / static response
    return _fetch_asn_from_fallback_api(ip, address_family)


def _parse_ip_rdap_payload(ip: str, address_family: str, data: Dict[str, Any]) -> Dict[str, Any]:
    net_name = data.get("name") or data.get("handle") or "Unknown Network"
    asn_str = None
    asn_org = net_name
    country = data.get("country", "Unknown")
    registry = (data.get("port43") or "ARIN").split(".")[-1].upper()
    abuse_contact = None
    cidr_route = None

    # Parse CIDR route prefix
    cidr_list = data.get("cidr0_cidrs", [])
    if cidr_list and isinstance(cidr_list, list):
        v = cidr_list[0]
        if isinstance(v, dict):
            cidr_route = f"{v.get('v4prefix' if address_family == 'IPv4' else 'v6prefix')}/{v.get('length')}"

    # Extract ASN and Entities
    entities = data.get("entities", [])
    for entity in entities:
        roles = entity.get("roles", [])
        handle = entity.get("handle", "")
        vcard = entity.get("vcardArray", [])

        if "registrant" in roles or "technical" in roles or "administrative" in roles:
            if len(vcard) > 1:
                for entry in vcard[1]:
                    if entry[0] == "fn":
                        asn_org = entry[3]

        if "abuse" in roles:
            if len(vcard) > 1:
                for entry in vcard[1]:
                    if entry[0] == "email":
                        abuse_contact = entry[3]

        if handle.startswith("AS") and handle[2:].isdigit():
            asn_str = handle

    # Fallback search for ASN string in raw payload
    if not asn_str and "autnum" in data:
        asn_str = f"AS{data['autnum']}"

    clean_asn = asn_str or "AS-UNKNOWN"
    clean_org = asn_org or net_name

    evidence_level = "VERIFIED" if abuse_contact or asn_str else "INFERRED"

    return {
        "ip": ip,
        "address_family": address_family,
        "status": "ASN_SUCCESS",
        "asn": clean_asn,
        "asn_organization": clean_org,
        "network_organization": _clean_network_org(clean_org),
        "infrastructure_provider": _clean_network_org(clean_org),
        "network_route": cidr_route,
        "country": country,
        "registry": registry,
        "abuse_contact": abuse_contact,
        "provider_evidence_level": evidence_level,
        "lookup_timestamp": _get_utc_timestamp()
    }


def _fetch_asn_from_fallback_api(ip: str, address_family: str) -> Dict[str, Any]:
    url = f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,org,as,query"
    req = urllib.request.Request(url, headers={"User-Agent": "KEIKAI-Brand-Protection/1.0"})

    try:
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            if resp.status == 200:
                data = json.loads(resp.read().decode("utf-8"))
                if data.get("status") == "success":
                    as_raw = data.get("as", "")
                    asn_parts = as_raw.split(" ", 1)
                    asn_code = asn_parts[0] if asn_parts[0].startswith("AS") else f"AS{asn_parts[0]}"
                    asn_name = asn_parts[1] if len(asn_parts) > 1 else data.get("org", "Unknown Network")
                    org_name = data.get("org") or asn_name

                    return {
                        "ip": ip,
                        "address_family": address_family,
                        "status": "ASN_SUCCESS",
                        "asn": asn_code,
                        "asn_organization": org_name,
                        "network_organization": _clean_network_org(org_name),
                        "infrastructure_provider": _clean_network_org(org_name),
                        "network_route": None,
                        "country": data.get("countryCode", "Unknown"),
                        "registry": "INFERRED",
                        "abuse_contact": None,
                        "provider_evidence_level": "INFERRED",
                        "lookup_timestamp": _get_utc_timestamp()
                    }
    except Exception:
        pass

    return _build_asn_error_response(ip, "ASN_UNAVAILABLE", "ASN resolution failed for IP")


def _clean_network_org(raw_org: str) -> str:
    if not raw_org:
        return "Unknown Network"
    clean = raw_org.strip()
    for suffix in [" LLC", " Inc.", " Inc", " CORP", " Corporation", " Ltd.", " Ltd", " S.A.", " Co., Ltd."]:
        if clean.endswith(suffix):
            clean = clean[:-len(suffix)].strip()
    return clean


def _build_asn_error_response(ip: str, status: str, error_message: str) -> Dict[str, Any]:
    return {
        "ip": ip,
        "address_family": "IPv4" if ":" not in ip else "IPv6",
        "status": status,
        "asn": "AS-UNKNOWN",
        "asn_organization": "Unknown Network Organization",
        "network_organization": "Unknown Provider",
        "infrastructure_provider": "Unknown Infrastructure",
        "network_route": None,
        "country": "UNKNOWN",
        "registry": "UNKNOWN",
        "abuse_contact": None,
        "provider_evidence_level": "UNAVAILABLE",
        "error_message": error_message,
        "lookup_timestamp": _get_utc_timestamp()
    }
