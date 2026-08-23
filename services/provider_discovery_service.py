"""
services/provider_discovery_service.py

TASK 6 — Phase 2 & Phase 3: Provider Discovery & WHOIS Fallback Service

Resolves domain registration and network infrastructure providers:
- Queries RDAP first for authoritative registrar name, IANA ID, abuse contact email/phone, nameservers.
- Performs WHOIS fallback when RDAP lacks abuse contact details (.com, .net, .org, ccTLDs).
- Resolves hosting/CDN network provider from BGP ASN / IP RDAP.
- Assigns contact state (VERIFIED, PARTIAL, UNAVAILABLE) and routing confidence (HIGH, MEDIUM, LOW).
- Never fabricates contact details or trusts frontend-supplied arbitrary emails.
"""

import logging
import time
from typing import Dict, Any, List, Optional, Tuple
from services.registration_intelligence_service import get_registration_intelligence, clean_domain_name
from services.dns_intelligence_service import resolve_dns_records
from services.asn_intelligence_service import lookup_ip_asn

logger = logging.getLogger(__name__)

_DISCOVERY_CACHE: Dict[str, Tuple[float, Dict[str, Any]]] = {}
_CACHE_TTL_SECONDS = 300  # 5 minutes cache


def clear_provider_discovery_cache() -> None:
    """Clears in-memory provider discovery cache."""
    _DISCOVERY_CACHE.clear()


def discover_provider_contacts(domain: str, use_cache: bool = True) -> Dict[str, Any]:
    """
    Performs RDAP-first + WHOIS fallback provider discovery.
    Resolves registrar abuse contact and network hosting provider.
    """
    if not domain or not isinstance(domain, str):
        return _build_unavailable_discovery(str(domain), "INVALID_DOMAIN")

    clean_dom = clean_domain_name(domain)
    if not clean_dom or "." not in clean_dom:
        return _build_unavailable_discovery(str(domain), "INVALID_DOMAIN")

    now = time.time()
    if use_cache and clean_dom in _DISCOVERY_CACHE:
        cached_time, cached_data = _DISCOVERY_CACHE[clean_dom]
        if now - cached_time < _CACHE_TTL_SECONDS:
            return cached_data

    # 1. Fetch RDAP + WHOIS registration intelligence
    reg_intel = get_registration_intelligence(clean_dom, use_cache=use_cache)

    registrar_info = reg_intel.get("registrar") or {}
    registrar_name = registrar_info.get("name") or "Unknown Registrar"
    iana_id = registrar_info.get("iana_id")

    abuse_contact = reg_intel.get("abuse_contact") or {}
    emails = abuse_contact.get("emails") or []
    phones = abuse_contact.get("phones") or []
    contact_state = abuse_contact.get("state", "UNAVAILABLE")

    # Clean abuse email list (remove invalid/untrusted entries)
    valid_emails = [e.strip() for e in emails if e and "@" in str(e) and str(e).lower() not in ["not disclosed", "unavailable", "none"]]
    verified_email = valid_emails[0] if valid_emails else None

    reg_source = reg_intel.get("source", "RDAP")
    nameservers = reg_intel.get("nameservers", [])

    # 2. Fetch DNS + IP + ASN infrastructure intelligence
    dns_intel = resolve_dns_records(clean_dom, use_cache=use_cache)
    resolved_ips = dns_intel.get("resolved_ips", [])
    network_provider_name = "Unknown Network Operator"
    network_asn = "AS-UNKNOWN"
    network_abuse_email = None

    if resolved_ips:
        top_ip = resolved_ips[0].get("ip")
        if top_ip:
            asn_data = lookup_ip_asn(top_ip, use_cache=use_cache)
            network_provider_name = asn_data.get("asn_organization") or asn_data.get("network_organization") or "Unknown Network"
            network_asn = asn_data.get("asn") or "AS-UNKNOWN"
            net_email = asn_data.get("abuse_contact")
            if net_email and "@" in str(net_email) and str(net_email).lower() not in ["not disclosed", "unavailable", "none"]:
                network_abuse_email = net_email

    # Check Cloudflare CDN / Proxy detection
    is_cloudflare = False
    if "cloudflare" in network_provider_name.lower() or network_asn == "AS13335":
        is_cloudflare = True
    for ns in nameservers:
        if "cloudflare.com" in ns.lower():
            is_cloudflare = True
            break

    # Determine confidence level
    if is_cloudflare:
        confidence = "HIGH"
        primary_provider = "Cloudflare"
        primary_method = "API"
        primary_source = "PROVIDER_INTEL"
        routing_reason = "Cloudflare CDN/DNS proxy detected. High-confidence Direct API route available."
    elif verified_email:
        confidence = "HIGH" if reg_source == "RDAP" else "MEDIUM"
        primary_provider = registrar_name
        primary_method = "EMAIL"
        primary_source = reg_source
        routing_reason = f"Registrar '{registrar_name}' abuse email verified through {reg_source}."
    else:
        confidence = "LOW"
        primary_provider = registrar_name
        primary_method = "BROWSER" if registrar_name != "Unknown Registrar" else "MANUAL"
        primary_source = reg_source
        routing_reason = "No verified abuse email available. Web form or manual escalation required."

    result = {
        "domain": clean_dom,
        "is_cloudflare": is_cloudflare,
        "primary_provider": primary_provider,
        "primary_method": primary_method,
        "confidence": confidence,
        "routing_reason": routing_reason,
        "registrar": {
            "name": registrar_name,
            "iana_id": iana_id,
            "abuse_email": verified_email,
            "abuse_phone": phones[0] if phones else None,
            "source": reg_source,
            "contact_state": contact_state if verified_email else "UNAVAILABLE"
        },
        "network": {
            "provider_name": network_provider_name,
            "asn": network_asn,
            "abuse_email": network_abuse_email,
            "is_cdn": is_cloudflare
        },
        "nameservers": nameservers,
        "source": primary_source,
        "queried_at": reg_intel.get("queried_at")
    }

    if use_cache:
        _DISCOVERY_CACHE[clean_dom] = (now, result)

    return result


def _build_unavailable_discovery(domain: str, reason: str) -> Dict[str, Any]:
    return {
        "domain": domain,
        "is_cloudflare": False,
        "primary_provider": "Unknown Provider",
        "primary_method": "MANUAL",
        "confidence": "LOW",
        "routing_reason": f"Provider discovery unavailable ({reason}). Manual escalation required.",
        "registrar": {
            "name": "Unknown Registrar",
            "iana_id": None,
            "abuse_email": None,
            "abuse_phone": None,
            "source": "NONE",
            "contact_state": "UNAVAILABLE"
        },
        "network": {
            "provider_name": "Unknown Network",
            "asn": "AS-UNKNOWN",
            "abuse_email": None,
            "is_cdn": False
        },
        "nameservers": [],
        "source": "NONE",
        "queried_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    }
