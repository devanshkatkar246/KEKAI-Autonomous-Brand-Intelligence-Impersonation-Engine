"""
services/abuse_target_service.py

TASK 3D — Unified Abuse Target Resolution Engine

Determines WHO SHOULD RECEIVE THE ABUSE REPORT for a suspicious candidate domain.
Combines RDAP Domain Intelligence, DNS + IP Intelligence, and ASN + Network Intelligence.

IMPORTANT:
This service does NOT send reports or automate takedowns.
It resolves, verifies, and explains reporting targets, legitimacy gates, and readiness for human review.

Target Selection Rules:
- Registered Domain -> Registrar is primary candidate (type: REGISTRAR, source: RDAP).
- Hosting / Network Operator -> Secondary escalation target (type: NETWORK, source: IP_RDAP).
- Does NOT claim registrar = hosting provider or ASN org = website operator.

Legitimacy Gate Rules:
- Evaluates domain against official_domain and authorized_domains.
- States: AUTHORIZED_DOMAIN, OFFICIAL_DOMAIN, UNKNOWN_DOMAIN, SUSPICIOUS_UNAUTHORIZED_DOMAIN.
- If OFFICIAL_DOMAIN or AUTHORIZED_DOMAIN -> reporting_eligibility = BLOCKED.

Abuse Readiness Status:
- READY_FOR_HUMAN_REVIEW returned ONLY when:
  suspicious candidate + reporting target identified + abuse contact available + sufficient evidence exists.
- Otherwise NOT_READY with explicit reason code.
"""

import logging
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple

logger = logging.getLogger(__name__)

_ABUSE_TARGET_CACHE: Dict[str, Tuple[float, Dict[str, Any]]] = {}
_CACHE_TTL_SECONDS = 300  # 5 minutes cache for target resolution


def clear_abuse_target_cache() -> None:
    """Clears in-memory abuse target resolution cache."""
    _ABUSE_TARGET_CACHE.clear()


def get_abuse_target_cache_size() -> int:
    """Returns size of cached target resolutions."""
    return len(_ABUSE_TARGET_CACHE)


def _get_utc_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()


def resolve_abuse_targets(
    domain: str,
    official_domain: Optional[str] = None,
    authorized_domains: Optional[List[str]] = None,
    evidence_score: float = 85.0,
    dns_data: Optional[Dict[str, Any]] = None,
    rdap_data: Optional[Dict[str, Any]] = None,
    use_cache: bool = True
) -> Dict[str, Any]:
    """
    Unified Abuse Target Resolution function.
    Given a domain, resolves primary & secondary targets, checks legitimacy gate,
    and calculates readiness for human review.
    """
    if not domain or not isinstance(domain, str):
        return _build_fallback_target_response(str(domain), "INVALID_INPUT", "Domain is invalid or missing")

    clean_domain = domain.strip().lower().replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
    clean_official = official_domain.strip().lower().replace("https://", "").replace("http://", "").split("/")[0].split(":")[0] if official_domain else None
    clean_authorized = [
        d.strip().lower().replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
        for d in (authorized_domains or [])
        if d
    ]

    cache_key = f"{clean_domain}:{clean_official}:{','.join(clean_authorized)}:{evidence_score}"
    now = datetime.now(timezone.utc).timestamp()
    if use_cache and cache_key in _ABUSE_TARGET_CACHE:
        cached_time, cached_data = _ABUSE_TARGET_CACHE[cache_key]
        if now - cached_time < _CACHE_TTL_SECONDS:
            return cached_data

    # 1. LEGITIMACY GATE EVALUATION
    legitimacy = _evaluate_legitimacy_gate(clean_domain, clean_official, clean_authorized)

    # 2. FETCH DEPENDENT INTELLIGENCE IF NOT PROVIDED
    if not dns_data or not rdap_data:
        from services.dns_intelligence_service import resolve_dns_records
        from services.rdap_service import fetch_rdap_data
        from services.asn_intelligence_service import lookup_ip_asn

        if not dns_data:
            dns_data = resolve_dns_records(clean_domain, use_cache=use_cache)
        if not rdap_data:
            rdap_data = fetch_rdap_data(clean_domain, use_cache=use_cache)

        # Enrich resolved IPs with ASN if needed
        raw_ips = dns_data.get("resolved_ips", [])
        if raw_ips and "asn" not in raw_ips[0]:
            enriched = []
            for ip_obj in raw_ips:
                asn_info = lookup_ip_asn(ip_obj.get("ip"), use_cache=use_cache)
                enriched.append({**ip_obj, **asn_info})
            dns_data["resolved_ips"] = enriched

    # 3. CONSTRUCT PRIMARY & SECONDARY ABUSE TARGETS
    primary_target = _build_primary_registrar_target(rdap_data)
    secondary_target = _build_secondary_network_target(dns_data)

    # 4. CALCULATE ABUSE REPORTING READINESS
    readiness = _calculate_reporting_readiness(
        legitimacy=legitimacy,
        primary_target=primary_target,
        secondary_target=secondary_target,
        evidence_score=evidence_score,
        rdap_data=rdap_data,
        dns_data=dns_data
    )

    result = {
        "domain": clean_domain,
        "legitimacy_gate": legitimacy,
        "abuse_targets": {
            "primary": primary_target,
            "secondary": secondary_target
        },
        "reporting_readiness": readiness,
        "resolved_at": _get_utc_timestamp()
    }

    if use_cache:
        _ABUSE_TARGET_CACHE[cache_key] = (now, result)

    return result


def _evaluate_legitimacy_gate(domain: str, official_domain: Optional[str], authorized_domains: List[str]) -> Dict[str, Any]:
    """
    Evaluates candidate domain against official and authorized domain lists.
    Prevents accidental reporting of official brand assets or authorized partners.
    """
    for auth_d in authorized_domains:
        if domain == auth_d or domain.endswith("." + auth_d):
            return {
                "status": "AUTHORIZED_DOMAIN",
                "reporting_eligibility": "BLOCKED",
                "reason": f"Candidate domain is on analyst authorized domain list ('{auth_d}'). Reporting is blocked.",
                "is_protected": True
            }

    if official_domain:
        if domain == official_domain or domain.endswith("." + official_domain):
            return {
                "status": "OFFICIAL_DOMAIN",
                "reporting_eligibility": "BLOCKED",
                "reason": "Candidate domain matches official brand domain. Reporting is blocked to protect brand assets.",
                "is_protected": True
            }

    return {
        "status": "SUSPICIOUS_UNAUTHORIZED_DOMAIN",
        "reporting_eligibility": "ELIGIBLE",
        "reason": "Candidate domain is unauthorized and matches brand impersonation criteria.",
        "is_protected": False
    }


def _build_primary_registrar_target(rdap_data: Dict[str, Any]) -> Dict[str, Any]:
    registrar_name = rdap_data.get("registrar") or "Unknown Registrar"
    abuse_email = rdap_data.get("abuse_email")
    if abuse_email in ["Not Disclosed", "Unavailable", "None", None] or "@" not in str(abuse_email):
        abuse_email = None

    confidence = "VERIFIED" if abuse_email and rdap_data.get("status") == "RDAP_SUCCESS" else "UNVERIFIED"

    return {
        "type": "REGISTRAR",
        "name": registrar_name,
        "email": abuse_email,
        "phone": None,
        "source": "RDAP",
        "confidence": confidence,
        "target_reason": "Registrar selected as primary reporting target because the candidate is a registered domain associated with suspected DNS abuse."
    }


def _build_secondary_network_target(dns_data: Dict[str, Any]) -> Dict[str, Any]:
    resolved_ips = dns_data.get("resolved_ips", [])
    if not resolved_ips:
        return {
            "type": "NETWORK",
            "name": "Unknown Network Operator",
            "email": None,
            "asn": "AS-UNKNOWN",
            "source": "IP_RDAP",
            "confidence": "UNAVAILABLE",
            "target_reason": "Network operator selected as secondary escalation target for hosting / BGP routing infrastructure."
        }

    top_ip = resolved_ips[0]
    asn_code = top_ip.get("asn") or "AS-UNKNOWN"
    net_org = top_ip.get("asn_organization") or top_ip.get("network_organization") or "Unknown Network"
    abuse_contact = top_ip.get("abuse_contact")
    if abuse_contact in ["Not Disclosed", "Unavailable", "None", None] or "@" not in str(abuse_contact):
        abuse_contact = None

    confidence = "VERIFIED" if abuse_contact else "INFERRED"

    return {
        "type": "NETWORK",
        "name": net_org,
        "email": abuse_contact,
        "asn": asn_code,
        "source": "IP_RDAP",
        "confidence": confidence,
        "target_reason": f"Network operator '{net_org}' ({asn_code}) selected as secondary escalation target for hosting / BGP routing infrastructure."
    }


def _calculate_reporting_readiness(
    legitimacy: Dict[str, Any],
    primary_target: Dict[str, Any],
    secondary_target: Dict[str, Any],
    evidence_score: float,
    rdap_data: Dict[str, Any],
    dns_data: Dict[str, Any]
) -> Dict[str, Any]:

    # If legitimacy gate blocked candidate
    if legitimacy.get("reporting_eligibility") == "BLOCKED":
        return {
            "status": "NOT_READY",
            "readiness_code": legitimacy.get("status"),
            "message": legitimacy.get("reason"),
            "evidence_score": evidence_score,
            "can_prepare_report": False
        }

    # If RDAP failed completely
    if rdap_data.get("status") == "RDAP_UNAVAILABLE":
        return {
            "status": "NOT_READY",
            "readiness_code": "RDAP_UNAVAILABLE",
            "message": "RDAP_UNAVAILABLE — Domain registration metadata could not be retrieved.",
            "evidence_score": evidence_score,
            "can_prepare_report": False
        }

    # If DNS failed completely
    if dns_data.get("dns_status") in ["DNS_ERROR", "DNS_NXDOMAIN"]:
        return {
            "status": "NOT_READY",
            "readiness_code": "DNS_FAILURE",
            "message": f"DNS_FAILURE — Domain DNS resolution failed with status '{dns_data.get('dns_status')}'.",
            "evidence_score": evidence_score,
            "can_prepare_report": False
        }

    # If primary registrar abuse email missing
    if not primary_target.get("email"):
        return {
            "status": "NOT_READY",
            "readiness_code": "NO_ABUSE_CONTACT",
            "message": "NO_ABUSE_CONTACT — Registrar abuse email contact is missing or unverified.",
            "evidence_score": evidence_score,
            "can_prepare_report": False
        }

    # If evidence score insufficient
    if evidence_score < 50.0:
        return {
            "status": "NOT_READY",
            "readiness_code": "INSUFFICIENT_EVIDENCE",
            "message": f"INSUFFICIENT_EVIDENCE — Impersonation evidence score ({evidence_score}%) is below required threshold (50%).",
            "evidence_score": evidence_score,
            "can_prepare_report": False
        }

    return {
        "status": "READY_FOR_HUMAN_REVIEW",
        "readiness_code": "READY_FOR_REVIEW",
        "message": "Target identified, abuse contact available, legitimacy check passed, and evidence threshold satisfied.",
        "evidence_score": evidence_score,
        "can_prepare_report": True
    }


def _build_fallback_target_response(domain: str, code: str, msg: str) -> Dict[str, Any]:
    return {
        "domain": domain,
        "legitimacy_gate": {
            "status": "UNKNOWN_DOMAIN",
            "reporting_eligibility": "BLOCKED",
            "reason": msg,
            "is_protected": False
        },
        "abuse_targets": {
            "primary": {
                "type": "REGISTRAR",
                "name": "Unknown Registrar",
                "email": None,
                "phone": None,
                "source": "RDAP",
                "confidence": "UNAVAILABLE",
                "target_reason": msg
            },
            "secondary": {
                "type": "NETWORK",
                "name": "Unknown Network",
                "email": None,
                "source": "IP_RDAP",
                "confidence": "UNAVAILABLE",
                "target_reason": msg
            }
        },
        "reporting_readiness": {
            "status": "NOT_READY",
            "readiness_code": code,
            "message": msg,
            "evidence_score": 0.0,
            "can_prepare_report": False
        },
        "resolved_at": _get_utc_timestamp()
    }
