"""
services/demo_scenario_service.py

TASK 7 — Phase 9 & Phase 13: Deterministic Demo Scenario & Case Intelligence Graph

Executes a sponsor-ready, end-to-end demonstration of KEIKAI's autonomous brand protection workflow:
Discovery → Logo Match → Threat Intel → Infrastructure → Risk Scoring → Case Creation → viaSocket Event → Human Approval → Snapshot Freeze → Takedown Dispatch → Final Report.

Does NOT send real external abuse reports (operates in safe DRY_RUN mode).
"""

import json
import os
import time
from datetime import datetime, timezone
from typing import Dict, Any

from database import abuse_execute, abuse_one, init_db
from services.abuse_control_service import approve, status as get_case_status
from services.provider_discovery_service import discover_provider_contacts
from services.universal_abuse_router import submit_universal_takedown
from services.viasocket_adapter import emit_viasocket_event


def run_demo_scenario(target_brand: str = "Amazon", candidate_domain: str = "amaz0n-security-login.xyz") -> Dict[str, Any]:
    """
    Executes a deterministic end-to-end demo scenario.
    Returns complete explainable case summary, timeline, and risk score breakdown.
    """
    init_db()
    case_id = f"case_demo_{target_brand.lower()}_001"

    # Step 1: Start Investigation
    emit_viasocket_event("INVESTIGATION_STARTED", case_id, {
        "target_brand": target_brand,
        "official_domain": f"{target_brand.lower()}.com",
        "candidate_domain": candidate_domain
    })

    # Step 2: Candidate Discovery & Logo Intelligence
    logo_match = {
        "detected_logo": target_brand,
        "confidence": 0.96,
        "bounding_box": [120, 45, 340, 110],
        "visual_similarity": 94.5
    }
    emit_viasocket_event("LOGO_MATCH_DETECTED", case_id, logo_match)

    # Step 3: Threat Intelligence & Multi-Signal Correlation
    threat_signals = {
        "sources": ["dnstwist", "openphish"],
        "domain_permutation": True,
        "credential_indicators": True,
        "screenshot": {"status": "SUCCESS", "source": "candidate_acquisition"}
    }

    # Step 4: Calculate Transparent Risk Score (94/100)
    risk_breakdown = [
        {"signal": "Domain Permutation (dnstwist)", "points": 15, "reason": "Homoglyph/typosquat lookalike match detected"},
        {"signal": "Phishpedia Visual Logo Recognition", "points": 35, "reason": f"Target brand '{target_brand}' logo recognized with 96% confidence"},
        {"signal": "Credential Harvesting Form", "points": 25, "reason": "Password/login input fields identified on target site"},
        {"signal": "OpenPhish Active Feed Confirmation", "points": 19, "reason": "Domain confirmed present in active threat intelligence feed"}
    ]
    risk_score = sum(item["points"] for item in risk_breakdown)

    emit_viasocket_event("IMPERSONATION_CONFIRMED", case_id, {
        "risk_score": risk_score,
        "level": "HIGH_CONFIDENCE_IMPERSONATION",
        "breakdown": risk_breakdown
    })

    # Step 5: Provider & Infrastructure Discovery
    try:
        discovery = discover_provider_contacts(candidate_domain, use_cache=True)
        if discovery.get("primary_method") == "MANUAL" or discovery.get("confidence") == "LOW":
            discovery = {
                "domain": candidate_domain,
                "is_cloudflare": True,
                "primary_provider": "Cloudflare",
                "primary_method": "API",
                "confidence": "HIGH",
                "routing_reason": "Cloudflare CDN/DNS proxy detected. Direct API route available.",
                "registrar": {"name": "Cloudflare Registrar", "iana_id": "1910", "abuse_email": "abuse@cloudflare.com", "contact_state": "VERIFIED"},
                "network": {"provider_name": "CLOUDFLARENET", "asn": "AS13335", "abuse_email": "abuse@cloudflare.com", "is_cdn": True},
                "source": "PROVIDER_INTEL"
            }
    except Exception:
        discovery = {
            "domain": candidate_domain,
            "is_cloudflare": True,
            "primary_provider": "Cloudflare",
            "primary_method": "API",
            "confidence": "HIGH",
            "routing_reason": "Cloudflare CDN/DNS proxy detected. Direct API route available.",
            "registrar": {"name": "Cloudflare Registrar", "iana_id": "1910", "abuse_email": "abuse@cloudflare.com", "contact_state": "VERIFIED"},
            "network": {"provider_name": "CLOUDFLARENET", "asn": "AS13335", "abuse_email": "abuse@cloudflare.com", "is_cdn": True},
            "source": "PROVIDER_INTEL"
        }
    emit_viasocket_event("TAKEDOWN_ROUTE_RESOLVED", case_id, discovery)

    # Step 6: Create Persistent Approval & Frozen Snapshot
    approval_payload = {
        "candidate_domain": candidate_domain,
        "target_brand": target_brand,
        "official_domain": f"{target_brand.lower()}.com",
        "evidence": {
            "sources": ["dnstwist", "openphish"],
            "domain_permutation": True,
            "strong_visual_match": True,
            "credential_indicators": True,
            "screenshot": {"status": "SUCCESS", "source": "candidate_acquisition"}
        },
        "approved_by": "Analyst Demo User"
    }

    appr_res = approve(case_id, approval_payload)
    approval_id = appr_res["approval_id"]
    snapshot_id = appr_res["snapshot_id"]

    emit_viasocket_event("APPROVAL_GRANTED", case_id, {
        "approval_id": approval_id,
        "snapshot_id": snapshot_id,
        "approved_by": "Analyst Demo User"
    })

    # Step 7: Universal Takedown Execution in DRY_RUN Mode
    os.environ['ABUSE_SUBMISSION_MODE'] = 'DRY_RUN'
    takedown_res = submit_universal_takedown(case_id, approval_id)

    emit_viasocket_event("TAKEDOWN_SUBMITTED", case_id, {
        "submission_id": takedown_res.get("submission_id"),
        "provider": takedown_res.get("provider"),
        "method": takedown_res.get("method"),
        "state": takedown_res.get("state")
    })

    # Step 8: Build Case Intelligence Graph
    case_graph = {
        "nodes": [
            {"id": "brand", "label": f"Target Brand: {target_brand}", "type": "BRAND"},
            {"id": "fake_domain", "label": f"Fake Domain: {candidate_domain}", "type": "DOMAIN"},
            {"id": "ip", "label": "IP: 104.21.48.91", "type": "IP"},
            {"id": "asn", "label": "ASN: AS13335 (Cloudflare)", "type": "ASN"},
            {"id": "nameserver", "label": "NS: ns1.cloudflare.com", "type": "NAMESERVER"},
            {"id": "registrar", "label": f"Registrar: {discovery['registrar']['name']}", "type": "REGISTRAR"},
            {"id": "provider", "label": f"Provider: {discovery['primary_provider']}", "type": "PROVIDER"},
            {"id": "route", "label": f"Route: {discovery['primary_method']}", "type": "TAKEDOWN_ROUTE"}
        ],
        "edges": [
            {"source": "brand", "target": "fake_domain", "relation": "IMPERSONATED_BY"},
            {"source": "fake_domain", "target": "ip", "relation": "RESOLVES_TO"},
            {"source": "ip", "target": "asn", "relation": "HOSTED_ON"},
            {"source": "fake_domain", "target": "nameserver", "relation": "DELEGATED_TO"},
            {"source": "fake_domain", "target": "registrar", "relation": "REGISTERED_WITH"},
            {"source": "registrar", "target": "provider", "relation": "ROUTED_TO"},
            {"source": "provider", "target": "route", "relation": "DISPATCHED_VIA"}
        ]
    }

    # Step 9: Compile Automated Case Report
    case_report = {
        "case_id": case_id,
        "executive_summary": (
            f"High-confidence brand impersonation targeting '{target_brand}' was detected on candidate domain "
            f"'{candidate_domain}'. Multi-signal analysis confirmed logo recognition (96%), credential harvesting forms, "
            f"and OpenPhish threat intelligence feeds. A persistent frozen snapshot was created, human approval granted, "
            f"and a DRY_RUN takedown report dispatched via {discovery['primary_provider']} ({discovery['primary_method']})."
        ),
        "target_brand": target_brand,
        "official_domain": f"{target_brand.lower()}.com",
        "suspected_domain": candidate_domain,
        "risk_score": risk_score,
        "risk_level": "CRITICAL_IMPERSONATION",
        "risk_breakdown": risk_breakdown,
        "logo_evidence": logo_match,
        "provider_intelligence": discovery,
        "approval": appr_res,
        "takedown_submission": takedown_res,
        "case_graph": case_graph,
        "timeline_summary": [
            {"step": "Detection", "status": "COMPLETED", "timestamp": _now_iso()},
            {"step": "Evidence Collection", "status": "COMPLETED", "timestamp": _now_iso()},
            {"step": "Risk Scoring (94/100)", "status": "COMPLETED", "timestamp": _now_iso()},
            {"step": "viaSocket Notification Emitted", "status": "COMPLETED", "timestamp": _now_iso()},
            {"step": "Human Approval & Snapshot Freeze", "status": "COMPLETED", "timestamp": _now_iso()},
            {"step": "DRY_RUN Takedown Dispatched", "status": "COMPLETED", "timestamp": _now_iso()}
        ]
    }

    return case_report


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
