"""
services/confidence_engine_service.py

KEIKAI EVIDENCE INTELLIGENCE V2 — CONFIDENCE & RISK SCORING ENGINE

Key Design Rules:
1. RISK SCORE (0-100) measures likelihood of brand impersonation.
2. EVIDENCE QUALITY SCORE (0-100) measures completeness of gathered evidence.
3. CRITICAL RULE: Missing or unavailable data contributes ZERO evidence points to risk score.
   Unavailable sources NEVER act as negative evidence or penalize candidate risk!
4. Classifies Risk into transparent categories: CRITICAL, HIGH, MEDIUM, LOW, INSUFFICIENT_EVIDENCE.
5. Classifies Investigation Quality into: COMPLETE, PARTIAL, DEGRADED.
"""

import logging
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)


class EvidenceConfidenceEngine:

    @classmethod
    def calculate_scores(
        cls,
        domain_relationship: Dict[str, Any],
        http_verification: Dict[str, Any],
        logo_evidence: Dict[str, Any],
        threat_intel: Dict[str, Any],
        infrastructure: Dict[str, Any],
        credential_indicators: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Calculates independent Risk Score, Evidence Quality Score, and Investigation Quality.
        """
        # Rule 1: Official Domain Safeguard
        if domain_relationship.get("is_official"):
            return {
                "risk_score": 0,
                "risk_category": "OFFICIAL_EXACT" if domain_relationship.get("relationship") == "OFFICIAL_EXACT" else "OFFICIAL_SUBDOMAIN",
                "risk_verdict": "OFFICIAL_BRAND_DOMAIN",
                "explainable_risk_breakdown": [
                    {"signal": "Official Brand Domain Match", "points": 0, "reason": domain_relationship.get("reason", "Exact official brand domain")}
                ],
                "evidence_quality_score": 100,
                "investigation_quality": "COMPLETE",
                "degraded_reasons": [],
                "observed_at": datetime.now(timezone.utc).isoformat()
            }

        risk_breakdown = []
        risk_points = 0

        # Signal 1: Domain Permutation / Lookalike
        rel_type = domain_relationship.get("relationship", "UNKNOWN")
        if rel_type == "LOOKALIKE":
            pts = 20
            risk_points += pts
            risk_breakdown.append({
                "signal": "Domain Permutation / Lookalike",
                "points": pts,
                "reason": domain_relationship.get("reason", "Typosquat lookalike match")
            })

        # Signal 2: Visual Logo Recognition
        if logo_evidence.get("overall_status") == "CONFIRMED":
            confirmed_cnt = logo_evidence.get("confirmed_layers_count", 1)
            pts = 35 if confirmed_cnt >= 2 else 25
            risk_points += pts
            risk_breakdown.append({
                "signal": "Visual Logo Impersonation",
                "points": pts,
                "reason": f"Confirmed visual impersonation across {confirmed_cnt} fallback layers."
            })

        # Signal 3: Threat Intelligence Feeds (OpenPhish / PhishTank)
        openphish_status = threat_intel.get("openphish", {}).get("status")
        phishtank_status = threat_intel.get("phishtank", {}).get("status")

        if openphish_status == "MATCH":
            pts = 25
            risk_points += pts
            risk_breakdown.append({
                "signal": "OpenPhish Active Threat Feed Confirmation",
                "points": pts,
                "reason": "Candidate domain confirmed present in active OpenPhish feed."
            })

        if phishtank_status == "MATCH":
            pts = 25
            risk_points += pts
            risk_breakdown.append({
                "signal": "PhishTank Validated Database Confirmation",
                "points": pts,
                "reason": "Candidate domain verified present in PhishTank database."
            })

        # Signal 4: Credential Harvesting Form Indicators
        if credential_indicators.get("has_login_form"):
            pts = 15
            risk_points += pts
            risk_breakdown.append({
                "signal": "Credential Harvesting Login Form",
                "points": pts,
                "reason": "HTML analysis identified login authentication form."
            })

        if credential_indicators.get("has_password_field"):
            pts = 10
            risk_points += pts
            risk_breakdown.append({
                "signal": "Password Input Field Detected",
                "points": pts,
                "reason": "Sensitive password input field found on page."
            })

        # Cap Risk Score at 100
        final_risk_score = min(100, risk_points)

        # Categorize Risk
        if final_risk_score >= 85:
            risk_category = "CRITICAL"
            risk_verdict = "CONFIRMED_BRAND_IMPERSONATION"
        elif final_risk_score >= 65:
            risk_category = "HIGH"
            risk_verdict = "LIKELY_BRAND_IMPERSONATION"
        elif final_risk_score >= 40:
            risk_category = "MEDIUM"
            risk_verdict = "SUSPECTED_BRAND_IMPERSONATION"
        elif final_risk_score >= 15:
            risk_category = "LOW"
            risk_verdict = "POTENTIAL_LOOKALIKE"
        else:
            risk_category = "INSUFFICIENT_EVIDENCE"
            risk_verdict = "INSUFFICIENT_EVIDENCE"

        # Calculate Evidence Quality Score (0-100) & Investigation Quality
        quality_points = 0
        quality_breakdown = []
        degraded_reasons = []

        # Quality Factor 1: HTTP Verification
        if http_verification.get("status") == "SUCCESS":
            quality_points += 25
            quality_breakdown.append("+ DNS & HTTP resolution verified (25 pts)")
        else:
            degraded_reasons.append(f"HTTP verification incomplete: {http_verification.get('detail', 'Connection failed')}")

        # Quality Factor 2: Visual Screenshot Acquisition
        if logo_evidence.get("overall_status") != "UNAVAILABLE" and logo_evidence.get("overall_status") != "NOT_RUN":
            quality_points += 25
            quality_breakdown.append("+ Screenshot & visual layers acquired (25 pts)")
        else:
            degraded_reasons.append("Screenshot acquisition unavailable or failed")

        # Quality Factor 3: Threat Intelligence Checks
        if openphish_status in ("MATCH", "NO_MATCH") and phishtank_status in ("MATCH", "NO_MATCH"):
            quality_points += 25
            quality_breakdown.append("+ Threat intelligence feeds queried (25 pts)")
        else:
            degraded_reasons.append("Threat intelligence feeds partially rate-limited or unavailable")

        # Quality Factor 4: Registration / RDAP Enrichment
        if infrastructure.get("rdap_status") == "CONFIRMED":
            quality_points += 25
            quality_breakdown.append("+ RDAP & infrastructure verified (25 pts)")
        else:
            degraded_reasons.append(f"RDAP lookup incomplete: {infrastructure.get('rdap_reason', 'RDAP network timeout')}")

        evidence_quality_score = min(100, quality_points)

        if evidence_quality_score >= 80:
            investigation_quality = "COMPLETE"
        elif evidence_quality_score >= 45:
            investigation_quality = "PARTIAL"
        else:
            investigation_quality = "DEGRADED"

        return {
            "risk_score": final_risk_score,
            "risk_category": risk_category,
            "risk_verdict": risk_verdict,
            "explainable_risk_breakdown": risk_breakdown,
            "evidence_quality_score": evidence_quality_score,
            "investigation_quality": investigation_quality,
            "quality_breakdown": quality_breakdown,
            "degraded_reasons": degraded_reasons,
            "observed_at": datetime.now(timezone.utc).isoformat()
        }
