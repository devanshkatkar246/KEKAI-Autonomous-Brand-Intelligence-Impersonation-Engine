"""
services/brand_identification_service.py

TASK 2D V4 — Logo-Based Brand Identification Service

Provides brand identification from uploaded logo features:
  - OCR text token alignment
  - Reference logo visual similarity matching
  - Known brand dictionary lookup

Returns explicit status:
  - BRAND_IDENTIFIED (high/medium confidence)
  - BRAND_CANDIDATES (multiple candidate brands)
  - BRAND_UNCERTAIN (inconclusive - prompts analyst for optional input without hallucination)
"""

import os
import sys
import logging
from typing import Dict, Any, List, Optional

logger = logging.getLogger("keikai.brand_identification")

# Verified brand dictionary from project configuration
KNOWN_BRAND_DATABASE = {
    "amazon": {"brand": "Amazon", "official_domain": "amazon.com", "aliases": ["aws", "amazonpay", "prime"]},
    "microsoft": {"brand": "Microsoft", "official_domain": "microsoft.com", "aliases": ["azure", "office365", "outlook"]},
    "apple": {"brand": "Apple", "official_domain": "apple.com", "aliases": ["icloud", "appstore", "iphone"]},
    "google": {"brand": "Google", "official_domain": "google.com", "aliases": ["gmail", "googlecloud", "workspace"]},
    "rolex": {"brand": "Rolex", "official_domain": "rolex.com", "aliases": ["oyster", "daytona", "submariner"]},
    "facebook": {"brand": "Facebook", "official_domain": "facebook.com", "aliases": ["meta", "instagram", "whatsapp"]},
    "netflix": {"brand": "Netflix", "official_domain": "netflix.com", "aliases": ["nflx"]},
    "paypal": {"brand": "PayPal", "official_domain": "paypal.com", "aliases": ["venmo", "pypl"]}
}


def identify_brand_from_logo(
    logo_profile: Dict[str, Any],
    phishpedia_result: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Attempts logo-based brand identification using OCR, reference database, and Phishpedia.

    Returns:
    {
        "status": "BRAND_IDENTIFIED" | "BRAND_CANDIDATES" | "BRAND_UNCERTAIN",
        "identified_brand": str | None,
        "official_domain": str | None,
        "confidence": "HIGH" | "MEDIUM" | "LOW",
        "signals_used": list,
        "candidate_brands": list,
        "message": str
    }
    """
    if not logo_profile or logo_profile.get("status") != "ready":
        return {
            "status": "BRAND_UNCERTAIN",
            "identified_brand": None,
            "official_domain": None,
            "confidence": "LOW",
            "signals_used": [],
            "candidate_brands": [],
            "message": "Logo profile not ready for identification."
        }

    ocr_tokens = [t.lower().strip() for t in logo_profile.get("ocr_text", []) if t]
    signals_used = []
    candidates = []

    # Signal 1: Phishpedia brand recognition
    p_brand = (phishpedia_result or {}).get("brand")
    p_conf = (phishpedia_result or {}).get("confidence", 0.0)
    if p_brand and p_conf >= 0.70:
        b_key = p_brand.lower().strip()
        if b_key in KNOWN_BRAND_DATABASE:
            entry = KNOWN_BRAND_DATABASE[b_key]
            signals_used.append("phishpedia_model")
            return {
                "status": "BRAND_IDENTIFIED",
                "identified_brand": entry["brand"],
                "official_domain": entry["official_domain"],
                "confidence": "HIGH",
                "signals_used": signals_used,
                "candidate_brands": [entry["brand"]],
                "message": f"Brand identified as '{entry['brand']}' via Phishpedia visual model."
            }

    # Signal 2: OCR Token alignment against known brand database
    for token in ocr_tokens:
        for b_key, b_info in KNOWN_BRAND_DATABASE.items():
            if token == b_key or token in b_info["aliases"]:
                signals_used.append("ocr_token_alignment")
                return {
                    "status": "BRAND_IDENTIFIED",
                    "identified_brand": b_info["brand"],
                    "official_domain": b_info["official_domain"],
                    "confidence": "HIGH",
                    "signals_used": signals_used,
                    "candidate_brands": [b_info["brand"]],
                    "message": f"Brand identified as '{b_info['brand']}' via logo OCR token '{token}'."
                }

    # Signal 3: Partial substring matching in OCR tokens
    for token in ocr_tokens:
        if len(token) >= 4:
            for b_key, b_info in KNOWN_BRAND_DATABASE.items():
                if token in b_key or b_key in token:
                    candidates.append(b_info["brand"])

    if len(candidates) == 1:
        signals_used.append("ocr_partial_match")
        b_key = candidates[0].lower()
        entry = KNOWN_BRAND_DATABASE.get(b_key, {"brand": candidates[0], "official_domain": f"{b_key}.com"})
        return {
            "status": "BRAND_IDENTIFIED",
            "identified_brand": entry["brand"],
            "official_domain": entry["official_domain"],
            "confidence": "MEDIUM",
            "signals_used": signals_used,
            "candidate_brands": [entry["brand"]],
            "message": f"Brand identified as '{entry['brand']}' via partial logo text alignment."
        }
    elif len(candidates) > 1:
        signals_used.append("ocr_multiple_candidates")
        return {
            "status": "BRAND_CANDIDATES",
            "identified_brand": None,
            "official_domain": None,
            "confidence": "LOW",
            "signals_used": signals_used,
            "candidate_brands": list(set(candidates)),
            "message": f"Multiple potential candidate brands found: {', '.join(candidates)}. Please select or confirm."
        }

    # Signal 4: Inconclusive -> BRAND_UNCERTAIN (Never hallucinate)
    return {
        "status": "BRAND_UNCERTAIN",
        "identified_brand": None,
        "official_domain": None,
        "confidence": "LOW",
        "signals_used": [],
        "candidate_brands": [],
        "message": "Brand identity could not be conclusively determined from logo alone. Please enter target brand name or domain."
    }
