"""
services/domain_relationship_service.py

KEIKAI EVIDENCE INTELLIGENCE V2 — DOMAIN RELATIONSHIP ENGINE

Classifies relationships between candidate domains and target brands:
- OFFICIAL_EXACT: Exact official brand domain (e.g. flipkart.com for Flipkart)
- OFFICIAL_SUBDOMAIN: Official subdomain (e.g. store.steampowered.com for Steam)
- VERIFIED_PARTNER: Official partner or subsidiary domain
- VERIFIED_RELATED: Verified related brand infrastructure
- LOOKALIKE: Typosquat, homoglyph, or brand-impersonating candidate
- UNRELATED: Domain without brand relationship indicators
- UNKNOWN: Insufficient domain intelligence
"""

import re
import urllib.parse
from typing import Dict, Any, List, Optional


# Known official domains registry (can be configured per investigation target)
KNOWN_OFFICIAL_REGISTRY = {
    "amazon": ["amazon.com", "amazon.co.uk", "amazon.in", "amazon.de", "aws.amazon.com"],
    "flipkart": ["flipkart.com", "flipkart.net"],
    "steam": ["steampowered.com", "steamcommunity.com"],
    "google": ["google.com", "google.co.in", "youtube.com"],
    "apple": ["apple.com", "icloud.com"],
    "microsoft": ["microsoft.com", "office.com", "live.com"]
}


class DomainRelationshipEngine:

    @staticmethod
    def normalize_domain(domain: str) -> str:
        if not domain:
            return ""
        clean = domain.strip().lower()
        if clean.startswith("http://") or clean.startswith("https://"):
            parsed = urllib.parse.urlparse(clean)
            clean = parsed.netloc or parsed.path
        clean = clean.split(":")[0]
        return clean.lstrip("www.")

    @classmethod
    def classify_relationship(
        cls,
        candidate_domain: str,
        target_brand: str,
        official_domain: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Classifies domain relationship with explicit provenance and confidence.
        Never relies solely on permutation generator presence.
        """
        cand_norm = cls.normalize_domain(candidate_domain)
        brand_norm = (target_brand or "").strip().lower()
        off_norm = cls.normalize_domain(official_domain) if official_domain else ""

        # 1. Check Exact Official Domain match
        if off_norm and cand_norm == off_norm:
            return {
                "relationship": "OFFICIAL_EXACT",
                "is_official": True,
                "is_impersonation": False,
                "confidence": "HIGH",
                "reason": f"Candidate domain '{cand_norm}' exactly matches specified official brand domain '{off_norm}'.",
                "source": "TARGET_CONFIG"
            }

        # 2. Check Known Official Registry match
        registry_matches = KNOWN_OFFICIAL_REGISTRY.get(brand_norm, [])
        if cand_norm in registry_matches:
            return {
                "relationship": "OFFICIAL_EXACT",
                "is_official": True,
                "is_impersonation": False,
                "confidence": "HIGH",
                "reason": f"Candidate domain '{cand_norm}' is registered as an official domain for '{target_brand}'.",
                "source": "BRAND_PROFILE"
            }

        # 3. Check Subdomain of Official Domain
        if off_norm and (cand_norm.endswith("." + off_norm) or off_norm in cand_norm.split(".")):
            return {
                "relationship": "OFFICIAL_SUBDOMAIN",
                "is_official": True,
                "is_impersonation": False,
                "confidence": "HIGH",
                "reason": f"Candidate domain '{cand_norm}' is a legitimate subdomain under official brand domain '{off_norm}'.",
                "source": "DNS_HIERARCHY"
            }

        for reg_dom in registry_matches:
            if cand_norm.endswith("." + reg_dom):
                return {
                    "relationship": "OFFICIAL_SUBDOMAIN",
                    "is_official": True,
                    "is_impersonation": False,
                    "confidence": "HIGH",
                    "reason": f"Candidate domain '{cand_norm}' is a legitimate subdomain under official domain '{reg_dom}'.",
                    "source": "DNS_HIERARCHY"
                }

        # 4. Lexical / Permutation lookalike detection
        brand_clean = re.sub(r'[^a-z0-9]', '', brand_norm)
        cand_clean = re.sub(r'[^a-z0-9]', '', cand_norm.split('.')[0])

        # Normalize homoglyphs (0->o, 1->l, 3->e, 5->s, 8->b)
        homoglyph_map = str.maketrans({'0': 'o', '1': 'l', '3': 'e', '5': 's', '8': 'b', 'v': 'u'})
        cand_dehomoglyph = cand_clean.translate(homoglyph_map)
        brand_dehomoglyph = brand_clean.translate(homoglyph_map)

        is_substring = (brand_clean and brand_clean in cand_clean) or (brand_dehomoglyph and brand_dehomoglyph in cand_dehomoglyph)

        # Character set overlap similarity
        cand_chars = set(cand_dehomoglyph)
        brand_chars = set(brand_dehomoglyph)
        overlap = len(cand_chars.intersection(brand_chars)) / max(len(brand_chars), 1) if brand_chars else 0

        if is_substring or overlap >= 0.75:
            return {
                "relationship": "LOOKALIKE",
                "is_official": False,
                "is_impersonation": True,
                "confidence": "HIGH",
                "reason": f"Candidate domain '{cand_norm}' matches target brand '{target_brand}' lookalike/typosquat indicators.",
                "source": "LEXICAL_PERMUTATION"
            }

        # 5. Default Unrelated
        return {
            "relationship": "UNRELATED",
            "is_official": False,
            "is_impersonation": False,
            "confidence": "MEDIUM",
            "reason": f"No official registry or lookalike relationship detected between '{cand_norm}' and '{target_brand}'.",
            "source": "DOMAIN_ANALYSIS"
        }
