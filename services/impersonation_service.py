import os
import re
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from urllib.parse import urlparse
from pydantic import BaseModel, Field

from services.phishpedia_service import analyze_screenshot_visual_brand
from services.threat_intelligence.orchestrator import ThreatIntelOrchestrator
from services.imagehash_service import compute_image_hashes

logger = logging.getLogger("keikai.impersonation_service")

MAX_CANDIDATES_LIMIT = int(os.getenv("LOGO_IMPERSONATION_MAX_CANDIDATES", "25"))


class TargetBrandProfile(BaseModel):
    brand: str
    official_domains: List[str] = Field(default_factory=list)
    known_domains: List[str] = Field(default_factory=list)
    reference_screenshot: Optional[str] = None


def clean_domain_string(domain_raw: str) -> str:
    """
    Normalizes domain/URL input into plain lowercase hostname.
    """
    if not domain_raw:
        return ""
    d = str(domain_raw).strip().lower()
    if "://" in d:
        d = d.split("://", 1)[1]
    d = d.split("/")[0].split("?")[0].split("#")[0].split(":")[0]
    return d


def evaluate_domain_relationship(
    candidate_domain: str,
    official_domains: List[str],
    known_domains: Optional[List[str]] = None
) -> Tuple[str, bool]:
    """
    Evaluates relationship between candidate domain and target brand's official domains.
    Returns (relationship_type, official_domain_match_flag).
    Relationships: 'official', 'subdomain', 'related', 'unrelated'.
    """
    cand_clean = clean_domain_string(candidate_domain)
    if not cand_clean:
        return "unrelated", False

    known = [clean_domain_string(kd) for kd in (known_domains or []) if kd]
    officials = [clean_domain_string(od) for od in official_domains if od]

    cand_base_host = cand_clean[4:] if cand_clean.startswith("www.") else cand_clean

    # 1. Check exact official domain match
    for off in officials:
        off_clean = off[4:] if off.startswith("www.") else off
        if cand_clean == off or cand_base_host == off_clean:
            return "official", True

    # 2. Check official subdomain match (e.g. aws.amazon.com vs amazon.com)
    for off in officials:
        if off and cand_clean.endswith(f".{off}"):
            return "subdomain", True

    # 3. Check known partner/related domains
    for k in known:
        if cand_clean == k or cand_clean.endswith(f".{k}"):
            return "related", False

    # 4. Check regional TLD variants (e.g. amazon.co.uk vs amazon.com)
    cand_base = cand_clean.split(".")[0]
    for off in officials:
        off_base = off.split(".")[0]
        if cand_base == off_base and len(cand_base) >= 4:
            return "related", False

    return "unrelated", False


def evaluate_visual_similarity(
    candidate_image_path: Optional[str],
    reference_image_path: Optional[str]
) -> Dict[str, Any]:
    """
    Signal 1 — Visual Screenshot Similarity: Compares candidate screenshot with reference screenshot using pHash & dHash.
    Returns interpretable similarity level (VERY_HIGH, HIGH, MEDIUM, LOW, VERY_LOW, UNKNOWN).
    """
    if not candidate_image_path or not os.path.exists(candidate_image_path):
        return {"status": "unavailable", "reason": "Candidate screenshot unavailable", "similarity_level": "UNKNOWN"}

    if not reference_image_path or not os.path.exists(reference_image_path):
        return {"status": "unavailable", "reason": "Reference screenshot unavailable", "similarity_level": "UNKNOWN"}

    try:
        cand_hashes = compute_image_hashes(candidate_image_path)
        ref_hashes = compute_image_hashes(reference_image_path)

        p_dist = cand_hashes["phash"] - ref_hashes["phash"]
        d_dist = cand_hashes["dhash"] - ref_hashes["dhash"]

        avg_dist = (p_dist + d_dist) / 2.0

        if avg_dist <= 5:
            level = "VERY_HIGH"
        elif avg_dist <= 12:
            level = "HIGH"
        elif avg_dist <= 20:
            level = "MEDIUM"
        elif avg_dist <= 30:
            level = "LOW"
        else:
            level = "VERY_LOW"

        return {
            "status": "success",
            "phash_distance": p_dist,
            "dhash_distance": d_dist,
            "similarity_level": level
        }
    except Exception as e:
        logger.warning(f"Visual similarity computation error: {e}")
        return {"status": "unavailable", "reason": str(e), "similarity_level": "UNKNOWN"}


def extract_brand_text_evidence(
    page_text: Optional[str],
    target_brand: str,
    page_title: Optional[str] = None
) -> Dict[str, Any]:
    """
    Signal 2 — Page Text / Brand Evidence: Analyzes target brand mentions in page title, headings, and body text.
    """
    if not page_text:
        return {"brand_mentions": 0, "title_mentions": 0, "assessment": "NONE"}

    brand_clean = target_brand.strip().lower()
    text_lower = page_text.lower()
    title_lower = (page_title or "").lower()

    brand_count = text_lower.count(brand_clean)
    title_count = title_lower.count(brand_clean)

    if brand_count >= 3 or title_count >= 1:
        assessment = "STRONG"
    elif brand_count >= 1:
        assessment = "MEDIUM"
    else:
        assessment = "NONE"

    return {
        "brand_mentions": brand_count,
        "title_mentions": title_count,
        "assessment": assessment
    }


def detect_credential_taking_indicators(
    html_content: Optional[str] = None,
    page_text: Optional[str] = None
) -> Dict[str, Any]:
    """
    Signal 3 — Credential-Taking Indicators: Passively inspects DOM/HTML for password/email inputs, forms, and login button keywords.
    Does NOT submit forms or enter credentials.
    """
    html_str = (html_content or "").lower()
    text_str = (page_text or "").lower()

    password_fields = len(re.findall(r'<input[^>]*type=["\']password["\']', html_str)) if html_str else 0
    email_fields = len(re.findall(r'<input[^>]*type=["\'](email|text)["\']', html_str)) if html_str else 0
    form_count = len(re.findall(r'<form[^>]*>', html_str)) if html_str else 0

    login_keywords = ["sign in", "login", "log in", "password", "passcode", "verify account", "enter password"]
    detected_kw = [kw for kw in login_keywords if kw in html_str or kw in text_str]

    if password_fields >= 1 or (form_count >= 1 and len(detected_kw) >= 2):
        assessment = "HIGH"
    elif form_count >= 1 or len(detected_kw) >= 1:
        assessment = "MEDIUM"
    else:
        assessment = "NONE"

    return {
        "password_fields": password_fields,
        "email_fields": email_fields,
        "login_forms": form_count,
        "login_keywords": detected_kw,
        "assessment": assessment
    }


def calculate_impersonation_evidence(
    candidate_domain: str,
    target_brand: str,
    official_domains: List[str],
    sources: List[str],
    is_known_phishing: bool,
    visual_analysis: Dict[str, Any],
    candidate_image_path: Optional[str] = None,
    reference_image_path: Optional[str] = None,
    page_text: Optional[str] = None,
    page_title: Optional[str] = None,
    html_content: Optional[str] = None
) -> Dict[str, Any]:
    """
    TASK 2C CORE ENGINE: Fuses 5 independent webpage-level evidence signals
    (Logo Detection + Visual Similarity + Text Evidence + Credential Indicators + Threat Intelligence)
    into an explainable Impersonation Assessment with machine-readable reasons.
    Does NOT generate a phishing verdict on its own.
    """
    cand_clean = clean_domain_string(candidate_domain)
    target_clean = target_brand.strip().capitalize()

    # Signal 5: Domain Relationship
    relationship, official_match = evaluate_domain_relationship(cand_clean, official_domains)

    # Signal Task 2A: Phishpedia Logo Detection
    brands_detected = visual_analysis.get("brands", [])
    target_brand_detected = False
    detected_brand_name = None
    logo_confidence = 0.0
    bounding_box = None

    for b in brands_detected:
        b_name = b.get("brand", "").strip().capitalize()
        if b_name.lower() == target_clean.lower() or target_clean.lower() in b_name.lower():
            target_brand_detected = True
            detected_brand_name = b.get("brand")
            logo_confidence = b.get("confidence", 0.0)
            bounding_box = b.get("bounding_box")
            break

    # Signal 1: Visual Screenshot Similarity
    visual_sim = evaluate_visual_similarity(candidate_image_path, reference_image_path)

    # Signal 2: Text / Brand Evidence
    text_ev = extract_brand_text_evidence(page_text, target_clean, page_title)

    # Signal 3: Credential-Taking Indicators
    cred_ev = detect_credential_taking_indicators(html_content, page_text)

    # Human-readable reasons checklist
    reasons = []

    if target_brand_detected:
        reasons.append(f"Target {target_clean} brand logo detected with {round(logo_confidence * 100, 1)}% visual confidence")

    if official_match:
        reasons.append(f"Domain match: Candidate domain '{cand_clean}' is an official brand asset")
    elif relationship == "related":
        reasons.append(f"Related domain: Candidate domain '{cand_clean}' is a recognized partner/regional domain")
    else:
        reasons.append(f"Domain mismatch: Candidate domain '{cand_clean}' is unrelated to official domain(s) ({', '.join(official_domains)})")

    if visual_sim.get("similarity_level") in ("HIGH", "VERY_HIGH"):
        reasons.append(f"High visual similarity with official reference screenshot (pHash dist: {visual_sim.get('phash_distance')})")

    if text_ev.get("assessment") == "STRONG":
        reasons.append(f"Strong target brand text mentions in title & form labels ({text_ev.get('brand_mentions')} mentions)")

    if cred_ev.get("assessment") == "HIGH":
        reasons.append("Credential-taking indicators detected (Password input field & login form present)")

    if is_known_phishing:
        reasons.append("Threat intelligence match: Verified in OpenPhish feed or PhishTank database")

    if "dnstwist" in sources:
        reasons.append("Lookalike domain permutation detected by dnstwist scanner")

    # DETERMINISTIC EVIDENCE FUSION ASSESSMENT
    if official_match:
        classification = "TARGET_BRAND_ON_OFFICIAL_DOMAIN"
        evidence_strength = "NONE"
    elif relationship == "related":
        classification = "RELATED_DOMAIN_REVIEW"
        evidence_strength = "LOW"
    elif target_brand_detected and not official_match and (cred_ev.get("assessment") == "HIGH" or visual_sim.get("similarity_level") in ("HIGH", "VERY_HIGH") or text_ev.get("assessment") == "STRONG" or is_known_phishing):
        classification = "STRONG_IMPERSONATION_EVIDENCE"
        evidence_strength = "STRONG"
    elif target_brand_detected and not official_match:
        classification = "LIKELY_IMPERSONATION"
        evidence_strength = "HIGH"
    elif not target_brand_detected and (cred_ev.get("assessment") == "HIGH" or is_known_phishing):
        classification = "POTENTIAL_IMPERSONATION"
        evidence_strength = "MEDIUM"
    elif is_known_phishing:
        classification = "KNOWN_PHISHING_UNRELATED_LOGO"
        evidence_strength = "MEDIUM"
    elif not target_brand_detected and visual_analysis.get("status") == "success":
        classification = "NO_TARGET_BRAND_DETECTED"
        evidence_strength = "NONE"
    else:
        classification = "INSUFFICIENT_EVIDENCE"
        evidence_strength = "NONE"

    return {
        "candidate_domain": cand_clean,
        "target_brand": target_clean,
        "detected_brand": detected_brand_name,
        "brand_match": target_brand_detected,
        "logo_confidence": logo_confidence,
        "bounding_box": bounding_box,
        "official_domain_match": official_match,
        "domain_relationship": relationship,
        "evidence_strength": evidence_strength,
        "classification": classification,
        "reasons": reasons,
        "signals": {
            "brand_detection": visual_analysis,
            "domain_relationship": {"relationship": relationship, "official_match": official_match},
            "visual_similarity": visual_sim,
            "text_evidence": text_ev,
            "credential_indicators": cred_ev,
            "threat_intelligence": {"sources": sources, "is_known_phishing": is_known_phishing}
        }
    }


def execute_brand_impersonation_scan(
    target_brand: str,
    official_domain: str,
    max_candidates: int = MAX_CANDIDATES_LIMIT,
    dummy_screenshot_path: Optional[str] = None,
    reference_screenshot_path: Optional[str] = None
) -> Dict[str, Any]:
    """
    Executes multi-signal visual impersonation discovery scan across candidate pool.
    """
    clean_target = target_brand.strip().capitalize()
    clean_off = clean_domain_string(official_domain)

    scan_output = ThreatIntelOrchestrator.execute_multi_source_scan(domain=clean_off, quick_mode=True, timeout=10)
    raw_permutations = scan_output.get("permutations", [])

    def priority_key(item):
        is_kp = item.get("is_known_phishing", False)
        src_len = len(item.get("sources", []))
        return (1 if is_kp else 0, src_len)

    sorted_candidates = sorted(raw_permutations, key=priority_key, reverse=True)
    selected_candidates = sorted_candidates[:max_candidates]

    impersonation_results = []
    target_logo_matches = 0
    strong_impersonations = 0

    for cand in selected_candidates:
        c_domain = cand.get("domain", "")
        c_sources = cand.get("sources", ["dnstwist"])
        c_known = cand.get("is_known_phishing", False)

        visual_analysis = {"status": "unavailable", "brands": []}
        if dummy_screenshot_path and os.path.exists(dummy_screenshot_path):
            visual_analysis = analyze_screenshot_visual_brand(dummy_screenshot_path, target_brand=clean_target)

        analysis = calculate_impersonation_evidence(
            candidate_domain=c_domain,
            target_brand=clean_target,
            official_domains=[clean_off],
            sources=c_sources,
            is_known_phishing=c_known,
            visual_analysis=visual_analysis,
            candidate_image_path=dummy_screenshot_path,
            reference_image_path=reference_screenshot_path
        )

        if analysis["brand_match"]:
            target_logo_matches += 1
        if analysis["classification"] in ("STRONG_IMPERSONATION_EVIDENCE", "LIKELY_IMPERSONATION"):
            strong_impersonations += 1

        impersonation_results.append(analysis)

    return {
        "target_brand": clean_target,
        "official_domain": clean_off,
        "total_candidates_analyzed": len(impersonation_results),
        "target_logo_matches": target_logo_matches,
        "strong_impersonations": strong_impersonations,
        "results": impersonation_results
    }
