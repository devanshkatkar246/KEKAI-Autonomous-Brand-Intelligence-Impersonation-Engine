"""
services/logo_intelligence_service.py

Task 2D V4 — Resilient Logo-First Reverse Visual Discovery & Intelligence Engine

Provides genuine Logo-First Reverse Visual Discovery:
  1. Target logo normalization & fingerprinting (pHash, dHash, OCR text)
  2. Logo-based brand identification (brand_identification_service)
  3. Visual Corpus search & candidate domain recovery (visual_retrieval_service)
  4. Multi-Source Candidate Fusion (LOGO_VISUAL_MATCH + DNSTWIST + OPENPHISH + PHISHTANK + BRAND_DISCOVERY)
  5. Multi-strategy candidate acquisition (CandidateAcquisitionEngine with DNS precheck & failure taxonomy)
  6. Multi-layer visual asset extraction (HTML <img>, <svg>, Favicon)
  7. Automatic visual asset indexing for progressive corpus improvement
  8. Two-Stage Visual Verification (VISUAL_MATCH_VERIFIED / UNVERIFIED / DISPROVED)
  9. State semantics safety & viaSocket event generation
 10. Recursive numpy primitive serialization safety
"""

import os
import re
import sys
import uuid
import logging
import warnings
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse

import requests
from PIL import Image

_LOCAL_IMAGEHASH_DIR = os.path.abspath("./imagehash")
if _LOCAL_IMAGEHASH_DIR not in sys.path:
    sys.path.insert(0, _LOCAL_IMAGEHASH_DIR)

try:
    import imagehash as _imagehash_lib
    HAS_IMAGEHASH = True
except ImportError:
    _imagehash_lib = None
    HAS_IMAGEHASH = False

try:
    import pytesseract
    HAS_PYTESSERACT = True
except ImportError:
    pytesseract = None
    HAS_PYTESSERACT = False

from services.candidate_acquisition_service import (
    CandidateAcquisitionEngine,
    extract_webpage_visual_assets,
    generate_viasocket_event_payload,
    check_dns_resolution
)
from services.visual_corpus_service import (
    index_reference_logo,
    query_visual_corpus,
    get_corpus_size
)
from services.brand_identification_service import (
    identify_brand_from_logo,
    KNOWN_BRAND_DATABASE
)
from services.visual_retrieval_service import (
    index_candidate_visual_asset,
    retrieve_visual_candidates,
    recover_candidate_domain,
    get_retrieval_corpus_size
)

logger = logging.getLogger("keikai.logo_intelligence")

LOGO_PHASH_VERY_STRONG_THRESHOLD = int(os.getenv("LOGO_PHASH_VERY_STRONG_THRESHOLD", "10"))
LOGO_PHASH_STRONG_THRESHOLD      = int(os.getenv("LOGO_PHASH_STRONG_THRESHOLD", "15"))
LOGO_PHASH_MODERATE_THRESHOLD    = int(os.getenv("LOGO_PHASH_MODERATE_THRESHOLD", "25"))

LOGO_DHASH_VERY_STRONG_THRESHOLD = int(os.getenv("LOGO_DHASH_VERY_STRONG_THRESHOLD", "10"))
LOGO_DHASH_STRONG_THRESHOLD      = int(os.getenv("LOGO_DHASH_STRONG_THRESHOLD", "15"))
LOGO_DHASH_MODERATE_THRESHOLD    = int(os.getenv("LOGO_DHASH_MODERATE_THRESHOLD", "25"))

SCREENSHOT_TIMEOUT = int(os.getenv("LOGO_SCREENSHOT_TIMEOUT", "8"))

SCREENSHOT_DIR = Path("./uploads/screenshots")
LOGO_CROPS_DIR = Path("./uploads/logo_crops")


def _ensure_dirs() -> None:
    SCREENSHOT_DIR.mkdir(parents=True, exist_ok=True)
    LOGO_CROPS_DIR.mkdir(parents=True, exist_ok=True)


# ---------------------------------------------------------------------------
# NUMPY PRIMITIVE SANITIZER
# ---------------------------------------------------------------------------

def sanitize_numpy_primitives(obj: Any) -> Any:
    if obj is None:
        return None
    
    type_str = str(type(obj))
    if "numpy" in type_str or "np." in type_str:
        if "int" in type_str:
            return int(obj)
        if "float" in type_str:
            return float(obj)
        if "bool" in type_str:
            return bool(obj)
        if "ndarray" in type_str:
            return [sanitize_numpy_primitives(x) for x in obj.tolist()]
    
    if isinstance(obj, dict):
        return {str(k): sanitize_numpy_primitives(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple, set)):
        return [sanitize_numpy_primitives(x) for x in obj]
    if isinstance(obj, (int, float, str, bool)):
        return obj
    
    try:
        return int(obj)
    except Exception:
        try:
            return float(obj)
        except Exception:
            return str(obj)


# ---------------------------------------------------------------------------
# OCR
# ---------------------------------------------------------------------------

def extract_logo_ocr_text(image_path: str, brand_hint: str = "") -> List[str]:
    texts: List[str] = []
    if HAS_PYTESSERACT:
        try:
            with Image.open(image_path) as img:
                raw = pytesseract.image_to_string(img, config="--psm 11 --oem 3")
                for word in raw.split():
                    token = word.lower().strip(".,;:!?'\"()[]{}|\\/-_").strip()
                    if len(token) >= 2:
                        texts.append(token)
        except Exception as e:
            logger.debug(f"[LogoIntelligence OCR] pytesseract failed: {e}")

    if brand_hint:
        hint = brand_hint.lower().strip()
        if hint and hint not in texts:
            texts.append(hint)

    return texts


# ---------------------------------------------------------------------------
# Target Logo Fingerprinting
# ---------------------------------------------------------------------------

def generate_target_logo_profile(image_path: str, brand: str = "") -> Dict[str, Any]:
    from services.imagehash_service import compute_image_hashes

    profile: Dict[str, Any] = {
        "status": "error",
        "brand": brand,
        "image_path": image_path,
        "normalized_image_path": None,
        "dimensions": None,
        "background": "unknown",
        "phash_str": None,
        "dhash_str": None,
        "ocr_text": [],
        "ocr_method": "none",
        "error": None
    }

    try:
        hash_data = compute_image_hashes(image_path, return_normalized_image=True)
        norm_img = hash_data.get("normalized_image")

        _ensure_dirs()
        if norm_img is not None:
            norm_path = LOGO_CROPS_DIR / f"norm_logo_{uuid.uuid4().hex[:10]}.png"
            norm_img.save(str(norm_path))
            profile["normalized_image_path"] = str(norm_path)
            profile["dimensions"] = {"width": int(norm_img.width), "height": int(norm_img.height)}

        profile["phash_str"] = str(hash_data["phash_str"])
        profile["dhash_str"] = str(hash_data["dhash_str"])

        try:
            with Image.open(image_path) as img:
                profile["background"] = "transparent" if img.mode in ("RGBA", "LA", "PA") else "opaque"
        except Exception:
            pass

        ocr_tokens = extract_logo_ocr_text(image_path, brand_hint=brand)
        profile["ocr_text"] = ocr_tokens
        profile["ocr_method"] = "pytesseract" if HAS_PYTESSERACT else "brand_hint_fallback"

        profile["status"] = "ready"
        
        if brand:
            index_reference_logo(brand=brand, logo_path=image_path)
        
        return sanitize_numpy_primitives(profile)

    except Exception as e:
        logger.error(f"[LogoIntelligence] Logo profile generation failed for {image_path}: {e}")
        profile["error"] = str(e)
        return sanitize_numpy_primitives(profile)


# ---------------------------------------------------------------------------
# Backward Compatibility Wrapper
# ---------------------------------------------------------------------------

def acquire_candidate_screenshot(url: str, timeout: int = SCREENSHOT_TIMEOUT) -> Dict[str, Any]:
    domain = url.split("://")[-1].split("/")[0] if url else ""
    acq = CandidateAcquisitionEngine.acquire_candidate_webpage(domain, timeout=timeout)
    
    return {
        "status": acq["status"],
        "path": acq.get("screenshot_path"),
        "requested_url": url,
        "final_url": acq.get("final_url") or url,
        "source": "multi_strategy_http" if acq["status"] == "success" else None,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "failure_reason": acq.get("failure_reason"),
        "failure_category": acq.get("failure_category"),
        "dns_status": acq.get("dns_status"),
        "attempts": acq.get("attempts", []),
        "redirect_chain": acq.get("redirect_chain", []),
        "tls_fallback_used": acq.get("tls_fallback_used", False)
    }


# ---------------------------------------------------------------------------
# Logo Cropping
# ---------------------------------------------------------------------------

def crop_logo_from_screenshot(
    screenshot_path: str,
    bounding_box: Optional[List[int]]
) -> Optional[str]:
    if not screenshot_path or not os.path.exists(screenshot_path):
        return None

    try:
        _ensure_dirs()
        with Image.open(screenshot_path) as img:
            if bounding_box and len(bounding_box) == 4:
                x1, y1, x2, y2 = bounding_box
                w, h = img.size
                x1 = max(0, min(int(x1), w))
                y1 = max(0, min(int(y1), h))
                x2 = max(x1 + 1, min(int(x2), w))
                y2 = max(y1 + 1, min(int(y2), h))
                crop = img.crop((x1, y1, x2, y2))
            else:
                crop = img.copy()

            crop_path = LOGO_CROPS_DIR / f"crop_{uuid.uuid4().hex[:12]}.png"
            if crop.mode not in ("RGB", "RGBA"):
                crop = crop.convert("RGB")
            crop.save(str(crop_path))
            return str(crop_path)

    except Exception as e:
        logger.warning(f"[LogoIntelligence] Logo crop failed for {screenshot_path}: {e}")
        return None


# ---------------------------------------------------------------------------
# Signals & Comparisons
# ---------------------------------------------------------------------------

def _phash_signal_level(distance: int) -> str:
    if distance <= LOGO_PHASH_VERY_STRONG_THRESHOLD:
        return "VERY_HIGH"
    elif distance <= LOGO_PHASH_STRONG_THRESHOLD:
        return "HIGH"
    elif distance <= LOGO_PHASH_MODERATE_THRESHOLD:
        return "MODERATE"
    else:
        return "LOW"


def _dhash_signal_level(distance: int) -> str:
    if distance <= LOGO_DHASH_VERY_STRONG_THRESHOLD:
        return "VERY_HIGH"
    elif distance <= LOGO_DHASH_STRONG_THRESHOLD:
        return "HIGH"
    elif distance <= LOGO_DHASH_MODERATE_THRESHOLD:
        return "MODERATE"
    else:
        return "LOW"


def _check_ocr_match(
    target_ocr: List[str],
    candidate_brand_name: Optional[str],
    target_brand: str
) -> str:
    if not target_ocr and not candidate_brand_name:
        return "NOT_AVAILABLE"

    target_lower = target_brand.lower().strip()
    cand_lower = (candidate_brand_name or "").lower().strip()

    if cand_lower:
        if cand_lower == target_lower or target_lower in cand_lower or cand_lower in target_lower:
            return "MATCH"

    for token in target_ocr:
        if token and len(token) >= 3 and cand_lower:
            if token in cand_lower or cand_lower in token:
                return "PARTIAL"

    return "NO_MATCH"


def _determine_match_level(
    phash_level: str,
    dhash_level: str,
    ocr_status: str,
    brand_matches: bool
) -> str:
    is_very_high = phash_level == "VERY_HIGH" and dhash_level == "VERY_HIGH"
    is_high = phash_level in ("VERY_HIGH", "HIGH") and dhash_level in ("VERY_HIGH", "HIGH")
    ocr_positive = ocr_status in ("MATCH", "PARTIAL")

    if not is_high and not is_very_high:
        if phash_level == "LOW" and (dhash_level in ("LOW", "UNAVAILABLE")):
            if ocr_positive or brand_matches:
                return "WEAK"
            return "NO_MATCH"

    if is_very_high and brand_matches:
        return "VERY_STRONG"
    if is_very_high and ocr_positive:
        return "VERY_STRONG"
    if is_high and (brand_matches or ocr_positive):
        return "STRONG"
    if is_high:
        return "STRONG"
    if phash_level == "MODERATE" and (brand_matches or ocr_positive):
        return "MODERATE"
    if phash_level == "MODERATE":
        return "MODERATE"
    if brand_matches:
        return "MODERATE"
    if ocr_positive:
        return "WEAK"

    return "NO_MATCH"


def compare_logo_profiles(
    target_profile: Dict[str, Any],
    candidate_profile: Dict[str, Any],
    target_brand: str,
    phishpedia_result: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    if not HAS_IMAGEHASH:
        return {
            "level": "UNAVAILABLE",
            "matched": False,
            "reason": "imagehash library unavailable",
            "signals": {}
        }

    t_phash_str = target_profile.get("phash_str")
    t_dhash_str = target_profile.get("dhash_str")
    c_phash_str = candidate_profile.get("phash_str")
    c_dhash_str = candidate_profile.get("dhash_str")

    if not t_phash_str or not c_phash_str:
        return {
            "level": "UNAVAILABLE",
            "matched": False,
            "reason": "Hash data missing — cannot compare",
            "signals": {}
        }

    try:
        t_ph = _imagehash_lib.hex_to_hash(t_phash_str)
        c_ph = _imagehash_lib.hex_to_hash(c_phash_str)
        phash_dist = int(t_ph - c_ph)
        phash_level = _phash_signal_level(phash_dist)

        dhash_dist = None
        dhash_level = "UNAVAILABLE"
        if t_dhash_str and c_dhash_str:
            t_dh = _imagehash_lib.hex_to_hash(t_dhash_str)
            c_dh = _imagehash_lib.hex_to_hash(c_dhash_str)
            dhash_dist = int(t_dh - c_dh)
            dhash_level = _dhash_signal_level(dhash_dist)

        phishpedia_brand = (phishpedia_result or {}).get("brand", "") or candidate_profile.get("brand", "")
        phishpedia_conf = (phishpedia_result or {}).get("confidence", 0.0)
        brand_matches = bool(phishpedia_brand and phishpedia_brand.lower().strip() == target_brand.lower().strip())

        target_ocr = target_profile.get("ocr_text", [])
        ocr_status = _check_ocr_match(target_ocr, phishpedia_brand, target_brand)

        level = _determine_match_level(phash_level, dhash_level, ocr_status, brand_matches)
        matched = (level in ("VERY_STRONG", "STRONG")) or (level == "MODERATE" and brand_matches)

        res = {
            "level": level,
            "matched": matched,
            "phash_distance": int(phash_dist),
            "dhash_distance": int(dhash_dist) if dhash_dist is not None else None,
            "signals": {
                "phash": {
                    "distance": int(phash_dist),
                    "level": phash_level,
                    "status": phash_level
                },
                "dhash": {
                    "distance": int(dhash_dist) if dhash_dist is not None else None,
                    "level": dhash_level,
                    "status": dhash_level
                },
                "ocr": {
                    "status": ocr_status,
                    "target_ocr": target_ocr,
                    "candidate_brand": phishpedia_brand
                },
                "phishpedia_brand": {
                    "brand": phishpedia_brand,
                    "confidence": round(float(phishpedia_conf or 0.0), 3),
                    "matches_target": brand_matches
                }
            }
        }
        return sanitize_numpy_primitives(res)

    except Exception as e:
        logger.error(f"[LogoIntelligence] Logo comparison error: {e}")
        return {
            "level": "UNAVAILABLE",
            "matched": False,
            "reason": f"Comparison error: {str(e)[:100]}",
            "signals": {}
        }


def _build_logo_match_result(
    logo_profile: Optional[Dict[str, Any]],
    visual_analysis: Dict[str, Any],
    screenshot_result: Dict[str, Any],
    screenshot_path: Optional[str],
    target_brand: str
) -> Dict[str, Any]:
    sc_status = screenshot_result.get("status", "unavailable")
    sc_success = sc_status == "success"
    sc_reason = screenshot_result.get("failure_reason", "")

    if not logo_profile or logo_profile.get("status") != "ready":
        return {
            "level": "UNAVAILABLE",
            "matched": False,
            "reason": "No target logo uploaded — logo comparison NOT RUN",
            "signals": {
                "phash": {"status": "NOT_RUN"},
                "dhash": {"status": "NOT_RUN"},
                "ocr": {"status": "NOT_RUN"},
                "phishpedia_brand": None
            }
        }

    if not sc_success or not screenshot_path or not os.path.exists(screenshot_path or ""):
        cat = screenshot_result.get("failure_category", sc_status.upper())
        return {
            "level": "UNAVAILABLE",
            "matched": False,
            "reason": f"Acquisition {cat}: logo comparison NOT RUN — {sc_reason}",
            "signals": {
                "phash": {"status": "NOT_RUN", "reason": f"Acquisition {cat}"},
                "dhash": {"status": "NOT_RUN", "reason": f"Acquisition {cat}"},
                "ocr": {"status": "NOT_RUN", "reason": f"Acquisition {cat}"},
                "phishpedia_brand": None
            }
        }

    va_status = visual_analysis.get("status", "unavailable")
    if va_status in ("unavailable", "not_run", "error"):
        return {
            "level": "UNAVAILABLE",
            "matched": False,
            "reason": f"Phishpedia {va_status.upper()}: {visual_analysis.get('reason', 'Logo detection unavailable')}",
            "signals": {
                "phash": {"status": "NOT_RUN", "reason": f"Phishpedia {va_status}"},
                "dhash": {"status": "NOT_RUN", "reason": f"Phishpedia {va_status}"},
                "ocr": {"status": "NOT_RUN"},
                "phishpedia_brand": None
            }
        }

    brands = visual_analysis.get("brands", [])
    if not brands:
        return {
            "level": "NO_MATCH",
            "matched": False,
            "reason": "Phishpedia ran successfully — no brand logos detected on this page",
            "signals": {
                "phash": {"status": "NOT_RUN", "reason": "No logo crop available"},
                "dhash": {"status": "NOT_RUN", "reason": "No logo crop available"},
                "ocr": {"status": "NOT_RUN"},
                "phishpedia_brand": {"brand": None, "confidence": 0.0, "matches_target": False}
            }
        }

    best_brand = next(
        (b for b in brands if b.get("brand", "").lower().strip() == target_brand.lower().strip()),
        brands[0]
    )
    bbox = best_brand.get("bounding_box")
    cropped_path = crop_logo_from_screenshot(screenshot_path, bbox) or screenshot_path

    try:
        candidate_profile = generate_target_logo_profile(cropped_path, best_brand.get("brand", ""))
        return compare_logo_profiles(
            target_profile=logo_profile,
            candidate_profile=candidate_profile,
            target_brand=target_brand,
            phishpedia_result=best_brand
        )
    except Exception as e:
        logger.error(f"[LogoIntelligence] Logo comparison exception: {e}")
        return {
            "level": "UNAVAILABLE",
            "matched": False,
            "reason": f"Logo comparison error: {str(e)[:80]}",
            "signals": {}
        }


# ---------------------------------------------------------------------------
# FULL TASK 2D V4 SCAN ORCHESTRATION — TRUE LOGO-FIRST REVERSE DISCOVERY
# ---------------------------------------------------------------------------

def run_logo_intelligence_scan(
    target_brand: Optional[str] = None,
    official_domain: Optional[str] = None,
    logo_path: Optional[str] = None,
    max_candidates: int = 25
) -> Dict[str, Any]:
    """
    Task 2D V4: Resilient Logo-First Reverse Visual Discovery & Intelligence Engine.

    Workflow:
      1. Target Logo Ingestion & Fingerprinting (pHash, dHash, OCR)
      2. Logo-based Brand Identification (if brand omitted)
      3. Stage 1 Visual Corpus Search & Candidate Domain Recovery
      4. Multi-Source Candidate Fusion (LOGO_VISUAL_MATCH + DNSTWIST + OPENPHISH + PHISHTANK + BRAND_DISCOVERY)
      5. Stage 2 Live Verification (Resilient Candidate Acquisition + Phishpedia + HTML Visual Assets)
      6. Automatic Visual Asset Indexing for progressive corpus improvement
      7. Two-Stage Visual Verification Status Determination (VERIFIED / UNVERIFIED / DISPROVED)
      8. viaSocket Event Schema Formatting
    """
    from services.threat_intelligence.orchestrator import ThreatIntelOrchestrator
    from services.phishpedia_service import analyze_screenshot_visual_brand
    from services.impersonation_service import (
        clean_domain_string,
        evaluate_domain_relationship,
        calculate_impersonation_evidence,
        MAX_CANDIDATES_LIMIT
    )

    max_cands = min(int(max_candidates), MAX_CANDIDATES_LIMIT)
    clean_target = (target_brand or "").strip().capitalize()
    clean_off = clean_domain_string(official_domain or "")

    # STEP 1: Target Logo Fingerprint
    logo_profile: Optional[Dict[str, Any]] = None
    if logo_path and os.path.exists(logo_path):
        logger.info(f"[LogoIntelligence V4] Generating fingerprint for: {logo_path}")
        logo_profile = generate_target_logo_profile(logo_path, clean_target)

    # STEP 2: Logo-Based Brand Identification (Phase 3)
    brand_id_result = None
    if not clean_target and logo_profile and logo_profile.get("status") == "ready":
        brand_id_result = identify_brand_from_logo(logo_profile)
        if brand_id_result["status"] == "BRAND_IDENTIFIED":
            clean_target = brand_id_result["identified_brand"]
            clean_off = brand_id_result["official_domain"] or clean_off
            logger.info(f"[LogoIntelligence V4] Auto-identified brand: {clean_target} ({clean_off})")
        else:
            logger.info(f"[LogoIntelligence V4] Brand identification status: {brand_id_result['status']}")

    # Infer domain fallback if still empty
    if clean_target and not clean_off:
        b_lower = clean_target.lower()
        clean_off = KNOWN_BRAND_DATABASE.get(b_lower, {}).get("official_domain", f"{b_lower}.com")

    # STEP 3: Stage 1 Visual Corpus Search & Domain Recovery (Phase 6, 9, 12)
    corpus_retrieved = []
    recovered_domains_map = {}  # domain -> corpus match details
    if logo_profile and logo_profile.get("phash_str"):
        corpus_matches = retrieve_visual_candidates(logo_profile, top_k=15)
        for c_match in corpus_matches:
            c_item = c_match["corpus_item"]
            r_dom, r_status = recover_candidate_domain(c_item)
            if r_dom:
                c_clean = clean_domain_string(r_dom)
                recovered_domains_map[c_clean] = {
                    "source": "LOGO_VISUAL_MATCH",
                    "match_level": c_match["match_level"],
                    "phash_distance": c_match["phash_distance"],
                    "dhash_distance": c_match["dhash_distance"],
                    "corpus_item": c_item,
                    "retrieval_status": r_status
                }
                corpus_retrieved.append(c_match)

    # STEP 4: Multi-Source Candidate Discovery & Fusion (Phase 5, 17, 24)
    raw_perms = []
    if clean_off:
        logger.info(f"[LogoIntelligence V4] Multi-source threat scan for: {clean_off}")
        scan_output = ThreatIntelOrchestrator.execute_multi_source_scan(
            domain=clean_off, quick_mode=True, timeout=10
        )
        raw_perms = scan_output.get("permutations", [])

    # Fusion candidate map: domain -> merged payload
    fused_candidates_map = {}

    # Add threat intel candidates
    for p in raw_perms:
        d = clean_domain_string(p.get("domain", ""))
        if not d:
            continue
        fused_candidates_map[d] = {
            "domain": d,
            "url": p.get("url") or f"http://{d}",
            "sources": list(p.get("sources", ["dnstwist"])),
            "is_known_phishing": bool(p.get("is_known_phishing", False)),
            "corpus_match": None
        }

    # Merge corpus recovered candidates
    for r_dom, r_info in recovered_domains_map.items():
        if r_dom in fused_candidates_map:
            # Domain exists in threat intel -> Merge provenance!
            if "LOGO_VISUAL_MATCH" not in fused_candidates_map[r_dom]["sources"]:
                fused_candidates_map[r_dom]["sources"].append("LOGO_VISUAL_MATCH")
            fused_candidates_map[r_dom]["corpus_match"] = r_info
        else:
            # Unique domain from visual corpus alone -> Add candidate!
            fused_candidates_map[r_dom] = {
                "domain": r_dom,
                "url": f"http://{r_dom}",
                "sources": ["LOGO_VISUAL_MATCH"],
                "is_known_phishing": False,
                "corpus_match": r_info
            }

    # Discovery coverage statistics
    dnstwist_count = sum(1 for c in fused_candidates_map.values() if "dnstwist" in c["sources"])
    openphish_count = sum(1 for c in fused_candidates_map.values() if "openphish" in c["sources"])
    phishtank_count = sum(1 for c in fused_candidates_map.values() if "phishtank" in c["sources"])
    visual_match_count = sum(1 for c in fused_candidates_map.values() if "LOGO_VISUAL_MATCH" in c["sources"])

    # STEP 5: Prioritization (Visual Match + Multi-source + Known Phishing -> Top)
    def _v4_priority(item: Dict) -> tuple:
        has_vm = 1 if "LOGO_VISUAL_MATCH" in item["sources"] else 0
        is_kp = 1 if item["is_known_phishing"] else 0
        src_cnt = len(item["sources"])
        return (has_vm, is_kp, src_cnt)

    sorted_fused = sorted(fused_candidates_map.values(), key=_v4_priority, reverse=True)
    selected_fused = sorted_fused[:max_cands]

    results = []
    target_logo_matches = 0
    strong_impersonations = 0
    screenshot_successes = 0
    live_verified_count = 0

    for cand_info in selected_fused:
        c_domain = cand_info["domain"]
        c_sources = cand_info["sources"]
        c_known = cand_info["is_known_phishing"]
        c_corpus_match = cand_info["corpus_match"]

        relationship, official_match = evaluate_domain_relationship(c_domain, [clean_off] if clean_off else [])

        # STEP 6: Resilient Candidate Acquisition (V3)
        acq_res = CandidateAcquisitionEngine.acquire_candidate_webpage(c_domain, timeout=SCREENSHOT_TIMEOUT)
        sc_path = acq_res.get("screenshot_path")
        sc_success = acq_res["status"] == "success"

        if sc_success:
            screenshot_successes += 1

        # Multi-layer HTML Visual Asset Extraction
        visual_assets_data = {"images_found": 0, "svg_found": 0, "favicons_found": 0, "assets": []}
        best_asset_match = None

        if sc_success and acq_res.get("html_content"):
            visual_assets_data = extract_webpage_visual_assets(
                html_content=acq_res["html_content"],
                base_url=acq_res["final_url"] or f"http://{c_domain}"
            )

            # Auto-index candidate visual assets into Visual Corpus (Phase 8)
            for ast in visual_assets_data["assets"]:
                l_path = ast.get("local_path")
                if l_path and os.path.exists(l_path):
                    index_candidate_visual_asset(
                        domain=c_domain,
                        url=acq_res.get("final_url"),
                        asset_type=ast.get("asset_type", "IMG"),
                        asset_path=l_path,
                        brand=clean_target
                    )

            # Match extracted HTML assets against target logo profile
            if logo_profile and visual_assets_data["assets"]:
                for ast in visual_assets_data["assets"]:
                    l_path = ast.get("local_path")
                    if l_path and os.path.exists(l_path) and not l_path.endswith(".svg"):
                        try:
                            ast_prof = generate_target_logo_profile(l_path, clean_target)
                            ast_cmp = compare_logo_profiles(logo_profile, ast_prof, clean_target)
                            ast["match"] = ast_cmp
                            if not best_asset_match or (ast_cmp.get("phash_distance") or 99) < (best_asset_match.get("phash_distance") or 99):
                                best_asset_match = {
                                    "asset_type": ast.get("asset_type"),
                                    "source": ast.get("source"),
                                    "phash": ast_cmp.get("signals", {}).get("phash", {}).get("level"),
                                    "dhash": ast_cmp.get("signals", {}).get("dhash", {}).get("level"),
                                    "ocr": ast_cmp.get("signals", {}).get("ocr", {}).get("status"),
                                    "match_level": ast_cmp.get("level"),
                                    "phash_distance": ast_cmp.get("phash_distance")
                                }
                        except Exception:
                            continue

        # Phishpedia brand analysis
        if sc_success and sc_path and os.path.exists(sc_path):
            visual_analysis = analyze_screenshot_visual_brand(sc_path, target_brand=clean_target)
        else:
            fail_cat = acq_res.get("failure_category", acq_res["status"].upper())
            fail_reason = acq_res.get("failure_reason", "Acquisition failed")
            visual_analysis = {
                "status": "not_run",
                "detected": False,
                "reason": f"Phishpedia NOT RUN — Acquisition {fail_cat}: {fail_reason}",
                "brands": [],
                "model": "Phishpedia (Not Run)"
            }

        screenshot_struct = {
            "status": acq_res["status"],
            "path": sc_path,
            "requested_url": f"http://{c_domain}",
            "final_url": acq_res.get("final_url"),
            "source": "multi_strategy_http" if sc_success else None,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "failure_reason": acq_res.get("failure_reason"),
            "failure_category": acq_res.get("failure_category"),
            "dns_status": acq_res.get("dns_status"),
            "dns_ip_addresses": acq_res.get("dns_ip_addresses", []),
            "attempts": acq_res.get("attempts", []),
            "redirect_chain": acq_res.get("redirect_chain", []),
            "tls_fallback_used": acq_res.get("tls_fallback_used", False)
        }

        # Logo match result
        logo_match_result = _build_logo_match_result(
            logo_profile=logo_profile,
            visual_analysis=visual_analysis,
            screenshot_result=screenshot_struct,
            screenshot_path=sc_path,
            target_brand=clean_target
        )

        if logo_match_result.get("matched"):
            target_logo_matches += 1

        # Two-Stage Visual Verification Status Determination (Phase 20)
        if c_corpus_match or logo_match_result.get("matched"):
            if sc_success and logo_match_result.get("matched"):
                two_stage_status = "VISUAL_MATCH_VERIFIED"
                live_verified_count += 1
            elif sc_success and not logo_match_result.get("matched"):
                two_stage_status = "VISUAL_MATCH_DISPROVED"
            else:
                two_stage_status = "VISUAL_MATCH_UNVERIFIED"
        else:
            two_stage_status = "VISUAL_MATCH_UNAVAILABLE"

        # Evidence fusion
        analysis = calculate_impersonation_evidence(
            candidate_domain=c_domain,
            target_brand=clean_target,
            official_domains=[clean_off] if clean_off else [],
            sources=c_sources,
            is_known_phishing=c_known,
            visual_analysis=visual_analysis,
            candidate_image_path=sc_path,
            reference_image_path=logo_path
        )

        # Impersonation Protection: Candidate domain mismatch + failed screenshot -> INSUFFICIENT_EVIDENCE
        if not sc_success and analysis["classification"] in ("STRONG_IMPERSONATION_EVIDENCE", "LIKELY_IMPERSONATION"):
            if not c_known:
                analysis["classification"] = "INSUFFICIENT_EVIDENCE"
                analysis["evidence_strength"] = "LOW"
                analysis["reasons"].append(f"Acquisition {acq_res.get('failure_category')}: candidate page visually inaccessible. Insufficient evidence for impersonation verdict.")

        # Attach V4 fields
        analysis["discovery_sources"] = c_sources
        analysis["two_stage_verification_status"] = two_stage_status
        analysis["live_verified"] = (two_stage_status == "VISUAL_MATCH_VERIFIED")
        analysis["corpus_match_info"] = c_corpus_match

        analysis["visual_evidence"] = {
            "screenshot": {"status": acq_res["status"], "path": sc_path},
            "phishpedia": visual_analysis,
            "assets": visual_assets_data,
            "best_logo_candidate": best_asset_match,
            "two_stage_status": two_stage_status
        }

        analysis["screenshot"] = screenshot_struct
        analysis["logo_match"] = logo_match_result
        analysis["investigation_mode"] = "logo_first_v4"

        # viaSocket Event Payload for High Confidence Impersonations
        if analysis["classification"] in ("STRONG_IMPERSONATION_EVIDENCE", "LIKELY_IMPERSONATION"):
            strong_impersonations += 1
            analysis["viasocket_event"] = generate_viasocket_event_payload(
                case_id=f"case_{uuid.uuid4().hex[:8]}",
                brand=clean_target,
                official_domain=clean_off,
                candidate_domain=c_domain,
                assessment=analysis["classification"],
                evidence_strength=analysis["evidence_strength"],
                visual_match_level=logo_match_result.get("level", "UNAVAILABLE"),
                threat_sources=c_sources,
                credential_indicators=analysis["signals"].get("credential_indicators", {}).get("assessment") == "HIGH",
                screenshot_available=sc_success
            )

        results.append(analysis)

    final_payload = {
        "target_brand": clean_target,
        "official_domain": clean_off,
        "brand_identification": brand_id_result,
        "logo_profile": logo_profile,
        "corpus_info": {
            "reference_corpus_size": get_corpus_size(),
            "retrieval_corpus_size": get_retrieval_corpus_size(),
            "matches_found": len(corpus_retrieved),
            "top_matches": corpus_retrieved[:3]
        },
        "discovery": {
            "dnstwist": dnstwist_count,
            "openphish": openphish_count,
            "phishtank": phishtank_count,
            "visual_corpus_matches": visual_match_count,
            "unique_candidates": len(fused_candidates_map),
            "analyzed": len(results)
        },
        "total_candidates_analyzed": len(results),
        "target_logo_matches": target_logo_matches,
        "live_verified_count": live_verified_count,
        "strong_impersonations": strong_impersonations,
        "screenshot_successes": screenshot_successes,
        "uploaded_logo_processed": bool(logo_path),
        "investigation_mode": "logo_first_v4",
        "results": results
    }

    return sanitize_numpy_primitives(final_payload)
