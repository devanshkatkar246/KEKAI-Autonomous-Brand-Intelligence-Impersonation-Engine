"""
services/visual_retrieval_service.py

TASK 2D V4 — Visual Retrieval & Candidate Domain Recovery Engine

Extends visual corpus capabilities with:
  1. Indexing candidate visual assets from live webpage scans
  2. Stage 1 cheap pHash/dHash/OCR visual retrieval
  3. Visual Candidate → Domain Recovery (recovers source_domain from matched corpus assets)
  4. Handles VISUAL_MATCH_ONLY when source domain is unavailable
"""

import os
import sys
import logging
import uuid
import time
from typing import Dict, Any, List, Optional, Tuple
from pathlib import Path

_LOCAL_IMAGEHASH_DIR = os.path.abspath("./imagehash")
if _LOCAL_IMAGEHASH_DIR not in sys.path:
    sys.path.insert(0, _LOCAL_IMAGEHASH_DIR)

try:
    import imagehash
    HAS_IMAGEHASH = True
except ImportError:
    HAS_IMAGEHASH = False

logger = logging.getLogger("keikai.visual_retrieval")

# Persistent/In-memory corpus index
_VISUAL_RETRIEVAL_CORPUS: List[Dict[str, Any]] = []


def index_candidate_visual_asset(
    domain: Optional[str],
    url: Optional[str],
    asset_type: str,
    asset_path: str,
    brand: Optional[str] = None,
    ocr_tokens: Optional[List[str]] = None
) -> Optional[Dict[str, Any]]:
    """
    Indexes a visual asset (logo, screenshot, img, svg, favicon) into the Visual Intelligence Corpus.
    Records source_domain, source_url, pHash, dHash, and OCR tokens for reverse domain recovery.
    """
    if not HAS_IMAGEHASH or not asset_path or not os.path.exists(asset_path):
        return None

    try:
        from services.imagehash_service import compute_image_hashes
        hashes = compute_image_hashes(asset_path)

        record = {
            "asset_id": f"asset_{uuid.uuid4().hex[:10]}",
            "asset_type": asset_type,
            "path": asset_path,
            "source_domain": domain,
            "source_url": url,
            "brand": brand,
            "phash_str": str(hashes.get("phash_str")),
            "dhash_str": str(hashes.get("dhash_str")),
            "ocr": ocr_tokens or [],
            "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        }

        _VISUAL_RETRIEVAL_CORPUS.append(record)
        logger.info(f"[VisualRetrieval] Indexed asset {record['asset_id']} (Domain: {domain})")
        return record
    except Exception as e:
        logger.warning(f"[VisualRetrieval] Failed to index asset {asset_path}: {e}")
        return None


def retrieve_visual_candidates(
    target_profile: Dict[str, Any],
    phash_max_distance: int = 25,
    top_k: int = 15
) -> List[Dict[str, Any]]:
    """
    Stage 1 Cheap Retrieval: Queries the Visual Intelligence Corpus using target logo's pHash/dHash/OCR.
    Returns matched candidates sorted by visual similarity distance.
    """
    if not HAS_IMAGEHASH or not target_profile or not target_profile.get("phash_str") or not _VISUAL_RETRIEVAL_CORPUS:
        return []

    t_phash_str = target_profile.get("phash_str")
    t_dhash_str = target_profile.get("dhash_str")
    target_ocr = [t.lower() for t in target_profile.get("ocr_text", [])]

    results = []
    try:
        t_ph = imagehash.hex_to_hash(t_phash_str)
        t_dh = imagehash.hex_to_hash(t_dhash_str) if t_dhash_str else None

        for item in _VISUAL_RETRIEVAL_CORPUS:
            c_ph_str = item.get("phash_str")
            if not c_ph_str:
                continue

            c_ph = imagehash.hex_to_hash(c_ph_str)
            p_dist = int(t_ph - c_ph)

            d_dist = None
            if t_dh and item.get("dhash_str"):
                c_dh = imagehash.hex_to_hash(item["dhash_str"])
                d_dist = int(t_dh - c_dh)

            ocr_match = False
            for token in item.get("ocr", []):
                if token.lower() in target_ocr or any(t in token.lower() for t in target_ocr):
                    ocr_match = True
                    break

            if p_dist <= phash_max_distance or ocr_match:
                if p_dist <= 10:
                    level = "VERY_STRONG"
                elif p_dist <= 15:
                    level = "STRONG"
                elif p_dist <= 25:
                    level = "MODERATE"
                else:
                    level = "WEAK"

                results.append({
                    "corpus_item": item,
                    "phash_distance": p_dist,
                    "dhash_distance": d_dist,
                    "match_level": level,
                    "ocr_match": ocr_match,
                    "recovered_domain": item.get("source_domain"),
                    "recovered_url": item.get("source_url")
                })

        results.sort(key=lambda x: (x["phash_distance"] if x["phash_distance"] is not None else 99))
        return results[:top_k]

    except Exception as e:
        logger.error(f"[VisualRetrieval] Query error: {e}")
        return []


def recover_candidate_domain(corpus_item: Dict[str, Any]) -> Tuple[Optional[str], str]:
    """
    Recovers candidate domain from visual corpus metadata.
    Returns (source_domain, retrieval_status).
    Retrieval Statuses: 'DOMAIN_RECOVERED' | 'VISUAL_MATCH_ONLY'
    """
    domain = corpus_item.get("source_domain") or corpus_item.get("recovered_domain")
    if domain:
        return domain, "DOMAIN_RECOVERED"
    return None, "VISUAL_MATCH_ONLY"


def clear_visual_retrieval_corpus() -> None:
    _VISUAL_RETRIEVAL_CORPUS.clear()


def get_retrieval_corpus_size() -> int:
    return len(_VISUAL_RETRIEVAL_CORPUS)
