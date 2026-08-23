"""
services/visual_corpus_service.py

TASK 2D V3 — Visual Intelligence Corpus & 2-Stage Visual Retrieval Engine

Maintains an indexed visual corpus of reference brand logos and known visual assets.
Supports Stage 1 cheap pHash/dHash filtering before Stage 2 expensive visual verification.
"""

import os
import sys
import logging
from typing import Dict, Any, List, Optional
from pathlib import Path

# Ensure local imagehash importable
_LOCAL_IMAGEHASH_DIR = os.path.abspath("./imagehash")
if _LOCAL_IMAGEHASH_DIR not in sys.path:
    sys.path.insert(0, _LOCAL_IMAGEHASH_DIR)

try:
    import imagehash
    HAS_IMAGEHASH = True
except ImportError:
    HAS_IMAGEHASH = False

logger = logging.getLogger("keikai.visual_corpus")

# In-memory visual corpus index
_VISUAL_CORPUS_INDEX: List[Dict[str, Any]] = []


def index_reference_logo(brand: str, logo_path: str, metadata: Optional[Dict[str, Any]] = None) -> bool:
    """
    Indexes a reference logo's pHash and dHash into the Visual Intelligence Corpus.
    """
    if not HAS_IMAGEHASH or not logo_path or not os.path.exists(logo_path):
        return False

    try:
        from services.imagehash_service import compute_image_hashes
        hashes = compute_image_hashes(logo_path)
        record = {
            "id": f"corpus_{len(_VISUAL_CORPUS_INDEX)+1}",
            "brand": brand,
            "logo_path": logo_path,
            "phash_str": hashes.get("phash_str"),
            "dhash_str": hashes.get("dhash_str"),
            "metadata": metadata or {}
        }
        _VISUAL_CORPUS_INDEX.append(record)
        return True
    except Exception as e:
        logger.warning(f"[VisualCorpus] Failed to index logo {logo_path}: {e}")
        return False


def query_visual_corpus(
    target_phash_str: str,
    target_dhash_str: Optional[str] = None,
    phash_max_distance: int = 25,
    top_k: int = 10
) -> List[Dict[str, Any]]:
    """
    Stage 1 Cheap Retrieval: Queries the indexed visual corpus using pHash Hamming distance.
    Returns nearest visual candidates sorted by distance.
    """
    if not HAS_IMAGEHASH or not target_phash_str or not _VISUAL_CORPUS_INDEX:
        return []

    results = []
    try:
        t_ph = imagehash.hex_to_hash(target_phash_str)
        t_dh = imagehash.hex_to_hash(target_dhash_str) if target_dhash_str else None

        for item in _VISUAL_CORPUS_INDEX:
            c_ph_str = item.get("phash_str")
            if not c_ph_str:
                continue

            c_ph = imagehash.hex_to_hash(c_ph_str)
            p_dist = int(t_ph - c_ph)

            d_dist = None
            if t_dh and item.get("dhash_str"):
                c_dh = imagehash.hex_to_hash(item["dhash_str"])
                d_dist = int(t_dh - c_dh)

            if p_dist <= phash_max_distance:
                match_level = "VERY_HIGH" if p_dist <= 10 else ("HIGH" if p_dist <= 15 else "MODERATE")
                results.append({
                    "corpus_item": item,
                    "phash_distance": p_dist,
                    "dhash_distance": d_dist,
                    "match_level": match_level
                })

        # Sort by pHash distance ascending
        results.sort(key=lambda x: x["phash_distance"])
        return results[:top_k]

    except Exception as e:
        logger.error(f"[VisualCorpus] Visual corpus query error: {e}")
        return []


def get_corpus_size() -> int:
    return len(_VISUAL_CORPUS_INDEX)
