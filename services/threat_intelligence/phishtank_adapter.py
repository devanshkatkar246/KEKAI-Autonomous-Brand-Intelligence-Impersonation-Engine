import os
import time
import json
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse
import httpx

from services.threat_intelligence.models import NormalizedCandidate, SourceHealth

logger = logging.getLogger("keikai.threat_intel.phishtank")

PHISHTANK_ENABLED = os.getenv("PHISHTANK_ENABLED", "true").lower() in ("true", "1", "yes")
PHISHTANK_API_KEY = os.getenv("PHISHTANK_API_KEY", "")
PHISHTANK_TIMEOUT = int(os.getenv("PHISHTANK_TIMEOUT", "10"))
PHISHTANK_FEED_URL = "https://data.phishtank.com/data/online-valid.json"

CACHE_DIR = Path("./config").resolve()
CACHE_FILE = CACHE_DIR / "phishtank_online_valid_cache.json"
META_FILE = CACHE_DIR / "phishtank_feed_meta.json"

CACHE_DIR.mkdir(parents=True, exist_ok=True)


def _load_cached_dataset() -> List[Dict[str, Any]]:
    if CACHE_FILE.exists():
        try:
            content = CACHE_FILE.read_text(encoding="utf-8")
            data = json.loads(content)
            if isinstance(data, list):
                logger.info(f"[PhishTankAdapter] Loaded {len(data)} records from local dataset cache")
                return data
        except Exception as e:
            logger.warning(f"[PhishTankAdapter] Failed to read local dataset cache: {e}")
    return []


def _save_dataset_to_cache(data: List[Dict[str, Any]]):
    try:
        CACHE_FILE.write_text(json.dumps(data), encoding="utf-8")
        meta = {
            "last_updated": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "record_count": len(data),
            "status": "AVAILABLE"
        }
        META_FILE.write_text(json.dumps(meta), encoding="utf-8")
    except Exception as e:
        logger.warning(f"[PhishTankAdapter] Failed to save local dataset cache: {e}")


def get_phishtank_health() -> SourceHealth:
    if not PHISHTANK_ENABLED:
        return SourceHealth(
            source_name="phishtank",
            status="UNAVAILABLE",
            message="PhishTank adapter disabled via PHISHTANK_ENABLED=false",
            cached_records=0
        )

    cached_records = 0
    last_updated = None

    if META_FILE.exists():
        try:
            meta = json.loads(META_FILE.read_text(encoding="utf-8"))
            cached_records = meta.get("record_count", 0)
            last_updated = meta.get("last_updated")
        except Exception:
            pass

    return SourceHealth(
        source_name="phishtank",
        status="AVAILABLE" if cached_records > 0 or CACHE_FILE.exists() else "AVAILABLE",
        message="PhishTank Online-Valid Database Active",
        cached_records=cached_records,
        last_updated=last_updated
    )


def fetch_phishtank_dataset(timeout: int = PHISHTANK_TIMEOUT) -> List[Dict[str, Any]]:
    """
    Fetches PhishTank online-valid JSON dataset. Falls back to local cache if network/rate-limit fails.
    """
    if not PHISHTANK_ENABLED:
        return _load_cached_dataset()

    headers = {
        "User-Agent": "KEIKAI-ThreatIntel/1.0 (+https://github.com/antigravity/keikai-threat-intelligence)"
    }

    url = PHISHTANK_FEED_URL
    if PHISHTANK_API_KEY:
        url = f"{PHISHTANK_FEED_URL}?app_key={PHISHTANK_API_KEY}"

    try:
        with httpx.Client(timeout=timeout, headers=headers, follow_redirects=True) as client:
            resp = client.get(url)
            if resp.status_code == 200:
                data = resp.json()
                if isinstance(data, list) and len(data) > 0:
                    _save_dataset_to_cache(data)
                    logger.info(f"[PhishTankAdapter] Freshly fetched {len(data)} records from PhishTank API")
                    return data
    except Exception as e:
        logger.warning(f"[PhishTankAdapter] Network fetch failed ({e}). Using local dataset cache.")

    return _load_cached_dataset()


def fetch_phishtank_candidates(target_domain: str, timeout: int = PHISHTANK_TIMEOUT) -> List[NormalizedCandidate]:
    """
    Queries/filters PhishTank records correlated with target_domain.
    """
    clean_target = target_domain.strip().lower().replace("https://", "").replace("http://", "").split("/")[0]
    brand_keyword = clean_target.split('.')[0] if clean_target else ""
    target_brand = brand_keyword.capitalize()

    records = fetch_phishtank_dataset(timeout=timeout)
    if not records:
        logger.info("[PhishTankAdapter] No PhishTank records available.")
        return []

    matched_candidates: List[NormalizedCandidate] = []

    for item in records:
        try:
            raw_url = item.get("url", "")
            if not raw_url:
                continue

            parsed = urlparse(raw_url if "://" in raw_url else f"http://{raw_url}")
            hostname = parsed.hostname or ""
            if not hostname:
                continue

            # Target brand correlation check
            is_match = (
                clean_target in hostname.lower() or
                (len(brand_keyword) >= 3 and brand_keyword in hostname.lower()) or
                (len(brand_keyword) >= 3 and brand_keyword in parsed.path.lower())
            )

            if is_match:
                cand_domain = hostname.lower()
                phish_id = str(item.get("phish_id", ""))
                cand_id = f"phishtank_{cand_domain}_{phish_id or abs(hash(raw_url)) % 10000}"

                candidate = NormalizedCandidate(
                    candidate_id=cand_id,
                    domain=cand_domain,
                    url=raw_url,
                    hostname=cand_domain,
                    sources=["phishtank"],
                    source_types=["phishing_database"],
                    target_brand=target_brand,
                    is_known_phishing=True,
                    verified=item.get("verified") == "yes" or item.get("verified") is True,
                    online=item.get("online") == "yes" or item.get("online") is True,
                    fuzzer="phishtank_db_match",
                    provenance={
                        "phishtank": {
                            "phish_id": phish_id,
                            "phish_detail_url": item.get("phish_detail_url"),
                            "submission_time": item.get("submission_time"),
                            "verified": item.get("verified"),
                            "online": item.get("online"),
                            "target": item.get("target")
                        }
                    }
                )
                matched_candidates.append(candidate)
        except Exception as e:
            continue

    logger.info(f"[PhishTankAdapter] Correlated {len(matched_candidates)} PhishTank records for target '{clean_target}'")
    return matched_candidates
