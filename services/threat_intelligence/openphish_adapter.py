import os
import time
import json
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse
import httpx

from services.threat_intelligence.models import NormalizedCandidate, SourceHealth

logger = logging.getLogger("keikai.threat_intel.openphish")

OPENPHISH_FEED_URL = "https://openphish.com/feed.txt"
CACHE_DIR = Path("./config").resolve()
CACHE_FILE = CACHE_DIR / "openphish_feed_cache.txt"
META_FILE = CACHE_DIR / "openphish_feed_meta.json"

CACHE_DIR.mkdir(parents=True, exist_ok=True)


def _load_cached_feed() -> List[str]:
    if CACHE_FILE.exists():
        try:
            content = CACHE_FILE.read_text(encoding="utf-8")
            lines = [line.strip() for line in content.splitlines() if line.strip()]
            logger.info(f"[OpenPhishAdapter] Loaded {len(lines)} URLs from local cache file")
            return lines
        except Exception as e:
            logger.warning(f"[OpenPhishAdapter] Failed to read local cache file: {e}")
    return []


def _save_feed_to_cache(urls: List[str]):
    try:
        CACHE_FILE.write_text("\n".join(urls), encoding="utf-8")
        meta = {
            "last_updated": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "record_count": len(urls),
            "status": "AVAILABLE"
        }
        META_FILE.write_text(json.dumps(meta), encoding="utf-8")
    except Exception as e:
        logger.warning(f"[OpenPhishAdapter] Failed to save local cache: {e}")


def get_openphish_health() -> SourceHealth:
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
        source_name="openphish",
        status="AVAILABLE" if cached_records > 0 or CACHE_FILE.exists() else "DEGRADED",
        message="OpenPhish Community Feed Active (Local Cache Fallback Ready)",
        cached_records=cached_records,
        last_updated=last_updated
    )


def fetch_openphish_feed(timeout: int = 8) -> List[str]:
    """
    Fetches OpenPhish Community Feed text file. Falls back to local file cache on network error.
    """
    urls: List[str] = []
    try:
        with httpx.Client(timeout=timeout, headers={"User-Agent": "KEIKAI-ThreatIntel/1.0"}) as client:
            resp = client.get(OPENPHISH_FEED_URL)
            if resp.status_code == 200 and resp.text:
                urls = [line.strip() for line in resp.text.splitlines() if line.strip()]
                if urls:
                    _save_feed_to_cache(urls)
                    logger.info(f"[OpenPhishAdapter] Freshly fetched {len(urls)} URLs from OpenPhish feed")
                    return urls
    except Exception as e:
        logger.warning(f"[OpenPhishAdapter] Network fetch failed ({e}). Using local feed cache.")

    return _load_cached_feed()


def fetch_openphish_candidates(target_domain: str, timeout: int = 8) -> List[NormalizedCandidate]:
    """
    Retrieves OpenPhish feed URLs and correlates them with the target brand/domain.
    """
    clean_target = target_domain.strip().lower().replace("https://", "").replace("http://", "").split("/")[0]
    brand_keyword = clean_target.split('.')[0] if clean_target else ""
    target_brand = brand_keyword.capitalize()

    feed_urls = fetch_openphish_feed(timeout=timeout)
    if not feed_urls:
        logger.info("[OpenPhishAdapter] No feed URLs available.")
        return []

    matched_candidates: List[NormalizedCandidate] = []

    for raw_url in feed_urls:
        try:
            parsed = urlparse(raw_url if "://" in raw_url else f"http://{raw_url}")
            hostname = parsed.hostname or ""
            if not hostname:
                continue

            # Brand/domain correlation check
            is_match = (
                clean_target in hostname.lower() or
                (len(brand_keyword) >= 3 and brand_keyword in hostname.lower()) or
                (len(brand_keyword) >= 3 and brand_keyword in parsed.path.lower())
            )

            if is_match:
                cand_domain = hostname.lower()
                cand_id = f"openphish_{cand_domain}_{abs(hash(raw_url)) % 10000}"

                candidate = NormalizedCandidate(
                    candidate_id=cand_id,
                    domain=cand_domain,
                    url=raw_url,
                    hostname=cand_domain,
                    sources=["openphish"],
                    source_types=["phishing_feed"],
                    target_brand=target_brand,
                    is_known_phishing=True,
                    verified=True,
                    online=True,
                    fuzzer="openphish_feed_match",
                    provenance={
                        "openphish": {
                            "feed_source": "OpenPhish Community Feed",
                            "matched_url": raw_url,
                            "update_frequency": "12 hours",
                            "status": "Verified Phishing Feed Match"
                        }
                    }
                )
                matched_candidates.append(candidate)
        except Exception as e:
            continue

    logger.info(f"[OpenPhishAdapter] Correlated {len(matched_candidates)} OpenPhish records for target '{clean_target}'")
    return matched_candidates
