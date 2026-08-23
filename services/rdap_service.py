"""
services/rdap_service.py

TASK 3B — RDAP Domain Intelligence Service

Fetches domain registration data (registrar, abuse email, creation date, expiration date,
status flags, nameservers, raw RDAP payload) from ICANN RDAP bootstrap endpoints.

Includes in-memory caching and graceful fallback handling.
"""

import logging
import urllib.request
import urllib.error
import json
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple

logger = logging.getLogger(__name__)

_RDAP_CACHE: Dict[str, Tuple[float, Dict[str, Any]]] = {}
_CACHE_TTL_SECONDS = 600  # 10 minutes cache for RDAP


def clear_rdap_cache() -> None:
    """Clears in-memory RDAP cache."""
    _RDAP_CACHE.clear()


def fetch_rdap_data(domain: str, use_cache: bool = True) -> Dict[str, Any]:
    """
    Queries RDAP for registration metadata.
    Returns normalized RDAP dictionary.
    """
    if not domain or not isinstance(domain, str):
        return _build_fallback_rdap(domain, "RDAP_INVALID_INPUT")

    clean_domain = domain.strip().lower().replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]

    now = datetime.now(timezone.utc).timestamp()
    if use_cache and clean_domain in _RDAP_CACHE:
        cached_time, cached_data = _RDAP_CACHE[clean_domain]
        if now - cached_time < _CACHE_TTL_SECONDS:
            return cached_data

    url = f"https://rdap.org/domain/{clean_domain}"
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "KEIKAI-Brand-Protection/1.0", "Accept": "application/rdap+json, application/json"}
    )

    try:
        with urllib.request.urlopen(req, timeout=5.0) as resp:
            if resp.status == 200:
                raw_bytes = resp.read()
                data = json.loads(raw_bytes.decode("utf-8"))
                parsed = _parse_rdap_payload(clean_domain, data)
                if use_cache:
                    _RDAP_CACHE[clean_domain] = (now, parsed)
                return parsed

    except urllib.error.HTTPError as e:
        if e.code == 404:
            res = _build_fallback_rdap(clean_domain, "RDAP_NOT_FOUND")
            if use_cache:
                _RDAP_CACHE[clean_domain] = (now, res)
            return res
        else:
            logger.warning(f"RDAP HTTP {e.code} for {clean_domain}")
    except (urllib.error.URLError, TimeoutError, Exception) as err:
        logger.warning(f"RDAP fetch failed for {clean_domain}: {err}")

    res = _build_fallback_rdap(clean_domain, "RDAP_UNAVAILABLE")
    if use_cache:
        _RDAP_CACHE[clean_domain] = (now, res)
    return res


def _parse_rdap_payload(domain: str, raw: Dict[str, Any]) -> Dict[str, Any]:
    registrar = "Unknown Registrar"
    abuse_email = None
    creation_date = None
    expiration_date = None
    status_flags: List[str] = raw.get("status", [])
    nameservers: List[str] = []

    # Extract entities (Registrar / Abuse Contact)
    entities = raw.get("entities", [])
    for entity in entities:
        roles = entity.get("roles", [])
        if "registrar" in roles:
            vcard = entity.get("vcardArray", [])
            if len(vcard) > 1:
                for entry in vcard[1]:
                    if entry[0] == "fn":
                        registrar = entry[3]
        if "abuse" in roles or "technical" in roles:
            vcard = entity.get("vcardArray", [])
            if len(vcard) > 1:
                for entry in vcard[1]:
                    if entry[0] == "email":
                        abuse_email = entry[3]

    # Extract events (Creation / Expiration)
    events = raw.get("events", [])
    for ev in events:
        action = ev.get("eventAction")
        date = ev.get("eventDate")
        if action in ["registration", "created"]:
            creation_date = date
        elif action in ["expiration"]:
            expiration_date = date

    # Extract nameservers
    ns_entries = raw.get("nameservers", [])
    for ns in ns_entries:
        ldh = ns.get("ldhName")
        if ldh:
            nameservers.append(ldh)

    return {
        "status": "RDAP_SUCCESS",
        "domain": domain,
        "registrar": registrar,
        "abuse_email": abuse_email or "Not Disclosed",
        "creation_date": creation_date or "Unknown",
        "expiration_date": expiration_date or "Unknown",
        "status_flags": status_flags,
        "nameservers": nameservers,
        "raw_rdap": raw
    }


def _build_fallback_rdap(domain: str, status_msg: str) -> Dict[str, Any]:
    return {
        "status": status_msg,
        "domain": domain,
        "registrar": "Unavailable",
        "abuse_email": "Unavailable",
        "creation_date": "Unavailable",
        "expiration_date": "Unavailable",
        "status_flags": [],
        "nameservers": [],
        "raw_rdap": {}
    }
