"""RDAP-first registration intelligence; no reporting or provider contact occurs here."""
import json
import logging
import socket
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from services.dnstwist_service import clean_domain_name
from services.rdap_service import fetch_rdap_data

logger = logging.getLogger(__name__)
_CACHE: Dict[str, Tuple[float, Dict[str, Any]]] = {}
_TTL = 600

def clear_registration_cache(): _CACHE.clear()
def _now(): return datetime.now(timezone.utc).isoformat()

def registrable_domain(value: str) -> Dict[str, str]:
    """Keeps hostname evidence; uses the existing normalizer for lookup target.
    The project has no public-suffix dependency, so unknown multi-label suffixes
    are intentionally not guessed beyond the common country-code form.
    """
    raw = str(value or "").strip().lower().split('://')[-1].split('/')[0].split(':')[0]
    hostname = clean_domain_name(value) if '.' in raw else ""
    labels = hostname.split('.')
    suffix_len = 2 if len(labels) >= 3 and len(labels[-1]) == 2 and len(labels[-2]) <= 3 else 1
    domain = '.'.join(labels[-(suffix_len + 1):]) if len(labels) > suffix_len else hostname
    return {"original": value, "hostname": hostname, "registrable_domain": domain}

def _vcard(entity: Dict[str, Any]) -> Dict[str, List[str]]:
    values = {"fn": [], "email": [], "tel": []}
    card = entity.get("vcardArray", [])
    if len(card) > 1:
        for item in card[1]:
            if item and item[0] in values and len(item) > 3 and item[3]: values[item[0]].append(str(item[3]))
    return values

def _walk_entities(entities: List[Dict[str, Any]]):
    for entity in entities or []:
        yield entity
        yield from _walk_entities(entity.get("entities", []))

def parse_rdap_registration(domain: str, raw: Dict[str, Any], endpoint: str = "https://rdap.org/domain/{domain}") -> Dict[str, Any]:
    registrar = None; abuse_emails = []; abuse_phones = []
    for entity in _walk_entities(raw.get("entities", [])):
        roles = {str(role).lower() for role in entity.get("roles", [])}; card = _vcard(entity)
        if "registrar" in roles:
            registrar = {"name": (card["fn"] or [None])[0], "iana_id": entity.get("publicIds", [{}])[0].get("identifier") if entity.get("publicIds") else entity.get("handle"), "abuse_email": None, "abuse_phone": None}
        if "abuse" in roles:
            abuse_emails.extend(card["email"]); abuse_phones.extend(card["tel"])
    if registrar:
        registrar["abuse_email"] = abuse_emails[0] if abuse_emails else None
        registrar["abuse_phone"] = abuse_phones[0] if abuse_phones else None
    events = {str(item.get("eventAction", "")).lower(): item.get("eventDate") for item in raw.get("events", [])}
    nameservers = sorted({str(item.get("ldhName", "")).lower().rstrip('.') for item in raw.get("nameservers", []) if item.get("ldhName")})
    contact_state = "VERIFIED" if abuse_emails and abuse_phones else "PARTIAL" if abuse_emails or abuse_phones else "UNAVAILABLE"
    target = {"type": "REGISTRAR", "name": registrar.get("name") if registrar else None, "iana_id": registrar.get("iana_id") if registrar else None, "abuse_email": abuse_emails, "abuse_phone": abuse_phones, "source": "RDAP", "verification": contact_state}
    return {"domain": domain, "source": "RDAP", "source_status": "SUCCESS", "source_endpoint": endpoint.format(domain=domain), "queried_at": _now(), "fallback_reason": None,
            "registrar": registrar, "abuse_contact": {"emails": abuse_emails, "phones": abuse_phones, "state": contact_state},
            "registration": {"created_at": events.get("registration") or events.get("created"), "updated_at": events.get("last changed") or events.get("last update"), "expires_at": events.get("expiration")},
            "domain_status": raw.get("status", []), "nameservers": nameservers, "registration_target": target,
            "raw_reference": {"type": "RDAP", "available": True}}

def _whois_lookup(domain: str, timeout: float = 5.0) -> str:
    """Bounded TCP WHOIS lookup; response is data only and is never executed."""
    with socket.create_connection(("whois.iana.org", 43), timeout=timeout) as conn:
        conn.sendall((domain + "\r\n").encode("ascii", "ignore"))
        return conn.recv(65536).decode("utf-8", "replace")

def _parse_whois(domain: str, text: str, fallback_reason: str) -> Dict[str, Any]:
    fields: Dict[str, List[str]] = {}
    for line in text.splitlines():
        if ':' in line:
            key, value = line.split(':', 1); fields.setdefault(key.strip().lower(), []).append(value.strip())
    get = lambda *keys: next((fields[k][0] for k in keys if fields.get(k)), None)
    emails = fields.get('registrar abuse contact email', [])
    phones = fields.get('registrar abuse contact phone', [])
    registrar = get('registrar', 'registrar name')
    state = 'VERIFIED' if emails and phones else 'PARTIAL' if emails or phones else 'UNAVAILABLE'
    return {"domain": domain, "source": "WHOIS", "source_status": "SUCCESS", "source_endpoint": "whois.iana.org:43", "queried_at": _now(), "fallback_reason": fallback_reason,
            "registrar": {"name": registrar, "iana_id": get('registrar iana id', 'registrar ianaid'), "abuse_email": emails[0] if emails else None, "abuse_phone": phones[0] if phones else None} if registrar else None,
            "abuse_contact": {"emails": emails, "phones": phones, "state": state}, "registration": {"created_at": get('creation date', 'created date'), "updated_at": get('updated date'), "expires_at": get('registry expiry date', 'expiration date')},
            "domain_status": fields.get('domain status', []), "nameservers": sorted({item.lower().rstrip('.') for item in fields.get('name server', [])}),
            "registration_target": {"type": "REGISTRAR", "name": registrar, "iana_id": get('registrar iana id'), "abuse_email": emails, "abuse_phone": phones, "source": "WHOIS", "verification": state}, "raw_reference": {"type": "WHOIS", "available": True}}

def get_registration_intelligence(value: str, use_cache: bool = True) -> Dict[str, Any]:
    normalized = registrable_domain(value); domain = normalized["registrable_domain"]
    if not domain or '.' not in domain:
        return {"domain": domain, "source": "RDAP", "source_status": "INVALID_DOMAIN", "queried_at": _now(), "registration_target": None}
    cached = _CACHE.get(domain)
    if use_cache and cached and time.time() - cached[0] < _TTL: return cached[1]
    rdap = fetch_rdap_data(domain, use_cache=use_cache)
    if rdap.get('status') == 'RDAP_SUCCESS' and isinstance(rdap.get('raw_rdap'), dict): result = parse_rdap_registration(domain, rdap['raw_rdap'])
    elif rdap.get('status') in {'RDAP_NOT_FOUND'}: result = {"domain": domain, "source": "RDAP", "source_status": "RDAP_NOT_FOUND", "queried_at": _now(), "registration_target": None}
    elif rdap.get('status') in {'RDAP_UNAVAILABLE'}:
        result = {"domain": domain, "source": "RDAP", "source_status": "RDAP_NETWORK_ERROR", "queried_at": _now(), "registration_target": None}
    else: result = {"domain": domain, "source": "RDAP", "source_status": rdap.get('status', 'RDAP_INVALID_RESPONSE'), "queried_at": _now(), "registration_target": None}
    if result['source_status'] in {'RDAP_NOT_FOUND', 'RDAP_UNSUPPORTED'}:
        try: result = _parse_whois(domain, _whois_lookup(domain), result['source_status'])
        except socket.timeout: result = {**result, "source_status": "WHOIS_TIMEOUT", "fallback_reason": result['source_status']}
        except OSError: result = {**result, "source_status": "WHOIS_UNAVAILABLE", "fallback_reason": result['source_status']}
    result['lookup_target'] = normalized
    if use_cache: _CACHE[domain] = (time.time(), result)
    return result
