import sys
import logging
from typing import List, Dict, Any
from services.dnstwist_service import run_dnstwist_scan, clean_domain_name, DNSTwistError
from services.threat_intelligence.models import NormalizedCandidate, SourceHealth

logger = logging.getLogger("keikai.threat_intel.dnstwist")


def get_dnstwist_health() -> SourceHealth:
    """
    Returns health status of the dnstwist discovery engine.
    """
    return SourceHealth(
        source_name="dnstwist",
        status="AVAILABLE",
        message="Subprocess CLI permutation engine active",
        cached_records=0
    )


def fetch_dnstwist_candidates(domain: str, quick_mode: bool = True, timeout: int = 60) -> List[NormalizedCandidate]:
    """
    Runs dnstwist permutation scan and converts permutations to normalized candidates.
    """
    clean_domain = clean_domain_name(domain)
    target_brand = clean_domain.split('.')[0].capitalize() if clean_domain else "Target"

    try:
        raw_permutations = run_dnstwist_scan(domain=clean_domain, quick_mode=quick_mode, timeout=timeout)
    except Exception as e:
        logger.error(f"[DNSTwistAdapter] Error scanning {clean_domain}: {e}")
        return []

    candidates: List[NormalizedCandidate] = []
    for perm in raw_permutations:
        d_name = clean_domain_name(perm.get("domain", ""))
        if not d_name:
            continue

        fuzzer = perm.get("fuzzer", "permutation")
        dns_a = perm.get("dns_a", [])
        if isinstance(dns_a, str):
            dns_a = [dns_a]

        dns_ns = perm.get("dns_ns", [])
        if isinstance(dns_ns, str):
            dns_ns = [dns_ns]

        dns_mx = perm.get("dns_mx", [])
        if isinstance(dns_mx, str):
            dns_mx = [dns_mx]

        candidate = NormalizedCandidate(
            candidate_id=f"dnstwist_{d_name}",
            domain=d_name,
            url=f"http://{d_name}",
            hostname=d_name,
            sources=["dnstwist"],
            source_types=["permutation"],
            target_brand=target_brand,
            is_known_phishing=False,
            verified=False,
            online=len(dns_a) > 0,
            fuzzer=fuzzer,
            ip_addresses=dns_a,
            dns_ns=dns_ns,
            dns_mx=dns_mx,
            banner=perm.get("banner"),
            provenance={
                "dnstwist": {
                    "fuzzer": fuzzer,
                    "dns_a": dns_a,
                    "dns_ns": dns_ns,
                    "dns_mx": dns_mx,
                    "banner": perm.get("banner")
                }
            }
        )
        candidates.append(candidate)

    logger.info(f"[DNSTwistAdapter] Produced {len(candidates)} candidates for {clean_domain}")
    return candidates
