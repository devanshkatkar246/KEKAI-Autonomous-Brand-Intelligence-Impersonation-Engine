import logging
from typing import List, Dict, Any
from services.threat_intelligence.models import NormalizedCandidate, SourceHealth
from services.threat_intelligence.dnstwist_adapter import fetch_dnstwist_candidates, get_dnstwist_health
from services.threat_intelligence.openphish_adapter import fetch_openphish_candidates, get_openphish_health
from services.threat_intelligence.phishtank_adapter import fetch_phishtank_candidates, get_phishtank_health

logger = logging.getLogger("keikai.threat_intel.orchestrator")


class ThreatIntelOrchestrator:
    """
    Unified Candidate Intelligence Orchestration Engine.
    Correlates dnstwist, OpenPhish, and PhishTank into a single deduplicated Candidate Intelligence Pool.
    """

    @staticmethod
    def get_all_sources_health() -> Dict[str, Any]:
        """
        Returns health status for all 3 intelligence sources.
        """
        dnstwist_h = get_dnstwist_health()
        openphish_h = get_openphish_health()
        phishtank_h = get_phishtank_health()

        return {
            "dnstwist": dnstwist_h.model_dump(),
            "openphish": openphish_h.model_dump(),
            "phishtank": phishtank_h.model_dump()
        }

    @classmethod
    def execute_multi_source_scan(
        cls,
        domain: str,
        quick_mode: bool = True,
        timeout: int = 60
    ) -> Dict[str, Any]:
        """
        Executes multi-source discovery layer and returns unified deduplicated candidate pool.
        """
        logger.info(f"[Orchestrator] Starting multi-source threat scan for target: {domain}")

        # 1. Fetch candidates from Source 1 (dnstwist)
        dnstwist_cands = fetch_dnstwist_candidates(domain=domain, quick_mode=quick_mode, timeout=timeout)

        # 2. Fetch candidates from Source 2 (OpenPhish)
        openphish_cands = fetch_openphish_candidates(target_domain=domain, timeout=8)

        # 3. Fetch candidates from Source 3 (PhishTank)
        phishtank_cands = fetch_phishtank_candidates(target_domain=domain, timeout=10)

        # 4. Deduplication & Provenance Merging
        merged_candidates: Dict[str, NormalizedCandidate] = {}

        all_raw_cands = dnstwist_cands + openphish_cands + phishtank_cands

        for cand in all_raw_cands:
            key = cand.domain.lower()

            if key not in merged_candidates:
                merged_candidates[key] = cand
            else:
                existing = merged_candidates[key]
                # Merge sources array without duplicates
                for src in cand.sources:
                    if src not in existing.sources:
                        existing.sources.append(src)

                # Merge source_types array without duplicates
                for st in cand.source_types:
                    if st not in existing.source_types:
                        existing.source_types.append(st)

                # Merge provenance dictionary
                existing.provenance.update(cand.provenance)

                # Merge flags
                existing.is_known_phishing = existing.is_known_phishing or cand.is_known_phishing
                existing.verified = existing.verified or cand.verified
                existing.online = existing.online or cand.online

                if cand.url and not existing.url:
                    existing.url = cand.url

                if cand.banner and not existing.banner:
                    existing.banner = cand.banner

                # Merge IP addresses without duplicates
                for ip in cand.ip_addresses:
                    if ip not in existing.ip_addresses:
                        existing.ip_addresses.append(ip)

                for ns in cand.dns_ns:
                    if ns not in existing.dns_ns:
                        existing.dns_ns.append(ns)

                for mx in cand.dns_mx:
                    if mx not in existing.dns_mx:
                        existing.dns_mx.append(mx)

        candidate_list = list(merged_candidates.values())
        logger.info(f"[Orchestrator] Deduplicated {len(all_raw_cands)} raw records -> {len(candidate_list)} unique candidates for {domain}")

        # Format candidates for backwards-compatible response payload
        formatted_permutations = []
        for c in candidate_list:
            c_dict = c.to_dict()
            formatted_permutations.append({
                "candidate_id": c.candidate_id,
                "fuzzer": c.fuzzer or "permutation",
                "domain": c.domain,
                "url": c.url,
                "hostname": c.hostname,
                "dns_a": c.ip_addresses,
                "dns_ns": c.dns_ns,
                "dns_mx": c.dns_mx,
                "banner": c.banner,
                "sources": c.sources,
                "source_types": c.source_types,
                "is_known_phishing": c.is_known_phishing,
                "verified": c.verified,
                "online": c.online,
                "provenance": c.provenance,
                "discovery_timestamp": c.discovery_timestamp
            })

        sources_health = cls.get_all_sources_health()

        return {
            "target_domain": domain,
            "total_candidates": len(formatted_permutations),
            "sources_health": sources_health,
            "permutations": formatted_permutations
        }
