import json
from typing import Dict, Any, List, Set, Tuple, Optional
from database import insert_scanned_asset, fetch_all_assets

HIGH_CARDINALITY_IP_THRESHOLD = 10


def index_domain_scan_results(domain: str, permutations: List[Dict[str, Any]], target_brand: Optional[str] = None):
    """
    Background worker indexing scanned domain permutations and IP addresses.
    Derives target_brand from root domain if unspecified (e.g. amazon.com -> Amazon).
    """
    if not target_brand and domain:
        clean_d = domain.replace("https://", "").replace("http://", "").split("/")[0]
        parts = clean_d.split(".")
        if len(parts) >= 2:
            target_brand = parts[-2].capitalize()
        else:
            target_brand = clean_d.capitalize()

    for item in permutations:
        perm_domain = item.get("domain")
        if not perm_domain:
            continue

        dns_a = item.get("dns_a")
        ip = None
        if isinstance(dns_a, list) and len(dns_a) > 0:
            ip = dns_a[0]
        elif isinstance(dns_a, str):
            ip = dns_a

        fuzzer = item.get("fuzzer", "unknown")
        sources = item.get("sources", ["dnstwist"])
        is_known_phishing = item.get("is_known_phishing", False)
        provenance = item.get("provenance", {})

        insert_scanned_asset(
            asset_type="domain",
            asset_id=perm_domain,
            ip_address=ip if ip and ip != "—" else None,
            target_brand=target_brand,
            confidence=90.0 if is_known_phishing else 50.0,
            metadata={
                "fuzzer": fuzzer,
                "original_domain": domain,
                "dns_a": dns_a,
                "sources": sources,
                "is_known_phishing": is_known_phishing,
                "provenance": provenance
            }
        )


def index_logo_batch_results(reference_filename: str, candidate_results: List[Dict[str, Any]]):
    """
    Background worker indexing logo match candidate hashes.
    """
    for item in candidate_results:
        cand_name = item.get("candidate_filename")
        if not cand_name:
            continue

        phash_dist = item.get("phash_distance")
        sim = item.get("combined_similarity_percentage")
        insert_scanned_asset(
            asset_type="logo",
            asset_id=cand_name,
            phash=str(phash_dist) if phash_dist is not None else None,
            metadata={"reference_filename": reference_filename, "phash_distance": phash_dist, "similarity": sim}
        )


def index_visual_phishing_result(url: str, verdict: str, target_brand: str, confidence: float):
    """
    Background worker indexing visual phishing check results.
    """
    insert_scanned_asset(
        asset_type="visual_phishing",
        asset_id=url,
        target_brand=target_brand if target_brand and target_brand != "None" and "Fallback" not in target_brand else None,
        confidence=confidence,
        metadata={"verdict": verdict}
    )


def get_excluded_high_cardinality_ips(assets: List[Dict[str, Any]]) -> Set[str]:
    """
    Identifies IP addresses that appear on >= 10 distinct assets (e.g. Cloudflare CDNs, shared hosting).
    """
    ip_counts: Dict[str, Set[str]] = {}
    for a in assets:
        ip = a.get("ip_address")
        if ip and ip != "—":
            ip_counts.setdefault(ip, set()).add(a["asset_id"])

    excluded = set()
    for ip, asset_set in ip_counts.items():
        if len(asset_set) >= HIGH_CARDINALITY_IP_THRESHOLD:
            excluded.add(ip)
    return excluded


def generate_plain_language_summary(
    ip_assets: List[Dict[str, Any]],
    ips: Set[str],
    unique_brands: Set[str],
    unique_hashes: Set[str]
) -> str:
    """
    Generates a dynamically constructed, plain-language summary for an infrastructure cluster
    based on its actual asset list and shared fingerprints.
    """
    total_count = len(ip_assets)
    asset_ids = [a["asset_id"] for a in ip_assets]
    
    # Form preview list
    if len(asset_ids) <= 3:
        id_preview = ", ".join(asset_ids)
    else:
        id_preview = f"{', '.join(asset_ids[:3])}, and {len(asset_ids) - 3} other properties"

    # Identify asset types
    type_counts = {}
    for a in ip_assets:
        atype = a.get("asset_type", "asset")
        type_counts[atype] = type_counts.get(atype, 0) + 1

    type_strings = []
    if type_counts.get("domain"):
        type_strings.append(f"{type_counts['domain']} domain(s)")
    if type_counts.get("logo"):
        type_strings.append(f"{type_counts['logo']} logo match(es)")
    if type_counts.get("visual_phishing"):
        type_strings.append(f"{type_counts['visual_phishing']} visual check(s)")
    if type_counts.get("listing"):
        type_strings.append(f"{type_counts['listing']} marketplace listing(s)")
    if type_counts.get("social_profile"):
        type_strings.append(f"{type_counts['social_profile']} social profile(s)")

    asset_type_desc = ", ".join(type_strings) if type_strings else f"{total_count} properties"

    # Fingerprint clauses
    fp_clauses = []
    if ips:
        ip_str = ", ".join(ips)
        fp_clauses.append(f"are hosted on the same server IP ({ip_str})")
    if unique_brands:
        brand_str = ", ".join(unique_brands)
        fp_clauses.append(f"target brand '{brand_str}'")
    if unique_hashes:
        fp_clauses.append("share identical perceptual image/logo hashes")

    if not fp_clauses:
        fp_clauses.append("share technical infrastructure attributes")

    fp_str = " and ".join(fp_clauses)

    return (
        f"{total_count} assets ({asset_type_desc}: {id_preview}) {fp_str} - "
        f"this pattern indicates they are likely operated by the same threat actor."
    )


def find_linked_infrastructure(
    evidence_domains: List[Dict[str, Any]],
    evidence_logos: List[Dict[str, Any]],
    evidence_visual_phishing: List[Dict[str, Any]]
) -> Dict[str, Any]:
    """
    Given active case evidence items, queries SQLite for other scanned assets sharing technical fingerprints.
    Filters out high-cardinality shared hosting IPs.
    """
    all_stored = fetch_all_assets()
    excluded_ips = get_excluded_high_cardinality_ips(all_stored)

    linked_map: Dict[str, Dict[str, Any]] = {}

    target_ips: Set[str] = set()
    target_brands: Set[str] = set()
    target_phashes: Set[str] = set()

    evidence_asset_ids = set()

    for dom in evidence_domains:
        evidence_asset_ids.add(dom.get("domain"))
        dns_a = dom.get("dns_a")
        if isinstance(dns_a, list) and len(dns_a) > 0:
            ip = dns_a[0]
            if ip not in excluded_ips:
                target_ips.add(ip)
        elif isinstance(dns_a, str) and dns_a != "—" and dns_a not in excluded_ips:
            target_ips.add(dns_a)

    for logo in evidence_logos:
        evidence_asset_ids.add(logo.get("candidate_filename"))
        phash = logo.get("phash_distance")
        if phash is not None:
            target_phashes.add(str(phash))

    for vp in evidence_visual_phishing:
        evidence_asset_ids.add(vp.get("url"))
        brand = vp.get("target_brand")
        if brand and brand != "None" and "Fallback" not in brand:
            target_brands.add(brand.lower())

    for asset in all_stored:
        if asset["asset_id"] in evidence_asset_ids:
            continue

        matched_signals = []

        if asset["ip_address"] and asset["ip_address"] in target_ips and asset["ip_address"] not in excluded_ips:
            matched_signals.append(f"Same Hosting IP ({asset['ip_address']})")

        if asset["target_brand"] and asset["target_brand"].lower() in target_brands:
            matched_signals.append(f"Same Target Brand ({asset['target_brand']})")

        if asset["phash"] and asset["phash"] in target_phashes:
            matched_signals.append(f"Same Logo Hash (pHash dist {asset['phash']})")

        if matched_signals:
            asset_key = f"{asset['asset_type']}:{asset['asset_id']}"
            linked_map[asset_key] = {
                "asset_type": asset["asset_type"],
                "asset_id": asset["asset_id"],
                "ip_address": asset["ip_address"],
                "target_brand": asset["target_brand"],
                "matched_signals": matched_signals,
                "overlap_count": len(matched_signals),
                "created_at": asset["created_at"]
            }

    linked_list = list(linked_map.values())
    linked_list.sort(key=lambda x: -x["overlap_count"])

    return {
        "total_linked_assets": len(linked_list),
        "linked_assets": linked_list
    }


def get_offender_clusters(brand: Optional[str] = None, case_id: Optional[str] = None) -> Dict[str, Any]:
    """
    Groups assets in SQLite database into offender infrastructure clusters.
    Supports optional brand or case filtering to isolate active case clusters.
    """
    assets = fetch_all_assets()
    if not assets:
        return {"total_clusters": 0, "clusters": []}

    excluded_ips = get_excluded_high_cardinality_ips(assets)

    ip_groups: Dict[str, List[Dict[str, Any]]] = {}
    brand_groups: Dict[str, List[Dict[str, Any]]] = {}
    phash_groups: Dict[str, List[Dict[str, Any]]] = {}

    for a in assets:
        ip = a.get("ip_address")
        if ip and ip != "—" and ip not in excluded_ips:
            ip_groups.setdefault(ip, []).append(a)
        if a.get("target_brand"):
            brand_groups.setdefault(a["target_brand"].lower(), []).append(a)
        ph = a.get("phash")
        if ph and ph != "0000000000000000":
            phash_groups.setdefault(ph, []).append(a)

    clusters = []
    seen_cluster_asset_sets = set()

    candidate_groups = list(ip_groups.values()) + list(phash_groups.values())

    for ip_assets in candidate_groups:
        if len(ip_assets) >= 2:
            asset_set_key = tuple(sorted(f"{a['asset_type']}:{a['asset_id']}" for a in ip_assets))
            if asset_set_key in seen_cluster_asset_sets:
                continue
            seen_cluster_asset_sets.add(asset_set_key)

            signal_types: Set[str] = set()
            shared_signals = []

            ips = set(a["ip_address"] for a in ip_assets if a.get("ip_address") and a.get("ip_address") != "—")
            if ips:
                signal_types.add("IP")
                shared_signals.append(f"Shared Hosting IP ({', '.join(ips)})")

            unique_brands = set(a["target_brand"] for a in ip_assets if a.get("target_brand"))
            if unique_brands:
                signal_types.add("BRAND")
                shared_signals.append(f"Shared Target Brand ({', '.join(unique_brands)})")

            unique_hashes = set(a["phash"] for a in ip_assets if a.get("phash"))
            if unique_hashes:
                signal_types.add("LOGO")
                shared_signals.append(f"Shared Logo Hash")

            num_distinct_signals = len(signal_types)

            # Strict Confidence Rules
            if num_distinct_signals >= 3:
                confidence = "High"
                score = 92
            elif num_distinct_signals == 2:
                confidence = "Medium"
                score = 70
            else:
                confidence = "Low"
                score = 40

            domain_count = sum(1 for a in ip_assets if a["asset_type"] == "domain")
            logo_count = sum(1 for a in ip_assets if a["asset_type"] == "logo")
            phish_count = sum(1 for a in ip_assets if a["asset_type"] == "visual_phishing")
            listing_count = sum(1 for a in ip_assets if a["asset_type"] == "listing")
            social_count = sum(1 for a in ip_assets if a["asset_type"] == "social_profile")

            summary_parts = []
            if domain_count > 0:
                summary_parts.append(f"{domain_count} domain scan(s)")
            if logo_count > 0:
                summary_parts.append(f"{logo_count} logo match(es)")
            if phish_count > 0:
                summary_parts.append(f"{phish_count} visual check(s)")
            if listing_count > 0:
                summary_parts.append(f"{listing_count} marketplace listing(s)")
            if social_count > 0:
                summary_parts.append(f"{social_count} social profile(s)")

            data_sources_summary = f"Derived from {', '.join(summary_parts)}" if summary_parts else "Derived from real scan data"

            # Dynamic Plain-Language Summary Generation
            plain_summary = generate_plain_language_summary(ip_assets, ips, unique_brands, unique_hashes)

            # Build Graph Nodes & Edges
            nodes = []
            edges = []
            seen_nodes = set()

            for a in ip_assets:
                node_id = f"{a['asset_type']}:{a['asset_id']}"
                if node_id not in seen_nodes:
                    seen_nodes.add(node_id)
                    nodes.append({
                        "id": node_id,
                        "label": a["asset_id"],
                        "type": a["asset_type"],
                        "ip": a["ip_address"]
                    })

            for i in range(len(nodes)):
                for j in range(i + 1, len(nodes)):
                    relationship_label = f"Same Hosting IP ({', '.join(ips)})" if ips else f"Same Fingerprint"
                    edges.append({
                        "source": nodes[i]["id"],
                        "target": nodes[j]["id"],
                        "relationship": relationship_label
                    })

            # Check if this cluster matches requested brand filter
            cluster_brands = set(b.lower() for b in unique_brands)
            for a in ip_assets:
                if a.get("metadata") and isinstance(a["metadata"], dict):
                    orig_d = a["metadata"].get("original_domain", "")
                    if orig_d:
                        cluster_brands.add(orig_d.split(".")[0].lower())
                if a["asset_id"]:
                    cluster_brands.add(a["asset_id"].split(".")[0].lower())

            matches_requested_brand = False
            if brand:
                clean_brand = brand.strip().lower()
                matches_requested_brand = any(clean_brand in b for b in cluster_brands)

            clusters.append({
                "cluster_id": "",  # Will be assigned after sorting/filtering
                "asset_count": len(nodes),
                "confidence": confidence,
                "confidence_score": score,
                "num_distinct_signals": num_distinct_signals,
                "shared_signals": shared_signals,
                "data_sources_summary": data_sources_summary,
                "plain_language_summary": plain_summary,
                "matches_requested_brand": matches_requested_brand,
                "source_counts": {
                    "domain_scans": domain_count,
                    "logo_matches": logo_count,
                    "visual_checks": phish_count,
                    "marketplace_listings": listing_count,
                    "social_profiles": social_count
                },
                "assets": [
                    {
                        "asset_type": a["asset_type"],
                        "asset_id": a["asset_id"],
                        "ip_address": a["ip_address"],
                        "target_brand": a["target_brand"],
                        "domain": a["asset_id"] if a["asset_type"] == "domain" else None
                    }
                    for a in ip_assets
                ],
                "nodes": nodes,
                "edges": edges
            })

    # Sort clusters: matching brand clusters first, then by confidence score
    if brand:
        clusters.sort(key=lambda c: (not c["matches_requested_brand"], -c["confidence_score"], -c["asset_count"]))
    else:
        clusters.sort(key=lambda c: (-c["confidence_score"], -c["asset_count"]))

    # Assign dynamic sequential cluster IDs
    for idx, cl in enumerate(clusters, start=1):
        cl["cluster_id"] = f"CLUSTER-{idx:03d}"

    return {
        "total_clusters": len(clusters),
        "filter_brand": brand,
        "excluded_high_cardinality_ips": list(excluded_ips),
        "clusters": clusters
    }


def get_domain_intelligence(
    domain: str,
    official_domain: Optional[str] = None,
    authorized_domains: Optional[List[str]] = None,
    evidence_score: float = 85.0,
    use_cache: bool = True
) -> Dict[str, Any]:
    """
    TASK 3D — Unified Domain & Abuse Target Intelligence Service.
    Combines RDAP registration, DNS + IP Infrastructure, ASN + Hosting Provider Intelligence,
    Legitimacy Gate evaluation, and Abuse Reporting Target Resolution.
    """
    from services.dns_intelligence_service import resolve_dns_records
    from services.rdap_service import fetch_rdap_data
    from services.asn_intelligence_service import lookup_ip_asn
    from services.abuse_target_service import resolve_abuse_targets

    dns_res = resolve_dns_records(domain, use_cache=use_cache)
    rdap_res = fetch_rdap_data(domain, use_cache=use_cache)

    raw_ips = dns_res.get("resolved_ips", [])
    enriched_ips = []
    primary_asn_data = None

    for ip_entry in raw_ips:
        ip_val = ip_entry.get("ip")
        if ip_val:
            asn_info = lookup_ip_asn(ip_val, use_cache=use_cache)
            merged_ip = {**ip_entry, **asn_info}
            enriched_ips.append(merged_ip)
            if not primary_asn_data and asn_info.get("status") == "ASN_SUCCESS":
                primary_asn_data = asn_info

    dns_res["resolved_ips"] = enriched_ips

    # Unified Abuse Target Resolution
    target_res = resolve_abuse_targets(
        domain=domain,
        official_domain=official_domain,
        authorized_domains=authorized_domains,
        evidence_score=evidence_score,
        dns_data=dns_res,
        rdap_data=rdap_res,
        use_cache=use_cache
    )

    return {
        "domain": dns_res.get("domain", domain),
        "dns_status": dns_res.get("dns_status", "DNS_ERROR"),
        "dns_intelligence": dns_res.get("dns_intelligence", {
            "a": [], "aaaa": [], "cname": [], "mx": [], "ns": []
        }),
        "resolved_ips": enriched_ips,
        "reverse_dns": dns_res.get("reverse_dns", []),
        "rdap": rdap_res,
        "primary_asn": primary_asn_data,
        "reporting_targets": target_res.get("abuse_targets"),
        "abuse_targets": target_res.get("abuse_targets"),
        "legitimacy_gate": target_res.get("legitimacy_gate"),
        "reporting_readiness": target_res.get("reporting_readiness"),
        "lookup_timestamp": dns_res.get("lookup_timestamp")
    }

