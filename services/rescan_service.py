import socket
import datetime
from typing import Dict, Any, List
from database import insert_scanned_asset, log_case_event, get_db_connection


def resolve_domain_ip(domain: str) -> List[str]:
    """
    Attempts to resolve domain A records using Python's socket library.
    """
    try:
        ip = socket.gethostbyname(domain)
        return [ip] if ip else []
    except Exception:
        return []


def rescan_case_evidence(
    case_id: str,
    evidence_domains: List[Dict[str, Any]],
    evidence_logos: List[Dict[str, Any]],
    evidence_visual_phishing: List[Dict[str, Any]]
) -> Dict[str, Any]:
    """
    Re-scans case evidence, diffing live DNS state against stored evidence.
    """
    timestamp_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    diffs = []
    updated_domains = []
    changes_detected = False

    for dom in evidence_domains:
        domain_name = dom.get("domain")
        if not domain_name:
            continue

        orig_registered = dom.get("isRegistered", False) or bool(dom.get("dns_a"))
        orig_ips = dom.get("dns_a", [])
        if isinstance(orig_ips, str):
            orig_ips = [orig_ips] if orig_ips != "—" else []

        live_ips = resolve_domain_ip(domain_name)
        live_registered = len(live_ips) > 0

        updated_dom = dict(dom)
        updated_dom["dns_a"] = live_ips if live_ips else orig_ips
        updated_dom["isRegistered"] = live_registered or orig_registered

        # Check for diff 1: Unregistered domain is now registered
        if not orig_registered and live_registered:
            changes_detected = True
            diffs.append({
                "domain": domain_name,
                "field": "registered",
                "old": "UNREGISTERED",
                "new": "REGISTERED",
                "details": f"New A record {live_ips[0]} detected"
            })
            updated_dom["riskScore"] = 90

        # Check for diff 2: IP address changed
        elif orig_ips and live_ips and orig_ips[0] != live_ips[0]:
            changes_detected = True
            diffs.append({
                "domain": domain_name,
                "field": "dns_a",
                "old": orig_ips[0],
                "new": live_ips[0],
                "details": f"DNS A record changed from {orig_ips[0]} to {live_ips[0]}"
            })

        # Update SQLite asset database with latest fingerprint
        insert_scanned_asset(
            asset_type="domain",
            asset_id=domain_name,
            ip_address=live_ips[0] if live_ips else (orig_ips[0] if orig_ips else None),
            metadata={"rescan_timestamp": timestamp_str, "live_registered": live_registered}
        )

        updated_domains.append(updated_dom)

    # Log case timeline event
    log_desc = f"Case re-scan executed at {timestamp_str}. "
    if changes_detected:
        log_desc += f"NEW ACTIVITY DETECTED: {len(diffs)} change(s) found across evidence."
    else:
        log_desc += "Re-scan complete — no infrastructure state changes detected."

    log_case_event(case_id, "case_rescan", log_desc, metadata={"changes_detected": changes_detected, "diff_count": len(diffs)})

    return {
        "case_id": case_id,
        "last_checked": timestamp_str,
        "new_activity_detected": changes_detected,
        "total_changes": len(diffs),
        "diffs": diffs,
        "updated_domains": updated_domains
    }
