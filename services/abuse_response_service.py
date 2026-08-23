"""Evidence integrity, legitimacy, and reporting-readiness assessment.

This module is intentionally side-effect free. It never sends a report, email,
or provider request; it converts existing KEIKAI investigation output into an
explainable backend-derived assessment.
"""
import hashlib
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from services.dnstwist_service import clean_domain_name

REGISTRY_PATH = Path("./config/authorization_registry.json")
EVIDENCE_WEIGHTS = {
    "STRONG_VISUAL_BRAND_MATCH": 30,
    "THREAT_INTELLIGENCE_CONFIRMATION": 25,
    "CREDENTIAL_COLLECTION_INDICATOR": 20,
    "SCREENSHOT_CAPTURED": 15,
    "DOMAIN_PERMUTATION": 10,
    "LOGO_DETECTION": 15,
    "PAGE_CONTENT_BRAND_MATCH": 10,
}


def _timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()


def normalize_domain(value: Optional[str]) -> str:
    """Use KEIKAI's existing dnstwist normalization, not a second algorithm."""
    return clean_domain_name(value or "").rstrip(".")


def _is_same_or_subdomain(domain: str, base: str) -> bool:
    return bool(domain and base and (domain == base or domain.endswith("." + base)))


def _load_registry(override: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    if override is not None:
        return override
    try:
        with REGISTRY_PATH.open("r", encoding="utf-8") as file:
            return json.load(file)
    except (OSError, json.JSONDecodeError):
        return {"version": 1, "source": "BRAND_AUTHORIZATION_REGISTRY", "brands": {}}


def _entries(registry: Dict[str, Any], brand: Optional[str]) -> Iterable[Dict[str, Any]]:
    data = registry.get("brands", {}).get((brand or "").strip().lower(), {})
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        return data.get("domains", data.get("entries", [])) or []
    return []


def _registry_classification(value: Any) -> str:
    aliases = {"AUTHORIZED": "AUTHORIZED_DOMAIN", "PARTNER": "KNOWN_PARTNER",
               "KNOWN_PARTNER_DOMAIN": "KNOWN_PARTNER", "SUBSIDIARY": "KNOWN_SUBSIDIARY",
               "RELATED": "KNOWN_RELATED_DOMAIN"}
    return aliases.get(str(value or "AUTHORIZED_DOMAIN").upper(), str(value or "AUTHORIZED_DOMAIN").upper())


def evaluate_legitimacy(candidate_domain: str, official_domain: Optional[str], target_brand: Optional[str] = None,
                        authorization_registry: Optional[Dict[str, Any]] = None,
                        evidence: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Classify authorization context; unknown is never treated as malicious."""
    candidate, official = normalize_domain(candidate_domain), normalize_domain(official_domain)
    if not candidate or "." not in candidate:
        return {"classification": "UNKNOWN_DOMAIN", "reporting_eligibility": "MANUAL_REVIEW_REQUIRED",
                "reason": "Candidate domain is missing or invalid; authorization cannot be determined.",
                "matched_authorization": None, "confidence": "LOW", "authorization_source": None}
    if official and _is_same_or_subdomain(candidate, official):
        return {"classification": "OFFICIAL_DOMAIN", "reporting_eligibility": "BLOCKED",
                "reason": "Candidate matches the official domain or one of its subdomains.",
                "matched_authorization": official, "confidence": "HIGH", "authorization_source": "OFFICIAL_DOMAIN_INPUT"}

    registry = _load_registry(authorization_registry)
    source = registry.get("source", "BRAND_AUTHORIZATION_REGISTRY")
    for entry in _entries(registry, target_brand):
        entry = {"domain": entry, "classification": "AUTHORIZED_DOMAIN"} if isinstance(entry, str) else entry
        domain = normalize_domain(entry.get("domain")) if isinstance(entry, dict) else ""
        if domain and _is_same_or_subdomain(candidate, domain):
            classification = _registry_classification(entry.get("classification", entry.get("type")))
            if classification not in {"AUTHORIZED_DOMAIN", "KNOWN_PARTNER", "KNOWN_SUBSIDIARY", "KNOWN_RELATED_DOMAIN"}:
                classification = "AUTHORIZED_DOMAIN"
            return {"classification": classification,
                    "reporting_eligibility": "BLOCKED" if classification == "AUTHORIZED_DOMAIN" else "MANUAL_REVIEW_REQUIRED",
                    "reason": f"Candidate matches registry entry '{domain}' classified as {classification}.",
                    "matched_authorization": domain, "confidence": "HIGH",
                    "authorization_source": entry.get("source", source)}

    signals = evidence or {}
    sources = {str(item).lower() for item in signals.get("sources", [])}
    suspicious = bool("dnstwist" in sources or "openphish" in sources or "phishtank" in sources
                      or signals.get("domain_permutation") or signals.get("credential_indicators"))
    if official and suspicious:
        return {"classification": "SUSPICIOUS_UNAUTHORIZED_DOMAIN", "reporting_eligibility": "ELIGIBLE_FOR_REVIEW",
                "reason": "No official or authorized-domain match was found, and existing investigation evidence identifies this unrelated domain as suspicious.",
                "matched_authorization": None, "confidence": "MEDIUM", "authorization_source": source}
    return {"classification": "UNKNOWN_DOMAIN", "reporting_eligibility": "MANUAL_REVIEW_REQUIRED",
            "reason": "No official or authorized-domain match was found, but available evidence is insufficient to classify the domain as unauthorized.",
            "matched_authorization": None, "confidence": "LOW", "authorization_source": source}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_screenshot_artifact(path: Path, case_id: Optional[str] = None, investigation_id: Optional[str] = None,
                              candidate_domain: Optional[str] = None, target_url: Optional[str] = None,
                              final_url: Optional[str] = None, acquisition_source: str = "candidate_acquisition") -> Dict[str, Any]:
    """Build a non-path-leaking SHA-256 record for a server-owned screenshot."""
    artifact_hash = sha256_file(path)
    return {"artifact_id": f"sha256:{artifact_hash}", "case_id": case_id, "investigation_id": investigation_id,
            "candidate_domain": normalize_domain(candidate_domain), "evidence_type": "SCREENSHOT",
            "source": acquisition_source, "collected_at": _timestamp(), "reference": path.name,
            "artifact_hash": artifact_hash, "metadata": {}, "confidence": None,
            "provenance": {"target_url": target_url, "final_url": final_url, "acquisition_status": "SUCCESS"}}


def evaluate_evidence(evidence: Optional[Dict[str, Any]] = None, case_id: Optional[str] = None,
                      investigation_id: Optional[str] = None, candidate_domain: Optional[str] = None) -> Dict[str, Any]:
    """Apply the documented, additive 30/25/20/15/10 evidence rubric."""
    data = evidence or {}
    sources = {str(item).lower() for item in data.get("sources", [])}
    signals, artifacts, missing = [], [], []
    def add(code: str, reason: str, evidence_type: str, source: str, confidence: Optional[float] = None) -> None:
        signals.append({"code": code, "contribution": EVIDENCE_WEIGHTS[code], "reason": reason})
        artifacts.append({"artifact_id": f"signal:{code.lower()}", "case_id": case_id, "investigation_id": investigation_id,
                          "candidate_domain": normalize_domain(candidate_domain), "evidence_type": evidence_type, "source": source,
                          "collected_at": _timestamp(), "reference": None, "artifact_hash": None, "metadata": {}, "confidence": confidence,
                          "provenance": {"derived_from": "existing_investigation_output"}})
    visual = float(data.get("visual_similarity", data.get("visual_confidence", 0)) or 0)
    visual = visual * 100 if visual <= 1 else visual
    if data.get("strong_visual_match") or visual >= 90:
        add("STRONG_VISUAL_BRAND_MATCH", "Strong target-brand visual match was recorded.", "LOGO_SIMILARITY", "phishpedia_or_logo_intelligence", visual)
    else: missing.append("Strong visual brand match")
    if data.get("logo_detected"):
        add("LOGO_DETECTION", "Target-brand logo detection was recorded.", "LOGO_DETECTION", "phishpedia")
    else: missing.append("Logo-detection evidence")
    if data.get("page_content_brand_match"):
        add("PAGE_CONTENT_BRAND_MATCH", "Target-brand page-content match was recorded.", "PAGE_CONTENT", "impersonation_service")
    else: missing.append("Page-content brand match")
    feeds = sources.intersection({"openphish", "phishtank"})
    if feeds: add("THREAT_INTELLIGENCE_CONFIRMATION", f"Candidate was confirmed by: {', '.join(sorted(feeds))}.", "THREAT_INTELLIGENCE", ",".join(sorted(feeds)))
    else: missing.append("Threat-intelligence confirmation")
    if data.get("credential_indicators") or data.get("login_form_detected"):
        add("CREDENTIAL_COLLECTION_INDICATOR", "Credential or login-form indicators were recorded.", "CREDENTIAL_INDICATOR", "impersonation_service")
    else: missing.append("Credential-collection indicator")
    screenshot = data.get("screenshot") or {}
    screenshot_status = str(screenshot.get("status", data.get("screenshot_status", "NOT_RUN"))).upper()
    if screenshot_status == "SUCCESS":
        add("SCREENSHOT_CAPTURED", "A usable screenshot/visual proxy was captured.", "SCREENSHOT", str(screenshot.get("source", "candidate_acquisition")))
        if artifacts and artifacts[-1].get("evidence_type") == "SCREENSHOT":
            artifacts[-1].update({
                "path": screenshot.get("path") or screenshot.get("reference"),
                "reference": screenshot.get("reference") or (Path(screenshot.get("path")).name if screenshot.get("path") else None),
                "artifact_hash": screenshot.get("artifact_hash") or screenshot.get("sha256"),
                "case_id": case_id or screenshot.get("case_id")
            })
    elif screenshot_status == "FAILED": missing.append("Visual evidence unavailable: screenshot acquisition failed")
    else: missing.append("Screenshot evidence not available")
    if data.get("domain_permutation") or "dnstwist" in sources:
        add("DOMAIN_PERMUTATION", "Candidate was identified as a domain permutation/lookalike.", "DOMAIN_RELATIONSHIP", "dnstwist")
    else: missing.append("Domain-permutation evidence")
    # Preserve custom artifacts passed in raw evidence
    for custom_art in data.get("artifacts", []):
        if isinstance(custom_art, dict):
            artifacts.append({
                "artifact_id": custom_art.get("artifact_id") or f"custom:{uuid.uuid4().hex[:8]}",
                "case_id": case_id or custom_art.get("case_id"),
                "investigation_id": investigation_id,
                "candidate_domain": normalize_domain(candidate_domain),
                "evidence_type": custom_art.get("evidence_type", "CUSTOM"),
                "source": custom_art.get("source", "investigation"),
                "collected_at": _timestamp(),
                "path": custom_art.get("path") or custom_art.get("reference"),
                "reference": custom_art.get("reference") or (Path(custom_art.get("path")).name if custom_art.get("path") else None),
                "artifact_hash": custom_art.get("artifact_hash") or custom_art.get("sha256"),
                "sha256": custom_art.get("sha256") or custom_art.get("artifact_hash"),
                "metadata": custom_art.get("metadata", {}),
                "confidence": custom_art.get("confidence")
            })

    score = min(100, sum(item["contribution"] for item in signals))
    level = "HIGH" if score >= 70 else "MEDIUM" if score >= 45 else "LOW" if score else "NONE"
    return {"evidence_level": f"EVIDENCE_{level}", "score": score / 100, "score_percent": score, "signals": signals,
            "missing": missing, "ready": level == "HIGH", "artifacts": artifacts, "weights": EVIDENCE_WEIGHTS,
            "screenshot_status": screenshot_status, "screenshot": screenshot}


def evaluate_reporting_eligibility(legitimacy: Dict[str, Any], evidence: Dict[str, Any]) -> Dict[str, Any]:
    classification, level = legitimacy["classification"], evidence["evidence_level"]
    if classification in {"OFFICIAL_DOMAIN", "AUTHORIZED_DOMAIN"}: decision = "BLOCKED"
    elif classification in {"KNOWN_PARTNER", "KNOWN_SUBSIDIARY", "KNOWN_RELATED_DOMAIN", "UNKNOWN_DOMAIN"}: decision = "MANUAL_REVIEW_REQUIRED"
    elif level == "EVIDENCE_HIGH": decision = "READY_FOR_HUMAN_REVIEW"
    else: decision = "INSUFFICIENT_EVIDENCE"
    return {"decision": decision, "ready_for_human_review": decision == "READY_FOR_HUMAN_REVIEW",
            "reasons": [legitimacy["reason"]] + [item["reason"] for item in evidence["signals"]],
            "missing_evidence": evidence["missing"]}


def evaluate_abuse_response(payload: Dict[str, Any]) -> Dict[str, Any]:
    candidate, raw_evidence = normalize_domain(payload.get("candidate_domain")), payload.get("evidence") or {}
    evidence = evaluate_evidence(raw_evidence, payload.get("case_id"), payload.get("investigation_id"), candidate)
    legitimacy = evaluate_legitimacy(candidate, payload.get("official_domain"), payload.get("target_brand"), payload.get("authorization_registry"), raw_evidence)
    return {"candidate_domain": candidate, "investigation_id": payload.get("investigation_id"), "target_brand": payload.get("target_brand"),
            "evaluated_at": _timestamp(), "evidence": evidence, "legitimacy": legitimacy,
            "reporting_eligibility": evaluate_reporting_eligibility(legitimacy, evidence)}
