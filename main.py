import os
import logging
from pathlib import Path
from typing import List, Optional, Dict, Any
from fastapi import FastAPI, File, UploadFile, Form, HTTPException, Request, status, Query
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException

from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response, JSONResponse

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("keikai.api")

from schemas import (
    StandardResponse, MetaModel, DomainScanRequest, DomainIntelligenceRequest,
    AsnIntelligenceRequest, AbuseTargetResolutionRequest, AbuseResponseEvaluateRequest,
    AbuseResponsePreviewRequest, AbuseApprovalRequest, AbuseSubmitRequest, AbuseRevokeRequest,
    UniversalRoutePreviewRequest, UniversalTakedownSubmitRequest, EvidenceIntelligenceAnalyzeRequest
)
from utils.temp_file import save_temp_file, save_temp_files
from services.dnstwist_service import run_dnstwist_scan, DNSTwistError
from services.imagehash_service import compare_two_images, compare_batch_images, ImageHashError
from services.report_service import generate_pdf_report


app = FastAPI(
    title="KEIKAI Engine API (dnstwist + imagehash)",
    description="FastAPI backend wrapping dnstwist for domain typosquatting scan and imagehash for logo similarity analysis.",
    version="1.0.0"
)

ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "http://localhost:3000,http://localhost:5173,http://127.0.0.1:3000,http://127.0.0.1:5173").split(",")

# Enable CORS for React frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in ALLOWED_ORIGINS if o.strip()],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Exception handler for custom response shape on HTTP errors
@app.exception_handler(HTTPException)
@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    # Determine source_tool from path if possible
    path = request.url.path
    if "domain-scan" in path:
        tool = "dnstwist"
    elif "logo" in path:
        tool = "imagehash"
    else:
        tool = "system"

    return JSONResponse(
        status_code=exc.status_code,
        content={
            "status": "error",
            "data": None,
            "error": exc.detail,
            "meta": {"source_tool": tool}
        }
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "status": "error",
            "data": None,
            "error": f"Validation Error: {str(exc)}",
            "meta": {"source_tool": "system"}
        }
    )


@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "status": "error",
            "data": None,
            "error": f"Internal Server Error: {str(exc)}",
            "meta": {"source_tool": "system"}
        }
    )


from services.phishpedia_service import (
    check_phishpedia_weights,
    get_phishpedia_license,
    process_phishpedia_job,
    PHISHPEDIA_JOBS,
    PhishpediaWeightsMissingError
)


import time
import uuid

SERVER_INSTANCE_ID = f"sess_{int(time.time())}_{uuid.uuid4().hex[:8]}"

@app.get("/api/session-info", response_model=StandardResponse)
async def session_info():
    """
    Returns server instance ID for session lifecycle synchronization.
    """
    return {
        "status": "success",
        "data": {
            "server_instance_id": SERVER_INSTANCE_ID
        },
        "meta": {"source_tool": "system"}
    }


@app.get("/api/health", response_model=StandardResponse)
async def health_check():
    """
    Health check endpoint.
    """
    return {
        "status": "success",
        "data": {
            "health": "ok",
            "uptime_status": "healthy",
            "server_instance_id": SERVER_INSTANCE_ID
        },
        "meta": {"source_tool": "system"}
    }
from services.infrastructure_service import (
    index_domain_scan_results,
    index_logo_batch_results,
    index_visual_phishing_result,
    find_linked_infrastructure,
    get_offender_clusters
)
from schemas import LinkInfrastructureRequest


@app.get("/api/credits", response_model=StandardResponse)
async def get_credits():
    """
    Returns metadata, GitHub URLs, and license information for wrapped tools.
    """
    phish_info = get_phishpedia_license()
    return {
        "status": "success",
        "data": {
            "tools": [
                {
                    "name": "dnstwist",
                    "description": "Domain name permutation engine for detecting homograph phishing attacks, typosquatting, and brand fraud.",
                    "github_url": "https://github.com/elceef/dnstwist",
                    "license": "GPLv3"
                },
                {
                    "name": "imagehash",
                    "description": "Perceptual image hashing library written in Python supporting ahash, phash, dhash, and whash algorithms.",
                    "github_url": "https://github.com/JohannesBuchner/imagehash",
                    "license": "BSD-2-Clause"
                },
                {
                    "name": phish_info["name"],
                    "description": phish_info["description"],
                    "github_url": phish_info["github_url"],
                    "license": phish_info["license"],
                    "paper_citation": phish_info["paper_citation"]
                },
                {
                    "name": "Infrastructure Fingerprinting Engine",
                    "description": "Proprietary offender correlation layer running SQLite-backed technical fingerprint analysis (shared hosting IPs, perceptual image hashes, target brand intentions) across all scan data.",
                    "github_url": "https://github.com/antigravity/brand-protection-fingerprinting",
                    "license": "Proprietary / Built-in Layer"
                }
            ]
        },
        "meta": {"source_tool": "system"}
    }


from services.dnstwist_service import clean_domain_name
from services.threat_intelligence.orchestrator import ThreatIntelOrchestrator


@app.get("/api/threat-intel/health", response_model=StandardResponse)
async def threat_intel_health():
    """
    Returns health status and cached record counts for dnstwist, OpenPhish, and PhishTank intelligence sources.
    """
    sources_health = ThreatIntelOrchestrator.get_all_sources_health()
    return {
        "status": "success",
        "data": {
            "sources": sources_health
        },
        "meta": {"source_tool": "threat_intelligence"}
    }


@app.post("/api/domain-scan", response_model=StandardResponse)
async def domain_scan(payload: DomainScanRequest):
    """
    Multi-Source Threat Discovery: Correlates dnstwist permutations, OpenPhish community feeds, and PhishTank databases into a unified Candidate Intelligence Pool.
    """
    clean_domain = clean_domain_name(payload.domain)
    if not clean_domain:
        raise HTTPException(status_code=400, detail="Invalid domain provided. Please supply a valid domain name like amazon.com")

    try:
        scan_output = ThreatIntelOrchestrator.execute_multi_source_scan(
            domain=clean_domain,
            quick_mode=payload.quick_mode,
            timeout=payload.timeout or 60
        )
        results = scan_output["permutations"]
        sources_health = scan_output["sources_health"]

        try:
            target_brand = clean_domain.split('.')[0].capitalize()
            index_domain_scan_results(clean_domain, results, target_brand=target_brand)
            log_case_event("default", "scan_run", f"Multi-source threat scan executed for {clean_domain} — {len(results)} candidates correlated across dnstwist, OpenPhish, and PhishTank.")
        except Exception as err:
            logger.warning(f"Failed to index domain scan results: {err}")

        return {
            "status": "success",
            "data": {
                "domain": clean_domain,
                "quick_mode": payload.quick_mode,
                "total_permutations": len(results),
                "sources_health": sources_health,
                "permutations": results
            },
            "meta": {"source_tool": "threat_intelligence"}
        }
    except Exception as e:
        logger.error(f"[KEIKAI API] Multi-source threat scan error for {payload.domain}: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Multi-source threat scan error: {str(e)}")


@app.post("/api/domain-intelligence", response_model=StandardResponse)
async def domain_intelligence_post(payload: DomainIntelligenceRequest):
    """
    TASK 3B — DNS + IP Infrastructure & RDAP Domain Intelligence API (POST).
    Resolves A, AAAA, CNAME, MX, NS records, IPs, Reverse DNS, and RDAP registration.
    """
    from services.infrastructure_service import get_domain_intelligence
    if not payload.domain:
        raise HTTPException(status_code=400, detail="Domain is required")

    try:
        intel = get_domain_intelligence(payload.domain, use_cache=payload.use_cache if payload.use_cache is not None else True)
        return {
            "status": "success",
            "data": intel,
            "meta": {"source_tool": "dns_infrastructure_intelligence"}
        }
    except Exception as e:
        logger.error(f"[KEIKAI API] Domain intelligence error for {payload.domain}: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Domain intelligence error: {str(e)}")


@app.get("/api/domain-intelligence", response_model=StandardResponse)
async def domain_intelligence_get(domain: str = Query(..., description="Target domain name"), use_cache: bool = Query(True)):
    """
    TASK 3B — DNS + IP Infrastructure & RDAP Domain Intelligence API (GET).
    """
    from services.infrastructure_service import get_domain_intelligence
    if not domain:
        raise HTTPException(status_code=400, detail="Domain is required")

    try:
        intel = get_domain_intelligence(domain, use_cache=use_cache)
        return {
            "status": "success",
            "data": intel,
            "meta": {"source_tool": "dns_infrastructure_intelligence"}
        }
    except Exception as e:
        logger.error(f"[KEIKAI API] Domain intelligence error for {domain}: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Domain intelligence error: {str(e)}")


@app.post("/api/asn-intelligence", response_model=StandardResponse)
async def asn_intelligence_post(payload: AsnIntelligenceRequest):
    """
    TASK 3C — ASN + Hosting Provider Intelligence API (POST).
    Resolves BGP ASN, ASN Organization, Infrastructure Provider, Country, CIDR route, and Abuse Contact.
    """
    from services.asn_intelligence_service import lookup_ip_asn
    if not payload.ip:
        raise HTTPException(status_code=400, detail="IP address is required")

    try:
        intel = lookup_ip_asn(payload.ip, use_cache=payload.use_cache if payload.use_cache is not None else True)
        return {
            "status": "success",
            "data": intel,
            "meta": {"source_tool": "asn_provider_intelligence"}
        }
    except Exception as e:
        logger.error(f"[KEIKAI API] ASN lookup error for {payload.ip}: {str(e)}")
        raise HTTPException(status_code=500, detail=f"ASN lookup error: {str(e)}")


@app.get("/api/asn-intelligence", response_model=StandardResponse)
async def asn_intelligence_get(ip: str = Query(..., description="Target IP address"), use_cache: bool = Query(True)):
    """
    TASK 3C — ASN + Hosting Provider Intelligence API (GET).
    """
    from services.asn_intelligence_service import lookup_ip_asn
    if not ip:
        raise HTTPException(status_code=400, detail="IP address is required")

    try:
        intel = lookup_ip_asn(ip, use_cache=use_cache)
        return {
            "status": "success",
            "data": intel,
            "meta": {"source_tool": "asn_provider_intelligence"}
        }
    except Exception as e:
        logger.error(f"[KEIKAI API] ASN lookup error for {ip}: {str(e)}")
        raise HTTPException(status_code=500, detail=f"ASN lookup error: {str(e)}")


@app.post("/api/abuse-target-resolution", response_model=StandardResponse)
async def abuse_target_resolution_post(payload: AbuseTargetResolutionRequest):
    """
    TASK 3D — Unified Abuse Target Resolution Engine API (POST).
    Determines WHO SHOULD RECEIVE THE ABUSE REPORT, evaluates Legitimacy Gate, and calculates Reporting Readiness.
    Does NOT send emails or submit automatic takedowns.
    """
    from services.abuse_target_service import resolve_abuse_targets
    if not payload.domain:
        raise HTTPException(status_code=400, detail="Domain is required")

    try:
        res = resolve_abuse_targets(
            domain=payload.domain,
            official_domain=payload.official_domain,
            authorized_domains=payload.authorized_domains,
            evidence_score=payload.evidence_score or 85.0,
            use_cache=payload.use_cache if payload.use_cache is not None else True
        )
        return {
            "status": "success",
            "data": res,
            "meta": {"source_tool": "abuse_target_resolution_engine"}
        }
    except Exception as e:
        logger.error(f"[KEIKAI API] Abuse target resolution error for {payload.domain}: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Abuse target resolution error: {str(e)}")


@app.get("/api/abuse-target-resolution", response_model=StandardResponse)
async def abuse_target_resolution_get(
    domain: str = Query(..., description="Target domain name"),
    official_domain: Optional[str] = Query(None),
    use_cache: bool = Query(True)
):
    """
    TASK 3D — Unified Abuse Target Resolution Engine API (GET).
    """
    from services.abuse_target_service import resolve_abuse_targets
    if not domain:
        raise HTTPException(status_code=400, detail="Domain is required")

    try:
        res = resolve_abuse_targets(
            domain=domain,
            official_domain=official_domain,
            use_cache=use_cache
        )
        return {
            "status": "success",
            "data": res,
            "meta": {"source_tool": "abuse_target_resolution_engine"}
        }
    except Exception as e:
        logger.error(f"[KEIKAI API] Abuse target resolution error for {domain}: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Abuse target resolution error: {str(e)}")


# TASK 5 — TAKEDOWN SUBMISSION CONTROL PLANE ENDPOINTS

@app.post("/api/abuse-response/evaluate", response_model=StandardResponse)
async def abuse_response_evaluate(payload: AbuseResponseEvaluateRequest):
    """
    Evaluates evidence sufficiency, legitimacy classification, and reporting eligibility.
    """
    from services.abuse_response_service import evaluate_abuse_response
    try:
        res = evaluate_abuse_response(payload.model_dump())
        return {
            "status": "success",
            "data": res,
            "meta": {"source_tool": "abuse_response_service"}
        }
    except Exception as e:
        logger.error(f"[KEIKAI API] Abuse response evaluation error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Abuse response evaluation error: {str(e)}")


@app.post("/api/abuse-response/preview", response_model=StandardResponse)
async def abuse_response_preview(payload: AbuseResponsePreviewRequest):
    """
    Generates dry-run submission previews and provider route recommendations.
    """
    from services.abuse_submission_router import AbuseSubmissionRouter
    try:
        router = AbuseSubmissionRouter()
        res = router.preview(payload.model_dump(), payload.provider_intelligence or {})
        return {
            "status": "success",
            "data": res,
            "meta": {"source_tool": "abuse_submission_router"}
        }
    except Exception as e:
        logger.error(f"[KEIKAI API] Abuse response preview error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Abuse response preview error: {str(e)}")


@app.post("/api/evidence-intelligence/analyze", response_model=StandardResponse)
async def evidence_intelligence_analyze_post(payload: EvidenceIntelligenceAnalyzeRequest):
    """
    EVIDENCE INTELLIGENCE V2: Executes full high-accuracy domain + visual + infrastructure enrichment.
    """
    from services.evidence_intelligence_service import EvidenceIntelligenceService
    try:
        pkg = EvidenceIntelligenceService.analyze_candidate(
            candidate_domain=payload.candidate_domain,
            target_brand=payload.target_brand,
            official_domain=payload.official_domain,
            screenshot_path=payload.screenshot_path,
            ocr_text=payload.ocr_text,
            webpage_title=payload.webpage_title
        )
        return {
            "status": "success",
            "data": pkg,
            "meta": {"source_tool": "evidence_intelligence_service"}
        }
    except Exception as e:
        logger.error(f"[KEIKAI API] Evidence Intelligence V2 analysis error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Evidence Intelligence V2 analysis error: {str(e)}")


@app.get("/api/evidence-intelligence/analyze", response_model=StandardResponse)
async def evidence_intelligence_analyze_get(
    domain: str = Query("amaz0n-security-login.xyz"),
    brand: str = Query("Amazon"),
    official: Optional[str] = Query("amazon.com")
):
    """
    EVIDENCE INTELLIGENCE V2: Executes full high-accuracy domain + visual + infrastructure enrichment (GET).
    """
    from services.evidence_intelligence_service import EvidenceIntelligenceService
    try:
        pkg = EvidenceIntelligenceService.analyze_candidate(
            candidate_domain=domain,
            target_brand=brand,
            official_domain=official
        )
        return {
            "status": "success",
            "data": pkg,
            "meta": {"source_tool": "evidence_intelligence_service"}
        }
    except Exception as e:
        logger.error(f"[KEIKAI API] Evidence Intelligence V2 analysis error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Evidence Intelligence V2 analysis error: {str(e)}")


@app.post("/api/abuse-control/approve", response_model=StandardResponse)
async def abuse_control_approve(payload: AbuseResponseEvaluateRequest):
    """
    Freezes a submission snapshot and creates a persistent human approval record.
    """
    from services.abuse_control_service import approve
    case_id = payload.case_id or payload.investigation_id or "default"
    try:
        res = approve(case_id, payload.model_dump())
        if "error" in res:
            return JSONResponse(
                status_code=400,
                content={"status": "error", "error": res["error"], "data": res, "meta": {"source_tool": "abuse_control"}}
            )
        return {
            "status": "success",
            "data": res,
            "meta": {"source_tool": "abuse_control"}
        }
    except Exception as e:
        logger.error(f"[KEIKAI API] Abuse approval error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Abuse approval error: {str(e)}")


@app.post("/api/abuse-control/submit", response_model=StandardResponse)
async def abuse_control_submit(payload: Dict[str, Any]):
    """
    Submits an approved takedown report. Revalidates evidence, legitimacy, and provider routes.
    Executes atomic claim and DRY_RUN or LIVE Cloudflare submission.
    """
    from services.abuse_control_service import submit
    case_id = payload.get("case_id") or "default"
    approval_id = payload.get("approval_id")

    if not approval_id:
        raise HTTPException(status_code=400, detail="approval_id is required")

    try:
        res = submit(case_id, approval_id, client_payload=payload)
        if "error" in res:
            return JSONResponse(
                status_code=400,
                content={"status": "error", "error": res["error"], "data": res, "meta": {"source_tool": "abuse_control"}}
            )
        return {
            "status": "success",
            "data": res,
            "meta": {"source_tool": "abuse_control"}
        }
    except Exception as e:
        logger.error(f"[KEIKAI API] Abuse submission error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Abuse submission error: {str(e)}")


@app.post("/api/demo/run-scenario", response_model=StandardResponse)
async def demo_run_scenario(brand: Optional[str] = Query("Amazon"), domain: Optional[str] = Query("amaz0n-security-login.xyz")):
    """
    TASK 7: Executes a deterministic end-to-end sponsor demo scenario.
    Discovery → Logo Match → Threat Intel → Risk Scoring → Case Creation → viaSocket Notification → Human Approval → Snapshot Freeze → DRY_RUN Takedown Dispatch → Automated Report.
    """
    from services.demo_scenario_service import run_demo_scenario
    try:
        case_report = run_demo_scenario(target_brand=brand or "Amazon", candidate_domain=domain or "amaz0n-security-login.xyz")
        return {
            "status": "success",
            "data": case_report,
            "meta": {"source_tool": "demo_scenario_service"}
        }
    except Exception as e:
        logger.error(f"[KEIKAI API] Demo scenario error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Demo scenario error: {str(e)}")


@app.post("/api/viasocket/emit-event", response_model=StandardResponse)
async def viasocket_emit_event(payload: Dict[str, Any]):
    """
    TASK 7: Emits a safe event payload to viaSocket workflow automation layer.
    """
    from services.viasocket_adapter import emit_viasocket_event
    event_type = payload.get("event_type", "CASE_CREATED")
    case_id = payload.get("case_id")
    event_data = payload.get("data", {})
    try:
        res = emit_viasocket_event(event_type, case_id, event_data)
        return {
            "status": "success",
            "data": res,
            "meta": {"source_tool": "viasocket_adapter"}
        }
    except Exception as e:
        logger.error(f"[KEIKAI API] viaSocket event emit error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"viaSocket event emit error: {str(e)}")


@app.get("/api/universal-takedown/route-preview", response_model=StandardResponse)
async def universal_route_preview_get(domain: str = Query("amaz0n-security-login.xyz")):
    """
    TASK 6/7: Resolves optimal takedown provider route preview for candidate domain.
    """
    from services.provider_discovery_service import discover_provider_contacts
    try:
        discovery = discover_provider_contacts(domain, use_cache=True)
        return {
            "status": "success",
            "data": discovery,
            "meta": {"source_tool": "provider_discovery_service"}
        }
    except Exception as e:
        logger.error(f"[KEIKAI API] Universal route preview error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Universal route preview error: {str(e)}")


@app.post("/api/universal-takedown/route-preview", response_model=StandardResponse)
async def universal_route_preview_post(payload: UniversalRoutePreviewRequest):
    """
    TASK 6/7: Resolves optimal takedown provider route preview for candidate domain (POST).
    """
    from services.provider_discovery_service import discover_provider_contacts
    try:
        discovery = discover_provider_contacts(payload.domain, use_cache=True)
        return {
            "status": "success",
            "data": discovery,
            "meta": {"source_tool": "provider_discovery_service"}
        }
    except Exception as e:
        logger.error(f"[KEIKAI API] Universal route preview error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Universal route preview error: {str(e)}")


@app.post("/api/universal-takedown/submit", response_model=StandardResponse)
async def universal_takedown_submit(payload: UniversalTakedownSubmitRequest):
    """
    TASK 6/7: Executes universal takedown passing through mandatory Task 5 approval boundary.
    """
    from services.universal_abuse_router import submit_universal_takedown
    try:
        res = submit_universal_takedown(payload.case_id, payload.approval_id, client_payload=payload.client_payload)
        if "error" in res:
            return JSONResponse(
                status_code=400,
                content={"status": "error", "error": res["error"], "data": res, "meta": {"source_tool": "universal_abuse_router"}}
            )
        return {
            "status": "success",
            "data": res,
            "meta": {"source_tool": "universal_abuse_router"}
        }
    except Exception as e:
        logger.error(f"[KEIKAI API] Universal takedown submit error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Universal takedown submit error: {str(e)}")
async def abuse_control_revoke(payload: AbuseRevokeRequest):
    """
    Revokes an active human approval record.
    """
    from services.abuse_control_service import revoke
    case_id = getattr(payload, "case_id", "default")
    try:
        res = revoke(case_id, payload.approval_id)
        if "error" in res:
            return JSONResponse(
                status_code=400,
                content={"status": "error", "error": res["error"], "data": res, "meta": {"source_tool": "abuse_control"}}
            )
        return {
            "status": "success",
            "data": res,
            "meta": {"source_tool": "abuse_control"}
        }
    except Exception as e:
        logger.error(f"[KEIKAI API] Abuse revocation error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Abuse revocation error: {str(e)}")


@app.get("/api/abuse-control/{case_id}/status", response_model=StandardResponse)
async def abuse_control_status(case_id: str):
    """
    Returns approval and submission status for a case.
    """
    from services.abuse_control_service import status
    try:
        res = status(case_id)
        return {
            "status": "success",
            "data": res,
            "meta": {"source_tool": "abuse_control"}
        }
    except Exception as e:
        logger.error(f"[KEIKAI API] Abuse status error for {case_id}: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Abuse status error: {str(e)}")

from services.phishpedia_service import analyze_screenshot_visual_brand, check_phishpedia_weights


@app.get("/api/domain-intelligence/registration/{domain}", response_model=StandardResponse)
async def registration_intelligence(domain: str, use_cache: bool = Query(True)):
    from services.registration_intelligence_service import get_registration_intelligence
    return {"status": "success", "data": {"registration_intelligence": get_registration_intelligence(domain, use_cache)}, "meta": {"source_tool": "registration_intelligence"}}

@app.get("/api/domain-intelligence/infrastructure/{domain}", response_model=StandardResponse)
async def provider_intelligence(domain: str, use_cache: bool = Query(True)):
    from services.provider_intelligence_service import get_provider_intelligence
    return {"status":"success","data":get_provider_intelligence(domain,use_cache),"meta":{"source_tool":"provider_intelligence"}}


from services.phishpedia_service import analyze_screenshot_visual_brand, check_phishpedia_weights


@app.post("/api/visual-brand-analysis", response_model=StandardResponse)
async def visual_brand_analysis(
    file: Optional[UploadFile] = File(None, description="Screenshot image file"),
    screenshot_path: Optional[str] = Form(None, description="Path to screenshot image file"),
    target_brand: Optional[str] = Form(None, description="Optional target brand name")
):
    """
    TASK 2A: Phishpedia Logo-Based Brand Recognition API.
    Detects logo bounding boxes and identifies visual brand representations from webpage screenshots.
    Does NOT declare a phishing verdict on its own.
    """
    temp_path = None
    try:
        target_path = screenshot_path
        if file:
            suffix = Path(file.filename).suffix or ".png"
            temp_file = Path("./uploads") / f"sc_{uuid.uuid4().hex}{suffix}"
            temp_file.parent.mkdir(parents=True, exist_ok=True)
            content = await file.read()
            temp_file.write_bytes(content)
            target_path = str(temp_file)
            temp_path = temp_file

        if not target_path:
            raise HTTPException(status_code=400, detail="Please upload a screenshot image file or provide a screenshot_path parameter.")

        res = analyze_screenshot_visual_brand(screenshot_path=target_path, target_brand=target_brand)
        return {
            "status": "success",
            "data": {
                "visual_brand_analysis": res
            },
            "meta": {"source_tool": "Phishpedia"}
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"[KEIKAI API] Visual brand analysis error: {e}")
        raise HTTPException(status_code=500, detail=f"Visual brand analysis error: {str(e)}")
    finally:
        if temp_path and temp_path.exists():
            try:
                temp_path.unlink()
            except Exception:
                pass


from services.impersonation_service import execute_brand_impersonation_scan


@app.post("/api/brand-impersonation-scan", response_model=StandardResponse)
async def brand_impersonation_scan(
    target_brand: str = Form("Amazon"),
    official_domain: str = Form("amazon.com"),
    max_candidates: int = Form(25),
    reference_screenshot: Optional[UploadFile] = File(None, description="Legitimate reference screenshot file"),
    reference_path: Optional[str] = Form(None, description="Path to reference screenshot")
):
    """
    TASK 2C: Multi-Signal Visual Impersonation Verification API.
    Fuses Phishpedia logo ID, pHash/dHash screenshot similarity, page text brand evidence, credential-taking DOM indicators, and threat intelligence.
    """
    temp_ref_path = None
    try:
        ref_p = reference_path
        if reference_screenshot:
            suffix = Path(reference_screenshot.filename).suffix or ".png"
            temp_file = Path("./uploads") / f"ref_{uuid.uuid4().hex}{suffix}"
            temp_file.parent.mkdir(parents=True, exist_ok=True)
            content = await reference_screenshot.read()
            temp_file.write_bytes(content)
            ref_p = str(temp_file)
            temp_ref_path = temp_file

        results = execute_brand_impersonation_scan(
            target_brand=target_brand,
            official_domain=official_domain,
            max_candidates=max_candidates,
            reference_screenshot_path=ref_p
        )
        return {
            "status": "success",
            "data": results,
            "meta": {"source_tool": "multi_signal_impersonation_engine"}
        }
    except Exception as e:
        logger.error(f"[KEIKAI API] Brand impersonation scan error: {e}")
        raise HTTPException(status_code=500, detail=f"Brand impersonation scan error: {str(e)}")
    finally:
        if temp_ref_path and temp_ref_path.exists():
            try:
                temp_ref_path.unlink()
            except Exception:
                pass


KNOWN_BRAND_DOMAINS = {
    "amazon": "amazon.com",
    "microsoft": "microsoft.com",
    "apple": "apple.com",
    "google": "google.com",
    "rolex": "rolex.com",
    "facebook": "facebook.com",
    "netflix": "netflix.com",
    "paypal": "paypal.com"
}


@app.post("/api/logo-investigation", response_model=StandardResponse)
async def logo_investigation(
    logo: Optional[UploadFile] = File(None, description="Uploaded brand logo image"),
    target_brand: Optional[str] = Form(None, description="Optional target brand name"),
    official_domain: Optional[str] = Form(None, description="Optional official domain"),
    max_candidates: int = Form(25, description="Max candidates to evaluate")
):
    """
    TASK 2D V2: Logo Intelligence & Visual Retrieval Engine.

    When logo is provided — Full V2 pipeline:
      Uploaded Logo → Fingerprint (pHash/dHash/OCR) → Candidate Discovery (dnstwist+OpenPhish+PhishTank)
      → Screenshot Acquisition (HTTP+OG image) → Phishpedia Logo Detection
      → Target↔Candidate Logo Comparison → Multi-Signal Evidence Fusion

    When no logo is provided — V1 domain-first scan (backward compatible).
    """
    temp_logo_path = None
    try:
        brand_name = (target_brand or "").strip()
        domain_name = (official_domain or "").strip()

        # Save uploaded logo if provided
        logo_path = None
        if logo:
            contents = await logo.read()
            if len(contents) > 5 * 1024 * 1024:
                raise HTTPException(status_code=400, detail="Uploaded logo file exceeds maximum allowed size of 5 MB.")

            suffix = Path(logo.filename).suffix or ".png"
            temp_file = Path("./uploads") / f"logo_inv_{uuid.uuid4().hex}{suffix}"
            temp_file.parent.mkdir(parents=True, exist_ok=True)
            temp_file.write_bytes(contents)
            logo_path = str(temp_file)
            temp_logo_path = temp_file

        # TASK 2D V4: Full True Logo-First Reverse Discovery when logo is provided
        if logo_path:
            from services.logo_intelligence_service import run_logo_intelligence_scan
            results = run_logo_intelligence_scan(
                target_brand=brand_name if brand_name else None,
                official_domain=domain_name if domain_name else None,
                logo_path=logo_path,
                max_candidates=max_candidates
            )
        elif brand_name:
            # Fallback when brand provided without logo
            if not domain_name:
                b_lower = brand_name.lower()
                domain_name = KNOWN_BRAND_DOMAINS.get(b_lower, f"{b_lower}.com")

            results = execute_brand_impersonation_scan(
                target_brand=brand_name,
                official_domain=domain_name,
                max_candidates=max_candidates,
                reference_screenshot_path=None
            )
            results["uploaded_logo_processed"] = False
            results["investigation_mode"] = "domain_first_v1"
        else:
            return {
                "status": "requires_brand_input",
                "data": {
                    "message": "Brand could not be determined. Please upload a logo or enter the target brand name.",
                    "brand_identification_required": True
                },
                "meta": {"source_tool": "logo_investigation_engine_v4"}
            }

        # Sanitize numpy primitives before returning response
        from services.logo_intelligence_service import sanitize_numpy_primitives
        sanitized_results = sanitize_numpy_primitives(results)

        return {
            "status": "success",
            "data": sanitized_results,
            "meta": {"source_tool": "logo_investigation_engine_v4"}
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"[KEIKAI API] Logo investigation error: {e}")
        raise HTTPException(status_code=500, detail=f"Logo investigation error: {str(e)}")
    finally:
        if temp_logo_path and temp_logo_path.exists():
            try:
                temp_logo_path.unlink()
            except Exception:
                pass


@app.post("/api/logo-compare", response_model=StandardResponse)
async def logo_compare(
    reference: Optional[UploadFile] = File(None, description="Reference logo image"),
    reference_logo: Optional[UploadFile] = File(None, description="Alias for reference logo image"),
    candidate: Optional[UploadFile] = File(None, description="Candidate image to test"),
    candidate_image: Optional[UploadFile] = File(None, description="Alias for candidate image"),
    threshold: int = Form(10, description="Hamming distance threshold for match (default: 10)")
):
    """
    Compares reference logo and candidate image using imagehash (phash and dhash).
    Returns Hamming distance, similarity percentage, and likely_match status.
    """
    ref_file = reference or reference_logo
    cand_file = candidate or candidate_image

    if not ref_file or not cand_file:
        raise HTTPException(
            status_code=400,
            detail="Both reference image (field 'reference' or 'reference_logo') and candidate image (field 'candidate' or 'candidate_image') are required."
        )

    # Save files to /tmp working dir with guaranteed cleanup
    with save_temp_file(ref_file) as ref_path:
        with save_temp_file(cand_file) as cand_path:
            try:
                comparison = compare_two_images(
                    reference_path=ref_path,
                    candidate_path=cand_path,
                    threshold=threshold
                )
                return {
                    "status": "success",
                    "data": comparison,
                    "meta": {"source_tool": "imagehash"}
                }
            except ImageHashError as e:
                raise HTTPException(status_code=400, detail=str(e))
            except Exception as e:
                raise HTTPException(status_code=500, detail=f"Unexpected logo comparison error: {str(e)}")


@app.post("/api/logo-batch", response_model=StandardResponse)
async def logo_batch(
    reference: Optional[UploadFile] = File(None, description="Reference logo image"),
    reference_logo: Optional[UploadFile] = File(None, description="Alias for reference logo image"),
    candidates: List[UploadFile] = File(..., description="Multiple candidate images to rank"),
    threshold: int = Form(10, description="Hamming distance threshold for match (default: 10)")
):
    """
    Compares one reference logo image against multiple candidate images and returns a ranked list.
    """
    ref_file = reference or reference_logo
    if not ref_file:
        raise HTTPException(
            status_code=400,
            detail="Reference logo image (field 'reference' or 'reference_logo') is required."
        )

    if not candidates:
        raise HTTPException(
            status_code=400,
            detail="At least one candidate image (field 'candidates') is required."
        )

    with save_temp_file(ref_file) as ref_path:
        with save_temp_files(candidates) as cand_paths:
            candidate_tuples = [
                (cand_path, cand_file.filename or f"candidate_{idx}.png")
                for idx, (cand_path, cand_file) in enumerate(zip(cand_paths, candidates))
            ]
            try:
                batch_result = compare_batch_images(
                    reference_path=ref_path,
                    reference_filename=ref_file.filename or "reference.png",
                    candidate_file_tuples=candidate_tuples,
                    threshold=threshold
                )
                try:
                    index_logo_batch_results(ref_file.filename or "reference.png", batch_result.get("ranked_results", []))
                    log_case_event("default", "scan_run", f"Logo batch comparison run against {ref_file.filename or 'reference.png'} with {len(candidates)} candidate images.")
                except Exception:
                    pass

                return {
                    "status": "success",
                    "data": batch_result,
                    "meta": {"source_tool": "imagehash"}
                }
            except ImageHashError as e:
                raise HTTPException(status_code=400, detail=str(e))
            except Exception as e:
                raise HTTPException(status_code=500, detail=f"Unexpected logo batch comparison error: {str(e)}")


@app.post("/api/generate-report")
async def generate_report(case_data: dict):
    """
    Generates a downloadable PDF case report compiling flagged domains, logo matches, and risk scores.
    """
    try:
        pdf_bytes = generate_pdf_report(case_data)
        case_id = case_data.get("case_id", "case_report")
        filename = f"{case_id.lower().replace('-', '_')}.pdf"
        
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"'
            }
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to generate PDF report: {str(e)}")


@app.get("/api/visual-phishing-status", response_model=StandardResponse)
async def visual_phishing_status():
    """
    Checks if Phishpedia model weights are loaded and ready for visual phishing detection.
    """
    logger.info("GET /api/visual-phishing-status — checking Phishpedia weight readiness")
    status_info = check_phishpedia_weights()
    loaded = status_info.get("weights_loaded", False)
    logger.info("GET /api/visual-phishing-status — outcome: weights_loaded=%s", loaded)
    return {
        "status": "success",
        "data": status_info,
        "meta": {"source_tool": "phishpedia"}
    }


@app.post("/api/visual-phishing-check")
async def visual_phishing_check(
    request: Request,
    url: str = Form(..., description="Target webpage URL"),
    screenshot: UploadFile = File(..., description="Webpage screenshot image file"),
    fallback: bool = Form(False, description="Run lightweight fallback hash check if weights are missing")
):
    """
    Initiates a visual phishing check job. If weights are missing and fallback=False, returns 503 error.
    If fallback=True, executes a lightweight hash-based fallback check.
    """
    logger.info("POST /api/visual-phishing-check — url=%s fallback=%s filename=%s", url, fallback, screenshot.filename)
    status_info = check_phishpedia_weights()
    use_fallback = False

    if not status_info["weights_loaded"]:
        if not fallback:
            logger.warning("POST /api/visual-phishing-check — 503 weights not loaded, fallback not requested")
            return JSONResponse(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                content={
                    "status": "error",
                    "data": status_info,
                    "error": status_info["message"],
                    "meta": {"source_tool": "phishpedia"}
                }
            )
        else:
            use_fallback = True

    # Save uploaded screenshot to temp file in /tmp
    from utils.temp_file import TMP_DIR
    ext = Path(screenshot.filename).suffix if screenshot.filename else ".png"
    # Enforce queue depth limit (max 10 active jobs)
    active_jobs = sum(1 for j in PHISHPEDIA_JOBS.values() if j.get("status") in ["pending", "processing"])
    if active_jobs >= 10:
        logger.warning("POST /api/visual-phishing-check — 429 job queue full (%d active)", active_jobs)
        raise HTTPException(
            status_code=429,
            detail="Visual Phishing Inference job queue is full (max 10 active jobs). Please wait for current jobs to finish."
        )

    temp_filename = f"phishpedia_{uuid.uuid4().hex}{ext}"
    temp_path = TMP_DIR / temp_filename

    with open(temp_path, "wb") as buffer:
        import shutil
        shutil.copyfileobj(screenshot.file, buffer)

    # Create job ID
    job_id = f"job_{uuid.uuid4().hex[:12]}"
    weights_status = check_phishpedia_weights()
    est_sec = 2 if (use_fallback or not weights_status["weights_loaded"]) else 15

    PHISHPEDIA_JOBS[job_id] = {
        "job_id": job_id,
        "status": "pending",
        "url": url,
        "inference_mode": "fallback" if (use_fallback or not weights_status["weights_loaded"]) else "full_ml",
        "estimated_seconds": est_sec,
        "result": None,
        "error": None,
        "annotated_bytes": None
    }

    logger.info("POST /api/visual-phishing-check — job_id=%s inference_mode=%s est=%ds",
                job_id, PHISHPEDIA_JOBS[job_id]["inference_mode"], est_sec)

    # Trigger background worker task
    import asyncio
    asyncio.create_task(process_phishpedia_job(job_id, url, str(temp_path), use_fallback=use_fallback))

    return {
        "status": "success",
        "data": {
            "job_id": job_id,
            "status": "pending",
            "inference_mode": PHISHPEDIA_JOBS[job_id]["inference_mode"],
            "estimated_seconds": est_sec
        },
        "meta": {"source_tool": "phishpedia"}
    }


@app.get("/api/visual-phishing-check/{job_id}", response_model=StandardResponse)
async def get_visual_phishing_job(job_id: str):
    """
    Polls the status and results of an ongoing or completed visual phishing check job.
    """
    logger.info("GET /api/visual-phishing-check/%s — polling job status", job_id)
    if job_id not in PHISHPEDIA_JOBS:
        logger.warning("GET /api/visual-phishing-check/%s — 404 job not found", job_id)
        raise HTTPException(status_code=404, detail=f"Visual phishing job '{job_id}' not found.")

    job = PHISHPEDIA_JOBS[job_id]
    logger.info("GET /api/visual-phishing-check/%s — status=%s", job_id, job['status'])
    job_data = {
        "job_id": job["job_id"],
        "status": job["status"],
        "result": job.get("result"),
        "error": job.get("error")
    }

    return {
        "status": "success",
        "data": job_data,
        "meta": {"source_tool": "phishpedia"}
    }


@app.get("/api/visual-phishing-image/{filename}")
async def get_visual_phishing_image(filename: str):
    """
    Serves the annotated screenshot image with detected logo bounding boxes.
    """
    job_id = filename.replace(".png", "")
    if job_id not in PHISHPEDIA_JOBS or not PHISHPEDIA_JOBS[job_id].get("annotated_bytes"):
        raise HTTPException(status_code=404, detail="Annotated screenshot image not found.")

    png_bytes = PHISHPEDIA_JOBS[job_id]["annotated_bytes"]
    return Response(content=png_bytes, media_type="image/png")


@app.post("/api/link-infrastructure", response_model=StandardResponse)
async def link_infrastructure(payload: LinkInfrastructureRequest):
    """
    Surfaces other scanned assets sharing technical fingerprints (hosting IP, image hash, target brand)
    with the given evidence items.
    """
    try:
        results = find_linked_infrastructure(
            evidence_domains=payload.evidence_domains or [],
            evidence_logos=payload.evidence_logos or [],
            evidence_visual_phishing=payload.evidence_visual_phishing or []
        )
        return {
            "status": "success",
            "data": results,
            "meta": {"source_tool": "infrastructure_fingerprinting"}
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to query linked infrastructure: {str(e)}")


@app.get("/api/offender-clusters", response_model=StandardResponse)
async def offender_clusters(brand: Optional[str] = Query(None), case_id: Optional[str] = Query(None)):
    """
    Returns all detected offender clusters across the database with confidence scores,
    signal tags, and network graph node/edge definitions. Supports filtering by brand or case_id.
    """
    try:
        clusters = get_offender_clusters(brand=brand, case_id=case_id)
        return {
            "status": "success",
            "data": clusters,
            "meta": {"source_tool": "infrastructure_fingerprinting", "filter_brand": brand, "filter_case_id": case_id}
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to compute offender clusters: {str(e)}")


from database import log_case_event, fetch_case_timeline
from schemas import CaseEventRequest


@app.get("/api/case/{case_id}/timeline", response_model=StandardResponse)
async def get_case_timeline(case_id: str):
    """
    Returns chronological event log timeline for a given case_id.
    """
    try:
        events = fetch_case_timeline(case_id)
        return {
            "status": "success",
            "data": {
                "case_id": case_id,
                "total_events": len(events),
                "timeline": events
            },
            "meta": {"source_tool": "system"}
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch case timeline: {str(e)}")


@app.post("/api/case/{case_id}/event", response_model=StandardResponse)
async def post_case_event(case_id: str, payload: CaseEventRequest):
    """
    Logs an append-only timeline event for a case.
    """
    try:
        log_case_event(
            case_id=case_id,
            event_type=payload.event_type,
            description=payload.description,
            metadata=payload.metadata
        )
        return {
            "status": "success",
            "data": {"case_id": case_id, "event_type": payload.event_type, "description": payload.description},
            "meta": {"source_tool": "system"}
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to log case event: {str(e)}")


from services.rescan_service import rescan_case_evidence
from schemas import CaseRescanRequest


@app.post("/api/case/{case_id}/rescan", response_model=StandardResponse)
async def rescan_case(case_id: str, payload: CaseRescanRequest):
    """
    Re-checks case evidence against live DNS state, diffing new status against saved evidence.
    """
    try:
        result = rescan_case_evidence(
            case_id=case_id,
            evidence_domains=payload.evidence_domains or [],
            evidence_logos=payload.evidence_logos or [],
            evidence_visual_phishing=payload.evidence_visual_phishing or []
        )
        return {
            "status": "success",
            "data": result,
            "meta": {"source_tool": "rescan_service"}
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Case re-scan failed: {str(e)}")


from services.intent_classifier_service import classify_intent
from schemas import ClassifyIntentRequest
from database import insert_scanned_asset


@app.post("/api/classify-intent", response_model=StandardResponse)
async def classify_intent_endpoint(payload: ClassifyIntentRequest):
    """
    Classifies brand usage intent (reseller, news, fan page, parody, counterfeit, phishing).
    Supports domain allowlist overrides and manual investigator label confirmation.
    """
    try:
        res = classify_intent(
            text=payload.text,
            url=payload.url,
            domain=payload.domain,
            override_label=payload.override_label
        )
        
        # Persist classification result into SQLite assets table if domain is present
        if res.get("domain"):
            try:
                insert_scanned_asset(
                    asset_type="domain",
                    asset_id=res["domain"],
                    intent_label=res["top_label"],
                    intent_confidence=res["confidence"],
                    metadata={
                        "is_legitimate": res["is_legitimate"],
                        "is_override": res["is_override"],
                        "override_reason": res.get("override_reason")
                    }
                )
                log_case_event(
                    "default",
                    "intent_classified",
                    f"Intent classified for {res['domain']}: '{res['top_label']}' ({res['confidence']}%)"
                )
            except Exception as db_err:
                pass

        return {
            "status": "success",
            "data": res,
            "meta": {"source_tool": "intent_classifier"}
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Intent classification failed: {str(e)}")


from services.listing_service import analyze_marketplace_listing, get_sample_listings
from schemas import ListingCheckRequest, ListingBatchUploadRequest


@app.post("/api/listing-check", response_model=StandardResponse)
async def listing_check_endpoint(
    title: str = Form(...),
    seller_name: str = Form(...),
    description: Optional[str] = Form(None),
    price: Optional[float] = Form(None),
    currency: str = Form("USD", description="Price currency: USD or INR"),
    target_brand: Optional[str] = Form(None),
    image: Optional[UploadFile] = File(None)
):
    """
    Analyzes a marketplace product listing for counterfeit indicators, image hash
    similarity, and price anomalies. Supports both USD and INR price comparison
    against the correct currency MSRP for the target brand.
    """
    try:
        temp_path = None
        if image and image.filename:
            from utils.temp_file import TMP_DIR
            ext = Path(image.filename).suffix or ".png"
            temp_filename = f"listing_{uuid.uuid4().hex}{ext}"
            temp_path = str(TMP_DIR / temp_filename)
            with open(temp_path, "wb") as buffer:
                import shutil
                shutil.copyfileobj(image.file, buffer)

        res = analyze_marketplace_listing(
            title=title,
            seller_name=seller_name,
            description=description,
            price=price,
            currency=currency.upper(),
            target_brand=target_brand,
            image_path=temp_path
        )

        if temp_path and os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except Exception:
                pass

        return {
            "status": "success",
            "data": res,
            "meta": {"source_tool": "counterfeit_listing_analyzer"}
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Marketplace listing analysis failed: {str(e)}")


@app.post("/api/listing-batch-upload", response_model=StandardResponse)
async def listing_batch_upload_endpoint(payload: ListingBatchUploadRequest):
    """
    Ingests a batch array of structured listing items (JSON/CSV upload) for bulk counterfeit detection.
    Each item may include a 'currency' field ("USD" or "INR"); defaults to "USD" if absent.
    """
    try:
        results = []
        for item in payload.listings:
            res = analyze_marketplace_listing(
                title=item.get("title", "Marketplace Item"),
                seller_name=item.get("seller_name", "Unknown Seller"),
                description=item.get("description"),
                price=item.get("price"),
                currency=str(item.get("currency", "USD")).upper(),
                target_brand=item.get("target_brand"),
                listing_id=item.get("listing_id")
            )
            results.append(res)

        return {
            "status": "success",
            "data": {
                "total_ingested": len(results),
                "listings": results
            },
            "meta": {"source_tool": "counterfeit_listing_analyzer"}
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Bulk listing batch ingestion failed: {str(e)}")


@app.get("/api/listing-sample-data", response_model=StandardResponse)
async def listing_sample_data_endpoint():
    """
    Returns preloaded sample/demo marketplace listings (mix of counterfeit replicas and authorized sellers).
    """
    try:
        samples = get_sample_listings()
        return {
            "status": "success",
            "data": {
                "count": len(samples),
                "sample_listings": samples
            },
            "meta": {"source_tool": "counterfeit_listing_analyzer"}
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch sample listings: {str(e)}")


from services.social_profile_service import (
    analyze_social_profile,
    get_sample_social_profiles,
    toggle_social_allowlist_handle
)
from schemas import (
    SocialProfileCheckRequest,
    SocialProfileBatchUploadRequest,
    SocialProfileVerifyOverrideRequest
)


@app.post("/api/social-profile-check", response_model=StandardResponse)
async def social_profile_check_endpoint(
    platform: str = Form(...),
    handle: str = Form(...),
    display_name: Optional[str] = Form(None),
    bio_text: Optional[str] = Form(None),
    follower_count: Optional[int] = Form(None),
    account_age_days: Optional[int] = Form(None),
    target_brand: Optional[str] = Form(None),
    protected_entity: Optional[str] = Form(None),
    entity_type: str = Form("brand", description="Entity type: 'brand' or 'individual'"),
    official_handle: Optional[str] = Form(None),
    profile_image: Optional[UploadFile] = File(None)
):
    """
    Analyzes a social media profile for brand or creator impersonation, giveaway scams, and image likeness.
    """
    try:
        temp_path = None
        if profile_image and profile_image.filename:
            from utils.temp_file import TMP_DIR
            ext = Path(profile_image.filename).suffix or ".png"
            temp_filename = f"social_{uuid.uuid4().hex}{ext}"
            temp_path = str(TMP_DIR / temp_filename)
            with open(temp_path, "wb") as buffer:
                import shutil
                shutil.copyfileobj(profile_image.file, buffer)

        entity_name = protected_entity or target_brand or "Target Entity"

        res = analyze_social_profile(
            platform=platform,
            handle=handle,
            display_name=display_name,
            bio_text=bio_text,
            follower_count=follower_count,
            account_age_days=account_age_days,
            target_brand=entity_name,
            protected_entity=entity_name,
            entity_type=entity_type,
            official_handle=official_handle,
            profile_image_path=temp_path
        )

        if temp_path and os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except Exception:
                pass

        return {
            "status": "success",
            "data": res,
            "meta": {"source_tool": "social_impersonation_analyzer"}
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Social profile analysis failed: {str(e)}")


@app.post("/api/social-profile-batch-upload", response_model=StandardResponse)
async def social_profile_batch_upload_endpoint(payload: SocialProfileBatchUploadRequest):
    """
    Ingests a batch array of structured social profile objects for bulk impersonation detection.
    """
    try:
        results = []
        for item in payload.profiles:
            entity_name = item.get("protected_entity") or item.get("target_brand") or "Target Entity"
            res = analyze_social_profile(
                platform=item.get("platform", "Instagram"),
                handle=item.get("handle", "@unknown"),
                display_name=item.get("display_name"),
                bio_text=item.get("bio_text"),
                follower_count=item.get("follower_count"),
                account_age_days=item.get("account_age_days"),
                target_brand=entity_name,
                protected_entity=entity_name,
                entity_type=item.get("entity_type", "brand"),
                official_handle=item.get("official_handle"),
                profile_id=item.get("profile_id")
            )
            results.append(res)

        return {
            "status": "success",
            "data": {
                "total_ingested": len(results),
                "profiles": results
            },
            "meta": {"source_tool": "social_impersonation_analyzer"}
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Bulk social profile ingestion failed: {str(e)}")


@app.get("/api/social-profile-sample-data", response_model=StandardResponse)
async def social_profile_sample_data_endpoint():
    """
    Returns preloaded sample/demo social media profiles (mix of fake impersonators and official brand accounts).
    """
    try:
        samples = get_sample_social_profiles()
        return {
            "status": "success",
            "data": {
                "count": len(samples),
                "sample_profiles": samples
            },
            "meta": {"source_tool": "social_impersonation_analyzer"}
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch sample social profiles: {str(e)}")


@app.post("/api/social-profile-verify-override", response_model=StandardResponse)
async def social_profile_verify_override_endpoint(payload: SocialProfileVerifyOverrideRequest):
    """
    Toggles manual investigator verification override for a social handle in config/social_allowlist.json.
    """
    try:
        res = toggle_social_allowlist_handle(payload.handle, add=payload.is_verified)
        return {
            "status": "success",
            "data": res,
            "meta": {"source_tool": "social_impersonation_analyzer"}
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to update verified handle override: {str(e)}")


@app.get("/api/demo/run-full-scenario", response_model=StandardResponse)
async def run_full_demo_scenario_endpoint():
    """
    Master One-Click Demo Scenario Endpoint.
    Seeds a coherent 5-surface fictional threat actor case for Rolex:
    - 1 Typosquat Domain
    - 1 Cloned Logo Match
    - 1 Visual Phishing Check
    - 1 Counterfeit Marketplace Listing
    - 1 Fake Social Media Impersonation Profile
    All assets share pHash/IP fingerprints and link into 1 Offender Cluster automatically.
    """
    try:
        from datetime import datetime, timezone
        from database import insert_scanned_asset, log_case_event

        shared_ip = "192.0.2.45"
        shared_phash = "a1b2c3d4e5f67890"

        # 1. Typosquat Domain Asset
        domain_item = {
            "domain": "rolex-luxury-watches-shop.com",
            "fuzzer": "addition",
            "isRegistered": True,
            "riskScore": 92,
            "dns_a": [shared_ip],
            "phash": shared_phash,
            "intent_label": "Counterfeit or impersonation",
            "intent_confidence": 95.0,
            "is_legitimate": False
        }
        insert_scanned_asset("domain", "rolex-luxury-watches-shop.com", ip_address=shared_ip, phash=shared_phash, target_brand="Rolex", confidence=92.0, metadata=domain_item)

        # 2. Cloned Logo Asset
        logo_item = {
            "candidate_filename": "rolex_crown_logo_fake.png",
            "phash_distance": 2,
            "dhash_distance": 3,
            "combined_similarity_percentage": 92.5,
            "likely_match": True,
            "ip_address": shared_ip,
            "phash": shared_phash,
            "target_brand": "Rolex"
        }
        insert_scanned_asset("logo", "rolex_crown_logo_fake.png", ip_address=shared_ip, phash=shared_phash, target_brand="Rolex", confidence=92.5, metadata=logo_item)

        # 3. Visual Phishing Asset
        phish_item = {
            "id": "DEMO-VP-ROLEX",
            "key": "DEMO-VP-ROLEX",
            "type": "visual_phishing",
            "url": "https://rolex-luxury-watches-shop.com/login.html",
            "verdict": "Phishing",
            "target_brand": "Rolex",
            "confidence": 96.0,
            "matched_domain": "rolex.com",
            "inference_mode": "full_ml",
            "is_fallback": False,
            "ip_address": shared_ip,
            "phash": shared_phash,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        insert_scanned_asset("visual_phishing", "https://rolex-luxury-watches-shop.com/login.html", ip_address=shared_ip, phash=shared_phash, target_brand="Rolex", confidence=96.0, metadata=phish_item)

        # 4. Counterfeit Marketplace Listing Asset
        listing_item = {
            "listing_id": "LST-ROLEX-001",
            "title": "Rolex Submariner Replica Brand New",
            "seller_name": "ReplicaDiscounts_Direct",
            "target_brand": "Rolex",
            "price": 199.99,
            "msrp": 10000.0,
            "discount_percentage": 98.0,
            "price_anomaly": True,
            "verdict": "High Risk Counterfeit",
            "risk_rating": 94.0,
            "phash": shared_phash,
            "intent_label": "Counterfeit or impersonation",
            "is_legitimate": False,
            "ip_address": shared_ip
        }
        insert_scanned_asset("listing", "LST-ROLEX-001", ip_address=shared_ip, phash=shared_phash, target_brand="Rolex", confidence=94.0, metadata=listing_item)

        # 5. Fake Social Media Profile Asset
        social_item = {
            "profile_id": "SOC-ROLEX-001",
            "platform": "Instagram",
            "handle": "@rolex_official_support_vip",
            "display_name": "Rolex Official VIP Support & Giveaways",
            "target_brand": "Rolex",
            "follower_count": 142,
            "account_age_days": 12,
            "verdict": "High Risk Fake Account",
            "risk_rating": 94.5,
            "phash": shared_phash,
            "intent_label": "Counterfeit or impersonation",
            "intent_confidence": 96.5,
            "is_legitimate": False,
            "is_verified_official": False,
            "ip_address": shared_ip
        }
        insert_scanned_asset("social_profile", "Instagram:@rolex_official_support_vip", ip_address=shared_ip, phash=shared_phash, target_brand="Rolex", confidence=94.5, metadata=social_item)

        log_case_event("default", "master_demo_run", "Master 5-surface demo scenario seeded for brand 'Rolex'. Linked 5 assets into offender cluster CLUSTER-ROLEX-OFFENDER-01.")

        master_case_data = {
            "brand_name": "Rolex Corporate (Master Demo)",
            "total_assets_linked": 5,
            "target_brand": "Rolex",
            "cluster_id": "CLUSTER-ROLEX-OFFENDER-01",
            "shared_ip": shared_ip,
            "shared_phash": shared_phash,
            "selected_domains": [domain_item],
            "selected_logos": [logo_item],
            "selected_visual_phishing": [phish_item],
            "selected_listings": [listing_item],
            "selected_social_profiles": [social_item],
            "composite_risk_score": 93.8,
            "notes": "Coherent 5-surface threat actor campaign targeting Rolex via typosquatting domain, cloned logo assets, visual phishing credential harvest portal, $199 counterfeit marketplace listings, and fake Instagram support account."
        }

        return {
            "status": "success",
            "data": master_case_data,
            "meta": {"source_tool": "master_demo_scenario_runner"}
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to execute master demo scenario: {str(e)}")



