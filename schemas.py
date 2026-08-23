from typing import Any, List, Optional, Dict
from pydantic import BaseModel, Field


class MetaModel(BaseModel):
    source_tool: str = Field(..., description="Name of the underlying tool used (e.g. dnstwist, imagehash, system)")


class StandardResponse(BaseModel):
    status: str = Field(..., description="Request status: success or error")
    data: Optional[Any] = Field(None, description="Response payload data")
    meta: MetaModel
    error: Optional[str] = Field(None, description="Error message if status is error")


class DomainScanRequest(BaseModel):
    domain: str = Field(..., example="example.com", description="Target domain name or URL to scan")
    quick_mode: bool = Field(False, description="Fast scan mode using registered domain lookup & optimized fuzzers")
    timeout: Optional[int] = Field(60, ge=5, le=300, description="Subprocess execution timeout in seconds")


class DomainIntelligenceRequest(BaseModel):
    domain: str = Field(..., example="suspicious-domain.com", description="Target domain to resolve DNS and RDAP intelligence")
    use_cache: Optional[bool] = Field(True, description="Whether to use cached DNS/RDAP results")


class AsnIntelligenceRequest(BaseModel):
    ip: str = Field(..., example="1.2.3.4", description="Target IP address to resolve ASN & network organization")
    use_cache: Optional[bool] = Field(True, description="Whether to use cached ASN results")


class AbuseTargetResolutionRequest(BaseModel):
    domain: str = Field(..., example="suspicious-domain.com", description="Target domain name to resolve abuse targets")
    official_domain: Optional[str] = Field(None, description="Optional official brand domain for legitimacy check")
    authorized_domains: Optional[List[str]] = Field(None, description="Optional list of analyst authorized domains")
    evidence_score: Optional[float] = Field(85.0, description="Evidence score for readiness evaluation")
    use_cache: Optional[bool] = Field(True, description="Whether to use cached resolution")


class AbuseResponseEvaluateRequest(BaseModel):
    investigation_id: Optional[str] = Field(None, description="Existing investigation identifier")
    case_id: Optional[str] = Field(None, description="Existing case identifier")
    candidate_domain: str = Field(..., description="Candidate domain under review")
    target_brand: Optional[str] = Field(None, description="Target brand for registry lookup")
    official_domain: Optional[str] = Field(None, description="Known official domain")
    evidence: Dict[str, Any] = Field(default_factory=dict, description="Existing investigation evidence summary")
    authorization_registry: Optional[Dict[str, Any]] = Field(None, description="Trusted registry override for server-side/admin use")

class AbuseResponsePreviewRequest(AbuseResponseEvaluateRequest):
    provider_intelligence: Dict[str, Any] = Field(default_factory=dict, description="Existing backend provider intelligence snapshot")
class AbuseApprovalRequest(AbuseResponseEvaluateRequest):
    approved_by: Optional[str] = None
class AbuseSubmitRequest(BaseModel):
    approval_id: str
class AbuseRevokeRequest(BaseModel):
    approval_id: str


class UniversalRoutePreviewRequest(BaseModel):
    candidate_domain: str = Field(..., description="Target domain to resolve takedown route")
    target_brand: Optional[str] = Field(None, description="Target brand")
    official_domain: Optional[str] = Field(None, description="Official domain")
    use_cache: Optional[bool] = Field(True, description="Whether to use cached provider discovery")


class UniversalTakedownSubmitRequest(BaseModel):
    case_id: str = Field(..., description="Case identifier")
    approval_id: str = Field(..., description="Task 5 human approval ID")
    client_payload: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Client context metadata")


class HashMetrics(BaseModel):
    reference: str
    candidate: str
    distance: int
    similarity_percentage: float


class CompareResult(BaseModel):
    phash: HashMetrics
    dhash: HashMetrics
    combined_similarity_percentage: float
    likely_match: bool
    threshold: int


class CandidateRankResult(BaseModel):
    candidate_filename: str
    phash_distance: int
    dhash_distance: int
    phash_similarity: float
    dhash_similarity: float
    combined_similarity_percentage: float
    likely_match: bool


class LogoBatchResult(BaseModel):
    reference_filename: str
    total_candidates: int
    ranked_results: List[CandidateRankResult]


class VisualPhishingStatus(BaseModel):
    weights_loaded: bool
    weights_missing: List[str]
    message: str


class VisualPhishingResult(BaseModel):
    verdict: str = Field(..., description="Verdict: Phishing or Benign")
    target_brand: Optional[str] = Field(None, description="Identified target brand name if phishing")
    confidence: Optional[float] = Field(None, description="Confidence score percentage")
    matched_domain: Optional[str] = Field(None, description="Matched brand domain")
    annotated_image_url: Optional[str] = Field(None, description="URL path to annotated screenshot image with bounding boxes")


class VisualPhishingJobData(BaseModel):
    job_id: str
    status: str = Field(..., description="Job status: pending, processing, completed, failed")
    estimated_seconds: Optional[int] = 15
    result: Optional[VisualPhishingResult] = None
    error: Optional[str] = None


class LinkInfrastructureRequest(BaseModel):
    evidence_domains: Optional[List[Dict[str, Any]]] = []
    evidence_logos: Optional[List[Dict[str, Any]]] = []
    evidence_visual_phishing: Optional[List[Dict[str, Any]]] = []


class LinkedAsset(BaseModel):
    asset_type: str
    asset_id: str
    ip_address: Optional[str] = None
    phash: Optional[str] = None
    target_brand: Optional[str] = None
    matched_signals: List[str]
    overlap_count: int


class ClusterNode(BaseModel):
    id: str
    label: str
    type: str  # domain, logo, visual_phishing
    ip: Optional[str] = None


class ClusterEdge(BaseModel):
    source: str
    target: str
    relationship: str  # Same IP, Same Hash, Same Brand


class OffenderCluster(BaseModel):
    cluster_id: str
    asset_count: int
    confidence: str  # High, Medium, Low
    confidence_score: int
    shared_signals: List[str]
    assets: List[Dict[str, Any]]
    nodes: List[ClusterNode]
    edges: List[ClusterEdge]


class CaseEventRequest(BaseModel):
    event_type: str = Field(..., description="Type of event: scan_run, evidence_added, cluster_linked, note_added, report_exported")
    description: str = Field(..., description="Human-readable event summary")
    metadata: Optional[Dict[str, Any]] = None


class CaseRescanRequest(BaseModel):
    evidence_domains: Optional[List[Dict[str, Any]]] = []
    evidence_logos: Optional[List[Dict[str, Any]]] = []
    evidence_visual_phishing: Optional[List[Dict[str, Any]]] = []


class ClassifyIntentRequest(BaseModel):
    text: Optional[str] = Field(None, description="Page title, description, or social caption text to classify")
    url: Optional[str] = Field(None, description="Target webpage URL to fetch and extract text from")
    domain: Optional[str] = Field(None, description="Source domain name for allowlist check")
    override_label: Optional[str] = Field(None, description="Manual investigator label override")


class IntentProbabilityItem(BaseModel):
    label: str
    probability: float


class ClassifyIntentResponse(BaseModel):
    domain: Optional[str] = None
    top_label: str
    confidence: float
    is_legitimate: bool
    is_override: bool
    override_reason: Optional[str] = None
    probabilities: List[IntentProbabilityItem]


class ListingCheckRequest(BaseModel):
    title: str = Field(..., description="Product listing title")
    seller_name: str = Field(..., description="Seller or vendor username")
    description: Optional[str] = Field(None, description="Listing item description text")
    price: Optional[float] = Field(None, description="Listed item price in USD")
    target_brand: Optional[str] = Field(None, description="Target brand name e.g. Rolex, Apple")


class ListingBatchUploadRequest(BaseModel):
    listings: List[Dict[str, Any]] = Field(..., description="Array of listing objects for bulk ingestion")


class SocialProfileCheckRequest(BaseModel):
    platform: str = Field(..., description="Platform e.g. Instagram, X, Facebook, TikTok, LinkedIn")
    handle: str = Field(..., description="Social account handle e.g. @rolex_support")
    display_name: Optional[str] = Field(None, description="Account display name")
    bio_text: Optional[str] = Field(None, description="Profile bio text")
    follower_count: Optional[int] = Field(None, description="Account follower count")
    account_age_days: Optional[int] = Field(None, description="Account age in days")
    target_brand: Optional[str] = Field(None, description="Target brand or entity name")
    protected_entity: Optional[str] = Field(None, description="Protected entity name e.g. Alex Rivers")
    entity_type: Optional[str] = Field("brand", description="Entity type: 'brand' or 'individual'")
    official_handle: Optional[str] = Field(None, description="Known official handle for handle spoofing check")


class SocialProfileBatchUploadRequest(BaseModel):
    profiles: List[Dict[str, Any]] = Field(..., description="Array of profile objects for bulk ingestion")


class UniversalRoutePreviewRequest(BaseModel):
    domain: str = Field(..., description="Target candidate domain name")


class UniversalTakedownSubmitRequest(BaseModel):
    case_id: str = Field(..., description="Case identifier")
    approval_id: str = Field(..., description="Active human approval record ID")
    client_payload: Optional[Dict[str, Any]] = None


class SocialProfileVerifyOverrideRequest(BaseModel):
    handle: str = Field(..., description="Social account handle to add or remove from verified allowlist")
    is_verified: bool = Field(True, description="True to verify as official account, False to remove")


class EvidenceIntelligenceAnalyzeRequest(BaseModel):
    candidate_domain: str = Field(..., description="Target candidate domain name e.g. flpkpart.com")
    target_brand: str = Field(..., description="Target brand name e.g. Flipkart")
    official_domain: Optional[str] = Field(None, description="Official brand domain e.g. flipkart.com")
    screenshot_path: Optional[str] = None
    ocr_text: Optional[str] = None
    webpage_title: Optional[str] = None


