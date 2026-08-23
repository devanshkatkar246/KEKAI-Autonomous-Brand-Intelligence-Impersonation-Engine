import time
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field


class SourceHealth(BaseModel):
    source_name: str
    status: str = Field(..., description="Status: AVAILABLE, DEGRADED, or UNAVAILABLE")
    message: str = ""
    cached_records: int = 0
    last_updated: Optional[str] = None


class NormalizedCandidate(BaseModel):
    candidate_id: str
    domain: str
    url: Optional[str] = None
    hostname: str
    sources: List[str] = Field(default_factory=list)
    source_types: List[str] = Field(default_factory=list)
    target_brand: Optional[str] = None
    is_known_phishing: bool = False
    verified: bool = False
    online: bool = False
    fuzzer: Optional[str] = None
    ip_addresses: List[str] = Field(default_factory=list)
    dns_ns: List[str] = Field(default_factory=list)
    dns_mx: List[str] = Field(default_factory=list)
    banner: Optional[str] = None
    provenance: Dict[str, Any] = Field(default_factory=dict)
    discovery_timestamp: str = Field(default_factory=lambda: time.strftime("%Y-%m-%dT%H:%M:%SZ"))

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump()
