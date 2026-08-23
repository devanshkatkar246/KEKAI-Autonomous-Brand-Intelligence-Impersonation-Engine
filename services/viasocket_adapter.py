"""
services/viasocket_adapter.py

TASK 7 — viaSocket Workflow & Automation Adapter

Safe, non-blocking viaSocket event orchestration layer for KEIKAI.

Key Design Principles:
- viaSocket is an ORCHESTRATION / NOTIFICATION layer ONLY. It is NOT the authority for approval, evidence validity, legitimacy, provider identity, or LIVE submission.
- Emits sanitized, safe internal event payloads (no API keys, tokens, or private credentials).
- Operates with bounded HTTP timeout (max 2.0s) and fails silently/gracefully if viaSocket is offline or unconfigured.
- Does NOT block the core KEIKAI investigation or takedown pipeline.
"""

import json
import logging
import os
import time
import urllib.request
import urllib.error
from datetime import datetime, timezone
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

# Safe internal event model types
ALLOWED_EVENT_TYPES = {
    "INVESTIGATION_STARTED",
    "CANDIDATE_DISCOVERED",
    "LOGO_MATCH_DETECTED",
    "IMPERSONATION_CONFIRMED",
    "CASE_CREATED",
    "EVIDENCE_READY",
    "APPROVAL_REQUIRED",
    "APPROVAL_GRANTED",
    "APPROVAL_REVOKED",
    "TAKEDOWN_ROUTE_RESOLVED",
    "TAKEDOWN_SUBMITTED",
    "TAKEDOWN_UNKNOWN",
    "TAKEDOWN_REJECTED",
    "TAKEDOWN_RESOLVED",
    "DAILY_INVESTIGATION_SUMMARY"
}

SENSITIVE_KEYS = {"api_key", "token", "authorization", "secret", "password", "auth", "private_key"}


def _sanitize_payload(data: Any) -> Any:
    """Recursively strips sensitive keys from event payloads."""
    if isinstance(data, dict):
        sanitized = {}
        for k, v in data.items():
            if str(k).lower() in SENSITIVE_KEYS:
                continue
            sanitized[k] = _sanitize_payload(v)
        return sanitized
    elif isinstance(data, list):
        return [_sanitize_payload(item) for item in data]
    return data


class ViaSocketWorkflowAdapter:

    def __init__(self, webhook_url: Optional[str] = None):
        self.webhook_url = webhook_url or os.environ.get("VIASOCKET_WEBHOOK_URL", "")

    @property
    def is_configured(self) -> bool:
        return bool(self.webhook_url and self.webhook_url.startswith("http"))

    def emit_event(self, event_type: str, case_id: Optional[str] = None, payload: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Emits a safe event payload to viaSocket webhook endpoint.
        Returns execution status without raising exceptions on viaSocket network errors.
        """
        if event_type not in ALLOWED_EVENT_TYPES:
            logger.warning(f"[viaSocket] Unknown event type '{event_type}'; emitting anyway under sanitized payload.")

        clean_payload = _sanitize_payload(payload or {})

        event_data = {
            "event_type": event_type,
            "system": "KEIKAI_BRAND_PROTECTION",
            "case_id": case_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": clean_payload
        }

        if not self.is_configured:
            logger.info(f"[viaSocket DRY_RUN] Webhook unconfigured. Emitted event '{event_type}' locally for case '{case_id}'.")
            return {
                "status": "DISABLED",
                "event_type": event_type,
                "case_id": case_id,
                "delivered": False,
                "detail": "viaSocket webhook URL not configured (operating in local event log mode)."
            }

        try:
            raw_body = json.dumps(event_data).encode("utf-8")
            req = urllib.request.Request(
                self.webhook_url,
                data=raw_body,
                headers={
                    "Content-Type": "application/json",
                    "User-Agent": "KEIKAI-viaSocket-Adapter/1.0"
                },
                method="POST"
            )

            with urllib.request.urlopen(req, timeout=2.0) as resp:
                status_code = resp.status
                resp_text = resp.read().decode("utf-8", errors="ignore")
                logger.info(f"[viaSocket HTTP {status_code}] Event '{event_type}' delivered successfully.")
                return {
                    "status": "DELIVERED",
                    "event_type": event_type,
                    "case_id": case_id,
                    "http_code": status_code,
                    "delivered": True,
                    "response": resp_text
                }

        except urllib.error.HTTPError as e:
            logger.warning(f"[viaSocket HTTP {e.code}] Event delivery failed for '{event_type}': {e.reason}")
            return {
                "status": "DELIVERY_FAILED",
                "event_type": event_type,
                "case_id": case_id,
                "http_code": e.code,
                "delivered": False,
                "error": f"HTTP {e.code}: {e.reason}"
            }
        except (urllib.error.URLError, TimeoutError, Exception) as err:
            logger.warning(f"[viaSocket Timeout/Error] Event delivery failed for '{event_type}': {err}")
            return {
                "status": "NETWORK_ERROR",
                "event_type": event_type,
                "case_id": case_id,
                "delivered": False,
                "error": str(err)
            }

    def notify_case_created(self, case_id: str, case_data: Dict[str, Any]) -> Dict[str, Any]:
        return self.emit_event("CASE_CREATED", case_id, case_data)

    def notify_approval_required(self, case_id: str, snapshot_id: str, target_domain: str) -> Dict[str, Any]:
        return self.emit_event("APPROVAL_REQUIRED", case_id, {
            "snapshot_id": snapshot_id,
            "target_domain": target_domain,
            "action": "Human review & approval required before takedown dispatch"
        })

    def notify_takedown_status(self, case_id: str, submission_id: str, status: str, provider: str) -> Dict[str, Any]:
        event_name = "TAKEDOWN_SUBMITTED" if "SUBMIT" in status or "COMPLETED" in status or "SENT" in status else "TAKEDOWN_UNKNOWN"
        return self.emit_event(event_name, case_id, {
            "submission_id": submission_id,
            "status": status,
            "provider": provider
        })

    def send_summary(self, summary_data: Dict[str, Any]) -> Dict[str, Any]:
        return self.emit_event("DAILY_INVESTIGATION_SUMMARY", None, summary_data)


_VIASOCKET_ADAPTER = ViaSocketWorkflowAdapter()


def emit_viasocket_event(event_type: str, case_id: Optional[str] = None, payload: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Public wrapper to emit viaSocket event."""
    return _VIASOCKET_ADAPTER.emit_event(event_type, case_id, payload)
