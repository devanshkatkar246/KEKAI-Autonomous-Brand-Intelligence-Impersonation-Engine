# KEKAI — Current Implementation & Scope Status

This document provides a factual breakdown of KEKAI's current implementation status across all system capabilities.

---

## Capability Status Breakdown

### 1. IMPLEMENTED (Core Operational Pipeline)
* **Domain Typosquat Scan**: Domain permutation generation via `dnstwist` CLI wrapper (`services/dnstwist_service.py`).
* **Zero-Shot Intent Classification**: Categorization of domain intent via transformer classifier (`services/intent_classifier_service.py`).
* **Multi-Signal Visual Fallback Engine**: 8-layer visual logo recognition chain including pHash, dHash, feature embeddings, and OCR text (`services/logo_fallback_service.py`).
* **Infrastructure Clustering**: Graph correlation across IP addresses, MX records, SSL certs, and visual fingerprints (`services/infrastructure_service.py`).
* **Public RDAP Intelligence**: Domain registration metadata lookup via public RDAP bootstrap endpoints (`services/rdap_service.py`).
* **PDF Report Generator**: Executive audit report compilation and PDF export (`services/report_service.py`).
* **Takedown Safety Control Plane**: Frozen evidence snapshot creation, SHA-256 integrity verification, and atomic SQLite claim leases (`services/universal_abuse_router.py`).
* **Human Analyst Approval Gate**: Mandatory human approval boundary before external response execution (`database.py`, `main.py`).
* **Cloudflare Abuse Client (DRY_RUN)**: Simulated abuse report creation and DRY_RUN state response (`services/cloudflare_abuse_client.py`).
* **viaSocket Workflow Adapter**: Non-blocking sanitized event emission (`services/viasocket_adapter.py`).
* **Interactive Demo Scenario**: 6-stage guided demonstration of the investigation lifecycle (`frontend/src/components/DemoScenarioModal.jsx`).

### 2. PARTIAL / FALLBACK
* **Phishpedia Deep Learning Model**: Fully integrated in `services/phishpedia_service.py`; operates when PyTorch weight files exist in `./Phishpedia/models/`, automatically falling back to the 8-layer visual chain when weights are unpopulated.

### 3. OPTIONAL / CONFIGURATION-DEPENDENT
* **Cloudflare LIVE Abuse Submission**: Requires setting `ABUSE_SUBMISSION_MODE=LIVE` and provisioning `CLOUDFLARE_API_TOKEN` & `CLOUDFLARE_ACCOUNT_ID`.
* **viaSocket External Delivery**: Requires provisioning `VIASOCKET_WEBHOOK_URL`.
* **PhishTank Feed Integration**: Public dataset accessible without credentials; accepts optional `PHISHTANK_API_KEY` for higher rate limits.

### 4. DEMO-ONLY
* **Amazon Demo Campaign Fixture**: Deterministic demo dataset (`amazon-security-login.example` displaying a 96.8% visual similarity example) used for judge demonstrations.

### 5. UNCONFIGURED / NOT IMPLEMENTED
* **Live Email Takedown Dispatch**: Resend/SendGrid adapters exist in `services/universal_abuse_router.py` but remain unconfigured by default.
