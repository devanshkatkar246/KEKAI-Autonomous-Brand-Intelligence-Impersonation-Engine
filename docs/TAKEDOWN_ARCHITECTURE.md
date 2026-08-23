# KEIKAI Takedown / Abuse Response Architecture

## 1. Current architecture

KEIKAI is a FastAPI application (`main.py`) with a React/Vite frontend (`frontend/src`). API endpoints are declared directly in `main.py`; business logic is split into focused modules under `services/`. `schemas.py` contains request/response contracts. SQLite persistence is centralized in `database.py` and currently stores scanned assets plus append-only case-timeline events in `brand_protection.db`.

The active investigation flow is:

`OnboardingPage -> DomainWatchTab / LogoMatchTab -> selected evidence in App.jsx -> LinkedInfrastructureTab -> CaseReportTab -> PDF export`.

Candidate discovery combines dnstwist, OpenPhish, and PhishTank through `services/threat_intelligence/`. Candidate evaluation uses intent classification, visual/logo analysis, Phishpedia, and impersonation signal fusion. Results are indexed as assets for infrastructure correlation and can be added to a client-held case selection. The backend timeline is persisted, but there is no persisted first-class case aggregate yet.

## 2. Existing reusable services

Do not recreate these services:

| Concern | Reuse |
| --- | --- |
| Domain/registration intelligence | `services/dns_intelligence_service.py`, `services/rdap_service.py`, `services/asn_intelligence_service.py`, `services/infrastructure_service.get_domain_intelligence` |
| Current non-submitting abuse target selection | `services/abuse_target_service.resolve_abuse_targets` and `/api/abuse-target-resolution` |
| Legitimacy protection | `abuse_target_service._evaluate_legitimacy_gate` |
| Asset/evidence correlation | `services/infrastructure_service.py`, `database.py:assets` |
| Case event audit trail | `database.log_case_event` / `fetch_case_timeline`, `/api/case/{case_id}/timeline` |
| Evidence revalidation | `services/rescan_service.py`, `/api/case/{case_id}/rescan` |
| Executive report generation | `services/report_service.py`, `/api/generate-report` |
| Candidate acquisition / visual assets | `services/candidate_acquisition_service.py`, `services/logo_intelligence_service.py` |

## 3. Current intelligence and evidence capabilities

DNS resolves A, AAAA, CNAME, MX, and NS records, extracts IPs, and performs PTR lookup. RDAP returns normalized registrar, abuse contact, registration events, nameservers, status flags, and raw payload. ASN lookup uses IP RDAP with a guarded fallback and labels provider evidence as verified, inferred, or unavailable. `get_domain_intelligence` already composes DNS, RDAP, ASN enrichment, and abuse-target resolution.

Visual evidence can originate from user-uploaded screenshots, Phishpedia annotation, or candidate acquisition. Candidate acquisition fetches HTML and saves a proxy visual from an Open Graph image, favicon, or suitable inline asset; it is **not** a browser-rendered Playwright/Puppeteer capture. Persistent visual artefacts are under `uploads/screenshots`, `uploads/logo_crops`, and `uploads/visual_assets`; temporary uploads use `utils/temp_file.py` and are cleaned up.

## 4. Abuse-response integration point and data flow

Use the existing output of `get_domain_intelligence` / `resolve_abuse_targets` after a candidate has enough investigation evidence, rather than running a new parallel RDAP/DNS stack.

`candidate asset + investigation evidence -> domain intelligence and legitimacy decision -> reporting targets -> draft AbuseCase -> human approval -> submission router -> submission attempts/status`.

The existing `reporting_readiness.status == READY_FOR_HUMAN_REVIEW` is a draft-readiness signal only. It must never call a submission adapter. The future UI should surface the abuse workflow from the case/evidence context (likely `CaseReportTab.jsx`), not from raw discovery rows, because it needs a stable evidence selection, analyst review, and provenance.

## 5. Proposed domain model (future implementation)

Extend rather than duplicate `assets` and `case_timeline_events`. Add first-class tables or equivalent server-side models only when a future task needs persistence:

| Object | Core fields | Relationship / source |
| --- | --- | --- |
| `AbuseCase` | id, investigation_id, domain, target_brand, official_domain, confidence, legitimacy_state, state, created/updated timestamps | Links selected existing asset IDs and case timeline |
| `ReportingTarget` | id, abuse_case_id, type, provider name, channel, endpoint/contact, confidence, source, provenance, resolved_at | Seed from existing registrar/network targets; preserve RDAP/IP-RDAP evidence |
| `EvidenceArtifact` | id, abuse_case_id, asset_id/path/URL, type, digest, collected_at, provenance, immutable metadata | Reference existing assets/uploads; do not duplicate binary data by default |
| `ProviderCapability` | provider key, supported channels, required fields, attachment/size limits, status support, config requirements | Static adapter metadata, not a secret-bearing record |
| `SubmissionAttempt` | id, abuse_case_id, reporting_target_id, channel, state, prepared_at, approved_at/by, submitted_at, idempotency key, request provenance | An append-only attempt record; no automatic creation from confidence |
| `SubmissionResult` | attempt_id, provider reference, state, response summary, received_at, next_action_at, error category | Store redacted response metadata only |
| `LegitimacyDecision` | abuse_case_id, state, reason, inputs/provenance, analyst override, decided_at/by | Preserve current resolver output and allow audited human correction |

Legitimacy states are `OFFICIAL_DOMAIN`, `AUTHORIZED_DOMAIN`, `KNOWN_PARTNER`, `RELATED_DOMAIN`, `UNKNOWN_DOMAIN`, and `SUSPICIOUS_UNAUTHORIZED_DOMAIN`. The currently implemented resolver covers official, authorized, unknown fallback, and suspicious-unapproved. `KNOWN_PARTNER` and `RELATED_DOMAIN` need an explicit curated relationship source and must default to blocked/manual review until that source exists.

## 6. Provider adapter model (future implementation)

Create an `AbuseSubmissionRouter` that selects an adapter from a normalized `ReportingTarget`; it must not decide legitimacy or evidence sufficiency. Project-style service names could be `services/abuse_submission_router.py` and `services/abuse_adapters/*.py`.

Every adapter should expose equivalent operations:

- `can_handle(target)` — deterministic provider/channel match with evidence level.
- `capabilities()` — channels, required fields, authentication, attachments, status polling, and rate limits.
- `validate_configuration()` — server-side configuration presence only; never return secrets.
- `prepare_submission(case, target, evidence)` — validates and produces a reviewable redacted draft; no network side effect.
- `submit(approved_attempt)` — performs one idempotent, audited submission after explicit approval.
- `get_status(attempt)` — optional provider status refresh with safe error normalization.

Initial adapter types: provider API (Cloudflare/Namecheap/etc.), registrar abuse email, network/hosting abuse email, and browser-form fallback. Provider identity inferred from ASN/CDN data is not proof of site ownership; preserve the existing VERIFIED/INFERRED/UNAVAILABLE provenance and require human review for inferred targets.

## 7. Legitimacy gate and submission lifecycle

The mandatory transition is:

`DRAFT -> EVIDENCE_READY -> LEGITIMACY_REVIEWED -> TARGET_RESOLVED -> PENDING_HUMAN_APPROVAL -> APPROVED -> SUBMITTED -> ACKNOWLEDGED / IN_PROGRESS / RESOLVED / REJECTED / FAILED / CANCELLED`.

`OFFICIAL_DOMAIN` and `AUTHORIZED_DOMAIN` must transition to `BLOCKED` and have no submit action. A high confidence score can reach `PENDING_HUMAN_APPROVAL`; it cannot approve or submit. Approval must record reviewer identity, timestamp, the evidence snapshot/digest, and selected target/channel. Retrying must create a new `SubmissionAttempt`, never overwrite the prior result.

### Implemented Task 1 assessment layer

`services/abuse_response_service.py` is the current read-only safety layer behind `POST /api/abuse-response/evaluate`. It derives `EvidenceArtifact` records from existing investigation output and hashes server-owned screenshot bytes with SHA-256; only a filename reference is returned, never an internal path. The deterministic additive rubric is: strong visual match 30, feed confirmation 25, credential indicator 20, screenshot captured 15, logo detection 15, page-content brand match 10, and dnstwist permutation 10 (capped at 100). `EVIDENCE_HIGH` is 70+, medium is 45–69, and low is 1–44. Screenshot failure is explicitly missing visual evidence, never a safety result.

The versioned `config/authorization_registry.json` is intentionally empty until a trusted brand-owner source populates it. It supports `AUTHORIZED_DOMAIN`, `KNOWN_PARTNER`, `KNOWN_SUBSIDIARY`, and `KNOWN_RELATED_DOMAIN`. Exact domain-or-subdomain boundary matching is used; substring matching is never used. Only official/authorized records block immediately. Partner, subsidiary, related, and unknown records require manual review. A domain becomes `SUSPICIOUS_UNAUTHORIZED_DOMAIN` only where existing domain-permutation, phishing-feed, or credential evidence supports that conclusion; otherwise it remains `UNKNOWN_DOMAIN`.

## 8. Secrets and configuration

Current server configuration uses environment variables read in service modules (`os.getenv`), for example `PHISHTANK_API_KEY`, acquisition timeouts, and Phishpedia/logo thresholds. There is no `.env` loader, secret manager, or frontend runtime-secret mechanism in the repository. Future provider credentials therefore belong in deployment/runtime environment variables read only by backend adapter modules. Add an ignored local example file and a documented production secret source in the future integration task; never put provider credentials in `frontend/src`, logs, API responses, database rows, or committed files.

## 9. Error handling, persistence, caching, and tests

FastAPI returns the `StandardResponse` shape for most endpoints and has global HTTP, validation, and generic exception handlers. Service modules use module logging and explicit normalized status/reason codes. DNS/RDAP/ASN/abuse-target lookups have in-memory TTL caches; they are process-local and should not be reused as submission-status storage.

Future adapters should classify errors as configuration, validation, provider rejection, transport timeout, authentication, rate limit, and unknown. Redact contacts, tokens, headers, and provider payloads in logs/events. Persist immutable evidence references and submission transitions in SQLite (or the later persistence layer) and log a corresponding case timeline event.

Add deterministic unit tests with mocked HTTP/email/browser boundaries for the gate, router selection, draft preparation, approval enforcement, idempotency, retries, redaction, and status transitions. Preserve current tests for RDAP/DNS/ASN/target resolution; no live provider calls in the standard suite.

## 10. Future integration files

Likely future additions: `services/abuse_submission_router.py`, `services/abuse_adapters/`, an abuse-case persistence module/migration, request schemas in `schemas.py`, guarded API routes in `main.py` or a future router module, and an approval UI integrated with `CaseReportTab.jsx`. Do **not** duplicate `rdap_service.py`, `dns_intelligence_service.py`, `asn_intelligence_service.py`, `abuse_target_service.py`, `report_service.py`, `database.py`, or candidate acquisition/screenshot services.

## 11. Audit baseline (2026-08-23)

- Python: `python -m pytest -q` could not run because `pytest` is not installed (`No module named pytest`). The repository's native `unittest` suite was then started with discovery; its initial abuse-target and API tests passed, but the command exceeded the 30-second execution window while an integration scan was running. Network warnings were expected in this environment because outbound RDAP connections were refused.
- Frontend: `npm run build` did not reach compilation. Vite failed loading `@tailwindcss/oxide-win32-x64-msvc` (native module reported invalid UTF-8) and also reported `spawn EPERM`. This is an installed dependency/environment baseline issue; no application files were altered.
