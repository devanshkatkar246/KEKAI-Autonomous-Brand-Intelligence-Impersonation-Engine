# KEIKAI — PPT PROJECT BRIEF

## 1. Executive Summary

KEIKAI is a FastAPI + React MVP for investigating suspected brand impersonation. It combines domain-permutation discovery, OpenPhish/PhishTank correlation, visual/logo analysis, intent signals, infrastructure linking, and PDF evidence reporting. Its strongest demonstrable claim is an explainable investigator workflow, not autonomous takedown or production monitoring.

## 2. Project Identity

- Team: BinaryBreez — Prestige Institute of Engineering Management & Research
- Track: 003 Cyber Security; Problem: 03-01 / IHCY1, ABIAE
- Members: Hritik Jaiswal (Lead), Devansh Katkar (AI & Cybersecurity Full Stack), Jeet Dubey (Research & Documentation), Bhumi Raghuvanshi (Design & Presentation).

## 3. Problem Statement

Brand abuse spans lookalike domains, cloned visual identities, phishing pages and related infrastructure. Investigators need to separate suspicious signals from legitimate references and preserve explainable evidence.

## 4. Target Users & Stakeholders

Brand-protection analysts, SOC teams, security researchers, marketplace trust-and-safety teams and affected brands. Current MVP use is analyst-assisted investigation.

## 5. Existing Gap

Discovery, visual review, technical attribution and evidence packaging are normally fragmented. KEIKAI presents these layers in one case-oriented workflow.

## 6. Solution Overview

Input a protected domain or logo → discover candidates → correlate feeds → inspect visual/content signals → link related fingerprints → select evidence → export an explainable PDF case report.

## 7. Core Value Proposition

Multi-signal, explainable investigation: domain similarity alone does not decide a case; intelligence provenance, visual evidence, intent and infrastructure are surfaced together.

## 8. System Architecture

React/Vite frontend calls a FastAPI API in `main.py`. Focused Python services wrap dnstwist, threat-intelligence adapters, image hashing, Phishpedia, DNS/RDAP/ASN intelligence, SQLite correlation, and FPDF reporting. Local uploads hold screenshots/visual artefacts; SQLite holds assets and timeline events.

## 9. End-to-End Workflow

`Onboarding → Domain Watch / Logo Match → candidate evidence → Linked Infrastructure → Case Report → PDF`. Optional registration/provider assessment and dry-run abuse controls are present but are not a validated production reporting capability.

## 10. AI/ML Intelligence

Phishpedia integration can use pretrained R-CNN logo detection and ResNet matching when local weights exist; otherwise the repository describes fallback behavior. KEIKAI also uses perceptual hashes and an intent-classifier service. Do not claim KEIKAI trained Phishpedia.

## 11. Domain & URL Intelligence

`dnstwist` generates typo, homoglyph, omission, transposition and bitsquatting candidates. OpenPhish and PhishTank adapters correlate feeds. DNS service resolves A/AAAA/CNAME/MX/NS and PTR; RDAP/ASN services add passive registration/network context. External access can be unavailable; caches/fallbacks exist.

## 12. Visual & Brand Intelligence

`imagehash_service.py` normalizes images and calculates pHash and dHash. pHash compares frequency structure; dHash emphasizes adjacent pixel gradients. Logo intelligence can acquire an HTML-derived OG-image/favicon proxy, crop visual assets, run OCR/matching, and preserve results. A proxy is not equivalent to a browser-rendered screenshot.

## 13. Content & Intent Intelligence

The code includes an intent classifier plus phishing/credential indicators in impersonation analysis. Allowlist/config-based context is used to avoid treating all brand mentions as abuse. Exact model benchmark metrics were not found in repository.

## 14. Risk Scoring Engine

There is no single global formula. DomainWatch uses UI-side risk thresholds (high ≥70, medium ≥40). The Task 1 evidence rubric is additive and explicit: strong visual 30, threat-feed confirmation 25, credential indicator 20, screenshot 15, logo detection 15, page-content match 10, domain permutation 10; high is ≥70. Demo-only fixtures contain separate illustrative risk breakdowns and must not be presented as validated production weights.

## 15. Evidence Generation

Evidence includes candidate/domain source provenance, DNS data, visual/logo scores, screenshot/proxy state, Phishpedia output, intent indicators, timeline events and selected case items. `report_service.py` produces a downloadable PDF. SHA-256 evidence artifacts and dry-run approval snapshots were added for the takedown-control work; their live workflow remains incomplete.

## 16. Offender / Re-upload Linking

Implemented: `infrastructure_service.py` indexes assets in SQLite and links shared IPs, pHash values, target brands and metadata into offender clusters. It is basic fingerprint correlation, not attribution of a real-world offender.

## 17. Key Features

| Feature | Technology | Status | Evidence |
|---|---|---|---|
| Typosquat discovery | dnstwist | Implemented | `dnstwist_service.py` |
| Feed correlation | OpenPhish, PhishTank adapters | Implemented with cache/failure states | `threat_intelligence/` |
| Logo similarity | ImageHash/Pillow | Implemented | `imagehash_service.py` |
| Visual recognition | Phishpedia pretrained model/fallback | Conditional | `phishpedia_service.py` |
| Infrastructure clustering | SQLite IP/hash correlation | Implemented | `infrastructure_service.py` |
| PDF case report | fpdf2 | Implemented | `report_service.py` |
| Provider/takedown controls | RDAP/DNS/ASN + dry-run services | Prototype/partial | abuse services |

## 18. Innovation

Technical: multi-source correlation across domain, feed, visual and infrastructure signals. Workflow: evidence-first case selection and explainable PDF. Security: legitimacy gates are designed to avoid automatically reporting official/authorized domains. Top three: explainable multi-signal analysis; linked technical fingerprints; analyst-facing evidence generation.

## 19. Technology Stack

Frontend: React 19, Vite 8, Tailwind 4, Lucide. Backend: Python, FastAPI, Pydantic, Uvicorn. Security/data: dnstwist, dnspython, requests/httpx, RDAP, SQLite. Visual: Pillow, ImageHash, OpenCV, Phishpedia. Reporting: fpdf2. No deployment configuration verified.

## 20. Repository Architecture

```text
frontend/src/components/  Investigator UI
services/                 Detection, intelligence, reporting services
services/threat_intelligence/  dnstwist/OpenPhish/PhishTank adapters
Phishpedia/               Third-party visual recognition project
database.py               SQLite schema/access
main.py                   FastAPI routes
uploads/                  Local visual artefacts
test_*.py                 unittest-style regression coverage
```

## 21. Data Flow & Database

`assets` persists scanned fingerprints/metadata; `case_timeline_events` is append-only. Assets are indexed by asset ID/IP/pHash/brand. Additional abuse snapshot/approval/submission tables exist from later work but should be described as control-plane prototype until fully verified.

## 22. Testing

Repository includes tests for API, acquisition, DNS, infrastructure, logo retrieval/investigation/calibration, Phishpedia, threat intelligence, timeline, rescan, social/listing detection and abuse routing. Test files are the strongest evidence of exercised scenarios; no formal consolidated coverage percentage was found.

## 23. Results & Metrics

No formal accuracy, precision, recall, F1, latency benchmark, or production dataset metric was established in the current MVP. Demo scenario values and UI examples are illustrative fixtures, not benchmark claims.

## 24. Real-World Demonstrations

Best judge demo: a protected-domain scan showing dnstwist candidates, feed provenance and risk filtering; then add evidence to a case, view linked IP/hash assets, and export PDF. The built-in Rolex master demo is explicitly seeded/demo data.

## 25. UI/UX

The app contains Onboarding, Domain Watch, Logo Match, Linked Infrastructure, and Case Report tabs. Recommended PPT screenshots: onboarding (slide 2/4), candidate evidence drawer (slide 6), linked graph (slide 8), PDF/case report (slide 9). Highlight provenance and reasons, not decorative risk badges alone.

## 26. Visual Assets

Use `uploads/screenshots`, `uploads/logo_crops`, UI screenshots, generated PDF output, and Phishpedia annotated visual results where available. Verify each asset is case-appropriate before presentation.

## 27. Security & Privacy

Inputs are processed server-side; temporary upload helpers clean temporary files. Secrets are read from environment variables in services. Limitations: permissive CORS is configured; acquisition can use insecure TLS fallback by configuration; uploaded/local artefacts and local SQLite are not production evidence custody controls.

## 28. Feasibility

Current MVP is technically feasible for bounded investigations and local demonstrations. Production requires authentication/RBAC, durable job queues, secured storage, robust public-suffix parsing, provider-contract validation, monitoring and legal/process governance.

## 29. Scalability

Current caches are in-process and SQLite is local. Future scope: worker queues, persistent job state, object storage, database scaling, scheduled feed refreshes, multi-brand tenancy and model serving.

## 30. Business & Real-World Viability

Useful for enterprise brand protection and analyst triage, particularly where evidence reports and technical linkage speed review. It is not yet a turnkey autonomous takedown product.

## 31. Cost Analysis

MVP mainly uses local/open-source components. External feed/RDAP availability and model weights are dependencies. Production cost was not estimated in repository.

## 32. Limitations

No verified formal benchmarks; outbound-dependent services can fail; visual capture is often a proxy; Phishpedia deep mode depends on weights; SQLite/local uploads are MVP persistence; domain-registration/provider/takedown paths are partial; no verified production deployment or auth system.

## 33. Future Roadmap

Phase 1: stabilise current detection/evidence MVP. Phase 2: authenticated multi-user cases, durable artefact storage and measured evaluation. Phase 3: queues, monitoring, scalable data layer and policy review. Phase 4: governed provider-specific takedown workflow and richer cross-platform intelligence.

## 34. Research & References

dnstwist (GPLv3), ImageHash (BSD-2-Clause per API credits), Phishpedia (USENIX Security 2021 referenced by UI/README), OpenPhish, PhishTank, FastAPI, React, Vite, Tailwind, Pillow and dnspython. Verify exact third-party licensing before final deck credit slide.

## 35. Open-Source Components

Credit dnstwist, ImageHash, Phishpedia, FastAPI, React, Vite, Tailwind, Pillow, OpenCV, dnspython and fpdf2. Do not imply ownership of those models/tools.

## 36. Claim Verification

| Claim | Repository evidence | Safe? | Notes |
|---|---|---|---|
| AI-powered visual analysis | Phishpedia + visual services | Yes, qualified | Pretrained/conditional weights |
| Multi-source intelligence | dnstwist/OpenPhish/PhishTank services | Yes | Availability can be cached/offline |
| Explainable evidence report | PDF and reasons/UI | Yes | Avoid legal certainty |
| Offender fingerprinting | SQLite IP/hash clusters | Yes, qualified | Correlation, not identity |
| Real-time/continuous monitoring | Not found | No | Future scope |
| Production-ready autonomous takedown | Not verified | No | Partial dry-run controls only |
| High accuracy | No formal benchmark | No | Do not use demo scores |

## 37. Likely Judge Questions

**Problem:** Why not rely on a blacklist? — It discovers lookalikes and combines multiple signals. **AI/ML:** Did you train Phishpedia? — No verified training; it is integrated pretrained/fallback technology. **Accuracy:** What is accuracy? — No formal benchmark yet; present scenario tests, not an invented metric. **Security:** How avoid false reports? — legitimacy/authorization checks and human review are the intended guardrails. **Architecture:** Why SQLite? — local MVP fingerprint/timeline persistence. **Scalability:** What changes first? — jobs, object storage, durable DB. **Data:** Are feeds live? — when outbound access is available; caches/failure states exist. **Visuals:** Is an OG image a screenshot? — no; it is a proxy and must be described honestly. **Risk:** Why explain scores? — analysts need auditable reasons. **Business:** Who pays? — organisations with brand-protection/SOC workflows. **Limitations:** What is missing? — benchmark, auth, deployment hardening and governed reporting. Prepare 20+ spoken Q&A by expanding these categories from code/tests.

## 38. Top 10 Judging Points

1. Concrete digital-fraud problem. 2. Multi-source discovery. 3. Visual + domain signals. 4. Explainability. 5. Case evidence export. 6. Legitimate-use awareness. 7. Infrastructure fingerprinting. 8. Useful analyst UI. 9. Modular services. 10. Clear production roadmap.

## 39. Recommended Presentation Story

Brand abuse is fragmented and costly to investigate. A lookalike alone is weak evidence, but multiple corroborating signals are actionable for review. KEIKAI begins with protected-domain or logo input, discovers candidates, correlates phishing intelligence and visual signals, then explains why the candidate merits attention. It preserves selected evidence in a case and links technically similar assets. The output is a human-readable report, not an unsupported automatic takedown. The MVP demonstrates a practical analyst workflow today while making the production gaps explicit.

## 40. Slide-by-Slide Content Mapping

| Slide | Main message | Visual | Speak, do not crowd |
|---|---|---|---|
| 1 | KEIKAI: explainable brand-abuse intelligence | product/UI hero | One-line purpose |
| 2 | BinaryBreez / track / roles | official template | team details |
| 3 | Fragmented evidence causes slow, risky decisions | threat-to-impact graphic | stakeholders |
| 4 | Multi-signal investigation workflow | 5-step flow | why each signal matters |
| 5 | Architecture: React + FastAPI + intelligence services | architecture diagram | external dependencies |
| 6 | Domain & feed intelligence | Domain Watch screenshot | dnstwist/feed provenance |
| 7 | Visual and intent verification | Logo/technical evidence screenshot | pretrained vs custom |
| 8 | Related-asset fingerprinting | infrastructure graph | correlation ≠ attribution |
| 9 | Evidence report and explainability | Case/PDF screenshot | risk logic caveat |
| 10 | MVP validation, limitations and roadmap | honest roadmap | no formal benchmark |
| 11 | Impact and closing | concise recap | next validation milestone |

## 41. Visual Presentation Strategy

Follow the official IKIGAI template; use the product’s dark/neutral security aesthetic only inside screenshots and diagrams. Prefer one key UI screenshot or one flow per slide, short labels, Lucide-like line iconography, and high contrast. Do not turn slides into dashboards.

## 42. Content Priority

**Must show:** problem, workflow, architecture, evidence, linking, honest MVP. **Must say:** model provenance, thresholds, limitations, privacy and roadmap. **Supporting:** API/status details and full service list. **Omit:** unverified accuracy, provider/takedown claims, generic AI slogans.

## 43. Project Snapshot

```text
Project: KEIKAI
Team: BinaryBreez
Track: Cyber Security
Problem: brand impersonation investigation
Solution: multi-signal analyst workflow
Primary Users: brand-protection/SOC analysts
Core Technology: FastAPI + React + SQLite
AI/ML: Phishpedia integration, perceptual hashing, intent service
Security Intelligence: dnstwist, feeds, DNS/RDAP/ASN
Key Innovation: explainable correlation across signals
Primary Input: protected domain or logo
Primary Output: selected evidence and PDF case report
Risk Assessment: explainable, multi-signal; no global benchmark
Evidence Generation: implemented PDF/report workflow
Current MVP: local analyst-assistance platform
Strongest Feature: linked domain/visual/infrastructure evidence
Best Demo: seeded Rolex case or domain-watch-to-PDF flow
Best Metric: No formal benchmark metric established
Biggest Limitation: production validation, deployment and governance
Future Direction: measured, authenticated, durable multi-brand platform
```
