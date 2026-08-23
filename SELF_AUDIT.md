# KEKAI — Self-Audit & Problem Statement Compliance Matrix

This document maps requirements from the **ABIAE Problem Statement (PS)** to implementation modules across the KEKAI codebase.

---

## 1. Problem Statement Requirements Matrix

| # | Problem Statement Requirement | Implementation File(s) & Route(s) | Unit Test Suite | Status |
| :--- | :--- | :--- | :--- | :---: |
| **1** | **Multi-Surface Coverage (Web / Marketplace / App / Social)** | Ingests domain permutations (`services/dnstwist_service.py`), visual logos (`services/logo_fallback_service.py`), phishing portals (`services/phishpedia_service.py`), marketplace listings (`services/listing_service.py`), and social profiles (`services/social_profile_service.py`). | `test_api.py`, `test_listing_detection.py`, `test_social_profile_detection.py` | `IMPLEMENTED` |
| **2** | **Brand-Asset Visual Similarity Detection** | Perceptual Image Hashing (pHash + dHash) via `services/logo_fallback_service.py` and PyTorch Faster R-CNN + ResNet brand matching via `services/phishpedia_service.py`. | `test_phishpedia_inference.py`, `test_phishpedia.py` | `IMPLEMENTED` |
| **3** | **Distinguish Malicious Impersonation from Legitimate Use** | Zero-shot transformer classifier in `services/intent_classifier_service.py`, `POST /api/classify-intent`, and verified domain allowlist (`config/domain_allowlist.json`). | `test_intent_classification.py` | `IMPLEMENTED` |
| **4** | **Explainable Composite Risk Score** | Dynamic normalized weighted score scaling across present evidence types (`services/confidence_engine_service.py`, `services/report_service.py`). | `test_master_integration.py` | `IMPLEMENTED` |
| **5** | **Offender Fingerprinting & Cluster Linking** | SQLite Asset Store and Graph Clustering Engine (`services/infrastructure_service.py`) correlating shared image hashes, IP addresses, and hosting subnets into Offender Clusters. | `test_infrastructure.py`, `test_clustering_rules.py` | `IMPLEMENTED` |
| **6** | **Auto-Generated Executive Evidence Report** | Executive PDF Report generator (`services/report_service.py`, `POST /api/generate-report`) formatting executive summary, dynamic score breakdown, and evidence audit trail. | `test_api.py`, `test_master_integration.py` | `IMPLEMENTED` |
| **7** | **Active Case DNS Re-Scan & Diff Engine** | Dynamic DNS re-scan & diff service (`services/rescan_service.py`, `POST /api/case/default/rescan`) detecting IP mutations and A-record drift. | `test_rescan.py` | `IMPLEMENTED` |
| **8** | **Interactive Guided Demo Scenario** | Guided 6-stage demo scenario (`frontend/src/components/DemoScenarioModal.jsx`, `services/demo_scenario_service.py`). | `test_master_integration.py` | `IMPLEMENTED` |

---

## 2. Test Suite Reference

The repository contains 32 automated Python test modules validating unit, integration, and security controls across all project services.

```bash
# Example test execution command
python -m unittest test_security_audit.py test_evidence_intelligence_v2.py test_task7_final_integration.py test_task6_universal_engine.py test_task5_control_plane.py
```

*Note: Test suite present; current pass status should be verified against the current repository commit.*
