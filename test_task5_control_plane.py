"""
test_task5_control_plane.py

TASK 5 — TAKEDOWN SUBMISSION CONTROL PLANE TEST SUITE

Includes E2E Lifecycle, Concurrency Test, and 29 Required Failure & Security Revalidation Tests:
 1. evidence modified -> APPROVAL_INVALIDATED_EVIDENCE_CHANGED
 2. evidence deleted -> APPROVAL_INVALIDATED_EVIDENCE_CHANGED
 3. evidence hash mismatch -> APPROVAL_INVALIDATED_EVIDENCE_CHANGED
 4. screenshot modified -> APPROVAL_INVALIDATED_EVIDENCE_CHANGED
 5. screenshot deleted -> APPROVAL_INVALIDATED_SCREENSHOT_DELETED
 6. domain changed -> APPROVAL_INVALIDATED_SNAPSHOT_TAMPERED
 7. brand changed -> APPROVAL_INVALIDATED_SNAPSHOT_TAMPERED
 8. official domain changed -> APPROVAL_INVALIDATED_SNAPSHOT_TAMPERED
 9. legitimacy changed -> APPROVAL_INVALIDATED_LEGITIMACY_CHANGED
10. provider changed -> APPROVAL_INVALIDATED_PROVIDER_CHANGED
11. provider method changed -> APPROVAL_INVALIDATED_PROVIDER_CHANGED
12. revoked approval -> APPROVAL_REVOKED
13. expired approval -> APPROVAL_EXPIRED
14. tampered snapshot -> APPROVAL_INVALIDATED_SNAPSHOT_TAMPERED
15. duplicate submission -> idempotency (returns existing submission)
16. simultaneous submission -> concurrency test (mock Cloudflare call count == 1)
17. stale submission lease -> UNKNOWN_SUBMISSION_STATE
18. Cloudflare timeout -> UNKNOWN_SUBMISSION_STATE
19. Cloudflare 401 -> CLOUDFLARE_AUTH_FAILED
20. Cloudflare 403 -> CLOUDFLARE_PERMISSION_DENIED
21. Cloudflare 429 -> CLOUDFLARE_RATE_LIMITED
22. Cloudflare 5xx -> CLOUDFLARE_SERVER_ERROR
23. DRY_RUN -> ZERO external requests, DRY_RUN_COMPLETED
24. LIVE mocked submission -> SUBMITTED with provider report ID
25. frontend approval bypass -> HUMAN_APPROVAL_REQUIRED
26. frontend LIVE manipulation -> server configuration authority preserved
27. cross-case snapshot access -> HUMAN_APPROVAL_REQUIRED / UNAUTHORIZED_SUBMIT_CROSS_CASE
28. cross-case approval access -> HUMAN_APPROVAL_REQUIRED
29. unauthorized submit -> HUMAN_APPROVAL_REQUIRED
"""

import hashlib
import json
import os
import sys
import tempfile
import unittest
import urllib.error
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone, timedelta
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from database import init_db, abuse_execute, abuse_one
from services.abuse_control_service import approve, submit, revoke, status, fingerprint
from services.cloudflare_abuse_client import create_phishing_report


def valid_payload(domain="amaz0n-security-login.xyz", **overrides):
    payload = {
        "candidate_domain": domain,
        "target_brand": "Amazon",
        "official_domain": "amazon.com",
        "evidence": {
            "sources": ["dnstwist", "openphish"],
            "domain_permutation": True,
            "strong_visual_match": True,
            "credential_indicators": True,
            "screenshot": {"status": "SUCCESS", "source": "candidate_acquisition"}
        },
        "authorization_registry": {
            "source": "REGISTRY",
            "brands": {"amazon": {"domains": [{"domain": "amazon.com", "classification": "OFFICIAL_DOMAIN"}]}}
        }
    }
    payload.update(overrides)
    return payload


class TestTask5ControlPlane(unittest.TestCase):

    def setUp(self):
        init_db()
        abuse_execute("DELETE FROM abuse_submissions")
        abuse_execute("DELETE FROM abuse_approvals")
        abuse_execute("DELETE FROM abuse_snapshots")
        os.environ['ABUSE_SUBMISSION_MODE'] = 'DRY_RUN'

    # E2E Lifecycle
    def test_e2e_mocked_lifecycle(self):
        case_id = "case_e2e_001"
        payload = valid_payload("amaz0n-phish-e2e.xyz")

        # 1. Approval
        appr_res = approve(case_id, payload)
        self.assertEqual(appr_res["state"], "HUMAN_APPROVED")
        aid = appr_res["approval_id"]

        # 2. Submission in DRY_RUN mode
        sub_res = submit(case_id, aid)
        self.assertEqual(sub_res["state"], "DRY_RUN_COMPLETED")
        self.assertFalse(sub_res["external_request_performed"])

        # 3. Status check
        st = status(case_id)
        self.assertIsNotNone(st["approval"])
        self.assertIsNotNone(st["submission"])
        self.assertEqual(st["submission"]["state"], "DRY_RUN_COMPLETED")

    # 1. evidence modified -> APPROVAL_INVALIDATED_EVIDENCE_CHANGED
    def test_01_evidence_modified(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            art_path = Path(tmpdir) / "evidence.dat"
            art_path.write_bytes(b"initial evidence bytes")
            initial_hash = hashlib.sha256(b"initial evidence bytes").hexdigest()

            payload = valid_payload("amaz0n-modified.xyz")
            payload["evidence"]["artifacts"] = [{
                "path": str(art_path),
                "sha256": initial_hash,
                "evidence_type": "PAGE_CONTENT"
            }]

            case_id = "case_mod_001"
            appr = approve(case_id, payload)
            aid = appr["approval_id"]

            # Modify evidence bytes on disk
            art_path.write_bytes(b"TAMPERED EVIDENCE BYTES")

            res = submit(case_id, aid)
            self.assertEqual(res["error"], "APPROVAL_INVALIDATED_EVIDENCE_CHANGED")

    # 2. evidence deleted -> APPROVAL_INVALIDATED_EVIDENCE_CHANGED
    def test_02_evidence_deleted(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            art_path = Path(tmpdir) / "evidence_del.dat"
            art_path.write_bytes(b"evidence bytes")

            payload = valid_payload("amaz0n-ev-del.xyz")
            payload["evidence"]["artifacts"] = [{
                "path": str(art_path),
                "sha256": hashlib.sha256(b"evidence bytes").hexdigest()
            }]

            case_id = "case_ev_del_001"
            appr = approve(case_id, payload)
            aid = appr["approval_id"]

            art_path.unlink()

            res = submit(case_id, aid)
            self.assertEqual(res["error"], "APPROVAL_INVALIDATED_EVIDENCE_CHANGED")

    # 3. evidence hash mismatch -> APPROVAL_INVALIDATED_EVIDENCE_CHANGED
    def test_03_evidence_hash_mismatch(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            art_path = Path(tmpdir) / "evidence_mismatch.dat"
            art_path.write_bytes(b"evidence bytes A")

            payload = valid_payload("amaz0n-ev-mismatch.xyz")
            payload["evidence"]["artifacts"] = [{
                "path": str(art_path),
                "sha256": hashlib.sha256(b"DIFFERENT EXPECTED HASH").hexdigest()
            }]

            case_id = "case_mismatch_001"
            appr = approve(case_id, payload)
            aid = appr["approval_id"]

            res = submit(case_id, aid)
            self.assertEqual(res["error"], "APPROVAL_INVALIDATED_EVIDENCE_CHANGED")

    # 4. screenshot modified -> APPROVAL_INVALIDATED_EVIDENCE_CHANGED
    def test_04_screenshot_modified(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            sc_path = Path(tmpdir) / "screenshot_mod.png"
            sc_path.write_bytes(b"original screenshot bytes")

            payload = valid_payload("amaz0n-sc-mod.xyz")
            payload["evidence"]["screenshot"] = {
                "status": "SUCCESS",
                "path": str(sc_path),
                "artifact_hash": hashlib.sha256(b"original screenshot bytes").hexdigest()
            }

            case_id = "case_sc_mod_001"
            appr = approve(case_id, payload)
            aid = appr["approval_id"]

            sc_path.write_bytes(b"MODIFIED SCREENSHOT BYTES")

            res = submit(case_id, aid)
            self.assertEqual(res["error"], "APPROVAL_INVALIDATED_EVIDENCE_CHANGED")

    # 5. screenshot deleted -> APPROVAL_INVALIDATED_SCREENSHOT_DELETED
    def test_05_screenshot_deleted(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            sc_path = Path(tmpdir) / "screenshot_del.png"
            sc_path.write_bytes(b"screenshot bytes")

            payload = valid_payload("amaz0n-deleted.xyz")
            payload["evidence"]["screenshot"] = {
                "status": "SUCCESS",
                "path": str(sc_path),
                "artifact_hash": hashlib.sha256(b"screenshot bytes").hexdigest()
            }

            case_id = "case_del_001"
            appr = approve(case_id, payload)
            aid = appr["approval_id"]

            sc_path.unlink()

            res = submit(case_id, aid)
            self.assertEqual(res["error"], "APPROVAL_INVALIDATED_SCREENSHOT_DELETED")

    # 6. domain changed -> tampered snapshot
    def test_06_domain_changed(self):
        case_id = "case_dom_chg_001"
        payload = valid_payload("amaz0n-dom-orig.xyz")
        appr = approve(case_id, payload)
        aid = appr["approval_id"]

        snap = abuse_one("SELECT * FROM abuse_snapshots WHERE case_id=?", (case_id,))
        snap_obj = json.loads(snap["snapshot_json"])
        snap_obj["candidate_domain"] = "different-domain.xyz"
        abuse_execute("UPDATE abuse_snapshots SET snapshot_json=? WHERE case_id=?", (json.dumps(snap_obj), case_id))

        res = submit(case_id, aid)
        self.assertEqual(res["error"], "APPROVAL_INVALIDATED_SNAPSHOT_TAMPERED")

    # 7. brand changed -> tampered snapshot
    def test_07_brand_changed(self):
        case_id = "case_brand_chg_001"
        payload = valid_payload("amaz0n-brand-chg.xyz")
        appr = approve(case_id, payload)
        aid = appr["approval_id"]

        snap = abuse_one("SELECT * FROM abuse_snapshots WHERE case_id=?", (case_id,))
        snap_obj = json.loads(snap["snapshot_json"])
        snap_obj["target_brand"] = "Different Brand"
        abuse_execute("UPDATE abuse_snapshots SET snapshot_json=? WHERE case_id=?", (json.dumps(snap_obj), case_id))

        res = submit(case_id, aid)
        self.assertEqual(res["error"], "APPROVAL_INVALIDATED_SNAPSHOT_TAMPERED")

    # 8. official domain changed -> tampered snapshot
    def test_08_official_domain_changed(self):
        case_id = "case_off_chg_001"
        payload = valid_payload("amaz0n-off-chg.xyz")
        appr = approve(case_id, payload)
        aid = appr["approval_id"]

        snap = abuse_one("SELECT * FROM abuse_snapshots WHERE case_id=?", (case_id,))
        snap_obj = json.loads(snap["snapshot_json"])
        snap_obj["official_domain"] = "other-official.com"
        abuse_execute("UPDATE abuse_snapshots SET snapshot_json=? WHERE case_id=?", (json.dumps(snap_obj), case_id))

        res = submit(case_id, aid)
        self.assertEqual(res["error"], "APPROVAL_INVALIDATED_SNAPSHOT_TAMPERED")

    # 9. legitimacy changed -> APPROVAL_INVALIDATED_LEGITIMACY_CHANGED
    def test_09_legitimacy_changed(self):
        case_id = "case_legit_001"
        payload = valid_payload("amaz0n-legit.xyz")
        appr = approve(case_id, payload)
        aid = appr["approval_id"]

        with patch("services.abuse_control_service.evaluate_legitimacy", return_value={"classification": "OFFICIAL_DOMAIN", "reporting_eligibility": "BLOCKED"}):
            res = submit(case_id, aid)
            self.assertEqual(res["error"], "APPROVAL_INVALIDATED_LEGITIMACY_CHANGED")

    # 10. provider changed -> APPROVAL_INVALIDATED_PROVIDER_CHANGED
    def test_10_provider_changed(self):
        case_id = "case_prov_001"
        payload = valid_payload("amaz0n-prov.xyz")
        appr = approve(case_id, payload)
        aid = appr["approval_id"]

        with patch("services.abuse_control_service.revalidate_provider_route", return_value="APPROVAL_INVALIDATED_PROVIDER_CHANGED"):
            res = submit(case_id, aid)
            self.assertEqual(res["error"], "APPROVAL_INVALIDATED_PROVIDER_CHANGED")

    # 11. provider method changed -> APPROVAL_INVALIDATED_PROVIDER_CHANGED
    def test_11_provider_method_changed(self):
        case_id = "case_meth_001"
        payload = valid_payload("amaz0n-meth.xyz")
        appr = approve(case_id, payload)
        aid = appr["approval_id"]

        snap = abuse_one("SELECT * FROM abuse_snapshots WHERE case_id=?", (case_id,))
        snap_obj = json.loads(snap["snapshot_json"])
        snap_obj["submission_method"] = "MANUAL_EMAIL"
        fp = fingerprint(snap_obj)
        abuse_execute("UPDATE abuse_snapshots SET snapshot_json=?, fingerprint=? WHERE case_id=?", (json.dumps(snap_obj), fp, case_id))

        res = submit(case_id, aid)
        self.assertEqual(res["error"], "APPROVAL_INVALIDATED_PROVIDER_CHANGED")

    # 12. revoked approval -> APPROVAL_REVOKED
    def test_12_revoked_approval(self):
        case_id = "case_rev_001"
        payload = valid_payload("amaz0n-rev.xyz")
        appr = approve(case_id, payload)
        aid = appr["approval_id"]

        revoke(case_id, aid)
        res = submit(case_id, aid)
        self.assertEqual(res["error"], "APPROVAL_REVOKED")

    # 13. expired approval -> APPROVAL_EXPIRED
    def test_13_expired_approval(self):
        case_id = "case_exp_001"
        payload = valid_payload("amaz0n-exp.xyz")
        appr = approve(case_id, payload)
        aid = appr["approval_id"]

        past = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
        abuse_execute("UPDATE abuse_approvals SET expires_at=? WHERE approval_id=?", (past, aid))

        res = submit(case_id, aid)
        self.assertEqual(res["error"], "APPROVAL_EXPIRED")

    # 14. tampered snapshot -> APPROVAL_INVALIDATED_SNAPSHOT_TAMPERED
    def test_14_tampered_snapshot(self):
        case_id = "case_tamp_001"
        payload = valid_payload("amaz0n-tamp.xyz")
        appr = approve(case_id, payload)
        aid = appr["approval_id"]

        abuse_execute("UPDATE abuse_snapshots SET snapshot_json=? WHERE case_id=?", (json.dumps({"tampered": True}), case_id))

        res = submit(case_id, aid)
        self.assertEqual(res["error"], "APPROVAL_INVALIDATED_SNAPSHOT_TAMPERED")

    # 15. duplicate submission -> idempotency (returns existing submission)
    def test_15_duplicate_submission(self):
        case_id = "case_dup_001"
        payload = valid_payload("amaz0n-dup.xyz")
        appr = approve(case_id, payload)
        aid = appr["approval_id"]

        first = submit(case_id, aid)
        second = submit(case_id, aid)
        self.assertEqual(first["submission_id"], second["submission_id"])
        self.assertEqual(second["state"], "DRY_RUN_COMPLETED")

    # 16. simultaneous submission -> concurrency test (mock Cloudflare call count == 1)
    def test_16_concurrency_simultaneous_submit(self):
        case_id = "case_concurrent_001"
        payload = valid_payload("amaz0n-concurrent.xyz")
        appr = approve(case_id, payload)
        aid = appr["approval_id"]

        os.environ['ABUSE_SUBMISSION_MODE'] = 'LIVE'
        mock_cf = MagicMock(return_value={"state": "SUBMITTED", "report_id": "report_cf_123"})

        with patch("services.abuse_control_service.create_phishing_report", mock_cf):
            def do_submit():
                return submit(case_id, aid)

            with ThreadPoolExecutor(max_workers=5) as executor:
                futures = [executor.submit(do_submit) for _ in range(5)]
                results = [f.result() for f in futures]

            sub_ids = set(r.get("submission_id") for r in results if "submission_id" in r)
            self.assertEqual(len(sub_ids), 1)
            self.assertEqual(mock_cf.call_count, 1)

    # 17. stale submission lease -> UNKNOWN_SUBMISSION_STATE
    def test_17_stale_submission_lease(self):
        case_id = "case_stale_001"
        payload = valid_payload("amaz0n-stale.xyz")
        appr = approve(case_id, payload)
        aid = appr["approval_id"]

        snap = abuse_one("SELECT fingerprint FROM abuse_snapshots WHERE case_id=?", (case_id,))
        past_lease = (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat()
        abuse_execute(
            "INSERT INTO abuse_submissions(submission_id, case_id, snapshot_id, fingerprint, state, lease_expires_at) VALUES(?,?,?,?,?,?)",
            ("sub_stale", case_id, "snap_stale", snap["fingerprint"], "SUBMITTING", past_lease)
        )

        res = submit(case_id, aid)
        self.assertEqual(res["state"], "UNKNOWN_SUBMISSION_STATE")

    # 18. Cloudflare timeout -> UNKNOWN_SUBMISSION_STATE
    def test_18_cloudflare_timeout(self):
        os.environ['ABUSE_SUBMISSION_MODE'] = 'LIVE'
        os.environ['CLOUDFLARE_ACCOUNT_ID'] = 'acc123'
        os.environ['CLOUDFLARE_API_TOKEN'] = 'tok123'

        with patch("urllib.request.urlopen", side_effect=TimeoutError("Connection timed out")):
            res = create_phishing_report({"test": 1})
            self.assertEqual(res["state"], "UNKNOWN_SUBMISSION_STATE")

    # 19. Cloudflare 401 -> CLOUDFLARE_AUTH_FAILED
    def test_19_cloudflare_401(self):
        os.environ['ABUSE_SUBMISSION_MODE'] = 'LIVE'
        os.environ['CLOUDFLARE_ACCOUNT_ID'] = 'acc123'
        os.environ['CLOUDFLARE_API_TOKEN'] = 'tok123'

        err = urllib.error.HTTPError(url="https://api.cloudflare.com", code=401, msg="Unauthorized", hdrs={}, fp=None)
        with patch("urllib.request.urlopen", side_effect=err):
            res = create_phishing_report({"test": 1})
            self.assertEqual(res["state"], "CLOUDFLARE_AUTH_FAILED")

    # 20. Cloudflare 403 -> CLOUDFLARE_PERMISSION_DENIED
    def test_20_cloudflare_403(self):
        os.environ['ABUSE_SUBMISSION_MODE'] = 'LIVE'
        os.environ['CLOUDFLARE_ACCOUNT_ID'] = 'acc123'
        os.environ['CLOUDFLARE_API_TOKEN'] = 'tok123'

        err = urllib.error.HTTPError(url="https://api.cloudflare.com", code=403, msg="Forbidden", hdrs={}, fp=None)
        with patch("urllib.request.urlopen", side_effect=err):
            res = create_phishing_report({"test": 1})
            self.assertEqual(res["state"], "CLOUDFLARE_PERMISSION_DENIED")

    # 21. Cloudflare 429 -> CLOUDFLARE_RATE_LIMITED
    def test_21_cloudflare_429(self):
        os.environ['ABUSE_SUBMISSION_MODE'] = 'LIVE'
        os.environ['CLOUDFLARE_ACCOUNT_ID'] = 'acc123'
        os.environ['CLOUDFLARE_API_TOKEN'] = 'tok123'

        err = urllib.error.HTTPError(url="https://api.cloudflare.com", code=429, msg="Too Many Requests", hdrs={}, fp=None)
        with patch("urllib.request.urlopen", side_effect=err):
            res = create_phishing_report({"test": 1})
            self.assertEqual(res["state"], "CLOUDFLARE_RATE_LIMITED")

    # 22. Cloudflare 5xx -> CLOUDFLARE_SERVER_ERROR
    def test_22_cloudflare_5xx(self):
        os.environ['ABUSE_SUBMISSION_MODE'] = 'LIVE'
        os.environ['CLOUDFLARE_ACCOUNT_ID'] = 'acc123'
        os.environ['CLOUDFLARE_API_TOKEN'] = 'tok123'

        err = urllib.error.HTTPError(url="https://api.cloudflare.com", code=503, msg="Service Unavailable", hdrs={}, fp=None)
        with patch("urllib.request.urlopen", side_effect=err):
            res = create_phishing_report({"test": 1})
            self.assertEqual(res["state"], "CLOUDFLARE_SERVER_ERROR")

    # 23. DRY_RUN -> ZERO external requests, DRY_RUN_COMPLETED
    def test_23_dry_run_zero_external_calls(self):
        os.environ['ABUSE_SUBMISSION_MODE'] = 'DRY_RUN'
        res = create_phishing_report({"test": 1})
        self.assertEqual(res["state"], "DRY_RUN")
        self.assertIsNone(res["response"])

    # 24. LIVE mocked submission -> SUBMITTED with provider report ID
    def test_24_live_mocked_submission(self):
        os.environ['ABUSE_SUBMISSION_MODE'] = 'LIVE'
        os.environ['CLOUDFLARE_ACCOUNT_ID'] = 'acc123'
        os.environ['CLOUDFLARE_API_TOKEN'] = 'tok123'

        mock_res = {"abuse_rand": "R12345", "result": {"id": "R12345"}}
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps(mock_res).encode('utf-8')
        mock_response.__enter__.return_value = mock_response

        with patch("urllib.request.urlopen", return_value=mock_response):
            res = create_phishing_report({"test": 1})
            self.assertEqual(res["state"], "SUBMITTED")
            self.assertEqual(res["report_id"], "R12345")

    # 25. frontend approval bypass -> HUMAN_APPROVAL_REQUIRED
    def test_25_frontend_approval_bypass(self):
        res = submit("case_fake", "non_existent_approval_id")
        self.assertEqual(res["error"], "HUMAN_APPROVAL_REQUIRED")

    # 26. frontend LIVE manipulation -> server configuration authority preserved
    def test_26_frontend_live_manipulation(self):
        os.environ['ABUSE_SUBMISSION_MODE'] = 'DRY_RUN'
        case_id = "case_manip_001"
        payload = valid_payload("amaz0n-manip.xyz")
        appr = approve(case_id, payload)

        res = submit(case_id, appr["approval_id"], client_payload={"mode": "LIVE", "provider": "LIVE"})
        self.assertEqual(res["state"], "DRY_RUN_COMPLETED")
        self.assertFalse(res["external_request_performed"])

    # 27. cross-case snapshot access -> HUMAN_APPROVAL_REQUIRED
    def test_27_cross_case_snapshot_access(self):
        payload1 = valid_payload("domain1.com")
        payload2 = valid_payload("domain2.com")

        appr1 = approve("case_A", payload1)
        appr2 = approve("case_B", payload2)

        res = submit("case_A", appr2["approval_id"])
        self.assertEqual(res["error"], "HUMAN_APPROVAL_REQUIRED")

    # 28. cross-case approval access -> HUMAN_APPROVAL_REQUIRED
    def test_28_cross_case_approval_access(self):
        payload = valid_payload("cross-case.com")
        appr = approve("case_X", payload)

        res = submit("case_Y", appr["approval_id"])
        self.assertEqual(res["error"], "HUMAN_APPROVAL_REQUIRED")

    # 29. unauthorized submit -> HUMAN_APPROVAL_REQUIRED
    def test_29_unauthorized_submit(self):
        res = submit("case_unauth", "invalid_aid_123")
        self.assertEqual(res["error"], "HUMAN_APPROVAL_REQUIRED")


if __name__ == "__main__":
    unittest.main(verbosity=2)
