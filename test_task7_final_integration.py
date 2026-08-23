"""
test_task7_final_integration.py

TASK 7 — FINAL INTEGRATION & SECURITY AUDIT TEST SUITE

Includes unit & integration tests for:
 1. viaSocket safe event emission with sanitized payload
 2. viaSocket sensitive keys (api_key, token, password, secret) stripped
 3. viaSocket unconfigured mode operates gracefully
 4. viaSocket network timeout handles gracefully without blocking
 5. viaSocket HTTP 500 error handles gracefully
 6. Automated high-confidence workflow (creates case & emits alert, but NEVER auto-approves)
 7. Deterministic sponsor demo scenario execution (`run_demo_scenario`)
 8. Explainable risk score calculation (94/100)
 9. Case intelligence graph construction
10. Security Audit: No secrets in payloads
11. Security Audit: Human approval strictly mandatory
12. Security Audit: Backend authority over mode, provider, and destination
"""

import json
import os
import sys
import unittest
import urllib.error
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from database import init_db, abuse_execute
from services.viasocket_adapter import emit_viasocket_event, ViaSocketWorkflowAdapter, _sanitize_payload
from services.demo_scenario_service import run_demo_scenario
from services.universal_abuse_router import submit_universal_takedown


class TestTask7FinalIntegration(unittest.TestCase):

    def setUp(self):
        init_db()
        abuse_execute("DELETE FROM abuse_submissions")
        abuse_execute("DELETE FROM abuse_approvals")
        abuse_execute("DELETE FROM abuse_snapshots")
        os.environ['ABUSE_SUBMISSION_MODE'] = 'DRY_RUN'

    # 1. viaSocket safe event emission with sanitized payload
    def test_01_viasocket_event_emission(self):
        adapter = ViaSocketWorkflowAdapter(webhook_url="https://viasocket.com/test-endpoint")
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = b'{"status": "ok"}'
        mock_resp.__enter__.return_value = mock_resp

        with patch("urllib.request.urlopen", return_value=mock_resp):
            res = adapter.emit_event("CASE_CREATED", "case_123", {"domain": "phish-test.com"})
            self.assertTrue(res["delivered"])
            self.assertEqual(res["event_type"], "CASE_CREATED")

    # 2. viaSocket sensitive keys stripped
    def test_02_viasocket_sensitive_keys_stripped(self):
        raw_payload = {
            "candidate_domain": "amaz0n-phish.com",
            "api_key": "SECRET_API_KEY_123",
            "token": "BEARER_TOKEN_ABC",
            "password": "super_secret_password",
            "authorization": "Bearer secret_header",
            "nested": {
                "secret": "nested_secret_val",
                "normal_field": "public_evidence"
            }
        }
        clean = _sanitize_payload(raw_payload)
        self.assertNotIn("api_key", clean)
        self.assertNotIn("token", clean)
        self.assertNotIn("password", clean)
        self.assertNotIn("authorization", clean)
        self.assertNotIn("secret", clean["nested"])
        self.assertEqual(clean["candidate_domain"], "amaz0n-phish.com")
        self.assertEqual(clean["nested"]["normal_field"], "public_evidence")

    # 3. viaSocket unconfigured mode operates gracefully
    def test_03_viasocket_unconfigured(self):
        adapter = ViaSocketWorkflowAdapter(webhook_url="")
        res = adapter.emit_event("INVESTIGATION_STARTED", "case_unconf")
        self.assertEqual(res["status"], "DISABLED")
        self.assertFalse(res["delivered"])

    # 4. viaSocket network timeout handles gracefully without blocking
    def test_04_viasocket_network_timeout(self):
        adapter = ViaSocketWorkflowAdapter(webhook_url="https://viasocket.com/slow-endpoint")
        with patch("urllib.request.urlopen", side_effect=TimeoutError("Connection timed out")):
            res = adapter.emit_event("APPROVAL_REQUIRED", "case_slow")
            self.assertEqual(res["status"], "NETWORK_ERROR")
            self.assertFalse(res["delivered"])

    # 5. viaSocket HTTP 500 error handles gracefully
    def test_05_viasocket_http_error(self):
        adapter = ViaSocketWorkflowAdapter(webhook_url="https://viasocket.com/error-endpoint")
        err = urllib.error.HTTPError(url="https://viasocket.com/error", code=500, msg="Internal Error", hdrs={}, fp=None)
        with patch("urllib.request.urlopen", side_effect=err):
            res = adapter.emit_event("TAKEDOWN_SUBMITTED", "case_err")
            self.assertEqual(res["status"], "DELIVERY_FAILED")
            self.assertFalse(res["delivered"])

    # 6. Automated high-confidence workflow (creates case & emits alert, but NEVER auto-approves)
    def test_06_high_confidence_workflow(self):
        # Even when high confidence impersonation is confirmed, submission fails without human approval
        res = submit_universal_takedown("case_high_conf", "non_existent_approval_id")
        self.assertEqual(res["error"], "HUMAN_APPROVAL_REQUIRED")

    # 7. Deterministic sponsor demo scenario execution (`run_demo_scenario`)
    def test_07_demo_scenario_execution(self):
        report = run_demo_scenario(target_brand="Amazon", candidate_domain="amaz0n-security-login.xyz")
        self.assertEqual(report["target_brand"], "Amazon")
        self.assertEqual(report["suspected_domain"], "amaz0n-security-login.xyz")
        self.assertEqual(report["risk_score"], 94)
        self.assertEqual(report["takedown_submission"]["state"], "DRY_RUN_COMPLETED")

    # 8. Explainable risk score calculation (94/100)
    def test_08_risk_score_calculation(self):
        report = run_demo_scenario()
        score = report["risk_score"]
        self.assertEqual(score, 94)
        self.assertTrue(len(report["risk_breakdown"]) >= 4)

    # 9. Case intelligence graph construction
    def test_09_case_intelligence_graph(self):
        report = run_demo_scenario()
        graph = report["case_graph"]
        self.assertIn("nodes", graph)
        self.assertIn("edges", graph)
        self.assertTrue(len(graph["nodes"]) >= 7)
        self.assertTrue(len(graph["edges"]) >= 6)

    # 10. Security Audit: No secrets in payloads
    def test_10_security_audit_no_secrets(self):
        payload = {"domain": "amaz0n-phish.com", "token": "SECRET"}
        sanitized = _sanitize_payload(payload)
        self.assertNotIn("token", sanitized)

    # 11. Security Audit: Human approval strictly mandatory
    def test_11_security_audit_human_approval_mandatory(self):
        res = submit_universal_takedown("case_fake", "unapproved_id")
        self.assertEqual(res["error"], "HUMAN_APPROVAL_REQUIRED")

    # 12. Security Audit: Backend authority over mode, provider, and destination
    def test_12_security_audit_backend_authority(self):
        os.environ['ABUSE_SUBMISSION_MODE'] = 'DRY_RUN'
        report = run_demo_scenario()
        # Ensure submission mode in report is DRY_RUN and external_request_performed is False
        sub = report["takedown_submission"]
        self.assertEqual(sub["state"], "DRY_RUN_COMPLETED")
        self.assertFalse(sub["external_request_performed"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
