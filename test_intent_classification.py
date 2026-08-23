import unittest
from fastapi.testclient import TestClient
from main import app
from services.intent_classifier_service import classify_intent, INTENT_LABELS, LEGITIMATE_LABELS

client = TestClient(app)


class TestIntentClassificationEngine(unittest.TestCase):

    def test_01_malicious_impersonation_classification(self):
        malicious_text = "Urgent Action Required: Verify your bank credentials and password immediately or your account will be suspended."
        res = classify_intent(text=malicious_text)

        self.assertIn("top_label", res)
        self.assertIn("confidence", res)
        self.assertFalse(res["is_legitimate"])
        self.assertIn(res["top_label"], ["Phishing/credential harvesting", "Counterfeit or impersonation"])
        self.assertEqual(len(res["probabilities"]), len(INTENT_LABELS))

    def test_02_legitimate_news_mention_classification(self):
        news_text = "Acme Corporate Brand announces record quarterly earnings and expansion in TechCrunch interview press release."
        res = classify_intent(text=news_text)

        self.assertTrue(res["is_legitimate"])
        self.assertEqual(res["top_label"], "News/media coverage")
        self.assertGreater(res["confidence"], 30.0)

    def test_03_domain_allowlist_rule_override(self):
        # official-partner.com is in config/domain_allowlist.json
        res = classify_intent(domain="official-partner.com")

        self.assertTrue(res["is_override"])
        self.assertTrue(res["is_legitimate"])
        self.assertEqual(res["top_label"], "Authorized reseller/partner")
        self.assertEqual(res["confidence"], 100.0)
        self.assertIn("matches verified partner allowlist", res["override_reason"])

    def test_04_manual_investigator_override(self):
        res = classify_intent(
            text="Random store text",
            override_label="Fan page/community content"
        )
        self.assertTrue(res["is_override"])
        self.assertTrue(res["is_legitimate"])
        self.assertEqual(res["top_label"], "Fan page/community content")
        self.assertEqual(res["confidence"], 100.0)

    def test_05_api_classify_intent_endpoint(self):
        payload = {
            "text": "Press release and journal reporting for Acme Corp",
            "domain": "reuters.com"
        }
        response = client.post("/api/classify-intent", json=payload)
        self.assertEqual(response.status_code, 200)
        res = response.json()
        self.assertEqual(res["status"], "success")
        self.assertEqual(res["meta"]["source_tool"], "intent_classifier")
        data = res["data"]
        self.assertEqual(data["top_label"], "Authorized reseller/partner") # reuters.com is allowlisted
        self.assertTrue(data["is_override"])


if __name__ == "__main__":
    unittest.main()
