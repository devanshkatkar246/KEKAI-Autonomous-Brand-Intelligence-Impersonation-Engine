import unittest
from pathlib import Path
from fastapi.testclient import TestClient

from main import app

client = TestClient(app)


class TestPhishpediaIntegration(unittest.TestCase):

    def test_01_phishpedia_status_endpoint(self):
        response = client.get("/api/visual-phishing-status")
        self.assertEqual(response.status_code, 200)
        res = response.json()
        self.assertEqual(res["status"], "success")
        self.assertEqual(res["meta"]["source_tool"], "phishpedia")
        self.assertIn("weights_loaded", res["data"])
        self.assertIsInstance(res["data"]["weights_loaded"], bool)

    def test_02_phishpedia_credits_updated(self):
        response = client.get("/api/credits")
        self.assertEqual(response.status_code, 200)
        res = response.json()
        tools = res["data"]["tools"]
        tool_names = [t["name"] for t in tools]
        self.assertIn("Phishpedia", tool_names)

        phish_tool = next(t for t in tools if t["name"] == "Phishpedia")
        self.assertIn("CC0-1.0", phish_tool["license"])
        self.assertIn("github.com/lindsey98/Phishpedia", phish_tool["github_url"])
        self.assertIn("USENIX Security 2021", phish_tool["paper_citation"])

    def test_03_visual_phishing_check_503_or_job(self):
        sample_img = Path("./imagehash/official_logo.png")
        if not sample_img.exists():
            self.skipTest("Sample logo image missing")

        with open(sample_img, "rb") as f:
            files = {"screenshot": ("shot.png", f, "image/png")}
            data = {"url": "https://paypal-verify-account.com/login"}
            response = client.post("/api/visual-phishing-check", files=files, data=data)

        # If weights are missing, expect 503 Service Unavailable
        if response.status_code == 503:
            res = response.json()
            self.assertEqual(res["status"], "error")
            self.assertEqual(res["meta"]["source_tool"], "phishpedia")
            self.assertIn("weights not loaded", res["error"])
        else:
            self.assertEqual(response.status_code, 200)
            res = response.json()
            self.assertEqual(res["status"], "success")
            self.assertIn("job_id", res["data"])


if __name__ == "__main__":
    unittest.main()
