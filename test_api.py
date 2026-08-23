import os
import sys
import unittest
from pathlib import Path
from fastapi.testclient import TestClient

from main import app
from utils.temp_file import TMP_DIR

client = TestClient(app)


class TestFastAPIBackend(unittest.TestCase):

    def test_01_health_endpoint(self):
        response = client.get("/api/health")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["status"], "success")
        self.assertEqual(data["meta"]["source_tool"], "system")
        self.assertEqual(data["data"]["health"], "ok")

    def test_02_credits_endpoint(self):
        response = client.get("/api/credits")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["status"], "success")
        self.assertEqual(data["meta"]["source_tool"], "system")
        
        tools = data["data"]["tools"]
        tool_names = [t["name"] for t in tools]
        licenses = {t["name"]: t["license"] for t in tools}

        self.assertIn("dnstwist", tool_names)
        self.assertIn("imagehash", tool_names)
        self.assertEqual(licenses["dnstwist"], "GPLv3")
        self.assertEqual(licenses["imagehash"], "BSD-2-Clause")

    def test_03_domain_scan_quick_mode(self):
        payload = {"domain": "example.com", "quick_mode": True, "timeout": 60}
        response = client.post("/api/domain-scan", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["status"], "success")
        self.assertEqual(data["meta"]["source_tool"], "dnstwist")
        self.assertEqual(data["data"]["domain"], "example.com")
        self.assertIn("permutations", data["data"])
        self.assertIsInstance(data["data"]["permutations"], list)

    def test_04_logo_compare(self):
        ref_path = Path("./imagehash/official_logo.png")
        cand_path = Path("./imagehash/official_logo2.png")

        if not ref_path.exists() or not cand_path.exists():
            self.skipTest("Sample logos not found in ./imagehash")

        with open(ref_path, "rb") as ref_f, open(cand_path, "rb") as cand_f:
            files = {
                "reference": ("official_logo.png", ref_f, "image/png"),
                "candidate": ("official_logo2.png", cand_f, "image/png")
            }
            data = {"threshold": "15"}
            response = client.post("/api/logo-compare", files=files, data=data)

        self.assertEqual(response.status_code, 200)
        res = response.json()
        self.assertEqual(res["status"], "success")
        self.assertEqual(res["meta"]["source_tool"], "imagehash")

        comparison = res["data"]
        self.assertIn("phash", comparison)
        self.assertIn("dhash", comparison)
        self.assertIn("distance", comparison["phash"])
        self.assertIn("similarity_percentage", comparison["phash"])
        self.assertIn("likely_match", comparison)
        self.assertIsInstance(comparison["likely_match"], bool)

    def test_05_logo_batch(self):
        ref_path = Path("./imagehash/official_logo.png")
        cand1_path = Path("./imagehash/official_logo2.png")
        cand2_path = Path("./imagehash/suspected_logo.png")

        if not ref_path.exists() or not cand1_path.exists():
            self.skipTest("Sample logos not found in ./imagehash")

        with open(ref_path, "rb") as ref_f, open(cand1_path, "rb") as c1_f, open(cand2_path, "rb") as c2_f:
            files = [
                ("reference", ("official_logo.png", ref_f, "image/png")),
                ("candidates", ("official_logo2.png", c1_f, "image/png")),
                ("candidates", ("suspected_logo.png", c2_f, "image/png"))
            ]
            data = {"threshold": "10"}
            response = client.post("/api/logo-batch", files=files, data=data)

        self.assertEqual(response.status_code, 200)
        res = response.json()
        self.assertEqual(res["status"], "success")
        self.assertEqual(res["meta"]["source_tool"], "imagehash")

        batch_data = res["data"]
        self.assertEqual(batch_data["total_candidates"], 2)
        self.assertEqual(len(batch_data["ranked_results"]), 2)
        # Verify ranking order (descending similarity)
        sim1 = batch_data["ranked_results"][0]["combined_similarity_percentage"]
        sim2 = batch_data["ranked_results"][1]["combined_similarity_percentage"]
        self.assertGreaterEqual(sim1, sim2)

    def test_06_temp_file_cleanup(self):
        # Count files in TMP_DIR before and after request
        files_before = list(TMP_DIR.glob("logo_*"))
        
        ref_path = Path("./imagehash/official_logo.png")
        cand_path = Path("./imagehash/official_logo2.png")
        with open(ref_path, "rb") as ref_f, open(cand_path, "rb") as cand_f:
            files = {
                "reference": ("official_logo.png", ref_f, "image/png"),
                "candidate": ("official_logo2.png", cand_f, "image/png")
            }
            client.post("/api/logo-compare", files=files)

        files_after = list(TMP_DIR.glob("logo_*"))
        self.assertEqual(len(files_after), len(files_before), "Temp files were not cleaned up!")


if __name__ == "__main__":
    unittest.main()
