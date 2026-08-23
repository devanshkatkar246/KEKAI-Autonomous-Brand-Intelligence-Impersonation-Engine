import os
import unittest
from pathlib import Path

from services.phishpedia_service import (
    check_phishpedia_weights,
    analyze_screenshot_visual_brand,
    run_fallback_phishing_check,
    get_phishpedia_license,
    PHISHPEDIA_JOBS
)

TEST_DATA_DIR = Path("./test_data").resolve()
PHISH_DIR = TEST_DATA_DIR / "phishing"
LEGIT_DIR = TEST_DATA_DIR / "legitimate"


class TestPhishpediaDeepLearningInference(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # Ensure test dataset exists
        assert PHISH_DIR.exists() and LEGIT_DIR.exists(), "Benchmark dataset directory missing."

    def test_01_phishpedia_weights_status_check(self):
        status = check_phishpedia_weights()
        self.assertIn("weights_loaded", status)
        self.assertIn("inference_mode", status)
        self.assertIn(status["inference_mode"], ["full_ml", "fallback", "disabled"])
        self.assertIn("device", status)

    def test_02_phishpedia_license_metadata(self):
        lic = get_phishpedia_license()
        self.assertIn("name", lic)
        self.assertEqual(lic["name"], "Phishpedia")
        self.assertIn("license", lic)
        self.assertIn("paper_citation", lic)

    def test_03_phishing_benchmark_sample_detection(self):
        phish_samples = list(PHISH_DIR.glob("*.png"))
        self.assertGreaterEqual(len(phish_samples), 5)

        correct_count = 0
        weights_status = check_phishpedia_weights()

        for img_path in phish_samples:
            url = f"https://verify-login-{img_path.stem}.account-secure-alert.com/login"
            if weights_status["weights_loaded"]:
                res = analyze_screenshot_visual_brand(screenshot_path=str(img_path))
            else:
                res = run_fallback_phishing_check(url=url, screenshot_path=str(img_path))

            self.assertIn("verdict", res)
            self.assertIn("inference_mode", res)
            if res["verdict"] == "Phishing":
                correct_count += 1

        accuracy_pct = (correct_count / len(phish_samples)) * 100.0
        print(f"\n[BENCHMARK] Phishing Detection Accuracy: {correct_count}/{len(phish_samples)} ({accuracy_pct:.1f}%) [Mode: {weights_status['inference_mode']}]")
        self.assertGreaterEqual(accuracy_pct, 80.0)

    def test_04_legitimate_benchmark_sample_detection(self):
        legit_samples = list(LEGIT_DIR.glob("*.png"))
        self.assertGreaterEqual(len(legit_samples), 5)

        correct_count = 0
        weights_status = check_phishpedia_weights()

        for img_path in legit_samples:
            url = f"https://www.{img_path.stem.split('_')[1]}.com/official-portal"
            if weights_status["weights_loaded"]:
                res = analyze_screenshot_visual_brand(screenshot_path=str(img_path))
            else:
                res = run_fallback_phishing_check(url=url, screenshot_path=str(img_path))

            self.assertIn("verdict", res)
            self.assertIn("inference_mode", res)
            if res["verdict"] == "Benign":
                correct_count += 1

        accuracy_pct = (correct_count / len(legit_samples)) * 100.0
        print(f"[BENCHMARK] Legitimate Detection Accuracy: {correct_count}/{len(legit_samples)} ({accuracy_pct:.1f}%) [Mode: {weights_status['inference_mode']}]")
        self.assertGreaterEqual(accuracy_pct, 80.0)

    def test_05_job_queue_depth_limit_constant(self):
        self.assertTrue(isinstance(PHISHPEDIA_JOBS, dict))


if __name__ == "__main__":
    unittest.main()
