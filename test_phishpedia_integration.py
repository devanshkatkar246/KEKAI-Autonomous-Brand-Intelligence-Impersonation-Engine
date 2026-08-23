import unittest
import os
import tempfile
from pathlib import Path
from services.phishpedia_service import (
    analyze_screenshot_visual_brand,
    check_phishpedia_weights
)


class TestPhishpediaIntegration(unittest.TestCase):

    def setUp(self):
        # Create a temporary dummy screenshot image file for testing
        self.temp_dir = tempfile.TemporaryDirectory()
        self.dummy_img_path = Path(self.temp_dir.name) / "test_screenshot.png"
        
        # Write dummy PNG header bytes
        with open(self.dummy_img_path, "wb") as f:
            f.write(b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15c4\x00\x00\x00\nIDATx\x9cc\x00\x01\x00\x00\x05\x00\x01\r\n-\xb4\x00\x00\x00\x00IEND\xaeB`\x82")

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_01_weights_validation_and_status(self):
        """Verify weights validation returns structured status without raising unhandled errors."""
        status = check_phishpedia_weights()
        self.assertIsInstance(status, dict)
        self.assertIn("weights_loaded", status)
        self.assertIn("message", status)
        self.assertIn("device", status)

    def test_02_invalid_screenshot_error_handling(self):
        """Test E: Non-existent screenshot file returns controlled error dictionary without crash."""
        res = analyze_screenshot_visual_brand("/invalid/path/to/non_existent_image.png")
        self.assertEqual(res["status"], "error")
        self.assertFalse(res["detected"])
        self.assertIn("not found", res["reason"])

    def test_03_phishpedia_unavailable_fallback(self):
        """Test D: When Phishpedia model weights are missing/unavailable, service returns controlled unavailable status."""
        res = analyze_screenshot_visual_brand(str(self.dummy_img_path))
        self.assertIsInstance(res, dict)
        self.assertIn(res["status"], ["success", "unavailable"])
        self.assertIsInstance(res["brands"], list)
        self.assertIn("model", res)

    def test_04_api_response_schema_contract(self):
        """Verify returned visual_brand_analysis payload contains required fields (brands, confidence, bounding_box)."""
        res = analyze_screenshot_visual_brand(str(self.dummy_img_path))
        self.assertIn("detected", res)
        self.assertIn("brands", res)
        if res["detected"]:
            brand_item = res["brands"][0]
            self.assertIn("brand", brand_item)
            self.assertIn("confidence", brand_item)
            self.assertIn("bounding_box", brand_item)
            self.assertEqual(len(brand_item["bounding_box"]), 4)

    def test_05_no_phishing_verdict_generated(self):
        """Verify that visual brand analysis strictly returns visual brand identification and NO phishing verdict."""
        res = analyze_screenshot_visual_brand(str(self.dummy_img_path))
        self.assertNotIn("verdict", res, "Visual brand analysis must NOT output a phishing verdict!")


if __name__ == "__main__":
    unittest.main()
