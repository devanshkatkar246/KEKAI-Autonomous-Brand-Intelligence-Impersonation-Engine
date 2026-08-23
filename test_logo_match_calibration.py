import unittest
import os
import sys
from PIL import Image, ImageDraw

# Ensure root directory is in sys.path
sys.path.insert(0, os.path.abspath("."))

from services.imagehash_service import (
    calibrate_hash_similarity,
    derive_similarity_metadata,
    compare_two_images,
    compare_batch_images
)

class TestLogoMatchCalibration(unittest.TestCase):
    def setUp(self):
        os.makedirs("./scratch/test_logos", exist_ok=True)

        # Create Test Image A (Adidas-like 3-stripe logo)
        self.img_amazon_path = "./scratch/test_logos/amazon_test.png"
        img_a = Image.new("RGB", (400, 400), (255, 255, 255))
        draw_a = ImageDraw.Draw(img_a)
        stripe_w = 400 // 8
        for offset in [400 // 5, 400 * 2 // 5, 400 * 3 // 5]:
            draw_a.polygon([(offset, 400), (offset + stripe_w, 400), (offset + stripe_w + 200, 0), (offset + 200, 0)], fill=(0, 0, 0))
        img_a.save(self.img_amazon_path)

        # Create Test Image B (Same logo resized to 200x200)
        self.img_amazon_resized_path = "./scratch/test_logos/amazon_resized_test.png"
        img_b = img_a.resize((200, 200), Image.LANCZOS)
        img_b.save(self.img_amazon_resized_path)

        # Create Test Image C (Red circle logo on white bg)
        self.img_flipkart_path = "./scratch/test_logos/flipkart_test.png"
        img_c = Image.new("RGB", (400, 400), (255, 255, 255))
        draw_c = ImageDraw.Draw(img_c)
        draw_c.ellipse([80, 80, 320, 320], fill=(220, 30, 30))
        img_c.save(self.img_flipkart_path)

        # Create Test Image D (Blue square logo on white bg)
        self.img_rolex_path = "./scratch/test_logos/rolex_test.png"
        img_d = Image.new("RGB", (400, 400), (255, 255, 255))
        draw_d = ImageDraw.Draw(img_d)
        draw_d.rectangle([80, 80, 320, 320], fill=(0, 96, 200))
        img_d.save(self.img_rolex_path)

    def test_calibration_formula_boundaries(self):
        """Test calibrated score decay across threshold boundaries."""
        t = 10
        self.assertEqual(calibrate_hash_similarity(0, t), 100.0)
        self.assertGreaterEqual(calibrate_hash_similarity(2, t), 80.0)
        self.assertGreaterEqual(calibrate_hash_similarity(5, t), 50.0)
        self.assertEqual(calibrate_hash_similarity(10, t), 50.0)
        self.assertLess(calibrate_hash_similarity(15, t), 20.0)
        self.assertEqual(calibrate_hash_similarity(20, t), 0.0)
        self.assertEqual(calibrate_hash_similarity(28, t), 0.0)

    def test_same_image_match(self):
        """Amazon vs Same Amazon logo must be ~100% and Likely Match: Yes."""
        res = compare_two_images(self.img_amazon_path, self.img_amazon_path, threshold=10)
        self.assertTrue(res["likely_match"])
        self.assertEqual(res["phash"]["distance"], 0)
        self.assertEqual(res["combined_similarity_percentage"], 100.0)
        self.assertEqual(res["similarity_label"], "VERY HIGH SIMILARITY")

    def test_resized_image_match(self):
        """Amazon vs Resized Amazon logo must have High similarity and Likely Match: Yes."""
        res = compare_two_images(self.img_amazon_path, self.img_amazon_resized_path, threshold=10)
        self.assertTrue(res["likely_match"])
        self.assertGreaterEqual(res["combined_similarity_percentage"], 70.0)

    def test_unrelated_logo_flipkart_vs_amazon(self):
        """Flipkart vs Amazon must have 0% / Low similarity and Likely Match: No."""
        res = compare_two_images(self.img_flipkart_path, self.img_amazon_path, threshold=10)
        self.assertFalse(res["likely_match"])
        self.assertLess(res["combined_similarity_percentage"], 15.0)
        self.assertIn(res["similarity_label"], ["NO MATCH", "LOW SIMILARITY"])
        self.assertIn("exceed", res["match_reason"])

    def test_batch_comparison_ranking(self):
        """Batch comparison ranks same/resized logos above unrelated logos."""
        candidates = [
            (self.img_flipkart_path, "flipkart.png"),
            (self.img_amazon_resized_path, "amazon_resized.png"),
            (self.img_rolex_path, "rolex.png")
        ]
        res = compare_batch_images(self.img_amazon_path, "amazon.png", candidates, threshold=10)

        results = res["ranked_results"]
        # Highest similarity candidate must be amazon_resized.png
        self.assertEqual(results[0]["candidate_filename"], "amazon_resized.png")
        self.assertTrue(results[0]["likely_match"])

        # flipkart and rolex must be Likely Match: False with very low similarity
        for cand in results[1:]:
            self.assertFalse(cand["likely_match"])
            self.assertLess(cand["combined_similarity_percentage"], 20.0)

if __name__ == "__main__":
    unittest.main()
