import unittest
from database import init_db, insert_scanned_asset, get_db_connection
from services.infrastructure_service import get_offender_clusters, find_linked_infrastructure


class TestClusteringRulesAndExclusion(unittest.TestCase):

    def setUp(self):
        # Reset test database table
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("DROP TABLE IF EXISTS assets")
        conn.commit()
        conn.close()
        init_db()

    def test_01_genuinely_related_cluster_scoring(self):
        # Insert 3 genuinely related assets sharing IP and Target Brand
        insert_scanned_asset(
            asset_type="domain",
            asset_id="paypal-fraud1.com",
            ip_address="192.168.5.50",
            target_brand="PayPal"
        )
        insert_scanned_asset(
            asset_type="domain",
            asset_id="paypal-fraud2.com",
            ip_address="192.168.5.50",
            target_brand="PayPal"
        )
        insert_scanned_asset(
            asset_type="visual_phishing",
            asset_id="https://paypal-portal.com/login",
            ip_address="192.168.5.50",
            target_brand="PayPal",
            confidence=95.0
        )

        res = get_offender_clusters()
        clusters = res["clusters"]
        self.assertEqual(len(clusters), 1)

        c = clusters[0]
        self.assertEqual(c["asset_count"], 3)
        self.assertEqual(c["confidence"], "Medium")  # 2 distinct signals (IP + Brand)
        self.assertIn("Derived from 2 domain scan(s), 1 visual check(s)", c["data_sources_summary"])

    def test_02_single_shared_ip_low_confidence(self):
        # Insert 2 domains sharing IP alone without shared target brand or hash
        insert_scanned_asset(
            asset_type="domain",
            asset_id="random-site-a.com",
            ip_address="192.168.8.8"
        )
        insert_scanned_asset(
            asset_type="domain",
            asset_id="random-site-b.com",
            ip_address="192.168.8.8"
        )

        res = get_offender_clusters()
        clusters = res["clusters"]
        self.assertEqual(len(clusters), 1)

        c = clusters[0]
        self.assertEqual(c["confidence"], "Low")  # Single signal type = Low confidence
        self.assertEqual(c["num_distinct_signals"], 1)

    def test_03_high_cardinality_cdn_ip_exclusion(self):
        # Insert 12 domains sharing Cloudflare CDN IP 104.21.50.1
        for i in range(12):
            insert_scanned_asset(
                asset_type="domain",
                asset_id=f"shared-cdn-domain-{i}.com",
                ip_address="104.21.50.1"
            )

        res = get_offender_clusters()
        self.assertIn("104.21.50.1", res["excluded_high_cardinality_ips"])
        # Should not create a mega-cluster for the CDN IP
        self.assertEqual(len(res["clusters"]), 0)


if __name__ == "__main__":
    unittest.main()
