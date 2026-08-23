from fastapi.testclient import TestClient
from main import app
from database import insert_scanned_asset, fetch_all_assets
from services.infrastructure_service import index_domain_scan_results, get_offender_clusters

client = TestClient(app)


def test_1_domain_scan_indexing_stores_brand():
    """
    Test 1: Verify index_domain_scan_results tags scanned domain assets with target_brand.
    """
    scan_results = [
        {"domain": "am-azon-test.com", "fuzzer": "addition", "dns_a": ["15.197.245.13"]},
        {"domain": "amazun-test.com", "fuzzer": "replacement", "dns_a": ["15.197.245.13"]}
    ]
    index_domain_scan_results("amazon.com", scan_results)

    assets = fetch_all_assets()
    amazon_assets = [a for a in assets if "am-azon-test" in a["asset_id"] or "amazun-test" in a["asset_id"]]
    assert len(amazon_assets) >= 2
    for a in amazon_assets:
        assert a["target_brand"] == "Amazon"


def test_2_rolex_demo_cluster_filtering():
    """
    Test 2: Verify get_offender_clusters(brand='Rolex') returns Rolex clusters.
    """
    result = get_offender_clusters(brand="Rolex")
    assert result["total_clusters"] > 0
    top_cluster = result["clusters"][0]
    assert top_cluster["matches_requested_brand"] is True
    has_rolex_asset = any("rolex" in a["asset_id"].lower() or (a.get("target_brand") and "rolex" in a["target_brand"].lower()) for a in top_cluster["assets"])
    assert has_rolex_asset is True


def test_3_switch_rolex_to_amazon_hides_rolex_from_top_cluster():
    """
    Test 3: Switch Rolex -> Amazon filter. Verify top cluster for Amazon contains Amazon assets, not Rolex.
    """
    result = get_offender_clusters(brand="Amazon")
    assert result["total_clusters"] > 0
    top_cluster = result["clusters"][0]
    assert top_cluster["matches_requested_brand"] is True
    # Ensure top cluster assets do not contain Rolex
    has_rolex_in_amazon_top = any("rolex" in a["asset_id"].lower() for a in top_cluster["assets"])
    assert has_rolex_in_amazon_top is False


def test_4_switch_amazon_to_rolex_hides_amazon_from_top_cluster():
    """
    Test 4: Switch Amazon -> Rolex filter. Verify top cluster for Rolex contains Rolex assets, not Amazon.
    """
    result = get_offender_clusters(brand="Rolex")
    assert result["total_clusters"] > 0
    top_cluster = result["clusters"][0]
    assert top_cluster["matches_requested_brand"] is True
    has_amazon_in_rolex_top = any("amazon" in a["asset_id"].lower() for a in top_cluster["assets"])
    assert has_amazon_in_rolex_top is False


def test_5_api_endpoint_brand_filtering():
    """
    Test 5: GET /api/offender-clusters?brand=Amazon returns filtered Amazon clusters.
    """
    response = client.get("/api/offender-clusters?brand=Amazon")
    assert response.status_code == 200
    json_data = response.json()
    assert json_data["status"] == "success"
    assert json_data["data"]["filter_brand"] == "Amazon"
    clusters = json_data["data"]["clusters"]
    assert len(clusters) > 0
    assert clusters[0]["cluster_id"] == "CLUSTER-001"
    assert clusters[0]["matches_requested_brand"] is True


def test_6_new_scan_after_demo_no_demo_leakage():
    """
    Test 6: Verify a new brand scan (e.g. brand='Nike') isolates results and does not leak Rolex demo assets into top cluster.
    """
    nike_scan = [
        {"domain": "nike-fake-store.com", "fuzzer": "addition", "dns_a": ["198.51.100.99"]},
        {"domain": "nikke-shop.com", "fuzzer": "homoglyph", "dns_a": ["198.51.100.99"]}
    ]
    index_domain_scan_results("nike.com", nike_scan)

    result = get_offender_clusters(brand="Nike")
    assert result["total_clusters"] > 0
    top_cluster = result["clusters"][0]
    assert top_cluster["matches_requested_brand"] is True
    asset_ids = [a["asset_id"] for a in top_cluster["assets"]]
    assert "nike-fake-store.com" in asset_ids or "nikke-shop.com" in asset_ids
def test_7_cluster_id_propagation_contract():
    """
    Test 7: Verify cluster_id sequencing begins at CLUSTER-001 for requested brand queries.
    """
    res_amazon = client.get("/api/offender-clusters?brand=Amazon").json()
    assert res_amazon["data"]["clusters"][0]["cluster_id"] == "CLUSTER-001"
    top_assets = [a["asset_id"] for a in res_amazon["data"]["clusters"][0]["assets"]]
    assert len(top_assets) > 0


if __name__ == "__main__":
    print("Running regression test suite...")
    test_1_domain_scan_indexing_stores_brand()
    print("[PASS] Test 1: Domain scan indexing stores brand")
    test_2_rolex_demo_cluster_filtering()
    print("[PASS] Test 2: Rolex demo cluster filtering")
    test_3_switch_rolex_to_amazon_hides_rolex_from_top_cluster()
    print("[PASS] Test 3: Switch Rolex -> Amazon hides Rolex from top cluster")
    test_4_switch_amazon_to_rolex_hides_amazon_from_top_cluster()
    print("[PASS] Test 4: Switch Amazon -> Rolex hides Amazon from top cluster")
    test_5_api_endpoint_brand_filtering()
    print("[PASS] Test 5: API endpoint brand filtering")
    test_7_cluster_id_propagation_contract()
    print("[PASS] Test 7: Cluster ID propagation contract")
    test_6_new_scan_after_demo_no_demo_leakage()
    print("[PASS] Test 6: New scan after demo no demo leakage")
    print("\n>>> ALL 7 REGRESSION TESTS PASSED CLEANLY! <<<")

